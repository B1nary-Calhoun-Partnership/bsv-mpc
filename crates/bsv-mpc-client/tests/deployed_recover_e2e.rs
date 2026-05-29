//! **#66 — `bsv-mpc-client` RECOVERS a wallet onto a fresh device (L1 backup share).**
//!
//! The 4th FFI seam's proof, completing the quartet (#65 create / #63 sign / #64
//! storage / this = recover). Exercises the high-level `recover_wallet` 100cash binds
//! to over UniFFI: the ADDRESS-PRESERVING reshare of an EXISTING wallet onto a fresh
//! device from the passkey-PRF-unwrapped backup share B, device-sealing the rotated
//! share, returning the `FfiSignerConfig`-shaped metadata `connect` consumes.
//!
//! Tiers:
//! - **local (always run):** `parse_old_share_topology` extracts the joint pubkey +
//!   `(t, n)` from a real cggmp24 share (the load-bearing "joint pubkey == original"
//!   invariant), and `recover_wallet` rejects a non-2-of-2 backup for the right reason
//!   (validate-don't-skip). No network.
//! - **`CLIENT_DEPLOYED_RECOVER=1` (free, no sats):** create a real 2-of-2 vs the
//!   deployed cosigner → DROP the sealed share (device loss) → `recover_wallet` onto a
//!   FRESH keystore → `connect` → `sign` → the signature verifies under the SAME joint
//!   key (same address). The protocol-asterisk killer.
//! - **`CLIENT_DEPLOYED_RECOVER_MAINNET=1` (REAL SATS):** fund the joint P2PKH, recover
//!   ENTIRELY through `recover_wallet`, spend from the SAME address → WoC TXID.
//!
//! ```bash
//! # free recovery ceremony (deployed infra, no sats):
//! CLIENT_DEPLOYED_RECOVER=1 cargo test -p bsv-mpc-client --features native \
//!   --test deployed_recover_e2e recover_roundtrip -- --nocapture --test-threads=1
//! # real mainnet recovered-spend (BURNS SATS, needs wallet:3321):
//! CLIENT_DEPLOYED_RECOVER_MAINNET=1 cargo test -p bsv-mpc-client --features native \
//!   --test deployed_recover_e2e recover_mainnet -- --nocapture --test-threads=1
//! ```
#![cfg(not(target_arch = "wasm32"))]

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use bsv::primitives::ec::{PrivateKey, PublicKey, Signature};
use bsv_mpc_client::native_io::keystore::{MemNativeKeyStore, NativeKeyStore};
use bsv_mpc_client::native_io::provision::ProvisionedWallet;
use bsv_mpc_client::native_io::recover::recover_wallet;
use bsv_mpc_client::native_io::signer::{DeployedSigner, DeployedSignerConfig, WalletMeta};
use bsv_mpc_core::types::{PolicyId, ThresholdConfig};
use cggmp24::security_level::{SecurityLevel, SecurityLevel128};
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;

const DEFAULT_CONTAINER: &str = "https://bsv-mpc-service-container.dev-a3e.workers.dev";
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";
const AT_REST_ROOT: [u8; 32] = [0x42u8; 32];

fn container_url() -> String {
    std::env::var("DEPLOYED_CONTAINER_URL").unwrap_or_else(|_| DEFAULT_CONTAINER.to_string())
}
fn relay_url() -> String {
    std::env::var("MESSAGEBOX_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY.to_string())
}

// ── round_based sim harness (mirrors hermetic_sign.rs) — builds REAL cggmp24 shares
//    locally (Blum-prime shortcut) for the no-network topology tests. ────────────

#[pin_project::pin_project]
struct BufferedSink<M, Inner> {
    #[pin]
    messages: VecDeque<M>,
    #[pin]
    inner: Inner,
}

type BufferedDelivery<M, D> = (
    <D as round_based::Delivery<M>>::Receive,
    BufferedSink<round_based::Outgoing<M>, <D as round_based::Delivery<M>>::Send>,
);

impl<M: Unpin, Inner: futures::Sink<M>> futures::Sink<M> for BufferedSink<M, Inner> {
    type Error = Inner::Error;
    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn start_send(self: std::pin::Pin<&mut Self>, item: M) -> std::result::Result<(), Self::Error> {
        self.project().messages.get_mut().push_back(item);
        Ok(())
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        while !self.messages.is_empty() {
            let mut projection = self.as_mut().project();
            let mut inner = projection.inner;
            std::task::ready!(inner.as_mut().poll_ready(cx))?;
            if let Some(item) = projection.messages.pop_front() {
                inner.as_mut().start_send(item)?;
            }
        }
        self.project().inner.poll_flush(cx)
    }
    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        self.project().inner.poll_close(cx)
    }
}

fn buffer_outgoing<M, D, R>(
    party: round_based::MpcParty<M, D, R>,
) -> round_based::MpcParty<M, BufferedDelivery<M, D>, R>
where
    M: Unpin,
    D: round_based::Delivery<M>,
    R: round_based::runtime::AsyncRuntime,
{
    party.map_delivery(|delivery| {
        let (incoming, outgoing) = delivery.split();
        let buffered_outgoing = BufferedSink {
            messages: VecDeque::new(),
            inner: outgoing,
        };
        (incoming, buffered_outgoing)
    })
}

fn generate_blum_prime(rng: &mut impl rand::RngCore, bits: u32) -> cggmp24::backend::Integer {
    use cggmp24::backend::Integer;
    loop {
        let n = Integer::generate_prime(rng, bits);
        if n.mod_u(4) == 3 {
            break n;
        }
    }
}

fn generate_test_primes(
    rng: &mut impl rand::RngCore,
) -> cggmp24::key_refresh::PregeneratedPrimes<SecurityLevel128> {
    let bits = SecurityLevel128::RSA_PRIME_BITLEN;
    let primes = [
        generate_blum_prime(rng, bits),
        generate_blum_prime(rng, bits),
        generate_blum_prime(rng, bits),
        generate_blum_prime(rng, bits),
    ];
    cggmp24::key_refresh::PregeneratedPrimes::try_from(primes).expect("primes wrong bit size")
}

/// Build `n` real signable cggmp24 KeyShares (`t`-of-`n`) via the round_based
/// simulator — the same shape `provision_wallet` device-seals.
fn dkg_key_shares(n: u16, t: u16) -> Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> {
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rand::Rng::gen(&mut rng);
    let eid = ExecutionId::new(&eid_bytes);
    let incomplete = round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut prng = rand::rngs::OsRng;
        async move {
            cggmp24::keygen::<Secp256k1>(eid, i, n)
                .set_threshold(t)
                .start(&mut prng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    let eid_bytes: [u8; 32] = rand::Rng::gen(&mut rng);
    let eid_aux = ExecutionId::new(&eid_bytes);
    let primes: Vec<_> = (0..n).map(|_| generate_test_primes(&mut rng)).collect();
    let aux = round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut prng = rand::rngs::OsRng;
        let pregen = primes[usize::from(i)].clone();
        async move {
            cggmp24::aux_info_gen(eid_aux, i, n, pregen)
                .start(&mut prng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    incomplete
        .into_iter()
        .zip(aux)
        .map(|(s, a)| {
            cggmp24::KeyShare::<Secp256k1, SecurityLevel128>::from_parts((s, a))
                .expect("key share validation")
        })
        .collect()
}

// ── local topology tests (no network) ────────────────────────────────────────

/// The load-bearing recovery invariant at the unit level: a backup share carries the
/// joint pubkey, so the recovering device derives the SAME address it is restoring —
/// `parse_old_share_topology` extracts `(2,2)`, the device index, and the joint
/// pubkey, and BOTH parties' shares agree on that joint pubkey.
#[test]
fn parse_topology_extracts_joint_pubkey_and_2of2() {
    let shares = dkg_key_shares(2, 2);
    let expected_joint = shares[0]
        .core
        .key_info
        .shared_public_key
        .to_bytes(true)
        .to_vec();

    for (i, ks) in shares.iter().enumerate() {
        let json = serde_json::to_vec(ks).expect("serialize key share");
        let topo = bsv_mpc_relay::parse_old_share_topology(&json).expect("parse topology");
        assert_eq!(topo.threshold, 2, "old threshold");
        assert_eq!(topo.parties, 2, "old party count");
        assert_eq!(
            topo.old_index as usize, i,
            "old index matches party position"
        );
        assert_eq!(
            topo.joint_pubkey_compressed, expected_joint,
            "both parties' shares MUST carry the SAME joint pubkey (the address)"
        );
    }
}

/// Validate-don't-skip: `recover_wallet` (L1 backup-share, v1) supports only the
/// proven 2-of-2 device+cosigner wallet, and rejects any other topology for the RIGHT
/// reason — BEFORE any network/seal (the guard runs before the container handshake).
#[tokio::test]
async fn recover_rejects_non_2of2_for_the_right_reason() {
    // A 2-of-3 share is a valid cggmp24 share with the wrong topology for L1.
    let shares = dkg_key_shares(3, 2);
    let backup = serde_json::to_vec(&shares[1]).expect("serialize");
    let ks = MemNativeKeyStore::new();
    let identity = PrivateKey::from_bytes(&[0x21u8; 32]).expect("identity");

    let res = recover_wallet(
        "https://relay.invalid",
        "https://container.invalid",
        identity,
        backup,
        Duration::from_secs(1),
        &ks,
    )
    .await;
    let Err(err) = res else {
        panic!("a non-2-of-2 backup must reject, got Ok");
    };
    let msg = err.to_string();
    assert!(
        msg.contains("2-of-2") && msg.contains("2-of-3"),
        "expected a 2-of-2-only reject naming the bad topology, got: {msg}"
    );
    // Fail-closed: nothing sealed.
    assert!(
        ks.unseal_share("x", "none").await.is_err(),
        "no share must be sealed when recovery rejects the topology"
    );
}

// ── deployed: create → lose → recover → sign (free, no sats) ──────────────────

/// Provision a real 2-of-2 vs the deployed cosigner, then DROP the share (device
/// loss) and recover it onto a FRESH keystore via `recover_wallet`. Returns the
/// recovered wallet + the fresh keystore + the original (pre-loss) wallet metadata.
async fn create_lose_recover(
    identity: PrivateKey,
) -> (
    ProvisionedWallet,
    Arc<MemNativeKeyStore>,
    ProvisionedWallet,
    Vec<u8>,
) {
    // 1. CREATE (the #65 seam): real DKG vs the deployed cosigner → sealed share B.
    eprintln!("(create: real distributed DKG vs the deployed cosigner — minutes)");
    let create_ks = Arc::new(MemNativeKeyStore::new());
    let created = bsv_mpc_client::native_io::provision_wallet(
        &container_url(),
        identity.clone(),
        ThresholdConfig::new(2, 2).expect("2-of-2"),
        create_ks.as_ref(),
    )
    .await
    .expect("provision_wallet (create) vs the deployed cosigner");
    eprintln!(
        "✔ created: agent_id={} address={}",
        created.agent_id, created.joint_key.address
    );

    // 2. Lift the backup share B out of the create keystore (the host's PRF unwrap),
    //    then DROP that keystore — the phone is "lost".
    let backup_factor = create_ks
        .unseal_share(&created.agent_id, "extract backup share B")
        .await
        .expect("backup share B present after create")
        .to_vec();
    drop(create_ks);

    // 3. RECOVER (the #66 seam): reshare onto a FRESH device/keystore.
    eprintln!("(recover: address-preserving reshare onto a fresh device — minutes)");
    let recover_ks = Arc::new(MemNativeKeyStore::new());
    let recovered = recover_wallet(
        &relay_url(),
        &container_url(),
        identity,
        backup_factor.clone(),
        Duration::from_secs(360),
        recover_ks.as_ref(),
    )
    .await
    .expect("recover_wallet onto the fresh device");
    eprintln!(
        "✔ recovered: agent_id={} address={}",
        recovered.agent_id, recovered.joint_key.address
    );

    (recovered, recover_ks, created, backup_factor)
}

/// Connect a `DeployedSigner` from recovered wallet metadata + the fresh keystore.
async fn connect_signer(
    recovered: &ProvisionedWallet,
    recover_ks: Arc<MemNativeKeyStore>,
    identity: PrivateKey,
) -> DeployedSigner {
    let bundle_dir =
        std::env::temp_dir().join(format!("bsvmpc-recover-bundles-{}", std::process::id()));
    DeployedSigner::connect(
        DeployedSignerConfig {
            relay_url: relay_url(),
            container_url: container_url(),
            identity,
            at_rest_root: AT_REST_ROOT,
            bundle_dir,
            policy_id: PolicyId([0u8; 32]),
            meta: WalletMeta {
                agent_id: recovered.agent_id.clone(),
                joint_key: recovered.joint_key.clone(),
                config: recovered.config,
                participants: recovered.participants.clone(),
                device_share_index: recovered.device_share_index,
                my_indices: vec![recovered.device_share_index],
                cosigner_party: recovered.cosigner_party,
                dkg_session_id: recovered.dkg_session_id,
            },
        },
        recover_ks,
    )
    .await
    .expect("connect recovered signer")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recover_roundtrip_signs_under_the_same_joint_key_no_sats() {
    if std::env::var("CLIENT_DEPLOYED_RECOVER").ok().as_deref() != Some("1") {
        eprintln!(
            "CLIENT_DEPLOYED_RECOVER=1 not set — skipping the free deployed-recovery verify."
        );
        return;
    }
    let identity = PrivateKey::from_bytes(&[0x66u8; 32]).expect("identity key");
    let (recovered, recover_ks, created, backup_factor) =
        create_lose_recover(identity.clone()).await;

    // The #35/#18 invariant: SAME joint pubkey + SAME address after recovery.
    assert_eq!(
        recovered.joint_key.compressed, created.joint_key.compressed,
        "recovered joint pubkey MUST equal the pre-loss key (no funds move)"
    );
    assert_eq!(
        recovered.joint_key.address, created.joint_key.address,
        "recovered address MUST equal the pre-loss address"
    );
    assert_eq!(recovered.agent_id, created.agent_id, "wallet id unchanged");

    // seal_share was invoked: the fresh keystore now holds the ROTATED share (≠ the
    // lost backup B — PSS rotation means the old copy is dead).
    let rotated = recover_ks
        .unseal_share(&recovered.agent_id, "verify recovered share present")
        .await
        .expect("recovered share sealed on the fresh device");
    assert_ne!(
        rotated.to_vec(),
        backup_factor,
        "the recovered share MUST be rotated (not the old backup) — PSS killed the old copy"
    );

    // Connect through the recovered config + sign → verify under the SAME joint key.
    let mut joint_arr = [0u8; 33];
    joint_arr.copy_from_slice(&recovered.joint_key.compressed);
    let joint_pub = PublicKey::from_bytes(&joint_arr).expect("joint pubkey");

    let signer = connect_signer(&recovered, recover_ks, identity).await;
    let minted = signer
        .top_up_presigs(1, "provision presigs", Duration::from_secs(180))
        .await
        .expect("presig top-up over the relay (with the rotated container share)");
    assert_eq!(minted, 1, "must mint exactly one bundle");

    let sighash = [0x9bu8; 32];
    let sig = signer
        .sign(
            &sighash,
            "Approve recovered-wallet test",
            None,
            Duration::from_secs(60),
            Duration::from_secs(180),
        )
        .await
        .expect("recovered-wallet sign over the live relay");

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.r);
    s.copy_from_slice(&sig.s);
    let bsv_sig = Signature::new(r, s);
    assert!(bsv_sig.is_low_s(), "signature must be low-s");
    assert!(
        joint_pub.verify(&sighash, &bsv_sig),
        "the recovered-wallet signature MUST verify under the UNCHANGED joint key"
    );
    eprintln!(
        "✔ recovered wallet signs + verifies under the same joint key (no sats) — #66 proven"
    );
}

// ── deployed: recovered-wallet REAL mainnet spend (REAL SATS) ─────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recover_mainnet_spends_from_the_same_address() {
    if std::env::var("CLIENT_DEPLOYED_RECOVER_MAINNET")
        .ok()
        .as_deref()
        != Some("1")
    {
        eprintln!(
            "CLIENT_DEPLOYED_RECOVER_MAINNET=1 not set — skipping the REAL-SATS recovered-spend gate."
        );
        return;
    }
    let http = reqwest::Client::new();
    let identity = PrivateKey::from_bytes(&[0x66u8; 32]).expect("identity key");

    // CREATE the wallet first, fund its address, THEN lose+recover, THEN spend from
    // the SAME address with the recovered (rotated) share.
    eprintln!("(create: real distributed DKG vs the deployed cosigner — minutes)");
    let create_ks = Arc::new(MemNativeKeyStore::new());
    let created = bsv_mpc_client::native_io::provision_wallet(
        &container_url(),
        identity.clone(),
        ThresholdConfig::new(2, 2).expect("2-of-2"),
        create_ks.as_ref(),
    )
    .await
    .expect("provision_wallet (create)");
    let mut joint_arr = [0u8; 33];
    joint_arr.copy_from_slice(&created.joint_key.compressed);
    let joint_pub = PublicKey::from_bytes(&joint_arr).expect("joint pubkey");
    let joint_locking =
        bsv_mpc_client::txbuild::p2pkh_locking_script_from_hash(&joint_pub.hash160());
    eprintln!(
        "✔ created + will fund address {}",
        created.joint_key.address
    );

    // Fund the joint P2PKH via wallet:3321; self-broadcast the BEEF v1 via ARC.
    let funding_amount: u64 = 1500;
    let mut fund_txid = String::new();
    for attempt in 1..=8 {
        let fund_text = http
            .post("http://localhost:3321/createAction")
            .header("Origin", "http://admin.com")
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "description": format!("bsv-mpc-client #66 recovered-spend gate (attempt {attempt})"),
                "outputs": [{
                    "satoshis": funding_amount,
                    "lockingScript": hex::encode(&joint_locking),
                    "outputDescription": "MPC client joint P2PKH (pre-recovery)"
                }]
            }))
            .send()
            .await
            .expect("wallet:3321 reachable")
            .text()
            .await
            .unwrap_or_default();
        let fund_json: serde_json::Value =
            serde_json::from_str(&fund_text).unwrap_or_else(|_| panic!("fund JSON: {fund_text}"));
        let txid = fund_json["txid"]
            .as_str()
            .expect("createAction txid")
            .to_string();
        if let Some(beef_hex) = broadcast_hex_from_create_action(&fund_json) {
            if broadcast_via_arc(&http, &beef_hex).await {
                eprintln!("✔ funded joint address: txid={txid} (attempt {attempt})");
                fund_txid = txid;
                break;
            }
        }
        eprintln!("  funding attempt {attempt} ({txid}) did NOT broadcast; retrying");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    assert!(
        !fund_txid.is_empty(),
        "could not broadcast a funding tx after 8 attempts"
    );

    // LOSE + RECOVER: lift the backup, drop the create keystore, reshare onto fresh.
    let backup_factor = create_ks
        .unseal_share(&created.agent_id, "extract backup share B")
        .await
        .expect("backup share present")
        .to_vec();
    drop(create_ks);
    eprintln!("(recover: address-preserving reshare onto a fresh device — minutes)");
    let recover_ks = Arc::new(MemNativeKeyStore::new());
    let recovered = recover_wallet(
        &relay_url(),
        &container_url(),
        identity.clone(),
        backup_factor,
        Duration::from_secs(360),
        recover_ks.as_ref(),
    )
    .await
    .expect("recover_wallet onto the fresh device");
    assert_eq!(
        recovered.joint_key.compressed, created.joint_key.compressed,
        "recovered address MUST be the funded address (no funds move)"
    );
    eprintln!("✔ recovered the funded wallet onto a fresh device (same address)");

    // Spend the funding UTXO with the RECOVERED (rotated) share over the relay.
    let signer = connect_signer(&recovered, recover_ks, identity).await;
    signer
        .top_up_presigs(1, "provision presigs", Duration::from_secs(180))
        .await
        .expect("presig top-up");

    let locking_hex = hex::encode(&joint_locking);
    let (vout, value) = find_utxo_on_woc(&http, &fund_txid, &locking_hex)
        .await
        .expect("MUST find funding UTXO on WoC");
    eprintln!("✔ UTXO {fund_txid}:{vout} ({value} sats)");

    let mut prev_txid = [0u8; 32];
    prev_txid.copy_from_slice(&hex::decode(&fund_txid).expect("txid hex"));
    prev_txid.reverse();
    let fee: u64 = 200;
    let change = value.checked_sub(fee).expect("UTXO must cover fee");

    let wallet_pub_hex = http
        .post("http://localhost:3321/getPublicKey")
        .header("Origin", "http://admin.com")
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({"identityKey": true}))
        .send()
        .await
        .expect("getPublicKey")
        .json::<serde_json::Value>()
        .await
        .expect("getPublicKey JSON")["publicKey"]
        .as_str()
        .expect("publicKey")
        .to_string();
    let change_script = bsv_mpc_client::txbuild::p2pkh_locking_script_from_hash(
        &PublicKey::from_hex(&wallet_pub_hex)
            .expect("wallet pub")
            .hash160(),
    );

    let sighash_type: u32 = 0x41; // SIGHASH_ALL | FORKID
    let sighash =
        bsv_mpc_client::txbuild::compute_bip143_sighash(&bsv_mpc_client::txbuild::SighashParams {
            version: 1,
            inputs: &[(prev_txid, vout, 0xFFFFFFFF)],
            outputs: &[(change, change_script.as_slice())],
            locktime: 0,
            input_index: 0,
            subscript: &joint_locking,
            input_satoshis: value,
            sighash_type,
        });

    // THE GATE: sign with the RECOVERED share via the deployed cosigner over the relay.
    let sig = signer
        .sign(
            &sighash,
            "Approve recovered mainnet spend",
            None,
            Duration::from_secs(60),
            Duration::from_secs(180),
        )
        .await
        .expect("recovered-wallet sign over the live relay");

    let mut sig_checksig = sig.signature.clone();
    sig_checksig.push(sighash_type as u8);
    let unlocking =
        bsv_mpc_client::txbuild::build_p2pkh_unlocking_script(&sig_checksig, &joint_arr);
    let raw_tx = bsv_mpc_client::txbuild::serialize_signed_tx(
        1,
        &[(prev_txid, vout, unlocking, 0xFFFFFFFF)],
        &[(change, change_script)],
        0,
    );
    let txid_hex = bsv_mpc_client::txbuild::compute_txid(&raw_tx);
    let raw_tx_hex = hex::encode(&raw_tx);

    let ok = broadcast_via_arc(&http, &raw_tx_hex).await;
    assert!(
        ok,
        "ARC broadcast MUST succeed — TXID={txid_hex} rawTx={raw_tx_hex}"
    );

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  #66 — bsv-mpc-client RECOVERED-wallet spend (mainnet)         ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!(
        "  joint_pubkey:  {}",
        hex::encode(&created.joint_key.compressed)
    );
    eprintln!(
        "  address:       {} (UNCHANGED across recovery)",
        created.joint_key.address
    );
    eprintln!("  funding_txid:  {fund_txid}");
    eprintln!("  spending_txid: {txid_hex}  (signed with the RECOVERED rotated share)");
    eprintln!("  view: https://whatsonchain.com/tx/{txid_hex}");
}

// ── chain helpers (mirror the #63 deployed_sign_e2e blueprint) ────────────────

fn broadcast_hex_from_create_action(resp: &serde_json::Value) -> Option<String> {
    let arr = resp.get("tx")?.as_array()?;
    let beef: Vec<u8> = arr.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect();
    let tx = bsv::Transaction::from_atomic_beef(&beef)
        .or_else(|_| bsv::Transaction::from_beef(&beef, None))
        .ok()?;
    match tx.to_beef_v1(false) {
        Ok(b) => Some(hex::encode(b)),
        Err(_) => Some(tx.to_hex()),
    }
}

async fn broadcast_via_arc(http: &reqwest::Client, raw_tx_hex: &str) -> bool {
    let taal_token = std::env::var("TAAL_ARC_TOKEN")
        .unwrap_or_else(|_| "mainnet_9596de07e92300c6287e4393594ae39c".to_string());
    for arc in &["https://arc.gorillapool.io", "https://arc.taal.com"] {
        let url = format!("{arc}/v1/tx");
        let mut req = http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("XDeployment-ID", "bsv-mpc-client-66")
            .json(&serde_json::json!({ "rawTx": raw_tx_hex }));
        if arc.contains("taal") {
            req = req.header("Authorization", format!("Bearer {taal_token}"));
        }
        let Ok(resp) = req.send().await else { continue };
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        eprintln!(
            "  broadcast {url}: status={status} body={}",
            text.chars().take(300).collect::<String>()
        );
        if status.is_success()
            || text.contains("SEEN_ON_NETWORK")
            || text.contains("STORED")
            || text.contains("MINED")
        {
            return true;
        }
    }
    false
}

async fn find_utxo_on_woc(
    http: &reqwest::Client,
    fund_txid: &str,
    expected_locking_hex: &str,
) -> Option<(u32, u64)> {
    let url = format!("https://api.whatsonchain.com/v1/bsv/main/tx/hash/{fund_txid}");
    for attempt in 1..=20 {
        eprintln!("  WoC attempt {attempt}: waiting 15s for indexing...");
        tokio::time::sleep(Duration::from_secs(15)).await;
        let Ok(resp) = http.get(&url).send().await else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(json) = resp.json::<serde_json::Value>().await else {
            continue;
        };
        let Some(vouts) = json["vout"].as_array() else {
            continue;
        };
        for vout in vouts {
            if vout["scriptPubKey"]["hex"].as_str().unwrap_or("") == expected_locking_hex {
                let n = vout["n"].as_u64().unwrap_or(0) as u32;
                let value = (vout["value"].as_f64().unwrap_or(0.0) * 100_000_000.0 + 0.5) as u64;
                return Some((n, value));
            }
        }
    }
    None
}
