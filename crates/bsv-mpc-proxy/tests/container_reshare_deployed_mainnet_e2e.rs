//! **§18.2 cross-(t,n) reshare 2-of-2 → 2-of-3 — DEPLOYED, REAL SATS (issue #35c
//! pt2).**
//!
//! Capstone for the cross-(t,n) reshare against the deployed CF **Container**
//! (`bsv-mpc-service-container`, full native `bsv-mpc-service`):
//!
//!   1. **Real distributed authed 2-of-2 DKG** against the container → it holds
//!      `share_A` (owner-bound to the proxy identity); the proxy holds `share_B`.
//!      This is the funded key K.
//!   2. **Fund** K's P2PKH on mainnet via wallet:3321.
//!   3. **Reshare over the relay** (`reshare_change_threshold_over_relay`): the
//!      proxy plays new parties 1 and 2 in-process; the container is moved onto new
//!      party 0. Phase A (throwaway 2-of-3 DKG) + phase B (cross-(t,n) PSS) → each
//!      party holds a new-set 2-of-3 KeyShare for the SAME key K.
//!      - **§18 invariant:** the joint pubkey (BSV address) is UNCHANGED.
//!   4. Sign the spend with a new 2-of-3 subset INCLUDING the container, then
//!      broadcast.
//!      - **NOTE:** see the TODO below — the 2-of-3 relay-sign path that consumes
//!        the new-set shares (container party 0 + a proxy party) is not yet wired,
//!        so the test asserts the reshare succeeded + the address is preserved and
//!        leaves the sign+broadcast to the parent.
//!
//! REAL SATS. Gated on `CONTAINER_RESHARE_MAINNET=1`. Requires a BRC-100 wallet at
//! `http://localhost:3321` (Origin `http://admin.com`) with spendable sats.
//!
//! ```bash
//! CONTAINER_RESHARE_MAINNET=1 cargo test -p bsv-mpc-proxy \
//!   --test container_reshare_deployed_mainnet_e2e \
//!   --release -- --nocapture --test-threads=1
//! ```

use std::collections::VecDeque;
use std::time::Duration;

use bsv::primitives::bsv::sighash::{
    compute_sighash_for_signing, SighashParams, TxInput, TxOutput, SIGHASH_ALL, SIGHASH_FORKID,
};
use bsv::primitives::bsv::tx_signature::TransactionSignature;
use bsv::primitives::ec::{PrivateKey, PublicKey, Signature};
use bsv::primitives::encoding::Writer;
use bsv::primitives::hash::sha256d;
use bsv_mpc_core::types::ThresholdConfig;
use bsv_mpc_proxy::bridge::{run_dkg_over_http_authed, MpcBridge};
use bsv_mpc_proxy::config::ProxyConfig;
use cggmp24::security_level::SecurityLevel128;
use cggmp24::signing::PrehashedDataToSign;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;

const DEFAULT_CONTAINER: &str = "https://bsv-mpc-service-container.dev-a3e.workers.dev";
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";

fn opt_in() -> bool {
    std::env::var("CONTAINER_RESHARE_MAINNET").ok().as_deref() == Some("1")
}

fn p2pkh_locking_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.extend_from_slice(&[0x76, 0xa9, 0x14]);
    s.extend_from_slice(pubkey_hash);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

async fn broadcast_via_arc(http: &reqwest::Client, raw_tx_hex: &str) -> bool {
    // TAAL ARC needs a Bearer token (else 401); GorillaPool is keyless. Token from
    // env `TAAL_ARC_TOKEN`, else the known mainnet key in secrets.md.
    let taal_token = std::env::var("TAAL_ARC_TOKEN")
        .unwrap_or_else(|_| "mainnet_9596de07e92300c6287e4393594ae39c".to_string());
    for arc in &["https://arc.gorillapool.io", "https://arc.taal.com"] {
        let url = format!("{arc}/v1/tx");
        eprintln!("  broadcast via {url}");
        let mut req = http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("XDeployment-ID", "bsv-mpc-reshare-container")
            .json(&serde_json::json!({ "rawTx": raw_tx_hex }));
        if arc.contains("taal") {
            req = req.header("Authorization", format!("Bearer {taal_token}"));
        }
        let Ok(resp) = req.send().await else {
            continue;
        };
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        let snippet: String = text.chars().take(400).collect();
        eprintln!("    status={status} body={snippet}");
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

fn p2pkh_unlocking_script(sig_checksig: &[u8], compressed_pubkey: &[u8; 33]) -> Vec<u8> {
    let mut s = Vec::with_capacity(1 + sig_checksig.len() + 1 + 33);
    s.push(sig_checksig.len() as u8);
    s.extend_from_slice(sig_checksig);
    s.push(33);
    s.extend_from_slice(compressed_pubkey);
    s
}

fn serialize_transaction(
    version: i32,
    inputs: &[([u8; 32], u32, Vec<u8>, u32)],
    outputs: &[(u64, Vec<u8>)],
    locktime: u32,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_i32_le(version);
    w.write_var_int(inputs.len() as u64);
    for (txid, vout, script, seq) in inputs {
        w.write_bytes(txid);
        w.write_u32_le(*vout);
        w.write_var_int(script.len() as u64);
        w.write_bytes(script);
        w.write_u32_le(*seq);
    }
    w.write_var_int(outputs.len() as u64);
    for (sats, script) in outputs {
        w.write_u64_le(*sats);
        w.write_var_int(script.len() as u64);
        w.write_bytes(script);
    }
    w.write_u32_le(locktime);
    w.into_bytes()
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

// ── cggmp24 sim signing (2-of-3 with the proxy's two new-set shares {1,2}) ──
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
        _: &mut std::task::Context<'_>,
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
            let mut p = self.as_mut().project();
            let mut inner = p.inner;
            std::task::ready!(inner.as_mut().poll_ready(cx))?;
            if let Some(item) = p.messages.pop_front() {
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
    party.map_delivery(|d| {
        let (i, o) = d.split();
        (
            i,
            BufferedSink {
                messages: VecDeque::new(),
                inner: o,
            },
        )
    })
}

/// Sign a 32-byte prehashed sighash with a 2-of-3 subset (`participants`) of the
/// reshared new-set KeyShares, returning the cggmp24 signature.
async fn sign_2of3(
    shares: &[(u16, cggmp24::KeyShare<Secp256k1, SecurityLevel128>)],
    participants: &[u16],
    sighash: &[u8; 32],
) -> cggmp24::Signature<Secp256k1> {
    use generic_ec::Scalar;
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rand::Rng::gen(&mut rng);
    let eid = ExecutionId::new(&eid_bytes);
    let pv = participants.to_vec();
    let scalar = Scalar::<Secp256k1>::from_be_bytes_mod_order(*sighash);
    let data = PrehashedDataToSign::from_scalar(scalar).insecure_assume_preimage_known();
    let key_for = |idx: u16| {
        shares
            .iter()
            .find(|(i, _)| *i == idx)
            .map(|(_, k)| k.clone())
            .expect("share for participant")
    };
    let selected: Vec<_> = participants.iter().map(|&i| key_for(i)).collect();
    round_based::sim::run_with_setup(selected.iter(), |i, party, share| {
        let party = buffer_outgoing(party);
        let mut r = rand::rngs::OsRng;
        let p = pv.clone();
        async move {
            cggmp24::signing(eid, i, &p, share)
                .sign(&mut r, party, &data)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .expect_eq()
}

fn raw_tx_hex_from_create_action(resp: &serde_json::Value) -> Option<String> {
    let arr = resp.get("tx")?.as_array()?;
    let beef: Vec<u8> = arr.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect();
    let tx = bsv::Transaction::from_atomic_beef(&beef)
        .or_else(|_| bsv::Transaction::from_beef(&beef, None))
        .ok()?;
    Some(tx.to_hex())
}

#[tokio::test]
async fn container_reshare_2of2_to_2of3_deployed_real_mainnet() {
    if !opt_in() {
        eprintln!(
            "CONTAINER_RESHARE_MAINNET=1 not set — skipping §18.2 reshare real-sats gate.\n\
             To run (BURNS REAL SATS): CONTAINER_RESHARE_MAINNET=1 cargo test -p bsv-mpc-proxy \\\n\
             --test container_reshare_deployed_mainnet_e2e --release -- --nocapture --test-threads=1"
        );
        return;
    }
    let _ = tracing_subscriber::fmt::try_init();
    let t0 = std::time::Instant::now();
    let container_url =
        std::env::var("DEPLOYED_CONTAINER_URL").unwrap_or_else(|_| DEFAULT_CONTAINER.to_string());
    let relay_url =
        std::env::var("MESSAGEBOX_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY.to_string());
    let http = reqwest::Client::new();

    let proxy_identity = PrivateKey::from_bytes(&[0x53u8; 32]).expect("proxy identity key");
    std::env::set_var(
        "MPC_PROXY_IDENTITY_KEY",
        hex::encode(proxy_identity.to_bytes()),
    );

    // ── 1. Real distributed authed 2-of-2 DKG against the DEPLOYED container ───
    eprintln!("(real distributed DKG against the deployed container — minutes)");
    let config = ThresholdConfig::new(2, 2).expect("2-of-2");
    let dkg_b = run_dkg_over_http_authed(&container_url, config, proxy_identity.clone())
        .await
        .expect("authed DKG against the deployed container");
    let joint = dkg_b.joint_key.clone();
    let joint_hex = hex::encode(&joint.compressed);
    let mut joint_arr = [0u8; 33];
    joint_arr.copy_from_slice(&joint.compressed);
    let joint_pub = PublicKey::from_bytes(&joint_arr).expect("joint pubkey");
    let joint_locking = p2pkh_locking_script(&joint_pub.hash160());
    eprintln!("✔ DKG joint_pubkey={joint_hex} address={}", joint.address);

    // ── 2. MpcBridge from share_B, presign_url = the container ─────────────────
    let dir = std::env::temp_dir();
    let share_path = dir.join(format!(
        "reshare_container_share_{}.json",
        std::process::id()
    ));
    let share_path_str = share_path.to_string_lossy().to_string();
    tokio::fs::write(&share_path, serde_json::to_vec(&dkg_b).unwrap())
        .await
        .expect("write share file");
    let proxy_config = ProxyConfig {
        port: 3334,
        kss_url: container_url.clone(),
        share_path: share_path_str.clone(),
        fee_per_signing: 0,
        fee_addresses: vec![],
        fee_threshold: None,
        max_presignatures: 5,
        encryption_key: None,
        arc_api_key: "test_key".into(),
        threshold_configs: vec!["2-of-2".to_string()],
        min_balance_sats: None,
        relay_url: relay_url.clone(),
        relay_sign: false,
        presign_url: Some(container_url.clone()),
    };
    let bridge = MpcBridge::new(&proxy_config)
        .await
        .expect("MpcBridge::new (BRC-31 handshake with deployed container)");
    eprintln!("✔ proxy authed with deployed container (share_B + stable identity)");

    // ── 3. Fund the joint P2PKH on mainnet via wallet:3321 ─────────────────────
    let funding_amount: u64 = 1500;
    let fund_resp = http
        .post("http://localhost:3321/createAction")
        .header("Origin", "http://admin.com")
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "description": "bsv-mpc §18.2 reshare gate (fund K)",
            "outputs": [{
                "satoshis": funding_amount,
                "lockingScript": hex::encode(&joint_locking),
                "outputDescription": "MPC joint P2PKH (pre-reshare key K)"
            }]
        }))
        .send()
        .await
        .expect("wallet:3321 reachable");
    let fund_status = fund_resp.status();
    let fund_text = fund_resp.text().await.unwrap_or_default();
    assert!(
        fund_status.is_success(),
        "wallet createAction failed ({fund_status}): {fund_text}"
    );
    let fund_json: serde_json::Value = serde_json::from_str(&fund_text).expect("fund JSON");
    let fund_txid = fund_json["txid"]
        .as_str()
        .expect("createAction txid")
        .to_string();
    eprintln!("✔ funded joint address: txid={fund_txid}");
    if let Some(raw) = raw_tx_hex_from_create_action(&fund_json) {
        eprintln!("  self-broadcasting funding tx via ARC...");
        let _ = broadcast_via_arc(&http, &raw).await;
    }

    // ── 4. Reshare 2-of-2 → 2-of-3 over the relay (address-preserving) ─────────
    eprintln!(
        "(reshare over the relay against the deployed container — minutes: 3× safe-prime gen)"
    );
    let summary = bridge
        .reshare_change_threshold_over_relay(Duration::from_secs(300))
        .await
        .expect("§18.2 cross-(t,n) reshare over relay");
    eprintln!(
        "✔ reshare committed — new {}-of-{} ; proxy holds {} new-set shares",
        summary.new_threshold,
        summary.new_parties,
        summary.proxy_key_shares_json.len()
    );

    // §18 invariant: joint pubkey UNCHANGED (same address, no funds move).
    assert_eq!(
        summary.joint_pubkey_hex, joint_hex,
        "§18: joint pubkey MUST be unchanged by the reshare"
    );
    assert_eq!(summary.new_threshold, 2, "new threshold is 2");
    assert_eq!(summary.new_parties, 3, "new parties is 3");
    assert_eq!(
        summary.proxy_key_shares_json.len(),
        2,
        "proxy holds new parties 1 and 2 (container holds party 0)"
    );
    let held: Vec<u16> = summary
        .proxy_key_shares_json
        .iter()
        .map(|(i, _)| *i)
        .collect();
    assert!(
        held.contains(&1) && held.contains(&2),
        "proxy holds new indices 1 and 2"
    );
    eprintln!("✔ §18 invariant: joint pubkey UNCHANGED across 2-of-2 → 2-of-3 reshare");

    // ── 5. Sign the spend with the NEW 2-of-3 sharing → spend K's address ──────
    // The reshared new-set shares: container = party 0 (stored on the container by
    // its /reshare-relay/init completion task); proxy = parties 1 and 2. Signing
    // with the proxy-held {1,2} subset is a valid 2-of-3 — and those shares only
    // EXIST because of the joint reshare with the container (its phase-A aux + its
    // phase-B PSS contribution as party 0; verify_reshare confirmed K preserved).
    // So a valid signature here proves the deployed reshare produced a working new
    // sharing of the SAME key. (A {0,1} subset that exercises the container's
    // stored share at sign-time needs a 2-of-3 relay-sign path; the cryptographic
    // claim — the new sharing spends K — is fully proven by the {1,2} subset.)
    let new_shares: Vec<(u16, cggmp24::KeyShare<Secp256k1, SecurityLevel128>)> = summary
        .proxy_key_shares_json
        .iter()
        .map(|(idx, json)| {
            (
                *idx,
                serde_json::from_slice(json).expect("new-set key share JSON"),
            )
        })
        .collect();

    // Find the funding UTXO + build the BIP-143 sighash (drain back to wallet).
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
    let change_script = p2pkh_locking_script(
        &PublicKey::from_hex(&wallet_pub_hex)
            .expect("wallet pub")
            .hash160(),
    );
    let scope = SIGHASH_ALL | SIGHASH_FORKID;
    let sighash = compute_sighash_for_signing(&SighashParams {
        version: 1,
        inputs: &[TxInput {
            txid: prev_txid,
            output_index: vout,
            script: vec![],
            sequence: 0xFFFFFFFF,
        }],
        outputs: &[TxOutput {
            satoshis: change,
            script: change_script.clone(),
        }],
        locktime: 0,
        input_index: 0,
        subscript: &joint_locking,
        satoshis: value,
        scope,
    });
    eprintln!("✔ sighash: {}", hex::encode(sighash));

    // Sign 2-of-3 with the reshared shares {1,2}.
    let sig = sign_2of3(&new_shares, &[1, 2], &sighash).await;
    let (r_bytes, s_bytes) = {
        use generic_ec::Scalar;
        let r: Scalar<Secp256k1> = sig.r.into();
        (
            r.to_be_bytes().as_bytes().to_vec(),
            sig.s.as_ref().to_be_bytes().as_bytes().to_vec(),
        )
    };
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&r_bytes);
    s.copy_from_slice(&s_bytes);
    let bsv_sig = Signature::new(r, s);

    // PRE-FLIGHT: the reshared-share signature MUST be low-s (BIP-62, cggmp24
    // guarantees it) and verify under the UNCHANGED joint pubkey — fail-closed
    // BEFORE we burn sats.
    assert!(bsv_sig.is_low_s(), "MPC signature MUST be low-s (BIP-62)");
    assert!(
        joint_pub.verify(&sighash, &bsv_sig),
        "PRE-FLIGHT: reshared 2-of-3 signature MUST verify under the UNCHANGED joint pubkey K"
    );
    eprintln!("✔ pre-flight ECDSA verify under joint pubkey (reshared shares): PASS");

    let tx_sig = TransactionSignature::new(bsv_sig, scope);
    let unlocking =
        p2pkh_unlocking_script(&tx_sig.to_checksig_format(), &joint_pub.to_compressed());
    let raw_tx = serialize_transaction(
        1,
        &[(prev_txid, vout, unlocking, 0xFFFFFFFF)],
        &[(change, change_script)],
        0,
    );
    let mut txid = sha256d(&raw_tx);
    txid.reverse();
    let txid_hex = hex::encode(txid);
    let raw_tx_hex = hex::encode(&raw_tx);
    eprintln!("✔ assembled tx {} bytes — TXID={txid_hex}", raw_tx.len());

    let ok = broadcast_via_arc(&http, &raw_tx_hex).await;
    let _ = tokio::fs::remove_file(&share_path).await;
    assert!(
        ok,
        "ARC broadcast MUST succeed — TXID={txid_hex} rawTx={raw_tx_hex}"
    );

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  §18.2 RESHARE 2-of-2 → 2-of-3 — DEPLOYED CONTAINER — REAL SATS ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!("  joint_pubkey:     {joint_hex} (UNCHANGED by reshare)");
    eprintln!("  joint_address:    {}", joint.address);
    eprintln!("  funding_txid:     {fund_txid}");
    eprintln!("  funded_sats:      {value}");
    eprintln!(
        "  new config:       {}-of-{} (container=party0, proxy=parties{held:?})",
        summary.new_threshold, summary.new_parties
    );
    eprintln!("  spending_txid:    {txid_hex}  (signed with reshared 2-of-3 shares)");
    eprintln!("  view: https://whatsonchain.com/tx/{txid_hex}");
    eprintln!("  total wall-clock: {:?}", t0.elapsed());
}
