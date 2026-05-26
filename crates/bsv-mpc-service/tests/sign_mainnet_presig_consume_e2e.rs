//! **MPC-Spec #4 item-7 / issue #25 capstone** — a real-mainnet e2e proving
//! §06.20 (sign-time consume of a BRC-2-encrypted presig share) produces a
//! valid on-chain BSV signature. Real sats burned.
//!
//! This is the on-chain proof that the §06.16 → §06.20 encrypted-share
//! round-trip integrates with real BSV signing end-to-end:
//!
//!   1. Local real 2-of-2 DKG (`run_dkg_2of2` — keygen + auxinfo via the
//!      `round_based` simulator). Yields the joint key + P2PKH address.
//!   2. Presignatures generated IN-PROCESS via the same simulator
//!      (`cggmp24::signing(...).generate_presignature`), mirroring
//!      `signing.rs::coordinator_presigned_1round_sign`. Party 0 (coordinator)
//!      keeps its `(Presignature, PresignaturePublicData)` tuple **in memory**
//!      (`PresignaturePublicData` isn't `Serialize` — documented in-memory
//!      approach). Party 1 (cosigner) holds its `Presignature`.
//!   3. The cosigner BRC-2-self-encrypts its presig share (§06.16):
//!      `ct = encrypt_presig_share(wallet, presig_id, serde_json(presig1.0))`.
//!      This `ct` is exactly the bundle's `cosigner_encrypted_share`.
//!   4. Fund the joint P2PKH address from wallet:3321, find the UTXO on WoC,
//!      build a spending tx + BIP-143 sighash (drain back to the wallet).
//!   5. §06.20 SIGN of that sighash:
//!        - coordinator: `SigningCoordinator::sign_with_presignature` →
//!          its own partial.
//!        - cosigner: `decrypt_and_issue_partial(wallet, presig_id, ct,
//!          sighash, None)` → its partial JSON (the §06.20 consume path).
//!        - coordinator combines via `process_round` → `SigningResult`.
//!   6. **Pre-flight ECDSA verify** against the joint pubkey BEFORE broadcast
//!      — we never burn sats on an invalid signature.
//!   7. Broadcast the fully-signed tx via ARC; assert a TXID + accepted /
//!      SEEN_ON_NETWORK status.
//!
//! Gated on **both** (NEVER runs in CI):
//! - `MESSAGEBOX_RELAY_URL` — opt-in to live e2e (mirrors the proven harness'
//!   opt-in even though this test does not touch the relay)
//! - `E2E_MAINNET=1` — opt-in to spending real sats
//!
//! Requires:
//! - A BRC-100 wallet at `http://localhost:3321` with spendable sats in the
//!   `default` basket (admin-reserved → header `Origin: http://admin.com`).
//! - Outbound network to `api.whatsonchain.com` (UTXO discovery) and
//!   `arc.taal.com` / `arc.gorillapool.io` (broadcast).
//!
//! Run (BURNS REAL SATS):
//!
//! ```bash
//! MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
//! E2E_MAINNET=1 \
//!   cargo test -p bsv-mpc-service \
//!     --test sign_mainnet_presig_consume_e2e \
//!     --release -- --nocapture --test-threads=1
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
use bsv_mpc_core::presig_encryption::{
    decrypt_and_issue_partial, encrypt_presig_share, wallet_from_identity,
};
use bsv_mpc_core::signing::{SigningCoordinator, SigningRoundResult};
use bsv_mpc_core::types::{EncryptedShare, RoundMessage, SessionId, ShareIndex, ThresholdConfig};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::signing::PresignaturePublicData;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::{ExecutionId, Presignature};
use rand::RngCore;

// ---------------------------------------------------------------------------
// Opt-in gate — mirror of sign_mainnet_via_messagebox_e2e::opt_in.
// ---------------------------------------------------------------------------

fn opt_in() -> Option<String> {
    let relay = std::env::var("MESSAGEBOX_RELAY_URL").ok()?;
    let mainnet = std::env::var("E2E_MAINNET").ok()?;
    if mainnet != "1" {
        return None;
    }
    Some(relay)
}

fn fresh_priv() -> PrivateKey {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0] |= 0x01;
    PrivateKey::from_bytes(&b).expect("fresh priv must be valid")
}

// ---------------------------------------------------------------------------
// Tx assembly helpers — copied verbatim from sign_mainnet_via_messagebox_e2e.
// ---------------------------------------------------------------------------

fn p2pkh_locking_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // push 20 bytes
    script.extend_from_slice(pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}

fn p2pkh_unlocking_script(sig_checksig: &[u8], compressed_pubkey: &[u8; 33]) -> Vec<u8> {
    let mut script = Vec::with_capacity(1 + sig_checksig.len() + 1 + 33);
    script.push(sig_checksig.len() as u8);
    script.extend_from_slice(sig_checksig);
    script.push(33);
    script.extend_from_slice(compressed_pubkey);
    script
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
    let url = format!(
        "https://api.whatsonchain.com/v1/bsv/main/tx/hash/{}",
        fund_txid
    );
    for attempt in 1..=8 {
        let wait_secs = attempt * 3;
        eprintln!("  attempt {attempt}: waiting {wait_secs}s for WoC indexing...");
        tokio::time::sleep(Duration::from_secs(wait_secs)).await;
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
            let script_hex = vout["scriptPubKey"]["hex"].as_str().unwrap_or("");
            if script_hex == expected_locking_hex {
                let n = vout["n"].as_u64().unwrap_or(0) as u32;
                let value_bsv = vout["value"].as_f64().unwrap_or(0.0);
                let value_sats = (value_bsv * 100_000_000.0 + 0.5) as u64;
                return Some((n, value_sats));
            }
        }
    }
    None
}

async fn broadcast_via_arc(http: &reqwest::Client, raw_tx_hex: &str) -> bool {
    for arc_url in &["https://arc.taal.com", "https://arc.gorillapool.io"] {
        let url = format!("{}/v1/tx", arc_url);
        eprintln!("  broadcast attempt via {url}");
        let resp = http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("XDeployment-ID", "bsv-mpc-presig-consume")
            .json(&serde_json::json!({ "rawTx": raw_tx_hex }))
            .send()
            .await;
        let Ok(resp) = resp else { continue };
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        let snippet: String = text.chars().take(400).collect();
        eprintln!("    status={status}  body={snippet}");
        if status.is_success()
            || text.contains("SEEN_ON_NETWORK")
            || text.contains("STORED")
            || text.contains("MINED")
        {
            eprintln!("    BROADCAST SUCCESS via {arc_url}");
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Local 2-of-2 DKG + presign via the round_based simulator — mirror of
// presign_2of2_via_messagebox_e2e::{buffer_outgoing, generate_pregenerated_primes,
// run_dkg_2of2} and signing.rs::coordinator_presigned_1round_sign.
// ---------------------------------------------------------------------------

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

fn generate_blum_prime(rng: &mut impl rand::RngCore, bits_size: u32) -> cggmp24::backend::Integer {
    use cggmp24::backend::Integer;
    loop {
        let n = Integer::generate_prime(rng, bits_size);
        if n.mod_u(4) == 3 {
            break n;
        }
    }
}

fn generate_pregenerated_primes(
    rng: &mut impl rand::RngCore,
) -> cggmp24::PregeneratedPrimes<SecurityLevel128> {
    use cggmp24::security_level::SecurityLevel;
    let bitsize = SecurityLevel128::RSA_PRIME_BITLEN;
    let primes = [
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
    ];
    cggmp24::PregeneratedPrimes::try_from(primes).expect("primes have wrong bit size")
}

async fn run_dkg_2of2() -> Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> {
    use rand::Rng;

    let mut rng = rand::rngs::OsRng;
    let n: u16 = 2;
    let t: u16 = 2;

    let eid_bytes: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid_bytes);

    let incomplete_shares = round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut party_rng = rand::rngs::OsRng;
        async move {
            cggmp24::keygen::<Secp256k1>(eid, i, n)
                .set_threshold(t)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    let eid_bytes_aux: [u8; 32] = rng.gen();
    let eid_aux = ExecutionId::new(&eid_bytes_aux);
    let primes: Vec<_> = (0..n)
        .map(|_| generate_pregenerated_primes(&mut rng))
        .collect();

    let aux_infos = round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut party_rng = rand::rngs::OsRng;
        let pregenerated = primes[usize::from(i)].clone();
        async move {
            cggmp24::aux_info_gen(eid_aux, i, n, pregenerated)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    incomplete_shares
        .into_iter()
        .zip(aux_infos)
        .map(|(share, aux)| {
            cggmp24::KeyShare::from_parts((share, aux)).expect("key share validation passes")
        })
        .collect()
}

/// Generate the 2-of-2 presignatures in-process via the simulator. Returns
/// `[(Presignature, PresignaturePublicData); 2]` keyed by party index — mirror
/// of `signing.rs::coordinator_presigned_1round_sign`.
async fn generate_presignatures_2of2(
    key_shares: &[cggmp24::KeyShare<Secp256k1, SecurityLevel128>],
) -> Vec<(Presignature<Secp256k1>, PresignaturePublicData<Secp256k1>)> {
    use rand::Rng;
    let participants: Vec<u16> = vec![0, 1];
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rng.gen();
    let eid_presign = ExecutionId::new(&eid_bytes);
    round_based::sim::run_with_setup(
        participants.iter().map(|i| &key_shares[usize::from(*i)]),
        |i, party, share| {
            let party = buffer_outgoing(party);
            let mut party_rng = rand::rngs::OsRng;
            let participants = participants.clone();
            async move {
                cggmp24::signing(eid_presign, i, &participants, share)
                    .generate_presignature(&mut party_rng, party)
                    .await
            }
        },
    )
    .unwrap()
    .expect_ok()
    .into_vec()
}

/// Wrap a cggmp24 KeyShare into our `EncryptedShare` (placeholder at-rest
/// encryption — `ciphertext` holds the plaintext JSON, the format
/// `SigningCoordinator` deserializes). Mirror of `signing.rs::key_share_to_encrypted`.
fn key_share_to_encrypted(
    key_share: &cggmp24::KeyShare<Secp256k1, SecurityLevel128>,
    index: u16,
    config: ThresholdConfig,
    session_id: SessionId,
) -> EncryptedShare {
    EncryptedShare {
        nonce: vec![0u8; 12],
        ciphertext: serde_json::to_vec(key_share).expect("key share serialize"),
        session_id,
        share_index: ShareIndex(index),
        config,
        joint_pubkey_compressed: key_share.core.shared_public_key.to_bytes(true).to_vec(),
    }
}

// ---------------------------------------------------------------------------
// THE CAPSTONE
// ---------------------------------------------------------------------------

#[tokio::test]
async fn within_stack_2of2_sign_mainnet_via_presig_consume() {
    let Some(_relay_url) = opt_in() else {
        eprintln!(
            "MESSAGEBOX_RELAY_URL + E2E_MAINNET=1 not both set — skipping §06.20 presig-consume mainnet TX.
To run (BURNS REAL SATS):
  MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \\
  E2E_MAINNET=1 \\
    cargo test -p bsv-mpc-service --test sign_mainnet_presig_consume_e2e \\
      --release -- --nocapture --test-threads=1"
        );
        return;
    };
    let _ = tracing_subscriber::fmt::try_init();
    let t0 = std::time::Instant::now();

    let config = ThresholdConfig::new(2, 2).expect("2-of-2");
    let participants: Vec<u16> = vec![0, 1];

    // ============ 1) Local real 2-of-2 DKG ============
    eprintln!("(generating real 2-of-2 key shares locally — Paillier primes, ~30-60s)");
    let dkg_t0 = std::time::Instant::now();
    let key_shares = run_dkg_2of2().await;
    eprintln!("✔ key shares ready in {:?}", dkg_t0.elapsed());

    let joint_compressed = key_shares[0].core.shared_public_key.to_bytes(true);
    let mut joint_pubkey_arr = [0u8; 33];
    joint_pubkey_arr.copy_from_slice(joint_compressed.as_ref());
    let joint_pubkey =
        PublicKey::from_bytes(&joint_pubkey_arr).expect("joint pubkey from compressed bytes");
    let joint_address = joint_pubkey.to_address();
    eprintln!(
        "✔ DKG complete — joint_pubkey={} address={}",
        hex::encode(joint_pubkey_arr),
        joint_address
    );

    // ============ 2) Presignatures IN-PROCESS via the simulator ============
    eprintln!("(generating 2-of-2 presignatures in-process)");
    let presig_t0 = std::time::Instant::now();
    let presigs = generate_presignatures_2of2(&key_shares).await;
    assert_eq!(presigs.len(), 2, "expect one presig tuple per party");
    let mut it = presigs.into_iter();
    // Party 0 = coordinator: keeps its (Presignature, PresignaturePublicData)
    // tuple IN MEMORY (PresignaturePublicData isn't Serialize).
    let presig0 = it.next().unwrap();
    // Party 1 = cosigner.
    let presig1 = it.next().unwrap();
    eprintln!("✔ presignatures generated in {:?}", presig_t0.elapsed());

    // ============ 3) Cosigner BRC-2-encrypts its presig share (§06.16) ============
    let cosigner_priv = fresh_priv();
    let cosigner_wallet = wallet_from_identity(&cosigner_priv);
    // presig_id binds the BRC-2 key (protocol_id + key_id). Any stable id works
    // for the round-trip; we mint a fresh random one for this ceremony.
    let presig_id = {
        let mut b = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut b);
        format!("presig-consume-{}", hex::encode(b))
    };
    let cosigner_share_bytes =
        serde_json::to_vec(&presig1.0).expect("serialize cosigner presig share");
    let ct = encrypt_presig_share(&cosigner_wallet, &presig_id, &cosigner_share_bytes)
        .expect("§06.16 BRC-2 encrypt cosigner presig share");
    assert!(!ct.is_empty(), "cosigner ciphertext must be non-empty");
    // Prove the coordinator could NOT decrypt it (opaque at rest, §06.17.1).
    let coord_priv = fresh_priv();
    assert!(
        decrypt_and_issue_partial(
            &wallet_from_identity(&coord_priv),
            &presig_id,
            &ct,
            &[0u8; 32],
            None,
        )
        .is_err(),
        "coordinator MUST NOT be able to decrypt the cosigner's share"
    );
    eprintln!(
        "✔ cosigner BRC-2-encrypted its presig share (§06.16) — presig_id={presig_id} ct={} bytes",
        ct.len()
    );

    // ============ 4) Fund the joint address via wallet:3321 ============
    let http = reqwest::Client::new();
    let funding_amount: u64 = 1500;
    let joint_locking = p2pkh_locking_script(&joint_pubkey.hash160());

    let fund_resp = http
        .post("http://localhost:3321/createAction")
        .header("Origin", "http://admin.com")
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "description": "bsv-mpc #25 §06.20 presig-consume mainnet test",
            "outputs": [{
                "satoshis": funding_amount,
                "lockingScript": hex::encode(&joint_locking),
                "outputDescription": "MPC joint P2PKH (presig-consume)"
            }],
            "options": { "acceptDelayedBroadcast": false }
        }))
        .send()
        .await
        .expect("wallet:3321 reachable — start bsv-wallet-cli first");
    let fund_status = fund_resp.status();
    let fund_text = fund_resp.text().await.unwrap_or_default();
    assert!(
        fund_status.is_success(),
        "wallet:3321 createAction failed ({fund_status}): {fund_text}"
    );
    let fund_json: serde_json::Value = serde_json::from_str(&fund_text).expect("fund resp JSON");
    let fund_txid = fund_json["txid"]
        .as_str()
        .expect("createAction response MUST include txid")
        .to_string();
    eprintln!("✔ funded joint address via wallet:3321: txid={fund_txid}");

    // ============ Find our UTXO via WhatsOnChain ============
    let mpc_locking_hex = hex::encode(&joint_locking);
    let (utxo_vout, utxo_value) = find_utxo_on_woc(&http, &fund_txid, &mpc_locking_hex)
        .await
        .expect("MUST find funding UTXO on WoC within retries");
    eprintln!("✔ UTXO indexed: {fund_txid}:{utxo_vout} ({utxo_value} sats)");

    // ============ Build spending tx + BIP-143 sighash ============
    let mut prev_txid = [0u8; 32];
    let txid_bytes = hex::decode(&fund_txid).expect("valid funding txid hex");
    prev_txid.copy_from_slice(&txid_bytes);
    prev_txid.reverse(); // display → internal byte order

    let fee: u64 = 100;
    let change = utxo_value.checked_sub(fee).expect("UTXO must cover fee");

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
        .expect("publicKey field")
        .to_string();
    let wallet_pubkey = PublicKey::from_hex(&wallet_pub_hex).expect("wallet pub");
    let change_script = p2pkh_locking_script(&wallet_pubkey.hash160());

    let scope = SIGHASH_ALL | SIGHASH_FORKID;
    let sighash_inputs = vec![TxInput {
        txid: prev_txid,
        output_index: utxo_vout,
        script: vec![],
        sequence: 0xFFFFFFFF,
    }];
    let sighash_outputs = vec![TxOutput {
        satoshis: change,
        script: change_script.clone(),
    }];
    let sighash = compute_sighash_for_signing(&SighashParams {
        version: 1,
        inputs: &sighash_inputs,
        outputs: &sighash_outputs,
        locktime: 0,
        input_index: 0,
        subscript: &joint_locking,
        satoshis: utxo_value,
        scope,
    });
    eprintln!("✔ sighash: {}", hex::encode(sighash));

    // ============ 5) §06.20 SIGN of that sighash ============
    // Coordinator (party 0): build a SigningCoordinator over its own share and
    // issue its partial via sign_with_presignature (holds the public data).
    let session = SessionId::from_str_hash("presig-consume-mainnet");
    let coord_share = key_share_to_encrypted(&key_shares[0], 0, config, session);
    let mut coord = SigningCoordinator::new(session, coord_share, config, participants.clone());
    let _out0 = coord
        .sign_with_presignature(&sighash, Box::new(presig0))
        .expect("coordinator issue partial via presignature");

    // Cosigner (party 1): the §06.20 consume path — decrypt the BRC-2
    // ciphertext under (cosigner wallet, presig_id) and issue its partial.
    // None = base key (no BRC-42 offset for this P2PKH).
    let partial1_json =
        decrypt_and_issue_partial(&cosigner_wallet, &presig_id, &ct, &sighash, None)
            .expect("§06.20 decrypt cosigner ciphertext + issue partial");
    eprintln!("✔ cosigner produced partial via §06.20 decrypt-and-issue");

    // Coordinator combines its own partial + the cosigner's (signing index 1).
    let combine_result = coord
        .process_round(vec![RoundMessage {
            session_id: session,
            round: 1,
            from: ShareIndex(1),
            to: None,
            payload: partial1_json,
        }])
        .expect("coordinator combine");
    let signing_result = match combine_result {
        SigningRoundResult::Complete(r) => r,
        SigningRoundResult::NextRound(_) => {
            panic!("§06.20 1-round consume MUST complete in a single round")
        }
    };
    eprintln!(
        "✔ §06.20 sign complete — DER sig {} bytes",
        signing_result.signature.len()
    );

    // ============ 6) PRE-FLIGHT ECDSA verify (NO broadcast on failure) ============
    let mut r_arr = [0u8; 32];
    let mut s_arr = [0u8; 32];
    r_arr.copy_from_slice(&signing_result.r);
    s_arr.copy_from_slice(&signing_result.s);
    let bsv_sig = Signature::new(r_arr, s_arr);
    assert!(
        bsv_sig.is_low_s(),
        "MPC signature MUST be low-s (BIP-62) — refusing to broadcast otherwise"
    );
    assert!(
        joint_pubkey.verify(&sighash, &bsv_sig),
        "PRE-FLIGHT: §06.20-derived signature MUST verify against joint pubkey before we burn sats"
    );
    eprintln!("✔ pre-flight ECDSA verify against joint pubkey: PASS");

    // ============ Build unlocking script + serialize tx ============
    let tx_sig = TransactionSignature::new(bsv_sig, scope);
    let checksig_bytes = tx_sig.to_checksig_format();
    let compressed_joint_pub = joint_pubkey.to_compressed();
    let unlocking = p2pkh_unlocking_script(&checksig_bytes, &compressed_joint_pub);

    let raw_tx = serialize_transaction(
        1,
        &[(prev_txid, utxo_vout, unlocking, 0xFFFFFFFF)],
        &[(change, change_script)],
        0,
    );
    let txid = sha256d(&raw_tx);
    let mut txid_display = txid;
    txid_display.reverse();
    let txid_hex = hex::encode(txid_display);
    eprintln!(
        "✔ assembled raw tx: {} bytes — TXID={}",
        raw_tx.len(),
        txid_hex
    );

    // ============ 7) Broadcast via ARC ============
    let raw_tx_hex = hex::encode(&raw_tx);
    let broadcast_ok = broadcast_via_arc(&http, &raw_tx_hex).await;
    assert!(
        broadcast_ok,
        "ARC broadcast MUST succeed — TXID={txid_hex}, rawTx=\"{raw_tx_hex}\""
    );

    eprintln!();
    eprintln!("╔═══════════════════════════════════════════════════════════════╗");
    eprintln!("║  #25 §06.20 PRESIG-CONSUME MAINNET TX — SIGNED VIA            ║");
    eprintln!("║  DECRYPTED BRC-2 PRESIG SHARE                                ║");
    eprintln!("╚═══════════════════════════════════════════════════════════════╝");
    eprintln!("  presig_id: {}", presig_id);
    eprintln!("  joint_pubkey: {}", hex::encode(joint_pubkey_arr));
    eprintln!("  joint_address: {}", joint_address);
    eprintln!("  funding_txid: {}", fund_txid);
    eprintln!("  funded_satoshis: {}", utxo_value);
    eprintln!("  spending_txid: {}", txid_hex);
    eprintln!("  drained_back: {} sats (fee: {})", change, fee);
    eprintln!("  view: https://whatsonchain.com/tx/{}", txid_hex);
    eprintln!("  total wall-clock: {:?}", t0.elapsed());
}
