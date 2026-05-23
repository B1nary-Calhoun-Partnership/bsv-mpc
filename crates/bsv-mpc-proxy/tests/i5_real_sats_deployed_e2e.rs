//! **#16 / I-5 MERGE GATE — real-sats mainnet TXID, deployed cosigner.**
//!
//! The capstone: a real BSV mainnet transaction co-signed by the **proxy**
//! (`share_B`) and the **DEPLOYED** `bsv-mpc-worker` Durable Object (`share_A`'s
//! partial, issued over the live MessageBox relay), then broadcast. This is the
//! within-stack Phase-E flow (`sign_mainnet_via_messagebox_e2e.rs`) except one
//! cosigner is the real deployed CF Worker, reached through the ADR-018 hybrid
//! relay path (`relay_sign::combine_sign_over_relay`, #12) — not an in-process
//! peer.
//!
//! REAL SATS. Gated on **`E2E_MAINNET=1`** (never runs in CI). Requires a
//! BRC-100 wallet at `http://localhost:3321` (Origin `http://admin.com`) with
//! spendable sats, plus outbound to WhatsOnChain (UTXO) + ARC (broadcast).
//! `DEPLOYED_WORKER_URL` / `MESSAGEBOX_RELAY_URL` default to the Calhoun
//! `dev-a3e` deployments.
//!
//! ```bash
//! E2E_MAINNET=1 cargo test -p bsv-mpc-proxy \
//!   --test i5_real_sats_deployed_e2e --release -- --nocapture --test-threads=1
//! ```
//!
//! God-tier gates (fail-closed — no sats burned on a bad signature):
//! - DKG joint-pubkey agreement asserted before funding.
//! - PRE-FLIGHT: low-s (BIP-62) + `joint_pubkey.verify(sighash, sig)` BEFORE broadcast.
//! - Broadcast failure ⇒ test failure (no TXID is the failure signal).

use std::time::Duration;

use bsv::primitives::bsv::sighash::{
    compute_sighash_for_signing, SighashParams, TxInput, TxOutput, SIGHASH_ALL, SIGHASH_FORKID,
};
use bsv::primitives::bsv::tx_signature::TransactionSignature;
use bsv::primitives::ec::{PrivateKey, PublicKey, Signature};
use bsv::primitives::encoding::Writer;
use bsv::primitives::hash::sha256d;
use bsv_mpc_core::dkg::{generate_test_primes, DkgCoordinator, DkgRoundResult};
use bsv_mpc_core::presigning::{PresigningManager, PresigningRoundResult};
use bsv_mpc_core::types::{EncryptedShare, JointPublicKey, SessionId, ShareIndex, ThresholdConfig};
use bsv_mpc_proxy::relay_sign::{combine_sign_over_relay, DoTrigger};
use rand::RngCore;

const DEFAULT_WORKER: &str = "https://bsv-mpc-kss.dev-a3e.workers.dev";
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";

type PresignBox = Box<dyn std::any::Any + Send>;

fn opt_in() -> bool {
    std::env::var("E2E_MAINNET").ok().as_deref() == Some("1")
}

fn fresh_priv() -> PrivateKey {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0] |= 0x01;
    PrivateKey::from_bytes(&b).expect("fresh priv")
}

// ── DKG + presig (bsv-mpc-core public API) ──────────────────────────────────

fn run_dkg_2of2() -> (JointPublicKey, EncryptedShare, EncryptedShare) {
    let config = ThresholdConfig::new(2, 2).expect("2-of-2");
    let session = SessionId::from_str_hash("i5-dkg");
    let mut c0 = DkgCoordinator::new(session, config, ShareIndex(0));
    let mut c1 = DkgCoordinator::new(session, config, ShareIndex(1));
    let mut rng = rand::rngs::OsRng;
    c0.set_pregenerated_primes(generate_test_primes(&mut rng));
    c1.set_pregenerated_primes(generate_test_primes(&mut rng));
    let mut out0 = c0.init().expect("c0 init");
    let mut out1 = c1.init().expect("c1 init");
    for round in 0..40 {
        let r0 = c0.process_round(out1.clone()).expect("c0 round");
        let r1 = c1.process_round(out0.clone()).expect("c1 round");
        match (r0, r1) {
            (DkgRoundResult::Complete(a), DkgRoundResult::Complete(b)) => {
                assert_eq!(
                    a.joint_key.compressed, b.joint_key.compressed,
                    "DKG MUST agree on the joint pubkey before we touch sats"
                );
                return (a.joint_key, a.share, b.share);
            }
            (DkgRoundResult::NextRound(n0), DkgRoundResult::NextRound(n1)) => {
                out0 = n0;
                out1 = n1;
            }
            _ => panic!("DKG desync at round {round}"),
        }
    }
    panic!("DKG did not complete");
}

fn gen_presig_pair(share0: EncryptedShare, share1: EncryptedShare) -> (Vec<u8>, PresignBox) {
    let session = SessionId::from_str_hash("i5-presig");
    let participants = vec![0u16, 1u16];
    let mut m0 = PresigningManager::new(session, share0, participants.clone(), 2);
    let mut m1 = PresigningManager::new(session, share1, participants, 2);
    let mut o0 = m0.init_generate().expect("m0 init");
    let mut o1 = m1.init_generate().expect("m1 init");
    let (mut d0, mut d1) = (false, false);
    for _ in 0..40 {
        if d0 && d1 {
            break;
        }
        let r0 = m0.process_generate_round(o1.clone()).expect("m0 round");
        let r1 = m1.process_generate_round(o0.clone()).expect("m1 round");
        o0 = match r0 {
            PresigningRoundResult::NextRound(m) => m,
            PresigningRoundResult::Complete => {
                d0 = true;
                vec![]
            }
        };
        o1 = match r1 {
            PresigningRoundResult::NextRound(m) => m,
            PresigningRoundResult::Complete => {
                d1 = true;
                vec![]
            }
        };
    }
    assert_eq!(m0.pool_size(), 1);
    assert_eq!(m1.pool_size(), 1);
    let (_w0, box0) = m0.take_raw().expect("m0 take_raw");
    let presig_a_json = bsv_mpc_core::presigning::serialize_party_presignature(box0)
        .expect("serialize Presignature_A");
    let (_w1, box1) = m1.take_raw().expect("m1 take_raw");
    (presig_a_json, box1)
}

// ── BSV tx helpers (mirror sign_mainnet_via_messagebox_e2e.rs) ───────────────

fn p2pkh_locking_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.extend_from_slice(&[0x76, 0xa9, 0x14]);
    s.extend_from_slice(pubkey_hash);
    s.extend_from_slice(&[0x88, 0xac]);
    s
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
    // WoC indexing can lag a freshly-broadcast tx by several minutes under load.
    // Poll on a steady 15s cadence for up to ~5 minutes before giving up.
    for attempt in 1..=20 {
        let wait = 15;
        eprintln!("  WoC attempt {attempt}: waiting {wait}s for indexing...");
        tokio::time::sleep(Duration::from_secs(wait)).await;
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

async fn broadcast_via_arc(http: &reqwest::Client, raw_tx_hex: &str) -> bool {
    for arc in &["https://arc.taal.com", "https://arc.gorillapool.io"] {
        let url = format!("{arc}/v1/tx");
        eprintln!("  broadcast via {url}");
        let Ok(resp) = http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("XDeployment-ID", "bsv-mpc-i5")
            .json(&serde_json::json!({ "rawTx": raw_tx_hex }))
            .send()
            .await
        else {
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

/// Extract the raw funding tx hex from a wallet `createAction` response.
///
/// wallet:3321 returns the signed tx as `tx` (atomic BEEF, a JSON byte array)
/// alongside `txid`. The wallet's own broadcaster has been observed to report
/// `sendWithResults: unproven` while the tx never propagates to public miners
/// (WoC/GorillaPool 404). So we extract the raw tx and broadcast it ourselves
/// via ARC — the same public path the spending tx uses — to guarantee the
/// funding UTXO actually lands on mainnet.
fn raw_tx_hex_from_create_action(resp: &serde_json::Value) -> Option<String> {
    let arr = resp.get("tx")?.as_array()?;
    let beef: Vec<u8> = arr.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect();
    let tx = bsv::Transaction::from_atomic_beef(&beef)
        .or_else(|_| bsv::Transaction::from_beef(&beef, None))
        .ok()?;
    Some(tx.to_hex())
}

#[tokio::test]
async fn i5_deployed_cosigner_real_mainnet_tx() {
    if !opt_in() {
        eprintln!(
            "E2E_MAINNET=1 not set — skipping I-5 real-sats merge gate.
To run (BURNS REAL SATS): E2E_MAINNET=1 cargo test -p bsv-mpc-proxy \\
  --test i5_real_sats_deployed_e2e --release -- --nocapture --test-threads=1"
        );
        return;
    }
    let _ = tracing_subscriber::fmt::try_init();
    let t0 = std::time::Instant::now();
    let worker_url =
        std::env::var("DEPLOYED_WORKER_URL").unwrap_or_else(|_| DEFAULT_WORKER.to_string());
    let relay_url =
        std::env::var("MESSAGEBOX_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY.to_string());
    let http = reqwest::Client::new();

    // ── 1. Real 2-of-2 DKG → joint key (share1 = proxy's share_B) ──────────
    let (joint, share0, share1) = run_dkg_2of2();
    let mut joint_arr = [0u8; 33];
    joint_arr.copy_from_slice(&joint.compressed);
    let joint_pub = PublicKey::from_bytes(&joint_arr).expect("joint pubkey");
    let joint_locking = p2pkh_locking_script(&joint_pub.hash160());
    eprintln!(
        "✔ DKG joint_pubkey={} address={}",
        hex::encode(joint_arr),
        joint.address
    );

    // ── 2. Fund the joint P2PKH address via wallet:3321 ────────────────────
    let funding_amount: u64 = 1500;
    let fund_resp = http
        .post("http://localhost:3321/createAction")
        .header("Origin", "http://admin.com")
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "description": "bsv-mpc I-5 deployed-cosigner mainnet gate",
            "outputs": [{
                "satoshis": funding_amount,
                "lockingScript": hex::encode(&joint_locking),
                "outputDescription": "MPC joint P2PKH"
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

    // ── 3. Find the UTXO on WhatsOnChain ───────────────────────────────────
    let locking_hex = hex::encode(&joint_locking);
    let (vout, value) = find_utxo_on_woc(&http, &fund_txid, &locking_hex)
        .await
        .expect("MUST find funding UTXO on WoC");
    eprintln!("✔ UTXO {fund_txid}:{vout} ({value} sats)");

    // ── 4. Build the spending tx + BIP-143 sighash (drain back to wallet) ──
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

    // ── 5. Correlated presig pair; deployed DO + proxy co-sign over relay ──
    let (presig_a_json, box_b) = gen_presig_pair(share0, share1.clone());
    let sig = combine_sign_over_relay(
        &relay_url,
        fresh_priv(),
        share1,
        vec![0, 1],
        ThresholdConfig::new(2, 2).unwrap(),
        SessionId::from_str_hash("i5-sign"),
        &sighash,
        box_b,
        &joint,
        None, // base-key sign (no BRC-42 offset)
        DoTrigger {
            url: format!("{worker_url}/poc/sign-relay"),
            presig_a_json,
            do_index: 0,
            agent_id: None,
            auth_headers: vec![],
            cosigner_encrypted_share: None,
            brc42_offset: None,
        },
        None, // unauthed POC route — no canonical signer
        Duration::from_secs(60),
    )
    .await
    .expect("proxy + deployed DO co-sign over the relay");
    eprintln!("✔ co-signed: DER {} bytes", sig.signature.len());

    // ── 6. PRE-FLIGHT verify — fail-closed BEFORE broadcast ────────────────
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.r);
    s.copy_from_slice(&sig.s);
    let bsv_sig = Signature::new(r, s);
    assert!(
        bsv_sig.is_low_s(),
        "MPC signature MUST be low-s (BIP-62) — refusing to broadcast"
    );
    assert!(
        joint_pub.verify(&sighash, &bsv_sig),
        "PRE-FLIGHT: signature MUST verify under the joint pubkey before we burn sats"
    );
    eprintln!("✔ pre-flight ECDSA verify under joint pubkey: PASS");

    // ── 7. Assemble + broadcast ────────────────────────────────────────────
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
    assert!(
        ok,
        "ARC broadcast MUST succeed — TXID={txid_hex} rawTx={raw_tx_hex}"
    );

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  I-5 MERGE GATE — DEPLOYED COSIGNER REAL MAINNET TX           ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!("  joint_pubkey:   {}", hex::encode(joint_arr));
    eprintln!("  joint_address:  {}", joint.address);
    eprintln!("  funding_txid:   {fund_txid}");
    eprintln!("  funded_sats:    {value}");
    eprintln!("  spending_txid:  {txid_hex}");
    eprintln!("  drained_back:   {change} sats (fee {fee})");
    eprintln!("  cosigner:       deployed bsv-mpc-worker DO (share_A partial over relay)");
    eprintln!("  combiner:       bsv-mpc-proxy (share_B)");
    eprintln!("  view: https://whatsonchain.com/tx/{txid_hex}");
    eprintln!("  total wall-clock: {:?}", t0.elapsed());
}

// ============================================================================
// #25b — §06.20 worker-self-encrypt-at-rest, DEPLOYED, REAL SATS
// ============================================================================
//
// The §06.20 capstone: identical to the I-5 gate above EXCEPT the deployed
// worker holds its presig as BRC-2 self-encrypted CIPHERTEXT at rest and
// DECRYPTS it at sign-time. To force the decrypt-of-stored-ciphertext path we
// drive the AUTHED pool route (not the unauthed `/poc/sign-relay` body path):
//
//   1. Real 2-of-2 DKG → joint key (share1 = proxy's share_B).
//   2. `MpcBridge` from share_B (stable identity + BRC-31 handshake w/ worker).
//   3. `provision_presig_to_do` → authed `/ceremony/ingest-presig`: the worker
//      BRC-2 self-encrypts Presignature_A and stores the CIPHERTEXT in its pool.
//   4. Fund the joint P2PKH on mainnet via wallet:3321; build the BIP-143 sighash.
//   5. `sign_over_relay` → authed `/sign-relay`: the worker CONSUMES the pooled
//      ciphertext, DECRYPTS it under the same presig_id (§06.20), issues its
//      partial over the relay; the proxy combines into a BSV-valid signature.
//   6. PRE-FLIGHT verify (low-s + joint-pubkey), then broadcast via ARC.
//
// This is the worker-self-encrypt-at-rest §06.20 variant. The full
// coordinator-holds-ciphertext topology (§06.17.1) is deferred to #25c.
//
// REAL SATS. Gated on `E2E_MAINNET=1` (shares the i5 env + worker URL).
//
// ```bash
// MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
//   E2E_MAINNET=1 DEPLOYED_WORKER_URL=https://bsv-mpc-kss.dev-a3e.workers.dev \
//   cargo test -p bsv-mpc-proxy --test i5_real_sats_deployed_e2e \
//   sec0620_deployed_decrypt_at_rest_real_mainnet_tx \
//   --release -- --nocapture --test-threads=1
// ```
#[tokio::test]
async fn sec0620_deployed_decrypt_at_rest_real_mainnet_tx() {
    use bsv_mpc_core::types::DkgResult;
    use bsv_mpc_proxy::bridge::MpcBridge;
    use bsv_mpc_proxy::config::ProxyConfig;

    if !opt_in() {
        eprintln!(
            "E2E_MAINNET=1 not set — skipping #25b §06.20 decrypt-at-rest real-sats gate."
        );
        return;
    }
    let _ = tracing_subscriber::fmt::try_init();
    let t0 = std::time::Instant::now();
    let worker_url =
        std::env::var("DEPLOYED_WORKER_URL").unwrap_or_else(|_| DEFAULT_WORKER.to_string());
    let relay_url =
        std::env::var("MESSAGEBOX_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY.to_string());
    let http = reqwest::Client::new();

    // ── 1. Real 2-of-2 DKG → joint key (share1 = proxy's share_B). ──────────
    let (joint, share0, share1) = run_dkg_2of2();
    let joint_hex = hex::encode(&joint.compressed);
    let mut joint_arr = [0u8; 33];
    joint_arr.copy_from_slice(&joint.compressed);
    let joint_pub = PublicKey::from_bytes(&joint_arr).expect("joint pubkey");
    let joint_locking = p2pkh_locking_script(&joint_pub.hash160());
    eprintln!("✔ DKG joint_pubkey={joint_hex} address={}", joint.address);

    // Correlated presig pair: Presignature_A (→ worker pool), box_B (→ proxy).
    let (presig_a_json, box_b) = gen_presig_pair(share0, share1.clone());

    // ── 2. MpcBridge from share_B → stable identity + BRC-31 handshake. ─────
    let dkg_session = SessionId::from_str_hash("i5-dkg");
    let dkg_result = DkgResult {
        joint_key: joint.clone(),
        share: share1,
        session_id: dkg_session,
    };
    let dir = std::env::temp_dir();
    let share_path = dir.join(format!("sec0620_share_{}.json", std::process::id()));
    tokio::fs::write(&share_path, serde_json::to_vec(&dkg_result).unwrap())
        .await
        .expect("write share file");
    let config = ProxyConfig {
        port: 3329,
        kss_url: worker_url.clone(),
        share_path: share_path.to_string_lossy().to_string(),
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
        presign_url: None,
    };
    let bridge = MpcBridge::new(&config)
        .await
        .expect("MpcBridge::new (BRC-31 handshake with deployed worker)");
    eprintln!("✔ proxy stable identity authed with deployed worker");

    // ── 3. Provision Presignature_A → worker pool (authed). The worker BRC-2
    //       self-encrypts it and stores the CIPHERTEXT (§06.20). ─────────────
    let presig_id = format!("sec0620-presig-{}", std::process::id());
    bridge
        .provision_presig_to_do(&joint_hex, &presig_a_json, "sec0620-session", &presig_id)
        .await
        .expect("provision presig to DO pool (authed /ceremony/ingest-presig)");
    eprintln!("✔ Presignature_A provisioned → worker self-encrypted it at rest (§06.20)");

    // ── 4. Fund the joint P2PKH address via wallet:3321. ────────────────────
    let funding_amount: u64 = 1500;
    let fund_resp = http
        .post("http://localhost:3321/createAction")
        .header("Origin", "http://admin.com")
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "description": "bsv-mpc #25b §06.20 decrypt-at-rest mainnet gate",
            "outputs": [{
                "satoshis": funding_amount,
                "lockingScript": hex::encode(&joint_locking),
                "outputDescription": "MPC joint P2PKH"
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
    eprintln!("✔ wallet built funding tx: txid={fund_txid}");

    // Self-broadcast the funding tx via public ARC (the wallet's own broadcaster
    // does not reliably reach public miners — see helper doc).
    let fund_raw = raw_tx_hex_from_create_action(&fund_json)
        .expect("extract raw funding tx from wallet createAction response");
    let funded = broadcast_via_arc(&http, &fund_raw).await;
    assert!(funded, "funding tx MUST broadcast to mainnet via ARC");
    eprintln!("✔ funding tx broadcast to mainnet via ARC");

    let locking_hex = hex::encode(&joint_locking);
    let (vout, value) = find_utxo_on_woc(&http, &fund_txid, &locking_hex)
        .await
        .expect("MUST find funding UTXO on WoC");
    eprintln!("✔ UTXO {fund_txid}:{vout} ({value} sats)");

    // ── 5. Build the spending tx + BIP-143 sighash (drain back to wallet). ──
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

    // ── 6. Authed /sign-relay: worker DECRYPTS its at-rest ciphertext, issues
    //       its partial over the relay, proxy combines. ─────────────────────
    let trigger = DoTrigger {
        url: format!("{worker_url}/sign-relay"),
        presig_a_json: vec![], // pool path: worker consumes + decrypts from its pool
        do_index: 0,
        agent_id: Some(joint_hex.clone()),
        auth_headers: vec![], // filled by sign_over_relay from the bridge session
        cosigner_encrypted_share: None,
        brc42_offset: None,
    };
    let sig = bridge
        .sign_over_relay(&sighash, box_b, None, trigger, Duration::from_secs(60))
        .await
        .expect("proxy + deployed worker co-sign via authed /sign-relay (§06.20 decrypt-at-rest)");
    eprintln!("✔ co-signed via decrypt-at-rest pool path: DER {} bytes", sig.signature.len());

    // ── 7. PRE-FLIGHT verify — fail-closed BEFORE broadcast. ────────────────
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.r);
    s.copy_from_slice(&sig.s);
    let bsv_sig = Signature::new(r, s);
    assert!(
        bsv_sig.is_low_s(),
        "MPC signature MUST be low-s (BIP-62) — refusing to broadcast"
    );
    assert!(
        joint_pub.verify(&sighash, &bsv_sig),
        "PRE-FLIGHT: signature MUST verify under the joint pubkey before we burn sats"
    );
    eprintln!("✔ pre-flight ECDSA verify under joint pubkey: PASS");

    // ── 8. Assemble + broadcast. ────────────────────────────────────────────
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
    assert!(
        ok,
        "ARC broadcast MUST succeed — TXID={txid_hex} rawTx={raw_tx_hex}"
    );

    let _ = tokio::fs::remove_file(&share_path).await;

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  #25b §06.20 GATE — DEPLOYED DECRYPT-AT-REST REAL MAINNET TX  ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!("  joint_pubkey:   {joint_hex}");
    eprintln!("  joint_address:  {}", joint.address);
    eprintln!("  funding_txid:   {fund_txid}");
    eprintln!("  funded_sats:    {value}");
    eprintln!("  spending_txid:  {txid_hex}");
    eprintln!("  drained_back:   {change} sats (fee {fee})");
    eprintln!("  presig path:    worker self-encrypted at ingest, DECRYPTED at sign (§06.20)");
    eprintln!("  cosigner:       deployed bsv-mpc-worker DO (authed /sign-relay pool consume)");
    eprintln!("  combiner:       bsv-mpc-proxy (share_B)");
    eprintln!("  view: https://whatsonchain.com/tx/{txid_hex}");
    eprintln!("  total wall-clock: {:?}", t0.elapsed());
}
