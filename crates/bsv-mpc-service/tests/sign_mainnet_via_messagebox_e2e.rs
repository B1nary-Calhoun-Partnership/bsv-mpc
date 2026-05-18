//! **Phase E merge gate** — real mainnet TX signed by 2-of-2 over MessageBox.
//!
//! End-to-end: two independent in-process `bsv-mpc-service`
//! participants run a real CGGMP'24 2-of-2 DKG via the live Calhoun
//! relay (Phase D), then sign a real BSV mainnet sighash via the same
//! relay (Phase E), then broadcast the signed transaction to ARC and
//! cite the returned TXID. Real sats burned.
//!
//! Gated on **both**:
//! - `MESSAGEBOX_RELAY_URL` — opt-in to live relay (Phase A–D pattern)
//! - `E2E_MAINNET=1` — opt-in to spending real sats (NEVER runs in CI)
//!
//! Requires:
//! - `bsv-wallet-cli` running at `http://localhost:3321` with at least
//!   ~3,000 sats spendable (funds the joint MPC address, then we drain
//!   most back). Origin `http://localhost` is the auth header the
//!   wallet expects per its BRC-100 dev-mode config.
//! - Outbound network to `api.whatsonchain.com` (UTXO discovery) and
//!   `arc.taal.com` / `arc.gorillapool.io` (broadcast fan-out).
//!
//! Run:
//!
//! ```bash
//! MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
//! E2E_MAINNET=1 \
//!   cargo test -p bsv-mpc-service \
//!     --test sign_mainnet_via_messagebox_e2e \
//!     --release -- --nocapture --test-threads=1
//! ```
//!
//! Total runtime: ~2-3 min (60-90s prime gen + 20s DKG + ~5s sign +
//! ~10-30s UTXO indexing wait + broadcast).
//!
//! Failure modes the test explicitly catches:
//! - DKG joint_pubkey mismatch (won't reach signing)
//! - SigningResult mismatch (won't reach broadcast)
//! - **Local ECDSA verification fail BEFORE broadcast** — pre-flight
//!   check against bsv-rs `joint_pubkey.verify(sighash, sig)` so we
//!   don't burn sats on an invalid signature.
//! - Broadcast rejection — fails closed (no TXID is the failure
//!   signal).

use std::sync::Arc;
use std::time::Duration;

use bsv::primitives::bsv::sighash::{
    compute_sighash_for_signing, SighashParams, TxInput, TxOutput, SIGHASH_ALL, SIGHASH_FORKID,
};
use bsv::primitives::bsv::tx_signature::TransactionSignature;
use bsv::primitives::ec::{PrivateKey, PublicKey, Signature};
use bsv::primitives::encoding::Writer;
use bsv::primitives::hash::sha256d;
use bsv_mpc_core::types::{SessionId, ThresholdConfig};
use bsv_mpc_messagebox::types::{BOX_DKG, BOX_SIGN};
use bsv_mpc_messagebox::MessageBoxClient;
use bsv_mpc_service::storage::SqliteShareStorage;
use bsv_mpc_service::{DkgHandler, MessageBoxListener, SigningHandler};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::PregeneratedPrimes;
use rand::RngCore;
use tempfile::TempDir;

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

fn fresh_storage() -> (Arc<std::sync::RwLock<SqliteShareStorage>>, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = SqliteShareStorage::open(dir.path().to_str().unwrap()).expect("open");
    (Arc::new(std::sync::RwLock::new(storage)), dir)
}

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

/// One bsv-mpc-service participant — what each "cosigner" runs locally
/// for the test. Holds the live MessageBoxClient + both handlers + both
/// listeners. The listeners (held in `_dkg_listener` / `_sign_listener`)
/// own background pump tasks that we keep alive for the test's
/// duration via the binding.
struct Cosigner {
    client: MessageBoxClient,
    pub_hex: String,
    /// Held to keep the Arc alive past the spawn_blocking lifetime;
    /// the handlers each own a separate Arc clone for share I/O.
    _storage: Arc<std::sync::RwLock<SqliteShareStorage>>,
    dkg_handler: DkgHandler,
    signing_handler: SigningHandler,
    _dkg_listener: MessageBoxListener,
    _sign_listener: MessageBoxListener,
    _storage_dir: TempDir,
}

async fn boot_cosigner(
    relay_url: &str,
    party_index: u16,
    config: ThresholdConfig,
    participants: Vec<u16>,
) -> Cosigner {
    let client = MessageBoxClient::new(relay_url, fresh_priv()).expect("client");
    let pub_hex = client.identity_hex().await.expect("identity_hex");
    let (storage, _storage_dir) = fresh_storage();

    let dkg_handler = DkgHandler::new(config, party_index, storage.clone());
    let signing_handler = SigningHandler::new(config, participants, storage.clone());

    let _dkg_listener =
        MessageBoxListener::start(client.clone(), BOX_DKG, dkg_handler.handler_fn())
            .await
            .expect("dkg listener");
    let _sign_listener =
        MessageBoxListener::start(client.clone(), BOX_SIGN, signing_handler.handler_fn())
            .await
            .expect("sign listener");

    Cosigner {
        client,
        pub_hex,
        _storage: storage,
        dkg_handler,
        signing_handler,
        _dkg_listener,
        _sign_listener,
        _storage_dir,
    }
}

#[tokio::test]
async fn within_stack_2of2_sign_mainnet_tx_via_messagebox() {
    let Some(relay_url) = opt_in() else {
        eprintln!(
            "MESSAGEBOX_RELAY_URL + E2E_MAINNET=1 not both set — skipping Phase E mainnet TX.
To run (BURNS REAL SATS):
  MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \\
  E2E_MAINNET=1 \\
    cargo test -p bsv-mpc-service --test sign_mainnet_via_messagebox_e2e \\
      --release -- --nocapture --test-threads=1"
        );
        return;
    };
    let _ = tracing_subscriber::fmt::try_init();
    let t0 = std::time::Instant::now();

    // ============ DKG ============
    let config = ThresholdConfig::new(2, 2).expect("2-of-2");
    let participants = vec![0u16, 1u16];

    let alice = boot_cosigner(&relay_url, 0, config, participants.clone()).await;
    let bob = boot_cosigner(&relay_url, 1, config, participants.clone()).await;
    eprintln!("✔ alice = {}", alice.pub_hex);
    eprintln!("✔ bob   = {}", bob.pub_hex);

    eprintln!("(generating Paillier safe primes — ~60-90s)");
    let primes_t0 = std::time::Instant::now();
    let (alice_primes, bob_primes) = tokio::task::spawn_blocking(|| {
        let a = std::thread::spawn(|| {
            PregeneratedPrimes::<SecurityLevel128>::generate(&mut rand::rngs::OsRng)
        });
        let b = std::thread::spawn(|| {
            PregeneratedPrimes::<SecurityLevel128>::generate(&mut rand::rngs::OsRng)
        });
        (a.join().unwrap(), b.join().unwrap())
    })
    .await
    .unwrap();
    eprintln!("✔ primes in {:?}", primes_t0.elapsed());

    let dkg_session_id = {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        SessionId(b)
    };
    alice
        .dkg_handler
        .seed_primes_for(dkg_session_id, alice_primes);
    bob.dkg_handler.seed_primes_for(dkg_session_id, bob_primes);

    let (alice_dkg_rx, alice_dkg_out) = alice
        .dkg_handler
        .initiate(dkg_session_id, bob.pub_hex.clone(), 1)
        .await
        .expect("alice dkg initiate");
    let (bob_dkg_rx, bob_dkg_out) = bob
        .dkg_handler
        .initiate(dkg_session_id, alice.pub_hex.clone(), 0)
        .await
        .expect("bob dkg initiate");

    for out in alice_dkg_out {
        alice
            .client
            .send_round_message(
                &out.recipient_pub_hex,
                &out.message_box,
                &out.round_msg,
                out.params,
            )
            .await
            .expect("alice dkg send");
    }
    for out in bob_dkg_out {
        bob.client
            .send_round_message(
                &out.recipient_pub_hex,
                &out.message_box,
                &out.round_msg,
                out.params,
            )
            .await
            .expect("bob dkg send");
    }

    let dkg_t0 = std::time::Instant::now();
    let (alice_dkg, bob_dkg) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(300), alice_dkg_rx),
        tokio::time::timeout(Duration::from_secs(300), bob_dkg_rx),
    );
    let alice_dkg = alice_dkg.unwrap().unwrap();
    let bob_dkg = bob_dkg.unwrap().unwrap();
    assert_eq!(
        alice_dkg.joint_key.compressed, bob_dkg.joint_key.compressed,
        "DKG MUST agree on joint pubkey before we touch sats"
    );
    let mut joint_pubkey_arr = [0u8; 33];
    joint_pubkey_arr.copy_from_slice(&alice_dkg.joint_key.compressed);
    let joint_pubkey =
        PublicKey::from_bytes(&joint_pubkey_arr).expect("joint pubkey from compressed bytes");
    let joint_address = alice_dkg.joint_key.address.clone();
    eprintln!(
        "✔ DKG complete in {:?} — joint_pubkey={} address={}",
        dkg_t0.elapsed(),
        hex::encode(joint_pubkey_arr),
        joint_address
    );

    // ============ Fund the joint address via wallet:3321 ============
    let http = reqwest::Client::new();
    let funding_amount: u64 = 1500;
    let joint_locking = p2pkh_locking_script(&joint_pubkey.hash160());

    let fund_resp = http
        .post("http://localhost:3321/createAction")
        .header("Origin", "http://localhost")
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "description": "bsv-mpc Phase E within-stack MessageBox-signed mainnet test",
            "outputs": [{
                "satoshis": funding_amount,
                "lockingScript": hex::encode(&joint_locking),
                "outputDescription": "MPC joint P2PKH"
            }]
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
        .header("Origin", "http://localhost")
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

    // ============ 2-of-2 sign via MessageBox ============
    let sign_session_id = {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        SessionId(b)
    };
    let agent_id = alice_dkg.session_id.hex(); // same on both sides (DKG agreed)

    let (alice_sig_rx, alice_sig_out) = alice
        .signing_handler
        .initiate(
            agent_id.clone(),
            sign_session_id,
            bob.pub_hex.clone(),
            1,
            sighash,
            joint_pubkey_arr,
            None,
        )
        .await
        .expect("alice sign initiate");
    let (bob_sig_rx, bob_sig_out) = bob
        .signing_handler
        .initiate(
            agent_id,
            sign_session_id,
            alice.pub_hex.clone(),
            0,
            sighash,
            joint_pubkey_arr,
            None,
        )
        .await
        .expect("bob sign initiate");

    for out in alice_sig_out {
        alice
            .client
            .send_round_message(
                &out.recipient_pub_hex,
                &out.message_box,
                &out.round_msg,
                out.params,
            )
            .await
            .expect("alice sig send");
    }
    for out in bob_sig_out {
        bob.client
            .send_round_message(
                &out.recipient_pub_hex,
                &out.message_box,
                &out.round_msg,
                out.params,
            )
            .await
            .expect("bob sig send");
    }

    let sig_t0 = std::time::Instant::now();
    let (alice_sig, bob_sig) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(120), alice_sig_rx),
        tokio::time::timeout(Duration::from_secs(120), bob_sig_rx),
    );
    let alice_sig = alice_sig
        .expect("alice sign within 120s")
        .expect("alice sig channel");
    let bob_sig = bob_sig
        .expect("bob sign within 120s")
        .expect("bob sig channel");
    assert_eq!(
        alice_sig.signature, bob_sig.signature,
        "BOTH cosigners MUST produce the byte-identical DER signature"
    );
    assert_eq!(alice_sig.r, bob_sig.r, "BOTH cosigners MUST agree on raw r");
    assert_eq!(alice_sig.s, bob_sig.s, "BOTH cosigners MUST agree on raw s");
    eprintln!(
        "✔ signing complete in {:?} — DER sig {} bytes (both sides byte-identical)",
        sig_t0.elapsed(),
        alice_sig.signature.len()
    );

    // ============ Pre-flight ECDSA verify against joint pubkey ============
    let mut r_arr = [0u8; 32];
    let mut s_arr = [0u8; 32];
    r_arr.copy_from_slice(&alice_sig.r);
    s_arr.copy_from_slice(&alice_sig.s);
    let bsv_sig = Signature::new(r_arr, s_arr);
    assert!(
        bsv_sig.is_low_s(),
        "MPC signature MUST be low-s (BIP-62) — refusing to broadcast otherwise"
    );
    assert!(
        joint_pubkey.verify(&sighash, &bsv_sig),
        "PRE-FLIGHT: signature MUST verify against joint pubkey before we burn sats on broadcast"
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

    // ============ Broadcast via ARC (TAAL, fallback to GorillaPool) ============
    let raw_tx_hex = hex::encode(&raw_tx);
    let broadcast_ok = broadcast_via_arc(&http, &raw_tx_hex).await;
    assert!(
        broadcast_ok,
        "ARC broadcast MUST succeed — TXID={txid_hex}, rawTx=\"{raw_tx_hex}\""
    );

    eprintln!();
    eprintln!("╔═══════════════════════════════════════════════════════════════╗");
    eprintln!("║  PHASE E MAINNET TX — SIGNED VIA MESSAGEBOX                  ║");
    eprintln!("╚═══════════════════════════════════════════════════════════════╝");
    eprintln!("  joint_pubkey: {}", hex::encode(joint_pubkey_arr));
    eprintln!("  joint_address: {}", joint_address);
    eprintln!("  funding_txid: {}", fund_txid);
    eprintln!("  funded_satoshis: {}", utxo_value);
    eprintln!("  spending_txid: {}", txid_hex);
    eprintln!("  drained_back: {} sats (fee: {})", change, fee);
    eprintln!("  view: https://whatsonchain.com/tx/{}", txid_hex);
    eprintln!("  total wall-clock: {:?}", t0.elapsed());
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
            .header("XDeployment-ID", "bsv-mpc-phase-e")
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
