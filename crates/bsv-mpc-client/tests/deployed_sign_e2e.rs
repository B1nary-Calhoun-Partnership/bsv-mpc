//! **#63 T3 — `bsv-mpc-client` signs vs the DEPLOYED cosigner over the LIVE relay.**
//!
//! Kills the in-process asterisk: the second party is the REAL deployed CF Container
//! cosigner reached over the LIVE MessageBox relay, driven entirely through the
//! native client's `DeployedSigner` / `DeployedCosigner` (the same high-level
//! `sign()` 100cash binds to over UniFFI). Mirrors the proxy blueprint
//! (`bsv-mpc-proxy/tests/container_sec0617_deployed_mainnet_e2e.rs`) but through the
//! client seam + presig pool.
//!
//! Two gates:
//!
//! - `CLIENT_DEPLOYED_SIGN=1` — free (no sats): real DKG + presig + sign over a dummy
//!   sighash; asserts the combined signature verifies under the joint key. The
//!   local-verify-equivalent + protocol-asterisk killer.
//! - `CLIENT_DEPLOYED_SIGN_MAINNET=1` — REAL SATS: funds the joint P2PKH via
//!   wallet:3321, signs through `DeployedSigner::sign`, broadcasts via ARC → WoC TXID.
//!
//! ```bash
//! # free ceremony verify (deployed infra, no sats):
//! CLIENT_DEPLOYED_SIGN=1 cargo test -p bsv-mpc-client --features native \
//!   --test deployed_sign_e2e ceremony_verify -- --nocapture --test-threads=1
//! # real mainnet TXID (BURNS SATS, needs wallet:3321):
//! CLIENT_DEPLOYED_SIGN_MAINNET=1 cargo test -p bsv-mpc-client --features native \
//!   --test deployed_sign_e2e real_mainnet -- --nocapture --test-threads=1
//! ```
#![cfg(not(target_arch = "wasm32"))]

use std::sync::Arc;
use std::time::Duration;

use bsv::primitives::ec::{PrivateKey, PublicKey, Signature};
use bsv_mpc_client::native_io::keystore::MemNativeKeyStore;
use bsv_mpc_client::native_io::signer::{DeployedSigner, DeployedSignerConfig, WalletMeta};
use bsv_mpc_core::types::{PolicyId, ThresholdConfig};

const DEFAULT_CONTAINER: &str = "https://bsv-mpc-service-container.dev-a3e.workers.dev";
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";
const AT_REST_ROOT: [u8; 32] = [0x42u8; 32];

fn container_url() -> String {
    std::env::var("DEPLOYED_CONTAINER_URL").unwrap_or_else(|_| DEFAULT_CONTAINER.to_string())
}
fn relay_url() -> String {
    std::env::var("MESSAGEBOX_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY.to_string())
}

/// Provision a real 2-of-2 with the deployed cosigner via the **#65 provisioning
/// seam** (`provision_wallet` → DKG + `seal_share`), then build a connected
/// `DeployedSigner` from the returned wallet metadata. Exercises #65 + #63 together.
async fn provision_and_connect() -> (DeployedSigner, PublicKey, Vec<u8>, String) {
    // Stable device identity (recorded as owner at DKG time, reused for presign+sign).
    let identity = PrivateKey::from_bytes(&[0x37u8; 32]).expect("identity key");
    let keystore = Arc::new(MemNativeKeyStore::new());

    eprintln!("(real distributed DKG via the #65 provisioning seam — minutes)");
    let config = ThresholdConfig::new(2, 2).expect("2-of-2");
    let w = bsv_mpc_client::native_io::provision_wallet(
        &container_url(),
        identity.clone(),
        config,
        keystore.as_ref(),
    )
    .await
    .expect("provision_wallet (DKG + seal) against the deployed cosigner");

    let joint = w.joint_key.clone();
    let mut joint_arr = [0u8; 33];
    joint_arr.copy_from_slice(&joint.compressed);
    let joint_pub = PublicKey::from_bytes(&joint_arr).expect("joint pubkey");
    eprintln!(
        "✔ provisioned: agent_id={} address={} (share sealed via seal_share)",
        w.agent_id, joint.address
    );

    let bundle_dir =
        std::env::temp_dir().join(format!("bsvmpc-client-bundles-{}", std::process::id()));
    let signer = DeployedSigner::connect(
        DeployedSignerConfig {
            relay_url: relay_url(),
            container_url: container_url(),
            identity,
            at_rest_root: AT_REST_ROOT,
            bundle_dir,
            policy_id: PolicyId([0u8; 32]),
            meta: WalletMeta {
                agent_id: w.agent_id.clone(),
                joint_key: joint.clone(),
                config: w.config,
                participants: w.participants,
                device_share_index: w.device_share_index,
                my_indices: vec![w.device_share_index],
                cosigner_party: w.cosigner_party,
                dkg_session_id: w.dkg_session_id,
            },
        },
        keystore,
    )
    .await
    .expect("connect deployed signer");
    eprintln!("✔ connected to deployed cosigner (pool ready)");

    (signer, joint_pub, joint.compressed.clone(), w.agent_id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ceremony_verify_signs_vs_deployed_cosigner_no_sats() {
    if std::env::var("CLIENT_DEPLOYED_SIGN").ok().as_deref() != Some("1") {
        eprintln!("CLIENT_DEPLOYED_SIGN=1 not set — skipping the free deployed-ceremony verify.");
        return;
    }
    let (signer, joint_pub, _joint_compressed, _agent_id) = provision_and_connect().await;

    // Opportunistic top-up (one biometric mints a bundle), then a fast online sign.
    let minted = signer
        .top_up_presigs(1, "provision presigs", Duration::from_secs(180))
        .await
        .expect("presig top-up over the relay");
    assert_eq!(minted, 1, "must mint exactly one bundle");
    assert_eq!(signer.pool_len(), 1, "pool must hold the minted bundle");

    // Sign an arbitrary 32-byte digest (no chain spend). sign() pre-flight-verifies
    // internally; we ALSO independently verify here under the joint key.
    let sighash = [0x9bu8; 32];
    let sig = signer
        .sign(
            &sighash,
            "Approve test",
            None,
            Duration::from_secs(60),
            Duration::from_secs(180),
        )
        .await
        .expect("deployed-cosigner sign over the live relay");
    assert_eq!(signer.pool_len(), 0, "bundle must be consumed single-use");

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.r);
    s.copy_from_slice(&sig.s);
    let bsv_sig = Signature::new(r, s);
    assert!(bsv_sig.is_low_s(), "signature must be low-s");
    assert!(
        joint_pub.verify(&sighash, &bsv_sig),
        "the deployed-cosigner combined signature MUST verify under the joint key"
    );
    eprintln!(
        "✔ deployed-cosigner ceremony verified under the joint key (no sats) — asterisk killed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_mainnet_tx_signed_by_client_vs_deployed_cosigner() {
    if std::env::var("CLIENT_DEPLOYED_SIGN_MAINNET")
        .ok()
        .as_deref()
        != Some("1")
    {
        eprintln!(
            "CLIENT_DEPLOYED_SIGN_MAINNET=1 not set — skipping the REAL-SATS mainnet gate.\n\
             To run (BURNS SATS, needs wallet:3321): CLIENT_DEPLOYED_SIGN_MAINNET=1 cargo test \\\n\
             -p bsv-mpc-client --features native --test deployed_sign_e2e real_mainnet -- --nocapture --test-threads=1"
        );
        return;
    }
    let http = reqwest::Client::new();
    let (signer, joint_pub, joint_compressed, _agent_id) = provision_and_connect().await;

    let joint_locking =
        bsv_mpc_client::txbuild::p2pkh_locking_script_from_hash(&joint_pub.hash160());

    // Top up one presig.
    signer
        .top_up_presigs(1, "provision presigs", Duration::from_secs(180))
        .await
        .expect("presig top-up");

    // Fund the joint P2PKH via wallet:3321; self-broadcast the BEEF v1 via ARC.
    let funding_amount: u64 = 1500;
    let mut fund_txid = String::new();
    for attempt in 1..=8 {
        let fund_text = http
            .post("http://localhost:3321/createAction")
            .header("Origin", "http://admin.com")
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "description": format!("bsv-mpc-client #63 deployed-sign gate (attempt {attempt})"),
                "outputs": [{
                    "satoshis": funding_amount,
                    "lockingScript": hex::encode(&joint_locking),
                    "outputDescription": "MPC client joint P2PKH"
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

    // Find the UTXO on WoC; build the BIP-143 sighash (drain to a wallet:3321 addr).
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
    eprintln!("✔ sighash: {}", hex::encode(sighash));

    // THE GATE: sign via the deployed cosigner over the live relay (pre-flight inside).
    let sig = signer
        .sign(
            &sighash,
            "Approve mainnet spend",
            None,
            Duration::from_secs(60),
            Duration::from_secs(180),
        )
        .await
        .expect("deployed-cosigner sign over the live relay");
    eprintln!(
        "✔ co-signed via deployed cosigner: DER {} bytes",
        sig.signature.len()
    );

    // Assemble (DER + 0x41 sig, 33-byte joint pubkey unlocking) + broadcast.
    let mut sig_checksig = sig.signature.clone();
    sig_checksig.push(sighash_type as u8);
    let mut joint_arr = [0u8; 33];
    joint_arr.copy_from_slice(&joint_compressed);
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
    eprintln!("✔ assembled tx {} bytes — TXID={txid_hex}", raw_tx.len());

    let ok = broadcast_via_arc(&http, &raw_tx_hex).await;
    assert!(
        ok,
        "ARC broadcast MUST succeed — TXID={txid_hex} rawTx={raw_tx_hex}"
    );

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  #63 — bsv-mpc-client signs vs the DEPLOYED cosigner (mainnet) ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!("  joint_pubkey:  {}", hex::encode(&joint_compressed));
    eprintln!("  funding_txid:  {fund_txid}");
    eprintln!("  spending_txid: {txid_hex}");
    eprintln!("  cosigner:      deployed bsv-mpc-service CONTAINER over live MessageBox relay");
    eprintln!("  combiner:      bsv-mpc-client DeployedSigner (high-level sign())");
    eprintln!("  view: https://whatsonchain.com/tx/{txid_hex}");
}

// ── chain helpers (mirrors the proxy blueprint) ──────────────────────────────

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
            .header("XDeployment-ID", "bsv-mpc-client-63")
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
