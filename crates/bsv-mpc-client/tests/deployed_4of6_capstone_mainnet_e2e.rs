//! **#69/#70/#85 CAPSTONE — genuine 4-of-6 with TWO INDEPENDENT deployed Notaries,
//! MITM-hardened, real BRC-31, over the live relay → mainnet TXID.**
//!
//! The closing artifact. The 6 shares split device `{0,1,2}` (w = t−1 = 3) +
//! **NotaryA** `{3,4}` + **NotaryB** `{5}` — two genuinely independent deployed
//! `bsv-mpc-service` containers with DISTINCT master identities (#70). Provisioning
//! PINS each Notary's master out-of-band and verifies every per-index relay-pub
//! attestation + a post-DKG liveness challenge against it (#85 MITM gate). A sign
//! uses device `{0,1,2}` + ONE Notary partial (NotaryA's `{3}`) — the
//! device-holds-(t−1) combine (#83) fed by a genuine n-party presign over the relay
//! (#86 / step 7a). Through the native client's `DeployedSigner` (the same high-level
//! `sign()` 100cash binds to over UniFFI).
//!
//! Two gates:
//! - `CLIENT_4OF6=1` — free (no sats): provision (2-Notary DKG, #85-pinned) → top-up
//!   → sign a dummy sighash → verify under the joint key. Proves the deployed 2-Notary
//!   4-of-6 + #85 end-to-end.
//! - `CLIENT_4OF6_MAINNET=1` — REAL SATS: funds the joint P2PKH via wallet:3321, signs
//!   through `DeployedSigner::sign`, broadcasts via ARC → WoC TXID. Closes #69/#70/#85/#86.
//!
//! ```bash
//! CLIENT_4OF6=1 cargo test -p bsv-mpc-client --features native \
//!   --test deployed_4of6_capstone_mainnet_e2e ceremony -- --nocapture --test-threads=1
//! CLIENT_4OF6_MAINNET=1 cargo test -p bsv-mpc-client --features native \
//!   --test deployed_4of6_capstone_mainnet_e2e real_mainnet -- --nocapture --test-threads=1
//! ```
#![cfg(not(target_arch = "wasm32"))]

use std::sync::Arc;
use std::time::Duration;

use bsv::primitives::ec::{PrivateKey, PublicKey, Signature};
use bsv_mpc_client::native_io::keystore::MemNativeKeyStore;
use bsv_mpc_client::native_io::provision::NpartyCosigner;
use bsv_mpc_client::native_io::signer::{DeployedSigner, DeployedSignerConfig, WalletMeta};
use bsv_mpc_core::types::{JointPublicKey, PolicyId, ThresholdConfig};

const NOTARY_A_URL: &str = "https://bsv-mpc-service-container.dev-a3e.workers.dev";
const NOTARY_B_URL: &str = "https://bsv-mpc-service-container-b.dev-a3e.workers.dev";
const NOTARY_A_MASTER: &str = "0278138e618ebb69c8bc6af07d15e50c72d9628b2c0fd7042185ee5cf5712af0e8";
const NOTARY_B_MASTER: &str = "034957e39818e8d073a025a5e9c99e99fadae20419150c3c1be89c259abaa4622f";
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";
const AT_REST_ROOT: [u8; 32] = [0x4fu8; 32];

const T: u16 = 4;
const N: u16 = 6;

fn relay_url() -> String {
    std::env::var("MESSAGEBOX_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY.to_string())
}

/// Provision a genuine 4-of-6 across device {0,1,2} + NotaryA {3,4} + NotaryB {5}
/// (real BRC-31, #85-pinned) and connect a multi-index `DeployedSigner`. The sign
/// completes the t-quorum with NotaryA's index 3 (the first cosigner).
async fn provision_and_connect_4of6() -> (DeployedSigner, PublicKey, Vec<u8>) {
    // Fresh device identity → recorded as the §08.1 owner at DKG, reused for sign.
    let identity = PrivateKey::from_bytes(&[0x6du8; 32]).expect("identity key");
    let keystore = Arc::new(MemNativeKeyStore::new());
    let config = ThresholdConfig::new(T, N).expect("4-of-6");

    eprintln!("(genuine 2-Notary 4-of-6 DKG over the live relay, #85-pinned — minutes)");
    let w = bsv_mpc_client::native_io::provision_wallet_nparty(
        &relay_url(),
        identity.clone(),
        config,
        vec![0, 1, 2], // device holds w = t−1 = 3
        vec![
            NpartyCosigner {
                container_url: NOTARY_A_URL.to_string(),
                indices: vec![3, 4],
                expected_master_pub: Some(NOTARY_A_MASTER.to_string()),
            },
            NpartyCosigner {
                container_url: NOTARY_B_URL.to_string(),
                indices: vec![5],
                expected_master_pub: Some(NOTARY_B_MASTER.to_string()),
            },
        ],
        Duration::from_secs(700),
        keystore.as_ref(),
    )
    .await
    .expect("provision_wallet_nparty (2-Notary DKG + #85 verify + seal) MUST succeed");

    let joint = w.joint_key.clone();
    let mut joint_arr = [0u8; 33];
    joint_arr.copy_from_slice(&joint.compressed);
    let joint_pub = PublicKey::from_bytes(&joint_arr).expect("joint pubkey");
    eprintln!(
        "✔ provisioned 4-of-6: agent_id={} address={} my_indices={:?} cosigner_indices={:?}",
        w.agent_id, joint.address, w.my_indices, w.cosigner_indices
    );

    // Signing subset = device {0,1,2} + NotaryA's {3} (the trigger cosigner) = t=4.
    let cosigner_party = 3u16;
    let mut participants = w.my_indices.clone();
    participants.push(cosigner_party);
    participants.sort_unstable();
    participants.dedup();
    let device_primary = *w.my_indices.first().expect("device holds indices");

    let bundle_dir =
        std::env::temp_dir().join(format!("bsvmpc-4of6-capstone-{}", std::process::id()));
    let signer = DeployedSigner::connect(
        DeployedSignerConfig {
            relay_url: relay_url(),
            container_url: NOTARY_A_URL.to_string(), // the trigger cosigner for the sign
            identity,
            at_rest_root: AT_REST_ROOT,
            bundle_dir,
            policy_id: PolicyId([0u8; 32]),
            meta: WalletMeta {
                agent_id: w.agent_id.clone(),
                joint_key: JointPublicKey {
                    compressed: joint.compressed.clone(),
                    address: joint.address.clone(),
                },
                config: w.config,
                participants,
                device_share_index: device_primary,
                my_indices: w.my_indices.clone(),
                cosigner_party,
                cosigner_master_pub: Some(NOTARY_A_MASTER.to_string()), // #85 presign pin
                dkg_session_id: w.dkg_session_id,
            },
        },
        keystore,
    )
    .await
    .expect("connect multi-index DeployedSigner to NotaryA");
    eprintln!("✔ connected (multi-index; trigger cosigner = NotaryA #3)");

    (signer, joint_pub, joint.compressed.clone())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 12)]
async fn ceremony_2notary_4of6_no_sats() {
    if std::env::var("CLIENT_4OF6").ok().as_deref() != Some("1") {
        eprintln!("CLIENT_4OF6=1 not set — skipping the free deployed 2-Notary 4-of-6 ceremony.");
        return;
    }
    let (signer, joint_pub, joint_compressed) = provision_and_connect_4of6().await;

    // On-demand presign + device-holds sign of a dummy digest (no chain spend).
    let sighash = [0x7cu8; 32];
    let sig = signer
        .sign(
            &sighash,
            "Approve 4-of-6 test",
            None,
            Duration::from_secs(90),
            Duration::from_secs(360),
        )
        .await
        .expect("deployed 2-Notary 4-of-6 device-holds sign over the live relay");

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.r);
    s.copy_from_slice(&sig.s);
    let bsv_sig = Signature::new(r, s);
    assert!(bsv_sig.is_low_s(), "signature must be low-s");
    assert!(
        joint_pub.verify(&sighash, &bsv_sig),
        "the deployed 2-Notary 4-of-6 signature MUST verify under the joint key"
    );
    eprintln!(
        "✔✔ DEPLOYED 2-NOTARY 4-of-6 PROVEN (no sats) — joint={} — #70 + #85 end-to-end",
        hex::encode(&joint_compressed)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 12)]
async fn real_mainnet_2notary_4of6_txid() {
    if std::env::var("CLIENT_4OF6_MAINNET").ok().as_deref() != Some("1") {
        eprintln!(
            "CLIENT_4OF6_MAINNET=1 not set — skipping the REAL-SATS 4-of-6 capstone.\n\
             To run (BURNS SATS, needs wallet:3321): CLIENT_4OF6_MAINNET=1 cargo test \\\n\
             -p bsv-mpc-client --features native --test deployed_4of6_capstone_mainnet_e2e \\\n\
             real_mainnet -- --nocapture --test-threads=1"
        );
        return;
    }
    let http = reqwest::Client::new();
    let (signer, joint_pub, joint_compressed) = provision_and_connect_4of6().await;

    let joint_locking =
        bsv_mpc_client::txbuild::p2pkh_locking_script_from_hash(&joint_pub.hash160());

    // Fund the joint P2PKH via wallet:3321; self-broadcast its BEEF via ARC.
    let funding_amount: u64 = 1500;
    let mut fund_txid = String::new();
    for attempt in 1..=8 {
        let fund_text = http
            .post("http://localhost:3321/createAction")
            .header("Origin", "http://admin.com")
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "description": format!("bsv-mpc 4-of-6 capstone (attempt {attempt})"),
                "outputs": [{
                    "satoshis": funding_amount,
                    "lockingScript": hex::encode(&joint_locking),
                    "outputDescription": "MPC 4-of-6 joint P2PKH"
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
        let txid = fund_json["txid"].as_str().unwrap_or_default().to_string();
        if !txid.is_empty() {
            if let Some(beef_hex) = broadcast_hex_from_create_action(&fund_json) {
                if broadcast_via_arc(&http, &beef_hex).await {
                    eprintln!("✔ funded joint address: txid={txid} (attempt {attempt})");
                    fund_txid = txid;
                    break;
                }
            }
        }
        eprintln!("  funding attempt {attempt} did NOT broadcast; retrying");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    assert!(!fund_txid.is_empty(), "could not broadcast a funding tx");

    let locking_hex = hex::encode(&joint_locking);
    let (vout, value) = find_utxo_on_woc(&http, &fund_txid, &locking_hex)
        .await
        .expect("MUST find funding UTXO on WoC");
    eprintln!("✔ UTXO {fund_txid}:{vout} ({value} sats)");

    let mut prev_txid = [0u8; 32];
    prev_txid.copy_from_slice(&hex::decode(&fund_txid).expect("txid hex"));
    prev_txid.reverse();
    let fee: u64 = 250;
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

    // THE GATE: genuine 4-of-6 device-holds sign (device {0,1,2} + NotaryA {3}) over
    // the live relay, MITM-hardened, pre-flight-verified inside `sign()`.
    let sig = signer
        .sign(
            &sighash,
            "Approve 4-of-6 mainnet spend",
            None,
            Duration::from_secs(90),
            Duration::from_secs(360),
        )
        .await
        .expect("deployed 4-of-6 sign over the live relay");
    eprintln!("✔ 4-of-6 co-signed: DER {} bytes", sig.signature.len());

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
    eprintln!("╔══════════════════════════════════════════════════════════════════╗");
    eprintln!("║  #69/#70/#85 CAPSTONE — 4-of-6, TWO independent Notaries, mainnet  ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════╝");
    eprintln!("  joint_pubkey:  {}", hex::encode(&joint_compressed));
    eprintln!("  topology:      device{{0,1,2}} + NotaryA{{3,4}} + NotaryB{{5}} (sign: device + NotaryA#3)");
    eprintln!("  funding_txid:  {fund_txid}");
    eprintln!("  spending_txid: {txid_hex}");
    eprintln!("  view: https://whatsonchain.com/tx/{txid_hex}");
}

// ── chain helpers (mirrors deployed_sign_e2e) ────────────────────────────────

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
            .header("XDeployment-ID", "bsv-mpc-4of6-capstone")
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
