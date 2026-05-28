//! **§06.20 HD-derived child-key signing over the relay — DEPLOYED, REAL SATS (issue #26).**
//!
//! Proves 1-round BRC-42 HD-derived signing through the deployed CF Container
//! cosigner: the proxy funds a BRC-42 *child* address (`child = joint + offset·G`),
//! then signs the spend over the relay with the offset applied on BOTH sides —
//! the coordinator via `sign_from_bundle_with_offset` and the deployed container
//! via `decrypt_and_issue_partial(Some(offset))` (§06.20). The combined signature
//! MUST verify under the CHILD pubkey (and must NOT verify under the base joint
//! key), then spends the child address on mainnet.
//!
//! This is the production-grade proof for #26: the relay sign path now passes the
//! BRC-42 offset end-to-end (no more base-key-only). Mirrors the proven
//! `container_sec0617_deployed_mainnet_e2e` bundle path, funding a child address.
//!
//! REAL SATS. Gated on `CONTAINER_HD_RELAY_MAINNET=1`. Requires a BRC-100 wallet
//! at `http://localhost:3321` (Origin `http://admin.com`) with spendable sats.
//!
//! ```bash
//! CONTAINER_HD_RELAY_MAINNET=1 cargo test -p bsv-mpc-proxy \
//!   --test container_hd_relay_deployed_mainnet_e2e \
//!   --release -- --nocapture --test-threads=1
//! ```

use std::sync::Arc;
use std::time::Duration;

use bsv::primitives::bsv::sighash::{
    compute_sighash_for_signing, SighashParams, TxInput, TxOutput, SIGHASH_ALL, SIGHASH_FORKID,
};
use bsv::primitives::bsv::tx_signature::TransactionSignature;
use bsv::primitives::ec::{PrivateKey, PublicKey, Signature};
use bsv::primitives::encoding::Writer;
use bsv::primitives::hash::sha256d;
use bsv_mpc_core::hd::{compute_brc42_hmac, compute_invoice, derive_anyone_pubkey};
use bsv_mpc_core::types::{PolicyId, ThresholdConfig};
use bsv_mpc_proxy::bridge::{run_dkg_over_http_authed, MpcBridge};
use bsv_mpc_proxy::config::ProxyConfig;
use bsv_mpc_service::FileBundleStore;

const DEFAULT_CONTAINER: &str = "https://bsv-mpc-service-container.dev-a3e.workers.dev";
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";

fn opt_in() -> bool {
    std::env::var("CONTAINER_HD_RELAY_MAINNET").ok().as_deref() == Some("1")
}

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

async fn broadcast_via_arc(http: &reqwest::Client, raw_tx_hex: &str) -> bool {
    // TAAL ARC needs a Bearer token (else 401); GorillaPool is keyless. Token from
    // env `TAAL_ARC_TOKEN`, else the known mainnet key (parity with the proven
    // container_reshare test that funds + propagates successfully).
    let taal_token = std::env::var("TAAL_ARC_TOKEN")
        .unwrap_or_else(|_| "mainnet_9596de07e92300c6287e4393594ae39c".to_string());
    for arc in &["https://arc.gorillapool.io", "https://arc.taal.com"] {
        let url = format!("{arc}/v1/tx");
        eprintln!("  broadcast via {url}");
        let mut req = http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("XDeployment-ID", "bsv-mpc-hd-relay-container")
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

fn raw_tx_hex_from_create_action(resp: &serde_json::Value) -> Option<String> {
    let arr = resp.get("tx")?.as_array()?;
    let beef: Vec<u8> = arr.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect();
    let tx = bsv::Transaction::from_atomic_beef(&beef)
        .or_else(|_| bsv::Transaction::from_beef(&beef, None))
        .ok()?;
    Some(tx.to_hex())
}

#[tokio::test]
async fn container_hd_child_key_signs_over_relay_deployed_real_mainnet() {
    if !opt_in() {
        eprintln!(
            "CONTAINER_HD_RELAY_MAINNET=1 not set — skipping §06.20 HD-over-relay real-sats gate.\n\
             To run (BURNS REAL SATS): CONTAINER_HD_RELAY_MAINNET=1 cargo test -p bsv-mpc-proxy \\\n\
             --test container_hd_relay_deployed_mainnet_e2e --release -- --nocapture --test-threads=1"
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

    let proxy_identity = PrivateKey::from_bytes(&[0x26u8; 32]).expect("proxy identity key");
    std::env::set_var(
        "MPC_PROXY_IDENTITY_KEY",
        hex::encode(proxy_identity.to_bytes()),
    );

    // ── 1. Real distributed authed DKG against the DEPLOYED container ──────────
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
    eprintln!("✔ DKG joint_pubkey={joint_hex}");

    // ── 1b. Derive a BRC-42 child key (the "anyone" derivation: child = joint +
    //        offset·G, offset = HMAC(joint_pub_compressed, invoice)). We fund +
    //        spend THIS child address; the offset is applied at sign-time. ──────
    let protocol = "mpc hd relay";
    let key_id = "child-key-26-001";
    let level = 2u8;
    let invoice = compute_invoice(level, protocol, key_id).expect("invoice");
    let offset: [u8; 32] = compute_brc42_hmac(&joint_pub, &invoice);
    let child_pub = derive_anyone_pubkey(&joint_pub, protocol, key_id, level).expect("child pub");
    let child_arr = child_pub.to_compressed();
    let child_locking = p2pkh_locking_script(&child_pub.hash160());
    eprintln!(
        "✔ BRC-42 child: invoice={invoice} child_pubkey={} (offset={})",
        hex::encode(child_arr),
        hex::encode(offset)
    );

    // ── 2. MpcBridge from share_B, presign_url = the container ─────────────────
    let dir = std::env::temp_dir();
    let share_path = dir.join(format!(
        "hd_relay_container_share_{}.json",
        std::process::id()
    ));
    tokio::fs::write(&share_path, serde_json::to_vec(&dkg_b).unwrap())
        .await
        .expect("write share file");
    let proxy_config = ProxyConfig {
        port: 3336,
        kss_url: container_url.clone(),
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
        presign_url: Some(container_url.clone()),
        approval_recv_timeout_secs: 60,
        network: None,
        policy_manifest_path: None,
    };
    let bridge = MpcBridge::new(&proxy_config)
        .await
        .expect("MpcBridge::new (BRC-31 handshake with deployed container)");
    eprintln!("✔ proxy authed with deployed container");

    // ── 3. §06.17.1 presign over the relay → durable PresigBundle (base key) ───
    let bundle_dir = tempfile::tempdir().expect("bundle dir");
    let bundle_store = Arc::new(FileBundleStore::new(bundle_dir.path()).expect("bundle store"));
    let at_rest_root = [0x42u8; 32];
    let bundle = bridge
        .coordinate_presign_bundle(
            bundle_store.clone(),
            at_rest_root,
            PolicyId([0u8; 32]),
            Duration::from_secs(180),
        )
        .await
        .expect("§06.17.1 presign over relay → bundle");
    let bundle = bundle_store.get(&bundle.presig_id).expect("bundle reloads");
    eprintln!("✔ PresigBundle assembled — presig_id={}", bundle.presig_id);

    // ── 4. Fund the CHILD P2PKH on mainnet via wallet:3321 ─────────────────────
    let funding_amount: u64 = 1500;
    let fund_resp = http
        .post("http://localhost:3321/createAction")
        .header("Origin", "http://admin.com")
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "description": "bsv-mpc §06.20 HD-over-relay gate (fund child)",
            "outputs": [{
                "satoshis": funding_amount,
                "lockingScript": hex::encode(&child_locking),
                "outputDescription": "MPC BRC-42 child P2PKH"
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
    eprintln!("✔ funded child address: txid={fund_txid}");
    if let Some(raw) = raw_tx_hex_from_create_action(&fund_json) {
        eprintln!("  self-broadcasting funding tx via ARC...");
        let _ = broadcast_via_arc(&http, &raw).await;
    }

    // ── 5. Find the UTXO + build the BIP-143 sighash over the CHILD script ─────
    let locking_hex = hex::encode(&child_locking);
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
        subscript: &child_locking,
        satoshis: value,
        scope,
    });
    eprintln!("✔ sighash: {}", hex::encode(sighash));

    // ── 6. §06.20 HD sign from the bundle over the relay WITH the offset ───────
    //     The coordinator applies the offset to its presig + public data; the
    //     deployed container applies the SAME offset via decrypt_and_issue_partial.
    let sig = bridge
        .sign_from_bundle_over_relay(
            &sighash,
            &bundle,
            at_rest_root,
            Duration::from_secs(60),
            Some(offset),
        )
        .await
        .expect("§06.20 HD sign from bundle over relay (offset applied both sides)");
    eprintln!(
        "✔ co-signed via §06.20 HD relay path: DER {} bytes",
        sig.signature.len()
    );

    // ── 7. PRE-FLIGHT verify under the CHILD key — fail-closed BEFORE broadcast ─
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.r);
    s.copy_from_slice(&sig.s);
    let bsv_sig = Signature::new(r, s);
    assert!(bsv_sig.is_low_s(), "MPC signature MUST be low-s (BIP-62)");
    assert!(
        child_pub.verify(&sighash, &bsv_sig),
        "PRE-FLIGHT: HD signature MUST verify under the CHILD pubkey (joint + offset·G)"
    );
    assert!(
        !joint_pub.verify(&sighash, &bsv_sig),
        "HD signature MUST NOT verify under the base joint key (offset must have taken effect)"
    );
    eprintln!(
        "✔ pre-flight: verifies under CHILD key, rejects under base key — offset took effect"
    );

    // ── 8. Assemble + broadcast (unlock with the CHILD pubkey) ─────────────────
    let tx_sig = TransactionSignature::new(bsv_sig, scope);
    let unlocking = p2pkh_unlocking_script(&tx_sig.to_checksig_format(), &child_arr);
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
    eprintln!("║  §06.20 HD-DERIVED CHILD-KEY SIGN OVER RELAY — DEPLOYED — REAL ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!("  base joint_pubkey: {joint_hex}");
    eprintln!("  invoice:           {invoice}");
    eprintln!("  child_pubkey:      {}", hex::encode(child_arr));
    eprintln!("  child_address:     spent (BRC-42 derived)");
    eprintln!("  funding_txid:      {fund_txid}");
    eprintln!("  spending_txid:     {txid_hex}  (signed with BRC-42 offset over the relay)");
    eprintln!("  view: https://whatsonchain.com/tx/{txid_hex}");
    eprintln!("  total wall-clock: {:?}", t0.elapsed());
}
