//! **§18.2 key-refresh — DEPLOYED, REAL SATS (issues #10e + #22c).**
//!
//! Capstone for the refresh + invalidation story against the deployed CF
//! **Container** (`bsv-mpc-service-container`, full native `bsv-mpc-service`):
//!
//!   1. **Real distributed authed DKG** against the container → it holds
//!      `share_A` (owner-bound to the proxy identity); the proxy holds `share_B`.
//!   2. Presign **bundle #1** over the relay (§06.17.1) → persisted.
//!   3. **Refresh over the relay** (`refresh_over_relay`): the proxy + the
//!      container each re-randomize their share (same joint pubkey), the proxy
//!      hot-swaps + persists `share_B`, and the §06.18 ShareRefresh invalidation
//!      purges bundle #1.
//!      - **#22c gate:** bundle #1 is GONE from the store after the refresh — no
//!        presig generated against the pre-refresh share survives the boundary.
//!      - **§18 invariant:** the joint pubkey (BSV address) is UNCHANGED.
//!   4. Presign **bundle #2** with the now-REFRESHED shares.
//!   5. Fund the (unchanged) joint P2PKH on mainnet via wallet:3321.
//!   6. Sign from bundle #2 over the relay (container decrypts its rotated share +
//!      co-signs); the proxy combines.
//!      - **#10e gate:** PRE-FLIGHT the signature verifies under the SAME joint
//!        pubkey — i.e. BOTH refreshed shares are mutually consistent — then
//!        broadcast and cite the TXID.
//!
//! REAL SATS. Gated on `CONTAINER_REFRESH_MAINNET=1`. Requires a BRC-100 wallet at
//! `http://localhost:3321` (Origin `http://admin.com`) with spendable sats, plus
//! outbound to WhatsOnChain + ARC.
//!
//! ```bash
//! CONTAINER_REFRESH_MAINNET=1 cargo test -p bsv-mpc-proxy \
//!   --test container_refresh_deployed_mainnet_e2e \
//!   --release -- --nocapture --test-threads=1
//! ```

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv::primitives::bsv::sighash::{
    compute_sighash_for_signing, SighashParams, TxInput, TxOutput, SIGHASH_ALL, SIGHASH_FORKID,
};
use bsv::primitives::bsv::tx_signature::TransactionSignature;
use bsv::primitives::ec::{PrivateKey, PublicKey, Signature};
use bsv::primitives::encoding::Writer;
use bsv::primitives::hash::sha256d;
use bsv_mpc_core::types::{PolicyId, ThresholdConfig};
use bsv_mpc_proxy::bridge::{run_dkg_over_http_authed, MpcBridge};
use bsv_mpc_proxy::config::ProxyConfig;
use bsv_mpc_proxy::presign_manager::PresignManager;
use bsv_mpc_service::FileBundleStore;

const DEFAULT_CONTAINER: &str = "https://bsv-mpc-service-container.dev-a3e.workers.dev";
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";

fn opt_in() -> bool {
    std::env::var("CONTAINER_REFRESH_MAINNET").ok().as_deref() == Some("1")
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
    for arc in &["https://arc.gorillapool.io", "https://arc.taal.com"] {
        let url = format!("{arc}/v1/tx");
        eprintln!("  broadcast via {url}");
        let Ok(resp) = http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("XDeployment-ID", "bsv-mpc-refresh-container")
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

fn raw_tx_hex_from_create_action(resp: &serde_json::Value) -> Option<String> {
    let arr = resp.get("tx")?.as_array()?;
    let beef: Vec<u8> = arr.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect();
    let tx = bsv::Transaction::from_atomic_beef(&beef)
        .or_else(|_| bsv::Transaction::from_beef(&beef, None))
        .ok()?;
    Some(tx.to_hex())
}

#[tokio::test]
async fn container_refresh_then_sign_deployed_real_mainnet_tx() {
    if !opt_in() {
        eprintln!(
            "CONTAINER_REFRESH_MAINNET=1 not set — skipping §18.2 refresh real-sats gate.\n\
             To run (BURNS REAL SATS): CONTAINER_REFRESH_MAINNET=1 cargo test -p bsv-mpc-proxy \\\n\
             --test container_refresh_deployed_mainnet_e2e --release -- --nocapture --test-threads=1"
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

    let proxy_identity = PrivateKey::from_bytes(&[0x37u8; 32]).expect("proxy identity key");
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
    let joint_locking = p2pkh_locking_script(&joint_pub.hash160());
    eprintln!("✔ DKG joint_pubkey={joint_hex} address={}", joint.address);

    // ── 2. MpcBridge from share_B, presign_url = the container ─────────────────
    let dir = std::env::temp_dir();
    let share_path = dir.join(format!("refresh_container_share_{}.json", std::process::id()));
    let share_path_str = share_path.to_string_lossy().to_string();
    tokio::fs::write(&share_path, serde_json::to_vec(&dkg_b).unwrap())
        .await
        .expect("write share file");
    let proxy_config = ProxyConfig {
        port: 3332,
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

    let bundle_dir = tempfile::tempdir().expect("bundle dir");
    let bundle_store = Arc::new(FileBundleStore::new(bundle_dir.path()).expect("bundle store"));
    let presign_manager = Arc::new(RwLock::new(PresignManager::new(16)));
    let at_rest_root = [0x42u8; 32];

    // ── 3. Presign bundle #1 (PRE-refresh) ─────────────────────────────────────
    let bundle1 = bridge
        .coordinate_presign_bundle(
            bundle_store.clone(),
            at_rest_root,
            PolicyId([0u8; 32]),
            Duration::from_secs(180),
        )
        .await
        .expect("pre-refresh presign bundle");
    let bundle1_id = bundle1.presig_id.clone();
    assert!(
        bundle_store.get(&bundle1_id).is_some(),
        "pre-refresh bundle MUST be in the store"
    );
    eprintln!("✔ pre-refresh PresigBundle #1 persisted: presig_id={bundle1_id}");

    // ── 4. REFRESH over the relay (rotation-on-commit + §06.18 invalidation) ────
    eprintln!("(refresh over the relay against the deployed container — ~seconds)");
    let (refreshed_jpk_hex, purged) = bridge
        .refresh_over_relay(
            &share_path_str,
            None,
            bundle_store.clone(),
            presign_manager.clone(),
            Duration::from_secs(120),
        )
        .await
        .expect("§18.2 refresh over relay");
    eprintln!("✔ refresh committed — purged {purged} bundle(s); jpk={refreshed_jpk_hex}");

    // §18 invariant: joint pubkey UNCHANGED.
    assert_eq!(
        refreshed_jpk_hex, joint_hex,
        "§18: joint pubkey MUST be unchanged by refresh (same address, no funds move)"
    );
    // #22c gate: the pre-refresh bundle is GONE (invalidated atomically).
    assert!(
        bundle_store.get(&bundle1_id).is_none(),
        "#22c: pre-refresh bundle MUST be purged by the ShareRefresh invalidation"
    );
    assert!(purged >= 1, "at least bundle #1 was purged");
    // Single-use/consume of the purged bundle yields nothing (defense in depth).
    {
        use bsv_mpc_service::BundleStore;
        assert!(
            bundle_store.consume(&bundle1_id).unwrap().is_none(),
            "#22c: a purged bundle MUST NOT be consumable across the refresh boundary"
        );
    }
    eprintln!("✔ #22c: pre-refresh bundle #{bundle1_id} purged + unconsumable");

    // ── 5. Presign bundle #2 with the REFRESHED shares ─────────────────────────
    let bundle2 = bridge
        .coordinate_presign_bundle(
            bundle_store.clone(),
            at_rest_root,
            PolicyId([0u8; 32]),
            Duration::from_secs(180),
        )
        .await
        .expect("post-refresh presign bundle (refreshed shares)");
    let bundle2 = bundle_store
        .get(&bundle2.presig_id)
        .expect("bundle #2 reloads from disk");
    assert_ne!(bundle2.presig_id, bundle1_id, "bundle #2 is a fresh presig");
    eprintln!("✔ post-refresh PresigBundle #2 (refreshed shares): presig_id={}", bundle2.presig_id);

    // ── 6. Fund the (UNCHANGED) joint P2PKH on mainnet ─────────────────────────
    let funding_amount: u64 = 1500;
    let fund_resp = http
        .post("http://localhost:3321/createAction")
        .header("Origin", "http://admin.com")
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "description": "bsv-mpc §18.2 refresh-then-sign gate",
            "outputs": [{
                "satoshis": funding_amount,
                "lockingScript": hex::encode(&joint_locking),
                "outputDescription": "MPC joint P2PKH (post-refresh, same address)"
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
    let fund_txid = fund_json["txid"].as_str().expect("createAction txid").to_string();
    eprintln!("✔ funded joint address: txid={fund_txid}");
    if let Some(raw) = raw_tx_hex_from_create_action(&fund_json) {
        eprintln!("  self-broadcasting funding tx via ARC...");
        let _ = broadcast_via_arc(&http, &raw).await;
    }

    // ── 7. Find UTXO + BIP-143 sighash (drain back to wallet) ──────────────────
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
    let change_script =
        p2pkh_locking_script(&PublicKey::from_hex(&wallet_pub_hex).expect("wallet pub").hash160());

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

    // ── 8. Sign from bundle #2 (REFRESHED shares) over the relay ───────────────
    let sig = bridge
        .sign_from_bundle_over_relay(&sighash, &bundle2, at_rest_root, Duration::from_secs(60))
        .await
        .expect("§06.17.1 sign from refreshed bundle over relay");
    eprintln!("✔ co-signed with REFRESHED shares: DER {} bytes", sig.signature.len());

    // ── 9. PRE-FLIGHT verify under the SAME joint pubkey (refreshed shares are
    //       mutually consistent) — fail-closed BEFORE broadcast ────────────────
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.r);
    s.copy_from_slice(&sig.s);
    let bsv_sig = Signature::new(r, s);
    assert!(bsv_sig.is_low_s(), "MPC signature MUST be low-s (BIP-62)");
    assert!(
        joint_pub.verify(&sighash, &bsv_sig),
        "PRE-FLIGHT: REFRESHED-share signature MUST verify under the UNCHANGED joint pubkey"
    );
    eprintln!("✔ pre-flight ECDSA verify under joint pubkey (refreshed shares): PASS");

    // ── 10. Assemble + broadcast ───────────────────────────────────────────────
    let tx_sig = TransactionSignature::new(bsv_sig, scope);
    let unlocking = p2pkh_unlocking_script(&tx_sig.to_checksig_format(), &joint_pub.to_compressed());
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
    assert!(ok, "ARC broadcast MUST succeed — TXID={txid_hex} rawTx={raw_tx_hex}");

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  §18.2 REFRESH — DEPLOYED CONTAINER — REAL MAINNET TX          ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!("  joint_pubkey:     {joint_hex} (UNCHANGED by refresh)");
    eprintln!("  joint_address:    {}", joint.address);
    eprintln!("  bundle#1 (pre):   {bundle1_id} — PURGED on refresh (#22c)");
    eprintln!("  bundles_purged:   {purged}");
    eprintln!("  bundle#2 (post):  {} — refreshed shares", bundle2.presig_id);
    eprintln!("  funding_txid:     {fund_txid}");
    eprintln!("  funded_sats:      {value}");
    eprintln!("  spending_txid:    {txid_hex}");
    eprintln!("  cosigner:         deployed bsv-mpc-service CONTAINER (refreshed share_A)");
    eprintln!("  view: https://whatsonchain.com/tx/{txid_hex}");
    eprintln!("  total wall-clock: {:?}", t0.elapsed());
}
