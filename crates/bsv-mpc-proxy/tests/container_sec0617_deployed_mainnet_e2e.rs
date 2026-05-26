//! **§06.17.1 CONTAINER-target — DEPLOYED, REAL SATS (issue #30 / #25c Stage 2).**
//!
//! The capstone for the corrected Stage 2: the deployed CF **Container** cosigner
//! (`bsv-mpc-service-container`, full native `bsv-mpc-service`) generates + BRC-2
//! self-encrypts its OWN presig share over the live relay; the proxy =
//! coordinator holds ONLY the opaque ciphertext (the §06.17.1 threshold gain over
//! the POC proxy-knows-both-shares shortcut), persists the `PresigBundle`, and at
//! sign-time ships the ciphertext back to the container's `/sign-relay`. The
//! container decrypts it under its OWN identity, issues + relays its partial; the
//! proxy combines into a BSV-valid signature that funds + spends a REAL mainnet TX.
//!
//! Flow:
//!   1. **Real distributed authed DKG** against the deployed container
//!      (`run_dkg_over_http_authed`) → the container holds `share_A` (recorded
//!      owner = the proxy identity, §08.1); the proxy holds `share_B`. No trusted
//!      dealer — neither party ever holds the other's share.
//!   2. `MpcBridge` from `share_B`, `presign_url` = the container (the heavy-MPC
//!      cosigner) — handshakes BRC-31 with it.
//!   3. `coordinate_presign_bundle` → drives the §06.17.1 presign over the relay;
//!      the container self-presigns + self-encrypts; the bundle is persisted to a
//!      `FileBundleStore`.
//!   4. Fund the joint P2PKH on mainnet via wallet:3321; self-broadcast the funding
//!      tx via ARC (wallet broadcast doesn't always propagate — #25b); build the
//!      BIP-143 sighash.
//!   5. `sign_from_bundle_over_relay` → ships the container's own ciphertext to
//!      `/sign-relay`; the container decrypts + co-signs over the relay; the proxy
//!      combines.
//!   6. PRE-FLIGHT verify (low-s + joint-pubkey) — fail-closed BEFORE broadcast.
//!   7. Broadcast via ARC; cite the TXID.
//!
//! REAL SATS. Gated on `CONTAINER_SEC0617_MAINNET=1`. Requires a BRC-100 wallet at
//! `http://localhost:3321` (Origin `http://admin.com`) with spendable sats, plus
//! outbound to WhatsOnChain + ARC. `DEPLOYED_CONTAINER_URL` /
//! `MESSAGEBOX_RELAY_URL` default to the Calhoun `dev-a3e` deployments.
//!
//! ```bash
//! CONTAINER_SEC0617_MAINNET=1 cargo test -p bsv-mpc-proxy \
//!   --test container_sec0617_deployed_mainnet_e2e \
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
use bsv_mpc_core::types::{PolicyId, ThresholdConfig};
use bsv_mpc_proxy::bridge::{run_dkg_over_http_authed, MpcBridge};
use bsv_mpc_proxy::config::ProxyConfig;
use bsv_mpc_service::FileBundleStore;

const DEFAULT_CONTAINER: &str = "https://bsv-mpc-service-container.dev-a3e.workers.dev";
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";

fn opt_in() -> bool {
    std::env::var("CONTAINER_SEC0617_MAINNET").ok().as_deref() == Some("1")
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
    // env `TAAL_ARC_TOKEN`, else the known mainnet key in secrets.md. (The bare
    // tokenless broadcaster 401s on TAAL — burned a real-sats run during #26.)
    let taal_token = std::env::var("TAAL_ARC_TOKEN")
        .unwrap_or_else(|_| "mainnet_9596de07e92300c6287e4393594ae39c".to_string());
    for arc in &["https://arc.gorillapool.io", "https://arc.taal.com"] {
        let url = format!("{arc}/v1/tx");
        eprintln!("  broadcast via {url}");
        let mut req = http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("XDeployment-ID", "bsv-mpc-sec0617-container")
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

/// BEEF V1 hex (ancestry-bearing, ARC-acceptable) from a wallet `createAction`
/// response (`tx` is AtomicBEEF). Falls back to bare raw tx hex if V1 can't be
/// built (unconfirmed parent without included source). ARC's `rawTx` accepts
/// BEEF V1 but 460s on a bare raw tx whose parent isn't already known.
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

#[tokio::test]
async fn container_sec0617_self_presign_deployed_real_mainnet_tx() {
    if !opt_in() {
        eprintln!(
            "CONTAINER_SEC0617_MAINNET=1 not set — skipping §06.17.1 CONTAINER real-sats gate.\n\
             To run (BURNS REAL SATS): CONTAINER_SEC0617_MAINNET=1 cargo test -p bsv-mpc-proxy \\\n\
             --test container_sec0617_deployed_mainnet_e2e --release -- --nocapture --test-threads=1"
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

    // The proxy's stable BRC-31 owner identity (§07.4) — used for authed DKG, the
    // presign-relay/init + sign-relay triggers, and the relay combiner identity.
    let proxy_identity = PrivateKey::from_bytes(&[0x37u8; 32]).expect("proxy identity key");
    std::env::set_var(
        "MPC_PROXY_IDENTITY_KEY",
        hex::encode(proxy_identity.to_bytes()),
    );

    // ── 1. Real distributed authed DKG against the DEPLOYED container ──────────
    //    The container holds share_A (owner-bound to the proxy identity, §08.1);
    //    the proxy holds share_B. Heavy (Paillier primes inline) — minutes.
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
        "sec0617_container_share_{}.json",
        std::process::id()
    ));
    tokio::fs::write(&share_path, serde_json::to_vec(&dkg_b).unwrap())
        .await
        .expect("write share file");
    let proxy_config = ProxyConfig {
        port: 3331,
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
        // The container is the heavy-MPC cosigner — presign + the §06.17.1 routes
        // live there.
        presign_url: Some(container_url.clone()),
    };
    let bridge = MpcBridge::new(&proxy_config)
        .await
        .expect("MpcBridge::new (BRC-31 handshake with deployed container)");
    eprintln!("✔ proxy authed with deployed container (share_B + stable identity)");

    // ── 3. §06.17.1 presign over the relay → durable PresigBundle ──────────────
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
    eprintln!(
        "✔ PresigBundle assembled — presig_id={} (container self-presigned + self-encrypted)",
        bundle.presig_id
    );
    // Reload from disk (durable across coordinator restart).
    let bundle = bundle_store
        .get(&bundle.presig_id)
        .expect("bundle reloads from disk");

    // ── 4. Fund the joint P2PKH on mainnet via wallet:3321 ─────────────────────
    // The wallet returns a txid but does not reliably propagate, and its coin
    // selection sometimes picks unconfirmed change (no on-chain ancestry → ARC
    // 460). Self-broadcast the BEEF V1 and RETRY with a fresh createAction (new
    // coin selection) until one lands (SEEN_ON_NETWORK).
    let funding_amount: u64 = 1500;
    let mut fund_txid = String::new();
    for attempt in 1..=8 {
        let fund_text = http
            .post("http://localhost:3321/createAction")
            .header("Origin", "http://admin.com")
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "description": format!("bsv-mpc §06.17.1 container self-presign gate (attempt {attempt})"),
                "outputs": [{
                    "satoshis": funding_amount,
                    "lockingScript": hex::encode(&joint_locking),
                    "outputDescription": "MPC joint P2PKH"
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
                eprintln!(
                    "✔ funded joint address: txid={txid} (broadcast BEEF v1, attempt {attempt})"
                );
                fund_txid = txid;
                break;
            }
        }
        eprintln!(
            "  funding attempt {attempt} ({txid}) did NOT broadcast (unconfirmed parent); retrying"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    assert!(
        !fund_txid.is_empty(),
        "could not get a funding tx to broadcast after 8 attempts"
    );

    // ── 5. Find the UTXO + build the BIP-143 sighash (drain back to wallet) ────
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

    // ── 6. §06.17.1 sign from the durable bundle over the relay ────────────────
    let sig = bridge
        .sign_from_bundle_over_relay(
            &sighash,
            &bundle,
            at_rest_root,
            Duration::from_secs(60),
            None,
        )
        .await
        .expect("§06.17.1 sign from bundle over relay (container decrypts + co-signs)");
    eprintln!(
        "✔ co-signed via §06.17.1 bundle path: DER {} bytes",
        sig.signature.len()
    );

    // ── 7. PRE-FLIGHT verify — fail-closed BEFORE broadcast ────────────────────
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

    // ── 8. Assemble + broadcast ────────────────────────────────────────────────
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
    eprintln!("║  §06.17.1 CONTAINER TARGET — DEPLOYED COSIGNER REAL MAINNET TX ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!("  joint_pubkey:   {joint_hex}");
    eprintln!("  joint_address:  {}", joint.address);
    eprintln!("  presig_id:      {}", bundle.presig_id);
    eprintln!("  funding_txid:   {fund_txid}");
    eprintln!("  funded_sats:    {value}");
    eprintln!("  spending_txid:  {txid_hex}");
    eprintln!("  cosigner:       deployed bsv-mpc-service CONTAINER (self-presign + self-encrypt + decrypt)");
    eprintln!("  combiner:       bsv-mpc-proxy (coordinator, held only the ciphertext)");
    eprintln!("  view: https://whatsonchain.com/tx/{txid_hex}");
    eprintln!("  total wall-clock: {:?}", t0.elapsed());
}
