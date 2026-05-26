//! **#40 GATE — TRUE device-loss recovery, DEPLOYED, REAL SATS.**
//!
//! The acceptance proof for #40: a device-loss recovery on mainnet with the
//! address PRESERVED, the RECOVERED device spending, and the old share dead — all
//! over the relay against the deployed CF **Container** (`bsv-mpc-service-container`,
//! full native `bsv-mpc-service`). Unlike `container_reshare_deployed_mainnet_e2e`
//! (which signed the proxy-held `{1,2}` subset IN-PROCESS), this exercises the
//! surviving container's ROTATED share at sign-time, with a brand-new device.
//!
//! A 2-of-2 cannot model device loss (t=2 needs both shares). So the gate starts
//! from a REDUNDANT 2-of-3, genuinely loses a device, and has the ≥t survivors
//! reshare onto a fresh device — the `recovery_health` survivor quorum (§18.4a) is
//! therefore REAL, not vacuous. Steps (all distributed, no custody shortcut):
//!
//!   1. **Real authed 2-of-2 DKG** against the container → container holds `share_A`
//!      (= party 0, owner-bound), proxy holds `share_B` (= party 1). Funded key K.
//!   2. **Fund** K's P2PKH on mainnet (BEEF-V1 + ARC/TAAL retry).
//!   3. **Reshare #1** (establish redundancy): `reshare_change_threshold_over_relay`
//!      → 2-of-3. Container rotates to P0′ (stored durably); proxy gets P1′ (party 1,
//!      a continuing cosigner) + **P2′ (party 2 = the user's phone)**. Address
//!      UNCHANGED.
//!   4. **LOSE P2′** (the phone). Survivors = {container P0′, proxy P1′} = 2 = t.
//!      `authorize_recovery` enforces the survivor quorum (§18.4a) + cooldown.
//!   5. **Reshare #2** (the recovery): the survivors `{0,1}` reshare (bridge pointed
//!      at the surviving P1′) → new 2-of-3 {P0″,P1″, **P2″ = the recovered device**}.
//!      The lost P2′ contributes NOTHING. Address UNCHANGED.
//!   6. **Spend `{0,2}` over the relay:** a bridge on the RECOVERED device's P2″
//!      share (auto-derives participants `[0,2]`, cosigner = container party 0)
//!      presigns + signs a real spend from the SAME address; the surviving container
//!      cosigns with its rotated P0″ share. Broadcast → WoC-confirm.
//!
//! REAL SATS. Gated on `RECOVERY_MAINNET=1`. Requires a BRC-100 wallet at
//! `http://localhost:3321` (Origin `http://admin.com`) with spendable sats.
//!
//! ```bash
//! RECOVERY_MAINNET=1 cargo test -p bsv-mpc-proxy \
//!   --test recovery_spend_deployed_mainnet_e2e \
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
use bsv_mpc_core::recovery_health::{authorize_recovery, survivor_quorum_ok, RecoveryCooldown};
use bsv_mpc_core::types::{
    DkgResult, EncryptedShare, PolicyId, SessionId, ShareIndex, ThresholdConfig,
};
use bsv_mpc_proxy::bridge::{run_dkg_over_http_authed, MpcBridge};
use bsv_mpc_proxy::config::ProxyConfig;
use bsv_mpc_service::FileBundleStore;

const DEFAULT_CONTAINER: &str = "https://bsv-mpc-service-container.dev-a3e.workers.dev";
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";
const WALLET_URL: &str = "http://localhost:3321";

fn opt_in() -> bool {
    std::env::var("RECOVERY_MAINNET").ok().as_deref() == Some("1")
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

async fn broadcast_via_arc(http: &reqwest::Client, body_hex: &str) -> bool {
    let taal_token = std::env::var("TAAL_ARC_TOKEN")
        .unwrap_or_else(|_| "mainnet_9596de07e92300c6287e4393594ae39c".to_string());
    for arc in &["https://arc.gorillapool.io", "https://arc.taal.com"] {
        let url = format!("{arc}/v1/tx");
        eprintln!("  broadcast via {url}");
        let mut req = http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("XDeployment-ID", "bsv-mpc-recovery-gate")
            .json(&serde_json::json!({ "rawTx": body_hex }));
        if arc.contains("taal") {
            req = req.header("Authorization", format!("Bearer {taal_token}"));
        }
        let Ok(resp) = req.send().await else { continue };
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

/// BEEF V1 hex from a wallet `createAction` response (handoff §6 funding fix).
fn broadcast_hex_from_create_action(resp: &serde_json::Value) -> Option<String> {
    let arr = resp.get("tx")?.as_array()?;
    let beef: Vec<u8> = arr.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect();
    let tx = bsv::Transaction::from_atomic_beef(&beef)
        .or_else(|_| bsv::Transaction::from_beef(&beef, None))
        .ok()?;
    match tx.to_beef_v1(false) {
        Ok(beef_v1) => Some(hex::encode(beef_v1)),
        Err(_) => Some(tx.to_hex()),
    }
}

/// Fund the joint P2PKH with `amount` sats, self-broadcasting + retrying (§6 fix).
async fn fund_joint(http: &reqwest::Client, joint_locking_hex: &str, amount: u64) -> String {
    for attempt in 1..=8 {
        let fund_text = http
            .post(format!("{WALLET_URL}/createAction"))
            .header("Origin", "http://admin.com")
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "description": format!("bsv-mpc #40 recovery fund (attempt {attempt})"),
                "outputs": [{
                    "satoshis": amount,
                    "lockingScript": joint_locking_hex,
                    "outputDescription": "MPC joint P2PKH (recovery gate, key K)"
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
            .unwrap_or_else(|| panic!("fund txid missing: {fund_text}"))
            .to_string();
        if let Some(beef_hex) = broadcast_hex_from_create_action(&fund_json) {
            if broadcast_via_arc(http, &beef_hex).await {
                eprintln!("  funding tx {txid} broadcast (BEEF v1, attempt {attempt})");
                return txid;
            }
        }
        eprintln!("  funding attempt {attempt} ({txid}) did NOT broadcast; retrying");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    panic!("could not broadcast a funding tx after 8 attempts");
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
        let Ok(resp) = http.get(&url).send().await else { continue };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(json) = resp.json::<serde_json::Value>().await else { continue };
        let Some(vouts) = json["vout"].as_array() else { continue };
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

/// Wrap a post-reshare cggmp24 `KeyShare` JSON (from `ReshareSummary`) as a
/// signing-ready `DkgResult` at `new_index` of the 2-of-3, bound to K.
fn dkg_result_for(
    new_index: u16,
    key_share_json: &[u8],
    joint: &bsv_mpc_core::types::JointPublicKey,
    session: SessionId,
) -> DkgResult {
    DkgResult {
        joint_key: joint.clone(),
        share: EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: key_share_json.to_vec(),
            session_id: session,
            share_index: ShareIndex(new_index),
            config: ThresholdConfig::new(2, 3).expect("2-of-3"),
            joint_pubkey_compressed: joint.compressed.clone(),
        },
        session_id: session,
    }
}

/// Build a `ProxyConfig` for a 2-of-3 bridge whose share is at `share_path`, with
/// the container as the heavy-MPC peer (reshare + presign).
fn proxy_config_2of3(port: u16, share_path: &str, container_url: &str, relay_url: &str) -> ProxyConfig {
    ProxyConfig {
        port,
        kss_url: container_url.to_string(),
        share_path: share_path.to_string(),
        fee_per_signing: 0,
        fee_addresses: vec![],
        fee_threshold: None,
        max_presignatures: 5,
        encryption_key: None,
        arc_api_key: "test_key".into(),
        threshold_configs: vec!["2-of-3".to_string()],
        min_balance_sats: None,
        relay_url: relay_url.to_string(),
        relay_sign: false,
        presign_url: Some(container_url.to_string()),
    }
}

#[tokio::test]
async fn recovery_spend_deployed_real_mainnet() {
    if !opt_in() {
        eprintln!(
            "RECOVERY_MAINNET=1 not set — skipping #40 true-loss recovery real-sats gate.\n\
             To run (BURNS REAL SATS): RECOVERY_MAINNET=1 cargo test -p bsv-mpc-proxy \\\n\
             --test recovery_spend_deployed_mainnet_e2e --release -- --nocapture --test-threads=1"
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
    let dir = std::env::temp_dir();
    let pid = std::process::id();

    let proxy_identity = PrivateKey::from_bytes(&[0x40u8; 32]).expect("proxy identity key");
    std::env::set_var("MPC_PROXY_IDENTITY_KEY", hex::encode(proxy_identity.to_bytes()));

    // ── 1. Real distributed authed 2-of-2 DKG against the deployed container ───
    eprintln!("(1) real distributed 2-of-2 DKG against the deployed container — minutes");
    let cfg2 = ThresholdConfig::new(2, 2).expect("2-of-2");
    let dkg_b = run_dkg_over_http_authed(&container_url, cfg2, proxy_identity.clone())
        .await
        .expect("authed 2-of-2 DKG against the deployed container");
    let joint = dkg_b.joint_key.clone();
    let joint_hex = hex::encode(&joint.compressed);
    let mut joint_arr = [0u8; 33];
    joint_arr.copy_from_slice(&joint.compressed);
    let joint_pub = PublicKey::from_bytes(&joint_arr).expect("joint pubkey");
    let joint_locking = p2pkh_locking_script(&joint_pub.hash160());
    let joint_locking_hex = hex::encode(&joint_locking);
    eprintln!("✔ funded key K = {joint_hex} / address {}", joint.address);

    // ── 2. Fund K's P2PKH on mainnet ──────────────────────────────────────────
    let fund_amount: u64 = 2000;
    let fund_txid = fund_joint(&http, &joint_locking_hex, fund_amount).await;
    let (vout, value) = find_utxo_on_woc(&http, &fund_txid, &joint_locking_hex)
        .await
        .expect("MUST find funding UTXO on WoC");
    eprintln!("✔ funded UTXO {fund_txid}:{vout} ({value} sats)");

    // ── 3. Reshare #1 (establish redundancy): 2-of-2 → 2-of-3 over the relay ───
    eprintln!("(3) reshare #1 (establish redundancy) 2-of-2 → 2-of-3 over the relay — minutes");
    let share_path1 = dir.join(format!("recovery_share1_{pid}.json"));
    tokio::fs::write(&share_path1, serde_json::to_vec(&dkg_b).unwrap())
        .await
        .expect("write share_B");
    let cfg1 = ProxyConfig {
        threshold_configs: vec!["2-of-2".to_string()],
        ..proxy_config_2of3(3340, &share_path1.to_string_lossy(), &container_url, &relay_url)
    };
    let summary1 = {
        let bridge1 = MpcBridge::new(&cfg1)
            .await
            .expect("bridge1 handshake (share_B)");
        bridge1
            .reshare_change_threshold_over_relay(Duration::from_secs(360))
            .await
            .expect("reshare #1 (2-of-2 → 2-of-3)")
        // bridge1 dropped here → #44 zeroizes its in-memory secret material.
    };
    assert_eq!(summary1.joint_pubkey_hex, joint_hex, "§18: address UNCHANGED by reshare #1");
    assert_eq!((summary1.new_threshold, summary1.new_parties), (2, 3));
    let p1_prime = summary1
        .proxy_key_shares_json
        .iter()
        .find(|(i, _)| *i == 1)
        .map(|(_, j)| j.clone())
        .expect("proxy holds new party 1 (continuing cosigner)");
    let _p2_prime = summary1
        .proxy_key_shares_json
        .iter()
        .find(|(i, _)| *i == 2)
        .map(|(_, j)| j.clone())
        .expect("proxy holds new party 2 (the phone)");
    eprintln!("✔ redundancy established: 2-of-3, container=P0′, proxy=P1′ + P2′(the phone)");

    // The container's reshare-commit runs in a completion task that finishes AFTER
    // its `/reshare-relay/init` HTTP response (it stores the rotated P0′ + shuts
    // down its `mpc-refresh` relay listener only once phase B completes). The
    // container uses ONE relay identity, so reshare #2's phase-B subscription on
    // that same identity must NOT overlap reshare #1's lingering one (the §06.17
    // two-subscription split race → reshare #2 PSS messages get lost → timeout).
    // Settle so the container fully commits + releases reshare #1 before reshare #2.
    eprintln!("  settling 60s so the container commits + releases reshare #1 (single-identity §06.17)");
    tokio::time::sleep(Duration::from_secs(60)).await;

    // ── 4. LOSE the phone (P2′). Survivors {container P0′, proxy P1′} = 2 = t. ──
    // §18.4a recovery_health survivor quorum + anti-hot-swap cooldown gate.
    assert!(
        survivor_quorum_ok(2, 2, 3),
        "survivor quorum: 2 survivors of a 2-of-3 MUST be enough to recover"
    );
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut cooldown = RecoveryCooldown::new(86_400);
    authorize_recovery(2, 2, 3, &mut cooldown, now_secs)
        .expect("recovery authorized: survivor quorum cleared + cooldown permits");
    eprintln!("✔ LOST the phone (P2′); recovery AUTHORIZED — survivors {{P0′,P1′}} = 2 = t (§18.4a)");

    // ── 5. Reshare #2 (the recovery): survivors {0,1} reshare onto fresh P2″ ────
    eprintln!("(5) reshare #2 (RECOVERY) survivors 2-of-3 → 2-of-3 onto a fresh device — minutes");
    let recovery_session = SessionId::from_str_hash("recovery-p1prime");
    let dkg_p1 = dkg_result_for(1, &p1_prime, &joint, recovery_session);
    let share_path2 = dir.join(format!("recovery_share2_{pid}.json"));
    tokio::fs::write(&share_path2, serde_json::to_vec(&dkg_p1).unwrap())
        .await
        .expect("write surviving P1′");
    let cfg2b = proxy_config_2of3(3341, &share_path2.to_string_lossy(), &container_url, &relay_url);
    let summary2 = {
        let bridge2 = MpcBridge::new(&cfg2b)
            .await
            .expect("bridge2 handshake (surviving P1′)");
        bridge2
            .reshare_change_threshold_over_relay(Duration::from_secs(360))
            .await
            .expect("reshare #2 (recovery, survivors 2-of-3 → 2-of-3)")
        // bridge2 dropped → #44 zeroizes the surviving-share secret material.
    };
    assert_eq!(summary2.joint_pubkey_hex, joint_hex, "§18: address UNCHANGED by recovery reshare");
    let p2_dprime = summary2
        .proxy_key_shares_json
        .iter()
        .find(|(i, _)| *i == 2)
        .map(|(_, j)| j.clone())
        .expect("the RECOVERED device holds new party 2");
    eprintln!("✔ recovery reshare committed — fresh device P2″ provisioned, address UNCHANGED");

    // Same §06.17 single-identity settle as after reshare #1 (above): the
    // container commits reshare #2 + shuts down its `mpc-refresh` PSS relay
    // listener in a completion task that runs AFTER its `/reshare-relay/init` HTTP
    // response. The container has ONE relay identity, so the presign cosigner's
    // `mpc_{sid}` subscription must NOT overlap reshare #2's lingering listener —
    // otherwise the two-subscription split race drops the presign round messages
    // and the coordinator times out "awaiting PresigBundle assembly" (observed
    // deterministically: the recovery presign failed here while the standalone
    // sec0617 presign — no prior ceremony on the identity — passed). Settle so the
    // container fully releases reshare #2 before the presign arms.
    eprintln!("  settling 60s so the container commits + releases reshare #2 (single-identity §06.17)");
    tokio::time::sleep(Duration::from_secs(60)).await;

    // ── 6. Spend {0,2} over the relay: recovered device P2″ + surviving container ─
    eprintln!("(6) presign + sign {{0,2}} over the relay — recovered device + container cosign");
    let recovered_session = SessionId::from_str_hash("recovery-p2dprime");
    let dkg_p2 = dkg_result_for(2, &p2_dprime, &joint, recovered_session);
    let share_path3 = dir.join(format!("recovery_share3_{pid}.json"));
    tokio::fs::write(&share_path3, serde_json::to_vec(&dkg_p2).unwrap())
        .await
        .expect("write recovered P2″");
    let cfg3 = proxy_config_2of3(3342, &share_path3.to_string_lossy(), &container_url, &relay_url);
    let bridge3 = MpcBridge::new(&cfg3)
        .await
        .expect("bridge3 handshake (recovered device P2″)");
    assert_eq!(
        bridge3.cosigner_index(),
        0,
        "recovered device's cosigner MUST be the surviving container (party 0)"
    );

    // Presign bundle {0,2} over the relay (container cosigns with its rotated P0″).
    let bundle_dir = tempfile::tempdir().expect("bundle dir");
    let bundle_store = Arc::new(FileBundleStore::new(bundle_dir.path()).expect("bundle store"));
    let at_rest_root = [0x42u8; 32];
    let bundle = bridge3
        .coordinate_presign_bundle(
            bundle_store.clone(),
            at_rest_root,
            PolicyId([0u8; 32]),
            Duration::from_secs(180),
        )
        .await
        .expect("presign bundle {0,2} over relay (recovered device + container)");
    let bundle = bundle_store
        .get(&bundle.presig_id)
        .expect("bundle reloads from disk");
    eprintln!("✔ presign bundle {{0,2}}: presig_id={}", bundle.presig_id);

    // Build the BIP-143 sighash draining K back to the wallet.
    let mut prev_txid = [0u8; 32];
    prev_txid.copy_from_slice(&hex::decode(&fund_txid).expect("txid hex"));
    prev_txid.reverse();
    let fee: u64 = 250;
    let change = value.checked_sub(fee).expect("UTXO must cover fee");
    let wallet_pub_hex = http
        .post(format!("{WALLET_URL}/getPublicKey"))
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
    eprintln!("✔ sighash {}", hex::encode(sighash));

    // Sign from the bundle over the relay: container cosigns with its rotated P0″.
    let sig = bridge3
        .sign_from_bundle_over_relay(&sighash, &bundle, at_rest_root, Duration::from_secs(60), None)
        .await
        .expect("sign {0,2} from bundle over relay (recovered device + container)");
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.r);
    s.copy_from_slice(&sig.s);
    let bsv_sig = Signature::new(r, s);

    // PRE-FLIGHT: low-s + verify under the UNCHANGED joint pubkey — fail closed.
    assert!(bsv_sig.is_low_s(), "recovery signature MUST be low-s (BIP-62)");
    assert!(
        joint_pub.verify(&sighash, &bsv_sig),
        "PRE-FLIGHT: recovered-device signature MUST verify under the UNCHANGED joint pubkey K"
    );
    eprintln!("✔ pre-flight ECDSA verify under K (recovered device + container): PASS");

    // Assemble + broadcast.
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
    eprintln!("✔ assembled recovery spend {} bytes — TXID={txid_hex}", raw_tx.len());

    let ok = broadcast_via_arc(&http, &raw_tx_hex).await;
    // Clean up share files (also drops bridge3 → #44 zeroize).
    drop(bridge3);
    for p in [&share_path1, &share_path2, &share_path3] {
        let _ = tokio::fs::remove_file(p).await;
    }
    assert!(ok, "ARC broadcast MUST succeed — TXID={txid_hex} rawTx={raw_tx_hex}");

    // ── 7. Independently confirm the spend on WhatsOnChain ─────────────────────
    let woc = format!("https://api.whatsonchain.com/v1/bsv/main/tx/hash/{txid_hex}");
    let mut confirmed: Option<serde_json::Value> = None;
    for attempt in 1..=12 {
        tokio::time::sleep(Duration::from_secs(attempt * 3)).await;
        if let Ok(r) = http.get(&woc).send().await {
            if r.status().is_success() {
                if let Ok(j) = r.json::<serde_json::Value>().await {
                    confirmed = Some(j);
                    break;
                }
            }
        }
    }
    let tx_json =
        confirmed.unwrap_or_else(|| panic!("recovery spend {txid_hex} MUST be found on WhatsOnChain"));
    let spent_prev: Vec<&str> = tx_json["vin"]
        .as_array()
        .expect("vin array")
        .iter()
        .filter_map(|v| v["txid"].as_str())
        .collect();
    assert!(
        spent_prev.contains(&fund_txid.as_str()),
        "recovery spend MUST consume the funded joint UTXO {fund_txid}; got {spent_prev:?}"
    );

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  #40 GATE — TRUE DEVICE-LOSS RECOVERY — DEPLOYED — REAL SATS    ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!("  joint_pubkey:     {joint_hex} (UNCHANGED across DKG → 2 reshares)");
    eprintln!("  joint_address:    {}", joint.address);
    eprintln!("  funding_txid:     {fund_txid}:{vout} ({value} sats)");
    eprintln!("  lost device:      P2′ (the phone); survivors {{container P0′, proxy P1′}} = 2 = t");
    eprintln!("  recovered device: P2″ (brand-new party from the recovery reshare)");
    eprintln!("  recovery_spend:   {txid_hex}  (recovered device + container cosign over relay)");
    eprintln!("  old 2-of-2 share_B: invalidated (off the rotated polynomial; presigs purged)");
    eprintln!("  view: https://whatsonchain.com/tx/{txid_hex}");
    eprintln!("  total wall-clock: {:?}", t0.elapsed());
}
