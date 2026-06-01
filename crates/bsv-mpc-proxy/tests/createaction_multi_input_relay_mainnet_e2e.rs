//! **#13 PREREQUISITE GATE — multi-input `createAction` over the relay, real
//! mainnet, ≥2 `vin`.**
//!
//! The one capability the relay sign path had NOT yet proven on mainnet: a
//! single `createAction` that spends **two or more** UTXOs, each input signed
//! over the authed MessageBox relay by the deployed cosigner. `create_action_impl`
//! loops the relay combiner per input (each `presign_manager.take_raw()` consumes
//! one correlated `Presignature_B` while the deployed cosigner consumes its
//! correlated `Presignature_A` from the DO pool), so multi-input *should* work —
//! this gate proves it at 110%: it funds ≥2 UTXOs to the joint P2PKH, provisions
//! ≥2 correlated presig pairs to BOTH pools, drives ONE `createAction` over the
//! relay spending both, pre-flight-verifies each input under the joint key inside
//! the proxy, broadcasts, and **independently confirms on WhatsOnChain that the
//! spend has ≥2 `vin`, each spending one of the funding UTXOs.**
//!
//! This MUST be green before the legacy 4-round HTTP sign path is deleted (#13):
//! after deletion there is no on-demand fallback, so multi-input relay signing is
//! the deployed reality and must be mainnet-proven first.
//!
//! Mirrors `createaction_relay_mainnet_e2e.rs` (the single-input #6 gate) and uses
//! the pool-consume relay flow against the deployed worker cosigner
//! (`/ceremony/ingest-presig` + `/sign-relay`). Local DKG + locally generated
//! presig pairs → the cosigner needs no DKG share at sign time, only the
//! correlated `Presignature_A`.
//!
//! REAL SATS. Gated on **`MULTI_INPUT_RELAY_MAINNET=1`**. Requires a BRC-100
//! wallet at `http://localhost:3321` (Origin `http://admin.com`) with spendable
//! sats.
//!
//! ```bash
//! MULTI_INPUT_RELAY_MAINNET=1 cargo test -p bsv-mpc-proxy \
//!   --test createaction_multi_input_relay_mainnet_e2e --release -- --nocapture --test-threads=1
//! ```

use std::time::Duration;

use bsv::primitives::ec::PublicKey;
use bsv::wallet::{CreateActionArgs, CreateActionOptions, CreateActionOutput};
use bsv_mpc_core::dkg::{generate_test_primes, DkgCoordinator, DkgRoundResult};
use bsv_mpc_core::presigning::{PresigningManager, PresigningRoundResult};
use bsv_mpc_core::types::{
    DkgResult, EncryptedShare, JointPublicKey, Presignature, SessionId, ShareIndex, ThresholdConfig,
};
use bsv_mpc_proxy::config::ProxyConfig;
use bsv_mpc_proxy::presign_manager::PresignManager;
use bsv_mpc_proxy::server::build_router;
use bsv_mpc_proxy::storage::InMemoryBackend;
use bsv_mpc_proxy::{MpcBridge, ProxyBuilder, TrackedOutput};

const DEFAULT_WORKER: &str = "https://bsv-mpc-kss.dev-a3e.workers.dev";
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";
const WALLET_URL: &str = "http://localhost:3321";

type PresignBox = Box<dyn std::any::Any + Send>;

fn opt_in() -> bool {
    std::env::var("MULTI_INPUT_RELAY_MAINNET").ok().as_deref() == Some("1")
}

fn p2pkh_locking_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.extend_from_slice(&[0x76, 0xa9, 0x14]);
    s.extend_from_slice(pubkey_hash);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

/// Self-broadcast a BEEF/raw-tx hex via ARC (TAAL needs a Bearer token, else 401;
/// GorillaPool is keyless). The wallet at 3321 returns a txid but may not
/// propagate the funding tx itself, so we push it onto the network directly.
/// ARC's `rawTx` field accepts BEEF V1 (which carries the parent ancestry/proofs)
/// — a bare raw tx 460s when the parent isn't already known to ARC.
async fn broadcast_via_arc(http: &reqwest::Client, body_hex: &str) -> bool {
    let taal_token = std::env::var("TAAL_ARC_TOKEN")
        .unwrap_or_else(|_| "mainnet_9596de07e92300c6287e4393594ae39c".to_string());
    for arc in &["https://arc.gorillapool.io", "https://arc.taal.com"] {
        let url = format!("{arc}/v1/tx");
        let mut req = http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("XDeployment-ID", "bsv-mpc-multi-input-gate")
            .json(&serde_json::json!({ "rawTx": body_hex }));
        if arc.contains("taal") {
            req = req.header("Authorization", format!("Bearer {taal_token}"));
        }
        let Ok(resp) = req.send().await else { continue };
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        let snippet: String = text.chars().take(300).collect();
        eprintln!("  ARC {url}: status={status} body={snippet}");
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
/// response (`tx` field is AtomicBEEF). Falls back to the bare raw tx hex if the
/// V1 conversion can't be built (e.g. unconfirmed parent without included source).
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

fn run_dkg_2of2() -> (JointPublicKey, EncryptedShare, EncryptedShare, SessionId) {
    let config = ThresholdConfig::new(2, 2).expect("2-of-2");
    let session = SessionId::from_str_hash("multi-ca-gate-dkg");
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
                assert_eq!(a.joint_key.compressed, b.joint_key.compressed);
                return (a.joint_key, a.share, b.share, session);
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

/// Generate ONE correlated presignature pair from the two DKG shares.
fn gen_presig_pair(
    share0: EncryptedShare,
    share1: EncryptedShare,
    tag: &str,
) -> (Vec<u8>, Presignature, PresignBox) {
    let session = SessionId::from_str_hash(tag);
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
            PresigningRoundResult::Complete(_) => {
                d0 = true;
                vec![]
            }
        };
        o1 = match r1 {
            PresigningRoundResult::NextRound(m) => m,
            PresigningRoundResult::Complete(_) => {
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
    let (presig_b, box1) = m1.take_raw().expect("m1 take_raw");
    (presig_a_json, presig_b, box1)
}

/// Fund the joint P2PKH with `amount` sats via the wallet at 3321, returning the
/// funding txid that **actually broadcast** to the network.
///
/// The wallet at 3321 does not reliably propagate its own txs and its coin
/// selection sometimes picks leftover *unconfirmed* change (whose ancestry isn't
/// on-chain → ARC 460 "parent not found"). So we self-broadcast each candidate's
/// BEEF V1 and RETRY with a fresh `createAction` (new coin selection) until one
/// lands — each retry burns through unconfirmed UTXOs toward the confirmed ones.
async fn fund_joint(
    http: &reqwest::Client,
    joint_locking_hex: &str,
    amount: u64,
    label: &str,
) -> String {
    for attempt in 1..=8 {
        let fund_text = http
            .post(format!("{WALLET_URL}/createAction"))
            .header("Origin", "http://admin.com")
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "description": format!("{label} (attempt {attempt})"),
                "outputs": [{
                    "satoshis": amount,
                    "lockingScript": joint_locking_hex,
                    "outputDescription": "MPC joint P2PKH (multi-input gate)"
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
        eprintln!(
            "  funding attempt {attempt} ({txid}) did NOT broadcast (unconfirmed parent); retrying"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    panic!("could not get a funding tx to broadcast after 8 attempts — wallet has no confirmed-parent UTXOs available");
}

async fn find_utxo_on_woc(
    http: &reqwest::Client,
    fund_txid: &str,
    expected_locking_hex: &str,
) -> Option<(u32, u64)> {
    let url = format!("https://api.whatsonchain.com/v1/bsv/main/tx/hash/{fund_txid}");
    for attempt in 1..=10 {
        tokio::time::sleep(Duration::from_secs(attempt * 3)).await;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_input_createaction_over_relay_real_mainnet() {
    if !opt_in() {
        eprintln!(
            "MULTI_INPUT_RELAY_MAINNET=1 not set — skipping #13 multi-input relay gate.
To run (BURNS REAL SATS): MULTI_INPUT_RELAY_MAINNET=1 cargo test -p bsv-mpc-proxy \\
  --test createaction_multi_input_relay_mainnet_e2e --release -- --nocapture --test-threads=1"
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

    // ── 1. DKG + TWO correlated presig pairs ───────────────────────────────
    let (joint, share0, share1, dkg_session) = run_dkg_2of2();
    let mut joint_arr = [0u8; 33];
    joint_arr.copy_from_slice(&joint.compressed);
    let joint_pub = PublicKey::from_bytes(&joint_arr).expect("joint pubkey");
    let joint_locking = p2pkh_locking_script(&joint_pub.hash160());
    let joint_locking_hex = hex::encode(&joint_locking);
    eprintln!(
        "✔ joint pubkey {} / {}",
        hex::encode(joint_arr),
        joint.address
    );

    let (a0_json, b0, box_b0) =
        gen_presig_pair(share0.clone(), share1.clone(), "multi-ca-presig-0");
    let (a1_json, b1, box_b1) =
        gen_presig_pair(share0.clone(), share1.clone(), "multi-ca-presig-1");
    eprintln!("✔ generated 2 correlated presig pairs");

    // ── 2. Fund TWO UTXOs to the joint P2PKH via wallet:3321 ────────────────
    let fund_amount: u64 = 2000;
    let fund_txid_0 = fund_joint(
        &http,
        &joint_locking_hex,
        fund_amount,
        "#13 multi-input fund 0",
    )
    .await;
    eprintln!("✔ funded joint UTXO #0: txid={fund_txid_0}");
    let fund_txid_1 = fund_joint(
        &http,
        &joint_locking_hex,
        fund_amount,
        "#13 multi-input fund 1",
    )
    .await;
    eprintln!("✔ funded joint UTXO #1: txid={fund_txid_1}");

    // ── 3. Find both UTXOs on WhatsOnChain ──────────────────────────────────
    let (vout0, value0) = find_utxo_on_woc(&http, &fund_txid_0, &joint_locking_hex)
        .await
        .expect("MUST find funding UTXO #0 on WoC");
    let (vout1, value1) = find_utxo_on_woc(&http, &fund_txid_1, &joint_locking_hex)
        .await
        .expect("MUST find funding UTXO #1 on WoC");
    eprintln!("✔ UTXO #0 {fund_txid_0}:{vout0} ({value0} sats)");
    eprintln!("✔ UTXO #1 {fund_txid_1}:{vout1} ({value1} sats)");

    // ── 4. Build the proxy: relay mode, seeded storage (2 UTXOs) + pool (2 box_B) ──
    let dkg_result = DkgResult {
        joint_key: joint.clone(),
        share: share1,
        session_id: dkg_session,
    };
    let dir = std::env::temp_dir();
    let share_path = dir.join(format!("multi_ca_gate_share_{}.json", std::process::id()));
    tokio::fs::write(&share_path, serde_json::to_vec(&dkg_result).unwrap())
        .await
        .expect("write share");
    let port = 13422u16;
    let config = ProxyConfig {
        port,
        kss_url: worker_url.clone(),
        share_path: share_path.to_string_lossy().to_string(),
        fee_per_signing: 0, // no MPC fee output — keep the gate tx minimal
        fee_addresses: vec![],
        fee_threshold: None,
        max_presignatures: 8,
        encryption_key: None,
        arc_api_key: "unused-gorillapool-beef".into(),
        threshold_configs: vec!["2-of-2".to_string()],
        min_balance_sats: None,
        relay_url: relay_url.clone(),
        relay_sign: true,
        presign_url: None,
        approval_recv_timeout_secs: 60,
        network: None,
        policy_manifest_path: None,
    };
    let bridge = MpcBridge::new(&config).await.expect("bridge handshake");

    // Provision BOTH Presignature_A → DO pool (authed), in FIFO order matching the
    // proxy pool below so input i consumes the correlated pair (b_i, a_i).
    bridge
        .provision_presig_to_do(&hex::encode(joint_arr), &a0_json, "multi-ca", "multi-ca-0")
        .await
        .expect("provision presig #0 to DO pool");
    bridge
        .provision_presig_to_do(&hex::encode(joint_arr), &a1_json, "multi-ca", "multi-ca-1")
        .await
        .expect("provision presig #1 to DO pool");
    eprintln!("✔ provisioned 2 Presignature_A → DO pool (FIFO)");

    let mut mgr = PresignManager::new(8);
    mgr.add(b0, box_b0);
    mgr.add(b1, box_b1);

    // Seed BOTH funded UTXOs into in-memory storage so createAction selects them.
    let storage = InMemoryBackend::new();
    for (txid, vout, value) in [
        (fund_txid_0.clone(), vout0, value0),
        (fund_txid_1.clone(), vout1, value1),
    ] {
        bsv_mpc_proxy::storage::StorageBackend::add_output(
            &storage,
            TrackedOutput {
                txid,
                vout,
                satoshis: value,
                locking_script: joint_locking.clone(),
                spending_txid: None,
                basket: Some("default".into()),
                tags: vec![],
                created_at: chrono::Utc::now(),
                source_beef: None,
            },
        )
        .await
        .expect("seed UTXO");
    }

    let state = ProxyBuilder::new(config)
        .with_bridge(bridge)
        .with_presign_manager(mgr)
        .with_storage(storage)
        .build()
        .await
        .expect("build AppState");

    // ── 5. Serve the proxy + drive ONE createAction that spends BOTH UTXOs ──
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind proxy");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve proxy");
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Drain to the funding wallet's identity address.
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
    let wallet_locking =
        p2pkh_locking_script(&PublicKey::from_hex(&wallet_pub_hex).unwrap().hash160());

    // Output value forces selecting BOTH UTXOs: just above the larger single UTXO,
    // well below the sum (so a non-trivial change still returns to the joint addr).
    let drain: u64 = value0.max(value1) + 1;
    assert!(
        drain + 300 < value0 + value1,
        "drain must leave room for mining fee + change across both UTXOs"
    );
    let args = CreateActionArgs {
        description: "bsv-mpc #13 multi-input createAction over relay".into(),
        input_beef: None,
        inputs: None,
        outputs: Some(vec![CreateActionOutput {
            locking_script: wallet_locking,
            satoshis: drain,
            output_description: "multi-input drain to wallet".into(),
            basket: None,
            custom_instructions: None,
            tags: None,
        }]),
        lock_time: None,
        version: None,
        labels: None,
        options: Some(CreateActionOptions {
            accept_delayed_broadcast: Some(false),
            ..Default::default()
        }),
    };
    let resp: serde_json::Value = http
        .post(format!("http://127.0.0.1:{port}/createAction"))
        .header("Content-Type", "application/json")
        .json(&args)
        .send()
        .await
        .expect("createAction POST")
        .json()
        .await
        .expect("createAction JSON");
    let txid = resp["txid"]
        .as_str()
        .unwrap_or_else(|| panic!("createAction did not broadcast: {resp}"))
        .to_string();

    server.abort();
    let _ = tokio::fs::remove_file(&share_path).await;

    // ── 6. Independently confirm ≥2 vin on WhatsOnChain ─────────────────────
    let woc = format!("https://api.whatsonchain.com/v1/bsv/main/tx/hash/{txid}");
    let mut tx_json: Option<serde_json::Value> = None;
    for attempt in 1..=10 {
        tokio::time::sleep(Duration::from_secs(attempt * 3)).await;
        if let Ok(r) = http.get(&woc).send().await {
            if r.status().is_success() {
                if let Ok(j) = r.json::<serde_json::Value>().await {
                    tx_json = Some(j);
                    break;
                }
            }
        }
    }
    let tx_json =
        tx_json.unwrap_or_else(|| panic!("spending tx {txid} MUST be found on WhatsOnChain"));
    let vins = tx_json["vin"].as_array().expect("vin array on WoC");
    assert!(
        vins.len() >= 2,
        "spend MUST have ≥2 vin (got {}): {txid}",
        vins.len()
    );
    // Each funding UTXO must appear as an input.
    let spent_prev: Vec<&str> = vins.iter().filter_map(|v| v["txid"].as_str()).collect();
    assert!(
        spent_prev.contains(&fund_txid_0.as_str()),
        "vin MUST spend funding UTXO #0 {fund_txid_0}; got {spent_prev:?}"
    );
    assert!(
        spent_prev.contains(&fund_txid_1.as_str()),
        "vin MUST spend funding UTXO #1 {fund_txid_1}; got {spent_prev:?}"
    );

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  #13 GATE — MULTI-INPUT createAction over relay, real mainnet  ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!("  joint_pubkey:  {}", hex::encode(joint_arr));
    eprintln!("  funding_txid0: {fund_txid_0}:{vout0} ({value0} sats)");
    eprintln!("  funding_txid1: {fund_txid_1}:{vout1} ({value1} sats)");
    eprintln!(
        "  spending_txid: {txid}  ({} vin, confirmed on WhatsOnChain)",
        vins.len()
    );
    eprintln!("  cosigner:      deployed bsv-mpc-worker DO (share_A partials over authed relay)");
    eprintln!("  view: https://whatsonchain.com/tx/{txid}");
    eprintln!("  total wall-clock: {:?}", t0.elapsed());
}
