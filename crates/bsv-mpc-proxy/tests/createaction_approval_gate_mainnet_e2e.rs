//! **#43 GATE — real-sats mainnet `createAction` that hit `RequireApproval`,
//! collected an approval over the relay, THEN signed.**
//!
//! This proves the §4 "two mandatory sides has teeth" guarantee end-to-end: the
//! proxy's policy engine returns `RequireApproval` for the spend; the proxy emits
//! an approval-request over the LIVE MessageBox relay to an eligible approver; a
//! separate approver identity (in-process, its own relay client) receives it,
//! signs `BRC-77(request_view_hash ‖ "mpc-approval-v1" ‖ session_id)`, and replies
//! over the relay; the proxy collects k=1 Allow, and ONLY THEN signs the spend
//! over the relay with the deployed cosigner and broadcasts. Independently
//! WhatsOnChain-confirmed.
//!
//! Signing topology is the proven 2-of-2 relay sign (#6/#13) — the #43 novelty is
//! the policy + approval gate, not device-holds (#38 proved that). The gate sits
//! in `create_action_impl` BEFORE any signing material is consumed.
//!
//! Funding uses the handoff §6 fix (BEEF V1 + TAAL bearer + retry-until-SEEN).
//!
//! REAL SATS. Gated on **`APPROVAL_GATE_MAINNET=1`**. Requires a BRC-100 wallet at
//! `http://localhost:3321` (Origin `http://admin.com`) with spendable sats.
//!
//! ```bash
//! APPROVAL_GATE_MAINNET=1 cargo test -p bsv-mpc-proxy \
//!   --test createaction_approval_gate_mainnet_e2e --release -- --nocapture --test-threads=1
//! ```

use std::time::Duration;

use bsv::primitives::ec::{PrivateKey, PublicKey};
use bsv::wallet::{CreateActionArgs, CreateActionOptions, CreateActionOutput};
use bsv_mpc_core::approval::ApprovalDecision;
use bsv_mpc_core::dkg::{generate_test_primes, DkgCoordinator, DkgRoundResult};
use bsv_mpc_core::policy::{ApprovalSpec, DefaultAction, PolicyEngine, PolicyManifest, Rule};
use bsv_mpc_core::presigning::{PresigningManager, PresigningRoundResult};
use bsv_mpc_core::types::{
    DkgResult, EncryptedShare, JointPublicKey, Presignature, SessionId, ShareIndex, ThresholdConfig,
};
use bsv_mpc_proxy::config::ProxyConfig;
use bsv_mpc_proxy::presign_manager::PresignManager;
use bsv_mpc_proxy::relay_approval::serve_one_approval;
use bsv_mpc_proxy::server::build_router;
use bsv_mpc_proxy::storage::InMemoryBackend;
use bsv_mpc_proxy::{MpcBridge, ProxyBuilder, TrackedOutput};

const DEFAULT_WORKER: &str = "https://bsv-mpc-kss.dev-a3e.workers.dev";
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";
const WALLET_URL: &str = "http://localhost:3321";

type PresignBox = Box<dyn std::any::Any + Send>;

fn opt_in() -> bool {
    std::env::var("APPROVAL_GATE_MAINNET").ok().as_deref() == Some("1")
}

fn p2pkh_locking_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.extend_from_slice(&[0x76, 0xa9, 0x14]);
    s.extend_from_slice(pubkey_hash);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

fn run_dkg_2of2() -> (JointPublicKey, EncryptedShare, EncryptedShare, SessionId) {
    let config = ThresholdConfig::new(2, 2).expect("2-of-2");
    let session = SessionId::from_str_hash("approval-gate-dkg");
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

fn gen_presig_pair(
    share0: EncryptedShare,
    share1: EncryptedShare,
) -> (Vec<u8>, Presignature, PresignBox) {
    let session = SessionId::from_str_hash("approval-gate-presig");
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
    let (_w0, box0) = m0.take_raw().expect("m0 take_raw");
    let presig_a_json = bsv_mpc_core::presigning::serialize_party_presignature(box0)
        .expect("serialize Presignature_A");
    let (presig_b, box1) = m1.take_raw().expect("m1 take_raw");
    (presig_a_json, presig_b, box1)
}

/// A single rule matching everything that REQUIRES a k=1 approval from `approver`.
fn rule_requiring_approval(approver: &PublicKey) -> Rule {
    Rule {
        protocol_pattern: "*".to_string(),
        max_amount_sats: None,
        max_per_hour: None,
        cumulative_daily_cap_sats: None,
        allowed_window: None,
        counterparty_allowlist: None,
        counterparty_denylist: None,
        min_fee_sats: None,
        jurisdiction: None,
        approval_spec: Some(ApprovalSpec {
            k: 1,
            eligible: vec![approver.to_compressed().to_vec()],
        }),
        attestation_spec: None,
    }
}

async fn broadcast_via_arc(http: &reqwest::Client, body_hex: &str) -> bool {
    let taal_token = std::env::var("TAAL_ARC_TOKEN")
        .unwrap_or_else(|_| "mainnet_9596de07e92300c6287e4393594ae39c".to_string());
    for arc in &["https://arc.gorillapool.io", "https://arc.taal.com"] {
        let url = format!("{arc}/v1/tx");
        let mut req = http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("XDeployment-ID", "bsv-mpc-approval-gate")
            .json(&serde_json::json!({ "rawTx": body_hex }));
        if arc.contains("taal") {
            req = req.header("Authorization", format!("Bearer {taal_token}"));
        }
        let Ok(resp) = req.send().await else { continue };
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        eprintln!("  ARC {url}: status={status} body={}", text.chars().take(200).collect::<String>());
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

async fn fund_joint(http: &reqwest::Client, joint_locking_hex: &str, amount: u64) -> String {
    for attempt in 1..=8 {
        let fund_text = http
            .post(format!("{WALLET_URL}/createAction"))
            .header("Origin", "http://admin.com")
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "description": format!("#43 approval-gate fund (attempt {attempt})"),
                "outputs": [{
                    "satoshis": amount,
                    "lockingScript": joint_locking_hex,
                    "outputDescription": "MPC joint P2PKH (approval gate)"
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
        let txid = fund_json["txid"].as_str().expect("fund txid").to_string();
        if let Some(beef_hex) = broadcast_hex_from_create_action(&fund_json) {
            if broadcast_via_arc(http, &beef_hex).await {
                eprintln!("  funding tx {txid} broadcast (attempt {attempt})");
                return txid;
            }
        }
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
async fn createaction_requires_approval_then_signs_real_mainnet() {
    if !opt_in() {
        eprintln!(
            "APPROVAL_GATE_MAINNET=1 not set — skipping #43 approval-gate mainnet test.
To run (BURNS REAL SATS): APPROVAL_GATE_MAINNET=1 cargo test -p bsv-mpc-proxy \\
  --test createaction_approval_gate_mainnet_e2e --release -- --nocapture --test-threads=1"
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

    // ── 1. DKG + presig pair (2-of-2 relay sign topology) ──────────────────
    let (joint, share0, share1, dkg_session) = run_dkg_2of2();
    let mut joint_arr = [0u8; 33];
    joint_arr.copy_from_slice(&joint.compressed);
    let joint_pub = PublicKey::from_bytes(&joint_arr).expect("joint pubkey");
    let joint_locking = p2pkh_locking_script(&joint_pub.hash160());
    let joint_locking_hex = hex::encode(&joint_locking);
    eprintln!("✔ joint pubkey {} / {}", hex::encode(joint_arr), joint.address);
    let (presig_a_json, presig_b, box_b) = gen_presig_pair(share0, share1.clone());

    // ── 2. The APPROVER identity + the policy manifest requiring its approval ─
    let approver_priv = PrivateKey::random();
    let approver_pub = approver_priv.public_key();
    eprintln!("✔ approver identity {}", approver_pub.to_hex());
    let mut manifest = PolicyManifest {
        version: 1,
        policy_id: bsv_mpc_core::types::PolicyId([0u8; 32]),
        cosigner_identity: joint_arr.to_vec(),
        group_key: joint_arr.to_vec(),
        rules: vec![rule_requiring_approval(&approver_pub)],
        default_action: DefaultAction::Deny,
        effective_after_ms: 0,
        expires_after_ms: None,
        prev_policy_id: None,
        approver_keys: vec![approver_pub.to_compressed().to_vec()],
        approver_sigs: vec![],
        dry_run: false,
    };
    manifest.policy_id = manifest.compute_policy_id();
    let engine = PolicyEngine::new(manifest).expect("valid manifest");

    // ── 3. Fund the joint P2PKH ────────────────────────────────────────────
    let fund_txid = fund_joint(&http, &joint_locking_hex, 1500).await;
    eprintln!("✔ funded joint UTXO: txid={fund_txid}");
    let (vout, value) = find_utxo_on_woc(&http, &fund_txid, &joint_locking_hex)
        .await
        .expect("MUST find funding UTXO on WoC");
    eprintln!("✔ UTXO {fund_txid}:{vout} ({value} sats)");

    // ── 4. Build the proxy (relay sign + policy engine) ────────────────────
    let dkg_result = DkgResult {
        joint_key: joint.clone(),
        share: share1,
        session_id: dkg_session,
    };
    let dir = std::env::temp_dir();
    let share_path = dir.join(format!("approval_gate_share_{}.json", std::process::id()));
    tokio::fs::write(&share_path, serde_json::to_vec(&dkg_result).unwrap())
        .await
        .expect("write share");
    let port = 13522u16;
    let config = ProxyConfig {
        port,
        kss_url: worker_url.clone(),
        share_path: share_path.to_string_lossy().to_string(),
        fee_per_signing: 0,
        fee_addresses: vec![],
        fee_threshold: None,
        max_presignatures: 5,
        encryption_key: None,
        arc_api_key: "unused-gorillapool-beef".into(),
        threshold_configs: vec!["2-of-2".to_string()],
        min_balance_sats: None,
        relay_url: relay_url.clone(),
        relay_sign: true,
        presign_url: None,
    };
    let bridge = MpcBridge::new(&config).await.expect("bridge handshake");
    bridge
        .provision_presig_to_do(&hex::encode(joint_arr), &presig_a_json, "approval-gate", "approval-gate-1")
        .await
        .expect("provision presig to DO pool");
    let mut mgr = PresignManager::new(4);
    mgr.add(presig_b, box_b);

    let storage = InMemoryBackend::new();
    bsv_mpc_proxy::storage::StorageBackend::add_output(
        &storage,
        TrackedOutput {
            txid: fund_txid.clone(),
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

    let state = ProxyBuilder::new(config)
        .with_bridge(bridge)
        .with_presign_manager(mgr)
        .with_policy_engine(engine)
        .with_storage(storage)
        .build()
        .await
        .expect("build AppState");

    // ── 5. Spawn the in-process APPROVER on the live relay (replies Allow) ──
    let approver_relay = relay_url.clone();
    let approver = tokio::spawn(async move {
        serve_one_approval(
            &approver_relay,
            approver_priv,
            ApprovalDecision::Allow,
            Duration::from_secs(90),
        )
        .await
    });
    // Give the approver a moment to subscribe to mpc-approval before the proxy
    // emits its request (relay backfill also covers a slightly late subscribe).
    tokio::time::sleep(Duration::from_secs(2)).await;

    // ── 6. Serve the proxy + drive ONE createAction ────────────────────────
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind proxy");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve proxy");
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

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

    let args = CreateActionArgs {
        description: "bsv-mpc #43 approval-gated createAction over relay".into(),
        input_beef: None,
        inputs: None,
        outputs: Some(vec![CreateActionOutput {
            locking_script: wallet_locking,
            satoshis: 600,
            output_description: "approval-gated drain".into(),
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
        .unwrap_or_else(|| panic!("createAction did not broadcast (approval gate?): {resp}"))
        .to_string();

    // The approver MUST have served the request (proves the relay round-trip).
    let approver_result = approver.await.expect("approver task joined");
    let (approved_vh, approved_sid) = approver_result.expect("approver served an approval request");
    eprintln!("✔ approver signed approval: view_hash={approved_vh} session={approved_sid}");

    server.abort();
    let _ = tokio::fs::remove_file(&share_path).await;

    // ── 7. Independently confirm the spend on WhatsOnChain ─────────────────
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
    let spent_prev: Vec<&str> = tx_json["vin"]
        .as_array()
        .expect("vin")
        .iter()
        .filter_map(|v| v["txid"].as_str())
        .collect();
    assert!(
        spent_prev.contains(&fund_txid.as_str()),
        "spend MUST consume the funded UTXO {fund_txid}; got {spent_prev:?}"
    );

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  #43 GATE — approval-gated createAction over relay, mainnet    ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!("  joint_pubkey:  {}", hex::encode(joint_arr));
    eprintln!("  policy:        rule \"*\" → RequireApproval k=1 of [approver]");
    eprintln!("  approver:      {}", approver_pub.to_hex());
    eprintln!("  flow:          createAction → RequireApproval → approval collected over relay → SIGN");
    eprintln!("  funding_txid:  {fund_txid}:{vout} ({value} sats)");
    eprintln!("  spending_txid: {txid}  (confirmed on WhatsOnChain)");
    eprintln!("  view: https://whatsonchain.com/tx/{txid}");
    eprintln!("  total wall-clock: {:?}", t0.elapsed());
}
