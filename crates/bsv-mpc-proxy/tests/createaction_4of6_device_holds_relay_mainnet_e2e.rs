//! **#38 GATE — real-sats mainnet 4-of-6 `createAction`, device holds t−1 (=3)
//! shares + ONE deployed cosigner over the relay.**
//!
//! The keystone (`poc_4of6_device_holds_3.rs`) and the presigned-combine POC
//! (`poc_4of6_device_holds_presig_relay.rs`) proved the crypto hermetically.
//! This is the production gate: the **proxy drives 3 local parties** (the device
//! holds shares `{0,1,2}` of a 4-of-6) **+ 1 deployed cosigner** (party 3, the
//! live `bsv-mpc-worker` DO) **over the authed MessageBox relay** to produce one
//! 4-of-6 ECDSA signature that **spends real mainnet sats**, independently
//! confirmed on WhatsOnChain.
//!
//! Topology (vs the proven 2-party `createaction_relay_mainnet_e2e`):
//!   - Local 4-of-6 DKG (6 parties) → 6 shares, one joint key.
//!   - A 4-party presign over the subset `{0,1,2,3}` → 4 correlated presigs.
//!   - The DEVICE keeps presigs for `{0,1,2}` (a `DevicePresigSetPool` set); the
//!     cosigner's correlated presig for party 3 is provisioned to the deployed
//!     worker pool (FIFO). The proxy loads a `DeviceShareBundle` of shares
//!     `{0,1,2}` → `MpcBridge::is_device_holds()`, `participants = [0,1,2,3]`,
//!     `external_cosigner_index = 3`.
//!   - ONE `/createAction` (canonical BRC-100 args) drains the funded joint UTXO.
//!     `relay_sign` consumes the device set, issues partials for `{0,1,2}`
//!     locally, triggers the deployed cosigner (party 3) over the relay, combines
//!     all 4 → broadcasts. The cosigner code is UNCHANGED (it issues one party's
//!     partial from `from_index=3`, agnostic to party count).
//!
//! Funding uses the handoff §6 fix: capture the wallet's BEEF → BEEF V1 →
//! self-broadcast to ARC (TAAL bearer) → retry until SEEN — the wallet at 3321
//! returns txids but does not reliably propagate.
//!
//! REAL SATS. Gated on **`DEVICE_HOLDS_4OF6_MAINNET=1`**. Requires a BRC-100
//! wallet at `http://localhost:3321` (Origin `http://admin.com`) with spendable
//! sats.
//!
//! ```bash
//! DEVICE_HOLDS_4OF6_MAINNET=1 cargo test -p bsv-mpc-proxy \
//!   --test createaction_4of6_device_holds_relay_mainnet_e2e --release \
//!   -- --nocapture --test-threads=1
//! ```

use std::time::Duration;

use bsv::primitives::ec::PublicKey;
use bsv::wallet::{CreateActionArgs, CreateActionOptions, CreateActionOutput};
use bsv_mpc_core::dkg::{generate_test_primes, DkgCoordinator, DkgRoundResult};
use bsv_mpc_core::presigning::{PresigningManager, PresigningRoundResult};
use bsv_mpc_core::types::{
    EncryptedShare, JointPublicKey, RoundMessage, SessionId, ShareIndex, ThresholdConfig,
};
use bsv_mpc_proxy::config::ProxyConfig;
use bsv_mpc_proxy::server::build_router;
use bsv_mpc_proxy::storage::InMemoryBackend;
use bsv_mpc_proxy::{
    DevicePresigSetPool, DeviceShareBundle, MpcBridge, ProxyBuilder, TrackedOutput,
};

const DEFAULT_WORKER: &str = "https://bsv-mpc-kss.dev-a3e.workers.dev";
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";
const WALLET_URL: &str = "http://localhost:3321";

type PresignBox = Box<dyn std::any::Any + Send>;

fn opt_in() -> bool {
    std::env::var("DEVICE_HOLDS_4OF6_MAINNET").ok().as_deref() == Some("1")
}

fn p2pkh_locking_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.extend_from_slice(&[0x76, 0xa9, 0x14]);
    s.extend_from_slice(pubkey_hash);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

/// **Generic n-party in-process DKG** (the keygen+auxinfo coordinators emit
/// per-recipient `RoundMessage`s; we route by party index: broadcast `to=None`
/// or p2p `to=Some(i)`). Returns the joint key + all `n` shares (positional by
/// share index).
fn run_dkg(n: u16, t: u16, session: SessionId) -> (JointPublicKey, Vec<EncryptedShare>) {
    let config = ThresholdConfig::new(t, n).expect("valid t-of-n");
    let mut rng = rand::rngs::OsRng;
    let mut coords: Vec<DkgCoordinator> = (0..n)
        .map(|i| {
            let mut c = DkgCoordinator::new(session, config, ShareIndex(i));
            c.set_pregenerated_primes(generate_test_primes(&mut rng));
            c
        })
        .collect();
    let mut outgoing: Vec<Vec<RoundMessage>> = coords
        .iter_mut()
        .map(|c| c.init().expect("dkg init"))
        .collect();
    let nn = n as usize;
    let mut shares: Vec<Option<EncryptedShare>> = (0..nn).map(|_| None).collect();
    let mut joint: Option<JointPublicKey> = None;

    for round in 0..100 {
        if shares.iter().all(|s| s.is_some()) {
            break;
        }
        let mut next: Vec<Vec<RoundMessage>> = (0..nn).map(|_| Vec::new()).collect();
        for i in 0..nn {
            if shares[i].is_some() {
                continue;
            }
            let inbound: Vec<RoundMessage> = (0..nn)
                .filter(|&j| j != i)
                .flat_map(|j| outgoing[j].iter().cloned())
                .filter(|m| m.to.is_none() || m.to == Some(ShareIndex(i as u16)))
                .collect();
            match coords[i].process_round(inbound).expect("dkg round") {
                DkgRoundResult::Complete(r) => {
                    joint = Some(r.joint_key.clone());
                    shares[i] = Some(r.share);
                }
                DkgRoundResult::NextRound(msgs) => next[i] = msgs,
            }
        }
        outgoing = next;
        let _ = round;
    }

    let shares: Vec<EncryptedShare> = shares
        .into_iter()
        .map(|s| s.expect("every party completed DKG"))
        .collect();
    (joint.expect("joint key"), shares)
}

/// **Generic k-party in-process presign** over `participants` (a subset of the
/// DKG parties). Routes by SIGNING index (position within `participants`).
/// Returns each participant's raw presig box tagged by PARTY index.
fn gen_presig_set(
    shares: &[EncryptedShare],
    participants: &[u16],
    session: SessionId,
) -> Vec<(u16, PresignBox)> {
    let k = participants.len();
    let mut mgrs: Vec<PresigningManager> = participants
        .iter()
        .map(|&p| {
            PresigningManager::new(
                session,
                shares[p as usize].clone(),
                participants.to_vec(),
                2,
            )
        })
        .collect();
    let mut outgoing: Vec<Vec<RoundMessage>> = mgrs
        .iter_mut()
        .map(|m| m.init_generate().expect("presign init"))
        .collect();
    let mut done = vec![false; k];

    for _ in 0..100 {
        if done.iter().all(|&d| d) {
            break;
        }
        let mut next: Vec<Vec<RoundMessage>> = (0..k).map(|_| Vec::new()).collect();
        for i in 0..k {
            if done[i] {
                continue;
            }
            let inbound: Vec<RoundMessage> = (0..k)
                .filter(|&j| j != i)
                .flat_map(|j| outgoing[j].iter().cloned())
                .filter(|m| m.to.is_none() || m.to == Some(ShareIndex(i as u16)))
                .collect();
            match mgrs[i]
                .process_generate_round(inbound)
                .expect("presign round")
            {
                PresigningRoundResult::Complete(_) => done[i] = true,
                PresigningRoundResult::NextRound(msgs) => next[i] = msgs,
            }
        }
        outgoing = next;
    }

    participants
        .iter()
        .enumerate()
        .map(|(i, &p)| {
            let (_w, raw) = mgrs[i].take_raw().expect("take_raw");
            (p, raw)
        })
        .collect()
}

/// Self-broadcast a BEEF/raw-tx hex via ARC (TAAL needs a Bearer token; Gorilla
/// is keyless). Handoff §6 funding fix.
async fn broadcast_via_arc(http: &reqwest::Client, body_hex: &str) -> bool {
    let taal_token = std::env::var("TAAL_ARC_TOKEN")
        .unwrap_or_else(|_| "mainnet_9596de07e92300c6287e4393594ae39c".to_string());
    for arc in &["https://arc.gorillapool.io", "https://arc.taal.com"] {
        let url = format!("{arc}/v1/tx");
        let mut req = http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("XDeployment-ID", "bsv-mpc-4of6-device-holds-gate")
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

/// BEEF V1 hex from a wallet `createAction` response (`tx` is AtomicBEEF).
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

/// Fund the joint P2PKH with `amount` sats, self-broadcasting + retrying until a
/// candidate lands on the network (handoff §6).
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
                    "outputDescription": "MPC 4-of-6 joint P2PKH (device-holds gate)"
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
async fn createaction_4of6_device_holds_3_over_relay_real_mainnet() {
    if !opt_in() {
        eprintln!(
            "DEVICE_HOLDS_4OF6_MAINNET=1 not set — skipping #38 4-of-6 device-holds gate.
To run (BURNS REAL SATS): DEVICE_HOLDS_4OF6_MAINNET=1 cargo test -p bsv-mpc-proxy \\
  --test createaction_4of6_device_holds_relay_mainnet_e2e --release -- --nocapture --test-threads=1"
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

    // ── 1. 4-of-6 DKG → 6 shares, one joint key ───────────────────────────
    eprintln!("(running 4-of-6 DKG — 6 parties keygen+auxinfo; ~3 min with test primes)");
    let dkg_session = SessionId::from_str_hash("4of6-device-holds-gate-dkg");
    let (joint, shares) = run_dkg(6, 4, dkg_session);
    assert_eq!(shares.len(), 6, "4-of-6 DKG must yield 6 shares");
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

    // ── 2. 4-party presign over {0,1,2,3} → 4 correlated presigs ───────────
    let participants = [0u16, 1, 2, 3];
    let presig_session = SessionId::from_str_hash("4of6-device-holds-gate-presig");
    let mut presigs = gen_presig_set(&shares, &participants, presig_session);
    // Tagged by party index; split into the DEVICE set {0,1,2} + cosigner {3}.
    presigs.sort_by_key(|(p, _)| *p);
    let cosigner_entry = presigs.pop().expect("party 3 present");
    assert_eq!(
        cosigner_entry.0, 3,
        "highest party is the external cosigner"
    );
    let device_set: Vec<(u16, PresignBox)> = presigs; // {0,1,2}
    assert_eq!(device_set.len(), 3, "device holds 3 correlated presigs");
    let cosigner_presig_json =
        bsv_mpc_core::presigning::serialize_party_presignature(cosigner_entry.1)
            .expect("serialize cosigner (party 3) presig");
    eprintln!("✔ 4-party presign: device keeps {{0,1,2}}, party 3 → deployed cosigner");

    // ── 3. Fund the joint P2PKH (BEEF V1 + retry) ──────────────────────────
    let fund_amount: u64 = 1500;
    let fund_txid = fund_joint(&http, &joint_locking_hex, fund_amount, "#38 4-of-6 fund").await;
    eprintln!("✔ funded joint UTXO: txid={fund_txid}");
    let (vout, value) = find_utxo_on_woc(&http, &fund_txid, &joint_locking_hex)
        .await
        .expect("MUST find funding UTXO on WoC");
    eprintln!("✔ UTXO {fund_txid}:{vout} ({value} sats)");

    // ── 4. Build the proxy: DEVICE holds shares {0,1,2}, device-set pool ───
    let device_bundle = DeviceShareBundle {
        joint_key: joint.clone(),
        session_id: dkg_session,
        shares: vec![shares[0].clone(), shares[1].clone(), shares[2].clone()],
    };
    let dir = std::env::temp_dir();
    let share_path = dir.join(format!(
        "device_holds_4of6_share_{}.json",
        std::process::id()
    ));
    tokio::fs::write(&share_path, serde_json::to_vec(&device_bundle).unwrap())
        .await
        .expect("write device share bundle");
    let port = 13462u16;
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
        threshold_configs: vec!["4-of-6".to_string()],
        min_balance_sats: None,
        relay_url: relay_url.clone(),
        relay_sign: true,
        presign_url: None,
        approval_recv_timeout_secs: 60,
        network: None,
        policy_manifest_path: None,
    };
    let bridge = MpcBridge::new(&config).await.expect("bridge handshake");
    assert!(
        bridge.is_device_holds(),
        "bridge MUST detect device-holds (3 shares)"
    );
    assert_eq!(
        bridge.device_party_indices(),
        vec![0, 1, 2],
        "device holds parties 0,1,2"
    );
    assert_eq!(
        bridge.external_cosigner_index(),
        3,
        "external cosigner is party 3"
    );

    // Provision the cosigner's correlated presig (party 3) → deployed worker pool.
    bridge
        .provision_presig_to_do(
            &hex::encode(joint_arr),
            &cosigner_presig_json,
            "4of6-device-holds",
            "4of6-device-holds-1",
        )
        .await
        .expect("provision party-3 presig to deployed cosigner pool");
    eprintln!("✔ provisioned party-3 presig → deployed cosigner pool");

    // Seed the device presig-SET pool with the {0,1,2} correlated set.
    let mut device_pool = DevicePresigSetPool::new(5);
    device_pool.add_set(device_set);

    // Seed the funded UTXO so createAction selects it.
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
        .with_device_presig_pool(device_pool)
        .with_storage(storage)
        .build()
        .await
        .expect("build AppState");

    // ── 5. Serve the proxy + drive ONE createAction (canonical BRC-100) ────
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
        description: "bsv-mpc #38 4-of-6 device-holds createAction over relay".into(),
        input_beef: None,
        inputs: None,
        outputs: Some(vec![CreateActionOutput {
            locking_script: wallet_locking,
            satoshis: 600, // remainder is change back to the joint address
            output_description: "4-of-6 drain to wallet".into(),
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

    // ── 6. Independently confirm the spend on WhatsOnChain ─────────────────
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
    let spent_prev: Vec<&str> = vins.iter().filter_map(|v| v["txid"].as_str()).collect();
    assert!(
        spent_prev.contains(&fund_txid.as_str()),
        "spend MUST consume the funded joint UTXO {fund_txid}; got {spent_prev:?}"
    );

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  #38 GATE — 4-of-6 device-holds-3 createAction over relay      ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!("  joint_pubkey:  {}", hex::encode(joint_arr));
    eprintln!("  device holds:  parties {{0,1,2}} (3 = t−1); cosigner = party 3");
    eprintln!("  funding_txid:  {fund_txid}:{vout} ({value} sats)");
    eprintln!("  spending_txid: {txid}  (confirmed on WhatsOnChain)");
    eprintln!("  signers:       3 LOCAL device parties + 1 DEPLOYED cosigner over relay");
    eprintln!("  view: https://whatsonchain.com/tx/{txid}");
    eprintln!("  total wall-clock: {:?}", t0.elapsed());
}
