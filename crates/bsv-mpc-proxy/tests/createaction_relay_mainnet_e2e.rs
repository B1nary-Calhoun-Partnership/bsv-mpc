//! **#6 MERGE GATE — real-sats mainnet `createAction` through the deployed
//! cosigner, driven by the canonical SDK BRC-100 client.**
//!
//! The capstone of Phase I-6: an *unmodified* BRC-100 client
//! (`bsv_rs::wallet::substrates::HttpWalletJson`, the SDK's HTTP wallet client,
//! default base `localhost:3321`) pointed at the **running MPC proxy**
//! (`localhost:<port>`, relay mode) issues a real `createAction`. The proxy
//! selects the funded joint-address UTXO, signs the input over the **authed
//! relay** with the **deployed CF cosigner** (`share_A` partial), pre-flight
//! verifies under the joint key, and broadcasts → real mainnet TXID. No
//! bsv-worm, no hand-rolled JSON — exactly what any BRC-100 client does.
//!
//! Provisioning is harness-driven (generate the correlated pair, ship
//! `Presignature_A` to the DO pool, seed the proxy pool with `box_B`) — the
//! container-side automation (#4) is a separate productionization step and is
//! not required to prove the signing/broadcast gate.
//!
//! REAL SATS. Gated on **`E2E_MAINNET=1`**. Requires a BRC-100 wallet at
//! `http://localhost:3321` (Origin `http://admin.com`) with spendable sats.
//!
//! ```bash
//! E2E_MAINNET=1 cargo test -p bsv-mpc-proxy \
//!   --test createaction_relay_mainnet_e2e --release -- --nocapture --test-threads=1
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
use cggmp24::signing::PresignaturePublicData;
use cggmp24::supported_curves::Secp256k1;

const DEFAULT_WORKER: &str = "https://bsv-mpc-kss.dev-a3e.workers.dev";
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";
const WALLET_URL: &str = "http://localhost:3321";

type PresignBox = Box<dyn std::any::Any + Send>;

fn opt_in() -> bool {
    std::env::var("E2E_MAINNET").ok().as_deref() == Some("1")
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
    let session = SessionId::from_str_hash("ca-gate-dkg");
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
    let session = SessionId::from_str_hash("ca-gate-presig");
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
    assert_eq!(m0.pool_size(), 1);
    assert_eq!(m1.pool_size(), 1);
    let (_w0, box0) = m0.take_raw().expect("m0 take_raw");
    let (presig_a, _pub_a) = *box0
        .downcast::<(
            cggmp24::Presignature<Secp256k1>,
            PresignaturePublicData<Secp256k1>,
        )>()
        .expect("box0 downcast");
    let presig_a_json = serde_json::to_vec(&presig_a).expect("serialize Presignature_A");
    let (presig_b, box1) = m1.take_raw().expect("m1 take_raw");
    (presig_a_json, presig_b, box1)
}

async fn find_utxo_on_woc(
    http: &reqwest::Client,
    fund_txid: &str,
    expected_locking_hex: &str,
) -> Option<(u32, u64)> {
    let url = format!("https://api.whatsonchain.com/v1/bsv/main/tx/hash/{fund_txid}");
    for attempt in 1..=8 {
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
async fn createaction_through_deployed_cosigner_real_mainnet() {
    if !opt_in() {
        eprintln!(
            "E2E_MAINNET=1 not set — skipping #6 createAction mainnet gate.
To run (BURNS REAL SATS): E2E_MAINNET=1 cargo test -p bsv-mpc-proxy \\
  --test createaction_relay_mainnet_e2e --release -- --nocapture --test-threads=1"
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

    // ── 1. DKG + correlated presig pair ───────────────────────────────────
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
    let (presig_a_json, presig_b, box_b) = gen_presig_pair(share0, share1.clone());

    // ── 2. Fund the joint P2PKH via wallet:3321 ────────────────────────────
    let funding_amount: u64 = 1500;
    let fund_text = http
        .post(format!("{WALLET_URL}/createAction"))
        .header("Origin", "http://admin.com")
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "description": "bsv-mpc #6 createAction gate fund",
            "outputs": [{
                "satoshis": funding_amount,
                "lockingScript": joint_locking_hex,
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
    let fund_txid = fund_json["txid"].as_str().expect("fund txid").to_string();
    eprintln!("✔ funded joint address: txid={fund_txid}");

    // ── 3. Find the UTXO on WhatsOnChain ───────────────────────────────────
    let (vout, value) = find_utxo_on_woc(&http, &fund_txid, &joint_locking_hex)
        .await
        .expect("MUST find funding UTXO on WoC");
    eprintln!("✔ UTXO {fund_txid}:{vout} ({value} sats)");

    // ── 4. Build the proxy: relay mode, seeded storage + pool, real bridge ──
    let dkg_result = DkgResult {
        joint_key: joint.clone(),
        share: share1,
        session_id: dkg_session,
    };
    let dir = std::env::temp_dir();
    let share_path = dir.join(format!("ca_gate_share_{}.json", std::process::id()));
    tokio::fs::write(&share_path, serde_json::to_vec(&dkg_result).unwrap())
        .await
        .expect("write share");
    let port = 13322u16;
    let config = ProxyConfig {
        port,
        kss_url: worker_url.clone(),
        share_path: share_path.to_string_lossy().to_string(),
        fee_per_signing: 0, // no MPC fee output — keep the gate tx minimal
        fee_addresses: vec![],
        fee_threshold: None,
        max_presignatures: 5,
        encryption_key: None,
        arc_api_key: "unused-gorillapool-beef".into(),
        threshold_configs: vec!["2-of-2".to_string()],
        min_balance_sats: None,
        relay_url: relay_url.clone(),
        relay_sign: true,
    };
    let bridge = MpcBridge::new(&config).await.expect("bridge handshake");

    // Provision Presignature_A → DO pool (authed); seed proxy pool with box_B.
    bridge
        .provision_presig_to_do(&presig_a_json, "ca-gate", "ca-gate-1")
        .await
        .expect("provision presig to DO pool");
    let mut mgr = PresignManager::new(4);
    mgr.add(presig_b, box_b);

    // Seed the funded UTXO into in-memory storage so createAction can select it.
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
        },
    )
    .await
    .expect("seed UTXO");

    let state = ProxyBuilder::new(config)
        .with_bridge(bridge)
        .with_presign_manager(mgr)
        .with_storage(storage)
        .build()
        .await
        .expect("build AppState");

    // ── 5. Serve the proxy + drive it with the canonical SDK BRC-100 client ─
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind proxy");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve proxy");
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Drain back to the funding wallet's identity address.
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

    // Build the request with the SDK's canonical `CreateActionArgs` type — the
    // exact wire bytes any BRC-100 client sends (lockingScript hex + satoshis,
    // camelCase). NOTE: the SDK's *client* `HttpWalletJson`/`CreateActionResult`
    // decodes `txid` as a `[u8;32]` array, but real BRC-100 wallet servers
    // (e.g. bsv-wallet-cli's `McCreateActionRes`) return `txid` as a HEX STRING —
    // so the canonical *wire* response is hex, which is what the proxy emits and
    // what we parse here.
    let args = CreateActionArgs {
        description: "bsv-mpc #6 deployed-cosigner mainnet gate".into(),
        input_beef: None,
        inputs: None,
        outputs: Some(vec![CreateActionOutput {
            locking_script: wallet_locking,
            satoshis: 600, // remainder becomes change back to the joint address
            output_description: "drain to wallet".into(),
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
    // POST the canonical CreateActionArgs JSON to the running proxy.
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
    // The proxy returns a TXID only on broadcast success; an error carries an
    // "error" field (and never reaches the network thanks to the pre-flight
    // verify inside create_action_impl).
    let txid = resp["txid"]
        .as_str()
        .unwrap_or_else(|| {
            panic!("createAction did not broadcast: {resp}");
        })
        .to_string();

    server.abort();
    let _ = tokio::fs::remove_file(&share_path).await;

    // Confirm the spending tx is accepted on-chain (the cosigner's signature is
    // valid mainnet money) — retry WoC indexing.
    let woc = format!("https://api.whatsonchain.com/v1/bsv/main/tx/hash/{txid}");
    let mut on_chain = false;
    for attempt in 1..=8 {
        tokio::time::sleep(Duration::from_secs(attempt * 3)).await;
        if let Ok(r) = http.get(&woc).send().await {
            if r.status().is_success() {
                on_chain = true;
                break;
            }
        }
    }
    assert!(on_chain, "spending tx {txid} MUST be found on WhatsOnChain");

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  #6 MERGE GATE — createAction via deployed cosigner, mainnet   ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!(
        "  client wire:   canonical BRC-100 CreateActionArgs (SDK type) → proxy /createAction"
    );
    eprintln!("  joint_pubkey:  {}", hex::encode(joint_arr));
    eprintln!("  funding_txid:  {fund_txid}");
    eprintln!("  spending_txid: {txid}  (confirmed on WhatsOnChain)");
    eprintln!("  cosigner:      deployed bsv-mpc-worker DO (share_A partial over authed relay)");
    eprintln!("  view: https://whatsonchain.com/tx/{txid}");
    eprintln!("  total wall-clock: {:?}", t0.elapsed());
}
