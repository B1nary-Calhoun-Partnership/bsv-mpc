//! **#7 finding #1 — deployed-enforcement (proxy side), local proof.**
//!
//! Proves the proxy authenticates to an **auth-ENFORCED** heavy-compute cosigner
//! (`presign_url`) as the share's owner, using a SECOND BRC-31 session distinct
//! from its DO (`kss_url`) session — the multi-server-auth that lets the deployed
//! CF Container turn on `MPC_SERVER_PRIVATE_KEY` without breaking the proxy.
//!
//! Topology mirrors deployed (two in-process ENFORCED services):
//!   - **container** (`presign_url`): runs DKG + presig, stores `share_A`.
//!   - **DO** (`kss_url`): the bridge handshakes with it at startup.
//!
//! Flow:
//! 1. Resolve a stable proxy identity X from `MPC_PROXY_IDENTITY_KEY` (the
//!    pre-DKG identity needed to match a container's DKG-time owner binding).
//! 2. `run_dkg_over_http_authed(container, .., X)` → container records
//!    `owner_identity = X` against `share_A` (§08.1).
//! 3. Build `MpcBridge` (kss=DO, presign=container) → it handshakes BOTH servers
//!    with X (separate sessions, same identity).
//! 4. `presign_raw()` → authed as X = owner against the ENFORCED container →
//!    the 3-round presig completes (proves authed presig end-to-end).
//! 5. Negative controls on the container: unauthed `/presign/init` → 401,
//!    stranger-authed → 403.
//!
//! Gated on `PROXY_ENFORCED_E2E=1` (a real DKG generates Paillier primes inline
//! → ~2 min):
//!
//! ```bash
//! PROXY_ENFORCED_E2E=1 cargo test -p bsv-mpc-proxy \
//!   --test proxy_enforced_cosigner_e2e --release -- --nocapture --test-threads=1
//! ```

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::brc31_client::{headers, Brc31Client};
use bsv_mpc_core::types::ThresholdConfig;
use bsv_mpc_proxy::bridge::{run_dkg_over_http_authed, MpcBridge};
use bsv_mpc_proxy::config::ProxyConfig;
use bsv_mpc_service::{build_router, AppState, AuthState, SqliteShareStorage};

fn opt_in() -> bool {
    std::env::var("PROXY_ENFORCED_E2E").ok().as_deref() == Some("1")
}

fn key_from(byte: u8) -> PrivateKey {
    PrivateKey::from_bytes(&[byte | 1; 32]).expect("valid key")
}

/// Spin up an in-process ENFORCED `bsv-mpc-service`; returns (url, join handle).
async fn spawn_enforced_service(
    server_key: PrivateKey,
    tag: &str,
) -> (String, tokio::task::JoinHandle<()>) {
    let data_dir = std::env::temp_dir().join(format!("proxy_enf_{tag}_{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).unwrap();
    let storage = SqliteShareStorage::open(data_dir.to_str().unwrap()).unwrap();
    let state = Arc::new(AppState {
        data_dir: data_dir.to_string_lossy().to_string(),
        storage: RwLock::new(storage),
        started_at: chrono::Utc::now(),
        provision: None,
        auth: AuthState::with_key(server_key),
    });
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    (url, handle)
}

async fn handshake(svc_url: &str, auth_key: PrivateKey) -> Brc31Client {
    let http = reqwest::Client::new();
    let mut brc = Brc31Client::new(auth_key);
    let mut req = http
        .post(format!("{svc_url}/.well-known/auth"))
        .header("content-type", "application/json")
        .body("{}");
    for (name, value) in brc.initial_request_headers() {
        req = req.header(name, value);
    }
    let resp = req.send().await.expect("handshake request");
    let h = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let server_identity = h(headers::IDENTITY_KEY).expect("server identity");
    let server_nonce = h(headers::NONCE).expect("server nonce");
    brc.complete_handshake(server_identity, server_nonce);
    brc
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_presigns_against_enforced_cosigner() {
    if !opt_in() {
        eprintln!(
            "PROXY_ENFORCED_E2E=1 not set — skipping deployed-enforcement (proxy-side) gate."
        );
        return;
    }
    let _ = tracing_subscriber::fmt::try_init();

    // ── Two ENFORCED in-process services: DO (kss) + container (presign). ──
    let (do_url, do_server) = spawn_enforced_service(key_from(0xd0), "do").await;
    let (container_url, container_server) = spawn_enforced_service(key_from(0xc0), "co").await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Stable proxy identity X (pre-DKG), shared by DKG + the bridge. ──
    let proxy_identity = key_from(0x99);
    let proxy_id_hex = proxy_identity.public_key().to_hex();
    std::env::set_var("MPC_PROXY_IDENTITY_KEY", hex::encode([0x99u8 | 1; 32]));

    // ── 1. Authed DKG against the ENFORCED container → owner_A = X. ──
    let config = ThresholdConfig::new(2, 2).unwrap();
    let dkg = run_dkg_over_http_authed(&container_url, config, key_from(0x99))
        .await
        .expect("authed DKG against enforced container");
    let joint_hex = hex::encode(&dkg.joint_key.compressed);
    eprintln!("✔ authed DKG complete — joint {joint_hex}, owner {proxy_id_hex}");

    // ── 2. Build the bridge (kss=DO, presign=container); both handshaked as X. ──
    let data_dir = std::env::temp_dir().join(format!("proxy_enf_share_{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).unwrap();
    let share_path = data_dir.join("share_b.json");
    tokio::fs::write(&share_path, serde_json::to_vec(&dkg).unwrap())
        .await
        .unwrap();
    let config = ProxyConfig {
        port: 3322,
        kss_url: do_url.clone(),
        share_path: share_path.to_string_lossy().to_string(),
        fee_per_signing: 0,
        fee_addresses: vec![],
        fee_threshold: None,
        max_presignatures: 5,
        encryption_key: None,
        arc_api_key: "unused".into(),
        threshold_configs: vec!["2-of-2".to_string()],
        min_balance_sats: None,
        relay_url: "http://unused.invalid".into(),
        relay_sign: false,
        presign_url: Some(container_url.clone()),
    };
    let bridge = MpcBridge::new(&config)
        .await
        .expect("bridge handshakes BOTH enforced servers as X");

    // ── 3. presign_raw against the ENFORCED container as the owner → succeeds. ──
    let (_presig_b, _box_b) = bridge
        .presign_raw()
        .await
        .expect("owner-authed presig against enforced container completes");
    eprintln!("✔ owner-authed presig against the ENFORCED container completed");

    // ── 4. Negative controls on the container's /presign/init. ──
    // Unauthed → 401.
    let unauthed = reqwest::Client::new()
        .post(format!("{container_url}/presign/init"))
        .json(&serde_json::json!({
            "agent_id": joint_hex, "session_id": dkg.session_id.hex(), "count": 1
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        unauthed.status().as_u16(),
        401,
        "unauthed /presign/init on the container MUST be rejected (§07.6)"
    );

    // Stranger (valid session, wrong identity) → 403.
    let stranger = handshake(&container_url, key_from(0x42)).await;
    let mut req = reqwest::Client::new()
        .post(format!("{container_url}/presign/init"))
        .json(&serde_json::json!({
            "agent_id": joint_hex, "session_id": dkg.session_id.hex(), "count": 1
        }));
    for (name, value) in stranger.request_headers().unwrap() {
        req = req.header(name, value);
    }
    let stranger_resp = req.send().await.unwrap();
    assert_eq!(
        stranger_resp.status().as_u16(),
        403,
        "stranger /presign/init on the container MUST be forbidden (§08.1)"
    );

    std::env::remove_var("MPC_PROXY_IDENTITY_KEY");
    do_server.abort();
    container_server.abort();
    let _ = std::fs::remove_dir_all(&data_dir);

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════════╗");
    eprintln!("║ deployed-enforcement (proxy side) GATE PASS — proxy authed-presig  ║");
    eprintln!("║ vs ENFORCED container as owner; unauthed→401, stranger→403.        ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════╝");
}
