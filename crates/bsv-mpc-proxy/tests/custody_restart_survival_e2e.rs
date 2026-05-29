//! **#9 fund-safety gate** — a cosigner's `share_A` survives an
//! ephemeral-container restart via durable KEK-wrapped custody on the worker DO.
//!
//! The restart is simulated controllably with two in-process service instances
//! that share the SAME custody identity/KEK, talking to the REAL deployed worker
//! custody endpoints:
//!
//! 1. **Service A** (ENFORCED, custody → deployed worker): an authed DKG records
//!    `owner = X` and persists the KEK-sealed `(share_A, owner)` to the worker DO
//!    at DKG-complete.
//! 2. **Drop A** (≡ container death — its in-memory share is gone).
//! 3. **Service B** — fresh empty storage, SAME server key (⇒ same KEK + custody
//!    identity) — i.e. the "restarted container".
//! 4. Authed-as-X `/ecdh` against B → local miss → recover `(share_A, owner=X)`
//!    from the worker → unwrap → compute a real partial from `share_A`'s scalar
//!    → **200** (the share is recovered + cryptographically usable; signing would
//!    work). A **stranger** → **403** (the owner binding survived recovery); an
//!    **unauthed** caller → **401**.
//!
//! Gated on `CUSTODY_E2E=1` (real DKG ≈ 2 min; needs the deployed worker):
//!
//! ```bash
//! CUSTODY_E2E=1 cargo test -p bsv-mpc-proxy \
//!   --test custody_restart_survival_e2e --release -- --nocapture --test-threads=1
//! ```

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::brc31_client::{headers, Brc31Client};
use bsv_mpc_core::types::ThresholdConfig;
use bsv_mpc_proxy::bridge::run_dkg_over_http_authed;
use bsv_mpc_service::{build_router, AppState, AuthState, CustodyConfig, SqliteShareStorage};

const DEFAULT_WORKER: &str = "https://bsv-mpc-kss.dev-a3e.workers.dev";

fn opt_in() -> bool {
    std::env::var("CUSTODY_E2E").ok().as_deref() == Some("1")
}

fn key_from(byte: u8) -> PrivateKey {
    PrivateKey::from_bytes(&[byte | 1; 32]).expect("valid key")
}

/// Build an in-process ENFORCED service with durable custody → `worker_url`,
/// using `server_byte` as the custody root (server identity + KEK). Returns
/// (url, server task).
async fn spawn_service(
    server_byte: u8,
    worker_url: &str,
    tag: &str,
) -> (String, tokio::task::JoinHandle<()>) {
    let data_dir = std::env::temp_dir().join(format!("custody_{tag}_{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).unwrap();
    let storage = SqliteShareStorage::open(data_dir.to_str().unwrap()).unwrap();
    let kek = bsv_mpc_core::custody::derive_custody_kek(&[server_byte | 1; 32]);
    let state = Arc::new(AppState {
        data_dir: data_dir.to_string_lossy().to_string(),
        storage: Arc::new(RwLock::new(storage)),
        started_at: chrono::Utc::now(),
        provision: None,
        auth: AuthState::with_key(key_from(server_byte)),
        custody: Some(CustodyConfig {
            worker_url: worker_url.to_string(),
            kek,
            auth: tokio::sync::Mutex::new(Brc31Client::new(key_from(server_byte))),
            http: reqwest::Client::new(),
        }),
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
    let init_body = brc.initial_request_body().expect("initial request body");
    let mut req = http
        .post(format!("{svc_url}/.well-known/auth"))
        .header("content-type", "application/json")
        .body(init_body);
    for (name, value) in brc.initial_request_headers() {
        req = req.header(name, value);
    }
    let resp = req.send().await.expect("handshake");
    let h = |n: &str| {
        resp.headers()
            .get(n)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    assert!(brc.complete_handshake(
        h(headers::IDENTITY_KEY).expect("server identity"),
        h(headers::NONCE).expect("server nonce"),
    ));
    brc
}

async fn post_ecdh(
    svc_url: &str,
    agent_id: &str,
    cp_pub: &str,
    brc: Option<&Brc31Client>,
) -> reqwest::Response {
    let http = reqwest::Client::new();
    let body = serde_json::to_vec(&serde_json::json!({
        "agent_id": agent_id, "counterparty_pub": cp_pub,
    }))
    .unwrap();
    let mut req = http
        .post(format!("{svc_url}/ecdh"))
        .header("content-type", "application/json")
        .body(body.clone());
    if let Some(brc) = brc {
        for (name, value) in brc
            .request_headers("POST", "/ecdh", &body)
            .expect("auth headers")
        {
            req = req.header(name, value);
        }
    }
    req.send().await.expect("/ecdh")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn share_a_survives_restart_via_custody() {
    if !opt_in() {
        eprintln!("CUSTODY_E2E=1 not set — skipping #9 restart-survival gate.");
        return;
    }
    let _ = tracing_subscriber::fmt::try_init();
    let worker_url =
        std::env::var("DEPLOYED_WORKER_URL").unwrap_or_else(|_| DEFAULT_WORKER.to_string());

    let server_byte = 0x5e; // custody root (server identity + KEK) — shared by A and B
    let owner_seed = 0x99; // proxy identity X (the share owner, §08.1)
    let owner_hex = key_from(owner_seed).public_key().to_hex();

    // ── 1. Service A: authed DKG → persist KEK-sealed (share_A, owner) to DO. ──
    let (a_url, a_server) = spawn_service(server_byte, &worker_url, "a").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let config = ThresholdConfig::new(2, 2).unwrap();
    let dkg = run_dkg_over_http_authed(&a_url, config, key_from(owner_seed))
        .await
        .expect("authed DKG against service A");
    let joint_hex = hex::encode(&dkg.joint_key.compressed);
    eprintln!("✔ DKG complete — joint {joint_hex}, owner {owner_hex}; persisted to worker custody");

    // ── 2. Drop A (≡ container death; in-memory share_A gone). ──
    a_server.abort();
    tokio::time::sleep(Duration::from_millis(300)).await;
    eprintln!("✔ service A dropped (simulated container restart)");

    // ── 3. Service B: fresh storage, SAME custody root → same KEK + identity. ──
    let (b_url, b_server) = spawn_service(server_byte, &worker_url, "b").await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let cp_pub = key_from(0x7c).public_key().to_hex();

    // ── 4a. Owner /ecdh on B → recover from custody → 200 + valid partial. ──
    let owner = handshake(&b_url, key_from(owner_seed)).await;
    let resp = post_ecdh(&b_url, &joint_hex, &cp_pub, Some(&owner)).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "owner /ecdh on the RESTARTED cosigner MUST succeed by recovering share_A from custody"
    );
    let body: serde_json::Value = resp.json().await.expect("ecdh json");
    let partial = body.get("partial").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(
        partial.len(),
        66,
        "recovered share_A MUST produce a valid 33-byte partial ECDH point — got {partial:?}"
    );
    eprintln!("✔ share_A RECOVERED from custody on the restarted cosigner → valid partial");

    // ── 4b. Owner binding survived recovery: stranger → 403. ──
    let stranger = handshake(&b_url, key_from(0x42)).await;
    let s = post_ecdh(&b_url, &joint_hex, &cp_pub, Some(&stranger)).await;
    assert_eq!(
        s.status().as_u16(),
        403,
        "a non-owner MUST be forbidden after recovery — the owner binding (§08.1) survived"
    );

    // ── 4c. Unauthed → 401. ──
    let u = post_ecdh(&b_url, &joint_hex, &cp_pub, None).await;
    assert_eq!(u.status().as_u16(), 401, "unauthed /ecdh MUST be rejected");

    b_server.abort();
    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════════╗");
    eprintln!("║ #9 GATE PASS — share_A survives restart via durable KEK-custody:  ║");
    eprintln!("║ recovered + usable + owner-bound (no fund-lock). unauthed→401.     ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════╝");
}
