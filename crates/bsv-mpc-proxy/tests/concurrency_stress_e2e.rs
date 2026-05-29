//! **#12 concurrency-stress gate** — K independent ceremonies in flight on ONE
//! cosigner must not corrupt shared state or deadlock (the #7 audit "concurrency"
//! class). Runs K authed DKGs in PARALLEL against a single ENFORCED in-process
//! service (custody → deployed worker), then verifies each share is independently
//! recoverable + owner-gated.
//!
//! Exercises the shared mutable state under concurrency: the global
//! `COORDINATOR_STORE` (live ceremonies), the BRC-31 session store, the share
//! storage, and the durable custody puts — all keyed by distinct ids, so K
//! parallel ceremonies must complete with K DISTINCT joint keys, no cross-talk.
//!
//! Gated on `CONCURRENCY_E2E=1` (K real DKGs in parallel ≈ a few min; needs the
//! deployed worker for custody):
//!
//! ```bash
//! CONCURRENCY_E2E=1 cargo test -p bsv-mpc-proxy \
//!   --test concurrency_stress_e2e --release -- --nocapture --test-threads=1
//! ```

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::brc31_client::{headers, Brc31Client};
use bsv_mpc_core::types::ThresholdConfig;
use bsv_mpc_proxy::bridge::run_dkg_over_http_authed;
use bsv_mpc_service::{build_router, AppState, AuthState, CustodyConfig, SqliteShareStorage};

const DEFAULT_WORKER: &str = "https://bsv-mpc-kss.dev-a3e.workers.dev";
const K: u8 = 3; // concurrent ceremonies

fn opt_in() -> bool {
    std::env::var("CONCURRENCY_E2E").ok().as_deref() == Some("1")
}

/// Distinct private key per seed byte. NOTE: use ODD seed bytes only — `| 1`
/// guards against a zero/low scalar, so even `b` and odd `b+1` would collide
/// (both → `b|1`). All seeds below are odd to stay distinct.
fn key_from(byte: u8) -> PrivateKey {
    PrivateKey::from_bytes(&[byte | 1; 32]).expect("valid key")
}

/// Distinct per-ceremony owner identity (odd, non-colliding under `| 1`).
fn owner_seed(i: u8) -> u8 {
    0xA1 + 2 * i // 0xA1, 0xA3, 0xA5, …
}

async fn handshake(svc_url: &str, k: PrivateKey) -> Brc31Client {
    let http = reqwest::Client::new();
    let mut brc = Brc31Client::new(k);
    let init_body = brc.initial_request_body().unwrap();
    let mut req = http
        .post(format!("{svc_url}/.well-known/auth"))
        .header("content-type", "application/json")
        .body(init_body);
    for (n, v) in brc.initial_request_headers() {
        req = req.header(n, v);
    }
    let resp = req.send().await.expect("handshake");
    let h = |n: &str| {
        resp.headers()
            .get(n)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    assert!(brc.complete_handshake(
        h(headers::IDENTITY_KEY).unwrap(),
        h(headers::NONCE).unwrap(),
    ));
    brc
}

async fn authed_ecdh_status(svc_url: &str, agent_id: &str, k: PrivateKey) -> u16 {
    let brc = handshake(svc_url, k).await;
    let http = reqwest::Client::new();
    let cp = key_from(0x7c).public_key().to_hex();
    let body = serde_json::to_vec(&serde_json::json!({
        "agent_id": agent_id, "counterparty_pub": cp,
    }))
    .unwrap();
    let mut req = http
        .post(format!("{svc_url}/ecdh"))
        .header("content-type", "application/json")
        .body(body.clone());
    for (n, v) in brc.request_headers("POST", "/ecdh", &body).unwrap() {
        req = req.header(n, v);
    }
    req.send().await.expect("/ecdh").status().as_u16()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn parallel_ceremonies_no_corruption() {
    if !opt_in() {
        eprintln!("CONCURRENCY_E2E=1 not set — skipping #12 concurrency-stress gate.");
        return;
    }
    let _ = tracing_subscriber::fmt::try_init();
    let worker_url =
        std::env::var("DEPLOYED_WORKER_URL").unwrap_or_else(|_| DEFAULT_WORKER.to_string());

    // One ENFORCED in-process cosigner with durable custody.
    let server_byte = 0x5e;
    let data_dir = std::env::temp_dir().join(format!("concurrency_{}", std::process::id()));
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
            worker_url: worker_url.clone(),
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
    let server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Launch K authed DKGs IN PARALLEL (distinct owner identities). ──
    let config = ThresholdConfig::new(2, 2).unwrap();
    let mut handles = Vec::new();
    for i in 0..K {
        let url = url.clone();
        let owner_byte = owner_seed(i); // distinct proxy identity per ceremony
        handles.push(tokio::spawn(async move {
            let dkg = run_dkg_over_http_authed(&url, config, key_from(owner_byte))
                .await
                .expect("concurrent authed DKG");
            (owner_byte, hex::encode(&dkg.joint_key.compressed))
        }));
    }
    let mut results = Vec::new();
    for h in handles {
        results.push(h.await.expect("DKG task joined"));
    }
    eprintln!("✔ {K} concurrent DKGs all completed");

    // ── Each ceremony produced a DISTINCT joint key (no cross-contamination). ──
    let joints: HashSet<String> = results.iter().map(|(_, j)| j.clone()).collect();
    assert_eq!(
        joints.len(),
        K as usize,
        "each concurrent DKG MUST produce a distinct joint key (no shared-state corruption)"
    );

    // ── Each share is independently recoverable + owner-gated. ──
    for (owner_byte, joint_hex) in &results {
        // The right owner can use its share.
        let owner_code = authed_ecdh_status(&url, joint_hex, key_from(*owner_byte)).await;
        assert_eq!(
            owner_code, 200,
            "owner of {joint_hex} MUST be able to use its share after concurrent DKG"
        );
        // A non-owner identity (fixed distinct stranger 0x43) is forbidden —
        // no cross-share authz bleed under concurrency.
        let stranger_code = authed_ecdh_status(&url, joint_hex, key_from(0x43)).await;
        assert_eq!(
            stranger_code, 403,
            "a non-owner MUST be forbidden on {joint_hex} (§08.1 isolation)"
        );
    }

    server.abort();
    let _ = std::fs::remove_dir_all(&data_dir);
    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════════╗");
    eprintln!("║ #12 concurrency GATE PASS — {K} parallel ceremonies: distinct keys, ║");
    eprintln!("║ each owner-gated + recoverable, no corruption/deadlock.            ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════╝");
}
