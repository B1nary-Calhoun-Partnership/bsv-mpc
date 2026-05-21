//! **#4d gate (DKG)** — real distributed 2-party CGGMP'24 DKG between the proxy
//! (party 1, share_B) and a `bsv-mpc-service` cosigner (party 0, share_A) over
//! HTTP. No trusted dealer: neither party ever holds the other's share.
//!
//! Spins up a real in-process `bsv-mpc-service` and drives
//! `bsv_mpc_proxy::bridge::run_dkg_over_http` against it. Proves agreement by
//! checking the service stored `share_A` keyed by **the same joint pubkey** the
//! proxy computed for `share_B` — i.e., both sides reached the identical joint
//! key through the ceremony. Fully local, no sats; gated on `DKG_HTTP_E2E=1`
//! (DKG generates Paillier primes inline → ~tens of seconds).
//!
//! ```bash
//! DKG_HTTP_E2E=1 cargo test -p bsv-mpc-proxy \
//!   --test dkg_over_http_local_e2e --release -- --nocapture --test-threads=1
//! ```

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv_mpc_core::types::ThresholdConfig;
use bsv_mpc_proxy::bridge::run_dkg_over_http;
use bsv_mpc_service::{build_router, AppState, SqliteShareStorage};

fn opt_in() -> bool {
    std::env::var("DKG_HTTP_E2E").ok().as_deref() == Some("1")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_and_service_distributed_dkg_over_http() {
    if !opt_in() {
        eprintln!("DKG_HTTP_E2E=1 not set — skipping #4d distributed-DKG-over-HTTP gate.");
        return;
    }
    let _ = tracing_subscriber::fmt::try_init();

    // ── Start a real in-process bsv-mpc-service (the party-0 cosigner). ──
    let data_dir = std::env::temp_dir().join(format!("dkg_http_svc_{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).unwrap();
    let storage = SqliteShareStorage::open(data_dir.to_str().unwrap()).expect("open storage");
    let state = Arc::new(AppState {
        data_dir: data_dir.to_string_lossy().to_string(),
        storage: RwLock::new(storage),
        started_at: chrono::Utc::now(),
        provision: None, // DKG only — no presig shipping in this gate
    });
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind service");
    let svc_addr = listener.local_addr().unwrap();
    let svc_url = format!("http://{svc_addr}");
    let server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Proxy (party 1) drives the DKG over HTTP. ──
    let config = ThresholdConfig::new(2, 2).unwrap();
    let dkg = run_dkg_over_http(&svc_url, config)
        .await
        .expect("proxy completes distributed DKG over HTTP");

    // Proxy got share_B (party index 1) + the joint key.
    assert_eq!(
        dkg.share.share_index.0, 1,
        "proxy holds share index 1 (share_B)"
    );
    assert_eq!(
        dkg.joint_key.compressed.len(),
        33,
        "joint pubkey is 33-byte compressed"
    );
    bsv_mpc_core::share::validate_encrypted_share(&dkg.share)
        .expect("share_B is structurally valid");
    let joint_hex = hex::encode(&dkg.joint_key.compressed);
    eprintln!("✔ proxy share_B + joint pubkey {joint_hex}");

    // ── Agreement: the service stored share_A under the SAME joint key. ──
    // If both sides reached the identical joint key, the ceremony succeeded with
    // no trusted dealer (each party holds only its own share).
    let http = reqwest::Client::new();
    let resp = http
        .get(format!("{svc_url}/shares/{joint_hex}"))
        .send()
        .await
        .expect("query service share metadata");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "service MUST have stored share_A under the joint key {joint_hex} the proxy computed"
    );
    let meta: serde_json::Value = resp.json().await.expect("share metadata JSON");
    eprintln!("✔ service stored share_A under the joint key: {meta}");

    server.abort();
    let _ = std::fs::remove_dir_all(&data_dir);

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  #4d GATE PASS — real distributed DKG proxy↔service over HTTP  ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
}
