//! **#8 round-handler defense-in-depth gate** — the service's round handlers
//! (`/dkg/round`, `/presign/round`) require a valid BRC-31
//! session in enforced mode (§07.6), not just an unguessable session id.
//!
//! Proves: unauthed round → **401**; an AUTHED session (valid BRC-31, unknown
//! ceremony) gets PAST auth → **404** (session-not-found), not 401 — i.e. the
//! gate is auth, and a real session is accepted. Dev-mode is covered by
//! orphan_cleanup_e2e (unauthed rounds allowed). Fast (no DKG).

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::brc31_client::{headers, Brc31Client};
use bsv_mpc_core::types::{RoundMessage, SessionId, ShareIndex};
use bsv_mpc_service::{build_router, AppState, AuthState, SqliteShareStorage};

fn key_from(byte: u8) -> PrivateKey {
    PrivateKey::from_bytes(&[byte | 1; 32]).expect("valid key")
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
    let resp = req.send().await.unwrap();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dkg_round_requires_brc31_session_when_enforced() {
    let _ = tracing_subscriber::fmt::try_init();
    let data_dir = std::env::temp_dir().join(format!("round_auth_{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).unwrap();
    let storage = SqliteShareStorage::open(data_dir.to_str().unwrap()).unwrap();
    let state = Arc::new(AppState {
        data_dir: data_dir.to_string_lossy().to_string(),
        storage: RwLock::new(storage),
        started_at: chrono::Utc::now(),
        provision: None,
        auth: AuthState::with_key(key_from(0x5e)), // ENFORCED
        custody: None,
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
    tokio::time::sleep(Duration::from_millis(150)).await;

    let msg = RoundMessage {
        session_id: SessionId::from_str_hash("x"),
        round: 0,
        from: ShareIndex(0),
        to: None,
        payload: b"irrelevant".to_vec(),
    };
    let body = serde_json::json!({ "session_id": "no-such-session", "round_message": msg });
    // Canonical wire: sign over + send the EXACT body bytes (not `.json()`).
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let http = reqwest::Client::new();

    // Unauthed → 401 (gated at the round handler).
    let unauthed = http
        .post(format!("{url}/dkg/round"))
        .header("content-type", "application/json")
        .body(body_bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        unauthed.status().as_u16(),
        401,
        "unauthed /dkg/round MUST be 401 in enforced mode (§07.6)"
    );

    // Authed session (unknown ceremony) → PAST auth → 404, not 401.
    let brc = handshake(&url, key_from(0x42)).await;
    let mut req = http
        .post(format!("{url}/dkg/round"))
        .header("content-type", "application/json")
        .body(body_bytes.clone());
    for (n, v) in brc
        .request_headers("POST", "/dkg/round", &body_bytes)
        .unwrap()
    {
        req = req.header(n, v);
    }
    let authed = req.send().await.unwrap();
    assert_eq!(
        authed.status().as_u16(),
        404,
        "an AUTHED round for an unknown session MUST pass auth and 404 (not 401)"
    );

    server.abort();
    let _ = std::fs::remove_dir_all(&data_dir);
    eprintln!("✔ round-handler auth: unauthed→401, authed-unknown-session→404");
}
