//! **#7 finding #3 gate** — a ceremony that errors mid-round must not leave an
//! orphaned coordinator (availability/hygiene: a stale coordinator would block a
//! retry of the same session id and grow unbounded under repeated errors).
//!
//! Exposing condition: `/dkg/round` with a malformed payload → `process_round`
//! errors (500). The fix removes the session on that error, so a follow-up round
//! for the same session id is **404 (not found)**, not a second 500 (which would
//! mean the orphan is still resident). Pre-fix, the session stayed in the map.
//!
//! Fast + hermetic (no DKG completion) → runs in normal `cargo test`.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv_mpc_core::types::{RoundMessage, SessionId, ShareIndex};
use bsv_mpc_service::{build_router, AppState, AuthState, SqliteShareStorage};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dkg_round_error_removes_orphan_coordinator() {
    let _ = tracing_subscriber::fmt::try_init();

    // Dev-mode in-process service (no auth needed for this hygiene gate).
    let data_dir = std::env::temp_dir().join(format!("orphan_{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).unwrap();
    let storage = SqliteShareStorage::open(data_dir.to_str().unwrap()).unwrap();
    let state = Arc::new(AppState {
        data_dir: data_dir.to_string_lossy().to_string(),
        storage: RwLock::new(storage),
        started_at: chrono::Utc::now(),
        provision: None,
        auth: AuthState::dev(),
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

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap();

    // 1. Start a DKG ceremony → a live coordinator keyed by session_id.
    let init: serde_json::Value = http
        .post(format!("{url}/dkg/init"))
        .json(&serde_json::json!({
            "agent_id": "",
            "config": { "threshold": 2, "parties": 2 },
            "label": "orphan-probe"
        }))
        .send()
        .await
        .expect("dkg/init")
        .json()
        .await
        .expect("dkg/init json");
    let session_id = init["session_id"].as_str().expect("session_id").to_string();

    // 2. Feed a MALFORMED round message → process_round errors (500).
    let garbage = RoundMessage {
        session_id: SessionId::from_str_hash(&session_id),
        round: 0,
        from: ShareIndex(0),
        to: None,
        payload: b"this-is-not-a-valid-wire-message".to_vec(),
    };
    let bad = http
        .post(format!("{url}/dkg/round"))
        .json(&serde_json::json!({ "session_id": session_id, "round_message": garbage }))
        .send()
        .await
        .expect("dkg/round (malformed)");
    assert_eq!(
        bad.status().as_u16(),
        500,
        "a malformed round MUST error (precondition for the orphan-cleanup gate)"
    );

    // 3. Retry the SAME session id → 404 proves the orphaned coordinator was
    //    removed on the error (pre-fix this would find the stale session again).
    let retry = http
        .post(format!("{url}/dkg/round"))
        .json(&serde_json::json!({ "session_id": session_id, "round_message": garbage }))
        .send()
        .await
        .expect("dkg/round (retry)");
    assert_eq!(
        retry.status().as_u16(),
        404,
        "after a mid-ceremony error the session MUST be gone (#7 finding #3) — \
         got {} (stale orphan still resident?)",
        retry.status()
    );

    server.abort();
    let _ = std::fs::remove_dir_all(&data_dir);
}
