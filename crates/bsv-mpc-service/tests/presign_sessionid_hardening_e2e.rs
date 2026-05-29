//! **#7 finding #4 gate** — `/presign/init` HARD-ERRORS on a malformed
//! session_id instead of silently re-hashing it.
//!
//! The presig session_id is the canonical 64-char-hex `SessionId` both parties
//! must agree on. The old code did `from_hex(...).unwrap_or_else(from_str_hash)`
//! — a corrupt hex would silently re-hash into a DIFFERENT SessionId → a
//! divergent cggmp24 ExecutionId → the presig fails far from the real cause
//! ("malformed or cheating party"). The fix returns 400 on malformed hex.
//!
//! Fast + hermetic: a dummy share is stored so the handler reaches the
//! session_id parse (which is after the share load) without a real DKG.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv_mpc_core::types::{EncryptedShare, SessionId, ShareIndex, ThresholdConfig};
use bsv_mpc_service::{build_router, AppState, AuthState, SqliteShareStorage};

fn dummy_share() -> EncryptedShare {
    EncryptedShare {
        nonce: vec![0u8; 12],
        ciphertext: vec![1u8; 32],
        session_id: SessionId::from_str_hash("dummy"),
        share_index: ShareIndex(0),
        config: ThresholdConfig::new(2, 2).unwrap(),
        joint_pubkey_compressed: vec![],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn presign_init_rejects_malformed_session_id() {
    let _ = tracing_subscriber::fmt::try_init();

    let data_dir = std::env::temp_dir().join(format!("presign_hardening_{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).unwrap();
    let storage = SqliteShareStorage::open(data_dir.to_str().unwrap()).unwrap();
    let state = Arc::new(AppState {
        data_dir: data_dir.to_string_lossy().to_string(),
        storage: Arc::new(RwLock::new(storage)),
        started_at: chrono::Utc::now(),
        provision: None,
        auth: AuthState::dev(), // dev mode — no owner bound, so authz allows
        custody: None,
    });
    // Pre-store a dummy share so /presign/init reaches the session_id parse.
    let agent_id = "02".to_string() + &"ab".repeat(32); // any 66-hex agent id
    state
        .storage
        .write()
        .unwrap()
        .store_share(&agent_id, &dummy_share())
        .unwrap();

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

    let http = reqwest::Client::new();

    // Malformed (non-hex) session_id → 400, not a silent re-hash.
    let bad = http
        .post(format!("{url}/presign/init"))
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "session_id": "not-a-canonical-hex-session-id",
            "count": 1
        }))
        .send()
        .await
        .expect("presign/init (malformed session_id)");
    assert_eq!(
        bad.status().as_u16(),
        400,
        "malformed session_id MUST be a 400 hard-error (#7 finding #4), not a silent re-hash"
    );

    // Wrong-length hex (63 chars) → also 400.
    let short = http
        .post(format!("{url}/presign/init"))
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "session_id": "a".repeat(63),
            "count": 1
        }))
        .send()
        .await
        .expect("presign/init (short hex)");
    assert_eq!(
        short.status().as_u16(),
        400,
        "wrong-length session_id hex MUST be a 400 hard-error"
    );

    server.abort();
    let _ = std::fs::remove_dir_all(&data_dir);
}
