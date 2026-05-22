//! **MPC-Spec #18 gate** — `/sign/init` HARD-ERRORS on a malformed session_id
//! instead of silently re-hashing it.
//!
//! The signing session_id is the canonical 64-char-hex `SessionId` both parties
//! must agree on. The old code did `SessionId::from_str_hash(&body.session_id)`,
//! which RE-HASHED the proxy's hex into a DIFFERENT SessionId → a divergent
//! cggmp24 ExecutionId → the 2PC ceremony aborted at round 2 with a confusing
//! "signing protocol failed" far from the real cause (this masked-then-loud bug
//! is exactly what the tests/e2e.rs silent-skip was hiding). The fix mirrors the
//! presign handler: `from_hex` + a 400 on malformed hex.
//!
//! Fast + hermetic (sibling of presign_sessionid_hardening_e2e.rs): a dummy share
//! is stored so the handler reaches the session_id parse (after the share load +
//! sighash parse) without a real DKG.

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
async fn sign_init_rejects_malformed_session_id() {
    let _ = tracing_subscriber::fmt::try_init();

    let data_dir = std::env::temp_dir().join(format!("sign_hardening_{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).unwrap();
    let storage = SqliteShareStorage::open(data_dir.to_str().unwrap()).unwrap();
    let state = Arc::new(AppState {
        data_dir: data_dir.to_string_lossy().to_string(),
        storage: RwLock::new(storage),
        started_at: chrono::Utc::now(),
        provision: None,
        auth: AuthState::dev(), // dev mode — no owner bound, so authz allows
        custody: None,
    });
    // Pre-store a dummy share so /sign/init reaches the session_id parse.
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
    let sighash = "ab".repeat(32); // valid 32-byte hex so we reach the session parse

    // Malformed (non-hex) session_id → 400, not a silent re-hash.
    let bad = http
        .post(format!("{url}/sign/init"))
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "session_id": "not-a-canonical-hex-session-id",
            "sighash": sighash,
            "use_presignature": false
        }))
        .send()
        .await
        .expect("sign/init (malformed session_id)");
    assert_eq!(
        bad.status().as_u16(),
        400,
        "malformed session_id MUST be a 400 hard-error (MPC-Spec #18), not a silent re-hash"
    );

    // Wrong-length hex (63 chars) → also 400.
    let short = http
        .post(format!("{url}/sign/init"))
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "session_id": "a".repeat(63),
            "sighash": sighash,
            "use_presignature": false
        }))
        .send()
        .await
        .expect("sign/init (short hex)");
    assert_eq!(
        short.status().as_u16(),
        400,
        "wrong-length session_id hex MUST be a 400 hard-error"
    );

    server.abort();
    let _ = std::fs::remove_dir_all(&data_dir);
}
