//! **#81 share-metadata auth gate** — `GET /shares/:agent_id` on the standalone
//! `bsv-mpc-service` now requires BRC-31 auth (§07.6) AND owner-authz (§08.1).
//!
//! Proves, in ENFORCED mode: unauthed → **401**; an AUTHED but NON-owner caller →
//! **403** (before any metadata is revealed); the AUTHED **owner** → **200** with
//! the share metadata. (`handle_dkg_init` + `handle_ecdh` were already gated by the
//! `auth.rs` work; this closes the last open TODO in the standalone service.)
//! Fast — no DKG; the share + its owner binding are seeded directly into storage.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::brc31_client::{headers, Brc31Client};
use bsv_mpc_core::types::{EncryptedShare, SessionId, ShareIndex, ThresholdConfig};
use bsv_mpc_service::{build_router, AppState, AuthState, SqliteShareStorage};

fn key_from(byte: u8) -> PrivateKey {
    PrivateKey::from_bytes(&[byte | 1; 32]).expect("valid key")
}

/// Run the canonical BRC-31 handshake against the live service, returning a client
/// bound to the issued session (identical to `round_handler_auth_e2e`).
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
async fn share_metadata_requires_brc31_owner_when_enforced() {
    let _ = tracing_subscriber::fmt::try_init();
    let data_dir = std::env::temp_dir().join(format!("share_meta_auth_{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).unwrap();
    let mut storage = SqliteShareStorage::open(data_dir.to_str().unwrap()).unwrap();

    // Seed a share whose §08.1 owner is the OWNER client's BRC-31 identity. `agent_id`
    // is a joint-pubkey-shaped hex string (no URL-special chars) — distinct from the
    // owner's identity key (the requester == agent_id phrasing in the issue really
    // means requester == the share's recorded owner).
    let owner_key = key_from(0x42);
    let owner_hex = owner_key.public_key().to_hex();
    let agent_id = "02bbccddeeff00112233445566778899aabbccddeeff00112233445566778899ab";
    let share = EncryptedShare {
        nonce: vec![],
        ciphertext: vec![1],
        session_id: SessionId::from_str_hash("meta"),
        share_index: ShareIndex(0),
        config: ThresholdConfig {
            threshold: 2,
            parties: 2,
        },
        joint_pubkey_compressed: vec![],
    };
    storage
        .store_share_with_owner(agent_id, &share, &owner_hex)
        .unwrap();

    let state = Arc::new(AppState {
        data_dir: data_dir.to_string_lossy().to_string(),
        storage: Arc::new(RwLock::new(storage)),
        started_at: chrono::Utc::now(),
        provision: None,
        auth: AuthState::with_key(key_from(0x5e)), // ENFORCED (server identity set)
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

    let http = reqwest::Client::new();
    let route_path = format!("/shares/{agent_id}");

    // 1. Unauthed → 401 (the §07.6 gate fires before any metadata is touched).
    let unauthed = http
        .get(format!("{url}{route_path}"))
        .header("content-type", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(
        unauthed.status().as_u16(),
        401,
        "unauthed share-metadata MUST be 401 in enforced mode (§07.6)"
    );

    // 2. Authed but NON-owner → 403 (§08.1), with NO metadata leaked.
    let stranger = handshake(&url, key_from(0x99)).await;
    let mut req = http
        .get(format!("{url}{route_path}"))
        .header("content-type", "application/json");
    for (n, v) in stranger.request_headers("GET", &route_path, b"").unwrap() {
        req = req.header(n, v);
    }
    let forbidden = req.send().await.unwrap();
    assert_eq!(
        forbidden.status().as_u16(),
        403,
        "an AUTHED non-owner MUST be 403, not granted the metadata (§08.1)"
    );

    // 3. Authed OWNER → 200 with the share metadata.
    let owner = handshake(&url, owner_key).await;
    let mut req = http
        .get(format!("{url}{route_path}"))
        .header("content-type", "application/json");
    for (n, v) in owner.request_headers("GET", &route_path, b"").unwrap() {
        req = req.header(n, v);
    }
    let ok = req.send().await.unwrap();
    assert_eq!(
        ok.status().as_u16(),
        200,
        "the AUTHED owner MUST get 200 with metadata"
    );
    let meta: serde_json::Value = ok.json().await.unwrap();
    assert_eq!(
        meta["agent_id"], agent_id,
        "metadata must be for the requested agent"
    );

    server.abort();
    let _ = std::fs::remove_dir_all(&data_dir);
    eprintln!("✔ #81 share-metadata auth: unauthed→401, non-owner→403, owner→200");
}
