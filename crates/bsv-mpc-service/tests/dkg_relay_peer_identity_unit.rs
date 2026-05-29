//! #69 PR-2 step 5a-ii — `GET /dkg-relay/peer-identity` route contract (hermetic).
//!
//! Pins the per-index relay-identity read WITHOUT a live relay:
//!   1. With a server identity set, `GET /dkg-relay/peer-identity?session&index`
//!      returns the SAME public key the core one-way derivation produces
//!      (`bsv_mpc_core::hd::derive_relay_index_privkey`) — the route↔core golden
//!      cross-check. This is the value `POST /dkg-relay/init` reports as
//!      `peer_pub_hex` for the same (session, index), so the device's 5b
//!      "arm-response pub == fetched relay_pub" invariant reduces to this.
//!   2. Distinct indices → distinct relay pubs (one container holding {3,4,5}
//!      gets three distinct relay rooms — the multi-index topology).
//!   3. A non-canonical session → 400 (parse reject, fires after the identity gate).
//!
//! The 412-when-no-identity case is covered by `dkg_relay_route_unit.rs` (a
//! SEPARATE test binary → separate process, so its `remove_var` cannot race the
//! `set_var` here).
//!
//! This whole file runs with `MPC_SERVER_PRIVATE_KEY` SET; every test wants the
//! same value, so concurrent execution within this binary is race-free.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::types::SessionId;
use bsv_mpc_service::{build_router, AppState, AuthState, SqliteShareStorage};

/// A fixed, valid secp256k1 private key (0x11…11 < n) for the container's master
/// server identity throughout this file.
const SERVER_KEY_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn set_server_identity() {
    std::env::set_var("MPC_SERVER_PRIVATE_KEY", SERVER_KEY_HEX);
}

async fn dev_server_with_identity() -> (String, tokio::task::JoinHandle<()>) {
    set_server_identity();
    let data_dir = std::env::temp_dir().join(format!("dkg_relay_peerid_{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).unwrap();
    let storage = SqliteShareStorage::open(data_dir.to_str().unwrap()).unwrap();
    let state = Arc::new(AppState {
        data_dir: data_dir.to_string_lossy().to_string(),
        storage: Arc::new(RwLock::new(storage)),
        started_at: chrono::Utc::now(),
        provision: None,
        auth: AuthState::dev(),
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
    (url, server)
}

/// The relay pub the CORE derivation yields for a given index, using the same
/// master key + session the route uses — the golden the route must match.
fn core_relay_pub(session_hex: &str, index: u16) -> String {
    let sp = PrivateKey::from_hex(SERVER_KEY_HEX).unwrap();
    let sess = SessionId::from_hex(session_hex).unwrap();
    bsv_mpc_core::hd::derive_relay_index_privkey(&sp, &sess, index)
        .unwrap()
        .public_key()
        .to_hex()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_identity_matches_core_derivation_and_is_distinct_per_index() {
    let (url, _server) = dev_server_with_identity().await;
    let http = reqwest::Client::new();
    let session_hex = "33".repeat(32);

    let mut seen = Vec::new();
    for index in [3u16, 4, 5] {
        let resp = http
            .get(format!("{url}/dkg-relay/peer-identity"))
            .query(&[
                ("session", session_hex.as_str()),
                ("index", &index.to_string()),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            200,
            "peer-identity must be 200 with a server identity set (index {index})"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        let route_pub = body["relay_pub_hex"].as_str().unwrap().to_string();

        // Route↔core golden cross-check: the route MUST return exactly the
        // one-way-derived per-index relay pub.
        assert_eq!(
            route_pub,
            core_relay_pub(&session_hex, index),
            "route peer-identity must equal the core derivation for index {index}"
        );
        // Echo fields are correct.
        assert_eq!(body["index"].as_u64().unwrap(), index as u64);
        assert_eq!(body["session"].as_str().unwrap(), session_hex);
        seen.push(route_pub);
    }

    // Distinct indices → distinct relay rooms (the {3,4,5}-on-one-container path).
    assert_ne!(seen[0], seen[1]);
    assert_ne!(seen[1], seen[2]);
    assert_ne!(seen[0], seen[2]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_identity_rejects_non_canonical_session() {
    let (url, _server) = dev_server_with_identity().await;
    let http = reqwest::Client::new();

    // Non-64-hex session → 400 (SessionId::from_hex reject), fires AFTER the
    // identity gate passes, so it is 400 not 412.
    let resp = http
        .get(format!("{url}/dkg-relay/peer-identity"))
        .query(&[("session", "not-canonical-hex"), ("index", "3")])
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        400,
        "peer-identity with a non-canonical session must be 400"
    );
}
