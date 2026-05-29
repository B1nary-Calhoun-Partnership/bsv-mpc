//! #69 PR-2 step 3 — `/dkg-relay/{identity,init}` route contract (hermetic).
//!
//! Pins the DKG-only wire shape + the pre-relay gates WITHOUT a live relay:
//!   1. `DkgRelayInitRequest` accepts the fresh-DKG fields and REJECTS reshare-only
//!      fields (`deny_unknown_fields`) — the cross-impl wire contract.
//!   2. Over the router with dev auth + no server identity: `GET /dkg-relay/identity`
//!      → 412; a well-formed `POST /dkg-relay/init` → 412 (auth passes, body parses,
//!      the server-identity gate fires before any relay connect); a body carrying a
//!      reshare-only field → 400 (parse reject).
//!
//! The genuine 6-party DKG-over-relay run is the relay-gated step-4 vector.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv_mpc_service::dkg_relay_handlers::DkgRelayInitRequest;
use bsv_mpc_service::{build_router, AppState, AuthState, SqliteShareStorage};

fn well_formed_init_json() -> serde_json::Value {
    serde_json::json!({
        "agent_id": "02bbccddeeff00112233445566778899aabbccddeeff00112233445566778899ab",
        "dkg_session": "11".repeat(32),
        "my_index": 3,
        "threshold": 4,
        "parties": 6,
        "peers": [
            { "index": 0, "pub_hex": "02aa" },
            { "index": 1, "pub_hex": "02bb" }
        ]
    })
}

#[test]
fn request_shape_accepts_dkg_fields_rejects_reshare_fields() {
    // Accepts the fresh-DKG fields.
    let ok: Result<DkgRelayInitRequest, _> = serde_json::from_value(well_formed_init_json());
    let req = ok.expect("well-formed DKG init request must parse");
    assert_eq!(req.my_index, 3);
    assert_eq!(req.threshold, 4);
    assert_eq!(req.parties, 6);
    assert_eq!(req.peers.len(), 2);

    // Rejects a reshare-only field (deny_unknown_fields) — this is a FRESH DKG, not
    // a reshare; the wire shape must not silently accept PSS/reshare parameters.
    let mut with_reshare = well_formed_init_json();
    with_reshare["reshare_session"] = serde_json::json!("22".repeat(32));
    let rejected: Result<DkgRelayInitRequest, _> = serde_json::from_value(with_reshare);
    assert!(
        rejected.is_err(),
        "DkgRelayInitRequest must reject reshare-only fields (deny_unknown_fields)"
    );
}

async fn dev_server_no_identity() -> (String, tokio::task::JoinHandle<()>) {
    // The relay routes take their server identity from MPC_SERVER_PRIVATE_KEY (NOT
    // AuthState); unset it so the identity gate fires deterministically. All
    // env-touching assertions here want it UNSET, so removal is race-safe.
    std::env::remove_var("MPC_SERVER_PRIVATE_KEY");

    let data_dir = std::env::temp_dir().join(format!("dkg_relay_unit_{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).unwrap();
    let storage = SqliteShareStorage::open(data_dir.to_str().unwrap()).unwrap();
    let state = Arc::new(AppState {
        data_dir: data_dir.to_string_lossy().to_string(),
        storage: Arc::new(RwLock::new(storage)),
        started_at: chrono::Utc::now(),
        provision: None,
        auth: AuthState::dev(), // allow-unauthenticated → auth passes, we reach the gates
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dkg_relay_routes_gate_on_server_identity_and_parse() {
    let (url, _server) = dev_server_no_identity().await;
    let http = reqwest::Client::new();

    // GET /dkg-relay/identity with no server identity → 412.
    let id_resp = http
        .get(format!("{url}/dkg-relay/identity"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        id_resp.status().as_u16(),
        412,
        "GET /dkg-relay/identity must be 412 PRECONDITION_FAILED when no server identity is set"
    );

    // Well-formed POST /dkg-relay/init: dev auth passes, body parses, then the
    // server-identity gate fires → 412 (before any relay connect).
    let init_412 = http
        .post(format!("{url}/dkg-relay/init"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&well_formed_init_json()).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(
        init_412.status().as_u16(),
        412,
        "well-formed POST /dkg-relay/init must reach the server-identity gate → 412"
    );

    // A body with a reshare-only field → 400 (parse reject, deny_unknown_fields) —
    // fires before the identity gate, so it is 400 not 412.
    let mut bad = well_formed_init_json();
    bad["reshare_session"] = serde_json::json!("22".repeat(32));
    let init_400 = http
        .post(format!("{url}/dkg-relay/init"))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&bad).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(
        init_400.status().as_u16(),
        400,
        "POST /dkg-relay/init with a reshare-only field must be 400 (deny_unknown_fields)"
    );
}
