//! **#7 finding #1 gate** — the self-hosted `bsv-mpc-service` enforces §07.6 +
//! §08.1 owner-authz on its funded-boundary endpoints.
//!
//! Before this, the service's `/dkg`, `/sign`, `/presign`, `/ecdh` loaded
//! `share_A` for ANY caller — an unauthenticated cosigner (DoS + ECDH-partial
//! leak; not fund-loss, since 2-of-2 needs both shares). This proves the fix
//! against a REAL in-process service over HTTP:
//!
//! 1. Spin up `bsv-mpc-service` with auth ENFORCED (a server identity key).
//! 2. Run a real **authed** distributed DKG (`run_dkg_over_http_authed`) as the
//!    owner → the service records `owner_identity` = the owner's BRC-31 key
//!    against `share_A` (§08.1) at DKG-complete.
//! 3. Exercise `/ecdh` (one round-trip) three ways:
//!    - **unauthed** (no BRC-104 headers) → **401** (§07.6).
//!    - **stranger** (valid BRC-31 session, different identity) → **403** (§08.1).
//!    - **owner** (the DKG identity) → **200** + a partial ECDH point.
//!
//!    Plus a spot-check that `/sign/init` + `/presign/init` reject the stranger.
//!
//! Gated on `SERVICE_AUTHZ_E2E=1` (a real DKG generates Paillier primes inline
//! → ~2 min):
//!
//! ```bash
//! SERVICE_AUTHZ_E2E=1 cargo test -p bsv-mpc-proxy \
//!   --test service_owner_authz_e2e --release -- --nocapture --test-threads=1
//! ```

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::brc31_client::{headers, Brc31Client};
use bsv_mpc_core::types::ThresholdConfig;
use bsv_mpc_proxy::bridge::run_dkg_over_http_authed;
use bsv_mpc_service::{build_router, AppState, AuthState, SqliteShareStorage};

fn opt_in() -> bool {
    std::env::var("SERVICE_AUTHZ_E2E").ok().as_deref() == Some("1")
}

/// Deterministic, valid secp256k1 key from a single seed byte.
fn key_from(byte: u8) -> PrivateKey {
    PrivateKey::from_bytes(&[byte | 1; 32]).expect("valid key")
}

/// Complete a BRC-31 handshake against the in-process service and return a
/// client whose `request_headers()` produce a verifiable authed request.
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
    let resp = req.send().await.expect("handshake request");
    assert!(
        resp.status().is_success(),
        "handshake must succeed, got {}",
        resp.status()
    );
    let h = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let server_identity = h(headers::IDENTITY_KEY).expect("server identity in handshake");
    let server_nonce = h(headers::NONCE).expect("server nonce in handshake");
    assert!(brc.complete_handshake(server_identity, server_nonce));
    brc
}

/// POST `/ecdh` with the given (optional) authed client. `None` ⇒ no auth headers.
async fn post_ecdh(
    svc_url: &str,
    agent_id: &str,
    counterparty_pub: &str,
    brc: Option<&Brc31Client>,
) -> reqwest::Response {
    let http = reqwest::Client::new();
    let body = serde_json::to_vec(&serde_json::json!({
        "agent_id": agent_id,
        "counterparty_pub": counterparty_pub,
    }))
    .unwrap();
    let mut req = http
        .post(format!("{svc_url}/ecdh"))
        .header("content-type", "application/json")
        .body(body.clone());
    if let Some(brc) = brc {
        for (name, value) in brc
            .request_headers("POST", "/ecdh", &body)
            .expect("authed headers")
        {
            req = req.header(name, value);
        }
    }
    req.send().await.expect("/ecdh request")
}

/// POST any JSON endpoint with an authed client (for the sign/presign spot-check).
async fn post_authed(
    svc_url: &str,
    path: &str,
    body: serde_json::Value,
    brc: &Brc31Client,
) -> reqwest::Response {
    let http = reqwest::Client::new();
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let mut req = http
        .post(format!("{svc_url}{path}"))
        .header("content-type", "application/json")
        .body(body_bytes.clone());
    for (name, value) in brc
        .request_headers("POST", path, &body_bytes)
        .expect("authed headers")
    {
        req = req.header(name, value);
    }
    req.send().await.expect("authed request")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn service_enforces_owner_authz() {
    if !opt_in() {
        eprintln!("SERVICE_AUTHZ_E2E=1 not set — skipping #7 finding-#1 owner-authz gate.");
        return;
    }
    let _ = tracing_subscriber::fmt::try_init();

    // ── 1. In-process service with auth ENFORCED. ──
    let server_key = key_from(0x5e); // the service's BRC-31 server identity
    let data_dir = std::env::temp_dir().join(format!("svc_authz_{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).unwrap();
    let storage = SqliteShareStorage::open(data_dir.to_str().unwrap()).unwrap();
    let state = Arc::new(AppState {
        data_dir: data_dir.to_string_lossy().to_string(),
        storage: RwLock::new(storage),
        started_at: chrono::Utc::now(),
        provision: None,
        auth: AuthState::with_key(server_key),
        custody: None,
    });
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let svc_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── 2. Authed DKG as the OWNER → service binds owner_identity (§08.1). ──
    let owner_seed = 0x01u8;
    let owner_hex = key_from(owner_seed).public_key().to_hex();
    let config = ThresholdConfig::new(2, 2).unwrap();
    let dkg = run_dkg_over_http_authed(&svc_url, config, key_from(owner_seed))
        .await
        .expect("authed distributed DKG");
    let joint_hex = hex::encode(&dkg.joint_key.compressed);
    eprintln!("✔ authed DKG complete — joint {joint_hex}, owner {owner_hex}");

    // A valid counterparty pubkey for the ECDH calls (content irrelevant to the gate).
    let cp_pub = key_from(0x7c).public_key().to_hex();

    // ── 3a. UNAUTHED /ecdh → 401 (§07.6: no endpoint trusted by location). ──
    let unauthed = post_ecdh(&svc_url, &joint_hex, &cp_pub, None).await;
    assert_eq!(
        unauthed.status().as_u16(),
        401,
        "unauthenticated /ecdh MUST be rejected (§07.6)"
    );

    // ── 3b. STRANGER (valid session, wrong identity) /ecdh → 403 (§08.1). ──
    let stranger = handshake(&svc_url, key_from(0x42)).await;
    let stranger_resp = post_ecdh(&svc_url, &joint_hex, &cp_pub, Some(&stranger)).await;
    assert_eq!(
        stranger_resp.status().as_u16(),
        403,
        "a non-owner identity MUST be forbidden from this share (§08.1)"
    );

    // ── 3c. OWNER /ecdh → 200 + a partial ECDH point. ──
    let owner = handshake(&svc_url, key_from(owner_seed)).await;
    let owner_resp = post_ecdh(&svc_url, &joint_hex, &cp_pub, Some(&owner)).await;
    assert_eq!(
        owner_resp.status().as_u16(),
        200,
        "the DKG-time owner MUST be authorized"
    );
    let body: serde_json::Value = owner_resp.json().await.expect("ecdh json");
    let partial = body.get("partial").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(
        partial.len(),
        66,
        "owner ECDH MUST return a 33-byte compressed partial point, got {partial:?}"
    );

    // ── 4. Spot-check: stranger is also rejected on /sign/init + /presign/init. ──
    let sign_resp = post_authed(
        &svc_url,
        "/sign/init",
        serde_json::json!({
            "agent_id": joint_hex,
            "session_id": dkg.session_id.hex(),
            "sighash": hex::encode([7u8; 32]),
            "use_presignature": false,
        }),
        &stranger,
    )
    .await;
    assert_eq!(
        sign_resp.status().as_u16(),
        403,
        "stranger MUST be forbidden from /sign/init (§08.1)"
    );
    let presign_resp = post_authed(
        &svc_url,
        "/presign/init",
        serde_json::json!({
            "agent_id": joint_hex,
            "session_id": dkg.session_id.hex(),
            "count": 1,
        }),
        &stranger,
    )
    .await;
    assert_eq!(
        presign_resp.status().as_u16(),
        403,
        "stranger MUST be forbidden from /presign/init (§08.1)"
    );

    // Negative control: unauthed /sign/init → 401.
    let unauthed_sign = reqwest::Client::new()
        .post(format!("{svc_url}/sign/init"))
        .json(&serde_json::json!({
            "agent_id": joint_hex,
            "session_id": dkg.session_id.hex(),
            "sighash": hex::encode([7u8; 32]),
            "use_presignature": false,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        unauthed_sign.status().as_u16(),
        401,
        "unauthenticated /sign/init MUST be rejected (§07.6)"
    );

    server.abort();
    let _ = std::fs::remove_dir_all(&data_dir);

    eprintln!();
    eprintln!("╔════════════════════════════════════════════════════════════════╗");
    eprintln!("║ #7 finding-#1 GATE PASS — service owner-authz: unauthed→401,    ║");
    eprintln!("║ stranger→403, owner→200 (§07.6 + §08.1), real in-process svc.    ║");
    eprintln!("╚════════════════════════════════════════════════════════════════╝");
}
