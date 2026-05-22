//! Canonical BRC-31 Authrite verification + owner-authz for the self-hosted KSS
//! (§07/§08).
//!
//! This is the **axum / native** server that mirrors the canonical
//! `bsv-middleware-rs` example (`examples/axum_server.rs`): the handshake parses
//! an `AuthMessage` InitialRequest and returns a signed InitialResponse; the
//! per-request gate rebuilds the BRC-104 binary payload via
//! `build_request_payload` + `filter_signable_headers`, looks up the session,
//! and verifies with `verify_message_signature`. The canonical
//! [`bsv_mpc_core::brc31_client::Brc31Client`] (proven by
//! `bsv-mpc-core/tests/conformance_07_brc31_auth.rs`) interoperates with it
//! byte-for-byte.
//!
//! ## Why this exists
//!
//! Before this, the standalone `bsv-mpc-service` exposed `/dkg`, `/sign`,
//! `/presign`, and `/ecdh` with **no authentication** — violating §07.6 ("no
//! endpoint is trusted by location"). A 2-of-2 wallet's funds can't be forged
//! with one share, so this is not fund-loss, but an unauthed cosigner is a DoS
//! surface and leaks `share_A`'s ECDH partials. This module closes that gap by
//! mirroring the worker's verified-caller + owner-authz model:
//!
//! 1. DKG-init captures the authenticated caller; DKG-complete records it as the
//!    share's `owner_identity` (§08.1).
//! 2. `/sign/init`, `/presign/init`, `/ecdh` verify BRC-31 and reject any caller
//!    that is not the recorded owner (403) — checked BEFORE share material is
//!    loaded or used.
//!
//! ## Replay (§07.1)
//!
//! Each session tracks the per-request nonces it has consumed (a bounded,
//! TTL-evicted set). A signed request that reuses a `(your_nonce, nonce)` pair
//! is rejected (401) — a captured request cannot be replayed.
//!
//! ## Dev mode
//!
//! When `MPC_SERVER_PRIVATE_KEY` is unset the service runs `allow_unauthenticated`
//! (no server identity to sign the handshake), preserving the existing local /
//! self-stocking-loop flows: an unauthenticated DKG records an empty owner, and
//! an empty owner authorizes any caller (the §07 entrypoint gate is simply
//! absent). To actually enforce §07.6 on a deployed cosigner, set the env var.

use std::collections::HashMap;
use std::sync::Mutex;

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::Engine;
use bsv::auth::{AuthMessage, MessageType, AUTH_VERSION};
use bsv::primitives::ec::PrivateKey;
use bsv::wallet::{Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel};
use bsv::PublicKey;
use bsv_middleware_rs::transport::{build_request_payload, filter_signable_headers};
use bsv_middleware_rs::{verify_message_signature, StoredSession};
use bsv_mpc_core::brc31_client::headers;

/// Default session TTL: 1 hour (§07.7).
const DEFAULT_SESSION_TTL_MS: u64 = 3_600_000;
/// Environment variable holding the server's secp256k1 identity key (hex). When
/// unset, the service runs in `allow_unauthenticated` (dev) mode.
const SERVER_KEY_ENV: &str = "MPC_SERVER_PRIVATE_KEY";
/// Cap on the number of consumed-nonce entries retained per session, so a
/// long-lived session's replay set can't grow unbounded. Older-than-TTL entries
/// are evicted; this is a hard ceiling under the TTL window.
const MAX_REPLAY_ENTRIES: usize = 8192;

/// A typed `(StatusCode, Json)` error body, identical in shape to the handlers'
/// own `err_response`, so a handler can `return resp;` directly.
pub type AuthRejection = (StatusCode, Json<serde_json::Value>);

fn reject(status: StatusCode, msg: impl std::fmt::Display) -> AuthRejection {
    (
        status,
        Json(serde_json::json!({ "error": msg.to_string() })),
    )
}

// ── Configuration + session storage (held in AppState) ──────────────────────

/// Server-side state for one authenticated BRC-31 connection. Wraps the
/// canonical [`StoredSession`] plus per-session replay bookkeeping (§07.1).
#[derive(Clone)]
struct AuthSession {
    /// Canonical session record (server nonce, peer identity, peer nonce, …).
    stored: StoredSession,
    /// Session creation time (ms since epoch) — for TTL enforcement (§07.7).
    created_at: u64,
    /// Consumed per-request nonces (the client's fresh `x-bsv-auth-nonce`),
    /// each with the time it was first seen. Reuse ⇒ replay ⇒ reject.
    consumed_nonces: HashMap<String, u64>,
}

/// BRC-31 server configuration + live session store. Lives in `AppState` so each
/// process (and each in-process test instance) is fully isolated.
pub struct AuthState {
    /// Server identity wallet. `None` ⇒ dev mode (`allow_unauthenticated`).
    wallet: Option<ProtoWallet>,
    /// Session TTL in milliseconds (§07.7, ≤ 1h).
    session_ttl_ms: u64,
    /// Live sessions keyed by `server_nonce` (the handshake-issued nonce the
    /// client echoes back as `x-bsv-auth-your-nonce`).
    sessions: Mutex<HashMap<String, AuthSession>>,
}

impl AuthState {
    /// Build from the environment: enforced when `MPC_SERVER_PRIVATE_KEY` is a
    /// valid hex key, dev mode otherwise.
    pub fn from_env() -> Self {
        match std::env::var(SERVER_KEY_ENV).ok() {
            Some(hex) if !hex.trim().is_empty() => match PrivateKey::from_hex(hex.trim()) {
                Ok(key) => {
                    tracing::info!("BRC-31 auth ENFORCED (MPC_SERVER_PRIVATE_KEY set)");
                    Self::with_key(key)
                }
                Err(e) => {
                    tracing::error!("MPC_SERVER_PRIVATE_KEY invalid hex ({e}); refusing to start in a false-secure state");
                    panic!("MPC_SERVER_PRIVATE_KEY set but invalid: {e}");
                }
            },
            _ => {
                tracing::warn!(
                    "BRC-31 auth DISABLED (dev mode) — set {SERVER_KEY_ENV} to enforce §07.6"
                );
                Self::dev()
            }
        }
    }

    /// Dev mode: no server key, all otherwise-unauthenticated requests allowed.
    pub fn dev() -> Self {
        Self {
            wallet: None,
            session_ttl_ms: DEFAULT_SESSION_TTL_MS,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Enforced mode with an explicit server identity key (used by tests).
    pub fn with_key(server_key: PrivateKey) -> Self {
        Self {
            wallet: Some(ProtoWallet::new(Some(server_key))),
            session_ttl_ms: DEFAULT_SESSION_TTL_MS,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Whether requests without BRC-104 headers are allowed through (dev mode).
    pub fn allow_unauthenticated(&self) -> bool {
        self.wallet.is_none()
    }

    fn put_session(&self, session: AuthSession) {
        self.sessions
            .lock()
            .expect("auth session lock poisoned")
            .insert(session.stored.session_nonce.clone(), session);
    }

    fn get_session(&self, server_nonce: &str) -> Option<AuthSession> {
        self.sessions
            .lock()
            .expect("auth session lock poisoned")
            .get(server_nonce)
            .cloned()
    }

    /// Atomically record that `request_nonce` was consumed on the session keyed
    /// by `server_nonce`. Returns `true` if it was fresh (accept), `false` if it
    /// had already been seen (replay → reject). Evicts TTL-stale entries.
    fn consume_request_nonce(&self, server_nonce: &str, request_nonce: &str, now: u64) -> bool {
        let mut guard = self.sessions.lock().expect("auth session lock poisoned");
        let Some(session) = guard.get_mut(server_nonce) else {
            return false;
        };
        let ttl = self.session_ttl_ms;
        session
            .consumed_nonces
            .retain(|_, seen_at| now.saturating_sub(*seen_at) <= ttl);
        if session.consumed_nonces.contains_key(request_nonce) {
            return false; // replay
        }
        // Hard ceiling: if somehow over cap (despite TTL eviction), drop oldest.
        if session.consumed_nonces.len() >= MAX_REPLAY_ENTRIES {
            if let Some(oldest) = session
                .consumed_nonces
                .iter()
                .min_by_key(|(_, t)| **t)
                .map(|(k, _)| k.clone())
            {
                session.consumed_nonces.remove(&oldest);
            }
        }
        session
            .consumed_nonces
            .insert(request_nonce.to_string(), now);
        true
    }
}

/// The authenticated caller's identity. Empty `identity_key` ⇒ dev/unauthenticated.
#[derive(Debug, Clone)]
pub struct CallerIdentity {
    pub identity_key: String,
}

impl CallerIdentity {
    fn unauthenticated() -> Self {
        Self {
            identity_key: String::new(),
        }
    }
    /// The caller as `Option<&str>` (None when unauthenticated/dev).
    pub fn as_opt(&self) -> Option<&str> {
        if self.identity_key.is_empty() {
            None
        } else {
            Some(&self.identity_key)
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn current_time_ms() -> u64 {
    chrono::Utc::now().timestamp_millis() as u64
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Whether the request carries a BRC-104 signature header (a signed request).
fn has_auth_headers(headers: &HeaderMap) -> bool {
    header(headers, headers::SIGNATURE)
        .map(|s| !s.is_empty())
        .unwrap_or(false)
}

/// Build the canonical signable header set the way the server reconstructs it
/// from the wire. Only `content-type` (and any `x-bsv-*` non-auth /
/// `authorization`) survive `filter_signable_headers`; the auth headers are
/// excluded. The client signs over exactly this set.
fn signable_from_request(headers: &HeaderMap) -> Vec<(String, String)> {
    let raw: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    filter_signable_headers(&raw)
}

// ── Core verification (§07) ─────────────────────────────────────────────────

/// Verify canonical BRC-31 auth over `(method, path, body)`, or allow through in
/// dev mode.
///
/// - **Dev mode** (no server key) ⇒ always `Ok(unauthenticated)`. We have no key
///   to verify a signature with, so ANY headers a client happens to send are
///   ignored rather than 500'd. With no bound owner this still authorizes
///   everyone — exactly the prior, un-enforced behavior.
/// - **Enforced**, no signature header ⇒ `Err(401)` (§07.6).
/// - **Enforced**, signed ⇒ full canonical verification (401/403/500), including
///   replay rejection (§07.1).
pub fn verify_or_allow(
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
    auth: &AuthState,
) -> Result<CallerIdentity, AuthRejection> {
    if auth.allow_unauthenticated() {
        return Ok(CallerIdentity::unauthenticated());
    }
    if !has_auth_headers(headers) {
        return Err(reject(
            StatusCode::UNAUTHORIZED,
            "Not authenticated: missing BRC-104 auth headers (§07.6)",
        ));
    }
    verify_request(method, path, headers, body, auth)
}

/// Verify the canonical BRC-31 signature on an incoming request via
/// `bsv-middleware-rs::verify_message_signature`.
fn verify_request(
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
    auth: &AuthState,
) -> Result<CallerIdentity, AuthRejection> {
    // The server must have an identity wallet to verify against.
    let wallet = auth.wallet.as_ref().ok_or_else(|| {
        reject(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server has no identity key configured but received signed request",
        )
    })?;

    // 1. Extract BRC-104 headers.
    let peer_identity_key = header(headers, headers::IDENTITY_KEY)
        .ok_or_else(|| reject(StatusCode::UNAUTHORIZED, "missing identity-key header"))?;
    let signature_hex = header(headers, headers::SIGNATURE)
        .ok_or_else(|| reject(StatusCode::UNAUTHORIZED, "missing signature header"))?;
    let nonce = header(headers, headers::NONCE)
        .ok_or_else(|| reject(StatusCode::UNAUTHORIZED, "missing nonce header"))?;
    let your_nonce = header(headers, headers::YOUR_NONCE)
        .ok_or_else(|| reject(StatusCode::UNAUTHORIZED, "missing your-nonce header"))?;
    let request_id_b64 = header(headers, headers::REQUEST_ID)
        .ok_or_else(|| reject(StatusCode::UNAUTHORIZED, "missing request-id header"))?;

    // 2. Decode the request id (32 bytes, base64) — part of the signed payload.
    let request_id: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(request_id_b64)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| {
            reject(
                StatusCode::UNAUTHORIZED,
                "request-id must be base64 of 32 bytes",
            )
        })?;

    // 3. Look up the session by your_nonce (= our server_nonce).
    let session = auth
        .get_session(your_nonce)
        .ok_or_else(|| reject(StatusCode::UNAUTHORIZED, "session not found for nonce"))?;

    // 4. TTL (§07.7).
    let now = current_time_ms();
    if now.saturating_sub(session.created_at) > auth.session_ttl_ms {
        return Err(reject(StatusCode::UNAUTHORIZED, "session expired"));
    }

    // 5. Identity must match the handshake-bound peer identity.
    if session.stored.peer_identity_key != peer_identity_key {
        return Err(reject(
            StatusCode::FORBIDDEN,
            "identity mismatch with established session",
        ));
    }

    // 6. Rebuild the BRC-104 payload exactly as the client signed it:
    //    (method, path, search="", signable headers, body).
    let signable = signable_from_request(headers);
    let payload = build_request_payload(&request_id, method, path, "", &signable, body);

    let peer_pub = PublicKey::from_hex(peer_identity_key).map_err(|e| {
        reject(
            StatusCode::UNAUTHORIZED,
            format!("invalid peer pubkey: {e}"),
        )
    })?;
    let signature = hex::decode(signature_hex).map_err(|e| {
        reject(
            StatusCode::UNAUTHORIZED,
            format!("invalid signature hex: {e}"),
        )
    })?;

    // 7. Reconstruct the canonical General AuthMessage and verify.
    let mut msg = AuthMessage::new(MessageType::General, peer_pub);
    msg.nonce = Some(nonce.to_string());
    msg.your_nonce = Some(your_nonce.to_string());
    msg.signature = Some(signature);
    msg.payload = Some(payload);

    match verify_message_signature(wallet, &msg, &session.stored) {
        Ok(true) => {}
        Ok(false) => {
            return Err(reject(
                StatusCode::UNAUTHORIZED,
                "ECDSA verification failed against canonical BRC-31 derived key",
            ))
        }
        Err(e) => {
            return Err(reject(
                StatusCode::UNAUTHORIZED,
                format!("BRC-31 verification error: {e}"),
            ))
        }
    }

    // 8. Replay rejection (§07.1): the signature is valid; now ensure this
    //    per-request nonce has not been consumed before on this session. Done
    //    AFTER signature verification so an attacker can't poison the set with
    //    forged nonces.
    if !auth.consume_request_nonce(your_nonce, nonce, now) {
        return Err(reject(
            StatusCode::UNAUTHORIZED,
            "stale/replayed request nonce (§07.1)",
        ));
    }

    Ok(CallerIdentity {
        identity_key: peer_identity_key.to_string(),
    })
}

// ── Owner authorization (§08.1) ─────────────────────────────────────────────

/// Pure authorization decision: a caller is authorized iff the share has no
/// bound owner (dev/legacy — the §07 gate already applied) or the caller's
/// identity exactly equals the bound owner.
pub fn is_owner_authorized(caller: Option<&str>, owner: Option<&str>) -> bool {
    match owner {
        None => true,
        Some(o) => caller == Some(o),
    }
}

/// Enforce that the authenticated caller owns the share it is operating on
/// (§08.1). Returns `Some((403, …))` to return when the caller is not the owner,
/// `None` when authorized. Call BEFORE any share material is loaded/used.
pub fn authz_owner_or_reject(caller: Option<&str>, owner: Option<&str>) -> Option<AuthRejection> {
    if is_owner_authorized(caller, owner) {
        return None;
    }
    let who = caller.unwrap_or("<unauthenticated>");
    Some(reject(
        StatusCode::FORBIDDEN,
        format!("identity {who} is not authorized for this share (§08.1)"),
    ))
}

// ── Handshake (POST /.well-known/auth) ──────────────────────────────────────

/// Handle the canonical BRC-31 handshake: parse the client's `AuthMessage`
/// InitialRequest from the raw body, mint + persist a server session nonce, and
/// return a signed InitialResponse (response headers + JSON body). In dev mode
/// (no server key) returns a benign stub — verification is skipped, so the
/// body/signature are unused.
pub fn handshake(
    body: &Bytes,
    auth: &AuthState,
) -> Result<(Vec<(String, String)>, serde_json::Value), AuthRejection> {
    let wallet = match auth.wallet.as_ref() {
        Some(w) => w,
        None => {
            // Dev mode: preserve the prior stub behavior so non-enforced flows
            // are unaffected.
            return Ok((
                vec![],
                serde_json::json!({
                    "identityKey": "00000000000000000000000000000000000000000000000000000000000000000",
                    "nonce": "development-stub-nonce",
                    "certificates": []
                }),
            ));
        }
    };

    // Parse the canonical InitialRequest.
    let req: AuthMessage = serde_json::from_slice(body).map_err(|e| {
        reject(
            StatusCode::BAD_REQUEST,
            format!("invalid InitialRequest: {e}"),
        )
    })?;
    if req.message_type != MessageType::InitialRequest {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "expected initialRequest message type",
        ));
    }
    let peer_nonce = req.initial_nonce.clone().or_else(|| req.nonce.clone());

    // Mint a fresh server session nonce (base64 of 32 random bytes).
    let mut nonce_bytes = [0u8; 32];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| {
        reject(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("entropy error: {e}"),
        )
    })?;
    let server_nonce = base64::engine::general_purpose::STANDARD.encode(nonce_bytes);

    let server_key = wallet.identity_key();
    let server_identity = server_key.to_hex();

    // Persist the canonical session keyed by server_nonce.
    let mut stored = StoredSession::new(server_nonce.clone(), req.identity_key.to_hex());
    stored.peer_nonce = peer_nonce.clone();
    stored.is_authenticated = true;
    auth.put_session(AuthSession {
        stored,
        created_at: current_time_ms(),
        consumed_nonces: HashMap::new(),
    });

    // Build + sign the InitialResponse (its own signing_data + get_key_id;
    // protocolID [Counterparty, "auth message signature"], counterparty = the
    // client). SecurityLevel::Counterparty matches the canonical @bsv TS handshake
    // (Peer.processInitialRequest) + bsv-rs + bsv-middleware-cloudflare, so a
    // canonical TS/cross-impl client can verify our InitialResponse signature.
    let mut resp = AuthMessage::new(MessageType::InitialResponse, server_key.clone());
    resp.nonce = Some(server_nonce.clone());
    resp.initial_nonce = Some(server_nonce.clone());
    resp.your_nonce = peer_nonce.clone();
    let data = resp.signing_data();
    let key_id = resp.get_key_id(None);
    let sig = wallet
        .create_signature(CreateSignatureArgs {
            data: Some(data),
            hash_to_directly_sign: None,
            protocol_id: Protocol::new(SecurityLevel::Counterparty, "auth message signature"),
            key_id,
            counterparty: Some(Counterparty::Other(req.identity_key.clone())),
        })
        .map_err(|e| {
            reject(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("InitialResponse signing failed: {e}"),
            )
        })?;
    resp.signature = Some(sig.signature);

    let body_json = serde_json::to_value(&resp).map_err(|e| {
        reject(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("serialize InitialResponse: {e}"),
        )
    })?;

    let resp_headers = vec![
        (headers::VERSION.to_string(), AUTH_VERSION.to_string()),
        (headers::IDENTITY_KEY.to_string(), server_identity),
        (
            headers::MESSAGE_TYPE.to_string(),
            "initialResponse".to_string(),
        ),
        (headers::NONCE.to_string(), server_nonce.clone()),
        (
            headers::YOUR_NONCE.to_string(),
            peer_nonce.unwrap_or_default(),
        ),
        ("content-type".to_string(), "application/json".to_string()),
        (
            "access-control-expose-headers".to_string(),
            [
                headers::VERSION,
                headers::IDENTITY_KEY,
                headers::NONCE,
                headers::YOUR_NONCE,
                headers::SIGNATURE,
                headers::MESSAGE_TYPE,
                headers::REQUEST_ID,
            ]
            .join(", "),
        ),
    ];
    Ok((resp_headers, body_json))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_mpc_core::brc31_client::Brc31Client;

    fn key(byte: u8) -> PrivateKey {
        PrivateKey::from_bytes(&[byte | 1; 32]).expect("valid key")
    }

    /// Drive a handshake through the public API and return a `Brc31Client` bound
    /// to the issued server session, plus the `AuthState`.
    fn handshook(server_seed: u8, client_seed: u8) -> (AuthState, Brc31Client) {
        let auth = AuthState::with_key(key(server_seed));
        let mut client = Brc31Client::new(key(client_seed));
        let body = Bytes::from(client.initial_request_body().unwrap());
        let (resp_headers, _body) = handshake(&body, &auth).expect("handshake ok");
        let get = |name: &str| {
            resp_headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        assert!(client.complete_handshake(get(headers::IDENTITY_KEY), get(headers::NONCE)));
        (auth, client)
    }

    /// Convert client header pairs into an axum `HeaderMap`.
    fn headers_of(pairs: Vec<(&'static str, String)>) -> HeaderMap {
        let mut hm = HeaderMap::new();
        for (name, value) in pairs {
            hm.insert(
                axum::http::HeaderName::from_static(name),
                value.parse().unwrap(),
            );
        }
        // The client always sends content-type: application/json with its body.
        hm.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        hm
    }

    #[test]
    fn dev_mode_allows_unauthenticated() {
        let auth = AuthState::dev();
        assert!(auth.allow_unauthenticated());
        let id = verify_or_allow("POST", "/sign/init", &HeaderMap::new(), b"{}", &auth)
            .expect("dev allows no-auth");
        assert!(id.as_opt().is_none());
    }

    #[test]
    fn dev_mode_allows_even_with_auth_headers() {
        let auth = AuthState::dev();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_static(super::headers::IDENTITY_KEY),
            "02abcdef".parse().unwrap(),
        );
        headers.insert(
            axum::http::HeaderName::from_static(super::headers::SIGNATURE),
            "deadbeef".parse().unwrap(),
        );
        let id = verify_or_allow("POST", "/sign/init", &headers, b"{}", &auth)
            .expect("dev allows even with headers");
        assert!(id.as_opt().is_none());
    }

    #[test]
    fn enforced_mode_rejects_unauthenticated() {
        let auth = AuthState::with_key(key(7));
        assert!(!auth.allow_unauthenticated());
        let err = verify_or_allow("POST", "/sign/init", &HeaderMap::new(), b"{}", &auth)
            .expect_err("enforced rejects no-auth");
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn owner_authz_rules() {
        assert!(is_owner_authorized(None, None));
        assert!(is_owner_authorized(Some("02ab"), None));
        assert!(is_owner_authorized(Some("02ab"), Some("02ab")));
        assert!(!is_owner_authorized(Some("02cd"), Some("02ab")));
        assert!(!is_owner_authorized(None, Some("02ab")));
        assert!(authz_owner_or_reject(Some("02ab"), Some("02ab")).is_none());
        let r = authz_owner_or_reject(Some("02cd"), Some("02ab")).expect("stranger rejected");
        assert_eq!(r.0, StatusCode::FORBIDDEN);
        let r = authz_owner_or_reject(None, Some("02ab")).expect("unauth rejected");
        assert_eq!(r.0, StatusCode::FORBIDDEN);
    }

    /// Full handshake → canonical authed request round trip, proving
    /// wire-compatibility with the canonical `Brc31Client`.
    #[test]
    fn handshake_then_authed_request_verifies() {
        let (auth, client) = handshook(0x11, 0x22);
        let body = br#"{"session_id":"c07"}"#;
        let req_headers = headers_of(client.request_headers("POST", "/sign/init", body).unwrap());
        let id = verify_or_allow("POST", "/sign/init", &req_headers, body, &auth)
            .expect("authed request verifies");
        assert_eq!(id.identity_key, key(0x22).public_key().to_hex());
    }

    #[test]
    fn tampered_body_rejected() {
        let (auth, client) = handshook(0x11, 0x22);
        let body = br#"{"session_id":"c07"}"#;
        let req_headers = headers_of(client.request_headers("POST", "/sign/init", body).unwrap());
        // Verify over a DIFFERENT body than was signed → must fail.
        let err = verify_or_allow("POST", "/sign/init", &req_headers, b"{}", &auth)
            .expect_err("tampered body rejected");
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn tampered_signature_rejected() {
        let (auth, client) = handshook(0x11, 0x22);
        let body = br#"{"x":1}"#;
        let mut pairs = client.request_headers("POST", "/sign/init", body).unwrap();
        for p in pairs.iter_mut() {
            if p.0 == super::headers::SIGNATURE {
                p.1 = "3006020100020100".to_string();
            }
        }
        let req_headers = headers_of(pairs);
        let err = verify_or_allow("POST", "/sign/init", &req_headers, body, &auth)
            .expect_err("tampered sig rejected");
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn unknown_session_rejected() {
        let auth = AuthState::with_key(key(0x11));
        let mut client = Brc31Client::new(key(0x22));
        let server_nonce = base64::engine::general_purpose::STANDARD.encode([0xEEu8; 32]);
        assert!(client.complete_handshake(key(0x11).public_key().to_hex(), server_nonce));
        let body = b"{}";
        let req_headers = headers_of(client.request_headers("POST", "/sign/init", body).unwrap());
        let err = verify_or_allow("POST", "/sign/init", &req_headers, body, &auth)
            .expect_err("unknown session rejected");
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn replay_of_same_request_rejected() {
        // §07.1: a valid authed request verifies once (200), an identical replay
        // (same headers, same body, same per-request nonce) is rejected.
        let (auth, client) = handshook(0x11, 0x22);
        let body = br#"{"session_id":"replay"}"#;
        let pairs = client.request_headers("POST", "/sign/init", body).unwrap();
        let req_headers = headers_of(pairs.clone());
        // First time → accepted.
        verify_or_allow("POST", "/sign/init", &req_headers, body, &auth)
            .expect("first authed request verifies");
        // Identical replay → rejected.
        let err = verify_or_allow("POST", "/sign/init", &req_headers, body, &auth)
            .expect_err("replay must be rejected");
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }
}
