//! BRC-31 Authrite verification + owner-authz for the self-hosted KSS (§07/§08).
//!
//! This is the **axum / non-Cloudflare** counterpart to
//! `bsv-mpc-worker/src/auth.rs`. The wire handshake is byte-identical (same
//! BRC-104 headers, same BRC-42-derived-key-over-`SHA-256(nonce)` signing), so
//! the existing transport-agnostic [`bsv_mpc_core::brc31_client::Brc31Client`]
//! talks to this server unchanged. §07.2 requires both hosts to re-derive the
//! same reference handshake; this is that re-derivation for axum.
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
//! ## Dev mode
//!
//! When `MPC_SERVER_PRIVATE_KEY` is unset the service runs `allow_unauthenticated`
//! (no server identity to sign the handshake), preserving the existing local /
//! self-stocking-loop flows: an unauthenticated DKG records an empty owner, and
//! an empty owner authorizes any caller (the §07 entrypoint gate is simply
//! absent). To actually enforce §07.6 on a deployed cosigner, set the env var.

use std::collections::HashMap;
use std::sync::Mutex;

use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use bsv::primitives::ec::{PrivateKey, PublicKey, Signature};
use bsv_mpc_core::brc31_client::headers;
use bsv_mpc_core::hd::{compute_invoice, derive_child_pubkey};

/// Auth protocol name for BRC-42 key derivation (from BRC-31 spec). MUST match
/// the worker + `Brc31Client`.
const AUTH_PROTOCOL_NAME: &str = "auth message signature";
/// BRC-42 security level: Counterparty (2).
const AUTH_SECURITY_LEVEL: u8 = 2;
/// Auth protocol version advertised in the handshake.
const AUTH_VERSION: &str = "0.1";
/// Default session TTL: 1 hour (§07.7).
const DEFAULT_SESSION_TTL_MS: u64 = 3_600_000;
/// Environment variable holding the server's secp256k1 identity key (hex). When
/// unset, the service runs in `allow_unauthenticated` (dev) mode.
const SERVER_KEY_ENV: &str = "MPC_SERVER_PRIVATE_KEY";

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

/// BRC-31 server configuration + live session store. Lives in `AppState` so each
/// process (and each in-process test instance) is fully isolated.
pub struct AuthState {
    /// Server identity key. `None` ⇒ dev mode (`allow_unauthenticated`).
    server_key: Option<PrivateKey>,
    /// Session TTL in milliseconds (§07.7, ≤ 1h).
    session_ttl_ms: u64,
    /// Live sessions keyed by `server_nonce` (the handshake-issued nonce the
    /// client echoes back as `x-bsv-auth-your-nonce`).
    sessions: Mutex<HashMap<String, AuthSession>>,
}

/// Server-side state for one authenticated BRC-31 connection.
#[derive(Clone)]
struct AuthSession {
    /// Server's nonce for this session (base64) — the lookup key.
    server_nonce: String,
    /// Client's identity key (66-char compressed-pubkey hex).
    peer_identity_key: String,
    /// Client's initial handshake nonce (base64).
    #[allow(dead_code)] // retained for response-signing / debugging parity with the worker
    peer_nonce: String,
    /// Session creation time (ms since epoch) — for TTL enforcement.
    created_at: u64,
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
            server_key: None,
            session_ttl_ms: DEFAULT_SESSION_TTL_MS,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Enforced mode with an explicit server identity key (used by tests).
    pub fn with_key(server_key: PrivateKey) -> Self {
        Self {
            server_key: Some(server_key),
            session_ttl_ms: DEFAULT_SESSION_TTL_MS,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Whether requests without BRC-104 headers are allowed through (dev mode).
    pub fn allow_unauthenticated(&self) -> bool {
        self.server_key.is_none()
    }

    fn put_session(&self, session: AuthSession) {
        self.sessions
            .lock()
            .expect("auth session lock poisoned")
            .insert(session.server_nonce.clone(), session);
    }

    fn get_session(&self, server_nonce: &str) -> Option<AuthSession> {
        self.sessions
            .lock()
            .expect("auth session lock poisoned")
            .get(server_nonce)
            .cloned()
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

// ── Helpers (byte-identical to bsv-mpc-worker::auth) ────────────────────────

/// BRC-42 invoice for auth signing: `"2-auth message signature-{key_id}"`.
fn auth_invoice(key_id: &str) -> String {
    compute_invoice(AUTH_SECURITY_LEVEL, AUTH_PROTOCOL_NAME, key_id)
        .expect("AUTH_PROTOCOL_NAME constant must pass canonical BRC-42 validation")
}

/// Signing data for our simplified BRC-31 transport: `SHA-256(nonce)`. The
/// per-request nonce prevents replay; the BRC-42 key_id (both session nonces)
/// binds the signature to the session.
fn compute_signing_hash(nonce: &str) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(nonce.as_bytes()).into()
}

/// Generate a cryptographically random 32-byte nonce, base64-encoded (matches
/// `Brc31Client::generate_nonce` and the worker).
fn generate_nonce() -> Result<String, AuthRejection> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| {
        reject(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("entropy error: {e}"),
        )
    })?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        bytes,
    ))
}

fn current_time_ms() -> u64 {
    chrono::Utc::now().timestamp_millis() as u64
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Whether the request carries a BRC-104 identity-key header.
fn has_auth_headers(headers: &HeaderMap) -> bool {
    header(headers, headers::IDENTITY_KEY)
        .map(|s| !s.is_empty())
        .unwrap_or(false)
}

// ── Core verification (§07) ─────────────────────────────────────────────────

/// Verify BRC-31 auth, or allow through in dev mode.
///
/// - **Dev mode** (no server key) ⇒ always `Ok(unauthenticated)`. We have no key
///   to verify a signature with, so ANY headers a client happens to send (e.g. a
///   proxy that handshook against the dev stub) are ignored rather than 500'd.
///   With no bound owner this still authorizes everyone — exactly the prior,
///   un-enforced behavior.
/// - **Enforced**, no auth headers ⇒ `Err(401)` (§07.6).
/// - **Enforced**, auth headers present ⇒ full BRC-31 verification (401/403/500).
pub fn verify_or_allow(
    headers: &HeaderMap,
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
    verify_request(headers, auth)
}

/// Verify the BRC-31 Authrite signature on an incoming request. Ported from the
/// worker's `verify_request` — identical math, axum types.
fn verify_request(headers: &HeaderMap, auth: &AuthState) -> Result<CallerIdentity, AuthRejection> {
    // The server must have an identity key to verify against. (Reached only when
    // auth headers ARE present; in dev mode with no headers we never get here.)
    let server_key = auth.server_key.as_ref().ok_or_else(|| {
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

    // 2. Look up the session by your_nonce (= our server_nonce).
    let session = auth
        .get_session(your_nonce)
        .ok_or_else(|| reject(StatusCode::UNAUTHORIZED, "session not found for nonce"))?;

    // 3. TTL (§07.7).
    let now = current_time_ms();
    if now.saturating_sub(session.created_at) > auth.session_ttl_ms {
        return Err(reject(StatusCode::UNAUTHORIZED, "session expired"));
    }

    // 4. Identity must match the handshake.
    if session.peer_identity_key != peer_identity_key {
        return Err(reject(
            StatusCode::FORBIDDEN,
            "identity mismatch with established session",
        ));
    }

    // 5. Derive the verification public key via BRC-42 (server side of ECDH).
    let peer_pub = PublicKey::from_hex(peer_identity_key).map_err(|e| {
        reject(
            StatusCode::UNAUTHORIZED,
            format!("invalid peer pubkey: {e}"),
        )
    })?;
    let shared_secret = server_key.derive_shared_secret(&peer_pub).map_err(|e| {
        reject(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("ECDH failed: {e}"),
        )
    })?;
    let key_id = format!("{} {}", nonce, session.server_nonce);
    let invoice = auth_invoice(&key_id);
    let verify_pub = derive_child_pubkey(&peer_pub, &shared_secret, &invoice).map_err(|e| {
        reject(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("BRC-42 derivation failed: {e}"),
        )
    })?;

    // 6. Verify the ECDSA signature over SHA-256(nonce).
    let msg_hash = compute_signing_hash(nonce);
    let sig_bytes = hex::decode(signature_hex).map_err(|e| {
        reject(
            StatusCode::UNAUTHORIZED,
            format!("invalid signature hex: {e}"),
        )
    })?;
    let signature = Signature::from_der(&sig_bytes).map_err(|e| {
        reject(
            StatusCode::UNAUTHORIZED,
            format!("invalid signature DER: {e}"),
        )
    })?;
    if !verify_pub.verify(&msg_hash, &signature) {
        return Err(reject(
            StatusCode::UNAUTHORIZED,
            "ECDSA verification failed against BRC-42 derived key",
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

/// Build the BRC-31 InitialResponse for the handshake. Returns the response
/// headers (to attach) and the JSON body. In dev mode (no server key) returns a
/// benign stub — verification is skipped, so the body/signature are unused.
pub fn handshake(
    headers: &HeaderMap,
    auth: &AuthState,
) -> Result<(Vec<(String, String)>, serde_json::Value), AuthRejection> {
    let server_key = match auth.server_key.as_ref() {
        Some(k) => k,
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

    let peer_identity_key = header(headers, headers::IDENTITY_KEY)
        .ok_or_else(|| reject(StatusCode::BAD_REQUEST, "missing identity-key header"))?;
    let peer_nonce = header(headers, headers::NONCE)
        .ok_or_else(|| reject(StatusCode::BAD_REQUEST, "missing nonce header"))?;
    let initial_nonce = header(headers, headers::INITIAL_NONCE).unwrap_or(peer_nonce);

    let server_nonce = generate_nonce()?;
    let server_pubkey = server_key.public_key();
    let server_identity = server_pubkey.to_hex();

    // Store the session keyed by server_nonce (looked up via your-nonce later).
    auth.put_session(AuthSession {
        server_nonce: server_nonce.clone(),
        peer_identity_key: peer_identity_key.to_string(),
        peer_nonce: initial_nonce.to_string(),
        created_at: current_time_ms(),
    });

    // Sign the InitialResponse body with the BRC-42 derived key (§07 mutual auth).
    let response_body = serde_json::json!({});
    let response_body_bytes =
        serde_json::to_vec(&response_body).expect("serialize empty JSON object");
    let peer_pub = PublicKey::from_hex(peer_identity_key)
        .map_err(|e| reject(StatusCode::BAD_REQUEST, format!("invalid peer pubkey: {e}")))?;
    let key_id = format!("{} {}", server_nonce, initial_nonce);
    let invoice = auth_invoice(&key_id);
    let signing_key = server_key.derive_child(&peer_pub, &invoice).map_err(|e| {
        reject(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("key derivation failed: {e}"),
        )
    })?;
    let msg_hash: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(&response_body_bytes).into()
    };
    let signature = signing_key.sign(&msg_hash).map_err(|e| {
        reject(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("signing failed: {e}"),
        )
    })?;
    let sig_hex = hex::encode(signature.to_der());

    let resp_headers = vec![
        (headers::VERSION.to_string(), AUTH_VERSION.to_string()),
        (headers::IDENTITY_KEY.to_string(), server_identity),
        (
            headers::MESSAGE_TYPE.to_string(),
            "initialResponse".to_string(),
        ),
        (headers::NONCE.to_string(), server_nonce),
        (headers::YOUR_NONCE.to_string(), initial_nonce.to_string()),
        (headers::SIGNATURE.to_string(), sig_hex),
        (
            "access-control-expose-headers".to_string(),
            [
                headers::VERSION,
                headers::IDENTITY_KEY,
                headers::NONCE,
                headers::YOUR_NONCE,
                headers::SIGNATURE,
                headers::MESSAGE_TYPE,
            ]
            .join(", "),
        ),
    ];
    Ok((resp_headers, response_body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> PrivateKey {
        PrivateKey::from_bytes(&[byte | 1; 32]).expect("valid key")
    }

    #[test]
    fn dev_mode_allows_unauthenticated() {
        let auth = AuthState::dev();
        assert!(auth.allow_unauthenticated());
        let id = verify_or_allow(&HeaderMap::new(), &auth).expect("dev allows no-auth");
        assert!(id.as_opt().is_none());
    }

    #[test]
    fn dev_mode_allows_even_with_auth_headers() {
        // Regression: a client that handshook against the dev stub then sends
        // BRC-104 headers must NOT 500 (no server key to verify) — dev mode
        // ignores them and allows. This is the self-stocking dev-container path.
        let auth = AuthState::dev();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_static(headers::IDENTITY_KEY),
            "02abcdef".parse().unwrap(),
        );
        headers.insert(
            axum::http::HeaderName::from_static(headers::SIGNATURE),
            "deadbeef".parse().unwrap(),
        );
        let id = verify_or_allow(&headers, &auth).expect("dev allows even with headers");
        assert!(id.as_opt().is_none());
    }

    #[test]
    fn enforced_mode_rejects_unauthenticated() {
        let auth = AuthState::with_key(key(7));
        assert!(!auth.allow_unauthenticated());
        let err = verify_or_allow(&HeaderMap::new(), &auth).expect_err("enforced rejects no-auth");
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn owner_authz_rules() {
        // No bound owner ⇒ any caller authorized (dev/legacy share).
        assert!(is_owner_authorized(None, None));
        assert!(is_owner_authorized(Some("02ab"), None));
        // Bound owner ⇒ only the exact owner.
        assert!(is_owner_authorized(Some("02ab"), Some("02ab")));
        assert!(!is_owner_authorized(Some("02cd"), Some("02ab")));
        assert!(!is_owner_authorized(None, Some("02ab")));
        // Reject helper mirrors the decision.
        assert!(authz_owner_or_reject(Some("02ab"), Some("02ab")).is_none());
        let r = authz_owner_or_reject(Some("02cd"), Some("02ab")).expect("stranger rejected");
        assert_eq!(r.0, StatusCode::FORBIDDEN);
        let r = authz_owner_or_reject(None, Some("02ab")).expect("unauth rejected");
        assert_eq!(r.0, StatusCode::FORBIDDEN);
    }

    /// Full handshake → authed request round trip, end to end through the
    /// public API, proving wire-compatibility with `Brc31Client`.
    #[test]
    fn handshake_then_authed_request_verifies() {
        let server_key = key(0x11);
        let server_pub_hex = server_key.public_key().to_hex();
        let auth = AuthState::with_key(server_key);

        let mut client = bsv_mpc_core::brc31_client::Brc31Client::new(key(0x22));

        // 1. Client initial request → server handshake.
        let mut init_headers = HeaderMap::new();
        for (name, value) in client.initial_request_headers() {
            init_headers.insert(
                axum::http::HeaderName::from_static(name),
                value.parse().unwrap(),
            );
        }
        let (resp_headers, _body) = handshake(&init_headers, &auth).expect("handshake ok");
        let get = |name: &str| {
            resp_headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        client.complete_handshake(get(headers::IDENTITY_KEY), get(headers::NONCE));
        assert_eq!(get(headers::IDENTITY_KEY), server_pub_hex);

        // 2. Authed request → server verifies, extracts the client identity.
        let mut req_headers = HeaderMap::new();
        for (name, value) in client.request_headers().unwrap() {
            req_headers.insert(
                axum::http::HeaderName::from_static(name),
                value.parse().unwrap(),
            );
        }
        let id = verify_or_allow(&req_headers, &auth).expect("authed request verifies");
        assert_eq!(id.identity_key, key(0x22).public_key().to_hex());
    }

    #[test]
    fn tampered_signature_rejected() {
        let auth = AuthState::with_key(key(0x11));
        let mut client = bsv_mpc_core::brc31_client::Brc31Client::new(key(0x22));
        let mut init_headers = HeaderMap::new();
        for (name, value) in client.initial_request_headers() {
            init_headers.insert(
                axum::http::HeaderName::from_static(name),
                value.parse().unwrap(),
            );
        }
        let (resp_headers, _) = handshake(&init_headers, &auth).unwrap();
        let get = |name: &str| {
            resp_headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        client.complete_handshake(get(headers::IDENTITY_KEY), get(headers::NONCE));

        let mut req_headers = HeaderMap::new();
        for (name, value) in client.request_headers().unwrap() {
            let v = if name == headers::SIGNATURE {
                // Flip the signature to a different (valid-DER) value → must fail.
                "3006020100020100".to_string()
            } else {
                value
            };
            req_headers.insert(
                axum::http::HeaderName::from_static(name),
                v.parse().unwrap(),
            );
        }
        let err = verify_or_allow(&req_headers, &auth).expect_err("tampered sig rejected");
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn unknown_session_rejected() {
        // A signed request whose your-nonce was never issued by this server.
        let auth = AuthState::with_key(key(0x11));
        let mut client = bsv_mpc_core::brc31_client::Brc31Client::new(key(0x22));
        client.complete_handshake(key(0x11).public_key().to_hex(), "never-issued-nonce".into());
        let mut req_headers = HeaderMap::new();
        for (name, value) in client.request_headers().unwrap() {
            req_headers.insert(
                axum::http::HeaderName::from_static(name),
                value.parse().unwrap(),
            );
        }
        let err = verify_or_allow(&req_headers, &auth).expect_err("unknown session rejected");
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }
}
