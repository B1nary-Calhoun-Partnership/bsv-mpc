//! BRC-31 Authrite authentication for the CF Worker KSS.
//!
//! Ported from bsv-auth-cloudflare middleware (~/bsv/rust-middleware).
//! Implements mutual authentication between the MPC Signing Proxy (client)
//! and this Key Share Service (server).
//!
//! ## Protocol Flow
//!
//! ```text
//! Proxy (client)                         KSS Worker (server)
//!     │                                       │
//!     │── POST /.well-known/auth ────────────►│
//!     │   x-bsv-auth-identity-key: <proxy>    │
//!     │   x-bsv-auth-nonce: <client_nonce>    │
//!     │   x-bsv-auth-message-type: initial    │
//!     │                                       │
//!     │◄── 200 + BRC-104 headers ────────────│
//!     │   x-bsv-auth-identity-key: <server>   │
//!     │   x-bsv-auth-nonce: <server_nonce>    │
//!     │   x-bsv-auth-signature: <sig>         │
//!     │                                       │
//!     │── POST /sign/init ───────────────────►│
//!     │   x-bsv-auth-identity-key: <proxy>    │
//!     │   x-bsv-auth-nonce: <fresh_nonce>     │
//!     │   x-bsv-auth-your-nonce: <srv_nonce>  │
//!     │   x-bsv-auth-signature: <sig>         │
//!     │                                       │
//!     │◄── 200 + BRC-104 auth headers ───────│
//! ```
//!
//! ## BRC-42 Key Derivation for Auth Signatures
//!
//! ```text
//! protocol = [2, "auth message signature"]
//! key_id = "{message_nonce} {peer_session_nonce}"
//! invoice = "2-auth message signature-{key_id}"
//! shared_secret = ECDH(counterparty_pub, my_priv)
//! hmac = HMAC-SHA256(compressed(shared_secret), invoice)
//! signing_key = my_priv + hmac  (scalar addition mod n)
//! ```
//!
//! References:
//! - BRC-31: ~/bsv/BRCs/peer-to-peer/0031.md
//! - BRC-42: ~/bsv/BRCs/key-derivation/0042.md
//! - BRC-104: ~/bsv/rust-middleware/bsv-auth-cloudflare/src/transport/cloudflare.rs
//! - POC 8: poc/poc8-brc31-auth/tests/poc.rs

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use bsv::primitives::ec::{PrivateKey, PublicKey, Signature};
use bsv_mpc_core::hd::{compute_invoice, derive_child_pubkey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use worker::*;

// ── BRC-104 Header Constants ─────────────────────────────────────────────
//
// Header names for BRC-104 HTTP transport of BRC-31 auth messages.
// Matches ~/bsv/rust-middleware/bsv-auth-cloudflare/src/transport/cloudflare.rs

/// BRC-104 header names used for Authrite mutual authentication.
pub mod headers {
    pub const VERSION: &str = "x-bsv-auth-version";
    pub const IDENTITY_KEY: &str = "x-bsv-auth-identity-key";
    pub const NONCE: &str = "x-bsv-auth-nonce";
    pub const INITIAL_NONCE: &str = "x-bsv-auth-initial-nonce";
    pub const YOUR_NONCE: &str = "x-bsv-auth-your-nonce";
    pub const SIGNATURE: &str = "x-bsv-auth-signature";
    pub const MESSAGE_TYPE: &str = "x-bsv-auth-message-type";
}

/// Auth protocol name for BRC-42 key derivation (from BRC-31 spec).
const AUTH_PROTOCOL_NAME: &str = "auth message signature";

/// BRC-42 security level: Counterparty (2).
const AUTH_SECURITY_LEVEL: u8 = 2;

/// Auth protocol version (matches bsv-auth-cloudflare).
const AUTH_VERSION: &str = "0.1";

/// Default session TTL: 1 hour in milliseconds.
const DEFAULT_SESSION_TTL_MS: u64 = 3_600_000;

// ── Types ────────────────────────────────────────────────────────────────

/// Configuration for BRC-31 authentication.
///
/// Created from CF Worker environment secrets. When `SERVER_PRIVATE_KEY`
/// is not set, falls back to `allow_unauthenticated` mode for development.
pub struct AuthConfig {
    /// Server's secp256k1 private key (hex-encoded, 64 chars).
    pub server_private_key_hex: String,
    /// Session time-to-live in milliseconds.
    pub session_ttl_ms: u64,
    /// Allow unauthenticated requests (development mode).
    pub allow_unauthenticated: bool,
}

impl AuthConfig {
    /// Load auth config from CF Worker environment.
    ///
    /// Reads `SERVER_PRIVATE_KEY` secret. If not set, enters development
    /// mode where all requests are allowed through without authentication.
    pub fn from_env(env: &Env) -> std::result::Result<Self, worker::Error> {
        match env.secret("SERVER_PRIVATE_KEY") {
            Ok(secret) => Ok(Self {
                server_private_key_hex: secret.to_string(),
                session_ttl_ms: DEFAULT_SESSION_TTL_MS,
                allow_unauthenticated: false,
            }),
            Err(_) => {
                // No server key configured — development mode
                Ok(Self {
                    server_private_key_hex: String::new(),
                    session_ttl_ms: DEFAULT_SESSION_TTL_MS,
                    allow_unauthenticated: true,
                })
            }
        }
    }

    /// Parse the server private key from hex.
    fn server_private_key(&self) -> std::result::Result<PrivateKey, AuthError> {
        PrivateKey::from_hex(&self.server_private_key_hex)
            .map_err(|e| AuthError::VerificationError(format!("invalid server key: {e}")))
    }
}

/// A successfully authenticated identity from a BRC-31 Authrite session.
#[derive(Debug, Clone)]
pub struct AuthenticatedIdentity {
    /// The client's BRC-31 identity key (33-byte compressed secp256k1 pubkey, hex-encoded).
    pub identity_key: String,
    /// The per-request nonce from the authenticated message.
    pub nonce: String,
    /// When this auth session was established (ms since epoch, as string).
    pub established_at: String,
}

impl AuthenticatedIdentity {
    /// Create a default unauthenticated identity (for development mode).
    fn unauthenticated() -> Self {
        Self {
            identity_key: String::new(),
            nonce: String::new(),
            established_at: String::new(),
        }
    }
}

/// Server-side session state for an authenticated BRC-31 connection.
///
/// Stored in memory, keyed by `server_nonce`. Created during handshake,
/// looked up during authenticated request verification.
#[derive(Clone)]
#[allow(dead_code)] // peer_nonce used by sign_response_headers (not yet wired into handlers)
pub struct AuthSession {
    /// Server's nonce for this session (base64-encoded, used as lookup key).
    pub server_nonce: String,
    /// Client's identity key (66-char hex compressed pubkey).
    pub peer_identity_key: String,
    /// Client's initial nonce from handshake (base64-encoded).
    pub peer_nonce: String,
    /// Session creation time (ms since epoch).
    pub created_at: u64,
}

/// Storage backend for BRC-31 auth sessions (§07.7 — caching allowed, TTL ≤ 1h).
///
/// Two impls: [`StaticSessionStore`] (process-global in-memory — native tests +
/// non-DO contexts) and `DoSqlStorage` (durable DO SQLite — the deployed
/// worker). The deployed worker MUST use the durable store: CF runs many
/// entrypoint isolates, so an in-memory session written during the handshake is
/// invisible to a follow-up request that lands on a different isolate
/// (`SessionNotFound`). Backing sessions with the per-identity DO's SQLite +
/// running auth INSIDE the pinned DO makes the handshake-write and request-read
/// hit the same store. (#5 / auth-session-isolate.)
pub trait AuthSessionStore {
    /// Persist (upsert) a session, keyed by `server_nonce`.
    fn put_session(&self, session: AuthSession) -> std::result::Result<(), String>;
    /// Look up a session by `server_nonce`.
    fn get_session(&self, server_nonce: &str) -> std::result::Result<Option<AuthSession>, String>;
}

/// Process-global in-memory session store (per-isolate). Used by native unit
/// tests and any non-DO context. NOT durable across CF isolate churn — the
/// deployed worker uses the DO-SQLite store instead.
pub struct StaticSessionStore;

impl AuthSessionStore for StaticSessionStore {
    fn put_session(&self, session: AuthSession) -> std::result::Result<(), String> {
        store_session(session);
        Ok(())
    }
    fn get_session(&self, server_nonce: &str) -> std::result::Result<Option<AuthSession>, String> {
        Ok(get_session(server_nonce))
    }
}

/// Errors that can occur during BRC-31 authentication.
#[derive(Debug, Error)]
pub enum AuthError {
    /// Request has no BRC-104 auth headers — client must initiate handshake.
    #[error("Not authenticated: missing BRC-104 auth headers")]
    NotAuthenticated,

    /// BRC-104 headers present but the ECDSA signature is invalid.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// The auth session has expired (default: 1 hour).
    #[error("Session expired: established at {established}, now {now}")]
    SessionExpired { established: String, now: String },

    /// No session found for the provided your_nonce.
    #[error("Session not found for the provided nonce")]
    SessionNotFound,

    /// The authenticated identity does not match the agent_id in the request body.
    #[error("Identity mismatch: authenticated as {authenticated} but requesting for {requested}")]
    IdentityMismatch {
        authenticated: String,
        requested: String,
    },

    /// Internal error during signature verification or key derivation.
    #[error("Verification error: {0}")]
    VerificationError(String),
}

impl AuthError {
    /// Map auth error to HTTP status code.
    pub fn status_code(&self) -> u16 {
        match self {
            Self::NotAuthenticated => 401,
            Self::InvalidSignature(_) => 401,
            Self::SessionExpired { .. } => 401,
            Self::SessionNotFound => 401,
            Self::IdentityMismatch { .. } => 403,
            Self::VerificationError(_) => 500,
        }
    }
}

/// Handshake response body (JSON).
#[derive(Serialize, Deserialize)]
struct HandshakeResponse {}

// ── Session Storage ──────────────────────────────────────────────────────
//
// In-memory session storage, keyed by server_nonce.
// Production: migrate to Durable Object SQLite for persistence across restarts.

static AUTH_SESSIONS: LazyLock<Mutex<HashMap<String, AuthSession>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn store_session(session: AuthSession) {
    let key = session.server_nonce.clone();
    AUTH_SESSIONS
        .lock()
        .expect("session lock poisoned")
        .insert(key, session);
}

fn get_session(server_nonce: &str) -> Option<AuthSession> {
    AUTH_SESSIONS
        .lock()
        .expect("session lock poisoned")
        .get(server_nonce)
        .cloned()
}

/// Get the number of active sessions (for health/debugging).
pub fn session_count() -> usize {
    AUTH_SESSIONS.lock().expect("session lock poisoned").len()
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Generate a cryptographically random nonce (32 bytes, base64-encoded).
///
/// Uses `getrandom` which maps to crypto.getRandomValues() in WASM.
fn generate_nonce() -> std::result::Result<String, AuthError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| AuthError::VerificationError(format!("entropy error: {e}")))?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        bytes,
    ))
}

/// Get current time in milliseconds since Unix epoch.
fn current_time_ms() -> u64 {
    chrono::Utc::now().timestamp_millis() as u64
}

/// Extract a header value from a request, returning AuthError if missing.
fn get_header(req: &Request, name: &str) -> std::result::Result<String, AuthError> {
    req.headers()
        .get(name)
        .ok()
        .flatten()
        .ok_or(AuthError::NotAuthenticated)
}

/// Check whether a request has BRC-104 auth headers.
pub fn has_auth_headers(req: &Request) -> bool {
    req.headers()
        .get(headers::IDENTITY_KEY)
        .ok()
        .flatten()
        .is_some()
}

/// Build the BRC-42 invoice string for auth message signing.
///
/// Format: `"2-auth message signature-{key_id}"`. AUTH_PROTOCOL_NAME is a
/// hardcoded constant known to pass canonical `validate_protocol_name`;
/// any validation failure here is a programming bug (constant misedit), not
/// a runtime condition. `.expect` is correct.
fn auth_invoice(key_id: &str) -> String {
    compute_invoice(AUTH_SECURITY_LEVEL, AUTH_PROTOCOL_NAME, key_id)
        .expect("AUTH_PROTOCOL_NAME constant must pass canonical BRC-42 validation")
}

/// Compute the message hash for signing/verification.
///
/// For our simplified BRC-31 transport, the signing data is SHA-256(nonce).
/// Each request has a unique nonce, preventing replay attacks. The BRC-42
/// key derivation (which includes both session nonces in the key_id)
/// binds the signature to the authenticated session.
///
/// Production upgrade: include body hash in the signing data for tamper
/// detection, matching the full BRC-104 varint payload format.
fn compute_signing_hash(nonce: &str) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(nonce.as_bytes()).into()
}

/// Build an error Response from an AuthError.
fn auth_error_response(err: &AuthError) -> Response {
    let body = serde_json::json!({
        "status": "error",
        "code": format!("{:?}", err).split('(').next().unwrap_or("AuthError"),
        "description": err.to_string(),
    });
    Response::from_json(&body)
        .unwrap_or_else(|_| Response::error(err.to_string(), 500).unwrap())
        .with_status(err.status_code())
}

// ── Core Auth Functions ──────────────────────────────────────────────────

/// Verify authentication or allow through in development mode.
///
/// Call this from each protected endpoint's router closure. Returns:
/// - `Ok(identity)` if authenticated or development mode
/// - `Err(Response)` with appropriate HTTP status if auth fails
///
/// The error is a `Response` (not `worker::Error`) so the caller can
/// return it directly with the correct HTTP status code (401/403/500).
pub fn verify_or_allow(
    req: &Request,
    config: &AuthConfig,
    store: &dyn AuthSessionStore,
) -> std::result::Result<AuthenticatedIdentity, Response> {
    if !has_auth_headers(req) {
        if config.allow_unauthenticated {
            return Ok(AuthenticatedIdentity::unauthenticated());
        }
        let err = AuthError::NotAuthenticated;
        return Err(auth_error_response(&err));
    }

    verify_request(req, config, store).map_err(|e| auth_error_response(&e))
}

/// Verify BRC-31 Authrite authentication on an incoming request.
///
/// 1. Extract BRC-104 auth headers
/// 2. Look up session by `your_nonce` (server's session nonce)
/// 3. Check session TTL
/// 4. Verify identity matches session
/// 5. Derive BRC-42 verification public key via ECDH
/// 6. Verify ECDSA signature over signing data
///
/// Ported from bsv-auth-cloudflare `verify_message_signature()`.
pub fn verify_request(
    req: &Request,
    config: &AuthConfig,
    store: &dyn AuthSessionStore,
) -> std::result::Result<AuthenticatedIdentity, AuthError> {
    // 1. Extract BRC-104 auth headers
    let peer_identity_key = get_header(req, headers::IDENTITY_KEY)?;
    let signature_hex = get_header(req, headers::SIGNATURE)?;
    let nonce = get_header(req, headers::NONCE)?;
    let your_nonce = get_header(req, headers::YOUR_NONCE)?;

    // 2. Look up session by your_nonce (which is our server_nonce)
    let session = store
        .get_session(&your_nonce)
        .map_err(AuthError::VerificationError)?
        .ok_or(AuthError::SessionNotFound)?;

    // 3. Check session TTL
    let now = current_time_ms();
    if now - session.created_at > config.session_ttl_ms {
        return Err(AuthError::SessionExpired {
            established: session.created_at.to_string(),
            now: now.to_string(),
        });
    }

    // 4. Verify identity matches session
    if session.peer_identity_key != peer_identity_key {
        return Err(AuthError::IdentityMismatch {
            authenticated: session.peer_identity_key,
            requested: peer_identity_key,
        });
    }

    // 5. Derive verification public key via BRC-42
    let server_key = config.server_private_key()?;
    let peer_pub = PublicKey::from_hex(&peer_identity_key)
        .map_err(|e| AuthError::VerificationError(format!("invalid peer pubkey: {e}")))?;

    // ECDH shared secret: server_priv * client_pub
    // This equals client_priv * server_pub (ECDH commutativity, proven in POC 8 Step 9)
    let shared_secret = server_key
        .derive_shared_secret(&peer_pub)
        .map_err(|e| AuthError::VerificationError(format!("ECDH failed: {e}")))?;

    // BRC-42 key_id: "{message_nonce} {server_session_nonce}"
    // The client used this same key_id when signing.
    let key_id = format!("{} {}", nonce, session.server_nonce);
    let invoice = auth_invoice(&key_id);

    // Derive peer's auth verification key:
    //   verify_pub = peer_pub + G * HMAC(shared_secret, invoice)
    // This matches the client's signing key because:
    //   signing_key = peer_priv + HMAC(same_shared_secret, same_invoice)
    //   G * signing_key = peer_pub + G * HMAC = verify_pub  ✓
    let verify_pub = derive_child_pubkey(&peer_pub, &shared_secret, &invoice)
        .map_err(|e| AuthError::VerificationError(format!("BRC-42 derivation failed: {e}")))?;

    // 6. Verify ECDSA signature
    let msg_hash = compute_signing_hash(&nonce);

    let sig_bytes = hex::decode(&signature_hex)
        .map_err(|e| AuthError::InvalidSignature(format!("invalid hex: {e}")))?;
    let signature = Signature::from_der(&sig_bytes)
        .map_err(|e| AuthError::InvalidSignature(format!("invalid DER: {e}")))?;

    if !verify_pub.verify(&msg_hash, &signature) {
        return Err(AuthError::InvalidSignature(
            "ECDSA verification failed against BRC-42 derived key".into(),
        ));
    }

    Ok(AuthenticatedIdentity {
        identity_key: peer_identity_key,
        nonce,
        established_at: session.created_at.to_string(),
    })
}

/// Handle the BRC-31 Authrite handshake (POST `/.well-known/auth`).
///
/// Ported from bsv-auth-cloudflare `handle_initial_request()`.
///
/// 1. Extract peer identity and nonce from BRC-104 headers
/// 2. Generate server nonce (32 random bytes, base64)
/// 3. Store session in memory
/// 4. Sign the InitialResponse with BRC-42 derived key
/// 5. Return response with BRC-104 headers
pub async fn handle_initial_request(
    req: Request,
    config: &AuthConfig,
    store: &dyn AuthSessionStore,
) -> std::result::Result<Response, worker::Error> {
    // Extract peer info from BRC-104 headers
    let peer_identity_key = req
        .headers()
        .get(headers::IDENTITY_KEY)?
        .ok_or_else(|| Error::from("missing x-bsv-auth-identity-key header"))?;

    let peer_nonce = req
        .headers()
        .get(headers::NONCE)?
        .ok_or_else(|| Error::from("missing x-bsv-auth-nonce header"))?;

    // Use initial-nonce if provided, fall back to nonce
    let initial_nonce = req
        .headers()
        .get(headers::INITIAL_NONCE)?
        .unwrap_or_else(|| peer_nonce.clone());

    // Generate server nonce
    let server_nonce = generate_nonce().map_err(|e| Error::from(e.to_string()))?;

    // Get server identity
    let server_key = config
        .server_private_key()
        .map_err(|e| Error::from(e.to_string()))?;
    let server_pubkey = server_key.public_key();
    let server_identity = server_pubkey.to_hex();

    // Store session (keyed by server_nonce for lookup during verify)
    let session = AuthSession {
        server_nonce: server_nonce.clone(),
        peer_identity_key: peer_identity_key.clone(),
        peer_nonce: initial_nonce.clone(),
        created_at: current_time_ms(),
    };
    store
        .put_session(session)
        .map_err(|e| Error::from(format!("persist auth session: {e}")))?;

    // Create response body
    let response_body = HandshakeResponse {};
    let response_body_bytes =
        serde_json::to_vec(&response_body).map_err(|e| Error::from(e.to_string()))?;

    // Sign the InitialResponse
    // BRC-42 key_id for InitialResponse: "{server_nonce} {peer_nonce}"
    let peer_pub = PublicKey::from_hex(&peer_identity_key)
        .map_err(|e| Error::from(format!("invalid peer pubkey: {e}")))?;

    let key_id = format!("{} {}", server_nonce, initial_nonce);
    let invoice = auth_invoice(&key_id);

    // Derive signing key: server_priv + HMAC(ECDH(peer_pub, server_priv), invoice)
    let signing_key = server_key
        .derive_child(&peer_pub, &invoice)
        .map_err(|e| Error::from(format!("key derivation failed: {e}")))?;

    // Sign SHA-256(response_body_bytes)
    let msg_hash: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(&response_body_bytes).into()
    };
    let signature = signing_key
        .sign(&msg_hash)
        .map_err(|e| Error::from(format!("signing failed: {e}")))?;
    let sig_hex = hex::encode(signature.to_der());

    // Build response with BRC-104 headers
    let mut resp = Response::from_json(&response_body)?;
    let h = resp.headers_mut();
    h.set(headers::VERSION, AUTH_VERSION)?;
    h.set(headers::IDENTITY_KEY, &server_identity)?;
    h.set(headers::MESSAGE_TYPE, "initialResponse")?;
    h.set(headers::NONCE, &server_nonce)?;
    h.set(headers::YOUR_NONCE, &initial_nonce)?;
    h.set(headers::SIGNATURE, &sig_hex)?;

    // CORS headers (needed if proxy runs in browser context)
    h.set("access-control-allow-origin", "*")?;
    h.set(
        "access-control-expose-headers",
        &[
            headers::VERSION,
            headers::IDENTITY_KEY,
            headers::NONCE,
            headers::YOUR_NONCE,
            headers::SIGNATURE,
            headers::MESSAGE_TYPE,
        ]
        .join(", "),
    )?;

    Ok(resp)
}

/// Generate BRC-104 auth headers for a signed response.
///
/// Signs the response body with a BRC-42 derived key and returns
/// header name/value pairs to add to the HTTP response.
///
/// Ported from bsv-auth-cloudflare `sign_json_response()`.
pub fn sign_response_headers(
    response_body: &[u8],
    request_nonce: &str,
    _server_nonce: &str,
    peer_identity_key: &str,
    peer_nonce: &str,
    config: &AuthConfig,
) -> std::result::Result<Vec<(String, String)>, AuthError> {
    let server_key = config.server_private_key()?;
    let server_identity = server_key.public_key().to_hex();

    let peer_pub = PublicKey::from_hex(peer_identity_key)
        .map_err(|e| AuthError::VerificationError(format!("invalid peer pubkey: {e}")))?;

    // Generate fresh response nonce
    let response_nonce = generate_nonce()?;

    // BRC-42 key_id for response: "{response_nonce} {peer_initial_nonce}"
    // This is different from the request key_id, preventing cross-use.
    let key_id = format!("{} {}", response_nonce, peer_nonce);
    let invoice = auth_invoice(&key_id);

    // Derive signing key
    let signing_key = server_key
        .derive_child(&peer_pub, &invoice)
        .map_err(|e| AuthError::VerificationError(format!("key derivation: {e}")))?;

    // Sign SHA-256(response_body)
    let msg_hash: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(response_body).into()
    };
    let signature = signing_key
        .sign(&msg_hash)
        .map_err(|e| AuthError::VerificationError(format!("signing: {e}")))?;
    let sig_hex = hex::encode(signature.to_der());

    Ok(vec![
        (headers::VERSION.to_string(), AUTH_VERSION.to_string()),
        (headers::IDENTITY_KEY.to_string(), server_identity),
        (headers::MESSAGE_TYPE.to_string(), "general".to_string()),
        (headers::NONCE.to_string(), response_nonce),
        (headers::YOUR_NONCE.to_string(), request_nonce.to_string()),
        (headers::SIGNATURE.to_string(), sig_hex),
    ])
}

/// Verify that the authenticated identity matches the agent_id in a request body.
///
/// This is a critical authorization check — it ensures that agent A cannot
/// perform DKG or signing operations on agent B's share.
///
/// In development mode (empty identity_key), all requests are allowed.
pub fn verify_agent_authorization(
    auth: &AuthenticatedIdentity,
    agent_id: &str,
) -> std::result::Result<(), AuthError> {
    // Development mode: allow all
    if auth.identity_key.is_empty() {
        return Ok(());
    }

    if auth.identity_key != agent_id {
        return Err(AuthError::IdentityMismatch {
            authenticated: auth.identity_key.clone(),
            requested: agent_id.to_string(),
        });
    }
    Ok(())
}

/// Handle CORS preflight (OPTIONS) requests.
///
/// Returns 204 with appropriate CORS headers allowing BRC-104 auth headers.
pub fn handle_cors_preflight() -> worker::Result<Response> {
    let mut resp = Response::empty()?.with_status(204);
    let h = resp.headers_mut();
    h.set("access-control-allow-origin", "*")?;
    h.set("access-control-allow-methods", "GET, POST, OPTIONS")?;
    h.set(
        "access-control-allow-headers",
        &[
            headers::VERSION,
            headers::IDENTITY_KEY,
            headers::NONCE,
            headers::INITIAL_NONCE,
            headers::YOUR_NONCE,
            headers::SIGNATURE,
            headers::MESSAGE_TYPE,
            "content-type",
        ]
        .join(", "),
    )?;
    h.set("access-control-max-age", "86400")?;
    Ok(resp)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Known test key (same as POC 3/POC 8 for consistency).
    fn test_server_key() -> PrivateKey {
        PrivateKey::from_bytes(&[
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0x00, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x13,
            0x57, 0x9b, 0xdf, 0x02,
        ])
        .expect("valid test server key")
    }

    fn test_client_key() -> PrivateKey {
        PrivateKey::from_bytes(&[
            0x0b, 0x1e, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1,
            0xe2, 0xf3, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf,
            0xd0, 0xe1, 0xf2, 0x03,
        ])
        .expect("valid test client key")
    }

    // ── BRC-42 Auth Key Derivation ──────────────────────────────────────

    #[test]
    fn test_auth_invoice_format() {
        let invoice = auth_invoice("nonce1 nonce2");
        assert_eq!(invoice, "2-auth message signature-nonce1 nonce2");
    }

    #[test]
    fn test_auth_key_derivation_matches_poc8() {
        // Replicate POC 8 Step 4: BRC-42 auth key derivation
        use bsv::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};

        let server_key = test_server_key();
        let client_key = test_client_key();
        let client_pub = client_key.public_key();
        let server_pub = server_key.public_key();

        let nonce = "test-nonce-abc";
        let server_nonce = "server-nonce-xyz";
        let key_id = format!("{} {}", nonce, server_nonce);
        let invoice = auth_invoice(&key_id);

        // Method 1: PrivateKey::derive_child (what our auth code uses for signing)
        let derived_priv = client_key.derive_child(&server_pub, &invoice).unwrap();
        let derived_pub_from_priv = derived_priv.public_key();

        // Method 2: derive_child_pubkey (what our auth code uses for verification)
        let shared_secret = server_key.derive_shared_secret(&client_pub).unwrap();
        let derived_pub_from_verify =
            derive_child_pubkey(&client_pub, &shared_secret, &invoice).unwrap();

        // Both must produce the same public key (ECDH commutativity)
        assert_eq!(
            derived_pub_from_priv.to_compressed(),
            derived_pub_from_verify.to_compressed(),
            "derive_child and derive_child_pubkey must produce matching keys"
        );

        // Method 3: BSV SDK KeyDeriver (cross-check against standard implementation)
        let deriver = KeyDeriver::new(Some(client_key));
        let protocol = Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_NAME);
        let sdk_derived = deriver
            .derive_public_key(&protocol, &key_id, &Counterparty::Other(server_pub), true)
            .expect("SDK derivation");

        assert_eq!(
            derived_pub_from_priv.to_compressed(),
            sdk_derived.to_compressed(),
            "derived key must match BSV SDK KeyDeriver"
        );
    }

    #[test]
    fn test_ecdh_commutativity_for_auth() {
        // POC 8 Step 9: ECDH(client_pub, server_priv) = ECDH(server_pub, client_priv)
        let server_key = test_server_key();
        let client_key = test_client_key();

        let ss_from_server = server_key
            .derive_shared_secret(&client_key.public_key())
            .unwrap();
        let ss_from_client = client_key
            .derive_shared_secret(&server_key.public_key())
            .unwrap();

        assert_eq!(
            ss_from_server.to_compressed(),
            ss_from_client.to_compressed(),
            "ECDH must be commutative"
        );
    }

    // ── Signature Round-Trip ────────────────────────────────────────────

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let server_key = test_server_key();
        let client_key = test_client_key();
        let server_pub = server_key.public_key();
        let client_pub = client_key.public_key();

        let nonce = "fresh-request-nonce-12345";
        let server_nonce = "session-server-nonce-67890";

        // Client signs
        let key_id = format!("{} {}", nonce, server_nonce);
        let invoice = auth_invoice(&key_id);
        let signing_key = client_key.derive_child(&server_pub, &invoice).unwrap();
        let msg_hash = compute_signing_hash(nonce);
        let signature = signing_key.sign(&msg_hash).unwrap();
        let sig_hex = hex::encode(signature.to_der());

        // Server verifies
        let shared_secret = server_key.derive_shared_secret(&client_pub).unwrap();
        let verify_pub = derive_child_pubkey(&client_pub, &shared_secret, &invoice).unwrap();
        let sig_bytes = hex::decode(&sig_hex).unwrap();
        let sig = Signature::from_der(&sig_bytes).unwrap();
        assert!(
            verify_pub.verify(&msg_hash, &sig),
            "server must verify client's BRC-31 signature"
        );
    }

    #[test]
    fn test_wrong_nonce_fails_verification() {
        let server_key = test_server_key();
        let client_key = test_client_key();
        let server_pub = server_key.public_key();
        let client_pub = client_key.public_key();

        let nonce = "correct-nonce";
        let server_nonce = "server-nonce";

        // Client signs with correct nonce
        let key_id = format!("{} {}", nonce, server_nonce);
        let invoice = auth_invoice(&key_id);
        let signing_key = client_key.derive_child(&server_pub, &invoice).unwrap();
        let msg_hash = compute_signing_hash(nonce);
        let signature = signing_key.sign(&msg_hash).unwrap();

        // Server verifies with wrong nonce → different derived key → verification fails
        let wrong_nonce = "wrong-nonce";
        let wrong_key_id = format!("{} {}", wrong_nonce, server_nonce);
        let wrong_invoice = auth_invoice(&wrong_key_id);
        let shared_secret = server_key.derive_shared_secret(&client_pub).unwrap();
        let wrong_verify_pub =
            derive_child_pubkey(&client_pub, &shared_secret, &wrong_invoice).unwrap();

        assert!(
            !wrong_verify_pub.verify(&msg_hash, &signature),
            "wrong nonce must fail verification"
        );
    }

    #[test]
    fn test_wrong_server_key_fails_verification() {
        let server_key = test_server_key();
        let client_key = test_client_key();
        let server_pub = server_key.public_key();
        let client_pub = client_key.public_key();

        let nonce = "test-nonce";
        let server_nonce = "server-nonce";
        let key_id = format!("{} {}", nonce, server_nonce);
        let invoice = auth_invoice(&key_id);

        // Client signs
        let signing_key = client_key.derive_child(&server_pub, &invoice).unwrap();
        let msg_hash = compute_signing_hash(nonce);
        let signature = signing_key.sign(&msg_hash).unwrap();

        // Different server tries to verify → different ECDH shared secret → fails
        let wrong_server = PrivateKey::from_bytes(&[0x01; 32]).unwrap();
        let wrong_shared_secret = wrong_server.derive_shared_secret(&client_pub).unwrap();
        let wrong_verify_pub =
            derive_child_pubkey(&client_pub, &wrong_shared_secret, &invoice).unwrap();

        assert!(
            !wrong_verify_pub.verify(&msg_hash, &signature),
            "wrong server key must fail verification"
        );
    }

    // ── Session Storage ─────────────────────────────────────────────────

    #[test]
    fn test_session_store_and_retrieve() {
        let session = AuthSession {
            server_nonce: "test-session-nonce-unique".into(),
            peer_identity_key: "02abcdef".into(),
            peer_nonce: "peer-nonce-123".into(),
            created_at: 1000,
        };
        store_session(session);

        let retrieved = get_session("test-session-nonce-unique");
        assert!(retrieved.is_some());
        let s = retrieved.unwrap();
        assert_eq!(s.peer_identity_key, "02abcdef");
        assert_eq!(s.peer_nonce, "peer-nonce-123");
        assert_eq!(s.created_at, 1000);
    }

    #[test]
    fn test_session_not_found() {
        let retrieved = get_session("nonexistent-nonce");
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_static_session_store_trait_round_trip() {
        // The AuthSessionStore trait (the abstraction the durable DO-SQLite
        // store also implements) round-trips a session via the static backend.
        let store = StaticSessionStore;
        store
            .put_session(AuthSession {
                server_nonce: "trait-store-nonce".into(),
                peer_identity_key: "02feedface".into(),
                peer_nonce: "peer-9".into(),
                created_at: 4242,
            })
            .unwrap();
        let got = store.get_session("trait-store-nonce").unwrap().unwrap();
        assert_eq!(got.peer_identity_key, "02feedface");
        assert_eq!(got.created_at, 4242);
        assert!(store.get_session("missing").unwrap().is_none());
    }

    // ── Nonce Generation ────────────────────────────────────────────────

    #[test]
    fn test_nonce_generation() {
        let n1 = generate_nonce().unwrap();
        let n2 = generate_nonce().unwrap();
        assert_ne!(n1, n2, "nonces must be unique");

        // Base64-encoded 32 bytes = 44 chars (with padding)
        assert_eq!(n1.len(), 44, "base64 of 32 bytes should be 44 chars");
    }

    // ── Auth Error Status Codes ─────────────────────────────────────────

    #[test]
    fn test_auth_error_status_codes() {
        assert_eq!(AuthError::NotAuthenticated.status_code(), 401);
        assert_eq!(AuthError::InvalidSignature("bad".into()).status_code(), 401);
        assert_eq!(AuthError::SessionNotFound.status_code(), 401);
        assert_eq!(
            AuthError::SessionExpired {
                established: "1".into(),
                now: "2".into()
            }
            .status_code(),
            401
        );
        assert_eq!(
            AuthError::IdentityMismatch {
                authenticated: "a".into(),
                requested: "b".into()
            }
            .status_code(),
            403
        );
        assert_eq!(AuthError::VerificationError("x".into()).status_code(), 500);
    }

    // ── Agent Authorization ─────────────────────────────────────────────

    #[test]
    fn test_verify_agent_authorization_matching() {
        let auth = AuthenticatedIdentity {
            identity_key: "02abcdef1234".into(),
            nonce: "n".into(),
            established_at: "0".into(),
        };
        assert!(verify_agent_authorization(&auth, "02abcdef1234").is_ok());
    }

    #[test]
    fn test_verify_agent_authorization_mismatch() {
        let auth = AuthenticatedIdentity {
            identity_key: "02abcdef1234".into(),
            nonce: "n".into(),
            established_at: "0".into(),
        };
        assert!(verify_agent_authorization(&auth, "02different").is_err());
    }

    #[test]
    fn test_verify_agent_authorization_dev_mode() {
        // Development mode: empty identity_key allows all
        let auth = AuthenticatedIdentity::unauthenticated();
        assert!(verify_agent_authorization(&auth, "any-agent-id").is_ok());
    }

    // ── Header Constants ────────────────────────────────────────────────

    #[test]
    fn test_header_constants_match_brc104() {
        // These must match the production middleware for interoperability
        assert_eq!(headers::IDENTITY_KEY, "x-bsv-auth-identity-key");
        assert_eq!(headers::SIGNATURE, "x-bsv-auth-signature");
        assert_eq!(headers::NONCE, "x-bsv-auth-nonce");
        assert_eq!(headers::YOUR_NONCE, "x-bsv-auth-your-nonce");
        assert_eq!(headers::VERSION, "x-bsv-auth-version");
        assert_eq!(headers::MESSAGE_TYPE, "x-bsv-auth-message-type");
        assert_eq!(headers::INITIAL_NONCE, "x-bsv-auth-initial-nonce");
    }

    // ── DER Signature Encoding ──────────────────────────────────────────

    #[test]
    fn test_der_signature_roundtrip() {
        // POC 8 Step 11: DER encoding for BRC-31 wire format
        let key = test_client_key();
        let msg_hash = compute_signing_hash("test-nonce");
        let sig = key.sign(&msg_hash).unwrap();

        let der = sig.to_der();
        let hex_str = hex::encode(&der);

        // DER roundtrip
        let recovered = Signature::from_der(&hex::decode(&hex_str).unwrap()).unwrap();
        assert!(
            key.public_key().verify(&msg_hash, &recovered),
            "DER roundtrip must preserve signature validity"
        );
    }
}
