//! BRC-31 Authrite authentication middleware for the CF Worker.
//!
//! Every mutation endpoint (DKG, signing, presigning) requires BRC-31 mutual
//! authentication. This ensures that only the MPC Signing Proxy that owns a
//! particular key share can request DKG or signing operations for that share.
//!
//! ## BRC-31 Flow (simplified)
//!
//! ```text
//! Client (Proxy)                   Server (Worker)
//!     │                                │
//!     │── Initial request ─────────────►│
//!     │◄── 401 + server nonce ─────────│  AuthError::NotAuthenticated
//!     │                                │
//!     │── /.well-known/auth ───────────►│  Authrite handshake
//!     │   { identityKey, nonce }       │
//!     │◄── { identityKey, nonce } ─────│  Mutual key exchange
//!     │                                │
//!     │── Signed request ──────────────►│  verify_request() succeeds
//!     │   x-authrite-* headers         │
//!     │◄── Response ───────────────────│
//! ```
//!
//! ## Security Properties
//!
//! - **Mutual authentication**: Both parties prove possession of their identity keys.
//! - **Replay protection**: Each session has a unique nonce; requests include timestamps.
//! - **Agent binding**: The authenticated identity key is matched against the
//!   `agent_id` in request bodies, preventing one agent from operating on
//!   another agent's share.
//! - **Session TTL**: Auth sessions expire after 1 hour.

use thiserror::Error;
use worker::*;

/// A successfully authenticated identity from a BRC-31 Authrite session.
#[derive(Debug, Clone)]
pub struct AuthenticatedIdentity {
    /// The client's BRC-31 identity key (33-byte compressed secp256k1 pubkey, hex-encoded).
    pub identity_key: String,
    /// The session nonce (unique per auth session, prevents replay).
    pub nonce: String,
    /// When this auth session was established (UTC ISO-8601).
    pub established_at: String,
}

/// Errors that can occur during authentication.
#[derive(Debug, Error)]
pub enum AuthError {
    /// Request has no Authrite headers — client must initiate handshake.
    #[error("Not authenticated: missing x-authrite headers")]
    NotAuthenticated,

    /// Authrite headers present but the signature is invalid.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// The auth session has expired (>1 hour since establishment).
    #[error("Session expired: established at {established}, now {now}")]
    SessionExpired {
        established: String,
        now: String,
    },

    /// The authenticated identity does not match the agent_id in the request body.
    #[error("Identity mismatch: authenticated as {authenticated} but requesting for {requested}")]
    IdentityMismatch {
        authenticated: String,
        requested: String,
    },

    /// Internal error during signature verification.
    #[error("Verification error: {0}")]
    VerificationError(String),
}

/// Verify that an incoming request has valid BRC-31 Authrite authentication.
///
/// Checks the `x-authrite-identity-key`, `x-authrite-signature`, and
/// `x-authrite-nonce` headers. Verifies the ECDSA signature over the
/// request body using the client's identity key.
///
/// Returns the authenticated identity on success, or an `AuthError` on failure.
///
/// # Headers Expected
///
/// - `x-authrite-identity-key`: Client's 33-byte compressed pubkey (hex)
/// - `x-authrite-signature`: ECDSA signature over SHA-256(nonce + method + path + body)
/// - `x-authrite-nonce`: Session nonce from the handshake
/// - `x-authrite-yournonce`: Server's nonce (proves client received handshake response)
/// - `x-authrite-certificates`: Optional BRC-52 certificate chain (JSON)
pub fn verify_request(req: &Request) -> std::result::Result<AuthenticatedIdentity, AuthError> {
    todo!(
        "1. Extract x-authrite-identity-key header or return NotAuthenticated\n\
         2. Extract x-authrite-signature header or return NotAuthenticated\n\
         3. Extract x-authrite-nonce header or return NotAuthenticated\n\
         4. Reconstruct the message: SHA-256(nonce + method + path + body_hash)\n\
         5. Verify ECDSA signature against identity_key\n\
         6. Check session TTL (1 hour)\n\
         7. Return AuthenticatedIdentity { identity_key, nonce, established_at }"
    )
}

/// Verify that the authenticated identity matches the agent_id in a request body.
///
/// This is a critical authorization check — it ensures that agent A cannot
/// perform DKG or signing operations on agent B's share.
pub fn verify_agent_authorization(
    auth: &AuthenticatedIdentity,
    agent_id: &str,
) -> std::result::Result<(), AuthError> {
    if auth.identity_key != agent_id {
        return Err(AuthError::IdentityMismatch {
            authenticated: auth.identity_key.clone(),
            requested: agent_id.to_string(),
        });
    }
    Ok(())
}

/// Handle the `/.well-known/auth` Authrite handshake endpoint.
///
/// This is the initial key exchange where both parties share their identity
/// keys and nonces. After this handshake, subsequent requests can include
/// `x-authrite-*` headers for authenticated communication.
///
/// # Request Body
///
/// ```json
/// {
///   "identityKey": "02abc...",
///   "nonce": "random-hex-string"
/// }
/// ```
///
/// # Response Body
///
/// ```json
/// {
///   "identityKey": "03def...",
///   "nonce": "server-random-hex",
///   "certificates": []
/// }
/// ```
pub async fn handle_authrite_handshake(mut req: Request) -> Result<Response> {
    todo!(
        "1. Parse request body: {{ identityKey, nonce }}\n\
         2. Generate server nonce (32 bytes, crypto random)\n\
         3. Store session: (client_key, client_nonce, server_nonce, timestamp)\n\
         4. Return JSON: {{ identityKey: server_identity_key, nonce: server_nonce, certificates: [] }}"
    )
}
