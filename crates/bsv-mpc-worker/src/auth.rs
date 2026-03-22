//! BRC-31 Authrite authentication stubs for the CF Worker.
//!
//! TODO: Implement full BRC-31 mutual authentication. References:
//! - ~/bsv/BRCs/peer-to-peer/0031.md (BRC-31 Authrite spec)
//! - ~/bsv/rust-middleware (production BRC-31 middleware for CF Workers)
//! - ~/bsv/agents (11 working BRC-31 examples in Rust WASM)
//!
//! For now, all endpoints are open for development/testing.
//! The `verify_request()` stub allows all requests through, extracting
//! the identity key from the `x-authrite-identity-key` header if present.

// Auth module is fully implemented but not yet wired into handlers.
// Suppress dead_code warnings until BRC-31 auth is enabled in production.
#![allow(dead_code)]

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
    SessionExpired { established: String, now: String },

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
/// # Current Behavior (Stub)
///
/// Always returns `Ok`. Extracts the identity key from the
/// `x-authrite-identity-key` header if present, otherwise returns
/// an empty identity key. No signature verification is performed.
///
/// # Production Behavior (TODO)
///
/// 1. Extract `x-authrite-identity-key`, `x-authrite-signature`,
///    `x-authrite-nonce`, `x-authrite-yournonce` headers.
/// 2. Reconstruct the message: `SHA-256(nonce + method + path + body_hash)`.
/// 3. Verify ECDSA signature against the identity key.
/// 4. Check session TTL (1 hour).
/// 5. Return `AuthenticatedIdentity` on success, `AuthError` on failure.
pub fn verify_request(req: &Request) -> std::result::Result<AuthenticatedIdentity, AuthError> {
    // TODO: Implement full BRC-31 Authrite verification.
    // See ~/bsv/BRCs/peer-to-peer/0031.md and ~/bsv/rust-middleware
    let identity_key = req
        .headers()
        .get("x-authrite-identity-key")
        .ok()
        .flatten()
        .unwrap_or_default();

    Ok(AuthenticatedIdentity {
        identity_key,
        nonce: String::new(),
        established_at: String::new(),
    })
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
/// # Current Behavior (Stub)
///
/// Returns a mock server identity with a placeholder key and nonce.
/// No real key generation or session storage is performed.
///
/// # Production Behavior (TODO)
///
/// 1. Parse client's `identityKey` and `nonce` from request body.
/// 2. Generate server nonce (32 bytes, crypto random via `getrandom`).
/// 3. Store auth session: `(client_key, client_nonce, server_nonce, timestamp)`.
/// 4. Return JSON: `{ identityKey: server_key, nonce: server_nonce, certificates: [] }`.
pub async fn handle_authrite_handshake(mut req: Request) -> Result<Response> {
    // Parse the client's handshake request
    let body: serde_json::Value = req.json().await?;

    let _client_key = body
        .get("identityKey")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let _client_nonce = body
        .get("nonce")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // TODO: Generate real server identity key from CF Worker secrets.
    // TODO: Generate crypto-random nonce via getrandom.
    // TODO: Store auth session for subsequent request verification.
    let response = serde_json::json!({
        "identityKey": "000000000000000000000000000000000000000000000000000000000000000000",
        "nonce": "development-stub-nonce",
        "certificates": []
    });

    Response::from_json(&response)
}
