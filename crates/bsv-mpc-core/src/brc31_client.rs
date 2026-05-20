//! Transport-agnostic BRC-31 (Authrite / BRC-104) **client** for talking to a
//! bsv-mpc KSS (the `bsv-mpc-worker` DO or `bsv-mpc-service`).
//!
//! This is the client counterpart to `bsv-mpc-worker/src/auth.rs` (the server).
//! It is deliberately **transport-free** — it only computes the BRC-104 header
//! sets and tracks session nonces — so it is `wasm32`-safe (no `reqwest`) and
//! reusable by every native consumer: the proxy (`bridge.rs`, talking to the DO
//! for signing) and the native cosigner/container (`bsv-mpc-service`, talking to
//! the DO to provision presignatures via `/ceremony/ingest-presig`). The caller
//! owns the HTTP round-trip.
//!
//! Handshake:
//! 1. [`Brc31Client::initial_request_headers`] → POST to `/.well-known/auth`.
//! 2. read the server's `x-bsv-auth-identity-key` + `x-bsv-auth-nonce` response
//!    headers → [`Brc31Client::complete_handshake`].
//! 3. [`Brc31Client::request_headers`] on every authed request thereafter.
//!
//! The signing math (BRC-42 derived key over `SHA-256(nonce)`) is byte-identical
//! to the proxy's original in-`bridge.rs` implementation, so existing deployed
//! sessions are unaffected.

use bsv::primitives::ec::{PrivateKey, PublicKey};

use crate::error::{MpcError, Result};
use crate::hd::compute_invoice;

/// BRC-104 header names (must match `bsv-mpc-worker/src/auth.rs`).
pub mod headers {
    pub const VERSION: &str = "x-bsv-auth-version";
    pub const IDENTITY_KEY: &str = "x-bsv-auth-identity-key";
    pub const NONCE: &str = "x-bsv-auth-nonce";
    pub const INITIAL_NONCE: &str = "x-bsv-auth-initial-nonce";
    pub const YOUR_NONCE: &str = "x-bsv-auth-your-nonce";
    pub const SIGNATURE: &str = "x-bsv-auth-signature";
    pub const MESSAGE_TYPE: &str = "x-bsv-auth-message-type";
}

/// Client-side BRC-31 session state.
pub struct Brc31Client {
    /// This client's long-lived auth identity key.
    auth_key: PrivateKey,
    /// Server identity key (compressed hex), learned during the handshake.
    server_identity_key: Option<String>,
    /// Our session nonce (sent in the initial handshake).
    our_nonce: Option<String>,
    /// Server session nonce (received in the handshake response).
    server_session_nonce: Option<String>,
}

impl Brc31Client {
    /// Create a client with the given long-lived identity key.
    pub fn new(auth_key: PrivateKey) -> Self {
        Self {
            auth_key,
            server_identity_key: None,
            our_nonce: None,
            server_session_nonce: None,
        }
    }

    /// Whether the handshake has completed (a session is established).
    pub fn is_authenticated(&self) -> bool {
        self.server_session_nonce.is_some()
    }

    /// Our identity key as compressed hex (the BRC-104 identity).
    pub fn identity_hex(&self) -> String {
        self.auth_key.public_key().to_hex()
    }

    /// The long-lived auth identity private key. §07.4: this same key signs
    /// BRC-31 auth and the §05 relay envelope outer-signatures, so the relay
    /// transport reuses it.
    pub fn auth_key(&self) -> &PrivateKey {
        &self.auth_key
    }

    /// Generate a fresh 32-byte nonce, base64-encoded (matches the server).
    fn generate_nonce() -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
    }

    /// Headers for the BRC-31 InitialRequest (the `/.well-known/auth` POST).
    /// Records our nonce so the follow-up [`complete_handshake`] is consistent.
    pub fn initial_request_headers(&mut self) -> Vec<(&'static str, String)> {
        let our_nonce = Self::generate_nonce();
        let identity = self.identity_hex();
        self.our_nonce = Some(our_nonce.clone());
        vec![
            (headers::VERSION, "0.1".to_string()),
            (headers::IDENTITY_KEY, identity),
            (headers::MESSAGE_TYPE, "initialRequest".to_string()),
            (headers::NONCE, our_nonce.clone()),
            (headers::INITIAL_NONCE, our_nonce),
        ]
    }

    /// Record the server's identity + session nonce from the InitialResponse.
    pub fn complete_handshake(&mut self, server_identity: String, server_nonce: String) {
        self.server_identity_key = Some(server_identity);
        self.server_session_nonce = Some(server_nonce);
    }

    /// Compute the BRC-104 headers for an authenticated `general` request.
    ///
    /// Generates a fresh per-request nonce, derives the BRC-42 signing key
    /// (`protocolID [2,"auth message signature"]`, keyID `"{nonce} {serverNonce}"`,
    /// counterparty = server identity), and signs `SHA-256(nonce)` — exactly
    /// what the server's `compute_signing_hash` verifies.
    pub fn request_headers(&self) -> Result<Vec<(&'static str, String)>> {
        let server_session_nonce = self
            .server_session_nonce
            .as_ref()
            .ok_or_else(|| MpcError::Protocol("BRC-31: not authenticated (no session)".into()))?;
        let server_identity = self.server_identity_key.as_ref().ok_or_else(|| {
            MpcError::Protocol("BRC-31: not authenticated (no server identity)".into())
        })?;

        let request_nonce = Self::generate_nonce();

        let server_pub = PublicKey::from_hex(server_identity)
            .map_err(|e| MpcError::Protocol(format!("invalid server pubkey: {e}")))?;
        let key_id = format!("{request_nonce} {server_session_nonce}");
        let invoice = compute_invoice(2, "auth message signature", &key_id)?;
        let signing_key = self
            .auth_key
            .derive_child(&server_pub, &invoice)
            .map_err(|e| MpcError::Protocol(format!("BRC-42 key derivation: {e}")))?;

        let msg_hash: [u8; 32] = {
            use sha2::Digest;
            sha2::Sha256::digest(request_nonce.as_bytes()).into()
        };
        let signature = signing_key
            .sign(&msg_hash)
            .map_err(|e| MpcError::Protocol(format!("ECDSA signing: {e}")))?;
        let sig_hex = hex::encode(signature.to_der());

        Ok(vec![
            (headers::VERSION, "0.1".to_string()),
            (headers::IDENTITY_KEY, self.identity_hex()),
            (headers::MESSAGE_TYPE, "general".to_string()),
            (headers::NONCE, request_nonce),
            (headers::YOUR_NONCE, server_session_nonce.clone()),
            (headers::SIGNATURE, sig_hex),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> PrivateKey {
        PrivateKey::from_bytes(&[byte | 1; 32]).expect("valid key")
    }

    #[test]
    fn not_authenticated_until_handshake_completes() {
        let mut c = Brc31Client::new(key(2));
        assert!(!c.is_authenticated());
        assert!(c.request_headers().is_err());
        let _ = c.initial_request_headers();
        assert!(
            !c.is_authenticated(),
            "initial request alone is not a session"
        );
        c.complete_handshake(key(9).public_key().to_hex(), "server-nonce".into());
        assert!(c.is_authenticated());
        assert!(c.request_headers().is_ok());
    }

    #[test]
    fn request_headers_carry_identity_and_fresh_nonces() {
        let mut c = Brc31Client::new(key(3));
        c.complete_handshake(key(9).public_key().to_hex(), "srv".into());
        let h1: std::collections::HashMap<_, _> =
            c.request_headers().unwrap().into_iter().collect();
        assert_eq!(h1[headers::IDENTITY_KEY], c.identity_hex());
        assert_eq!(h1[headers::MESSAGE_TYPE], "general");
        assert_eq!(h1[headers::YOUR_NONCE], "srv");
        // Fresh nonce per request.
        let h2: std::collections::HashMap<_, _> =
            c.request_headers().unwrap().into_iter().collect();
        assert_ne!(h1[headers::NONCE], h2[headers::NONCE]);
    }
}
