//! Canonical BRC-31 (Authrite / BRC-104) **client** for talking to a bsv-mpc
//! KSS (the native `bsv-mpc-service`).
//!
//! This is the client counterpart to the canonical `bsv-middleware-rs` server
//! verifier. It signs a General request EXACTLY as `bsv_rs::auth::Peer` does
//! (proven by `tests/conformance_07_brc31_auth.rs`):
//!
//! - build the BRC-104 binary payload over method/path/search=""/signable
//!   headers/body via `bsv_middleware_rs::transport::build_request_payload` +
//!   `filter_signable_headers` (so client and server agree byte-for-byte);
//! - construct an [`AuthMessage`] of type `General` carrying a fresh per-request
//!   `nonce`, the server's session nonce as `your_nonce`, and that payload;
//! - sign with `key_id = msg.get_key_id(Some(server_session_nonce))` over
//!   `msg.signing_data()`, `protocolID [2, "auth message signature"]`,
//!   `counterparty = Other(server_identity)`.
//!
//! The caller owns the HTTP round-trip. It MUST send the EXACT body bytes that
//! were signed (via `.body(body_bytes)`, NOT `.json()`), include the
//! `content-type: application/json` header, and attach the returned
//! `x-bsv-auth-*` headers.
//!
//! Handshake:
//! 1. POST [`Brc31Client::initial_request_body`] (with
//!    [`Brc31Client::initial_request_headers`]) to `/.well-known/auth`.
//! 2. read the server's `x-bsv-auth-identity-key` + `x-bsv-auth-nonce` response
//!    headers → [`Brc31Client::complete_handshake`].
//! 3. [`Brc31Client::request_headers`] on every authed request thereafter.

use base64::Engine;
use bsv::auth::{AuthMessage, MessageType, AUTH_PROTOCOL_ID, AUTH_VERSION};
use bsv::primitives::ec::PrivateKey;
use bsv::wallet::{Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel};
use bsv::PublicKey;
use bsv_middleware_rs::transport::{build_request_payload, filter_signable_headers};

use crate::error::{MpcError, Result};

/// BRC-104 header names (canonical `x-bsv-auth-*`).
pub mod headers {
    pub const VERSION: &str = "x-bsv-auth-version";
    pub const IDENTITY_KEY: &str = "x-bsv-auth-identity-key";
    pub const NONCE: &str = "x-bsv-auth-nonce";
    pub const INITIAL_NONCE: &str = "x-bsv-auth-initial-nonce";
    pub const YOUR_NONCE: &str = "x-bsv-auth-your-nonce";
    pub const SIGNATURE: &str = "x-bsv-auth-signature";
    pub const MESSAGE_TYPE: &str = "x-bsv-auth-message-type";
    pub const REQUEST_ID: &str = "x-bsv-auth-request-id";
}

/// The `content-type` header value the proxy/client always sends with its JSON
/// request bodies. It MUST be a signable header (per `filter_signable_headers`)
/// so the client signs and the server verifies over the SAME header set.
const JSON_CONTENT_TYPE: &str = "application/json";

/// Client-side BRC-31 session state.
pub struct Brc31Client {
    /// This client's long-lived auth identity wallet.
    wallet: ProtoWallet,
    /// This client's auth identity private key (retained for §07.4 relay reuse).
    auth_key: PrivateKey,
    /// Server identity key, learned during the handshake.
    server_identity_key: Option<PublicKey>,
    /// Our session nonce (sent in the initial handshake).
    our_nonce: Option<String>,
    /// Server session nonce (received in the handshake response).
    server_session_nonce: Option<String>,
}

impl Brc31Client {
    /// Create a client with the given long-lived identity key.
    pub fn new(auth_key: PrivateKey) -> Self {
        Self {
            wallet: ProtoWallet::new(Some(auth_key.clone())),
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
        self.wallet.identity_key().to_hex()
    }

    /// The long-lived auth identity private key. §07.4: this same key signs
    /// BRC-31 auth and the §05 relay envelope outer-signatures, so the relay
    /// transport reuses it.
    pub fn auth_key(&self) -> &PrivateKey {
        &self.auth_key
    }

    /// Generate a fresh 32 random bytes via the OS CSPRNG.
    fn random_32() -> [u8; 32] {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        bytes
    }

    /// Generate a fresh 32-byte nonce, base64-encoded. BRC-31 key derivation
    /// decodes nonce tokens, so nonces MUST be real base64 of 32 bytes.
    fn generate_nonce() -> String {
        base64::engine::general_purpose::STANDARD.encode(Self::random_32())
    }

    /// The canonical InitialRequest body bytes (an `AuthMessage` of type
    /// `InitialRequest`). Records our nonce so the follow-up
    /// [`complete_handshake`] is consistent. The caller POSTs these bytes to
    /// `/.well-known/auth` (with [`initial_request_headers`]).
    pub fn initial_request_body(&mut self) -> Result<Vec<u8>> {
        let our_nonce = Self::generate_nonce();
        self.our_nonce = Some(our_nonce.clone());
        let mut msg = AuthMessage::new(MessageType::InitialRequest, self.wallet.identity_key());
        msg.nonce = Some(our_nonce.clone());
        msg.initial_nonce = Some(our_nonce);
        serde_json::to_vec(&msg)
            .map_err(|e| MpcError::Serialization(format!("BRC-31 InitialRequest serialize: {e}")))
    }

    /// Headers for the BRC-31 InitialRequest POST (the `/.well-known/auth`
    /// handshake). These accompany [`initial_request_body`].
    pub fn initial_request_headers(&self) -> Vec<(&'static str, String)> {
        vec![
            (headers::VERSION, AUTH_VERSION.to_string()),
            (headers::IDENTITY_KEY, self.identity_hex()),
            (headers::MESSAGE_TYPE, "initialRequest".to_string()),
            ("content-type", JSON_CONTENT_TYPE.to_string()),
        ]
    }

    /// Record the server's identity + session nonce from the InitialResponse.
    pub fn complete_handshake(&mut self, server_identity: String, server_nonce: String) -> bool {
        match PublicKey::from_hex(&server_identity) {
            Ok(pk) => {
                self.server_identity_key = Some(pk);
                self.server_session_nonce = Some(server_nonce);
                true
            }
            Err(_) => false,
        }
    }

    /// Compute the canonical BRC-104 headers for an authenticated `general`
    /// request over `(method, path, body)`.
    ///
    /// The signed payload is built over `search=""` and the single signable
    /// header `content-type: application/json` — exactly what the server
    /// reconstructs from the request it receives. The caller MUST send the EXACT
    /// `body` bytes (via `.body(body)`, NOT `.json()`), the `content-type:
    /// application/json` header, and the returned `x-bsv-auth-*` headers.
    pub fn request_headers(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<Vec<(&'static str, String)>> {
        let server_session_nonce = self
            .server_session_nonce
            .as_ref()
            .ok_or_else(|| MpcError::Protocol("BRC-31: not authenticated (no session)".into()))?;
        let server_identity = self.server_identity_key.as_ref().ok_or_else(|| {
            MpcError::Protocol("BRC-31: not authenticated (no server identity)".into())
        })?;

        // Fresh 32-byte request id (base64) — correlates request/response and is
        // part of the signed BRC-104 payload.
        let request_id = Self::random_32();

        // The signable headers the server will reconstruct from the wire: just
        // the content-type (auth headers are excluded by filter_signable_headers).
        let signable =
            filter_signable_headers(&[("content-type".to_string(), JSON_CONTENT_TYPE.to_string())]);
        let payload = build_request_payload(&request_id, method, path, "", &signable, body);

        let request_nonce = Self::generate_nonce();
        let mut msg = AuthMessage::new(MessageType::General, self.wallet.identity_key());
        msg.nonce = Some(request_nonce.clone());
        msg.your_nonce = Some(server_session_nonce.clone());
        msg.payload = Some(payload);

        let key_id = msg.get_key_id(Some(server_session_nonce));
        let data = msg.signing_data();
        let sig = self
            .wallet
            .create_signature(CreateSignatureArgs {
                data: Some(data),
                hash_to_directly_sign: None,
                protocol_id: Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID),
                key_id,
                counterparty: Some(Counterparty::Other(server_identity.clone())),
            })
            .map_err(|e| MpcError::Protocol(format!("BRC-31 create_signature: {e}")))?;
        let sig_bytes = sig.signature;

        Ok(vec![
            (headers::VERSION, AUTH_VERSION.to_string()),
            (headers::IDENTITY_KEY, self.identity_hex()),
            (headers::MESSAGE_TYPE, "general".to_string()),
            (headers::NONCE, request_nonce),
            (headers::YOUR_NONCE, server_session_nonce.clone()),
            (headers::SIGNATURE, hex::encode(sig_bytes)),
            (
                headers::REQUEST_ID,
                base64::engine::general_purpose::STANDARD.encode(request_id),
            ),
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
        assert!(c.request_headers("POST", "/sign/init", b"{}").is_err());
        let _ = c.initial_request_body().unwrap();
        assert!(
            !c.is_authenticated(),
            "initial request alone is not a session"
        );
        let server_nonce = base64::engine::general_purpose::STANDARD.encode([0xA1u8; 32]);
        assert!(c.complete_handshake(key(9).public_key().to_hex(), server_nonce));
        assert!(c.is_authenticated());
        assert!(c.request_headers("POST", "/sign/init", b"{}").is_ok());
    }

    #[test]
    fn request_headers_carry_identity_and_fresh_nonces() {
        let mut c = Brc31Client::new(key(3));
        let server_nonce = base64::engine::general_purpose::STANDARD.encode([0xB2u8; 32]);
        assert!(c.complete_handshake(key(9).public_key().to_hex(), server_nonce.clone()));
        let h1: std::collections::HashMap<_, _> = c
            .request_headers("POST", "/sign/init", b"{}")
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(h1[headers::IDENTITY_KEY], c.identity_hex());
        assert_eq!(h1[headers::MESSAGE_TYPE], "general");
        assert_eq!(h1[headers::YOUR_NONCE], server_nonce);
        assert!(h1.contains_key(headers::SIGNATURE));
        assert!(h1.contains_key(headers::REQUEST_ID));
        // Fresh nonce per request.
        let h2: std::collections::HashMap<_, _> = c
            .request_headers("POST", "/sign/init", b"{}")
            .unwrap()
            .into_iter()
            .collect();
        assert_ne!(h1[headers::NONCE], h2[headers::NONCE]);
    }
}
