//! `RelaySession` — the shared client-side BRC-31 session (§07.4), promoted out of
//! the proxy's `bridge::BridgeAuth` so the BRC-100 proxy AND the native client use
//! the EXACT same handshake + canonical request-signing (issue #63, path
//! a-extended). It owns the `reqwest` handshake round-trip; the header/body crypto
//! lives in [`bsv_mpc_core::brc31_client::Brc31Client`].
//!
//! One long-lived identity key, per-server sessions: the same key signs the
//! BRC-31 `/.well-known/auth` handshake, every authed `/dkg|/presign|/sign` POST,
//! and the §05 relay envelope outer-signatures (so the relay transport reuses it).

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::brc31_client::{self, Brc31Client};
use bsv_mpc_core::error::{MpcError, Result};

/// A BRC-31 client session against one server (KSS / cosigner / container).
///
/// Thin wrapper over [`Brc31Client`] adding the `reqwest` handshake round-trip and
/// owned `(name, value)` header pairs convenient for both a `reqwest` builder and
/// the relay trigger bodies. Caller-provided identity derivation (e.g. the proxy's
/// §07.4 share-derived identity) stays caller-side; this type only needs the key.
pub struct RelaySession {
    client: Brc31Client,
}

impl RelaySession {
    /// Build a session with an explicit long-lived identity key.
    pub fn new(auth_key: PrivateKey) -> Self {
        Self {
            client: Brc31Client::new(auth_key),
        }
    }

    /// Build a session from explicit 32-byte identity-key material. Used to honor
    /// an operator-provided stable identity and to construct a SECOND session
    /// (e.g. against a separate `presign_url`) with the SAME long-lived identity.
    pub fn from_key_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let auth_key = PrivateKey::from_bytes(bytes)
            .map_err(|e| MpcError::Protocol(format!("invalid auth key bytes: {e}")))?;
        Ok(Self::new(auth_key))
    }

    /// Whether the handshake has completed (a session is established).
    pub fn is_authenticated(&self) -> bool {
        self.client.is_authenticated()
    }

    /// The long-lived auth/relay identity key (§07.4 — one key for BRC-31 auth +
    /// the §05 relay envelope outer-signatures).
    pub fn auth_key(&self) -> &PrivateKey {
        self.client.auth_key()
    }

    /// Our identity key as compressed hex (the BRC-104 identity / owner id).
    pub fn identity_hex(&self) -> String {
        self.client.identity_hex()
    }

    /// Perform the canonical BRC-31 handshake with `base_url` (the `reqwest`
    /// round-trip; the header/body crypto is the core [`Brc31Client`]). Sends a
    /// canonical `AuthMessage` InitialRequest body and parses the InitialResponse
    /// identity + session nonce from the response headers.
    pub async fn handshake(&mut self, client: &reqwest::Client, base_url: &str) -> Result<()> {
        let handshake_url = format!("{base_url}/.well-known/auth");
        let init_body = self.client.initial_request_body()?;
        let mut req = client
            .post(&handshake_url)
            .header("content-type", "application/json")
            .body(init_body);
        for (name, value) in self.client.initial_request_headers() {
            req = req.header(name, value);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| MpcError::Protocol(format!("BRC-31 handshake failed: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(MpcError::Protocol(format!(
                "BRC-31 handshake returned {status}: {body}"
            )));
        }

        let header = |name: &str| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        };
        let server_identity = header(brc31_client::headers::IDENTITY_KEY).ok_or_else(|| {
            MpcError::Protocol("BRC-31: missing server identity in handshake response".into())
        })?;
        let server_nonce = header(brc31_client::headers::NONCE).ok_or_else(|| {
            MpcError::Protocol("BRC-31: missing server nonce in handshake response".into())
        })?;

        tracing::info!(server_identity = %server_identity, "BRC-31: handshake complete");
        if !self
            .client
            .complete_handshake(server_identity, server_nonce)
        {
            return Err(MpcError::Protocol(
                "BRC-31: handshake response carried an invalid server identity key".into(),
            ));
        }
        Ok(())
    }

    /// Canonical BRC-104 auth headers for a fresh request over `(method, path,
    /// body)` — owned `(name, value)` pairs (the core client's `&'static str`
    /// names are promoted to `String` so this matches the [`RelayRequestSigner`]
    /// closure shape used by every trigger).
    pub fn auth_header_pairs(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<Vec<(String, String)>> {
        Ok(self
            .client
            .request_headers(method, path, body)?
            .into_iter()
            .map(|(name, value)| (name.to_string(), value))
            .collect())
    }
}
