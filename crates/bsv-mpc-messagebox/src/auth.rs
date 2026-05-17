//! BRC-31 mutual auth for the MessageBox transport, wrapping
//! `bsv_rs::auth::Peer` with `SimplifiedFetchTransport` for HTTP routes
//! and a one-shot `/.well-known/auth` handshake for WebSocket upgrades.
//!
//! ## Why we use bsv-rs's Peer instead of porting `bridge.rs::BridgeAuth`
//!
//! Two distinct BRC-31 signing flavors exist in this stack:
//!
//! 1. **Simple per-request signing** (`bsv-mpc-proxy/src/bridge.rs`):
//!    `ECDSA(SHA-256(per_request_nonce))` with a BRC-42-derived child key.
//!    Server-side counterpart is `bsv-mpc-worker/src/auth.rs`. Works for
//!    the internal proxy↔KSS path only.
//!
//! 2. **BRC-104 SimplifiedFetchTransport** (any
//!    `bsv-middleware-cloudflare-public`-style server, including the live
//!    Calhoun MessageBox relay): the signature covers a serialized
//!    `(request_id, method, path, search, signable_headers, body)`
//!    payload per BRC-104. Verified by reading the server source at
//!    `~/bsv/bsv-middleware-cloudflare-public/src/transport/cloudflare.rs::
//!    extract_auth_message` + `build_request_payload`.
//!
//! Flavor 1 returns 500 against MessageBox. Flavor 2 is what bsv-rs's
//! `Peer + SimplifiedFetchTransport` implements; the canonical Rust
//! consumer is `~/bsv/bsv-wallet-toolbox-rs/src/storage/client/
//! storage_client.rs:280-510`. We wrap the same pattern here.
//!
//! ## Why a separate handshake for the WS upgrade
//!
//! `Peer` keeps its `SessionManager` private (`Arc<RwLock<…>>` with no
//! public accessor), so its established `(client_nonce, server_nonce,
//! server_identity_key)` triple isn't reachable for signing a foreign
//! payload. The canonical Rust precedent for this exact case lives in
//! `~/bsv/bsv-messagebox-cloudflare-public/tests/load_gen/src/{handshake,
//! connect,serialize}.rs` — it runs one `POST /.well-known/auth`
//! initialRequest/initialResponse exchange via reqwest and caches the
//! resulting `Session`, then signs the WS upgrade GET by hand. We port
//! that pattern as-is; one extra round-trip per (re)connect is cheaper
//! than fighting Peer's encapsulation.
//!
//! ## Surface
//!
//! Construct via [`MessageBoxAuth::new`] with a stable identity priv;
//! call [`MessageBoxAuth::peer`] to access the underlying `Peer` for
//! request dispatch (see `crate::http`). [`MessageBoxAuth::start`] kicks
//! off the transport callback once at startup (per bsv-rs Peer protocol).
//! Call [`MessageBoxAuth::sign_ws_upgrade`] when opening a WebSocket
//! (see `crate::ws`).

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bsv::auth::{Peer, PeerOptions, SimplifiedFetchTransport};
use bsv::primitives::ec::PrivateKey;
use bsv::wallet::{Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel};
use rand::RngCore;
use serde_json::{json, Value};
use tokio::sync::RwLock;

use crate::error::{MessageBoxError, Result};

/// `Peer` parameterized to the way `bsv_rs` expects: ProtoWallet identity
/// over the SimplifiedFetchTransport HTTP transport.
pub type MessageBoxPeer = Peer<ProtoWallet, SimplifiedFetchTransport>;

/// One BRC-31 session against the relay. Mirrors the load_gen `Session`
/// shape so the signing logic in [`brc104`] is a byte-for-byte port.
#[derive(Debug, Clone)]
struct Session {
    server_identity_key: String,
    server_nonce_b64: String,
    #[allow(dead_code)] // kept for diagnostics; the WS signer doesn't read it back
    client_nonce_b64: String,
}

/// One set of pre-signed BRC-31 headers ready to attach to a WS upgrade
/// `GET` request. The caller (`crate::ws`) adds the standard
/// `Connection`/`Upgrade`/`Sec-WebSocket-*` headers itself.
pub type SignedWsHeaders = Vec<(String, String)>;

/// BRC-31 client for one `(our_identity, relay_url)` pair. Wraps the
/// bsv-rs `Peer` lifecycle so the rest of this crate uses a stable
/// interface.
pub struct MessageBoxAuth {
    relay_url: String,
    peer: Arc<MessageBoxPeer>,
    wallet: ProtoWallet,
    /// Cached BRC-31 session for WS-upgrade signing. Lazily populated on
    /// the first call to [`MessageBoxAuth::sign_ws_upgrade`]; cleared by
    /// [`MessageBoxAuth::refresh_ws_session`] on reconnect after auth
    /// failure or after long idle.
    ws_session: Arc<RwLock<Option<Session>>>,
}

impl MessageBoxAuth {
    /// Construct an auth client for `relay_url`. The identity priv is
    /// stable across restarts — other cosigners route to this identity's
    /// public key per §06.7. `start` MUST be called once before any
    /// request dispatch.
    pub fn new(relay_url: impl Into<String>, our_priv: PrivateKey) -> Result<Self> {
        let relay_url = relay_url.into();
        let wallet = ProtoWallet::new(Some(our_priv));
        let transport = SimplifiedFetchTransport::new(&relay_url);
        let peer = Peer::new(PeerOptions {
            wallet: wallet.clone(),
            transport,
            certificates_to_request: None,
            session_manager: None,
            auto_persist_last_session: true,
            originator: Some("bsv-mpc-messagebox".to_string()),
        });
        Ok(Self {
            relay_url,
            peer: Arc::new(peer),
            wallet,
            ws_session: Arc::new(RwLock::new(None)),
        })
    }

    /// Initialize the transport callback. MUST be called once before any
    /// `to_peer` round-trip; see `bsv_rs::auth::Peer::start`.
    pub fn start(&self) {
        self.peer.start();
    }

    /// The underlying `Peer` — used by [`crate::http`] for request
    /// dispatch + response listener management.
    pub fn peer(&self) -> &Arc<MessageBoxPeer> {
        &self.peer
    }

    /// Our wallet (used by callers that need to read our identity pub).
    pub fn wallet(&self) -> &ProtoWallet {
        &self.wallet
    }

    /// Our identity pubkey as lowercase hex — what cosigners route to.
    pub async fn identity_hex(&self) -> Result<String> {
        let key =
            self.peer.get_identity_key().await.map_err(|e| {
                MessageBoxError::Auth(format!("Peer.get_identity_key failed: {e:?}"))
            })?;
        Ok(key.to_hex())
    }

    /// The relay base URL this client is bound to.
    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    /// Drop the cached WS session so the next [`sign_ws_upgrade`] call
    /// re-runs the `/.well-known/auth` handshake. Use on reconnect after
    /// an auth-fail close or a long idle gap (relay sessions may rotate).
    pub async fn refresh_ws_session(&self) {
        *self.ws_session.write().await = None;
    }

    /// Build signed BRC-31 headers for a bare `GET <path>` WS upgrade
    /// against this relay. Lazily runs (and caches) the one-shot
    /// `/.well-known/auth` handshake on first call. The caller attaches
    /// the standard WS upgrade headers (`Connection`, `Upgrade`,
    /// `Sec-WebSocket-Version`, `Sec-WebSocket-Key`) themselves.
    ///
    /// `path` MUST start with `/` and SHOULD be the path component of
    /// the WS URL exactly as it will appear on the request line. Pass
    /// `""` for `query` when the URL has no query string; otherwise the
    /// signable string MUST be the raw `?…` form.
    pub async fn sign_ws_upgrade(&self, path: &str, query: &str) -> Result<SignedWsHeaders> {
        let session = self.ensure_session().await?;
        brc104::sign_ws_get(
            &self.wallet,
            &session.server_identity_key,
            &session.server_nonce_b64,
            path,
            query,
        )
    }

    /// Return the cached session, populating it on first call.
    async fn ensure_session(&self) -> Result<Session> {
        if let Some(s) = self.ws_session.read().await.clone() {
            return Ok(s);
        }
        let session = brc104::do_handshake(&self.relay_url, &self.wallet).await?;
        *self.ws_session.write().await = Some(session.clone());
        Ok(session)
    }
}

// ===========================================================================
// BRC-104 / BRC-31 wire helpers — direct port of
// `~/bsv/bsv-messagebox-cloudflare-public/tests/load_gen/src/
// {handshake,serialize,connect}.rs`. Kept private to this module so the
// only entry point is [`MessageBoxAuth::sign_ws_upgrade`].
// ===========================================================================

mod brc104 {
    use super::*;

    /// Sentinel for "this optional string/byte field is empty/absent" in
    /// the BRC-104 serialize-request encoding. Nine 0xFF bytes — chosen
    /// so it's unrepresentable as a varint length prefix.
    const EMPTY_SENTINEL: [u8; 9] = [0xFF; 9];

    /// Bitcoin-style varint LE encoder. Same byte layout used by the
    /// canonical TS / Go / Rust `bsv-middleware-cloudflare-public` server
    /// when it reconstructs the payload to verify the signature.
    fn write_varint(buf: &mut Vec<u8>, n: u64) {
        if n <= 252 {
            buf.push(n as u8);
        } else if n <= 0xFFFF {
            buf.push(0xFD);
            buf.extend_from_slice(&(n as u16).to_le_bytes());
        } else if n <= 0xFFFF_FFFF {
            buf.push(0xFE);
            buf.extend_from_slice(&(n as u32).to_le_bytes());
        } else {
            buf.push(0xFF);
            buf.extend_from_slice(&n.to_le_bytes());
        }
    }

    fn write_varint_bytes(buf: &mut Vec<u8>, data: &[u8]) {
        write_varint(buf, data.len() as u64);
        buf.extend_from_slice(data);
    }

    fn write_optional_string(buf: &mut Vec<u8>, value: Option<&str>) {
        match value {
            Some(s) if !s.is_empty() => write_varint_bytes(buf, s.as_bytes()),
            _ => buf.extend_from_slice(&EMPTY_SENTINEL),
        }
    }

    fn write_optional_bytes(buf: &mut Vec<u8>, data: Option<&[u8]>) {
        match data {
            Some(d) if !d.is_empty() => write_varint_bytes(buf, d),
            _ => buf.extend_from_slice(&EMPTY_SENTINEL),
        }
    }

    fn write_headers(buf: &mut Vec<u8>, headers: &[(String, String)]) {
        write_varint(buf, headers.len() as u64);
        for (key, value) in headers {
            write_varint_bytes(buf, key.as_bytes());
            write_varint_bytes(buf, value.as_bytes());
        }
    }

    /// Serialize an HTTP request into BRC-104 binary format for signing.
    /// Matches `bsv-messagebox-cloudflare-public/tests/load_gen/src/
    /// serialize.rs::serialize_request` byte-for-byte.
    pub(super) fn serialize_request(
        request_id: &[u8; 32],
        method: &str,
        path: Option<&str>,
        query: Option<&str>,
        signable_headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(request_id);
        write_varint_bytes(&mut buf, method.as_bytes());
        write_optional_string(&mut buf, path);
        write_optional_string(&mut buf, query);
        write_headers(&mut buf, signable_headers);
        write_optional_bytes(&mut buf, body);
        buf
    }

    /// Auth-header set carried by every signed BRC-31 request. Field
    /// names match the `bsv-middleware-cloudflare-public` server's
    /// `extract_auth_message` expectations.
    fn build_auth_headers(
        identity_key: &str,
        nonce_b64: &str,
        your_nonce_b64: &str,
        signature_hex: &str,
        request_id_b64: &str,
    ) -> Vec<(String, String)> {
        vec![
            ("x-bsv-auth-version".into(), "0.1".into()),
            ("x-bsv-auth-identity-key".into(), identity_key.into()),
            ("x-bsv-auth-message-type".into(), "general".into()),
            ("x-bsv-auth-nonce".into(), nonce_b64.into()),
            ("x-bsv-auth-your-nonce".into(), your_nonce_b64.into()),
            ("x-bsv-auth-signature".into(), signature_hex.into()),
            ("x-bsv-auth-request-id".into(), request_id_b64.into()),
        ]
    }

    /// Run the BRC-31 `initialRequest`/`initialResponse` exchange against
    /// `<relay_url>/.well-known/auth`. Direct port of load_gen's
    /// `do_handshake`.
    pub(super) async fn do_handshake(relay_url: &str, wallet: &ProtoWallet) -> Result<Session> {
        let trimmed = relay_url.trim_end_matches('/');
        let mut client_nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut client_nonce_bytes);
        let client_nonce_b64 = BASE64.encode(client_nonce_bytes);

        let identity_key = wallet.identity_key_hex();
        let body = json!({
            "version": "0.1",
            "messageType": "initialRequest",
            "identityKey": identity_key,
            "initialNonce": client_nonce_b64,
        });

        let url = format!("{trimmed}/.well-known/auth");
        let client = reqwest::Client::new();
        let resp = client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| MessageBoxError::Auth(format!("POST {url}: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            let snippet: String = text.chars().take(400).collect();
            return Err(MessageBoxError::Auth(format!(
                "handshake HTTP {status}: {snippet}"
            )));
        }

        let data: Value = resp
            .json()
            .await
            .map_err(|e| MessageBoxError::Auth(format!("parse initialResponse: {e}")))?;

        let server_identity_key = data
            .get("identityKey")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MessageBoxError::Auth("initialResponse missing identityKey".into()))?
            .to_string();

        // Server's nonce field is `initialNonce` or `nonce` depending on
        // server version. Accept both so we stay compatible with the
        // Calhoun relay (which emits `initialNonce`) AND any other
        // `bsv-middleware-cloudflare-public`-derived server.
        let server_nonce_b64 = data
            .get("initialNonce")
            .or_else(|| data.get("nonce"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                MessageBoxError::Auth("initialResponse missing initialNonce/nonce".into())
            })?
            .to_string();

        if let Some(your_nonce) = data.get("yourNonce").and_then(|v| v.as_str()) {
            if your_nonce != client_nonce_b64 {
                return Err(MessageBoxError::Auth(format!(
                    "yourNonce mismatch: sent {client_nonce_b64}, got {your_nonce}"
                )));
            }
        }

        Ok(Session {
            server_identity_key,
            server_nonce_b64,
            client_nonce_b64,
        })
    }

    /// Build signed BRC-31 headers for a bare `GET <path>?<query>` WS
    /// upgrade. No application headers on a bare GET upgrade, so the
    /// signable-header list is empty and the body is `None`. Mirrors
    /// `load_gen::connect::signed_ws_headers` byte-for-byte.
    pub(super) fn sign_ws_get(
        wallet: &ProtoWallet,
        server_identity_key: &str,
        server_nonce_b64: &str,
        path: &str,
        query: &str,
    ) -> Result<SignedWsHeaders> {
        let path_opt = if path.is_empty() {
            Some("/")
        } else {
            Some(path)
        };
        let query_opt = if query.is_empty() { None } else { Some(query) };

        let mut msg_nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut msg_nonce);
        let msg_nonce_b64 = BASE64.encode(msg_nonce);

        let mut request_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut request_id);
        let request_id_b64 = BASE64.encode(request_id);

        let serialized = serialize_request(&request_id, "GET", path_opt, query_opt, &[], None);

        let key_id = format!("{msg_nonce_b64} {server_nonce_b64}");
        let counterparty = Counterparty::from_hex(server_identity_key).map_err(|e| {
            MessageBoxError::Auth(format!("parse server identity_key as Counterparty: {e:?}"))
        })?;

        let result = wallet
            .create_signature(CreateSignatureArgs {
                data: Some(serialized),
                hash_to_directly_sign: None,
                protocol_id: Protocol::new(SecurityLevel::Counterparty, "auth message signature"),
                key_id,
                counterparty: Some(counterparty),
            })
            .map_err(|e| MessageBoxError::Auth(format!("create_signature: {e:?}")))?;
        let signature_hex = hex::encode(&result.signature);

        Ok(build_auth_headers(
            &wallet.identity_key_hex(),
            &msg_nonce_b64,
            server_nonce_b64,
            &signature_hex,
            &request_id_b64,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn fresh_priv() -> PrivateKey {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b[0] |= 0x01;
        PrivateKey::from_bytes(&b).unwrap()
    }

    #[test]
    fn construct_does_not_panic() {
        let auth = MessageBoxAuth::new("https://relay.example/", fresh_priv()).unwrap();
        assert_eq!(auth.relay_url(), "https://relay.example/");
    }

    #[tokio::test]
    async fn identity_hex_round_trips_pub() {
        let priv_ = fresh_priv();
        let expected = priv_.public_key().to_hex();
        let auth = MessageBoxAuth::new("https://relay.example/", priv_).unwrap();
        let actual = auth.identity_hex().await.unwrap();
        assert_eq!(actual, expected);
    }

    // ----- BRC-104 wire-shape tests --------------------------------------
    //
    // These pin the byte format the load_gen + canonical TS/Go clients
    // produce. If any of these break, the live relay will reject our
    // signatures and the live_relay_proof test will fail to verify —
    // these unit checks let us catch the regression locally first.

    #[test]
    fn brc104_serialize_request_get_no_query_no_body() {
        // Fixed request_id so the output is byte-deterministic. Matches
        // the load_gen serialize_request behaviour: 32B request_id ‖
        // varint(3)"GET" ‖ varint(4)"/foo" ‖ EMPTY_SENTINEL (no query) ‖
        // varint(0) headers ‖ EMPTY_SENTINEL (no body).
        let request_id = [0u8; 32];
        let out = brc104::serialize_request(&request_id, "GET", Some("/foo"), None, &[], None);
        let mut expected = Vec::new();
        expected.extend_from_slice(&request_id);
        expected.push(3);
        expected.extend_from_slice(b"GET");
        expected.push(4);
        expected.extend_from_slice(b"/foo");
        expected.extend_from_slice(&[0xFF; 9]); // no query → sentinel
        expected.push(0); // zero signable headers
        expected.extend_from_slice(&[0xFF; 9]); // no body → sentinel
        assert_eq!(out, expected);
    }

    #[test]
    fn brc104_serialize_request_with_query_and_body() {
        // Asserts: varint-prefixed query string, varint-prefixed body,
        // headers count + per-header varint length prefixes.
        let request_id = [0xAB; 32];
        let headers = vec![("content-type".to_string(), "application/json".to_string())];
        let body = br#"{"k":"v"}"#;
        let out = brc104::serialize_request(
            &request_id,
            "POST",
            Some("/sendMessage"),
            Some("?box=mpc-dkg"),
            &headers,
            Some(body),
        );

        let mut expected = Vec::new();
        expected.extend_from_slice(&request_id);
        expected.push(4);
        expected.extend_from_slice(b"POST");
        expected.push(12);
        expected.extend_from_slice(b"/sendMessage");
        expected.push(12);
        expected.extend_from_slice(b"?box=mpc-dkg");
        // 1 header: content-type → application/json
        expected.push(1);
        expected.push(12);
        expected.extend_from_slice(b"content-type");
        expected.push(16);
        expected.extend_from_slice(b"application/json");
        // body
        expected.push(body.len() as u8);
        expected.extend_from_slice(body);
        assert_eq!(out, expected);
    }

    #[test]
    fn sign_ws_upgrade_returns_full_brc31_header_set() {
        // We can't reach the live relay in a unit test, so prime the
        // session cache directly with a synthetic Session and assert the
        // header shape sign_ws_get produces.
        let priv_ = fresh_priv();
        let server_priv = fresh_priv();
        let server_identity_hex = server_priv.public_key().to_hex();
        let mut server_nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut server_nonce_bytes);
        let server_nonce_b64 = BASE64.encode(server_nonce_bytes);

        let wallet = ProtoWallet::new(Some(priv_));
        let headers =
            brc104::sign_ws_get(&wallet, &server_identity_hex, &server_nonce_b64, "/ws", "")
                .expect("sign_ws_get must succeed against a well-formed Session");

        // The 7 BRC-31 auth headers must all be present and in the
        // canonical order build_auth_headers produces.
        let names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "x-bsv-auth-version",
                "x-bsv-auth-identity-key",
                "x-bsv-auth-message-type",
                "x-bsv-auth-nonce",
                "x-bsv-auth-your-nonce",
                "x-bsv-auth-signature",
                "x-bsv-auth-request-id",
            ]
        );
        // Quick sanity: identity-key header is our pub hex; your-nonce
        // header is the server's nonce.
        let map: std::collections::HashMap<_, _> = headers.iter().cloned().collect();
        assert_eq!(
            map.get("x-bsv-auth-identity-key").unwrap(),
            &wallet.identity_key_hex()
        );
        assert_eq!(map.get("x-bsv-auth-your-nonce").unwrap(), &server_nonce_b64);
        assert_eq!(map.get("x-bsv-auth-version").unwrap(), "0.1");
        assert_eq!(map.get("x-bsv-auth-message-type").unwrap(), "general");
        // Signature is non-empty hex.
        let sig_hex = map.get("x-bsv-auth-signature").unwrap();
        assert!(!sig_hex.is_empty());
        assert!(hex::decode(sig_hex).is_ok());
    }
}
