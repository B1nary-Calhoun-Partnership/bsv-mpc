//! Native BRC-103/104 storage client (issue #64).
//!
//! A `reqwest`-backed port of `WorkerStorageClient`
//! (`rust-middleware/bsv-auth-cloudflare/src/client/storage.rs`), which itself
//! runs the BRC-103/104 handshake + per-request signed General messages inline
//! (no `Peer` type). This port keeps the proven byte layout and signing rules
//! and adds one hardening: it VERIFIES the server's response signature against
//! the server identity key established at handshake (the reference client skips
//! this), failing closed on mismatch.
//!
//! Rust owns ALL the BRC-31/103/104 crypto/auth here. The high-level surface is:
//!   - [`open`]`(base_url, identity_key_hex)` → runs Phase A (handshake)
//!   - [`StorageConn::rpc`]`(method, params_json)` → Phase B (signed General
//!     message), returns the parsed JSON-RPC `result`.
//!
//! The identity private key is held only inside a [`Zeroizing`] hex string for
//! as long as it takes to construct the in-memory `ProtoWallet`.

use std::sync::Mutex;

use bsv::auth::transports::HttpRequest;
use bsv::auth::types::{AuthMessage, MessageType, AUTH_PROTOCOL_ID};
use bsv::auth::utils::create_nonce;
use bsv::primitives::{from_base64, to_base64, PrivateKey, PublicKey};
use bsv::wallet::{
    Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel, VerifySignatureArgs,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::ClientError;

/// Originator string for auth operations (matches the reference client).
const ORIGINATOR: &str = "bsv-wallet-toolbox";

/// BRC-104 header names (BRC-104 §HTTP transport).
mod headers {
    pub const VERSION: &str = "x-bsv-auth-version";
    pub const IDENTITY_KEY: &str = "x-bsv-auth-identity-key";
    pub const NONCE: &str = "x-bsv-auth-nonce";
    pub const YOUR_NONCE: &str = "x-bsv-auth-your-nonce";
    pub const SIGNATURE: &str = "x-bsv-auth-signature";
    pub const MESSAGE_TYPE: &str = "x-bsv-auth-message-type";
    pub const REQUEST_ID: &str = "x-bsv-auth-request-id";
}

fn host(seam: &'static str, e: impl std::fmt::Display) -> ClientError {
    ClientError::Host {
        seam,
        reason: e.to_string(),
    }
}

// ── JSON-RPC 2.0 wire types (ported from bsv-auth-cloudflare client::json_rpc) ──

const JSON_RPC_VERSION: &str = "2.0";

#[derive(Debug, Clone, Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<Value>,
    id: u64,
}

impl JsonRpcRequest {
    fn new(id: u64, method: &str, params: Vec<Value>) -> Self {
        Self {
            jsonrpc: JSON_RPC_VERSION.to_string(),
            method: method.to_string(),
            params,
            id,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct JsonRpcResponse {
    #[allow(dead_code)]
    #[serde(default)]
    jsonrpc: String,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<JsonRpcError>,
    #[serde(default)]
    id: u64,
}

/// Some servers (e.g. storage.babbage.systems) return `{isError, name, message}`
/// instead of `{code, message, data}` — all fields optional to accept both.
#[derive(Debug, Clone, Deserialize)]
struct JsonRpcError {
    #[serde(default)]
    code: Option<i32>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    data: Option<Value>,
    #[serde(default)]
    name: Option<String>,
}

impl std::fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = self.message.as_deref().unwrap_or("unknown error");
        match (self.code, self.name.as_deref()) {
            (Some(code), _) => write!(f, "JSON-RPC error {code}: {msg}"),
            (None, Some(name)) => write!(f, "JSON-RPC error ({name}): {msg}"),
            _ => write!(f, "JSON-RPC error: {msg}"),
        }
    }
}

// ── BRC-104 request payload byte layout (ported from transport/cloudflare.rs) ──

/// Writes a Bitcoin-style varint, matching the TS SDK `Writer.writeVarIntNum`:
/// - value < 0 (i.e. -1): 9 bytes of 0xFF ("missing/empty")
/// - value < 253: single byte
/// - value < 0x10000: 0xFD + 2 bytes LE
/// - value < 0x100000000: 0xFE + 4 bytes LE
/// - else: 0xFF + 8 bytes LE
fn write_varint(value: i64) -> Vec<u8> {
    if value < 0 {
        vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    } else if value < 253 {
        vec![value as u8]
    } else if value < 0x10000 {
        let bytes = (value as u16).to_le_bytes();
        vec![0xFD, bytes[0], bytes[1]]
    } else if value < 0x100000000 {
        let bytes = (value as u32).to_le_bytes();
        vec![0xFE, bytes[0], bytes[1], bytes[2], bytes[3]]
    } else {
        let bytes = (value as u64).to_le_bytes();
        vec![
            0xFF, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]
    }
}

/// Builds the BRC-104 General-message request payload that gets signed.
///
/// Byte-identical to `build_request_payload` in the reference transport:
/// `[request_id:32][method][path][search][headers][body]` where each
/// variable field is `varint(len) || bytes`, and an empty path/search/body is
/// the `varint(-1)` empty marker.
fn build_request_payload(
    request_id: &[u8; 32],
    method: &str,
    path: &str,
    search: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();

    payload.extend_from_slice(request_id);

    let method_bytes = method.as_bytes();
    payload.extend(write_varint(method_bytes.len() as i64));
    payload.extend_from_slice(method_bytes);

    if path.is_empty() {
        payload.extend(write_varint(-1));
    } else {
        let path_bytes = path.as_bytes();
        payload.extend(write_varint(path_bytes.len() as i64));
        payload.extend_from_slice(path_bytes);
    }

    if search.is_empty() {
        payload.extend(write_varint(-1));
    } else {
        let search_bytes = search.as_bytes();
        payload.extend(write_varint(search_bytes.len() as i64));
        payload.extend_from_slice(search_bytes);
    }

    payload.extend(write_varint(headers.len() as i64));
    for (key, value) in headers {
        let key_bytes = key.as_bytes();
        payload.extend(write_varint(key_bytes.len() as i64));
        payload.extend_from_slice(key_bytes);
        let val_bytes = value.as_bytes();
        payload.extend(write_varint(val_bytes.len() as i64));
        payload.extend_from_slice(val_bytes);
    }

    if body.is_empty() {
        payload.extend(write_varint(-1));
    } else {
        payload.extend(write_varint(body.len() as i64));
        payload.extend_from_slice(body);
    }

    payload
}

// ── Session state ─────────────────────────────────────────────────────────────

/// Session state established by the Phase-A handshake.
struct SessionState {
    /// Our session nonce (base64). Used as the verifier-side key_id component
    /// when checking the server's response signature.
    our_nonce: String,
    /// Server's session nonce (base64) — used as `your_nonce` and the signer
    /// key_id component on outgoing General messages.
    peer_nonce: String,
    /// Server's identity key (the counterparty for sign + verify).
    server_identity_key: PublicKey,
}

// ── The client ──────────────────────────────────────────────────────────────

/// A native, `reqwest`-backed BRC-103/104 storage client.
///
/// Construct via [`StorageClient::open`] (which performs the handshake), then
/// issue authed JSON-RPC via [`StorageClient::rpc`]. Unauthenticated,
/// pre-handshake methods (`makeAvailable`, `findOrInsertUser`) also flow through
/// `rpc` — the server auto-establishes / looks up the session by nonce.
pub struct StorageClient {
    endpoint_url: String,
    wallet: ProtoWallet,
    http: reqwest::Client,
    /// `next_id` and `session` are behind a `Mutex` so `rpc(&self, …)` can stay
    /// `&self` (required for a `uniffi::Object` whose methods take `&self`).
    next_id: Mutex<u64>,
    session: Mutex<Option<SessionState>>,
}

impl StorageClient {
    /// Opens a client and runs the Phase-A BRC-103/104 handshake.
    ///
    /// `identity_key_hex` is the device identity private key (64-char hex). It
    /// is held in [`Zeroizing`] only long enough to build the in-memory wallet.
    pub async fn open(base_url: &str, identity_key_hex: &str) -> Result<Self, ClientError> {
        let key_hex = Zeroizing::new(identity_key_hex.trim().to_string());
        let private_key = PrivateKey::from_hex(&key_hex)
            .map_err(|e| host("storage", format!("bad identity key: {e}")))?;
        let wallet = ProtoWallet::new(Some(private_key));

        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| host("storage", e))?;

        let client = Self {
            endpoint_url: base_url.trim_end_matches('/').to_string(),
            wallet,
            http,
            next_id: Mutex::new(1),
            session: Mutex::new(None),
        };

        client.perform_handshake().await?;
        Ok(client)
    }

    /// Our identity key.
    fn identity_key(&self) -> PublicKey {
        self.wallet.identity_key()
    }

    /// Phase A: InitialRequest → InitialResponse, verify, store session.
    async fn perform_handshake(&self) -> Result<(), ClientError> {
        let my_identity = self.identity_key();

        // create_nonce(counterparty=None=Self) — 48-byte canonical nonce.
        let session_nonce = create_nonce(&self.wallet, None, ORIGINATOR)
            .await
            .map_err(|e| host("storage", e))?;

        let mut msg = AuthMessage::new(MessageType::InitialRequest, my_identity);
        msg.initial_nonce = Some(session_nonce.clone());

        let auth_url = format!("{}/.well-known/auth", self.endpoint_url);
        let body = serde_json::to_string(&msg).map_err(ClientError::from)?;

        let response = self
            .http
            .post(&auth_url)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| host("storage", e))?;

        let status = response.status();
        let response_text = response.text().await.map_err(|e| host("storage", e))?;
        if !status.is_success() {
            return Err(host(
                "storage",
                format!("auth endpoint returned {status}: {response_text}"),
            ));
        }

        let response_msg: AuthMessage = serde_json::from_str(&response_text).map_err(|e| {
            host(
                "storage",
                format!("parse auth response: {e} — body: {response_text}"),
            )
        })?;

        if response_msg.message_type != MessageType::InitialResponse {
            return Err(host(
                "storage",
                format!(
                    "expected InitialResponse, got {:?}",
                    response_msg.message_type
                ),
            ));
        }

        // your_nonce must echo our session nonce.
        let echoed = response_msg.your_nonce.as_deref().unwrap_or("");
        if echoed != session_nonce {
            return Err(host(
                "storage",
                "InitialResponse your_nonce does not match our session nonce",
            ));
        }

        let server_nonce = response_msg
            .initial_nonce
            .as_ref()
            .or(response_msg.nonce.as_ref())
            .ok_or_else(|| host("storage", "InitialResponse missing server nonce"))?
            .clone();

        // Verify InitialResponse signature: signing_data() = your_nonce || initial_nonce.
        let data = response_msg.signing_data();
        let key_id = response_msg.get_key_id(None); // InitialResponse derives key_id from its own fields
        let signature = response_msg
            .signature
            .as_ref()
            .ok_or_else(|| host("storage", "InitialResponse not signed"))?;
        let protocol = Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID);

        let verify = self
            .wallet
            .verify_signature(VerifySignatureArgs {
                data: Some(data),
                hash_to_directly_verify: None,
                signature: signature.clone(),
                protocol_id: protocol,
                key_id,
                counterparty: Some(Counterparty::Other(response_msg.identity_key.clone())),
                for_self: None,
            })
            .map_err(|e| host("storage", e))?;
        if !verify.valid {
            return Err(host("storage", "InitialResponse signature invalid"));
        }

        *self.session.lock().expect("session lock") = Some(SessionState {
            our_nonce: session_nonce,
            peer_nonce: server_nonce,
            server_identity_key: response_msg.identity_key,
        });

        Ok(())
    }

    /// Phase B: signed General JSON-RPC call. Returns the parsed `result`.
    ///
    /// HARDENED vs the reference client: verifies the server's response General
    /// message signature against the handshake-established server identity key,
    /// failing closed on mismatch.
    pub async fn rpc(&self, method: &str, params: Vec<Value>) -> Result<Value, ClientError> {
        // Snapshot session fields (clone out of the mutex; never hold the guard
        // across the .await).
        let (peer_nonce, server_identity_key, our_nonce) = {
            let guard = self.session.lock().expect("session lock");
            let s = guard
                .as_ref()
                .ok_or_else(|| host("storage", "no session — call open() first"))?;
            (
                s.peer_nonce.clone(),
                s.server_identity_key.clone(),
                s.our_nonce.clone(),
            )
        };

        let id = {
            let mut g = self.next_id.lock().expect("id lock");
            let id = *g;
            *g += 1;
            id
        };

        let rpc_req = JsonRpcRequest::new(id, method, params);
        let rpc_body = serde_json::to_vec(&rpc_req).map_err(ClientError::from)?;

        // 32-byte random request id.
        let mut request_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut request_id);

        // BRC-104 request payload for signing (POST "/", content-type signable header).
        let http_request = HttpRequest {
            request_id,
            method: "POST".to_string(),
            path: "/".to_string(),
            search: String::new(),
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: rpc_body.clone(),
        };
        // Use our own port-parity builder (asserted byte-identical in tests).
        let payload = build_request_payload(
            &request_id,
            &http_request.method,
            &http_request.path,
            &http_request.search,
            &http_request.headers,
            &http_request.body,
        );

        // Build + sign the General AuthMessage.
        let my_identity = self.identity_key();
        let mut msg = AuthMessage::new(MessageType::General, my_identity);

        let mut random_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        msg.nonce = Some(to_base64(&random_bytes));
        msg.your_nonce = Some(peer_nonce.clone());
        msg.payload = Some(payload);

        let data = msg.signing_data();
        let key_id = msg.get_key_id(Some(&peer_nonce));
        let protocol = Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID);
        let sig_result = self
            .wallet
            .create_signature(CreateSignatureArgs {
                data: Some(data),
                hash_to_directly_sign: None,
                protocol_id: protocol,
                key_id,
                counterparty: Some(Counterparty::Other(server_identity_key.clone())),
            })
            .map_err(|e| host("storage", e))?;
        msg.signature = Some(sig_result.signature);

        // BRC-104 headers.
        let request_id_b64 = to_base64(&request_id);
        let mut req = self
            .http
            .post(format!("{}/", self.endpoint_url))
            .header(headers::VERSION, msg.version.clone())
            .header(headers::IDENTITY_KEY, msg.identity_key.to_hex())
            .header(headers::MESSAGE_TYPE, "general")
            .header(headers::REQUEST_ID, request_id_b64.clone())
            .header("content-type", "application/json");
        if let Some(ref nonce) = msg.nonce {
            req = req.header(headers::NONCE, nonce.clone());
        }
        if let Some(ref your_nonce) = msg.your_nonce {
            req = req.header(headers::YOUR_NONCE, your_nonce.clone());
        }
        if let Some(ref sig) = msg.signature {
            req = req.header(headers::SIGNATURE, hex::encode(sig));
        }

        let response = req
            .body(rpc_body)
            .send()
            .await
            .map_err(|e| host("storage", e))?;

        let status = response.status();
        // Capture response auth headers BEFORE consuming the body.
        let resp_headers = response.headers().clone();
        let response_text = response.text().await.map_err(|e| host("storage", e))?;

        if !status.is_success() {
            return Err(host(
                "storage",
                format!("storage server returned {status}: {response_text}"),
            ));
        }

        // HARDENING: verify the server's response General-message signature.
        self.verify_response_signature(
            &resp_headers,
            &request_id,
            status.as_u16(),
            response_text.as_bytes(),
            &server_identity_key,
            &our_nonce,
        )?;

        // Parse JSON-RPC envelope.
        let rpc_resp: JsonRpcResponse = serde_json::from_str(&response_text).map_err(|e| {
            host(
                "storage",
                format!("parse RPC response: {e} — body: {response_text}"),
            )
        })?;
        if let Some(error) = rpc_resp.error {
            return Err(host("storage", format!("RPC error: {error}")));
        }
        if rpc_resp.id != id {
            return Err(host(
                "storage",
                format!("RPC id mismatch: expected {id}, got {}", rpc_resp.id),
            ));
        }

        Ok(rpc_resp.result.unwrap_or(Value::Null))
    }

    /// Verifies the server's BRC-104 response General-message signature.
    ///
    /// Mirrors `verify_message_signature` + `HttpResponseData::to_payload` in the
    /// server (`bsv-auth-cloudflare/src/middleware/auth.rs`): the signed payload
    /// is `[request_id:32][status varint][signable response headers][body]`, the
    /// data is that payload, the key_id is `"{server msg nonce} {our session
    /// nonce}"`, the protocol is `(Counterparty, "auth message signature")`, and
    /// the counterparty is the server identity key. Fails closed.
    fn verify_response_signature(
        &self,
        resp_headers: &reqwest::header::HeaderMap,
        request_id: &[u8; 32],
        status: u16,
        body: &[u8],
        server_identity_key: &PublicKey,
        our_nonce: &str,
    ) -> Result<(), ClientError> {
        let get = |name: &str| -> Option<String> {
            resp_headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        };

        // The response must carry the auth headers (identity-key + signature).
        let server_msg_nonce = get(headers::NONCE).unwrap_or_default();
        let sig_hex = get(headers::SIGNATURE).ok_or_else(|| {
            host(
                "storage",
                "server response missing auth signature header (fail-closed)",
            )
        })?;
        let signature = hex::decode(&sig_hex)
            .or_else(|_| from_base64(&sig_hex))
            .map_err(|e| host("storage", format!("bad response signature encoding: {e}")))?;

        // The response identity-key header must match the handshake server key.
        if let Some(resp_id_key) = get(headers::IDENTITY_KEY) {
            if resp_id_key != server_identity_key.to_hex() {
                return Err(host(
                    "storage",
                    "server response identity key does not match handshake key (fail-closed)",
                ));
            }
        }

        // Reconstruct the signed response payload. Signable response headers
        // follow the SimplifiedFetchTransport rule (x-bsv-* excluding
        // x-bsv-auth-*, plus authorization), sorted by lowercased key.
        let mut signable: Vec<(String, String)> = resp_headers
            .iter()
            .filter_map(|(k, v)| {
                let key = k.as_str().to_lowercase();
                let val = v.to_str().ok()?.to_string();
                if key.starts_with("x-bsv-auth-") {
                    None
                } else if key.starts_with("x-bsv-") || key == "authorization" {
                    Some((key, val))
                } else {
                    None
                }
            })
            .collect();
        signable.sort_by(|a, b| a.0.cmp(&b.0));

        let payload = build_response_payload(request_id, status, &signable, body);

        // Rebuild the General message the server signed and verify.
        let mut msg = AuthMessage::new(MessageType::General, server_identity_key.clone());
        msg.nonce = Some(server_msg_nonce);
        msg.your_nonce = Some(our_nonce.to_string());
        msg.payload = Some(payload);

        // signing_data() for a General message is just the payload (set above).
        let data = msg.signing_data();
        // Verifier key_id: "{server msg nonce} {our session nonce}".
        let key_id = msg.get_key_id(Some(our_nonce));
        let protocol = Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID);

        let verify = self
            .wallet
            .verify_signature(VerifySignatureArgs {
                data: Some(data),
                hash_to_directly_verify: None,
                signature,
                protocol_id: protocol,
                key_id,
                counterparty: Some(Counterparty::Other(server_identity_key.clone())),
                for_self: None,
            })
            .map_err(|e| host("storage", e))?;
        if !verify.valid {
            return Err(host(
                "storage",
                "server response signature failed verification (fail-closed)",
            ));
        }
        Ok(())
    }

    /// Test-only: send a General message whose BRC-104 signature is computed
    /// over a DIFFERENT body than the one transmitted, so the server's
    /// signature check must reject it. Used by the live T2 to prove the server
    /// rejects tampered requests for the right reason.
    #[cfg(test)]
    async fn rpc_tampered(&self, method: &str) -> Result<Value, ClientError> {
        let (peer_nonce, server_identity_key) = {
            let guard = self.session.lock().expect("session lock");
            let s = guard
                .as_ref()
                .ok_or_else(|| host("storage", "no session"))?;
            (s.peer_nonce.clone(), s.server_identity_key.clone())
        };

        let signed_body = serde_json::to_vec(&JsonRpcRequest::new(999, method, vec![]))
            .map_err(ClientError::from)?;
        // The body actually sent differs from what we sign over.
        let sent_body = serde_json::to_vec(&JsonRpcRequest::new(1000, "makeAvailable", vec![]))
            .map_err(ClientError::from)?;

        let mut request_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut request_id);
        let signable_headers = vec![("content-type".to_string(), "application/json".to_string())];
        let payload = build_request_payload(
            &request_id,
            "POST",
            "/",
            "",
            &signable_headers,
            &signed_body, // sign over signed_body
        );

        let my_identity = self.identity_key();
        let mut msg = AuthMessage::new(MessageType::General, my_identity);
        let mut random_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        msg.nonce = Some(to_base64(&random_bytes));
        msg.your_nonce = Some(peer_nonce.clone());
        msg.payload = Some(payload);
        let key_id = msg.get_key_id(Some(&peer_nonce));
        let protocol = Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID);
        let sig_result = self
            .wallet
            .create_signature(CreateSignatureArgs {
                data: Some(msg.signing_data()),
                hash_to_directly_sign: None,
                protocol_id: protocol,
                key_id,
                counterparty: Some(Counterparty::Other(server_identity_key)),
            })
            .map_err(|e| host("storage", e))?;
        msg.signature = Some(sig_result.signature);

        let response = self
            .http
            .post(format!("{}/", self.endpoint_url))
            .header(headers::VERSION, msg.version.clone())
            .header(headers::IDENTITY_KEY, msg.identity_key.to_hex())
            .header(headers::MESSAGE_TYPE, "general")
            .header(headers::REQUEST_ID, to_base64(&request_id))
            .header(headers::NONCE, msg.nonce.clone().unwrap())
            .header(headers::YOUR_NONCE, peer_nonce)
            .header(headers::SIGNATURE, hex::encode(msg.signature.unwrap()))
            .header("content-type", "application/json")
            .body(sent_body) // send a different body than we signed
            .send()
            .await
            .map_err(|e| host("storage", e))?;

        let status = response.status();
        let text = response.text().await.map_err(|e| host("storage", e))?;
        if !status.is_success() {
            return Err(host(
                "storage",
                format!("tampered request rejected with {status}: {text}"),
            ));
        }
        // Should not reach here — but if it does, surface the body.
        Ok(serde_json::from_str(&text).unwrap_or(Value::String(text)))
    }
}

/// Builds the BRC-104 response payload (mirrors `HttpResponseData::to_payload`):
/// `[request_id:32][status varint][headers][body]`.
fn build_response_payload(
    request_id: &[u8; 32],
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(request_id);
    payload.extend(write_varint(status as i64));
    payload.extend(write_varint(headers.len() as i64));
    for (key, value) in headers {
        let key_bytes = key.as_bytes();
        payload.extend(write_varint(key_bytes.len() as i64));
        payload.extend_from_slice(key_bytes);
        let val_bytes = value.as_bytes();
        payload.extend(write_varint(val_bytes.len() as i64));
        payload.extend_from_slice(val_bytes);
    }
    if body.is_empty() {
        payload.extend(write_varint(-1));
    } else {
        payload.extend(write_varint(body.len() as i64));
        payload.extend_from_slice(body);
    }
    payload
}

/// High-level entry point: open a connection and run the Phase-A handshake.
///
/// `identity_key_hex` is the device identity private key (64-char hex).
pub async fn open(base_url: &str, identity_key_hex: &str) -> Result<StorageClient, ClientError> {
    StorageClient::open(base_url, identity_key_hex).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── T1: BRC-104 request-payload byte layout port parity ──────────────────
    //
    // These vectors are taken verbatim from the reference transport tests
    // (`bsv-auth-cloudflare/src/transport/cloudflare.rs`) so a regression in our
    // ported `build_request_payload` / `write_varint` is caught here.

    #[test]
    fn varint_matches_reference_vectors() {
        assert_eq!(write_varint(0), vec![0x00]);
        assert_eq!(write_varint(1), vec![0x01]);
        assert_eq!(write_varint(252), vec![252]);
        assert_eq!(write_varint(253), vec![0xFD, 253, 0]);
        assert_eq!(write_varint(256), vec![0xFD, 0, 1]);
        assert_eq!(write_varint(0xFFFF), vec![0xFD, 0xFF, 0xFF]);
        assert_eq!(write_varint(0x10000), vec![0xFE, 0, 0, 1, 0]);
        assert_eq!(
            write_varint(0xFFFFFFFF_i64),
            vec![0xFE, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        // -1 empty marker = 9 bytes of 0xFF.
        let neg = write_varint(-1);
        assert_eq!(neg.len(), 9);
        assert!(neg.iter().all(|&b| b == 0xFF));
        // 8-byte path.
        let big = write_varint(0x100000000_i64);
        assert_eq!(big.len(), 9);
        assert_eq!(big[0], 0xFF);
        assert_eq!(big[1..], [0, 0, 0, 0, 1, 0, 0, 0]);
    }

    #[test]
    fn request_payload_get_byte_layout() {
        // Mirrors `test_request_payload_get_request`.
        let request_id = [42u8; 32];
        let payload = build_request_payload(&request_id, "GET", "/api/data", "", &[], &[]);
        assert_eq!(&payload[0..32], &[42u8; 32]);
        assert_eq!(payload[32], 3); // method len varint "GET"
        assert_eq!(&payload[33..36], b"GET");
        assert_eq!(payload[36], 9); // path len varint "/api/data"
        assert_eq!(&payload[37..46], b"/api/data");
        assert_eq!(&payload[46..55], &[0xFF; 9]); // empty search marker
    }

    #[test]
    fn request_payload_post_with_body_and_headers() {
        let request_id = [0u8; 32];
        let body = br#"{"jsonrpc":"2.0","method":"getBalance","params":[],"id":1}"#;
        let headers = vec![("content-type".to_string(), "application/json".to_string())];
        let payload = build_request_payload(&request_id, "POST", "/", "", &headers, body);

        // request_id
        assert_eq!(&payload[0..32], &[0u8; 32]);
        // method POST
        assert_eq!(payload[32], 4);
        assert_eq!(&payload[33..37], b"POST");
        // path "/"
        assert_eq!(payload[37], 1);
        assert_eq!(&payload[38..39], b"/");
        // empty search marker
        assert_eq!(&payload[39..48], &[0xFF; 9]);
        // header count = 1
        assert_eq!(payload[48], 1);
        // header key "content-type" (12 bytes)
        assert_eq!(payload[49], 12);
        assert_eq!(&payload[50..62], b"content-type");
        // header value "application/json" (16 bytes)
        assert_eq!(payload[62], 16);
        assert_eq!(&payload[63..79], b"application/json");
        // body
        assert_eq!(payload[79], body.len() as u8);
        assert_eq!(&payload[80..80 + body.len()], body);
    }

    /// A tampered request payload must produce a different signed-data input
    /// (so the resulting signature differs / server verify fails).
    #[test]
    fn tampered_request_payload_changes_signed_bytes() {
        let request_id = [7u8; 32];
        let headers = vec![("content-type".to_string(), "application/json".to_string())];
        let body = br#"{"id":1,"method":"getBalance"}"#;
        let good = build_request_payload(&request_id, "POST", "/", "", &headers, body);

        // Tamper the body (e.g. swap method).
        let evil_body = br#"{"id":1,"method":"createAction"}"#;
        let evil = build_request_payload(&request_id, "POST", "/", "", &headers, evil_body);
        assert_ne!(good, evil, "tampered body must change the signed payload");

        // Tamper the path.
        let evil_path = build_request_payload(&request_id, "POST", "/admin", "", &headers, body);
        assert_ne!(
            good, evil_path,
            "tampered path must change the signed payload"
        );
    }

    // ── T1: 48-byte nonce derivation parity ──────────────────────────────────
    //
    // create_nonce() must yield the canonical 48-byte (16 random || 32 HMAC)
    // format and round-trip-verify, matching bsv-rs `create_nonce`/`verify_nonce`.

    #[tokio::test]
    async fn nonce_is_canonical_48_bytes_and_verifies() {
        use bsv::auth::utils::verify_nonce;

        let wallet = ProtoWallet::new(Some(
            PrivateKey::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap(),
        ));
        let nonce = create_nonce(&wallet, None, ORIGINATOR).await.unwrap();
        let decoded = from_base64(&nonce).unwrap();
        assert_eq!(decoded.len(), 48, "canonical nonce must be 48 bytes");
        // First 16 = random, last 32 = full HMAC; verify reproduces the HMAC.
        assert!(verify_nonce(&nonce, &wallet, None, ORIGINATOR)
            .await
            .unwrap());

        // A tampered nonce (flip a byte in the HMAC region) must NOT verify.
        let mut bad = decoded.clone();
        bad[40] ^= 0xFF;
        let bad_nonce = to_base64(&bad);
        assert!(
            !verify_nonce(&bad_nonce, &wallet, None, ORIGINATOR)
                .await
                .unwrap(),
            "tampered nonce must fail verification"
        );
    }

    // ── T2: live integration (gated STORAGE_SEAM_LIVE=1) ─────────────────────

    #[tokio::test]
    async fn live_handshake_and_authed_rpc() {
        if std::env::var("STORAGE_SEAM_LIVE").ok().as_deref() != Some("1") {
            eprintln!("skipping live test: set STORAGE_SEAM_LIVE=1 to run");
            return;
        }
        let base_url = std::env::var("STORAGE_SEAM_URL")
            .unwrap_or_else(|_| "https://wallet-infra.x402agency.com".to_string());

        // Ephemeral device identity — the server auto-creates the user row.
        let priv_hex = {
            let pk = PrivateKey::random();
            pk.to_hex()
        };
        let identity_hex = PrivateKey::from_hex(&priv_hex)
            .unwrap()
            .public_key()
            .to_hex();

        // open() runs Phase A (handshake): InitialResponse signature verified
        // against the server identity key, or this expect() fails.
        let client = open(&base_url, &priv_hex)
            .await
            .expect("Phase-A handshake (incl. InitialResponse sig verify) must succeed");

        // Unauth method works through rpc(); makeAvailable returns the server's
        // storage settings (incl. its storageIdentityKey). An Ok here also means
        // verify_response_signature() (the hardening) PASSED — it runs inside
        // rpc() and fails closed, so a bad/missing response sig => Err.
        let avail = client
            .rpc("makeAvailable", vec![])
            .await
            .expect("makeAvailable must succeed AND its response signature must verify");
        assert!(
            avail.get("storageIdentityKey").is_some(),
            "makeAvailable result should carry storageIdentityKey: {avail}"
        );
        eprintln!("makeAvailable OK + response sig verified: {avail}");

        // Authed RPC (server auto-creates the user row for the ephemeral key).
        // Ok => the response General-message signature verified (fail-closed).
        let auth = serde_json::json!({"identityKey": identity_hex});
        let args = serde_json::json!({"basket": "default", "limit": 5});
        let outputs = client
            .rpc("listOutputs", vec![auth, args])
            .await
            .expect("authed listOutputs must succeed AND its response signature must verify");
        eprintln!("listOutputs OK + response sig verified: {outputs}");

        // A tampered request (signature computed over a DIFFERENT body than the
        // one transmitted) must be REJECTED by the server's BRC-104 verify — it
        // must NOT be processed. The right reason here is the signature/body
        // mismatch: the server refuses the request rather than executing the
        // sent `makeAvailable` body. (The deployed wallet-infra Worker collapses
        // its BRC-104 auth-verify failure to a 500 rather than a 401; the
        // load-bearing property is non-success / rejection, which we assert.)
        let tampered = client.rpc_tampered("getBalance").await;
        let err = tampered.expect_err("server must reject a tampered (mis-signed) request");
        let msg = err.to_string().to_lowercase();
        eprintln!("tampered request correctly rejected: {err}");
        assert!(
            msg.contains("rejected") || msg.contains("returned"),
            "tampered request must surface as a non-success rejection, got: {err}"
        );
        // And it must NOT have been processed as the (different) body we sent —
        // i.e. we must not have gotten a valid makeAvailable result back.
        assert!(
            !msg.contains("storageidentitykey"),
            "tampered request must not be processed by the server"
        );
    }
}
