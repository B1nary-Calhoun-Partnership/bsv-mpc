//! `SocketIoTransport` — `bsv_rs::auth::Transport` implementation that
//! drives the BRC-103 `authMessage` event channel over the Socket.IO
//! layer atop the [`WsSender`]/[`WsHandle`] substrate.
//!
//! Target-agnostic: the `WsSender`/`WsHandle` types are `use`-aliased to
//! [`crate::transport_wasm`] on wasm32 and [`crate::transport_native`]
//! on native, so this module compiles unchanged on both targets. The
//! `unsafe impl Send/Sync` shield is `#[cfg(target_arch = "wasm32")]`-
//! gated because only the wasm32 `WsSender` is `!Send`; the native one
//! is genuinely `Send + Sync`.
//!
//! Graduated from `poc/poc17-cf-outbound-ws/src/transport_socketio.rs`
//! (Phase H Step 3 POC) into this crate as Phase H Step 4 sub-gate
//! H-4.3.
//!
//! # Wire shape (matches canonical TS `@bsv/authsocket-client` v2.0.7)
//!
//! Outbound: each `AuthMessage` is JSON-serialized via `serde_json` and
//! emitted as a Socket.IO EVENT packet whose data array is
//! `["authMessage", <json>]` on the default namespace `/`. The
//! canonical TS path at `~/bsv/authsocket-client/src/SocketClientTransport.ts:28`
//! is literally `this.socket.emit('authMessage', message)`; on the wire
//! that's a single Engine.IO `Message(4)` framing
//! `2["authMessage",{<authMessage JSON>}]`.
//!
//! Inbound: the dispatch loop (see [`run_dispatch`]) decodes Engine.IO
//! `Message(4)` frames, extracts the Socket.IO EVENT payload, matches
//! `data[0] == "authMessage"`, deserializes `data[1]` as an
//! [`AuthMessage`], and invokes the registered [`TransportCallback`].
//! Engine.IO Ping frames are auto-replied with Pong via the same
//! [`WsSender`] clone so the relay's `pingTimeout` never fires while a
//! dispatch is in-flight.
//!
//! Server-side reference for the same wire shape:
//! `~/bsv/bsv-messagebox-cloudflare-public/src/engineio/auth.rs:1-26`
//! which explicitly notes: "BRC-103 is layered as a single event named
//! `authMessage` whose only argument is the JSON-serialised
//! `bsv_rs::auth::types::AuthMessage`."

use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use bsv::auth::transports::{Transport, TransportCallback};
use bsv::auth::types::AuthMessage;
use bsv::primitives::PublicKey;
use bsv::wallet::WalletInterface;
use bsv::{Error, Result};
use serde::Serialize;
use serde_json::Value;

use crate::engineio::codec::SocketIoPacket;

#[cfg(not(target_arch = "wasm32"))]
use crate::transport_native::{WsHandle, WsSender};
#[cfg(target_arch = "wasm32")]
use crate::transport_wasm::{WsHandle, WsSender};

/// `bsv_rs::auth::Transport` implementation over a Socket.IO
/// `authMessage` event channel. Cheap to clone (all fields are either
/// `WsSender` handles or `Arc`s); use one clone per consumer
/// ([`bsv::auth::Peer`] consumes one, the dispatch task another).
///
/// Construct via [`SocketIoTransport::new`]; register a callback via
/// the [`Transport::set_callback`] trait method (or indirectly by
/// passing this transport into [`bsv::auth::Peer::new`] and calling
/// `Peer::start`). Use [`SocketIoTransport::callback_handle`] to obtain
/// a clone of the callback slot for the dispatch task.
#[derive(Clone)]
pub struct SocketIoTransport {
    sender: WsSender,
    callback: Arc<StdMutex<Option<Box<TransportCallback>>>>,
}

// SAFETY: wasm32 is single-threaded by construction — the CF Worker
// isolate (and `workerd` in local `wrangler dev`) provably never spawns
// OS threads, so the `!Send + !Sync` `web_sys::WebSocket` held inside
// the wasm32 `WsSender` can never be concurrently accessed across
// threads. The `Send + Sync` bound on `bsv_rs::auth::Transport` is
// required so `Peer` can hold `Arc<T>` and dispatch from boxed
// `Send + 'static` futures, but on `wasm32-unknown-unknown` that
// "cross-thread" guarantee is vacuously satisfied. Same precedent as
// Phase G §2.5 / commit `a9a7e18`. On native the type is genuinely
// `Send + Sync` (the `WsSender` is an `mpsc::UnboundedSender`), so the
// shield is wasm32-only.
#[cfg(target_arch = "wasm32")]
unsafe impl Send for SocketIoTransport {}
#[cfg(target_arch = "wasm32")]
unsafe impl Sync for SocketIoTransport {}

impl SocketIoTransport {
    /// Wrap a [`WsSender`] as a BRC-103 `authMessage` transport. The
    /// callback slot starts empty; either call
    /// [`Transport::set_callback`] directly or call `Peer::start` after
    /// passing this into `Peer::new` to populate it.
    pub fn new(sender: WsSender) -> Self {
        Self {
            sender,
            callback: Arc::new(StdMutex::new(None)),
        }
    }

    /// Return a clone of the callback slot. The dispatch task (see
    /// [`run_dispatch`]) holds one of these so it can find the
    /// registered callback for each inbound `AuthMessage`. Cloning the
    /// `Arc` does NOT clone the callback itself — the registered
    /// `Box<TransportCallback>` lives behind the shared `Mutex`.
    pub fn callback_handle(&self) -> Arc<StdMutex<Option<Box<TransportCallback>>>> {
        self.callback.clone()
    }

    /// The cloneable sender half. Useful for the dispatch loop, which
    /// needs to write Pong replies on inbound Ping frames.
    pub fn sender(&self) -> WsSender {
        self.sender.clone()
    }
}

#[async_trait]
impl Transport for SocketIoTransport {
    async fn send(&self, message: &AuthMessage) -> Result<()> {
        // Serialize the AuthMessage as the second arg of an
        // `["authMessage", <msg>]` Socket.IO EVENT on the default
        // namespace. The canonical TS at
        // `~/bsv/authsocket-client/src/SocketClientTransport.ts:28`
        // does `this.socket.emit('authMessage', message)` — the wire
        // byte-form is identical because socket.io-client serializes
        // the JS object via `JSON.stringify` exactly as `serde_json`
        // does the Rust `AuthMessage` (camelCase per the
        // `#[serde(rename_all = "camelCase")]` on `AuthMessage`).
        let json = serde_json::to_value(message)
            .map_err(|e| Error::AuthError(format!("SocketIoTransport::send: serialize: {e}")))?;
        let pkt = SocketIoPacket::Event {
            nsp: "/".to_string(),
            ack_id: None,
            data: vec![Value::String("authMessage".to_string()), json],
        };
        self.sender
            .send_socketio(&pkt)
            .map_err(|e| Error::AuthError(format!("SocketIoTransport::send: ws: {e}")))
    }

    fn set_callback(&self, callback: Box<TransportCallback>) {
        // `StdMutex` is safe here — on wasm32 there's no contention
        // (one thread); on native it serializes the dispatch task vs.
        // `Peer::start`. Poisoning is theoretical; if it happens we
        // silently drop the registration, matching the
        // `SimplifiedFetchTransport` behaviour at
        // `~/bsv/bsv-rs/src/auth/transports/http.rs`.
        if let Ok(mut cb) = self.callback.lock() {
            *cb = Some(callback);
        }
    }

    fn clear_callback(&self) {
        if let Ok(mut cb) = self.callback.lock() {
            *cb = None;
        }
    }
}

// ============================================================================
// Inbound dispatch loop
// ============================================================================

/// Background dispatch task body. Consumes a [`WsHandle`] (taking
/// ownership of the inbound frame source), reads Engine.IO frames in a
/// loop, and:
///
/// - Replies to inbound Engine.IO `Ping` with `Pong` via the provided
///   [`WsSender`] so the relay heartbeat never fires.
/// - On Engine.IO `Message(4)` carrying a Socket.IO EVENT whose
///   `data[0]` is `"authMessage"`, deserializes `data[1]` as an
///   [`AuthMessage`] and:
///   - If the message is an `InitialResponse` AND `snoop` is populated,
///     sends the full message over the `oneshot` so a caller can observe
///     the handshake completion (server identity + nonce). Subsequent
///     `InitialResponse` frames are NOT re-snooped.
///   - Invokes the registered [`TransportCallback`] (typically the one
///     `Peer::start` installs) so `Peer`'s session manager stays
///     consistent.
/// - Exits the loop on `recv_engineio` error (WS closed).
///
/// Drives one BRC-103 channel; spawn one of these per WS (wasm32:
/// `wasm_bindgen_futures::spawn_local`; native: `tokio::spawn` — the
/// future is `Send` on native because `WsHandle`/`WsSender`/the callback
/// `Arc` are all `Send`).
pub async fn run_dispatch(
    mut ws: WsHandle,
    sender: WsSender,
    callback: Arc<StdMutex<Option<Box<TransportCallback>>>>,
    snoop: Option<futures::channel::oneshot::Sender<AuthMessage>>,
) {
    use crate::engineio::codec::EngineIoPacket;
    use bsv::auth::types::MessageType;

    let mut snoop_slot = snoop;
    loop {
        let frame = match ws.recv_engineio().await {
            Ok(f) => f,
            Err(_) => break, // WS closed — exit dispatch.
        };
        match frame {
            EngineIoPacket::Ping(payload) => {
                let _ = sender.send_engineio(&EngineIoPacket::Pong(payload));
            }
            EngineIoPacket::Message(payload) => {
                let sio = match SocketIoPacket::decode(&payload) {
                    Ok(p) => p,
                    Err(_) => continue, // ignore malformed Socket.IO frames
                };
                if let SocketIoPacket::Event { data, .. } = sio {
                    if data.len() >= 2 && data[0].as_str() == Some("authMessage") {
                        let auth_msg: AuthMessage = match serde_json::from_value(data[1].clone()) {
                            Ok(m) => m,
                            Err(_) => continue,
                        };

                        // Snoop the FULL InitialResponse off the first
                        // post-handshake frame so the caller can observe
                        // BOTH the server's identity AND the server's
                        // session-nonce (needed for the canonical BRC-31
                        // key_id "{our_nonce} {server_nonce}" when
                        // emitting signed Generals). The snoop fires
                        // BEFORE invoking the Peer callback so the caller
                        // doesn't race with the session-manager mutation
                        // Peer performs.
                        if auth_msg.message_type == MessageType::InitialResponse {
                            if let Some(tx) = snoop_slot.take() {
                                let _ = tx.send(auth_msg.clone());
                            }
                        }

                        // Synchronously invoke the callback under the
                        // lock to produce the future; drop the lock
                        // before awaiting. Same pattern as
                        // `SimplifiedFetchTransport::invoke_callback`.
                        let fut_opt = {
                            match callback.lock() {
                                Ok(guard) => guard.as_ref().map(|cb| cb(auth_msg)),
                                Err(_) => None, // poisoned — drop the message
                            }
                        };
                        if let Some(fut) = fut_opt {
                            let _ = fut.await;
                        }
                    }
                }
            }
            _ => { /* Open/Close/Pong/Upgrade/Noop — ignore */ }
        }
    }
}

// ============================================================================
// Application-event envelope layer (H-3.4)
// ============================================================================

/// One application-level event decoded from a post-BRC-103-handshake
/// `MessageType::General` AuthMessage's payload. The payload shape is the
/// canonical `{eventName, data}` JSON envelope used by
/// `~/bsv/authsocket-client/src/AuthSocketClient.ts:82-84`
/// (`encodeEventPayload`) on the wire — byte-identical between the TS
/// canonical and this Rust client. Server-side suffixes
/// `sendMessage`/`sendMessageAck` event names with `-${roomId}` (see
/// `~/bsv/bsv-messagebox-cloudflare-public/src/engineio/session.rs:1574-1580`)
/// so receivers can route by event_name alone without re-parsing data.
#[derive(Debug, Clone, PartialEq)]
pub struct AppEvent {
    /// The signing identity from the inbound General's `identity_key`
    /// field. For server-emitted application events this is always the
    /// server's identity key; left typed as `PublicKey` so the same shape
    /// generalizes to peer-to-peer events (Phase I cosigner gossip).
    pub sender: PublicKey,
    /// The `eventName` field from the payload JSON. Examples emitted by
    /// the live Calhoun relay: `"sendMessage-<roomId>"`,
    /// `"sendMessageAck-<roomId>"`, `"authenticated"`. Empty string when
    /// the payload was missing the field (still surfaces so callers can
    /// observe malformed traffic instead of silently dropping).
    pub event_name: String,
    /// The `data` field from the payload JSON. Type varies by event:
    /// `joinRoom` carries a string roomId, `sendMessage`/`sendMessageAck`
    /// carry a `{roomId, message: {...}}` object, `authenticated` carries
    /// `{}` (per session.rs:1080-1095). Left as `serde_json::Value` so
    /// callers parse the per-event shape themselves.
    pub data: Value,
}

/// Install an inbound listener that decodes every post-BRC-103 General
/// message payload as the canonical `{eventName, data}` envelope (matching
/// `~/bsv/authsocket-client/src/AuthSocketClient.ts:82-84`) and forwards
/// it on an unbounded `mpsc` channel. The returned `Receiver` is the
/// caller's queue of inbound application events; the `u32` is the
/// `Peer::listen_for_general_messages` callback id (pass it to
/// `Peer::stop_listening_for_general_messages` on teardown if needed).
///
/// Requires `Peer::start()` to have been called on the same Peer so
/// the start-callback routes inbound Generals to the
/// `general_message_callbacks` map this helper subscribes to.
///
/// **Requires bsv-rs ≥ 0.3.9** for wasm32 targets. v0.3.8's
/// `Peer::start()` inbound path calls `session.touch()` →
/// `current_time_ms()` → `std::time::SystemTime::now()` which panics
/// on `wasm32-unknown-unknown` (no system-time impl). v0.3.9 cfg-gates
/// the time call to `js_sys::Date::now()` on wasm32 under the
/// existing `wasm` feature.
pub async fn install_app_event_listener<W, T>(
    peer: &bsv::auth::Peer<W, T>,
) -> (futures::channel::mpsc::UnboundedReceiver<AppEvent>, u32)
where
    W: WalletInterface + 'static,
    T: Transport + 'static,
{
    let (tx, rx) = futures::channel::mpsc::unbounded::<AppEvent>();
    let id = peer
        .listen_for_general_messages(move |sender, payload| {
            let tx = tx.clone();
            Box::pin(async move {
                let envelope = parse_app_event_payload(&payload);
                let _ = tx.unbounded_send(AppEvent {
                    sender,
                    event_name: envelope.0,
                    data: envelope.1,
                });
                Ok(())
            })
        })
        .await;
    (rx, id)
}

/// Parse a `{eventName, data}` JSON envelope from a General message's
/// `payload` bytes. Returns `("", Value::Null)` on parse failure so
/// callers can observe malformed traffic without panicking.
///
/// Exposed for unit testing (see the `tests` module below) — the
/// inbound listener uses this helper directly.
fn parse_app_event_payload(payload: &[u8]) -> (String, Value) {
    match serde_json::from_slice::<Value>(payload) {
        Ok(json) => {
            let event_name = json
                .get("eventName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let data = json.get("data").cloned().unwrap_or(Value::Null);
            (event_name, data)
        }
        Err(_) => (String::new(), Value::Null),
    }
}

/// Build the canonical `{eventName, data}` envelope as UTF-8 JSON bytes.
/// Byte-identical to the TS canonical at
/// `~/bsv/authsocket-client/src/AuthSocketClient.ts:82-84`:
///
/// ```ts
/// private encodeEventPayload(eventName: string, data: any): number[] {
///     const obj = { eventName, data }
///     return Utils.toArray(JSON.stringify(obj), 'utf8')
/// }
/// ```
///
/// **Critical wire-compat detail**: JS `JSON.stringify` emits keys in
/// object-literal **insertion order** (`{"eventName":...,"data":...}`).
/// Rust `serde_json::json!({...})` defaults to a `BTreeMap`-backed
/// `Value::Object` which produces **alphabetical order**
/// (`{"data":...,"eventName":...}`) when serialised — unless the
/// `preserve_order` feature is enabled. To match canonical TS without
/// the workspace-wide feature flip, we use a typed `Envelope` struct
/// with `#[derive(Serialize)]`, which serialises fields in
/// **declaration order** (eventName first, data second). Verified by
/// the byte-exact vector tests below.
pub fn build_envelope_payload(event_name: &str, data: &Value) -> Vec<u8> {
    #[derive(Serialize)]
    struct Envelope<'a> {
        #[serde(rename = "eventName")]
        event_name: &'a str,
        data: &'a Value,
    }
    let envelope = Envelope { event_name, data };
    serde_json::to_vec(&envelope).unwrap_or_default()
}

/// Outcome of [`emit_signed_general`] — surfaces the values the caller
/// would otherwise have to reconstruct (the random `msg_nonce_b64` used
/// to derive the BRC-42 signing key + the exact `payload_bytes` that
/// were signed). Returned for tests + telemetry; the BRC-103 wire frame
/// has already left the WS by the time this struct exists.
#[derive(Debug, Clone, PartialEq)]
pub struct EmittedGeneral {
    /// The base64-encoded 32-byte random `nonce` field placed on the
    /// outbound General. Half of the BRC-31 key_id `"{our_nonce} {server_nonce}"`.
    pub msg_nonce_b64: String,
    /// The exact UTF-8 JSON bytes of the `{eventName, data}` envelope
    /// that became the General's `payload` field. Useful for byte-equality
    /// assertions against a reflected `sendMessage-<roomId>` echo.
    pub payload_bytes: Vec<u8>,
}

/// Build, sign, and emit a BRC-31 `MessageType::General` wrapping the
/// canonical `{eventName, data}` envelope as its payload. Byte-identical
/// to the canonical TS path at
/// `~/bsv/authsocket-client/src/AuthSocketClient.ts:59-65`.
///
/// All arguments are passed explicitly so the helper has no implicit
/// state — caller threads through the captured (server_identity,
/// server_nonce, our_identity) tuple from the BRC-103 handshake.
///
/// Cryptographic shape (verified against
/// `~/bsv/bsv-rs/src/auth/peer.rs` `Peer::sign_message`, which is what
/// canonical TS exercises through `peer.toPeer`):
///
/// - `data` signed = the envelope payload bytes verbatim.
/// - `key_id` = `"{msg_nonce_b64} {server_nonce_b64}"`.
/// - `protocol_id` = `Counterparty`-level `"auth message signature"`.
/// - `counterparty` = `Counterparty::Other(server_identity.clone())`.
pub async fn emit_signed_general(
    transport: &SocketIoTransport,
    wallet: &bsv::wallet::ProtoWallet,
    server_identity: &PublicKey,
    server_nonce_b64: &str,
    event_name: &str,
    data: &Value,
) -> std::result::Result<EmittedGeneral, Error> {
    use bsv::auth::types::{MessageType, AUTH_PROTOCOL_ID};
    use bsv::primitives::to_base64;
    use bsv::wallet::{Counterparty, CreateSignatureArgs, Protocol, SecurityLevel};
    use rand::RngCore;

    let payload_bytes = build_envelope_payload(event_name, data);

    let mut nonce_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let msg_nonce_b64 = to_base64(&nonce_bytes);

    let our_identity = wallet.identity_key();
    let mut msg = AuthMessage::new(MessageType::General, our_identity);
    msg.nonce = Some(msg_nonce_b64.clone());
    msg.your_nonce = Some(server_nonce_b64.to_string());
    msg.payload = Some(payload_bytes.clone());

    let key_id = format!("{} {}", msg_nonce_b64, server_nonce_b64);
    let protocol = Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID);
    let counterparty = Counterparty::Other(server_identity.clone());

    let sig_result = wallet
        .create_signature(CreateSignatureArgs {
            data: Some(payload_bytes.clone()),
            hash_to_directly_sign: None,
            protocol_id: protocol,
            key_id,
            counterparty: Some(counterparty),
        })
        .map_err(|e| Error::AuthError(format!("create_signature: {e:?}")))?;
    msg.signature = Some(sig_result.signature);

    transport.send(&msg).await?;

    Ok(EmittedGeneral {
        msg_nonce_b64,
        payload_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_app_event_decodes_joinroom_envelope() {
        let payload = br#"{"eventName":"joinRoom","data":"02abc...xyz-payment_inbox"}"#;
        let (event_name, data) = parse_app_event_payload(payload);
        assert_eq!(event_name, "joinRoom");
        assert_eq!(data, json!("02abc...xyz-payment_inbox"));
    }

    #[test]
    fn parse_app_event_decodes_sendmessage_envelope() {
        let payload = br#"{"eventName":"sendMessage","data":{"roomId":"02abc-test","message":{"messageId":"h34","body":"hello"}}}"#;
        let (event_name, data) = parse_app_event_payload(payload);
        assert_eq!(event_name, "sendMessage");
        assert_eq!(
            data,
            json!({"roomId":"02abc-test","message":{"messageId":"h34","body":"hello"}})
        );
    }

    #[test]
    fn parse_app_event_decodes_sendmessageack_with_room_suffix() {
        let payload = br#"{"eventName":"sendMessageAck-02abc-h34-test","data":{"status":"success","messageId":"h34"}}"#;
        let (event_name, data) = parse_app_event_payload(payload);
        assert_eq!(event_name, "sendMessageAck-02abc-h34-test");
        assert_eq!(data["status"], json!("success"));
        assert_eq!(data["messageId"], json!("h34"));
    }

    #[test]
    fn parse_app_event_handles_empty_data() {
        let payload = br#"{"eventName":"authenticated","data":{}}"#;
        let (event_name, data) = parse_app_event_payload(payload);
        assert_eq!(event_name, "authenticated");
        assert_eq!(data, json!({}));
    }

    #[test]
    fn parse_app_event_returns_empty_on_malformed_json() {
        let payload = b"this is not json";
        let (event_name, data) = parse_app_event_payload(payload);
        assert_eq!(event_name, "");
        assert_eq!(data, Value::Null);
    }

    #[test]
    fn parse_app_event_returns_empty_on_missing_fields() {
        let payload = br#"{"foo":"bar"}"#;
        let (event_name, data) = parse_app_event_payload(payload);
        assert_eq!(event_name, "");
        assert_eq!(data, Value::Null);
    }

    #[test]
    fn parse_app_event_handles_event_name_only() {
        let payload = br#"{"eventName":"someEvent"}"#;
        let (event_name, data) = parse_app_event_payload(payload);
        assert_eq!(event_name, "someEvent");
        assert_eq!(data, Value::Null);
    }

    #[test]
    fn parse_app_event_byte_exact_against_ts_emit_vector() {
        let canonical_ts_bytes: &[u8] = b"{\"eventName\":\"sendMessage\",\"data\":{\"roomId\":\"abc-test\",\"message\":{\"messageId\":\"v1\",\"body\":\"hi\"}}}";
        let (event_name, data) = parse_app_event_payload(canonical_ts_bytes);
        assert_eq!(event_name, "sendMessage");
        assert_eq!(data["roomId"], json!("abc-test"));
        assert_eq!(data["message"]["messageId"], json!("v1"));
        assert_eq!(data["message"]["body"], json!("hi"));
    }

    #[test]
    fn build_envelope_payload_joinroom_byte_exact() {
        let bytes = build_envelope_payload("joinRoom", &json!("02abc-test_inbox"));
        assert_eq!(
            bytes.as_slice(),
            b"{\"eventName\":\"joinRoom\",\"data\":\"02abc-test_inbox\"}".as_slice(),
        );
    }

    #[test]
    fn build_envelope_payload_sendmessage_byte_exact() {
        let bytes = build_envelope_payload(
            "sendMessage",
            &json!({"roomId": "abc-test", "message": {"messageId": "v1", "body": "hi"}}),
        );
        assert_eq!(
            bytes.as_slice(),
            b"{\"eventName\":\"sendMessage\",\"data\":{\"roomId\":\"abc-test\",\"message\":{\"messageId\":\"v1\",\"body\":\"hi\"}}}".as_slice(),
        );
    }

    #[test]
    fn build_envelope_payload_leaveroom_byte_exact() {
        let bytes = build_envelope_payload("leaveRoom", &json!("02abc-test_inbox"));
        assert_eq!(
            bytes.as_slice(),
            b"{\"eventName\":\"leaveRoom\",\"data\":\"02abc-test_inbox\"}".as_slice(),
        );
    }

    #[test]
    fn build_envelope_payload_empty_data_object() {
        let bytes = build_envelope_payload("authenticated", &json!({}));
        assert_eq!(
            bytes.as_slice(),
            b"{\"eventName\":\"authenticated\",\"data\":{}}".as_slice(),
        );
    }

    #[test]
    fn build_envelope_payload_round_trips_through_parser() {
        let cases: Vec<(&str, Value)> = vec![
            ("joinRoom", json!("02abc-room")),
            (
                "sendMessage",
                json!({"roomId": "02abc-room", "message": {"messageId": "m1", "body": "hi"}}),
            ),
            ("leaveRoom", json!("02abc-room")),
            ("authenticated", json!({})),
            ("sendMessageAck-02abc-room", json!({"status": "success"})),
        ];
        for (name, data) in cases {
            let bytes = build_envelope_payload(name, &data);
            let (decoded_name, decoded_data) = parse_app_event_payload(&bytes);
            assert_eq!(decoded_name, name, "event_name round-trip for {name}");
            assert_eq!(decoded_data, data, "data round-trip for {name}");
        }
    }
}
