//! `SocketIoTransport` — `bsv_rs::auth::Transport` implementation that
//! drives the BRC-103 `authMessage` event channel over the Socket.IO
//! layer atop the [`crate::transport_wasm::WsHandle`] substrate.
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
//! [`WsSender`] clone so the relay's `pingTimeout` (20s on the Calhoun
//! relay per H-3.2 handshake) never fires while a dispatch is
//! in-flight.
//!
//! Server-side reference for the same wire shape:
//! `~/bsv/bsv-messagebox-cloudflare-public/src/engineio/auth.rs:1-26`
//! which explicitly notes: "BRC-103 is layered as a single event named
//! `authMessage` whose only argument is the JSON-serialised
//! `bsv_rs::auth::types::AuthMessage`." That note also independently
//! confirms why we cannot use `bsv_rs::auth::Peer::initiate_handshake`
//! to drive the protocol from CF Worker scope — `Peer` is built around
//! `tokio::sync::{RwLock, oneshot}` and `tokio::time::timeout` at
//! `~/bsv/bsv-rs/src/auth/peer.rs:681`, none of which run on
//! `wasm32-unknown-unknown` (no tokio runtime in CF Workers). The
//! upstream PR to swap that for a runtime-agnostic select-with-timeout
//! is tracked for Phase H Step 4 per audit §11.2; for H-3.3b we route
//! around it by triggering the InitialRequest manually
//! (`transport.send(&msg).await`) and snooping the InitialResponse off
//! the dispatch loop.
//!
//! # Threading model
//!
//! `wasm32-unknown-unknown` is single-threaded — the CF Worker isolate
//! never spawns OS threads. `web_sys::WebSocket` is `!Send + !Sync`
//! because its underlying JS-handle storage is thread-local on browsers
//! that DO have worker threads, but on `wasm32-unknown-unknown` /
//! `workerd` there is provably one thread. The
//! [`bsv_rs::auth::Transport`] trait at
//! `~/bsv/bsv-rs/src/auth/transports/http.rs:30` requires `Send + Sync`
//! so the [`Peer`](bsv::auth::Peer) can hold a transport behind an
//! `Arc<T>` and dispatch from boxed `Send + 'static` futures. We
//! satisfy the bound with an `unsafe impl Send + Sync` shield citing
//! the Phase G §2.5 / commit `a9a7e18` precedent (the same shield used
//! by `DkgCoordinator` et al for the same `!Send` reason).

use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use bsv::auth::transports::{Transport, TransportCallback};
use bsv::auth::types::AuthMessage;
use bsv::primitives::PublicKey;
use bsv::wallet::WalletInterface;
use bsv::{Error, Result};
use serde::Serialize;
use serde_json::Value;

use crate::engineio_codec::SocketIoPacket;
use crate::transport_wasm::WsSender;

/// `bsv_rs::auth::Transport` implementation over a Socket.IO
/// `authMessage` event channel. Cheap to clone (all fields are either
/// JS-handle clones or `Arc`s); use one clone per consumer
/// ([`bsv::auth::Peer`] consumes one, the dispatch task another).
///
/// Construct via [`SocketIoTransport::new`]; register a callback via
/// the [`Transport::set_callback`] trait method (or indirectly by
/// passing this transport into [`bsv::auth::Peer::new`] and calling
/// [`Peer::start`](bsv::auth::Peer::start)). Use [`callback_handle`]
/// to obtain a clone of the callback slot for the dispatch task.
///
/// [`callback_handle`]: SocketIoTransport::callback_handle
#[derive(Clone)]
pub struct SocketIoTransport {
    sender: WsSender,
    callback: Arc<StdMutex<Option<Box<TransportCallback>>>>,
}

// SAFETY: wasm32 is single-threaded by construction — the CF Worker
// isolate (and `workerd` in local `wrangler dev`) provably never spawns
// OS threads, so the `!Send + !Sync` `web_sys::WebSocket` held inside
// `WsSender` can never be concurrently accessed across threads. The
// `Send + Sync` bound on `bsv_rs::auth::Transport` is required so
// `Peer` can hold `Arc<T>` and dispatch from boxed `Send + 'static`
// futures, but on `wasm32-unknown-unknown` that "cross-thread" guarantee
// is vacuously satisfied. Same precedent as Phase G §2.5 / commit
// `a9a7e18` on the inline DkgCoordinator/SigningCoordinator/PresigningCoordinator
// (see `crates/bsv-mpc-core/src/dkg.rs`).
#[cfg(target_arch = "wasm32")]
unsafe impl Send for SocketIoTransport {}
#[cfg(target_arch = "wasm32")]
unsafe impl Sync for SocketIoTransport {}

impl SocketIoTransport {
    /// Wrap a [`WsSender`] as a BRC-103 `authMessage` transport. The
    /// callback slot starts empty; either call
    /// [`Transport::set_callback`] directly or call
    /// [`Peer::start`](bsv::auth::Peer::start) after passing this into
    /// `Peer::new` to populate it.
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
        // `StdMutex` is wasm32-safe — no contention because only one
        // thread exists. Poisoning is theoretical; if it happens we
        // silently drop the registration, matching the
        // `SimplifiedFetchTransport` behaviour at
        // `~/bsv/bsv-rs/src/auth/transports/http.rs:835`.
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

#[cfg(target_arch = "wasm32")]
mod dispatch {
    use super::*;
    use crate::engineio_codec::EngineIoPacket;
    use crate::transport_wasm::WsHandle;
    use bsv::auth::types::MessageType;
    use futures::channel::oneshot;

    /// Background dispatch task body. Consumes a [`WsHandle`] (taking
    /// ownership of the inbound `mpsc` receiver), reads Engine.IO
    /// frames in a loop, and:
    ///
    /// - Replies to inbound Engine.IO `Ping` with `Pong` via the
    ///   provided [`WsSender`] so the relay heartbeat never fires.
    /// - On Engine.IO `Message(4)` carrying a Socket.IO EVENT whose
    ///   `data[0]` is `"authMessage"`, deserializes `data[1]` as an
    ///   [`AuthMessage`] and:
    ///   - If the message is an `InitialResponse` AND `snoop` is
    ///     populated, sends the server's identity key over the
    ///     `oneshot` so the H-3.3b route handler can observe the
    ///     handshake completion. Subsequent `InitialResponse` frames
    ///     (which the protocol does not allow) are NOT re-snooped.
    ///   - Invokes the registered [`TransportCallback`] (typically the
    ///     one [`Peer::start`](bsv::auth::Peer::start) installs) so
    ///     `Peer`'s session manager stays consistent.
    /// - Exits the loop on `recv_engineio` error (WS closed), letting
    ///   the [`WsHandle`] drop and tear down the JS-side handlers.
    ///
    /// Drives one BRC-103 channel; spawn one of these per WS via
    /// `wasm_bindgen_futures::spawn_local`.
    pub async fn run_dispatch(
        mut ws: WsHandle,
        sender: WsSender,
        callback: Arc<StdMutex<Option<Box<TransportCallback>>>>,
        snoop: Option<oneshot::Sender<AuthMessage>>,
    ) {
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
                            let auth_msg: AuthMessage =
                                match serde_json::from_value(data[1].clone()) {
                                    Ok(m) => m,
                                    Err(_) => continue,
                                };

                            // Snoop the FULL InitialResponse off the first
                            // post-handshake frame so the route handler can
                            // observe BOTH the server's identity AND the
                            // server's session-nonce (needed for the
                            // canonical BRC-31 key_id "{our_nonce}
                            // {server_nonce}" when emitting signed Generals
                            // in H-3.4). The snoop fires BEFORE invoking
                            // the Peer callback so the route doesn't race
                            // with the session-manager mutation Peer
                            // performs.
                            if auth_msg.message_type == MessageType::InitialResponse {
                                if let Some(tx) = snoop_slot.take() {
                                    let _ = tx.send(auth_msg.clone());
                                }
                            }

                            // Synchronously invoke the callback under
                            // the lock to produce the future; drop the
                            // lock before awaiting. Same pattern as
                            // `SimplifiedFetchTransport::invoke_callback`
                            // at `~/bsv/bsv-rs/src/auth/transports/http.rs:582`.
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
}

#[cfg(target_arch = "wasm32")]
pub use dispatch::run_dispatch;

#[cfg(not(target_arch = "wasm32"))]
/// Native stub — `run_dispatch` is wasm32-only since it consumes the
/// wasm32-only [`WsHandle`] inbound `mpsc` receiver and spawns nothing
/// (the route handler does the spawn via `wasm_bindgen_futures::spawn_local`).
/// Present so `cargo build --workspace --all-targets` compiles on native.
pub async fn run_dispatch(
    _ws: crate::transport_wasm::WsHandle,
    _sender: WsSender,
    _callback: Arc<StdMutex<Option<Box<TransportCallback>>>>,
    _snoop: Option<futures::channel::oneshot::Sender<AuthMessage>>,
) {
    // wasm32-only — see #[cfg(target_arch = "wasm32")] mod dispatch.
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
///
/// JS `JSON.stringify` and Rust `serde_json::to_vec` produce identical
/// byte output for ASCII keys + ASCII-or-UTF-8 string values + the
/// numeric / object / array / null / boolean primitives used by every
/// MessageBox event (`joinRoom`, `sendMessage`, `sendMessageAck`,
/// `leaveRoom`, `authenticated`). Non-ASCII characters in values may
/// diverge (TS uses `\uXXXX` escapes for some code points; serde_json
/// defaults to raw UTF-8) — pin per-event vectors in the unit tests
/// below if a future event introduces non-ASCII payloads.
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
/// `~/bsv/authsocket-client/src/AuthSocketClient.ts:59-65`:
///
/// ```ts
/// emit(eventName: string, data: any): this {
///     const encoded = this.encodeEventPayload(eventName, data)
///     this.peer.toPeer(encoded, this.serverIdentityKey).catch(...)
///     return this
/// }
/// ```
///
/// Sidesteps `Peer::to_peer` for the same reason H-3.3b sidesteps
/// `Peer::initiate_handshake` — `to_peer` routes through
/// `get_authenticated_session(identity_key, max_wait_time)` which falls
/// through to `initiate_handshake` on cache miss (at
/// `~/bsv/bsv-rs/src/auth/peer.rs:376`), and `initiate_handshake` uses
/// `tokio::time::timeout` which panics in wasm32 CF Worker scope.
/// Reading the cached session would be safe IF we could guarantee the
/// session manager already has the entry — which it does after H-3.3b's
/// snoop oneshot fires AND `Peer::start()`'s callback has finished
/// processing the InitialResponse. That ordering is fragile; constructing
/// the General manually (Path 2) is unambiguously correct.
///
/// All arguments are passed explicitly so the helper has no implicit
/// state — caller threads through the captured (server_identity,
/// server_nonce, our_identity) tuple from the BRC-103 handshake.
///
/// Cryptographic shape (verified against `~/bsv/bsv-rs/src/auth/peer.rs:582-608`
/// `Peer::sign_message`, which is what canonical TS exercises through
/// `peer.toPeer`):
///
/// - `data` signed = the envelope payload bytes verbatim (per
///   `AuthMessage::signing_data()` for `General` at `types.rs:163-166`).
/// - `key_id` = `"{msg_nonce_b64} {server_nonce_b64}"` (per
///   `AuthMessage::get_key_id` `_` arm at `types.rs:206-210`).
/// - `protocol_id` = `Counterparty`-level `"auth message signature"`
///   (per `AUTH_PROTOCOL_ID` at `types.rs:18`).
/// - `counterparty` = `Counterparty::Other(server_identity.clone())` —
///   ECDSA over the BRC-42-derived key for THIS particular peer.
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

    // Unit tests for parse_app_event_payload — the canonical envelope
    // decoder. Wire-shape pinned against the TS encoding at
    // `~/bsv/authsocket-client/src/AuthSocketClient.ts:82-84`:
    //   private encodeEventPayload(eventName: string, data: any): number[] {
    //       const obj = { eventName, data }
    //       return Utils.toArray(JSON.stringify(obj), 'utf8')
    //   }
    // So the wire is `Utils.toArray(JSON.stringify({eventName, data}))` —
    // i.e. UTF-8 bytes of a JSON object with exactly those two top-level
    // keys. We assert byte-exact decode against literal vectors.

    #[test]
    fn parse_app_event_decodes_joinroom_envelope() {
        // Canonical joinRoom payload — TS emits `{eventName: "joinRoom",
        // data: roomId}` where roomId is a plain string.
        let payload = br#"{"eventName":"joinRoom","data":"02abc...xyz-payment_inbox"}"#;
        let (event_name, data) = parse_app_event_payload(payload);
        assert_eq!(event_name, "joinRoom");
        assert_eq!(data, json!("02abc...xyz-payment_inbox"));
    }

    #[test]
    fn parse_app_event_decodes_sendmessage_envelope() {
        // Canonical sendMessage payload — TS emits
        // `{eventName: "sendMessage", data: {roomId, message: {...}}}`.
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
        // Inbound sendMessageAck event name has `-{roomId}` server-side
        // suffix per `~/bsv/bsv-messagebox-cloudflare-public/src/engineio/session.rs:1574-1580`.
        let payload = br#"{"eventName":"sendMessageAck-02abc-h34-test","data":{"status":"success","messageId":"h34"}}"#;
        let (event_name, data) = parse_app_event_payload(payload);
        assert_eq!(event_name, "sendMessageAck-02abc-h34-test");
        assert_eq!(data["status"], json!("success"));
        assert_eq!(data["messageId"], json!("h34"));
    }

    #[test]
    fn parse_app_event_handles_empty_data() {
        // The post-auth `authenticated` event carries `data: {}` per
        // `~/bsv/bsv-messagebox-cloudflare-public/src/engineio/session.rs:1080-1095`.
        let payload = br#"{"eventName":"authenticated","data":{}}"#;
        let (event_name, data) = parse_app_event_payload(payload);
        assert_eq!(event_name, "authenticated");
        assert_eq!(data, json!({}));
    }

    #[test]
    fn parse_app_event_returns_empty_on_malformed_json() {
        // Non-JSON payload — server shouldn't emit this, but we don't
        // panic either. Empty event_name signals the inbound observer
        // that the envelope was unparseable.
        let payload = b"this is not json";
        let (event_name, data) = parse_app_event_payload(payload);
        assert_eq!(event_name, "");
        assert_eq!(data, Value::Null);
    }

    #[test]
    fn parse_app_event_returns_empty_on_missing_fields() {
        // Well-formed JSON but missing both expected fields.
        let payload = br#"{"foo":"bar"}"#;
        let (event_name, data) = parse_app_event_payload(payload);
        assert_eq!(event_name, "");
        assert_eq!(data, Value::Null);
    }

    #[test]
    fn parse_app_event_handles_event_name_only() {
        // `eventName` present, `data` missing — surface event_name and
        // null data rather than dropping the entire envelope.
        let payload = br#"{"eventName":"someEvent"}"#;
        let (event_name, data) = parse_app_event_payload(payload);
        assert_eq!(event_name, "someEvent");
        assert_eq!(data, Value::Null);
    }

    #[test]
    fn parse_app_event_byte_exact_against_ts_emit_vector() {
        // Vector test: this is the EXACT byte sequence the TS canonical
        // client at `~/bsv/authsocket-client/src/AuthSocketClient.ts:82-84`
        // produces for emit("sendMessage", {roomId: "abc-test", message:
        // {messageId: "v1", body: "hi"}}) — verified by reading
        // `Utils.toArray(JSON.stringify({eventName, data}), 'utf8')`
        // which is just UTF-8 bytes of `JSON.stringify(...)`. JS
        // JSON.stringify produces no whitespace and preserves insertion
        // order of object literals; our parser matches.
        let canonical_ts_bytes: &[u8] = b"{\"eventName\":\"sendMessage\",\"data\":{\"roomId\":\"abc-test\",\"message\":{\"messageId\":\"v1\",\"body\":\"hi\"}}}";
        let (event_name, data) = parse_app_event_payload(canonical_ts_bytes);
        assert_eq!(event_name, "sendMessage");
        assert_eq!(data["roomId"], json!("abc-test"));
        assert_eq!(data["message"]["messageId"], json!("v1"));
        assert_eq!(data["message"]["body"], json!("hi"));
    }

    // ====================================================================
    // build_envelope_payload — outbound vector tests
    //
    // These prove the OUTBOUND envelope wire bytes are byte-identical to
    // what the TS canonical produces. If any of these break, the live
    // relay will see a different `payload` shape than `peer.toPeer`
    // produces from the TS client, and the `Peer`-installed server-side
    // signature verifier will reject the General. These unit tests catch
    // the regression LOCALLY before the empirical /envelope-roundtrip
    // gate (H-3.4.C) has to.
    // ====================================================================

    #[test]
    fn build_envelope_payload_joinroom_byte_exact() {
        // Canonical TS `emit('joinRoom', '02abc-test_inbox')` produces:
        //   JSON.stringify({eventName: "joinRoom", data: "02abc-test_inbox"})
        //   = '{"eventName":"joinRoom","data":"02abc-test_inbox"}'
        let bytes = build_envelope_payload("joinRoom", &json!("02abc-test_inbox"));
        assert_eq!(
            bytes.as_slice(),
            b"{\"eventName\":\"joinRoom\",\"data\":\"02abc-test_inbox\"}".as_slice(),
        );
    }

    #[test]
    fn build_envelope_payload_sendmessage_byte_exact() {
        // Canonical TS `emit('sendMessage', {roomId: "abc-test", message:
        // {messageId: "v1", body: "hi"}})` produces:
        //   JSON.stringify({eventName: "sendMessage", data: {roomId: "abc-test",
        //                   message: {messageId: "v1", body: "hi"}}})
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
        // Canonical TS `emit('leaveRoom', '02abc-test_inbox')`.
        let bytes = build_envelope_payload("leaveRoom", &json!("02abc-test_inbox"));
        assert_eq!(
            bytes.as_slice(),
            b"{\"eventName\":\"leaveRoom\",\"data\":\"02abc-test_inbox\"}".as_slice(),
        );
    }

    #[test]
    fn build_envelope_payload_empty_data_object() {
        // Some events have no data — TS passes `{}` (empty object).
        let bytes = build_envelope_payload("authenticated", &json!({}));
        assert_eq!(
            bytes.as_slice(),
            b"{\"eventName\":\"authenticated\",\"data\":{}}".as_slice(),
        );
    }

    #[test]
    fn build_envelope_payload_round_trips_through_parser() {
        // Property test: anything build_envelope_payload produces, the
        // parser MUST decode back to the same (event_name, data) tuple.
        // Covers the entire envelope layer round-trip in one assertion.
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
