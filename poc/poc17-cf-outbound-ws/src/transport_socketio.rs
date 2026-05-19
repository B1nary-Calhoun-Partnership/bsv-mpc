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
use bsv::{Error, Result};
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
    use bsv::primitives::PublicKey;
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
        snoop: Option<oneshot::Sender<PublicKey>>,
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

                            // Snoop the server identity off the first
                            // InitialResponse so the H-3.3b route can
                            // return it as JSON proof. Note this must
                            // happen BEFORE invoking the Peer callback
                            // so the route doesn't race with the
                            // session-manager mutation Peer performs.
                            if auth_msg.message_type == MessageType::InitialResponse {
                                if let Some(tx) = snoop_slot.take() {
                                    let _ = tx.send(auth_msg.identity_key.clone());
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
