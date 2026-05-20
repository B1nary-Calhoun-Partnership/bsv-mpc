//! wasm32 transport substrate — `worker::Fetch` (Engine.IO polling
//! handshake) + `web_sys::WebSocket` (WS upgrade phase).
//!
//! Graduated from `poc/poc17-cf-outbound-ws/src/transport_wasm.rs`
//! (Phase H Step 3 POC) into this crate as Phase H Step 4 sub-gate
//! H-4.3. The whole module is `#[cfg(target_arch = "wasm32")]`-gated at
//! the crate root (`lib.rs`); the native counterpart is
//! [`crate::transport_native`], which mirrors this method surface with
//! `tokio-tungstenite` + `reqwest`. Both share
//! [`crate::engineio::codec`] byte-for-byte.
//!
//! Both phases of the Engine.IO 4 client lifecycle live here:
//!   1. [`polling_handshake`] GETs `<relay>/socket.io/?EIO=4&transport=
//!      polling&t=<t>` via `worker::Fetch`; the server returns the
//!      Engine.IO `Open` packet whose payload is the handshake JSON.
//!   2. [`WsHandle::open_and_upgrade`] opens `web_sys::WebSocket` to
//!      `wss://<relay>/socket.io/?EIO=4&transport=websocket&sid=<sid>`
//!      and runs the `2probe`→`3probe`→`5` upgrade dance.

use crate::engineio::codec::EngineIoPacket;
use serde::{Deserialize, Serialize};
use worker::{Error, Fetch, Method, Request, RequestInit, Result};

/// Parsed Engine.IO `Open` handshake payload, returned by the server on
/// the polling-transport GET. Shape per Engine.IO 4 spec.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EngineIoHandshake {
    /// Server-assigned Engine.IO session id.
    pub sid: String,
    /// Transports the server is willing to upgrade to. For our relay
    /// this is `["websocket"]`.
    pub upgrades: Vec<String>,
    /// Server-side heartbeat cadence in ms (server → client pings).
    #[serde(rename = "pingInterval")]
    pub ping_interval: u64,
    /// Heartbeat timeout in ms — if no pong/ping within this window
    /// either side may close.
    #[serde(rename = "pingTimeout")]
    pub ping_timeout: u64,
    /// Max payload size the server will accept on a single packet, in
    /// bytes. The Calhoun relay sets this to 1_000_000 (1 MB) per the
    /// live handshake observed during H-3 prep.
    #[serde(default, rename = "maxPayload")]
    pub max_payload: Option<u64>,
}

/// Initiate an Engine.IO 4 polling handshake against `<relay>/socket.io/`
/// and return the parsed `Open` payload.
///
/// This is the FIRST half of the Engine.IO 4 client lifecycle. The
/// returned `sid` feeds into the subsequent WS upgrade phase
/// ([`WsHandle::open_and_upgrade`]).
///
/// # Wire shape (per the canonical Engine.IO 4 spec, verified live)
///
/// Request:
/// ```text
/// GET https://<relay>/socket.io/?EIO=4&transport=polling&t=<cache-buster>
/// ```
///
/// Response:
/// ```text
/// 200 OK
/// Content-Type: text/plain; charset=UTF-8
/// 0{"sid":"...","upgrades":["websocket"],"pingInterval":25000,"pingTimeout":20000,"maxPayload":1000000}
/// ```
///
/// The leading `0` is the Engine.IO `Open` packet type code; the rest
/// is the handshake JSON. Decode is delegated to
/// [`EngineIoPacket::decode`] from the shared codec.
pub async fn polling_handshake(relay_url: &str) -> Result<EngineIoHandshake> {
    let base = relay_url.trim_end_matches('/');
    // The `t` query-param is a per-request cache-buster per Engine.IO 4
    // spec — CF / Cloudflare caches may otherwise dedupe handshake GETs.
    let t = js_sys::Date::now() as u64;
    let url = format!("{base}/socket.io/?EIO=4&transport=polling&t={t}");

    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    let request = Request::new_with_init(&url, &init)?;

    let mut response = Fetch::Request(request).send().await?;
    let status = response.status_code();
    if !(200..300).contains(&status) {
        return Err(Error::RustError(format!(
            "polling handshake HTTP {status} against {url}"
        )));
    }

    let body = response.text().await?;
    if body.is_empty() {
        return Err(Error::RustError(
            "polling handshake returned empty body".into(),
        ));
    }

    let packet = EngineIoPacket::decode(&body)
        .map_err(|e| Error::RustError(format!("Engine.IO codec: {e}")))?;
    match packet {
        EngineIoPacket::Open(payload) => {
            let handshake: EngineIoHandshake = serde_json::from_str(&payload).map_err(|e| {
                Error::RustError(format!(
                    "handshake JSON decode failed: {e} (payload={payload})"
                ))
            })?;
            Ok(handshake)
        }
        other => Err(Error::RustError(format!(
            "expected Engine.IO Open, got {other:?}"
        ))),
    }
}

// ============================================================================
// WS upgrade via `web_sys::WebSocket`
// ============================================================================
//
// The Engine.IO 4 upgrade dance from a CLIENT perspective:
//
//   1. Open `wss://<relay>/socket.io/?EIO=4&transport=websocket&sid=<sid>`
//   2. Wait for `onopen`.
//   3. Send `2probe` (Engine.IO Ping packet, payload = "probe").
//   4. Wait for `3probe` (Engine.IO Pong packet, payload = "probe").
//   5. Send `5` (Engine.IO Upgrade packet, empty payload).
//   6. WS is now the active Engine.IO transport.

mod ws_upgrade {
    use super::*;
    use crate::engineio::codec::{EngineIoPacket, SocketIoPacket};
    use futures::channel::{mpsc, oneshot};
    use futures::StreamExt;
    use std::cell::RefCell;
    use std::rc::Rc;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsCast;
    use web_sys::{CloseEvent, Event, MessageEvent, WebSocket};

    /// Result of the upgrade dance — returned to callers that only need
    /// the metadata (URL + probe RTT) without the live handle.
    #[derive(Serialize, Debug, Clone)]
    pub struct UpgradeResult {
        pub ws_url: String,
        pub probe_round_trip_ms: f64,
    }

    /// Long-lived WebSocket handle held after the Engine.IO 4 upgrade
    /// completes. Inbound text frames flow through an unbounded mpsc
    /// channel; outbound is via [`WsHandle::send_text`] (or the
    /// higher-level [`WsHandle::send_engineio`]/[`WsHandle::send_socketio`]
    /// helpers).
    ///
    /// **Lifetime**: the underlying `web_sys::WebSocket` is closed when
    /// `WsHandle` drops. Closures are held in the struct so they survive
    /// across calls; dropping `WsHandle` drops the closures too, which
    /// releases the JS-side function references.
    pub struct WsHandle {
        ws: WebSocket,
        msg_rx: mpsc::UnboundedReceiver<std::result::Result<String, String>>,
        url: String,
        probe_round_trip_ms: f64,
        // Held to keep the JS-side callback alive for the lifetime of
        // the handle. Drop order matters: closures must drop BEFORE the
        // WebSocket (otherwise JS-side handlers fire on a dropped Rust
        // closure and panic). Rust drops fields in declaration order,
        // so these come AFTER `ws`. Reversing order would be unsound.
        _on_msg: Closure<dyn FnMut(MessageEvent)>,
        _on_err: Closure<dyn FnMut(Event)>,
        _on_close: Closure<dyn FnMut(CloseEvent)>,
    }

    /// Send-only half of a [`WsHandle`]. Returned by [`WsHandle::sender`]
    /// when a caller needs outbound access independent of the inbound
    /// `mpsc` receiver (e.g. `SocketIoTransport` whose background
    /// dispatch task owns the receiver and whose `Transport::send` impl
    /// runs from a different scope).
    ///
    /// Holds a `Clone` of the underlying `web_sys::WebSocket` JS handle.
    /// Cloning a `web_sys::WebSocket` is a refcount bump on the JS side
    /// — every clone references the same socket.
    #[derive(Clone)]
    pub struct WsSender {
        ws: WebSocket,
    }

    impl WsSender {
        /// Send a raw text frame. Equivalent to [`WsHandle::send_text`].
        pub fn send_text(&self, s: &str) -> std::result::Result<(), String> {
            self.ws
                .send_with_str(s)
                .map_err(|e| format!("ws send_with_str: {e:?}"))
        }

        /// Send an [`EngineIoPacket`]; the codec encodes the wire form.
        pub fn send_engineio(&self, pkt: &EngineIoPacket) -> std::result::Result<(), String> {
            self.send_text(&pkt.encode())
        }

        /// Send a [`SocketIoPacket`] wrapped in Engine.IO `Message(4)`.
        pub fn send_socketio(&self, pkt: &SocketIoPacket) -> std::result::Result<(), String> {
            let wrapped = EngineIoPacket::Message(pkt.encode());
            self.send_engineio(&wrapped)
        }
    }

    impl WsHandle {
        /// Open a WebSocket against `<relay>/socket.io/?...&transport=
        /// websocket&sid=<sid>` and complete the Engine.IO 4 upgrade
        /// dance (`2probe` → `3probe` → `5` Upgrade). Returns the live
        /// handle ready for `emit`/`recv` operations.
        pub async fn open_and_upgrade(
            relay_url: &str,
            sid: &str,
        ) -> std::result::Result<Self, String> {
            let base = relay_url.trim_end_matches('/');
            let ws_base = if let Some(rest) = base.strip_prefix("https://") {
                format!("wss://{rest}")
            } else if let Some(rest) = base.strip_prefix("http://") {
                format!("ws://{rest}")
            } else {
                base.to_string()
            };
            let url = format!("{ws_base}/socket.io/?EIO=4&transport=websocket&sid={sid}");

            let ws = WebSocket::new(&url).map_err(|e| format!("WebSocket::new({url}): {e:?}"))?;
            ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

            // ── Wait for onopen ──
            let (open_tx, open_rx) = oneshot::channel::<std::result::Result<(), String>>();
            let open_tx = Rc::new(RefCell::new(Some(open_tx)));

            let open_tx_for_open = open_tx.clone();
            let on_open: Closure<dyn FnMut(Event)> = Closure::new(move |_e: Event| {
                if let Some(t) = open_tx_for_open.borrow_mut().take() {
                    let _ = t.send(Ok(()));
                }
            });
            ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));

            // ── Persistent inbound message channel (unbounded mpsc) ──
            // Set up BEFORE awaiting open so the FIRST server-sent frame
            // after the upgrade isn't dropped.
            let (msg_tx, msg_rx) = mpsc::unbounded::<std::result::Result<String, String>>();
            let msg_tx_for_msg = msg_tx.clone();
            let on_msg: Closure<dyn FnMut(MessageEvent)> = Closure::new(move |e: MessageEvent| {
                // Engine.IO 4 AuthSocket profile uses text frames only.
                if let Some(text) = e.data().as_string() {
                    let _ = msg_tx_for_msg.unbounded_send(Ok(text));
                }
            });
            ws.set_onmessage(Some(on_msg.as_ref().unchecked_ref()));

            let open_tx_for_err = open_tx.clone();
            let msg_tx_for_err = msg_tx.clone();
            let on_err: Closure<dyn FnMut(Event)> = Closure::new(move |e: Event| {
                let err = format!("ws onerror: {e:?}");
                // Surface the error on whichever channel is still listening.
                if let Some(t) = open_tx_for_err.borrow_mut().take() {
                    let _ = t.send(Err(err.clone()));
                }
                let _ = msg_tx_for_err.unbounded_send(Err(err));
            });
            ws.set_onerror(Some(on_err.as_ref().unchecked_ref()));

            let msg_tx_for_close = msg_tx.clone();
            let on_close: Closure<dyn FnMut(CloseEvent)> = Closure::new(move |e: CloseEvent| {
                let _ = msg_tx_for_close.unbounded_send(Err(format!(
                    "ws closed: code={} reason={:?}",
                    e.code(),
                    e.reason()
                )));
            });
            ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));

            // Drop the strong refs to msg_tx so the mpsc closes when all
            // closures drop. (Otherwise `msg_rx.next()` would never see
            // a None — it'd hang forever on a dropped WS.)
            drop(msg_tx);

            let t_probe_start = js_sys::Date::now();

            // Await the onopen event.
            open_rx
                .await
                .map_err(|_| "ws open channel dropped".to_string())??;

            // Send `2probe` (Engine.IO Ping with payload="probe").
            let probe_packet = EngineIoPacket::Ping("probe".to_string()).encode();
            ws.send_with_str(&probe_packet)
                .map_err(|e| format!("ws send 2probe: {e:?}"))?;

            let mut msg_rx_drain = msg_rx;
            // Await the server's `3probe` reply. We pull from the
            // persistent mpsc; any frames the server sent in the same
            // window stay queued for subsequent recv calls.
            let pong_text = msg_rx_drain
                .next()
                .await
                .ok_or_else(|| "ws closed before pong".to_string())??;
            match EngineIoPacket::decode(&pong_text).map_err(|e| format!("decode pong: {e}"))? {
                EngineIoPacket::Pong(payload) if payload == "probe" => { /* expected */ }
                other => return Err(format!("expected Pong(\"probe\"), got {other:?}")),
            }
            let probe_round_trip_ms = js_sys::Date::now() - t_probe_start;

            // Commit the upgrade — send Engine.IO `5` (Upgrade) packet.
            let upgrade_packet = EngineIoPacket::Upgrade.encode();
            ws.send_with_str(&upgrade_packet)
                .map_err(|e| format!("ws send Upgrade: {e:?}"))?;

            Ok(WsHandle {
                ws,
                msg_rx: msg_rx_drain,
                url,
                probe_round_trip_ms,
                _on_msg: on_msg,
                _on_err: on_err,
                _on_close: on_close,
            })
        }

        pub fn url(&self) -> &str {
            &self.url
        }

        pub fn probe_round_trip_ms(&self) -> f64 {
            self.probe_round_trip_ms
        }

        /// Send a raw text frame. Lower-level than `send_engineio` /
        /// `send_socketio`; useful for probe/upgrade-style packets.
        pub fn send_text(&self, s: &str) -> std::result::Result<(), String> {
            self.ws
                .send_with_str(s)
                .map_err(|e| format!("ws send_with_str: {e:?}"))
        }

        /// Send an [`EngineIoPacket`] (the codec encodes the wire form).
        pub fn send_engineio(&self, pkt: &EngineIoPacket) -> std::result::Result<(), String> {
            self.send_text(&pkt.encode())
        }

        /// Send a [`SocketIoPacket`] wrapped in Engine.IO `Message(4)`.
        pub fn send_socketio(&self, pkt: &SocketIoPacket) -> std::result::Result<(), String> {
            let wrapped = EngineIoPacket::Message(pkt.encode());
            self.send_engineio(&wrapped)
        }

        /// Return a cheap, cloneable [`WsSender`] that can be handed to
        /// callers (e.g. `SocketIoTransport`) which only need outbound
        /// access. The underlying `web_sys::WebSocket` is a JS-handle and
        /// `Clone` is a refcount bump on the JS side — sends from any
        /// clone reach the same socket. The owning [`WsHandle`] retains
        /// the closures + the inbound `mpsc` receiver and remains the
        /// sole owner of teardown (its `Drop` impl detaches the JS
        /// callbacks and closes the connection).
        pub fn sender(&self) -> WsSender {
            WsSender {
                ws: self.ws.clone(),
            }
        }

        /// Receive the next inbound text frame. Returns `Ok(None)` if
        /// the channel has closed (WS dropped).
        pub async fn recv_text(&mut self) -> Option<std::result::Result<String, String>> {
            self.msg_rx.next().await
        }

        /// Convenience: receive the next inbound frame and decode as an
        /// Engine.IO packet via the shared codec.
        pub async fn recv_engineio(&mut self) -> std::result::Result<EngineIoPacket, String> {
            let text = self
                .recv_text()
                .await
                .ok_or_else(|| "ws closed".to_string())??;
            EngineIoPacket::decode(&text).map_err(|e| format!("decode engineio: {e}"))
        }

        /// Convenience: receive an inbound frame and decode through both
        /// the Engine.IO and Socket.IO layers, returning the inner
        /// Socket.IO packet.
        ///
        /// Returns `Err` if the inbound packet is NOT an Engine.IO
        /// `Message(...)` carrying a Socket.IO payload. Other Engine.IO
        /// types (Ping/Pong/etc) surface via [`Self::recv_engineio`] instead.
        pub async fn recv_socketio(&mut self) -> std::result::Result<SocketIoPacket, String> {
            let eio = self.recv_engineio().await?;
            match eio {
                EngineIoPacket::Message(payload) => {
                    SocketIoPacket::decode(&payload).map_err(|e| format!("decode socketio: {e}"))
                }
                other => Err(format!("expected Engine.IO Message, got {other:?}")),
            }
        }
    }

    impl Drop for WsHandle {
        fn drop(&mut self) {
            // Detach JS-side handlers BEFORE the closures drop (which
            // happens automatically after this fn returns). Otherwise a
            // late-firing event would call into a dropped Rust closure.
            self.ws.set_onmessage(None);
            self.ws.set_onerror(None);
            self.ws.set_onclose(None);
            self.ws.set_onopen(None);
            // CloseEvent code 1000 = normal closure.
            let _ = self.ws.close_with_code(1000);
        }
    }

    /// Convenience: open + upgrade + drop. Same shape as the native
    /// counterpart so callers that only need the metadata don't hold the
    /// live handle.
    pub async fn upgrade_to_websocket(
        relay_url: &str,
        sid: &str,
    ) -> std::result::Result<UpgradeResult, String> {
        let handle = WsHandle::open_and_upgrade(relay_url, sid).await?;
        Ok(UpgradeResult {
            ws_url: handle.url().to_string(),
            probe_round_trip_ms: handle.probe_round_trip_ms(),
        })
    }
}

pub use ws_upgrade::{upgrade_to_websocket, UpgradeResult, WsHandle, WsSender};
