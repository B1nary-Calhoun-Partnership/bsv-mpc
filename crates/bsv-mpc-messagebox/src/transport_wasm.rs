//! wasm32 WS substrate for the upstream Socket.IO + BRC-103 transport —
//! `worker::Fetch` (Engine.IO polling handshake) + `web_sys::WebSocket`
//! (WS upgrade phase).
//!
//! Provides the wasm32 implementations of the bsv-rs `socketio`
//! substrate traits:
//!
//! - [`WsSender`] implements [`bsv::auth::SocketIoSink`] (outbound).
//! - [`WsHandle`] implements [`bsv::auth::SocketIoFrameSource`] (inbound)
//!   and owns the Engine.IO 4 handshake/upgrade dance.
//!
//! Plugged into the upstream `bsv::auth::SocketIoTransport<WsSender>` +
//! `bsv::auth::run_dispatch`, so all Socket.IO / BRC-103 protocol logic
//! lives in bsv-rs 0.3.10; this module is purely the wasm32 transport
//! plumbing. The native counterpart is [`crate::transport_native`].
//!
//! The whole module is `#[cfg(target_arch = "wasm32")]`-gated at the
//! crate root (`lib.rs`).
//!
//! Both phases of the Engine.IO 4 client lifecycle live here:
//!   1. [`polling_handshake`] GETs `<relay>/socket.io/?EIO=4&transport=
//!      polling&t=<t>` via `worker::Fetch`; the server returns the
//!      Engine.IO `Open` packet whose payload is the handshake JSON.
//!   2. [`WsHandle::open_and_upgrade`] opens `web_sys::WebSocket` to
//!      `wss://<relay>/socket.io/?EIO=4&transport=websocket&sid=<sid>`
//!      and runs the `2probe`→`3probe`→`5` upgrade dance.

use bsv::auth::transports::socketio::codec::EngineIoPacket;
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
    /// bytes. The Calhoun relay sets this to 1_000_000 (1 MB).
    #[serde(default, rename = "maxPayload")]
    pub max_payload: Option<u64>,
}

/// Initiate an Engine.IO 4 polling handshake against `<relay>/socket.io/`
/// and return the parsed `Open` payload. The returned `sid` feeds the
/// subsequent WS upgrade phase ([`WsHandle::open_and_upgrade`]).
pub async fn polling_handshake(relay_url: &str) -> Result<EngineIoHandshake> {
    let base = relay_url.trim_end_matches('/');
    // Per-request cache-buster per Engine.IO 4 spec.
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
//   1. Open `wss://<relay>/socket.io/?EIO=4&transport=websocket&sid=<sid>`
//   2. Wait for `onopen`.
//   3. Send `2probe` (Engine.IO Ping packet, payload = "probe").
//   4. Wait for `3probe` (Engine.IO Pong packet, payload = "probe").
//   5. Send `5` (Engine.IO Upgrade packet, empty payload).
//   6. WS is now the active Engine.IO transport.

mod ws_upgrade {
    use super::*;
    use bsv::auth::transports::socketio::codec::{EngineIoPacket, SocketIoPacket};
    use bsv::auth::{SocketIoFrameSource, SocketIoSink};
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
    /// channel ([`SocketIoFrameSource::recv_engineio`]); outbound is via
    /// the cloneable [`WsSender`] ([`SocketIoSink`]).
    ///
    /// **Lifetime**: the underlying `web_sys::WebSocket` is closed when
    /// `WsHandle` drops. Closures are held in the struct so they survive
    /// across calls; dropping `WsHandle` drops the closures too.
    pub struct WsHandle {
        ws: WebSocket,
        msg_rx: mpsc::UnboundedReceiver<std::result::Result<String, String>>,
        url: String,
        probe_round_trip_ms: f64,
        // Held to keep the JS-side callback alive for the lifetime of
        // the handle. Drop order matters: closures must drop BEFORE the
        // WebSocket. Rust drops fields in declaration order, so these
        // come AFTER `ws`.
        _on_msg: Closure<dyn FnMut(MessageEvent)>,
        _on_err: Closure<dyn FnMut(Event)>,
        _on_close: Closure<dyn FnMut(CloseEvent)>,
    }

    /// Send-only half of a [`WsHandle`]. Holds a `Clone` of the
    /// underlying `web_sys::WebSocket` JS handle (a refcount bump). Backs
    /// an upstream `bsv::auth::SocketIoTransport` via [`SocketIoSink`].
    #[derive(Clone)]
    pub struct WsSender {
        ws: WebSocket,
    }

    // SAFETY: wasm32 is single-threaded by construction — the CF Worker
    // isolate (and `workerd` in local `wrangler dev`) provably never
    // spawns OS threads, so the `!Send + !Sync` `web_sys::WebSocket` +
    // `Closure`s held here can never be concurrently accessed across
    // threads. The `Send + Sync` bound on `bsv::auth::SocketIoSink` (and
    // `Send` on `SocketIoFrameSource`) is required so the upstream
    // `Peer`/`run_dispatch` can hold/drive them across boxed
    // `Send + 'static` futures, but on `wasm32-unknown-unknown` that
    // cross-thread guarantee is vacuously satisfied. Same precedent as
    // Phase G §2.5 / commit `a9a7e18`. On native the equivalents are
    // genuinely `Send + Sync` (see `crate::transport_native`), so this
    // shield is wasm32-only.
    unsafe impl Send for WsSender {}
    unsafe impl Sync for WsSender {}
    unsafe impl Send for WsHandle {}
    unsafe impl Sync for WsHandle {}

    impl WsSender {
        /// Send a raw text frame.
        fn send_text(&self, s: &str) -> std::result::Result<(), String> {
            self.ws
                .send_with_str(s)
                .map_err(|e| format!("ws send_with_str: {e:?}"))
        }
    }

    impl SocketIoSink for WsSender {
        fn send_socketio(&self, pkt: &SocketIoPacket) -> std::result::Result<(), String> {
            self.send_text(&EngineIoPacket::Message(pkt.encode()).encode())
        }

        /// Override the trait default so we can emit non-`Message`
        /// Engine.IO packets directly (e.g. `Pong` heartbeat replies).
        fn send_engineio(&self, pkt: &EngineIoPacket) -> std::result::Result<(), String> {
            self.send_text(&pkt.encode())
        }
    }

    impl WsHandle {
        /// Open a WebSocket against `<relay>/socket.io/?...&transport=
        /// websocket&sid=<sid>` and complete the Engine.IO 4 upgrade
        /// dance (`2probe` → `3probe` → `5` Upgrade). Returns the live
        /// handle ready for `recv_engineio` + a [`WsSender`].
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
            // closures drop.
            drop(msg_tx);

            let t_probe_start = js_sys::Date::now();

            open_rx
                .await
                .map_err(|_| "ws open channel dropped".to_string())??;

            // Send `2probe` (Engine.IO Ping with payload="probe").
            let probe_packet = EngineIoPacket::Ping("probe".to_string()).encode();
            ws.send_with_str(&probe_packet)
                .map_err(|e| format!("ws send 2probe: {e:?}"))?;

            let mut msg_rx_drain = msg_rx;
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

        /// Return a cheap, cloneable [`WsSender`] for outbound access.
        /// The owning [`WsHandle`] retains the closures + the inbound
        /// `mpsc` receiver and remains the sole owner of teardown.
        pub fn sender(&self) -> WsSender {
            WsSender {
                ws: self.ws.clone(),
            }
        }

        /// Receive the next inbound text frame. Returns `None` if the
        /// channel has closed (WS dropped).
        async fn recv_text(&mut self) -> Option<std::result::Result<String, String>> {
            self.msg_rx.next().await
        }
    }

    #[async_trait::async_trait]
    impl SocketIoFrameSource for WsHandle {
        async fn recv_engineio(&mut self) -> std::result::Result<EngineIoPacket, String> {
            let text = self
                .recv_text()
                .await
                .ok_or_else(|| "ws closed".to_string())??;
            EngineIoPacket::decode(&text).map_err(|e| format!("decode engineio: {e}"))
        }
    }

    impl Drop for WsHandle {
        fn drop(&mut self) {
            // Detach JS-side handlers BEFORE the closures drop. Otherwise
            // a late-firing event would call into a dropped Rust closure.
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
