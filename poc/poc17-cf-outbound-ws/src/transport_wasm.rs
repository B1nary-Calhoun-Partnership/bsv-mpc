//! wasm32 transport substrate — `worker::Fetch` (Engine.IO polling
//! handshake) + `web_sys::WebSocket` (WS upgrade phase).
//!
//! Both phases of the Engine.IO 4 client lifecycle live here.
//! `socketio_client.rs` is transport-agnostic and consumes this
//! substrate via the (forthcoming) `SocketIo` trait abstraction.
//!
//! # H-3.2a scope (this commit)
//!
//! Engine.IO polling handshake via `worker::Fetch`. The client GETs
//! `<relay>/socket.io/?EIO=4&transport=polling&t=<t>`; the server
//! returns `200 OK` with body = `0{"sid":"...","upgrades":["websocket"],...}`
//! (an Engine.IO `Open` packet whose payload is the handshake JSON).
//! Decoded via the vendored [`crate::engineio_codec`].
//!
//! H-3.2b adds the `web_sys::WebSocket` upgrade phase.

use crate::engineio_codec::EngineIoPacket;
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
/// This is the FIRST half of the Engine.IO 4 client lifecycle (H-3.2a).
/// The returned `sid` feeds into the subsequent WS upgrade phase
/// (H-3.2b — `upgrade_to_websocket()`).
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
/// [`EngineIoPacket::decode`] from the vendored codec.
pub async fn polling_handshake(relay_url: &str) -> Result<EngineIoHandshake> {
    let base = relay_url.trim_end_matches('/');
    // The `t` query-param is a per-request cache-buster per Engine.IO 4
    // spec — CF / Cloudflare caches may otherwise dedupe handshake GETs.
    // We use a high-resolution timestamp from the JS Date global; on
    // native it falls back to a zero (harmless — handshake still works).
    let t = current_timestamp_ms();
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

/// High-resolution `Date.now()` in milliseconds. Used only as a
/// cache-buster on the polling URL — no security or freshness property
/// depends on it being monotonic or accurate.
fn current_timestamp_ms() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

// ============================================================================
// H-3.2b: WS upgrade via `web_sys::WebSocket`
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
//
// Empirical verification (H-3.2b) returns success once steps 1-5 complete.
// Subsequent Engine.IO messages (Socket.IO CONNECT etc) land in H-3.3.

#[cfg(target_arch = "wasm32")]
mod ws_upgrade {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsCast;
    use web_sys::{Event, MessageEvent, WebSocket};

    /// Result of the H-3.2b upgrade dance — returned to the caller for
    /// inclusion in the `/open` JSON response.
    #[derive(Serialize, Debug, Clone)]
    pub struct UpgradeResult {
        pub ws_url: String,
        pub probe_round_trip_ms: f64,
    }

    /// Run the Engine.IO 4 WS upgrade dance against `<relay>` for the
    /// given `sid` (obtained from a prior polling handshake).
    ///
    /// Returns once the `5` Upgrade packet has been sent. Does NOT keep
    /// the WS alive — the connection is dropped when the `WsHandle`
    /// goes out of scope. H-3.3+ will hold the WS for long-lived use.
    pub async fn upgrade_to_websocket(relay_url: &str, sid: &str) -> Result<UpgradeResult, String> {
        let base = relay_url.trim_end_matches('/');
        // Convert https:// → wss:// (or http:// → ws://); other schemes
        // are passed through unchanged.
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
        let (open_tx, open_rx) = futures::channel::oneshot::channel::<Result<(), String>>();
        let open_tx = Rc::new(RefCell::new(Some(open_tx)));

        let open_tx_open = open_tx.clone();
        let on_open = Closure::wrap(Box::new(move |_e: Event| {
            if let Some(t) = open_tx_open.borrow_mut().take() {
                let _ = t.send(Ok(()));
            }
        }) as Box<dyn FnMut(Event)>);
        ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));

        let open_tx_err = open_tx.clone();
        let on_err = Closure::wrap(Box::new(move |e: Event| {
            if let Some(t) = open_tx_err.borrow_mut().take() {
                let _ = t.send(Err(format!("ws error before open: {e:?}")));
            }
        }) as Box<dyn FnMut(Event)>);
        ws.set_onerror(Some(on_err.as_ref().unchecked_ref()));

        // Channel that the message handler will fire on the FIRST inbound
        // text frame. We set this up BEFORE awaiting open so we don't
        // miss a server-sent message that arrives the moment the socket
        // is established.
        let (msg_tx, msg_rx) = futures::channel::oneshot::channel::<Result<String, String>>();
        let msg_tx = Rc::new(RefCell::new(Some(msg_tx)));
        let msg_tx_clone = msg_tx.clone();
        let on_msg = Closure::wrap(Box::new(move |e: MessageEvent| {
            // The Engine.IO transport uses text frames exclusively on the
            // AuthSocket profile (binary frames carry Socket.IO BINARY
            // attachments which the canonical TS @bsv/authsocket client
            // doesn't use — confirmed in agent H-1c).
            if let Some(text) = e.data().as_string() {
                if let Some(t) = msg_tx_clone.borrow_mut().take() {
                    let _ = t.send(Ok(text));
                }
            }
        }) as Box<dyn FnMut(MessageEvent)>);
        ws.set_onmessage(Some(on_msg.as_ref().unchecked_ref()));

        let t_probe_start = js_sys::Date::now();

        // Await the onopen event.
        open_rx
            .await
            .map_err(|_| "ws open channel dropped".to_string())?
            .map_err(|e| e)?;

        // Send the Engine.IO Ping with "probe" payload — encoded as
        // `2probe` via the vendored codec.
        let probe_packet = EngineIoPacket::Ping("probe".to_string()).encode();
        ws.send_with_str(&probe_packet)
            .map_err(|e| format!("ws send 2probe: {e:?}"))?;

        // Await the server's `3probe` reply.
        let pong_text = msg_rx
            .await
            .map_err(|_| "ws message channel dropped before pong".to_string())?
            .map_err(|e| e)?;
        let pong_packet =
            EngineIoPacket::decode(&pong_text).map_err(|e| format!("decode pong: {e}"))?;
        match pong_packet {
            EngineIoPacket::Pong(payload) if payload == "probe" => { /* expected */ }
            other => return Err(format!("expected Pong(\"probe\"), got {other:?}")),
        }
        let probe_round_trip_ms = js_sys::Date::now() - t_probe_start;

        // Commit the upgrade — send Engine.IO `5` (Upgrade) packet.
        let upgrade_packet = EngineIoPacket::Upgrade.encode();
        ws.send_with_str(&upgrade_packet)
            .map_err(|e| format!("ws send Upgrade: {e:?}"))?;

        // Clear the callbacks so the closures can be dropped along with
        // `ws` when this function returns. (Without these clears,
        // `Closure::forget()` would leak; we never call forget()
        // explicitly here — the JS-side function refs are released
        // when `ws.set_on...(None)` runs.)
        ws.set_onopen(None);
        ws.set_onerror(None);
        ws.set_onmessage(None);
        drop(on_open);
        drop(on_err);
        drop(on_msg);

        // H-3.2b explicitly does NOT keep the WS alive. The connection
        // closes when `ws` is dropped. H-3.3+ will own the WS in a
        // longer-lived struct.
        Ok(UpgradeResult {
            ws_url: url,
            probe_round_trip_ms,
        })
    }
}

#[cfg(target_arch = "wasm32")]
pub use ws_upgrade::{upgrade_to_websocket, UpgradeResult};

// Native build target: provide a stub so the workspace `cargo build
// --all-targets` doesn't fail. The actual H-3.2b verification runs only
// in the wasm32 CF Worker context — there's no native equivalent of
// `web_sys::WebSocket`.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Serialize, Debug, Clone)]
pub struct UpgradeResult {
    pub ws_url: String,
    pub probe_round_trip_ms: f64,
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn upgrade_to_websocket(
    _relay_url: &str,
    _sid: &str,
) -> std::result::Result<UpgradeResult, String> {
    Err("upgrade_to_websocket is wasm32-only; native consumers should use a tokio-tungstenite path (not implemented in this POC)".into())
}
