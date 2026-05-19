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
