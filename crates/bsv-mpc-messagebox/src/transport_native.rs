//! Native transport substrate — `reqwest` (Engine.IO polling handshake)
//! + `tokio-tungstenite` (WS upgrade phase).
//!
//! Native counterpart of [`crate::transport_wasm`], introduced in Phase
//! H Step 4 sub-gate H-4.3. The whole module is
//! `#[cfg(not(target_arch = "wasm32"))]`-gated at the crate root
//! (`lib.rs`). It mirrors the `transport_wasm` method surface
//! ([`EngineIoHandshake`], [`polling_handshake`], [`WsHandle`],
//! [`WsSender`]) so [`crate::transport_socketio`] — and its target-
//! agnostic `run_dispatch` loop — compile against either substrate by a
//! single `use`-alias swap. Both share [`crate::engineio::codec`]
//! byte-for-byte.
//!
//! # Wire shape (identical to the wasm32 path, verified against the live
//! Calhoun relay `rust-message-box.dev-a3e.workers.dev`)
//!
//!   1. [`polling_handshake`] GETs
//!      `<relay>/socket.io/?EIO=4&transport=polling&t=<t>` and parses the
//!      Engine.IO `Open` packet (handshake JSON).
//!   2. [`WsHandle::open_and_upgrade`] opens
//!      `wss://<relay>/socket.io/?EIO=4&transport=websocket&sid=<sid>`,
//!      runs the `2probe`→`3probe`→`5` upgrade dance, then splits the
//!      stream: a writer task owns the sink (fed by an unbounded mpsc so
//!      [`WsSender`] is cheap to clone), and the handle keeps the read
//!      half for [`WsHandle::recv_engineio`].
//!
//! TLS is handled transparently by `tokio_tungstenite::connect_async`
//! for `wss://` URLs (rustls via the `rustls-tls-webpki-roots` feature),
//! matching the pattern in `~/bsv/bsv-rs/src/auth/transports/websocket_transport.rs`.

use std::time::Instant;

use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::Message, MaybeTlsStream, WebSocketStream,
};

use crate::engineio::codec::{EngineIoPacket, SocketIoPacket};

/// Parsed Engine.IO `Open` handshake payload, returned by the server on
/// the polling-transport GET. Shape per Engine.IO 4 spec — mirrors
/// [`crate::transport_wasm::EngineIoHandshake`].
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
    /// Heartbeat timeout in ms.
    #[serde(rename = "pingTimeout")]
    pub ping_timeout: u64,
    /// Max payload size the server will accept on a single packet.
    #[serde(default, rename = "maxPayload")]
    pub max_payload: Option<u64>,
}

/// Initiate an Engine.IO 4 polling handshake against `<relay>/socket.io/`
/// and return the parsed `Open` payload. Native counterpart of
/// [`crate::transport_wasm::polling_handshake`] (uses `reqwest` instead
/// of `worker::Fetch`).
pub async fn polling_handshake(relay_url: &str) -> std::result::Result<EngineIoHandshake, String> {
    let base = relay_url.trim_end_matches('/');
    // Per-request cache-buster per Engine.IO 4 spec.
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let url = format!("{base}/socket.io/?EIO=4&transport=polling&t={t}");

    let response = reqwest::get(&url)
        .await
        .map_err(|e| format!("polling handshake GET {url}: {e}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("polling handshake HTTP {status} against {url}"));
    }
    let body = response
        .text()
        .await
        .map_err(|e| format!("polling handshake body read: {e}"))?;
    if body.is_empty() {
        return Err("polling handshake returned empty body".to_string());
    }

    let packet = EngineIoPacket::decode(&body).map_err(|e| format!("Engine.IO codec: {e}"))?;
    match packet {
        EngineIoPacket::Open(payload) => serde_json::from_str(&payload)
            .map_err(|e| format!("handshake JSON decode failed: {e} (payload={payload})")),
        other => Err(format!("expected Engine.IO Open, got {other:?}")),
    }
}

/// Derive the `wss://`/`ws://` upgrade URL from the relay base URL +
/// Engine.IO session id. Pulled out as a free function so it can be unit
/// tested without a live socket.
fn ws_upgrade_url(relay_url: &str, sid: &str) -> String {
    let base = relay_url.trim_end_matches('/');
    let ws_base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base.to_string()
    };
    format!("{ws_base}/socket.io/?EIO=4&transport=websocket&sid={sid}")
}

type NativeWsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Send-only half of a [`WsHandle`]. Cheap to clone (holds an
/// unbounded-mpsc sender into the writer task that owns the WS sink).
/// Mirrors [`crate::transport_wasm::WsSender`]'s method surface so
/// [`crate::transport_socketio::SocketIoTransport`] is target-agnostic.
///
/// Unlike the wasm32 variant (which is `!Send` and carries an
/// `unsafe impl Send` shield), this is genuinely `Send + Sync` —
/// `mpsc::UnboundedSender` is both.
#[derive(Clone)]
pub struct WsSender {
    tx: mpsc::UnboundedSender<Message>,
}

impl WsSender {
    /// Send a raw text frame. Returns `Err` if the writer task has
    /// exited (WS closed).
    pub fn send_text(&self, s: &str) -> std::result::Result<(), String> {
        self.tx
            .send(Message::Text(s.into()))
            .map_err(|e| format!("ws send: {e}"))
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

/// Long-lived WebSocket handle held after the Engine.IO 4 upgrade
/// completes. Outbound frames go through a cloneable [`WsSender`]
/// (backed by a writer task that owns the split sink); inbound frames
/// are pulled from the split stream via [`WsHandle::recv_engineio`].
///
/// Mirrors [`crate::transport_wasm::WsHandle`]'s method surface.
pub struct WsHandle {
    stream: futures::stream::SplitStream<NativeWsStream>,
    tx: mpsc::UnboundedSender<Message>,
    url: String,
    probe_round_trip_ms: f64,
    // Held so the writer task is aborted when the handle drops, closing
    // the WS sink and tearing down the connection.
    writer: JoinHandle<()>,
}

impl WsHandle {
    /// Open a WebSocket against `<relay>/socket.io/?...&transport=
    /// websocket&sid=<sid>` and complete the Engine.IO 4 upgrade dance
    /// (`2probe` → `3probe` → `5` Upgrade). Returns the live handle ready
    /// for `send_*`/`recv_*` operations.
    pub async fn open_and_upgrade(relay_url: &str, sid: &str) -> std::result::Result<Self, String> {
        let url = ws_upgrade_url(relay_url, sid);

        let (mut ws_stream, _resp) = connect_async(&url)
            .await
            .map_err(|e| format!("connect_async({url}): {e}"))?;

        // ── Probe dance on the un-split stream ──
        let t_probe = Instant::now();
        let probe = EngineIoPacket::Ping("probe".to_string()).encode();
        ws_stream
            .send(Message::Text(probe))
            .await
            .map_err(|e| format!("ws send 2probe: {e}"))?;

        // Await the server's `3probe` reply, skipping any interleaved
        // control / binary frames.
        loop {
            match ws_stream.next().await {
                Some(Ok(Message::Text(t))) => {
                    match EngineIoPacket::decode(&t).map_err(|e| format!("decode pong: {e}"))? {
                        EngineIoPacket::Pong(payload) if payload == "probe" => break,
                        other => return Err(format!("expected Pong(\"probe\"), got {other:?}")),
                    }
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Binary(_))) => continue,
                Some(Ok(Message::Close(c))) => return Err(format!("ws closed before pong: {c:?}")),
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(format!("ws recv before pong: {e}")),
                None => return Err("ws closed before pong".to_string()),
            }
        }
        let probe_round_trip_ms = t_probe.elapsed().as_secs_f64() * 1000.0;

        // Commit the upgrade — send Engine.IO `5` (Upgrade) packet.
        let upgrade = EngineIoPacket::Upgrade.encode();
        ws_stream
            .send(Message::Text(upgrade))
            .await
            .map_err(|e| format!("ws send Upgrade: {e}"))?;

        // Split: a writer task owns the sink + drains an unbounded mpsc
        // so `WsSender` is cheap to clone and sends are non-blocking.
        let (mut sink, stream) = ws_stream.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        let writer = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if sink.send(msg).await.is_err() {
                    break;
                }
            }
        });

        Ok(WsHandle {
            stream,
            tx,
            url,
            probe_round_trip_ms,
            writer,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn probe_round_trip_ms(&self) -> f64 {
        self.probe_round_trip_ms
    }

    /// Send a raw text frame.
    pub fn send_text(&self, s: &str) -> std::result::Result<(), String> {
        self.tx
            .send(Message::Text(s.into()))
            .map_err(|e| format!("ws send: {e}"))
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

    /// Return a cheap, cloneable [`WsSender`] for outbound access. The
    /// owning [`WsHandle`] retains the read half + the writer task and
    /// remains the sole owner of teardown (its `Drop` impl aborts the
    /// writer, closing the sink).
    pub fn sender(&self) -> WsSender {
        WsSender {
            tx: self.tx.clone(),
        }
    }

    /// Receive the next inbound text frame. Returns `None` if the stream
    /// has closed (WS dropped). Control / binary frames are skipped.
    pub async fn recv_text(&mut self) -> Option<std::result::Result<String, String>> {
        loop {
            match self.stream.next().await {
                Some(Ok(Message::Text(t))) => return Some(Ok(t)),
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Binary(_))) => continue,
                Some(Ok(Message::Close(c))) => return Some(Err(format!("ws closed: {c:?}"))),
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Some(Err(format!("ws recv: {e}"))),
                None => return None,
            }
        }
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

    /// Convenience: receive an inbound frame and decode through both the
    /// Engine.IO and Socket.IO layers, returning the inner Socket.IO
    /// packet.
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
        // Aborting the writer task drops the sink, which closes the WS.
        self.writer.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_upgrade_url_https_to_wss() {
        let url = ws_upgrade_url("https://relay.example.workers.dev", "abc123");
        assert_eq!(
            url,
            "wss://relay.example.workers.dev/socket.io/?EIO=4&transport=websocket&sid=abc123"
        );
    }

    #[test]
    fn ws_upgrade_url_http_to_ws() {
        let url = ws_upgrade_url("http://localhost:8787", "sid-xyz");
        assert_eq!(
            url,
            "ws://localhost:8787/socket.io/?EIO=4&transport=websocket&sid=sid-xyz"
        );
    }

    #[test]
    fn ws_upgrade_url_strips_trailing_slash() {
        let url = ws_upgrade_url("https://relay.example.com/", "s1");
        assert_eq!(
            url,
            "wss://relay.example.com/socket.io/?EIO=4&transport=websocket&sid=s1"
        );
    }

    #[test]
    fn handshake_json_decodes_open_payload() {
        // Byte-shape pinned against the live Calhoun relay's Open packet.
        let payload = r#"{"sid":"abc","upgrades":["websocket"],"pingInterval":25000,"pingTimeout":20000,"maxPayload":1000000}"#;
        let h: EngineIoHandshake = serde_json::from_str(payload).unwrap();
        assert_eq!(h.sid, "abc");
        assert_eq!(h.upgrades, vec!["websocket".to_string()]);
        assert_eq!(h.ping_interval, 25000);
        assert_eq!(h.ping_timeout, 20000);
        assert_eq!(h.max_payload, Some(1_000_000));
    }

    #[test]
    fn handshake_json_tolerates_missing_max_payload() {
        // `maxPayload` is `#[serde(default)]` — older relays omit it.
        let payload = r#"{"sid":"x","upgrades":[],"pingInterval":25000,"pingTimeout":20000}"#;
        let h: EngineIoHandshake = serde_json::from_str(payload).unwrap();
        assert_eq!(h.sid, "x");
        assert!(h.upgrades.is_empty());
        assert_eq!(h.max_payload, None);
    }

    #[test]
    fn ws_sender_send_after_writer_drop_errors() {
        // A WsSender whose receiver half has been dropped surfaces the
        // closed-channel error rather than panicking.
        let (tx, rx) = mpsc::unbounded_channel::<Message>();
        let sender = WsSender { tx };
        drop(rx);
        let err = sender.send_text("2probe").unwrap_err();
        assert!(err.contains("ws send"), "unexpected error: {err}");
    }
}
