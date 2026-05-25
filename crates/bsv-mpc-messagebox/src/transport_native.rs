//! Native WS substrate for the upstream Socket.IO + BRC-103 transport.
//!
//! Provides the native ([`tokio-tungstenite`] + [`reqwest`]) implementations
//! of the bsv-rs `socketio` substrate traits:
//!
//! - [`WsSender`] implements [`bsv::auth::SocketIoSink`] (outbound frames).
//! - [`WsHandle`] implements [`bsv::auth::SocketIoFrameSource`] (inbound
//!   frames) and owns the Engine.IO 4 handshake/upgrade dance.
//!
//! Plugged into the upstream `bsv::auth::SocketIoTransport<WsSender>` +
//! `bsv::auth::run_dispatch`, so all the Socket.IO / BRC-103 protocol
//! logic lives in bsv-rs 0.3.10 (graduated from H-4.3); this module is
//! purely the native transport plumbing. The wasm32 counterpart is
//! [`crate::transport_wasm`].
//!
//! # Wire shape (verified against the live Calhoun relay
//! `rust-message-box.dev-a3e.workers.dev`)
//!
//!   1. [`polling_handshake`] GETs
//!      `<relay>/socket.io/?EIO=4&transport=polling&t=<t>` and parses the
//!      Engine.IO `Open` packet (handshake JSON).
//!   2. [`WsHandle::open_and_upgrade`] opens
//!      `wss://<relay>/socket.io/?EIO=4&transport=websocket&sid=<sid>`,
//!      runs the `2probe`→`3probe`→`5` upgrade dance, then splits the
//!      stream: a writer task owns the sink (fed by an unbounded mpsc so
//!      [`WsSender`] is cheap to clone), and the handle keeps the read
//!      half for [`bsv::auth::SocketIoFrameSource::recv_engineio`].
//!
//! TLS is handled transparently by `tokio_tungstenite::connect_async`
//! for `wss://` URLs (rustls via the `rustls-tls-webpki-roots` feature).

use std::time::Instant;

use bsv::auth::transports::socketio::codec::{EngineIoPacket, SocketIoPacket};
use bsv::auth::{SocketIoFrameSource, SocketIoSink};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::{
    client_async_tls, tungstenite::protocol::Message, MaybeTlsStream, WebSocketStream,
};

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

/// Per-address TCP connect timeout (happy-eyeballs-lite). Short so a dead address
/// is abandoned quickly and the next is tried.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

/// Extract `(host, port)` from a `ws://`/`wss://` URL (default 80/443).
fn ws_host_port(ws_url: &str) -> std::result::Result<(String, u16), String> {
    let (default_port, after) = if let Some(r) = ws_url.strip_prefix("wss://") {
        (443u16, r)
    } else if let Some(r) = ws_url.strip_prefix("ws://") {
        (80u16, r)
    } else {
        return Err(format!("not a ws(s) url: {ws_url}"));
    };
    let authority = after.split('/').next().unwrap_or(after);
    match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port = p
                .parse::<u16>()
                .map_err(|_| format!("bad port in {ws_url}"))?;
            Ok((h.to_string(), port))
        }
        None => Ok((authority.to_string(), default_port)),
    }
}

/// Resolve `host:port` and connect TCP, **preferring IPv4** and bounding each
/// attempt by [`TCP_CONNECT_TIMEOUT`].
///
/// `tokio_tungstenite::connect_async` uses tokio's plain sequential connect with
/// NO per-address timeout, so if the host resolves to an IPv6 address first and
/// that route black-holes (observed: a CF container's egress completes plain HTTPS
/// — reqwest/hyper does happy-eyeballs + falls back to IPv4 — but the WS upgrade's
/// IPv6 connect hangs forever), the whole reshare stalls. We resolve ourselves,
/// try IPv4 addresses first (then IPv6), each bounded, and hand the live stream to
/// `client_async_tls`. This keeps the fast WebSocket transport working on egress
/// paths where only IPv4 is viable.
async fn connect_tcp_prefer_ipv4(host: &str, port: u16) -> std::result::Result<TcpStream, String> {
    let mut addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("dns lookup {host}:{port}: {e}"))?
        .collect();
    // IPv4 first, then IPv6.
    addrs.sort_by_key(|a| match a.ip() {
        IpAddr::V4(_) => 0u8,
        IpAddr::V6(_) => 1u8,
    });
    if addrs.is_empty() {
        return Err(format!("no addresses resolved for {host}:{port}"));
    }
    let mut last_err = String::from("no connect attempted");
    for addr in addrs {
        match tokio::time::timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last_err = format!("connect {addr}: {e}"),
            Err(_) => last_err = format!("connect {addr} timed out after {TCP_CONNECT_TIMEOUT:?}"),
        }
    }
    Err(format!("all addresses failed for {host}:{port}: {last_err}"))
}

type NativeWsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Send-only half of a [`WsHandle`]. Cheap to clone (holds an
/// unbounded-mpsc sender into the writer task that owns the WS sink).
/// Implements [`bsv::auth::SocketIoSink`] so it can back an upstream
/// `SocketIoTransport`.
///
/// Genuinely `Send + Sync` (`mpsc::UnboundedSender` is both) — no
/// `unsafe` shield needed, unlike the wasm32 substrate.
#[derive(Clone)]
pub struct WsSender {
    tx: mpsc::UnboundedSender<Message>,
}

impl WsSender {
    /// Send a raw text frame. Returns `Err` if the writer task has
    /// exited (WS closed). Used by the [`SocketIoSink`] impl and by the
    /// handshake setup path.
    fn send_text(&self, s: &str) -> std::result::Result<(), String> {
        self.tx
            .send(Message::Text(s.to_string()))
            .map_err(|e| format!("ws send: {e}"))
    }
}

impl SocketIoSink for WsSender {
    fn send_socketio(&self, pkt: &SocketIoPacket) -> std::result::Result<(), String> {
        self.send_text(&EngineIoPacket::Message(pkt.encode()).encode())
    }

    /// Override the trait default so we can emit non-`Message` Engine.IO
    /// packets directly (e.g. `Pong` heartbeat replies the upstream
    /// `run_dispatch` loop sends).
    fn send_engineio(&self, pkt: &EngineIoPacket) -> std::result::Result<(), String> {
        self.send_text(&pkt.encode())
    }
}

/// Long-lived WebSocket handle held after the Engine.IO 4 upgrade
/// completes. Outbound frames go through a cloneable [`WsSender`]
/// (backed by a writer task that owns the split sink); inbound frames
/// are pulled from the split stream via the [`SocketIoFrameSource`] impl.
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
    /// for `recv_engineio` ([`SocketIoFrameSource`]) + a [`WsSender`].
    pub async fn open_and_upgrade(relay_url: &str, sid: &str) -> std::result::Result<Self, String> {
        let url = ws_upgrade_url(relay_url, sid);

        // Connect the TCP ourselves (IPv4-preferred, bounded) rather than letting
        // `connect_async` do a plain sequential connect that can hang on IPv6, then
        // run TLS + the WS handshake over that stream.
        let (host, port) = ws_host_port(&url)?;
        let tcp = connect_tcp_prefer_ipv4(&host, port).await?;
        let (mut ws_stream, _resp) = client_async_tls(url.as_str(), tcp)
            .await
            .map_err(|e| format!("client_async_tls({url}): {e}"))?;

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
    async fn recv_text(&mut self) -> Option<std::result::Result<String, String>> {
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
    fn ws_sender_send_socketio_after_writer_drop_errors() {
        // A WsSender whose receiver half has been dropped surfaces the
        // closed-channel error rather than panicking.
        let (tx, rx) = mpsc::unbounded_channel::<Message>();
        let sender = WsSender { tx };
        drop(rx);
        let err = sender
            .send_socketio(&SocketIoPacket::Connect {
                nsp: "/".to_string(),
                data: None,
            })
            .unwrap_err();
        assert!(err.contains("ws send"), "unexpected error: {err}");
    }
}
