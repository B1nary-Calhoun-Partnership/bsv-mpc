//! `/ws` WebSocket subscribe per MPC-Spec §06.4 + §06.12.
//!
//! Opens a single WebSocket against the Calhoun relay (`/ws` on
//! `bsv-messagebox-cloudflare-public`), authenticates the upgrade GET
//! with BRC-31 (see [`crate::auth::MessageBoxAuth::sign_ws_upgrade`]),
//! joins one room per subscribed mailbox (`<our_identity>-<box>`), and
//! pumps incoming `sendMessage` events into an mpsc channel.
//!
//! ## Lifecycle (per spec §06.12)
//!
//! 1. Drain `/listMessages` for each subscribed box — backfill any
//!    messages that landed while the WS was disconnected (REQUIRED on
//!    every (re)connect by §06.12: "after reconnection, the receiver
//!    MUST re-fetch missed messages via /listMessages").
//! 2. Open `wss://relay/ws` with the pre-signed BRC-31 headers.
//! 3. Wait for the server-initiated `connected` greeting (verifies the
//!    101 was real auth and not an auth-fail close-on-accept).
//! 4. Emit one `joinRoom` per `<identity>-<box>`; await each
//!    `joinedRoom` ack.
//! 5. Loop: select over (a) inbound text frame, (b) 30s heartbeat tick,
//!    (c) shutdown signal. On disconnect: warn, sleep with exponential
//!    backoff (initial 1s, double, cap 30s), refresh the WS session,
//!    repeat from step 1.
//!
//! ## Heartbeat
//!
//! We send a literal `"ping"` text frame every 30s. The relay binds
//! `WebSocketRequestResponsePair::new("ping", "pong")` on the per-
//! identity `MessageHub` Durable Object (see
//! `~/bsv/bsv-messagebox-cloudflare-public/src/message_hub.rs:251`), so
//! the runtime auto-replies with `"pong"` without un-hibernating. This
//! is text-frame-based heartbeat, NOT the WebSocket protocol's
//! ping/pong opcode — using opcodes would un-hibernate the DO on every
//! beat.
//!
//! ## Body shape normalization
//!
//! The relay sends WS push with the **raw** original body value
//! (`message_hub.rs::emit_send_message`), while `/listMessages` returns
//! the D1-stored `{"message": <body>}` server-wrap
//! (`routes/send_message.rs:202`). To give consumers a single decoder,
//! we wrap WS-push bodies into the same `{"message": <body>}` shape at
//! this boundary so [`crate::wire::unwrap_inbound_body`] works on
//! `InboundEnvelopeEvent.body` regardless of path.

use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{interval, MissedTickBehavior};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        handshake::client::generate_key, http::Request, protocol::Message,
    },
    MaybeTlsStream, WebSocketStream,
};
use tracing::{debug, warn};
use url::Url;

use crate::auth::MessageBoxAuth;
use crate::error::{MessageBoxError, Result};
use crate::http;

/// Heartbeat cadence per §06.12. The relay disconnects sockets idle for
/// 60s; 30s gives us one full cycle of slack on either side.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Initial reconnect backoff per §06.12 ("exponential backoff with cap;
/// initial 1s, double, cap 30s").
const RECONNECT_BACKOFF_INITIAL: Duration = Duration::from_secs(1);

/// Reconnect backoff cap per §06.12.
const RECONNECT_BACKOFF_CAP: Duration = Duration::from_secs(30);

/// Time to wait for the `connected` greeting on a fresh socket. The
/// relay sends this synchronously after `accept_web_socket` returns; a
/// 5 s timeout is plenty of headroom for a cold CF Worker spin-up.
const GREETING_TIMEOUT: Duration = Duration::from_secs(5);

/// Time to wait for each per-room `joinedRoom` ack.
const JOIN_ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// One inbound envelope event delivered to the subscriber.
///
/// `body` is always in the **`/listMessages` server-wrap shape** —
/// `{"message": <body>}` JSON-stringified — even when the path was the
/// live WS push, so consumers can decode uniformly via
/// [`crate::wire::unwrap_inbound_body`]. See module-level docs.
#[derive(Debug, Clone)]
pub struct InboundEnvelopeEvent {
    pub message_box: String,
    pub sender: String,
    pub message_id: String,
    pub body: String,
    pub via: InboundVia,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundVia {
    /// Pushed live over the WebSocket.
    WsPush,
    /// Drained via `/listMessages` on (re)connect.
    Backfill,
}

/// Handle to an active WS subscription. Holding it keeps the background
/// task alive; drop it (or call [`WsSubscription::shutdown`]) to stop.
pub struct WsSubscription {
    /// Receiver for inbound envelopes (live push + backfill). Items are
    /// `Err` when the relay emits a `joinFailed` / `leaveFailed` /
    /// `messageFailed` event the loop can't recover from.
    pub inbound: mpsc::Receiver<Result<InboundEnvelopeEvent>>,
    handle: Option<JoinHandle<()>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl WsSubscription {
    /// Gracefully stop the background task and await its exit.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            let _ = h.await;
        }
    }
}

impl Drop for WsSubscription {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

/// Subscribe to one or more `(our_identity, box)` mailboxes on the
/// relay. The returned [`WsSubscription`] holds an mpsc receiver of
/// [`InboundEnvelopeEvent`]; backfill rows arrive first.
///
/// `subscribe` performs the **first** backfill drain + WS connect +
/// join inline before returning, so a successful `Ok(_)` guarantees
/// every requested room is live. If the first connect fails the caller
/// sees the error directly. The background task takes over for
/// subsequent disconnects, applying §06.12 exponential backoff +
/// backfill-on-reconnect (Option A from the #13 plan).
pub async fn subscribe(
    auth: Arc<MessageBoxAuth>,
    boxes: Vec<String>,
) -> Result<WsSubscription> {
    if boxes.is_empty() {
        return Err(MessageBoxError::Protocol(
            "subscribe requires at least one message_box".into(),
        ));
    }
    let identity_hex = auth.identity_hex().await?;
    let ws_url = build_ws_url(auth.relay_url())?;

    let (inbound_tx, inbound_rx) = mpsc::channel::<Result<InboundEnvelopeEvent>>(64);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    // First-attempt backfill + connect + join, inline. If this fails
    // the caller sees the error rather than a silently-reconnecting
    // background task.
    if !drain_backfill(&auth, &boxes, &inbound_tx).await {
        return Err(MessageBoxError::Protocol(
            "subscriber dropped during initial backfill".into(),
        ));
    }
    let ws = connect_and_join(&auth, &identity_hex, &boxes, &ws_url).await?;

    // Hand off the live socket to the pump loop.
    let auth_for_task = auth.clone();
    let handle = tokio::spawn(async move {
        run_loop_with_socket(
            auth_for_task,
            identity_hex,
            boxes,
            ws_url,
            ws,
            inbound_tx,
            shutdown_rx,
        )
        .await;
    });

    Ok(WsSubscription {
        inbound: inbound_rx,
        handle: Some(handle),
        shutdown_tx: Some(shutdown_tx),
    })
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn build_ws_url(relay_url: &str) -> Result<Url> {
    let trimmed = relay_url.trim_end_matches('/');
    let with_ws = if let Some(rest) = trimmed.strip_prefix("https://") {
        format!("wss://{rest}/ws")
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        format!("ws://{rest}/ws")
    } else {
        return Err(MessageBoxError::Protocol(format!(
            "relay_url must start with https:// or http://; got {relay_url}"
        )));
    };
    Url::parse(&with_ws).map_err(|e| MessageBoxError::Protocol(format!("ws url parse: {e}")))
}

/// Outer reconnect loop. The first connect was done inline by
/// [`subscribe`] (so the caller saw any startup error); this loop only
/// runs on disconnect. Backoff sequence per §06.12 (initial 1s,
/// double, cap 30s); reset to initial after every healthy join.
async fn run_loop(
    auth: Arc<MessageBoxAuth>,
    identity_hex: String,
    boxes: Vec<String>,
    ws_url: Url,
    inbound: mpsc::Sender<Result<InboundEnvelopeEvent>>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut backoff = RECONNECT_BACKOFF_INITIAL;
    loop {
        if shutdown_fired(&mut shutdown) {
            return;
        }

        // (A) backfill-first: drain /listMessages for every box before
        // opening the WS, so the consumer never sees a live push
        // arrive before a backfill row from the same gap.
        if !drain_backfill(&auth, &boxes, &inbound).await {
            return; // consumer gone
        }

        let ws = match connect_and_join(&auth, &identity_hex, &boxes, &ws_url).await {
            Ok(s) => {
                // Healthy session — reset backoff for the next cycle.
                backoff = RECONNECT_BACKOFF_INITIAL;
                s
            }
            Err(e) => {
                warn!(reconnect_in = ?backoff, "ws connect/join failed: {e}");
                auth.refresh_ws_session().await;
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = &mut shutdown => return,
                }
                backoff = next_backoff(backoff);
                continue;
            }
        };

        match pump_frames_owned(ws, &identity_hex, &inbound, &mut shutdown).await {
            PumpExit::Shutdown | PumpExit::ConsumerGone => return,
            PumpExit::Disconnected(reason) => {
                warn!(reconnect_in = ?backoff, "ws disconnected: {reason}");
                auth.refresh_ws_session().await;
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = &mut shutdown => return,
                }
                backoff = next_backoff(backoff);
            }
        }
    }
}

/// Variant entry point used by [`subscribe`]: the first WS has already
/// been opened and joined inline; pump it, then fall back to the
/// standard reconnect loop on disconnect.
async fn run_loop_with_socket(
    auth: Arc<MessageBoxAuth>,
    identity_hex: String,
    boxes: Vec<String>,
    ws_url: Url,
    initial_ws: WsStream,
    inbound: mpsc::Sender<Result<InboundEnvelopeEvent>>,
    mut shutdown: oneshot::Receiver<()>,
) {
    match pump_frames_owned(initial_ws, &identity_hex, &inbound, &mut shutdown).await {
        PumpExit::Shutdown | PumpExit::ConsumerGone => return,
        PumpExit::Disconnected(reason) => {
            warn!("ws disconnected (initial session): {reason}");
            auth.refresh_ws_session().await;
        }
    }
    run_loop(auth, identity_hex, boxes, ws_url, inbound, shutdown).await;
}

#[derive(Debug)]
enum PumpExit {
    Shutdown,
    ConsumerGone,
    Disconnected(String),
}

/// Compute the next backoff in the §06.12 sequence: double the current
/// value, then clamp at the cap.
fn next_backoff(current: Duration) -> Duration {
    let doubled = current.saturating_mul(2);
    if doubled > RECONNECT_BACKOFF_CAP {
        RECONNECT_BACKOFF_CAP
    } else {
        doubled
    }
}

fn shutdown_fired(shutdown: &mut oneshot::Receiver<()>) -> bool {
    use oneshot::error::TryRecvError;
    match shutdown.try_recv() {
        Ok(()) | Err(TryRecvError::Closed) => true,
        Err(TryRecvError::Empty) => false,
    }
}

/// Drain `/listMessages` for every subscribed box, pushing each row
/// into the inbound channel as `InboundVia::Backfill`. Returns `false`
/// if the consumer dropped (no point continuing).
async fn drain_backfill(
    auth: &Arc<MessageBoxAuth>,
    boxes: &[String],
    inbound: &mpsc::Sender<Result<InboundEnvelopeEvent>>,
) -> bool {
    for message_box in boxes {
        match http::list_messages(auth, message_box).await {
            Ok(list) => {
                for msg in list.messages {
                    let event = InboundEnvelopeEvent {
                        message_box: message_box.clone(),
                        sender: msg.sender,
                        message_id: msg.message_id,
                        body: msg.body,
                        via: InboundVia::Backfill,
                    };
                    if inbound.send(Ok(event)).await.is_err() {
                        return false;
                    }
                }
            }
            Err(e) => {
                warn!("backfill listMessages({message_box}) failed: {e}");
                // Don't abort the WS subscription on a transient
                // backfill error — surface it to the consumer and keep
                // going. They can decide whether to bail.
                if inbound
                    .send(Err(MessageBoxError::Http(format!(
                        "backfill /listMessages({message_box}) failed: {e}"
                    ))))
                    .await
                    .is_err()
                {
                    return false;
                }
            }
        }
    }
    true
}

/// Open the WS, await `connected`, join every subscribed room, return
/// the live socket ready to pump.
async fn connect_and_join(
    auth: &Arc<MessageBoxAuth>,
    identity_hex: &str,
    boxes: &[String],
    ws_url: &Url,
) -> Result<WsStream> {
    let mut ws = open_socket(auth, ws_url).await?;

    if let Err(e) = await_connected(&mut ws, identity_hex).await {
        let _ = ws.close(None).await;
        return Err(e);
    }

    for message_box in boxes {
        let room_id = format!("{identity_hex}-{message_box}");
        if let Err(e) = send_join_room(&mut ws, &room_id).await {
            let _ = ws.close(None).await;
            return Err(e);
        }
        if let Err(e) = await_joined_room(&mut ws, &room_id).await {
            let _ = ws.close(None).await;
            return Err(e);
        }
    }
    Ok(ws)
}

/// Open a WebSocket with the BRC-31-signed upgrade headers attached.
async fn open_socket(auth: &Arc<MessageBoxAuth>, ws_url: &Url) -> Result<WsStream> {
    let path = if ws_url.path().is_empty() {
        "/"
    } else {
        ws_url.path()
    };
    let query_owned = ws_url.query().map(|q| format!("?{q}"));
    let query = query_owned.as_deref().unwrap_or("");

    let auth_headers = auth.sign_ws_upgrade(path, query).await?;

    // Mirror load_gen::connect::open_ws header set.
    let host = ws_url
        .host_str()
        .ok_or_else(|| MessageBoxError::WebSocket(format!("ws url missing host: {ws_url}")))?;
    let host_hdr = match ws_url.port_or_known_default() {
        Some(443) | Some(80) | None => host.to_string(),
        Some(p) => format!("{host}:{p}"),
    };

    let mut builder = Request::builder()
        .method("GET")
        .uri(ws_url.as_str())
        .header("Host", host_hdr)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", generate_key());
    for (k, v) in &auth_headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let req = builder
        .body(())
        .map_err(|e| MessageBoxError::WebSocket(format!("build upgrade request: {e}")))?;

    let (ws, _resp) = connect_async(req)
        .await
        .map_err(|e| MessageBoxError::WebSocket(format!("connect_async: {e}")))?;
    Ok(ws)
}

async fn await_connected(ws: &mut WsStream, identity_hex: &str) -> Result<()> {
    let frame = tokio::time::timeout(GREETING_TIMEOUT, ws.next())
        .await
        .map_err(|_| MessageBoxError::WsTimeout("connected greeting".into()))?
        .ok_or_else(|| MessageBoxError::WebSocket("ws closed before greeting".into()))?
        .map_err(|e| MessageBoxError::WebSocket(format!("greeting recv: {e}")))?;

    let text = expect_text(frame, "greeting")?;
    let event = parse_server_event(&text)?;
    match event {
        ServerEvent::Connected { identity_key } => {
            if identity_key != identity_hex {
                return Err(MessageBoxError::Auth(format!(
                    "greeting identityKey mismatch: expected {identity_hex}, got {identity_key}"
                )));
            }
            Ok(())
        }
        other => Err(MessageBoxError::WebSocket(format!(
            "expected `connected` greeting, got {other:?}"
        ))),
    }
}

async fn send_join_room(ws: &mut WsStream, room_id: &str) -> Result<()> {
    let frame = json!({ "event": "joinRoom", "data": { "roomId": room_id } }).to_string();
    ws.send(Message::Text(frame))
        .await
        .map_err(|e| MessageBoxError::WebSocket(format!("send joinRoom: {e}")))
}

async fn await_joined_room(ws: &mut WsStream, expected_room: &str) -> Result<()> {
    let deadline = tokio::time::Instant::now() + JOIN_ACK_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(MessageBoxError::WsTimeout(format!(
                "joinedRoom({expected_room})"
            )));
        }
        let frame = tokio::time::timeout(remaining, ws.next())
            .await
            .map_err(|_| MessageBoxError::WsTimeout(format!("joinedRoom({expected_room})")))?
            .ok_or_else(|| {
                MessageBoxError::WebSocket(format!(
                    "ws closed waiting for joinedRoom({expected_room})"
                ))
            })?
            .map_err(|e| MessageBoxError::WebSocket(format!("joinedRoom recv: {e}")))?;

        let text = match frame {
            Message::Text(t) => t.to_string(),
            // Ignore pong frames and the "pong" auto-response while
            // waiting for joinedRoom — they're not failures.
            Message::Pong(_) => continue,
            Message::Close(c) => {
                return Err(MessageBoxError::WebSocket(format!(
                    "server closed while waiting for joinedRoom({expected_room}): {c:?}"
                )))
            }
            other => {
                debug!("ignoring non-text frame during join: {other:?}");
                continue;
            }
        };
        if text == "pong" {
            continue;
        }
        match parse_server_event(&text)? {
            ServerEvent::JoinedRoom { room_id } if room_id == expected_room => return Ok(()),
            ServerEvent::JoinFailed { reason } => {
                return Err(MessageBoxError::WebSocket(format!(
                    "joinRoom({expected_room}) rejected: {reason}"
                )));
            }
            ServerEvent::Connected { .. } => {
                // Stray re-greet (shouldn't happen). Tolerate.
                debug!("ignoring stray `connected` while waiting for joinedRoom");
            }
            other => {
                // Live `sendMessage` etc. can interleave the join
                // phase — we'd already have joined other rooms. Quietly
                // drop while we wait; the next pump cycle will catch
                // any push that arrives after we exit this function.
                debug!("dropping pre-join frame while waiting for joinedRoom: {other:?}");
            }
        }
    }
}

async fn pump_frames_owned(
    mut ws: WsStream,
    identity_hex: &str,
    inbound: &mpsc::Sender<Result<InboundEnvelopeEvent>>,
    shutdown: &mut oneshot::Receiver<()>,
) -> PumpExit {
    let ws = &mut ws;
    let mut heartbeat = interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // Skip the immediate first tick so we don't send a heartbeat the
    // moment we join.
    heartbeat.tick().await;

    loop {
        tokio::select! {
            biased;

            _ = &mut *shutdown => {
                let _ = ws.close(None).await;
                return PumpExit::Shutdown;
            }
            _ = heartbeat.tick() => {
                if let Err(e) = ws.send(Message::Text("ping".into())).await {
                    return PumpExit::Disconnected(format!("heartbeat send: {e}"));
                }
            }
            maybe_frame = ws.next() => {
                let frame = match maybe_frame {
                    Some(Ok(f)) => f,
                    Some(Err(e)) => {
                        return PumpExit::Disconnected(format!("ws recv: {e}"));
                    }
                    None => return PumpExit::Disconnected("ws stream ended".into()),
                };
                match handle_frame(frame, identity_hex, inbound).await {
                    FrameOutcome::Ok => continue,
                    FrameOutcome::ConsumerGone => return PumpExit::ConsumerGone,
                    FrameOutcome::Disconnect(reason) => {
                        let _ = ws.close(None).await;
                        return PumpExit::Disconnected(reason);
                    }
                }
            }
        }
    }
}

enum FrameOutcome {
    Ok,
    ConsumerGone,
    Disconnect(String),
}

async fn handle_frame(
    frame: Message,
    identity_hex: &str,
    inbound: &mpsc::Sender<Result<InboundEnvelopeEvent>>,
) -> FrameOutcome {
    match frame {
        Message::Text(t) => {
            let text = t.to_string();
            // "pong" auto-response from the DO's heartbeat binding. Not
            // a JSON envelope.
            if text == "pong" {
                return FrameOutcome::Ok;
            }
            match parse_server_event(&text) {
                Ok(event) => dispatch_event(event, identity_hex, inbound).await,
                Err(e) => {
                    // Don't kill the loop on a single malformed frame —
                    // log + surface as Err and continue.
                    let send = inbound
                        .send(Err(MessageBoxError::Protocol(format!(
                            "unparseable WS frame: {e} (text: {text})"
                        ))))
                        .await;
                    if send.is_err() {
                        FrameOutcome::ConsumerGone
                    } else {
                        FrameOutcome::Ok
                    }
                }
            }
        }
        Message::Binary(_) => {
            warn!("ignoring binary WS frame (event channel is JSON-only)");
            FrameOutcome::Ok
        }
        Message::Ping(payload) => {
            // Protocol-level ping (vs the "ping" text-frame heartbeat).
            // tokio-tungstenite normally auto-pongs, but be explicit so
            // a hand-disabled auto-pong build stays correct.
            debug!("server ping ({} bytes)", payload.len());
            FrameOutcome::Ok
        }
        Message::Pong(_) => FrameOutcome::Ok,
        Message::Close(c) => FrameOutcome::Disconnect(format!("server close: {c:?}")),
        Message::Frame(_) => FrameOutcome::Ok,
    }
}

async fn dispatch_event(
    event: ServerEvent,
    _identity_hex: &str,
    inbound: &mpsc::Sender<Result<InboundEnvelopeEvent>>,
) -> FrameOutcome {
    match event {
        ServerEvent::SendMessage(d) => {
            let message_box = match d.room_id.split_once('-') {
                Some((_identity, suffix)) => suffix.to_string(),
                None => {
                    debug!(
                        "dropping sendMessage with no `<identity>-<box>` room_id: {}",
                        d.room_id
                    );
                    return FrameOutcome::Ok;
                }
            };
            // Normalize to /listMessages server-wrap shape — see
            // module-level docs.
            let wrapped_body = json!({ "message": d.body }).to_string();
            let event = InboundEnvelopeEvent {
                message_box,
                sender: d.sender,
                message_id: d.message_id,
                body: wrapped_body,
                via: InboundVia::WsPush,
            };
            if inbound.send(Ok(event)).await.is_err() {
                FrameOutcome::ConsumerGone
            } else {
                FrameOutcome::Ok
            }
        }
        ServerEvent::JoinFailed { reason }
        | ServerEvent::LeaveFailed { reason }
        | ServerEvent::MessageFailed { reason } => {
            let send = inbound
                .send(Err(MessageBoxError::WebSocket(format!(
                    "server rejected event: {reason}"
                ))))
                .await;
            if send.is_err() {
                FrameOutcome::ConsumerGone
            } else {
                FrameOutcome::Ok
            }
        }
        ServerEvent::Connected { .. }
        | ServerEvent::JoinedRoom { .. }
        | ServerEvent::LeftRoom
        | ServerEvent::AuthenticationSuccess
        | ServerEvent::Unknown => FrameOutcome::Ok,
    }
}

fn expect_text(frame: Message, label: &str) -> Result<String> {
    match frame {
        Message::Text(t) => Ok(t.to_string()),
        Message::Close(c) => Err(MessageBoxError::WebSocket(format!(
            "{label}: server closed: {c:?}"
        ))),
        other => Err(MessageBoxError::WebSocket(format!(
            "{label}: expected text frame, got {other:?}"
        ))),
    }
}

/// Parse one inbound frame from `message_hub.rs`. Two-step so that
/// unknown event names (`sendMessageAck`, future events) fall through
/// to [`ServerEvent::Unknown`] without erroring out the pump loop —
/// serde's `#[serde(other)]` doesn't compose with the adjacently-
/// tagged `(tag, content)` form when the unknown variant has content.
fn parse_server_event(text: &str) -> Result<ServerEvent> {
    let raw: RawFrame = serde_json::from_str(text).map_err(MessageBoxError::Json)?;
    let event = match raw.event.as_str() {
        "connected" => ServerEvent::Connected {
            identity_key: raw
                .data
                .get("identityKey")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        },
        "authenticationSuccess" => ServerEvent::AuthenticationSuccess,
        "joinedRoom" => ServerEvent::JoinedRoom {
            room_id: str_field(&raw.data, "roomId").unwrap_or_default(),
        },
        "leftRoom" => ServerEvent::LeftRoom,
        "joinFailed" => ServerEvent::JoinFailed {
            reason: str_field(&raw.data, "reason").unwrap_or_default(),
        },
        "leaveFailed" => ServerEvent::LeaveFailed {
            reason: str_field(&raw.data, "reason").unwrap_or_default(),
        },
        "messageFailed" => ServerEvent::MessageFailed {
            reason: str_field(&raw.data, "reason").unwrap_or_default(),
        },
        "sendMessage" => {
            let data: SendMessageData =
                serde_json::from_value(raw.data).map_err(MessageBoxError::Json)?;
            ServerEvent::SendMessage(data)
        }
        _ => ServerEvent::Unknown,
    };
    Ok(event)
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(str::to_string)
}

// ---------------------------------------------------------------------------
// Server frame shape (matches `message_hub.rs` outbound emitters)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawFrame {
    event: String,
    #[serde(default)]
    data: Value,
}

#[derive(Debug)]
enum ServerEvent {
    Connected { identity_key: String },
    AuthenticationSuccess,
    JoinedRoom { room_id: String },
    LeftRoom,
    JoinFailed { reason: String },
    LeaveFailed { reason: String },
    MessageFailed { reason: String },
    SendMessage(SendMessageData),
    /// Any event name we don't act on (`sendMessageAck`, future events).
    /// Kept so the pump loop never errors on a new event type.
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendMessageData {
    #[serde(rename = "roomId")]
    room_id: String,
    sender: String,
    #[serde(rename = "messageId")]
    message_id: String,
    /// Raw original-shape body sent by the peer (string / object /
    /// number / etc). Re-wrapped to listMessages shape before reaching
    /// the consumer; see module docs.
    body: Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_ws_url_swaps_https_for_wss() {
        let u = build_ws_url("https://rust-message-box.dev-a3e.workers.dev").unwrap();
        assert_eq!(u.scheme(), "wss");
        assert_eq!(u.host_str().unwrap(), "rust-message-box.dev-a3e.workers.dev");
        assert_eq!(u.path(), "/ws");
    }

    #[test]
    fn build_ws_url_swaps_http_for_ws() {
        let u = build_ws_url("http://localhost:8787/").unwrap();
        assert_eq!(u.scheme(), "ws");
        assert_eq!(u.host_str().unwrap(), "localhost");
        assert_eq!(u.port(), Some(8787));
        assert_eq!(u.path(), "/ws");
    }

    #[test]
    fn build_ws_url_rejects_unknown_scheme() {
        let err = build_ws_url("ftp://relay.example").unwrap_err();
        assert!(matches!(err, MessageBoxError::Protocol(_)));
    }

    #[test]
    fn next_backoff_doubles_then_caps_at_30s() {
        // §06.12 sequence: 1, 2, 4, 8, 16, 30, 30, 30, …
        let mut b = RECONNECT_BACKOFF_INITIAL;
        let expected = [
            Duration::from_secs(2),
            Duration::from_secs(4),
            Duration::from_secs(8),
            Duration::from_secs(16),
            Duration::from_secs(30),
            Duration::from_secs(30),
            Duration::from_secs(30),
        ];
        for want in expected {
            b = next_backoff(b);
            assert_eq!(b, want);
        }
    }

    #[test]
    fn server_event_parses_connected_greeting() {
        let raw = r#"{"event":"connected","data":{"identityKey":"02ab"}}"#;
        let ev = parse_server_event(raw).unwrap();
        match ev {
            ServerEvent::Connected { identity_key } => assert_eq!(identity_key, "02ab"),
            other => panic!("expected Connected, got {other:?}"),
        }
    }

    #[test]
    fn server_event_parses_joined_room() {
        let raw = r#"{"event":"joinedRoom","data":{"roomId":"02ab-mpc-sign"}}"#;
        let ev = parse_server_event(raw).unwrap();
        match ev {
            ServerEvent::JoinedRoom { room_id } => assert_eq!(room_id, "02ab-mpc-sign"),
            other => panic!("expected JoinedRoom, got {other:?}"),
        }
    }

    #[test]
    fn server_event_parses_send_message_with_string_body() {
        let raw = r#"{
            "event":"sendMessage",
            "data":{"roomId":"02ab-mpc-sign","sender":"02cd","messageId":"m1","body":"ac01"}
        }"#;
        let ev = parse_server_event(raw).unwrap();
        match ev {
            ServerEvent::SendMessage(d) => {
                assert_eq!(d.room_id, "02ab-mpc-sign");
                assert_eq!(d.sender, "02cd");
                assert_eq!(d.message_id, "m1");
                assert_eq!(d.body, Value::String("ac01".into()));
            }
            other => panic!("expected SendMessage, got {other:?}"),
        }
    }

    #[test]
    fn server_event_unknown_falls_through() {
        let raw = r#"{"event":"sendMessageAck","data":{"roomId":"x","status":"success","messageId":"m1"}}"#;
        let ev = parse_server_event(raw).unwrap();
        assert!(matches!(ev, ServerEvent::Unknown));
    }

    #[test]
    fn server_event_parses_failures() {
        let raw = r#"{"event":"joinFailed","data":{"reason":"bad room"}}"#;
        match parse_server_event(raw).unwrap() {
            ServerEvent::JoinFailed { reason } => assert_eq!(reason, "bad room"),
            other => panic!("expected JoinFailed, got {other:?}"),
        }
    }
}
