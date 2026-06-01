//! Socket.IO + BRC-103 subscribe per MPC-Spec §06.4 + §06.12.
//!
//! Replaces the former raw-`/ws` subscribe (`ws.rs`, deleted in H-4.4b)
//! with the canonical `@bsv/message-box-client` flow: a `bsv::auth::Peer`
//! over the upstream `bsv::auth::SocketIoTransport<WsSender>` (native WS
//! substrate in [`crate::transport_native`]). Room ops are signed BRC-31
//! Generals carrying the canonical `{eventName, data}` envelope:
//!
//! - **joinRoom** — `peer.to_peer(envelope("joinRoom", roomId), …)` where
//!   `roomId = "{our_identity}-{message_box}"` (matches
//!   `~/bsv/message-box-client/src/MessageBoxClient.ts:581,590`).
//! - **inbound live message** — the relay emits a General whose event is
//!   `sendMessage-{roomId}` with flat `data = {roomId, sender, messageId,
//!   body}` (`~/bsv/bsv-messagebox-cloudflare-public/src/engineio/
//!   session.rs:1450-1457,1574-1581`). We normalize the raw `body` into
//!   the `/listMessages` server-wrap shape `{"message": <body>}` so
//!   [`crate::wire::unwrap_inbound_body`] decodes both paths uniformly.
//! - **leaveRoom** — `peer.to_peer(envelope("leaveRoom", roomId), …)` on
//!   shutdown (best-effort).
//!
//! ## Lifecycle (per spec §06.12)
//!
//! 1. Drain `/listMessages` for each subscribed box (backfill) before
//!    going live, so the consumer never sees a live push before a
//!    backfill row from the same gap.
//! 2. Engine.IO polling handshake → WS upgrade → Socket.IO CONNECT.
//! 3. `Peer::start`; spawn the upstream `run_dispatch` inbound loop.
//! 4. joinRoom for each box (the first `to_peer` auto-initiates the
//!    BRC-103 handshake; the server identity is learned from the first
//!    inbound General and reused for subsequent room ops — the canonical
//!    TS pattern).
//! 5. Pump: forward each inbound `sendMessage-*` General as an
//!    [`InboundEnvelopeEvent`]; on WS disconnect, reconnect with §06.12
//!    exponential backoff (1s → cap 30s) + re-backfill.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use bsv::auth::transports::socketio::build_envelope_payload;
use bsv::auth::transports::socketio::codec::{EngineIoPacket, SocketIoPacket};
use bsv::auth::{
    install_app_event_listener, run_dispatch, AppEvent, Peer, PeerOptions, SocketIoFrameSource,
    SocketIoSink, SocketIoTransport,
};
use bsv::wallet::ProtoWallet;
use futures::channel::mpsc as fmpsc;
use futures::StreamExt;
use serde_json::json;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::auth::MessageBoxAuth;
use crate::error::{MessageBoxError, Result};
use crate::http;
use crate::transport_native::{polling_handshake, WsHandle, WsSender};

/// Initial reconnect backoff per §06.12 ("exponential backoff with cap;
/// initial 1s, double, cap 30s").
const RECONNECT_BACKOFF_INITIAL: Duration = Duration::from_secs(1);

/// Reconnect backoff cap per §06.12.
const RECONNECT_BACKOFF_CAP: Duration = Duration::from_secs(30);

/// Max wait for a `to_peer` round-trip (handshake + signed General).
const TO_PEER_TIMEOUT_MS: u64 = 20_000;

/// Max wait for the first inbound General (the relay's `authenticated`
/// event) from which we learn the server identity.
const SERVER_ID_TIMEOUT: Duration = Duration::from_secs(10);

/// Max wait for ONE `connect_and_join` (the Engine.IO polling handshake, WS
/// upgrade, probe dance, joinRoom, and server-id learn). The underlying
/// `reqwest::get` / `connect_async` have NO timeout of their own, so without this
/// an outbound WS that hangs (observed deployed: a CF container's egress WS to the
/// relay hung indefinitely, stalling the entire reshare with no error) blocks
/// forever.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Initial-subscribe WS connect attempts before falling back to HTTP polling.
/// A hung WS upgrade fails fast on `CONNECT_TIMEOUT`; a couple of fresh attempts
/// cover a transient stall, after which we switch to the always-available HTTP
/// `/listMessages` polling path (see [`run_loop_polling`]).
const CONNECT_ATTEMPTS: u32 = 2;

/// Backoff between initial-subscribe connect attempts.
const CONNECT_RETRY_BACKOFF: Duration = Duration::from_secs(2);

/// Max wait for a `drain_backfill` pass. Backfill uses the BRC-104
/// `SimplifiedFetchTransport` authed `POST /listMessages` — a DIFFERENT auth than
/// the BRC-103 WS subscribe. If that authed HTTP path stalls (observed deployed: a
/// CF container's BRC-104 auth handshake to the relay hung indefinitely while
/// plain HTTPS + the WS path were fine), backfill MUST NOT block the live WS
/// subscribe. We bound each pass and treat the initial backfill as best-effort.
const BACKFILL_TIMEOUT: Duration = Duration::from_secs(8);

/// HTTP-polling receive interval (fallback transport). Round messages are small
/// and a ceremony's per-round budget is seconds, so a short poll keeps the
/// ceremony converging without hammering the relay.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// WS-connected **reliability safety-net** interval. Even while the WebSocket is
/// up and live-pushing, re-drain `/listMessages` this often.
///
/// WS live-push is a latency FAST PATH, not a reliability guarantee: through CF
/// egress-NAT it is lossy + duplicating + reordering (root-caused 2026-05-31 — a
/// deployed presign cosigner's `WsPush` silently dropped rounds 2–5, leaving them
/// unacked in the relay box; the WS never disconnected, so the reconnect re-drain
/// never fired, and the ceremony burned the full 600s budget). PULL is therefore
/// the source of truth: this periodic re-drain recovers anything push dropped
/// within one interval. `/listMessages` is non-destructive and the consumer dedups
/// by `message_id`, so push + poll = exactly-once delivery to the handler. Matches
/// the HTTP-fallback [`POLL_INTERVAL`] so recovery latency is bounded the same way
/// on both transports.
const WSPUSH_SAFETY_NET_INTERVAL: Duration = Duration::from_secs(2);

/// Max wait for a `leftRoom`-equivalent on graceful shutdown — best
/// effort; we proceed to close regardless.
const LEAVE_TIMEOUT_MS: u64 = 1_000;

/// Whether a subscribed mailbox needs the WS-push **reliability drain**
/// ([`periodic_drain`]).
///
/// True ONLY for the per-session presign mailboxes — `mpc_{session}` (round-trip)
/// and `presig_return_{session}` — which carry the multi-round n-party presign over
/// a CF egress-NAT'd cosigner where live-push is lossy (it silently dropped rounds
/// 2–5). The FIXED ceremony boxes (`mpc-dkg`, `mpc-sign`, `mpc-refresh`, `mpc-ecdh`,
/// …) keep the proven WS-only path: their delivery is healthy, and a periodic
/// re-drain during DKG's slow safe-prime rounds floods the channel + churns
/// per-duplicate acks (root-caused 2.4× DKG slowdown + a hung custody PUT). The
/// session boxes use the `mpc_` (underscore) / `presig_return_` prefixes; the fixed
/// boxes use `mpc-` (hyphen) — see `types.rs`.
fn box_needs_reliability_drain(message_box: &str) -> bool {
    message_box.starts_with("mpc_") || message_box.starts_with("presig_return_")
}

/// Type alias for the upstream transport over our native sink.
type NativeSocketIoTransport = SocketIoTransport<WsSender>;

/// One inbound envelope event delivered to the subscriber.
///
/// `body` is always in the **`/listMessages` server-wrap shape** —
/// `{"message": <body>}` JSON-stringified — even when the path was the
/// live Socket.IO push, so consumers can decode uniformly via
/// [`crate::wire::unwrap_inbound_body`]. **Layout is load-bearing**
/// (consumed by `client.rs` + `bsv-mpc-service`); keep it byte-stable.
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
    /// Pushed live over the Socket.IO `sendMessage-{roomId}` General.
    WsPush,
    /// Drained via `/listMessages` on (re)connect.
    Backfill,
}

/// Handle to an active subscription. Holding it keeps the background
/// task alive; drop it (or call [`WsSubscription::shutdown`]) to stop.
pub struct WsSubscription {
    /// Receiver for inbound envelopes (live push + backfill). Items are
    /// `Err` when the relay reports an unrecoverable error.
    pub inbound: mpsc::Receiver<Result<InboundEnvelopeEvent>>,
    handle: Option<JoinHandle<()>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl WsSubscription {
    /// Gracefully stop the background task and await its exit (sends
    /// `leaveRoom` for each joined room first, best-effort).
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
/// The first backfill drain + connect + join runs inline before
/// returning, so a successful `Ok(_)` guarantees every requested room is
/// live. The background task takes over for subsequent disconnects,
/// applying §06.12 exponential backoff + backfill-on-reconnect.
pub async fn subscribe(auth: Arc<MessageBoxAuth>, boxes: Vec<String>) -> Result<WsSubscription> {
    if boxes.is_empty() {
        return Err(MessageBoxError::Protocol(
            "subscribe requires at least one message_box".into(),
        ));
    }
    let identity_hex = auth.identity_hex().await?;

    let (inbound_tx, inbound_rx) = mpsc::channel::<Result<InboundEnvelopeEvent>>(64);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    // First-attempt backfill + connect + join, inline. If this fails the
    // caller sees the error rather than a silently-reconnecting task.
    //
    // RELIABILITY (§06.17): the WS upgrade (`connect_async` / Engine.IO handshake)
    // has no timeout of its own, and on some egress paths it HANGS rather than
    // erroring — observed deployed: a CF container's outbound WS to the relay hung
    // indefinitely (pinpointed via the `/reshare-relay/debug` checkpoint trail
    // freezing at `dkg_listener_starting`), so `/reshare-relay/init` never returned
    // and the whole reshare timed out "awaiting throwaway DKG aux". We therefore
    // bound each connect by `CONNECT_TIMEOUT` and retry a hung/failed connect a few
    // times — a fresh attempt reliably succeeds (the relay WS is healthy; the
    // in-process path connects every time).
    // Initial backfill is BEST-EFFORT + bounded: the BRC-104 authed /listMessages
    // is a separate auth from the BRC-103 WS subscribe below, and a stalled authed
    // HTTP path must not block the live subscribe. Anything missed here is caught
    // by the post-join re-drain (also best-effort) + live WS push.
    match tokio::time::timeout(
        BACKFILL_TIMEOUT,
        drain_backfill(&auth, &boxes, &inbound_tx, None),
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return Err(MessageBoxError::Protocol(
                "subscriber dropped during initial backfill".into(),
            ));
        }
        Err(_) => warn!(
            "initial backfill timed out after {BACKFILL_TIMEOUT:?} (authed /listMessages); \
             proceeding to WS subscribe — live push + post-join re-drain will deliver"
        ),
    }

    let mut conn = None;
    let mut last_err = String::from("no attempt made");
    for attempt in 1..=CONNECT_ATTEMPTS {
        match tokio::time::timeout(
            CONNECT_TIMEOUT,
            connect_and_join(&auth, &identity_hex, &boxes, &inbound_tx),
        )
        .await
        {
            Ok(Ok(c)) => {
                conn = Some(c);
                break;
            }
            Ok(Err(e)) => {
                last_err = format!("{e}");
                warn!(attempt, "subscribe connect/join failed: {last_err}");
            }
            Err(_) => {
                last_err = format!("connect/join timed out after {CONNECT_TIMEOUT:?}");
                warn!(attempt, "subscribe connect/join hung: {last_err}");
            }
        }
        if attempt < CONNECT_ATTEMPTS {
            tokio::time::sleep(CONNECT_RETRY_BACKOFF).await;
        }
    }

    // FALLBACK (§06.17): if the WS upgrade never connects, run over HTTP polling
    // instead of failing. Some egress paths (observed deployed: a CF container's
    // outbound WS to the relay Worker) complete plain HTTPS but HANG the WebSocket
    // upgrade indefinitely. Sending already uses HTTP (`POST /sendMessage`), so
    // receiving via periodic `/listMessages` (the same call `drain_backfill` makes,
    // deduped by `message_id` at the consumer) makes the transport fully functional
    // without a WS. Local/hermetic paths connect WS on the first attempt and never
    // reach here.
    let handle = match conn {
        Some(conn) => tokio::spawn(run_loop_with_conn(
            auth,
            identity_hex,
            boxes,
            conn,
            inbound_tx,
            shutdown_rx,
        )),
        None => {
            warn!(
                "subscribe: WS connect failed {CONNECT_ATTEMPTS}× ({last_err}); falling back to \
                 HTTP /listMessages polling every {POLL_INTERVAL:?}"
            );
            tokio::spawn(run_loop_polling(auth, boxes, inbound_tx, shutdown_rx))
        }
    };

    Ok(WsSubscription {
        inbound: inbound_rx,
        handle: Some(handle),
        shutdown_tx: Some(shutdown_tx),
    })
}

/// A live, joined Socket.IO connection: the `Peer` (kept alive so its
/// inbound callback keeps firing), the app-event stream, the learned
/// server identity (for room ops + leave), and the dispatch task handle
/// (completes when the WS dies — our disconnect signal).
struct LiveConn {
    peer: Peer<ProtoWallet, NativeSocketIoTransport>,
    events: fmpsc::UnboundedReceiver<AppEvent>,
    server_id_hex: String,
    dispatch: JoinHandle<()>,
}

/// Open the WS, complete the Engine.IO/Socket.IO/BRC-103 handshake, join
/// every subscribed room, and return the live connection. Any inbound
/// `sendMessage` General seen while learning the server identity is
/// forwarded so no message is lost in the join window.
async fn connect_and_join(
    auth: &Arc<MessageBoxAuth>,
    identity_hex: &str,
    boxes: &[String],
    inbound: &mpsc::Sender<Result<InboundEnvelopeEvent>>,
) -> Result<LiveConn> {
    let relay = auth.relay_url();

    // Engine.IO polling handshake + WS upgrade.
    let handshake = polling_handshake(relay)
        .await
        .map_err(MessageBoxError::WebSocket)?;
    let mut ws = WsHandle::open_and_upgrade(relay, &handshake.sid)
        .await
        .map_err(MessageBoxError::WebSocket)?;
    let sink = ws.sender();

    // Socket.IO 5 CONNECT to default namespace `/`.
    sink.send_socketio(&SocketIoPacket::Connect {
        nsp: "/".to_string(),
        data: None,
    })
    .map_err(MessageBoxError::WebSocket)?;
    loop {
        match ws
            .recv_engineio()
            .await
            .map_err(MessageBoxError::WebSocket)?
        {
            EngineIoPacket::Ping(payload) => {
                let _ = sink.send_engineio(&EngineIoPacket::Pong(payload));
            }
            EngineIoPacket::Message(payload) => {
                if let Ok(SocketIoPacket::Connect { .. }) = SocketIoPacket::decode(&payload) {
                    break; // CONNECT-ack — Socket.IO ready.
                }
            }
            _ => {}
        }
    }

    // Build the Peer over the upstream SocketIoTransport.
    let wallet = auth.wallet().clone();
    let transport = SocketIoTransport::new(sink.clone());
    let callback = transport.callback_handle();
    let dispatch_sink = sink.clone();
    let peer = Peer::new(PeerOptions {
        wallet,
        transport,
        certificates_to_request: None,
        session_manager: None,
        auto_persist_last_session: true,
        originator: Some("bsv-mpc-messagebox".to_string()),
    });
    peer.start();
    let (mut events, _cb_id) = install_app_event_listener(&peer).await;

    // Pump inbound authMessage frames into the Peer callback.
    let dispatch = tokio::spawn(run_dispatch(ws, dispatch_sink, callback));

    // joinRoom for the first box. `to_peer(_, None, _)` auto-initiates
    // the BRC-103 handshake (InitialRequest → InitialResponse) and signs
    // the General internally.
    let first_room = format!("{identity_hex}-{}", boxes[0]);
    emit_room_op(&peer, "joinRoom", &first_room, None)
        .await
        .map_err(|e| MessageBoxError::WebSocket(format!("joinRoom({first_room}): {e}")))?;

    // Learn the server identity from the first inbound General (the
    // relay's `authenticated` event), forwarding any live message that
    // happens to arrive first so it isn't dropped.
    let server_id_hex = learn_server_identity(&mut events, identity_hex, inbound).await?;

    // Join any remaining boxes, reusing the established session.
    for message_box in &boxes[1..] {
        let room = format!("{identity_hex}-{message_box}");
        emit_room_op(&peer, "joinRoom", &room, Some(&server_id_hex))
            .await
            .map_err(|e| MessageBoxError::WebSocket(format!("joinRoom({room}): {e}")))?;
    }

    Ok(LiveConn {
        peer,
        events,
        server_id_hex,
        dispatch,
    })
}

/// Emit a signed `{eventName, data:<roomId>}` General via `Peer::to_peer`
/// with a bounded wait. `server_id` is `None` for the first send (which
/// initiates the handshake) and `Some(hex)` thereafter to reuse the
/// session.
async fn emit_room_op(
    peer: &Peer<ProtoWallet, NativeSocketIoTransport>,
    event_name: &str,
    room_id: &str,
    server_id: Option<&str>,
) -> std::result::Result<(), String> {
    let payload = build_envelope_payload(event_name, &json!(room_id));
    tokio::time::timeout(
        Duration::from_millis(TO_PEER_TIMEOUT_MS),
        peer.to_peer(&payload, server_id, Some(TO_PEER_TIMEOUT_MS)),
    )
    .await
    .map_err(|_| format!("{event_name} timed out"))?
    .map_err(|e| format!("{event_name} send failed: {e:?}"))
}

/// Read inbound app-events until the first one arrives; its `sender` is
/// the server identity (canonical TS pattern). Any `sendMessage-*` event
/// seen meanwhile is forwarded so it isn't lost.
async fn learn_server_identity(
    events: &mut fmpsc::UnboundedReceiver<AppEvent>,
    identity_hex: &str,
    inbound: &mpsc::Sender<Result<InboundEnvelopeEvent>>,
) -> Result<String> {
    // One inbound General suffices: its `sender` IS the server identity,
    // and if it happens to be a live message we forward it so it isn't
    // lost in the join window.
    match tokio::time::timeout(SERVER_ID_TIMEOUT, events.next()).await {
        Ok(Some(ev)) => {
            let server_id = ev.sender.to_hex();
            if let Some(event) = map_send_message(&ev, identity_hex) {
                let _ = inbound.send(Ok(event)).await;
            }
            Ok(server_id)
        }
        Ok(None) => Err(MessageBoxError::WebSocket(
            "inbound channel closed before server identity learned".into(),
        )),
        Err(_) => Err(MessageBoxError::WsTimeout(
            "first inbound General (server identity)".into(),
        )),
    }
}

/// Map a `sendMessage-{roomId}` app-event to an [`InboundEnvelopeEvent`].
/// Returns `None` for non-`sendMessage` events (`authenticated`,
/// `sendMessageAck-*`, `joinedRoom`, …). The raw `data.body` is
/// normalized into the `/listMessages` `{"message": <body>}` wrap.
fn map_send_message(ev: &AppEvent, _identity_hex: &str) -> Option<InboundEnvelopeEvent> {
    if !ev.event_name.starts_with("sendMessage-") {
        return None;
    }
    let room_id = ev.data.get("roomId").and_then(|v| v.as_str())?;
    // roomId == "{identity}-{message_box}"; the box is everything after
    // the first '-'.
    let message_box = match room_id.split_once('-') {
        Some((_identity, suffix)) => suffix.to_string(),
        None => {
            debug!("dropping sendMessage with no `<identity>-<box>` roomId: {room_id}");
            return None;
        }
    };
    let sender = ev.data.get("sender").and_then(|v| v.as_str())?.to_string();
    let message_id = ev
        .data
        .get("messageId")
        .and_then(|v| v.as_str())?
        .to_string();
    let raw_body = ev
        .data
        .get("body")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    // Normalize the raw live body into the /listMessages server-wrap
    // shape so `wire::unwrap_inbound_body` decodes both paths uniformly.
    let body = json!({ "message": raw_body }).to_string();
    Some(InboundEnvelopeEvent {
        message_box,
        sender,
        message_id,
        body,
        via: InboundVia::WsPush,
    })
}

#[derive(Debug)]
enum PumpExit {
    Shutdown,
    Disconnected(String),
}

/// Pump a live connection: forward inbound `sendMessage` Generals (the WS latency
/// fast-path), detect disconnect (the dispatch task completing), and handle shutdown
/// (`leaveRoom` per room, best-effort).
///
/// The reliability **pull** path runs as a SEPARATE concurrent task
/// ([`periodic_drain`], spawned by the callers) — deliberately NOT a branch in this
/// `select!`. Awaiting a bounded `/listMessages` inside a `select!` arm runs that arm
/// to completion before any other arm is re-polled, so it would starve WS-push
/// forwarding for the whole drain (root-caused 2026-05-31: an in-arm drain stalled
/// live-push and 2.4×-slowed a deployed DKG, cascading into a double-arm + a hung
/// custody PUT). Pull and push therefore run concurrently; the consumer dedups by
/// `message_id`.
async fn pump(
    conn: &mut LiveConn,
    identity_hex: &str,
    boxes: &[String],
    inbound: &mpsc::Sender<Result<InboundEnvelopeEvent>>,
    shutdown: &mut oneshot::Receiver<()>,
) -> PumpExit {
    loop {
        tokio::select! {
            biased;
            _ = &mut *shutdown => {
                graceful_leave(conn, identity_hex, boxes).await;
                return PumpExit::Shutdown;
            }
            // The dispatch task completes only when the WS closes.
            _ = &mut conn.dispatch => {
                return PumpExit::Disconnected("ws dispatch loop ended".into());
            }
            maybe_ev = conn.events.next() => {
                let Some(ev) = maybe_ev else {
                    return PumpExit::Disconnected("inbound app-event channel closed".into());
                };
                if let Some(event) = map_send_message(&ev, identity_hex) {
                    if inbound.send(Ok(event)).await.is_err() {
                        // Consumer dropped — stop cleanly.
                        graceful_leave(conn, identity_hex, boxes).await;
                        return PumpExit::Shutdown;
                    }
                }
            }
        }
    }
}

/// Reliability **pull** drain — the source-of-truth path that runs ALONGSIDE (never
/// inside) the WS [`pump`], so a slow/bounded `/listMessages` can never starve
/// live-push forwarding. WS push is a latency accelerator; this re-drain recovers
/// anything push drops/reorders within one [`WSPUSH_SAFETY_NET_INTERVAL`] (root
/// cause: CF egress-NAT silently dropped presign rounds 2–5 from a connected WS that
/// never reconnected, so the reconnect re-drain never fired). Spawned per live
/// connection and aborted when the pump exits. Dedup is downstream by `message_id`,
/// so push + poll = exactly-once delivery to the handler.
async fn periodic_drain(
    auth: Arc<MessageBoxAuth>,
    boxes: Vec<String>,
    inbound: mpsc::Sender<Result<InboundEnvelopeEvent>>,
) {
    let mut ticker = tokio::time::interval(WSPUSH_SAFETY_NET_INTERVAL);
    ticker.tick().await; // consume the immediate first tick — the caller drained on (re)connect.
                         // Per-poller dedup (see `drain_backfill`): forward each message_id once so a
                         // still-unacked in-flight row is never re-sent every tick.
    let mut seen: HashSet<String> = HashSet::new();
    loop {
        ticker.tick().await;
        // Bounded so a hung authed `/listMessages` (issue #58) self-heals on the next
        // tick instead of wedging the drain. `Ok(false)` = consumer dropped → exit.
        if let Ok(false) = tokio::time::timeout(
            BACKFILL_TIMEOUT,
            drain_backfill(&auth, &boxes, &inbound, Some(&mut seen)),
        )
        .await
        {
            return;
        }
    }
}

/// Best-effort `leaveRoom` for each subscribed room, then let the
/// connection drop (which aborts dispatch + closes the WS).
async fn graceful_leave(conn: &LiveConn, identity_hex: &str, boxes: &[String]) {
    for message_box in boxes {
        let room = format!("{identity_hex}-{message_box}");
        let payload = build_envelope_payload("leaveRoom", &json!(room));
        let _ = tokio::time::timeout(
            Duration::from_millis(LEAVE_TIMEOUT_MS),
            conn.peer
                .to_peer(&payload, Some(&conn.server_id_hex), Some(LEAVE_TIMEOUT_MS)),
        )
        .await;
    }
}

/// HTTP-polling receive loop — the WebSocket fallback (§06.17). Repeatedly drains
/// `/listMessages` for every subscribed box and forwards new rows to the inbound
/// channel; `/listMessages` is non-destructive and the consumer dedups by
/// `message_id`, so re-listing the same rows each tick is harmless. Used when the
/// outbound WS upgrade cannot connect (observed: a CF container's egress hangs the
/// WS upgrade while plain HTTPS works). Sending stays on `POST /sendMessage`, so
/// this completes a fully-functional HTTP-only transport. Runs until shutdown or
/// the consumer drops.
async fn run_loop_polling(
    auth: Arc<MessageBoxAuth>,
    boxes: Vec<String>,
    inbound: mpsc::Sender<Result<InboundEnvelopeEvent>>,
    mut shutdown: oneshot::Receiver<()>,
) {
    // Per-poller dedup (see `drain_backfill`): this fallback is a repeating poller too.
    let mut seen: HashSet<String> = HashSet::new();
    loop {
        if !drain_backfill(&auth, &boxes, &inbound, Some(&mut seen)).await {
            return; // consumer gone
        }
        tokio::select! {
            biased;
            _ = &mut shutdown => return,
            _ = tokio::time::sleep(POLL_INTERVAL) => {}
        }
    }
}

/// Drive the initial live connection, then fall into the reconnect loop
/// on disconnect. Mirrors the former `ws.rs::run_loop_with_socket`.
async fn run_loop_with_conn(
    auth: Arc<MessageBoxAuth>,
    identity_hex: String,
    boxes: Vec<String>,
    mut conn: LiveConn,
    inbound: mpsc::Sender<Result<InboundEnvelopeEvent>>,
    mut shutdown: oneshot::Receiver<()>,
) {
    // §06.17 reliability: recover any message a peer `POST`ed in the window between
    // the pre-join backfill drain and `joinRoom` completing — it's not in the
    // (already-drained) backfill and wasn't live-pushed (room not joined when it
    // landed), so without this it sits undelivered and stalls the ceremony into a
    // timeout. `/listMessages` is non-destructive + consumers dedup by `message_id`,
    // so re-draining here is safe.
    //
    // CRITICAL: this re-drain MUST be bounded. It runs SEQUENTIALLY before `pump`
    // (the WS live-push forwarder) below, so if the BRC-104 `/listMessages` hangs
    // — which it does, with no timeout, from a CF container (issue #58) — `pump`
    // NEVER STARTS and NO live WS message is forwarded to the handler. The
    // container receives a peer's round over the WebSocket but never delivers it,
    // stalling the ceremony. (Reshare's large per-phase budget hid this; presign's
    // tight single budget did not — the deployed presign timed out here.) Bound it
    // best-effort like the initial backfill so the WS pump starts promptly; live
    // push + the reconnect re-drain recover anything this pass missed.
    match tokio::time::timeout(
        BACKFILL_TIMEOUT,
        drain_backfill(&auth, &boxes, &inbound, None),
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => return, // consumer gone
        Err(_) => warn!(
            "post-join re-drain timed out after {BACKFILL_TIMEOUT:?} (authed /listMessages); \
             starting WS pump anyway — live push delivers"
        ),
    }
    // Run the reliability pull-drain concurrently with the WS pump — but ONLY for the
    // per-session presign mailboxes that need it (see `box_needs_reliability_drain`);
    // fixed-box ceremonies (DKG, refresh, sign) keep the proven WS-only path. Aborted
    // the instant the pump exits so it never outlives the connection.
    let drain = boxes
        .iter()
        .any(|b| box_needs_reliability_drain(b))
        .then(|| tokio::spawn(periodic_drain(auth.clone(), boxes.clone(), inbound.clone())));
    let exit = pump(&mut conn, &identity_hex, &boxes, &inbound, &mut shutdown).await;
    if let Some(drain) = drain {
        drain.abort();
    }
    match exit {
        PumpExit::Shutdown => return,
        PumpExit::Disconnected(reason) => {
            warn!("subscribe disconnected (initial session): {reason}");
        }
    }
    drop(conn); // abort the dead dispatch task before reconnecting.
    run_loop(auth, identity_hex, boxes, inbound, shutdown).await;
}

/// Reconnect loop per §06.12: backfill-first, connect+join, pump; on
/// failure/disconnect, exponential backoff (reset after a healthy join).
async fn run_loop(
    auth: Arc<MessageBoxAuth>,
    identity_hex: String,
    boxes: Vec<String>,
    inbound: mpsc::Sender<Result<InboundEnvelopeEvent>>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut backoff = RECONNECT_BACKOFF_INITIAL;
    loop {
        if shutdown_fired(&mut shutdown) {
            return;
        }
        // Backfill-first so the consumer never sees a live push before a
        // backfill row from the same gap. Bounded best-effort (same reason as the
        // post-join re-drain above): a hung BRC-104 `/listMessages` must not block
        // the reconnect's `pump` from re-establishing WS live-push.
        match tokio::time::timeout(
            BACKFILL_TIMEOUT,
            drain_backfill(&auth, &boxes, &inbound, None),
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => return, // consumer gone
            Err(_) => warn!(
                "reconnect re-drain timed out after {BACKFILL_TIMEOUT:?}; reconnecting WS anyway"
            ),
        }

        let connect = tokio::time::timeout(
            CONNECT_TIMEOUT,
            connect_and_join(&auth, &identity_hex, &boxes, &inbound),
        )
        .await
        .unwrap_or_else(|_| {
            Err(MessageBoxError::WsTimeout(format!(
                "reconnect connect/join hung > {CONNECT_TIMEOUT:?}"
            )))
        });
        match connect {
            Ok(mut conn) => {
                backoff = RECONNECT_BACKOFF_INITIAL; // healthy — reset.
                                                     // Concurrent reliability pull-drain — presign session boxes only
                                                     // (see `box_needs_reliability_drain`); aborted on exit.
                let drain = boxes
                    .iter()
                    .any(|b| box_needs_reliability_drain(b))
                    .then(|| {
                        tokio::spawn(periodic_drain(auth.clone(), boxes.clone(), inbound.clone()))
                    });
                let exit = pump(&mut conn, &identity_hex, &boxes, &inbound, &mut shutdown).await;
                if let Some(drain) = drain {
                    drain.abort();
                }
                match exit {
                    PumpExit::Shutdown => return,
                    PumpExit::Disconnected(reason) => {
                        warn!(reconnect_in = ?backoff, "subscribe disconnected: {reason}");
                        drop(conn);
                    }
                }
            }
            Err(e) => {
                warn!(reconnect_in = ?backoff, "subscribe connect/join failed: {e}");
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = &mut shutdown => return,
        }
        backoff = next_backoff(backoff);
    }
}

/// Drain `/listMessages` for every subscribed box, pushing each row into
/// the inbound channel as [`InboundVia::Backfill`]. Returns `false` if
/// the consumer dropped.
async fn drain_backfill(
    auth: &Arc<MessageBoxAuth>,
    boxes: &[String],
    inbound: &mpsc::Sender<Result<InboundEnvelopeEvent>>,
    mut seen: Option<&mut HashSet<String>>,
) -> bool {
    for message_box in boxes {
        match http::list_messages(auth, message_box).await {
            Ok(list) => {
                for msg in list.messages {
                    // Per-poller dedup: forward each `message_id` AT MOST ONCE from a
                    // repeating poller, so a still-unacked in-flight row is not re-sent
                    // every tick — that re-flooding + the consumer's per-duplicate ack
                    // is what 2.4×-slowed a deployed DKG. One-shot callers (initial /
                    // post-join / reconnect backfill) pass `None`: re-sending is rare
                    // there and the consumer dedups downstream.
                    if let Some(seen) = seen.as_deref_mut() {
                        if !msg.message_id.is_empty() && !seen.insert(msg.message_id.clone()) {
                            continue;
                        }
                    }
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

/// Compute the next backoff in the §06.12 sequence: double, clamp at cap.
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

#[cfg(test)]
mod tests {
    use super::*;
    use bsv::primitives::ec::PrivateKey;
    use serde_json::json;

    fn app_event(event_name: &str, data: serde_json::Value) -> AppEvent {
        // A throwaway pubkey for the `sender` field — `map_send_message`
        // reads `data.sender`, not `ev.sender`, for the envelope.
        let server = PrivateKey::from_bytes(&[0x07; 32]).unwrap().public_key();
        AppEvent {
            sender: server,
            event_name: event_name.to_string(),
            data,
        }
    }

    #[test]
    fn map_send_message_extracts_fields_and_wraps_body() {
        let ev = app_event(
            "sendMessage-02abc-mpc-sign",
            json!({
                "roomId": "02abc-mpc-sign",
                "sender": "02cd",
                "messageId": "m1",
                "body": "deadbeef"
            }),
        );
        let out = map_send_message(&ev, "02abc").expect("must map");
        assert_eq!(out.message_box, "mpc-sign");
        assert_eq!(out.sender, "02cd");
        assert_eq!(out.message_id, "m1");
        assert_eq!(out.via, InboundVia::WsPush);
        // Body normalized into the /listMessages server-wrap shape.
        assert_eq!(out.body, r#"{"message":"deadbeef"}"#);
    }

    #[test]
    fn map_send_message_handles_multi_dash_box() {
        // roomId splits on the FIRST '-' only; the box keeps its dashes.
        let ev = app_event(
            "sendMessage-02abc-mpc-sign-extra",
            json!({"roomId":"02abc-mpc-sign-extra","sender":"02cd","messageId":"m2","body":"00"}),
        );
        let out = map_send_message(&ev, "02abc").expect("must map");
        assert_eq!(out.message_box, "mpc-sign-extra");
    }

    #[test]
    fn map_send_message_wraps_object_body() {
        // Live body may be a JSON object (not a hex string); it's wrapped
        // verbatim under `message`.
        let ev = app_event(
            "sendMessage-02abc-mpc-dkg",
            json!({"roomId":"02abc-mpc-dkg","sender":"02cd","messageId":"m3","body":{"k":"v"}}),
        );
        let out = map_send_message(&ev, "02abc").expect("must map");
        assert_eq!(out.body, r#"{"message":{"k":"v"}}"#);
    }

    #[test]
    fn map_send_message_ignores_non_send_events() {
        assert!(map_send_message(&app_event("authenticated", json!({})), "02abc").is_none());
        assert!(map_send_message(
            &app_event("sendMessageAck-02abc-mpc-sign", json!({"status":"success"})),
            "02abc"
        )
        .is_none());
        assert!(
            map_send_message(&app_event("joinedRoom", json!({"roomId":"x"})), "02abc").is_none()
        );
    }

    #[test]
    fn reliability_drain_scoped_to_presign_session_boxes_only() {
        // Per-session presign mailboxes (egress-NAT lossy live-push) → drain ON.
        let sid = "f25e7c5e560e01926dfbfd70f3940352c1349e1e69a2f17c1668bda988014e0b";
        assert!(box_needs_reliability_drain(&format!("mpc_{sid}")));
        assert!(box_needs_reliability_drain(&format!("presig_return_{sid}")));
        // FIXED ceremony boxes keep the proven WS-only path — the drain MUST NOT run
        // for DKG (its slow safe-prime rounds + a re-drain = the 2.4× regression).
        for fixed in [
            "mpc-dkg",
            "mpc-sign",
            "mpc-presign",
            "mpc-refresh",
            "mpc-ecdh",
        ] {
            assert!(
                !box_needs_reliability_drain(fixed),
                "{fixed} must NOT get the reliability drain"
            );
        }
    }

    #[test]
    fn next_backoff_doubles_then_caps_at_30s() {
        let mut b = RECONNECT_BACKOFF_INITIAL;
        for want in [2u64, 4, 8, 16, 30, 30, 30] {
            b = next_backoff(b);
            assert_eq!(b, Duration::from_secs(want));
        }
    }
}
