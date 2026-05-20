//! Durable Object that owns one cosigner's BRC-103 session against the
//! MessageBox relay. Replaces the H-3.1 stub.
//!
//! # Layout
//!
//! - `EngineIoSessionDo` — the `#[durable_object]` impl. One DO instance
//!   per cosigner identity (audit §11.1).
//! - `establish_session()` — internal helper that drives the full
//!   Engine.IO polling → WS upgrade → Socket.IO CONNECT → BRC-103
//!   InitialRequest → InitialResponse cycle and returns the captured
//!   substrate (`Peer`, `SocketIoTransport`, app-event mpsc, server
//!   identity + nonce). Both `handle_handshake` (H-3.5b) and
//!   `handle_echo` (H-3.5c) use it. Step 4 migration will extract this
//!   helper to `crates/bsv-mpc-messagebox/` so the same shape is shared
//!   across the native + wasm32 transports.
//!
//! # Locked design decisions (from `docs/H-3-5-PLAN.md`)
//!
//! - **Identity from `SERVER_PRIVATE_KEY` secret**, not random per-DO.
//! - **Per-identity DO** topology — audit §11.1.
//! - **Strategy 1 — re-handshake on every wake** — outbound WS is not
//!   hibernation-eligible; relay-side per-sid `SessionState` resets on
//!   a fresh sid anyway.
//! - **Path 2 manual InitialRequest** — bsv-rs ≥ 0.3.9 makes
//!   `Peer::initiate_handshake` runtime-safe but Path 2 gives us direct
//!   snoop control over the handshake completion.
//! - **Deploy-only empirical harness** — `wrangler dev` does not
//!   hibernate DOs; every H-3.5 sub-gate proof is `wrangler deploy` +
//!   `curl` against the deployed worker URL.

use worker::*;

/// The Durable Object class. One instance per cosigner identity (per
/// audit §11.1).
#[durable_object]
pub struct EngineIoSessionDo {
    state: State,
    env: Env,
}

impl DurableObject for EngineIoSessionDo {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        let path = url.path();
        match path {
            "/relay-via-do/identity" => self.handle_identity().await,
            "/relay-via-do/handshake" => self.handle_handshake().await,
            "/relay-via-do/echo" => self.handle_echo().await,
            other => Response::error(format!("EngineIoSessionDo: unknown path {other}"), 404),
        }
    }
}

/// Captured outputs of [`EngineIoSessionDo::establish_session`].
struct EstablishedSession {
    transport: crate::transport_socketio::SocketIoTransport,
    wallet: bsv::wallet::ProtoWallet,
    app_event_rx: futures::channel::mpsc::UnboundedReceiver<crate::transport_socketio::AppEvent>,
    server_identity: bsv::primitives::PublicKey,
    server_nonce_b64: String,
    client_pub_hex: String,
    engineio_sid: String,
    handshake_round_trip_ms: f64,
    relay: String,
}

impl EngineIoSessionDo {
    /// `GET /relay-via-do/identity` — returns this DO's stable
    /// `client_identity` pubkey hex derived from the `SERVER_PRIVATE_KEY`
    /// secret. Two consecutive curls MUST return the same hex (H-3.5a
    /// empirical bar). Does NOT touch the network.
    async fn handle_identity(&self) -> Result<Response> {
        let priv_hex = self
            .env
            .secret("SERVER_PRIVATE_KEY")
            .map_err(|_| {
                Error::RustError(
                    "Missing SERVER_PRIVATE_KEY secret; set via \
                     `wrangler secret put SERVER_PRIVATE_KEY`"
                        .into(),
                )
            })?
            .to_string();

        let client_priv = bsv::primitives::PrivateKey::from_hex(&priv_hex).map_err(|e| {
            Error::RustError(format!(
                "invalid SERVER_PRIVATE_KEY (expected 32-byte hex): {e:?}"
            ))
        })?;
        let client_pub_hex = client_priv.public_key().to_hex();

        Response::from_json(&serde_json::json!({
            "socketio_status": "do_identity",
            "do_id": self.state.id().to_string(),
            "do_name": "cosigner-test-1",
            "client_identity": client_pub_hex,
            "gate": "H-3.5a",
        }))
    }

    /// `GET /relay-via-do/handshake` — drive a full BRC-103 mutual auth
    /// handshake. H-3.5b empirical bar: returns `brc103_authenticated`
    /// with the SAME `client_identity` as `/relay-via-do/identity` AND
    /// `server_identity` matching the live relay (`02d7c923...`).
    async fn handle_handshake(&self) -> Result<Response> {
        let t_start = js_sys::Date::now();
        let session = self.establish_session().await?;
        let elapsed_ms = js_sys::Date::now() - t_start;

        Response::from_json(&serde_json::json!({
            "socketio_status": "brc103_authenticated",
            "do_id": self.state.id().to_string(),
            "do_name": "cosigner-test-1",
            "relay": session.relay,
            "engineio_sid": session.engineio_sid,
            "client_identity": session.client_pub_hex,
            "server_identity": session.server_identity.to_hex(),
            "handshake_round_trip_ms": session.handshake_round_trip_ms,
            "elapsed_ms": elapsed_ms,
            "gate": "H-3.5b",
        }))
    }

    /// `GET /relay-via-do/echo` — canonical envelope round-trip through
    /// the DO. H-3.5c empirical bar: full handshake + joinRoom +
    /// sendMessage + await `sendMessageAck-<roomId>` + JSON proof with
    /// byte-identical messageId echo. Mirrors H-3.4 /envelope-roundtrip
    /// but driven by the stable-identity DO instead of a per-request
    /// `PrivateKey::random()`.
    async fn handle_echo(&self) -> Result<Response> {
        use crate::transport_socketio::emit_signed_general;
        use futures::StreamExt;

        let t_start = js_sys::Date::now();
        let mut session = self.establish_session().await?;

        // Unique room name per request (canonical messageBox convention
        // — server reconstructs `roomId = "{identity}-{messageBox}"`).
        let now_ms = js_sys::Date::now() as u64;
        let message_box = format!("h35c-{now_ms}");
        let room_id = format!("{}-{}", session.client_pub_hex, message_box);
        let message_id = format!("h35c-test-{now_ms}");
        let body_text = format!("envelope-roundtrip-{room_id}");

        // (1) joinRoom — signed General; data = roomId string.
        let t_join_start = js_sys::Date::now();
        let join_data = serde_json::json!(room_id);
        let _joined = emit_signed_general(
            &session.transport,
            &session.wallet,
            &session.server_identity,
            &session.server_nonce_b64,
            "joinRoom",
            &join_data,
        )
        .await
        .map_err(|e| Error::RustError(format!("emit joinRoom: {e:?}")))?;
        let join_round_trip_ms = js_sys::Date::now() - t_join_start;

        // (2) sendMessage — canonical {messageBox, message: {messageId,
        // recipient, body}} envelope. Self-recipient so the ack comes
        // back to us.
        let t_send_start = js_sys::Date::now();
        let send_data = serde_json::json!({
            "messageBox": message_box,
            "message": {
                "messageId": message_id,
                "recipient": session.client_pub_hex,
                "body": body_text,
            }
        });
        let sent = emit_signed_general(
            &session.transport,
            &session.wallet,
            &session.server_identity,
            &session.server_nonce_b64,
            "sendMessage",
            &send_data,
        )
        .await
        .map_err(|e| Error::RustError(format!("emit sendMessage: {e:?}")))?;

        // (3) Drain inbound events until we see sendMessageAck-<roomId>.
        let expected_ack = format!("sendMessageAck-{room_id}");
        let mut intermediate_events: Vec<String> = Vec::new();
        let ack_event = loop {
            let ev = match session.app_event_rx.next().await {
                Some(e) => e,
                None => {
                    return Response::error(
                        format!(
                            "inbound channel closed before ack; intermediates={:?}",
                            intermediate_events
                        ),
                        502,
                    );
                }
            };
            if ev.event_name == expected_ack {
                break ev;
            }
            intermediate_events.push(ev.event_name);
        };
        let ack_round_trip_ms = js_sys::Date::now() - t_send_start;
        let elapsed_ms = js_sys::Date::now() - t_start;

        Response::from_json(&serde_json::json!({
            "socketio_status": "envelope_roundtripped",
            "do_id": self.state.id().to_string(),
            "do_name": "cosigner-test-1",
            "relay": session.relay,
            "engineio_sid": session.engineio_sid,
            "client_identity": session.client_pub_hex,
            "server_identity": session.server_identity.to_hex(),
            "room_id": room_id,
            "sent_message_id": message_id,
            "ack_event_name": ack_event.event_name,
            "ack_data": ack_event.data,
            "ack_message_id_matches_sent":
                ack_event.data.get("messageId").and_then(|v| v.as_str())
                    == Some(message_id.as_str()),
            "intermediate_events": intermediate_events,
            "join_round_trip_ms": join_round_trip_ms,
            "ack_round_trip_ms": ack_round_trip_ms,
            "handshake_round_trip_ms": session.handshake_round_trip_ms,
            "elapsed_ms": elapsed_ms,
            "sent_payload_bytes_len": sent.payload_bytes.len(),
            "gate": "H-3.5c",
        }))
    }

    /// Drive a fresh BRC-103 session against the live Calhoun relay.
    /// Returns the captured substrate (Peer is set up + started; the
    /// app-event listener is registered; the dispatch task is spawned;
    /// InitialResponse has already been observed and `server_identity`
    /// + `server_nonce_b64` extracted).
    ///
    /// Identity is loaded from `SERVER_PRIVATE_KEY` every call — stable
    /// across the DO's lifetime. The handshake itself is fresh per call
    /// (new Engine.IO sid, new nonces) per Strategy 1 — H-3.5e proves
    /// this works across forced hibernation.
    async fn establish_session(&self) -> Result<EstablishedSession> {
        use crate::engineio_codec::{EngineIoPacket, SocketIoPacket};
        use crate::transport_socketio::{
            install_app_event_listener, run_dispatch, SocketIoTransport,
        };
        use bsv::auth::transports::Transport;
        use bsv::auth::types::{AuthMessage, MessageType};
        use bsv::auth::{Peer, PeerOptions};
        use bsv::primitives::{to_base64, PrivateKey};
        use bsv::wallet::ProtoWallet;
        use futures::channel::oneshot;
        use rand::RngCore;

        let relay = self
            .env
            .var("RELAY_URL")
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "https://rust-message-box.dev-a3e.workers.dev".to_string());

        let handshake = crate::transport_wasm::polling_handshake(&relay)
            .await
            .map_err(|e| Error::RustError(format!("polling_handshake: {e}")))?;
        let mut ws = crate::transport_wasm::WsHandle::open_and_upgrade(&relay, &handshake.sid)
            .await
            .map_err(|e| Error::RustError(format!("WS open+upgrade: {e}")))?;

        // Socket.IO 5 CONNECT to default namespace.
        let connect_pkt = SocketIoPacket::Connect {
            nsp: "/".to_string(),
            data: None,
        };
        ws.send_socketio(&connect_pkt)
            .map_err(|e| Error::RustError(format!("send Socket.IO CONNECT: {e}")))?;
        loop {
            let pkt = ws
                .recv_engineio()
                .await
                .map_err(|e| Error::RustError(format!("ws closed waiting for CONNECT-ack: {e}")))?;
            match pkt {
                EngineIoPacket::Ping(payload) => {
                    let _ = ws.send_engineio(&EngineIoPacket::Pong(payload));
                }
                EngineIoPacket::Message(payload) => {
                    if let Ok(SocketIoPacket::Connect { .. }) = SocketIoPacket::decode(&payload) {
                        break;
                    }
                }
                _ => {}
            }
        }

        // Transport substrate + dispatch task with snoop.
        let sender = ws.sender();
        let transport = SocketIoTransport::new(sender.clone());
        let callback_handle = transport.callback_handle();
        let (snoop_tx, snoop_rx) = oneshot::channel::<AuthMessage>();
        wasm_bindgen_futures::spawn_local(async move {
            run_dispatch(ws, sender, callback_handle, Some(snoop_tx)).await;
        });

        // Stable identity from SERVER_PRIVATE_KEY.
        let priv_hex = self
            .env
            .secret("SERVER_PRIVATE_KEY")
            .map_err(|_| {
                Error::RustError(
                    "Missing SERVER_PRIVATE_KEY secret; set via `wrangler secret put`".into(),
                )
            })?
            .to_string();
        let client_priv = PrivateKey::from_hex(&priv_hex).map_err(|e| {
            Error::RustError(format!("invalid SERVER_PRIVATE_KEY (32-byte hex): {e:?}"))
        })?;
        let client_pub_hex = client_priv.public_key().to_hex();
        let wallet = ProtoWallet::new(Some(client_priv));

        let peer = Peer::new(PeerOptions {
            wallet: wallet.clone(),
            transport: transport.clone(),
            certificates_to_request: None,
            session_manager: None,
            auto_persist_last_session: false,
            originator: Some("poc17-cf-outbound-ws/h3.5".to_string()),
        });
        peer.start();

        // Register inbound listener BEFORE sending any outbound.
        let (app_event_rx, _cb_id) = install_app_event_listener(&peer).await;

        // Path 2 manual InitialRequest.
        let my_identity = peer
            .get_identity_key()
            .await
            .map_err(|e| Error::RustError(format!("peer.get_identity_key: {e:?}")))?;
        let mut nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let initial_nonce_b64 = to_base64(&nonce_bytes);
        let mut initial_req = AuthMessage::new(MessageType::InitialRequest, my_identity);
        initial_req.initial_nonce = Some(initial_nonce_b64);

        let t_send_start = js_sys::Date::now();
        transport
            .send(&initial_req)
            .await
            .map_err(|e| Error::RustError(format!("transport.send InitialRequest: {e:?}")))?;

        // Await server's InitialResponse off the snoop.
        let server_response = snoop_rx.await.map_err(|e| {
            Error::RustError(format!(
                "snoop canceled before InitialResponse arrived: {e:?}"
            ))
        })?;
        let server_identity = server_response.identity_key.clone();
        let server_nonce_b64 = server_response
            .initial_nonce
            .as_deref()
            .or(server_response.nonce.as_deref())
            .ok_or_else(|| {
                Error::RustError("InitialResponse missing both initial_nonce and nonce".into())
            })?
            .to_string();
        let handshake_round_trip_ms = js_sys::Date::now() - t_send_start;

        Ok(EstablishedSession {
            transport,
            wallet,
            app_event_rx,
            server_identity,
            server_nonce_b64,
            client_pub_hex,
            engineio_sid: handshake.sid,
            handshake_round_trip_ms,
            relay,
        })
    }
}
