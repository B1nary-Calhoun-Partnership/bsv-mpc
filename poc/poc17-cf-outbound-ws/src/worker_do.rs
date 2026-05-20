//! Durable Object that owns one cosigner's BRC-103 session against the
//! MessageBox relay. Replaces the H-3.1 stub.
//!
//! # H-3.5a scope
//!
//! Minimum-viable scaffold: the DO loads its identity priv from the
//! `SERVER_PRIVATE_KEY` secret on every fetch, derives the cosigner's
//! public-key hex, and surfaces it via `/identity`. The DO is bound as
//! `ENGINEIO_SESSION_DO` per `wrangler.toml`; the worker entry point
//! reaches it via
//! `env.durable_object("ENGINEIO_SESSION_DO")?.id_from_name("cosigner-test-1")?.get_stub()?.fetch_with_request(req)`.
//!
//! # Locked design decisions (from `docs/H-3-5-PLAN.md`)
//!
//! - **Identity from `SERVER_PRIVATE_KEY` secret**, not random per-DO.
//!   Matches every production Calhoun worker
//!   (`~/bsv/agents/test-agent/src/lib.rs:86`).
//! - **Per-identity DO** (audit §11.1 lock): one DO per cosigner.
//! - **Strategy 1 — re-handshake on every wake** (H-3.5 plan §"Reconnect strategy"):
//!   the outbound WS is NOT hibernation-eligible (no `state.accept_web_socket()`
//!   contract for client sockets); the relay's per-sid `SessionState` resets
//!   on a fresh Engine.IO sid anyway, so caching the BRC-103 session state
//!   wouldn't help. H-3.5a doesn't yet exercise the handshake — that's H-3.5b.
//! - **Empirical harness: deploy + curl** only (`wrangler dev` does not
//!   hibernate DOs). Truth lives in the deployed worker.
//!
//! # H-3.5b+ extensions (later sub-gates)
//!
//! - **H-3.5b**: in-DO BRC-103 handshake. Moves the H-3.3b /brc103-handshake
//!   flow into `fetch_handshake()`.
//! - **H-3.5c**: `/echo` POST handler — emits a signed General + awaits
//!   sendMessageAck through the DO-owned Peer.
//! - **H-3.5d**: persist `PersistedBrc103Session` (last_known_peer_identity_hex,
//!   persisted_at_ms, relay_url) to `state.storage()`.
//! - **H-3.5e**: forced-hibernation merge gate — pre.json + idle ≥70s + post.json
//!   with identical client_identity AND server_identity.

use worker::*;

/// The Durable Object class. One instance per cosigner identity (per
/// audit §11.1). Currently holds only the runtime handles; future
/// sub-gates add `inner: RefCell<Option<SessionPeer>>` for the live
/// `Peer` + `WsSender` between fetches.
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

        // The DO receives requests forwarded by the worker entry point's
        // `/relay-via-do/*` routes. The path is the full original URL
        // path, so we match on the full string (mirrors the canonical
        // pattern in `~/bsv/bsv-messagebox-cloudflare-public/src/engineio/session.rs`).
        match path {
            "/relay-via-do/identity" => self.handle_identity().await,
            "/relay-via-do/handshake" => self.handle_handshake().await,
            other => Response::error(format!("EngineIoSessionDo: unknown path {other}"), 404),
        }
    }
}

impl EngineIoSessionDo {
    /// `GET /relay-via-do/identity` — returns this DO's stable
    /// `client_identity` pubkey hex derived from the `SERVER_PRIVATE_KEY`
    /// secret. Two consecutive curls MUST return the same hex (H-3.5a
    /// empirical bar).
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
    /// handshake against the live Calhoun MessageBox relay from INSIDE
    /// the DO. Same wire shape as the H-3.3b /brc103-handshake route at
    /// `lib.rs:223-389`, but with identity loaded from
    /// `SERVER_PRIVATE_KEY` (stable per-DO) instead of
    /// `PrivateKey::random()` (ephemeral per-request).
    ///
    /// Path 2 (manual InitialRequest construction) retained per the
    /// locked H-3.5 plan — the canonical `Peer::initiate_handshake`
    /// would work in v0.3.9 but Path 2 gives us direct snoop control.
    /// Step 4 migration switches to canonical Peer paths in
    /// `crates/bsv-mpc-messagebox/`.
    ///
    /// Empirical bar: deploy + curl returns `brc103_authenticated` with
    /// the SAME `client_identity` as `/relay-via-do/identity` (stable
    /// per-DO from secret) AND `server_identity` matching the live
    /// relay's identity (`02d7c923...`).
    async fn handle_handshake(&self) -> Result<Response> {
        use crate::engineio_codec::{EngineIoPacket, SocketIoPacket};
        use crate::transport_socketio::{run_dispatch, SocketIoTransport};
        use bsv::auth::transports::Transport;
        use bsv::auth::types::{AuthMessage, MessageType};
        use bsv::auth::{Peer, PeerOptions};
        use bsv::primitives::{to_base64, PrivateKey};
        use bsv::wallet::ProtoWallet;
        use futures::channel::oneshot;
        use rand::RngCore;

        let t_start = js_sys::Date::now();

        let relay = self
            .env
            .var("RELAY_URL")
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "https://rust-message-box.dev-a3e.workers.dev".to_string());

        // Engine.IO 4 polling phase.
        let handshake = match crate::transport_wasm::polling_handshake(&relay).await {
            Ok(h) => h,
            Err(e) => return Response::error(format!("polling handshake failed: {e}"), 502),
        };

        // Engine.IO 4 WS upgrade.
        let mut ws =
            match crate::transport_wasm::WsHandle::open_and_upgrade(&relay, &handshake.sid).await {
                Ok(h) => h,
                Err(e) => {
                    return Response::error(
                        format!("ws open+upgrade failed (sid={}): {e}", handshake.sid),
                        502,
                    )
                }
            };

        // Socket.IO 5 CONNECT exchange.
        let connect_pkt = SocketIoPacket::Connect {
            nsp: "/".to_string(),
            data: None,
        };
        if let Err(e) = ws.send_socketio(&connect_pkt) {
            return Response::error(format!("send Socket.IO CONNECT: {e}"), 502);
        }
        loop {
            let pkt = match ws.recv_engineio().await {
                Ok(p) => p,
                Err(e) => {
                    return Response::error(format!("ws closed waiting for CONNECT-ack: {e}"), 502)
                }
            };
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

        // Build SocketIoTransport + dispatch task.
        let sender = ws.sender();
        let transport = SocketIoTransport::new(sender.clone());
        let callback_handle = transport.callback_handle();
        let (snoop_tx, snoop_rx) = oneshot::channel::<AuthMessage>();
        wasm_bindgen_futures::spawn_local(async move {
            run_dispatch(ws, sender, callback_handle, Some(snoop_tx)).await;
        });

        // Stable identity from `SERVER_PRIVATE_KEY` secret (per H-3.5
        // locked discipline — NOT `PrivateKey::random()` like H-3.3b).
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

        // Peer.new + start. Requires bsv-rs ≥ 0.3.9 for the wasm32
        // SystemTime fix (PeerSession::touch panic in v0.3.8 and earlier).
        let peer = Peer::new(PeerOptions {
            wallet,
            transport: transport.clone(),
            certificates_to_request: None,
            session_manager: None,
            auto_persist_last_session: false,
            originator: Some("poc17-cf-outbound-ws/h3.5".to_string()),
        });
        peer.start();

        // Path 2 manual InitialRequest.
        let my_identity = match peer.get_identity_key().await {
            Ok(k) => k,
            Err(e) => return Response::error(format!("peer.get_identity_key: {e:?}"), 500),
        };
        let mut nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let initial_nonce_b64 = to_base64(&nonce_bytes);
        let mut initial_req = AuthMessage::new(MessageType::InitialRequest, my_identity);
        initial_req.initial_nonce = Some(initial_nonce_b64);

        let t_send_start = js_sys::Date::now();
        if let Err(e) = transport.send(&initial_req).await {
            return Response::error(format!("transport.send InitialRequest: {e:?}"), 502);
        }

        let server_response = match snoop_rx.await {
            Ok(msg) => msg,
            Err(e) => {
                return Response::error(
                    format!("snoop oneshot canceled before InitialResponse: {e:?}"),
                    502,
                )
            }
        };
        let server_identity_hex = server_response.identity_key.to_hex();
        let handshake_round_trip_ms = js_sys::Date::now() - t_send_start;
        let elapsed_ms = js_sys::Date::now() - t_start;

        Response::from_json(&serde_json::json!({
            "socketio_status": "brc103_authenticated",
            "do_id": self.state.id().to_string(),
            "do_name": "cosigner-test-1",
            "relay": relay,
            "engineio_sid": handshake.sid,
            "client_identity": client_pub_hex,
            "server_identity": server_identity_hex,
            "handshake_round_trip_ms": handshake_round_trip_ms,
            "elapsed_ms": elapsed_ms,
            "gate": "H-3.5b",
        }))
    }
}
