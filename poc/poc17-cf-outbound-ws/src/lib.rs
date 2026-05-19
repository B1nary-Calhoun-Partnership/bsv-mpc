//! # POC 17 — Phase H Step 3: pure-Rust Engine.IO + Socket.IO client + BRC-103 transport
//!
//! Cloudflare Worker (DO scaffolding lands in H-3.5) that proves the
//! **pure Rust+WASM** substrate for the Phase H wasm32 MessageBox client
//! (audit `docs/PHASE-H-AUDIT.md` §2.5b + §11 + §11.2 revised).
//!
//! ## The five gates (audit §6.2 as rewritten in §2.5b)
//!
//! | Gate | What it proves | Status |
//! |---|---|---|
//! | H-3.1 | `cargo build --target wasm32-unknown-unknown -p poc17-cf-outbound-ws` clean | ✓ `cb923fc` |
//! | H-3.2a | Engine.IO polling handshake against live relay via `worker::Fetch` | ✓ `bc8b0b4` |
//! | H-3.2b | WS upgrade via `web_sys::WebSocket`; Engine.IO probe/pong/upgrade dance | ✓ `6ff1a53` |
//! | H-3.3a | Long-lived `WsHandle` + Socket.IO CONNECT/ack exchange over the upgraded WS | this commit |
//! | H-3.3b | BRC-103 mutual auth via `SocketIoTransport` driving `bsv_rs::auth::Peer` | next commit |
//! | H-3.4 | Canonical CBOR envelope round-trips byte-exact through the live Calhoun relay | subsequent |
//! | H-3.5 | Forced-hibernation reconnect via the DO; backfill via `/listMessages` | subsequent |

pub mod engineio_codec;
pub mod socketio_client;
pub mod transport;
pub mod transport_socketio;
pub mod transport_wasm;
pub mod worker_do;

use worker::*;

/// Default relay URL — overridable via `RELAY_URL` env var declared in
/// `wrangler.example.toml` so the operator can point the POC at a
/// staging relay for testing.
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";

/// CF Worker fetch event handler. H-3.2a routes `GET /open` to the
/// Engine.IO polling handshake; future gates add more endpoints.
#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();

    router
        // Liveness / sanity — also useful for verifying wrangler dev works
        // before exercising any outbound network.
        .get("/health", |_req, _ctx| {
            Response::ok("poc17-cf-outbound-ws — Phase H POC. See README.md for gates.\n")
        })
        // H-3.2 gate: drive the full Engine.IO 4 client handshake
        // against the live relay — polling phase (H-3.2a) followed by
        // the WS upgrade dance (H-3.2b). Returns parsed Open payload +
        // upgrade-result JSON.
        .get_async("/open", |_req, ctx| async move {
            let relay = ctx
                .env
                .var("RELAY_URL")
                .map(|v| v.to_string())
                .unwrap_or_else(|_| DEFAULT_RELAY.to_string());

            // H-3.2a: polling handshake.
            let handshake = match transport_wasm::polling_handshake(&relay).await {
                Ok(h) => h,
                Err(e) => return Response::error(format!("polling handshake failed: {e}"), 502),
            };

            // H-3.2b: WS upgrade via web_sys::WebSocket. Returns once
            // the `5` Upgrade packet has been sent after a successful
            // probe/pong exchange.
            let upgrade = match transport_wasm::upgrade_to_websocket(&relay, &handshake.sid).await {
                Ok(u) => u,
                Err(e) => {
                    return Response::error(
                        format!("ws upgrade failed (sid={}): {e}", handshake.sid),
                        502,
                    )
                }
            };

            Response::from_json(&serde_json::json!({
                "socketio_status": "ws_upgraded",
                "relay": relay,
                "sid": handshake.sid,
                "upgrades": handshake.upgrades,
                "pingInterval": handshake.ping_interval,
                "pingTimeout": handshake.ping_timeout,
                "maxPayload": handshake.max_payload,
                "ws_url": upgrade.ws_url,
                "probe_round_trip_ms": upgrade.probe_round_trip_ms,
                "gate": "H-3.2 (H-3.2a polling + H-3.2b ws-upgrade)",
            }))
        })
        // H-3.3a gate: take the upgraded WS and exchange the Socket.IO
        // CONNECT packet to default namespace. Server replies with
        // `40{"sid":"..."}` (Engine.IO Message wrapping Socket.IO
        // CONNECT-ack). Proves the long-lived WsHandle + persistent mpsc
        // inbound dispatch + the codec's Socket.IO layer all work
        // end-to-end against the live relay.
        .get_async("/socketio-connect", |_req, ctx| async move {
            use crate::engineio_codec::SocketIoPacket;

            let relay = ctx
                .env
                .var("RELAY_URL")
                .map(|v| v.to_string())
                .unwrap_or_else(|_| DEFAULT_RELAY.to_string());

            // Engine.IO 4 polling phase.
            let handshake = match transport_wasm::polling_handshake(&relay).await {
                Ok(h) => h,
                Err(e) => return Response::error(format!("polling handshake failed: {e}"), 502),
            };

            // Engine.IO 4 WS upgrade — held as a live handle for the
            // rest of this request (drops only when ws goes out of scope).
            let mut ws =
                match transport_wasm::WsHandle::open_and_upgrade(&relay, &handshake.sid).await {
                    Ok(h) => h,
                    Err(e) => {
                        return Response::error(
                            format!("ws open+upgrade failed (sid={}): {e}", handshake.sid),
                            502,
                        )
                    }
                };

            // Socket.IO 5 CONNECT to default namespace (`40`). The default
            // namespace `/` is OMITTED in the wire form per the vendored
            // codec's §SocketIoPacket doc-comment (line ~158).
            let connect_pkt = SocketIoPacket::Connect {
                nsp: "/".to_string(),
                data: None,
            };
            if let Err(e) = ws.send_socketio(&connect_pkt) {
                return Response::error(format!("send Socket.IO CONNECT: {e}"), 502);
            }
            let t_connect_start = js_sys::Date::now();

            // Await CONNECT-ack. Pull frames until we find an Engine.IO
            // Message carrying a Socket.IO CONNECT packet — the server
            // may interleave Engine.IO Ping packets (e.g. from the
            // upgrade-finalize handshake), which we just acknowledge and
            // keep waiting.
            let mut frames_seen: Vec<String> = Vec::new();
            let socket_sid;
            loop {
                let pkt = match ws.recv_engineio().await {
                    Ok(p) => p,
                    Err(e) => {
                        return Response::error(
                            format!(
                                "ws closed waiting for CONNECT-ack \
                                 after {} frame(s) seen={:?}: {e}",
                                frames_seen.len(),
                                frames_seen
                            ),
                            502,
                        )
                    }
                };
                match pkt {
                    crate::engineio_codec::EngineIoPacket::Ping(payload) => {
                        // Server-initiated heartbeat — reply with Pong so
                        // the relay doesn't time us out while we wait.
                        let pong = crate::engineio_codec::EngineIoPacket::Pong(payload).encode();
                        if let Err(e) = ws.send_text(&pong) {
                            return Response::error(format!("ws send Pong: {e}"), 502);
                        }
                        frames_seen.push("ping/pong".to_string());
                    }
                    crate::engineio_codec::EngineIoPacket::Noop => {
                        frames_seen.push("noop".to_string());
                    }
                    crate::engineio_codec::EngineIoPacket::Message(payload) => {
                        // Decode the Socket.IO layer.
                        let sio = match SocketIoPacket::decode(&payload) {
                            Ok(s) => s,
                            Err(e) => {
                                frames_seen.push(format!("socketio-decode-err:{e}"));
                                continue;
                            }
                        };
                        match sio {
                            SocketIoPacket::Connect { nsp, data } => {
                                let sid_from_data = data
                                    .as_ref()
                                    .and_then(|v| v.get("sid"))
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string());
                                socket_sid = sid_from_data
                                    .unwrap_or_else(|| format!("(no sid in payload; nsp={nsp})"));
                                break;
                            }
                            other => {
                                frames_seen.push(format!("unexpected-sio:{other:?}"));
                            }
                        }
                    }
                    other => {
                        frames_seen.push(format!("unexpected-eio:{other:?}"));
                    }
                }
            }
            let connect_round_trip_ms = js_sys::Date::now() - t_connect_start;

            Response::from_json(&serde_json::json!({
                "socketio_status": "socketio_connected",
                "relay": relay,
                "engineio_sid": handshake.sid,
                "socketio_sid": socket_sid,
                "probe_round_trip_ms": ws.probe_round_trip_ms(),
                "connect_round_trip_ms": connect_round_trip_ms,
                "ws_url": ws.url(),
                "intermediate_frames": frames_seen,
                "gate": "H-3.3a",
            }))
        })
        .run(req, env)
        .await
}
