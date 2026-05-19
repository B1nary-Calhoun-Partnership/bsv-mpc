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
        // H-3.3b gate: BRC-103 mutual auth via SocketIoTransport + Peer.
        // Builds on the H-3.3a substrate (polling → WS upgrade → Socket.IO
        // CONNECT), then wires `bsv_rs::auth::Peer` over our new
        // `SocketIoTransport`, sends an `InitialRequest` manually via the
        // transport (Path 2; avoids `Peer::initiate_handshake` which uses
        // `tokio::time::timeout` — non-functional in `wasm32-unknown-unknown`
        // CF Worker scope per audit §11.2 + the server's own analysis at
        // `~/bsv/bsv-messagebox-cloudflare-public/src/engineio/auth.rs:14-26`),
        // and snoops the server's `InitialResponse` off the dispatch loop
        // for the JSON proof.
        .get_async("/brc103-handshake", |_req, ctx| async move {
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

            // Engine.IO 4 WS upgrade.
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

            // Socket.IO 5 CONNECT exchange — same substrate as H-3.3a but
            // inlined here so the route is self-contained.
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
                        return Response::error(
                            format!("ws closed waiting for CONNECT-ack: {e}"),
                            502,
                        )
                    }
                };
                match pkt {
                    EngineIoPacket::Ping(payload) => {
                        let _ = ws.send_engineio(&EngineIoPacket::Pong(payload));
                    }
                    EngineIoPacket::Message(payload) => {
                        if let Ok(SocketIoPacket::Connect { .. }) = SocketIoPacket::decode(&payload)
                        {
                            break; // CONNECT-ack — Socket.IO ready.
                        }
                    }
                    _ => {}
                }
            }

            // Build the SocketIoTransport substrate. `transport` is Clone
            // (all internal state is `Arc`-shared or JS-handle-cheap), so
            // we hand one clone to `Peer::new` (consumed by value) and
            // keep this one to invoke `transport.send(&InitialRequest)`
            // directly for the Path 2 handshake trigger.
            let sender = ws.sender();
            let transport = SocketIoTransport::new(sender.clone());
            let callback_handle = transport.callback_handle();

            // Snoop oneshot: the dispatch task captures the full
            // InitialResponse `AuthMessage` off the first inbound frame
            // before invoking Peer's callback. This is how we surface
            // the handshake completion to the route handler without
            // needing `Peer::initiate_handshake`'s (tokio-bound) wait
            // machinery. /brc103-handshake only needs `identity_key`;
            // /envelope-roundtrip (H-3.4.C) also needs the
            // `initial_nonce` so it can construct the BRC-31 key_id for
            // outbound signed Generals.
            let (snoop_tx, snoop_rx) = oneshot::channel::<AuthMessage>();

            // Spawn the inbound dispatch task. Consumes the WsHandle —
            // dispatch owns inbound exclusively. The dispatch sender
            // clone is for auto-Pong on inbound Ping frames.
            wasm_bindgen_futures::spawn_local(async move {
                run_dispatch(ws, sender, callback_handle, Some(snoop_tx)).await;
            });

            // One-shot client identity. Phase H Step 4 will swap this
            // for the cosigner's stable identity priv per audit §11.4.
            let client_priv = PrivateKey::random();
            let client_pub_hex = client_priv.public_key().to_hex();
            let wallet = ProtoWallet::new(Some(client_priv));

            // Wire Peer over our SocketIoTransport. peer.start() installs
            // the inbound callback into our `Arc<StdMutex<...>>` slot;
            // the dispatch task (already running) will invoke it on each
            // decoded `authMessage` event.
            let peer = Peer::new(PeerOptions {
                wallet,
                transport: transport.clone(),
                certificates_to_request: None,
                session_manager: None,
                auto_persist_last_session: false,
                originator: Some("poc17-cf-outbound-ws".to_string()),
            });
            peer.start();

            // Construct InitialRequest manually. Per
            // `~/bsv/bsv-rs/src/auth/types.rs:183`, `InitialRequest` is
            // unsigned (the protocol bootstrap), so all we need is our
            // identity_key + a random 32-byte initial_nonce.
            let my_identity = match peer.get_identity_key().await {
                Ok(k) => k,
                Err(e) => {
                    return Response::error(format!("peer.get_identity_key: {e:?}"), 500);
                }
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

            // Await the dispatch task's snoop of the InitialResponse.
            // The CF Worker request lifecycle bounds this — if the relay
            // never replies, the request times out at ~30s rather than
            // hanging indefinitely.
            let server_response = match snoop_rx.await {
                Ok(msg) => msg,
                Err(e) => {
                    return Response::error(
                        format!("snoop oneshot canceled before InitialResponse arrived: {e:?}"),
                        502,
                    )
                }
            };
            let server_identity_hex = server_response.identity_key.to_hex();
            let handshake_round_trip_ms = js_sys::Date::now() - t_send_start;
            let elapsed_ms = js_sys::Date::now() - t_start;

            Response::from_json(&serde_json::json!({
                "socketio_status": "brc103_authenticated",
                "relay": relay,
                "engineio_sid": handshake.sid,
                "client_identity": client_pub_hex,
                "server_identity": server_identity_hex,
                "handshake_round_trip_ms": handshake_round_trip_ms,
                "elapsed_ms": elapsed_ms,
                "gate": "H-3.3b",
            }))
        })
        .run(req, env)
        .await
}
