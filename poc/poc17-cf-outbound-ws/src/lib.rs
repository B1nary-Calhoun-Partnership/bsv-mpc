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
        // H-3.4 gate: canonical envelope round-trip via signed BRC-31
        // Generals on the post-handshake Socket.IO `authMessage` channel.
        // Builds on H-3.3b's BRC-103 handshake, then exercises the full
        // application-event substrate:
        //   1. install_app_event_listener — registers a Peer
        //      general_message_callback that decodes `{eventName, data}`
        //      JSON envelopes from inbound General payloads and forwards
        //      on an mpsc.
        //   2. emit_signed_general — builds + signs + emits an outbound
        //      General wrapping a `joinRoom` envelope, then another for
        //      `sendMessage`. Byte-identical to canonical TS
        //      `peer.toPeer(encoded, serverIdentityKey)` per
        //      `~/bsv/authsocket-client/src/AuthSocketClient.ts:59-65`.
        //   3. Await the live relay's `sendMessageAck-<roomId>` reply on
        //      the inbound mpsc.
        //   4. Return JSON proof with byte-comparison of the round-trip.
        .get_async("/envelope-roundtrip", |_req, ctx| async move {
            use crate::engineio_codec::{EngineIoPacket, SocketIoPacket};
            use crate::transport_socketio::{
                emit_signed_general, install_app_event_listener, run_dispatch, SocketIoTransport,
            };
            use bsv::auth::transports::Transport;
            use bsv::auth::types::{AuthMessage, MessageType};
            use bsv::auth::{Peer, PeerOptions};
            use bsv::primitives::{to_base64, PrivateKey};
            use bsv::wallet::ProtoWallet;
            use futures::channel::oneshot;
            use futures::StreamExt;
            use rand::RngCore;

            let t_start = js_sys::Date::now();

            let relay = ctx
                .env
                .var("RELAY_URL")
                .map(|v| v.to_string())
                .unwrap_or_else(|_| DEFAULT_RELAY.to_string());

            // Engine.IO + Socket.IO substrate — identical to /brc103-handshake.
            let handshake = match transport_wasm::polling_handshake(&relay).await {
                Ok(h) => h,
                Err(e) => return Response::error(format!("polling handshake failed: {e}"), 502),
            };
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
                            break;
                        }
                    }
                    _ => {}
                }
            }

            // SocketIoTransport substrate.
            let sender = ws.sender();
            let transport = SocketIoTransport::new(sender.clone());
            let callback_handle = transport.callback_handle();
            let (snoop_tx, snoop_rx) = oneshot::channel::<AuthMessage>();

            // Spawn dispatch task. Consumes the WsHandle; owns inbound.
            wasm_bindgen_futures::spawn_local(async move {
                run_dispatch(ws, sender, callback_handle, Some(snoop_tx)).await;
            });

            // Identity + Peer wiring. Canonical path (bsv-rs ≥ 0.3.9
            // required — v0.3.9 ships the wasm32 cfg-gate for
            // `current_time_ms` that Peer's session manager invokes via
            // `session.touch()` on every inbound message).
            let client_priv = PrivateKey::random();
            let client_pub_hex = client_priv.public_key().to_hex();
            let wallet = ProtoWallet::new(Some(client_priv));
            let peer = Peer::new(PeerOptions {
                wallet: wallet.clone(),
                transport: transport.clone(),
                certificates_to_request: None,
                session_manager: None,
                auto_persist_last_session: false,
                originator: Some("poc17-cf-outbound-ws".to_string()),
            });
            peer.start();

            // Register the inbound app-event listener BEFORE sending any
            // outbound General. If the server pushes events between our
            // send + the listener registration, we'd miss them.
            let (mut app_event_rx, _cb_id) = install_app_event_listener(&peer).await;

            // Trigger BRC-103 handshake (Path 2 — manual InitialRequest;
            // sidesteps `Peer::initiate_handshake`'s tokio::time::timeout
            // even though v0.3.8+ has the runtime-agnostic fix, because
            // get_authenticated_session's None-identity branch unconditionally
            // calls initiate_handshake which we still want to avoid for
            // ergonomic reasons — Path 2 gives us direct control over
            // the snoop + handshake completion).
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
            let t_handshake_start = js_sys::Date::now();
            if let Err(e) = transport.send(&initial_req).await {
                return Response::error(format!("transport.send InitialRequest: {e:?}"), 502);
            }

            // Await server's InitialResponse. Extract identity + nonce
            // (server's session-nonce) — both load-bearing for outbound
            // signed Generals.
            let server_response = match snoop_rx.await {
                Ok(msg) => msg,
                Err(e) => {
                    return Response::error(
                        format!("snoop oneshot canceled before InitialResponse: {e:?}"),
                        502,
                    )
                }
            };
            let server_identity = server_response.identity_key.clone();
            let server_identity_hex = server_identity.to_hex();
            // BRC-31 cross-SDK compat: TS sends `initialNonce` only; Go
            // sends both `nonce` and `initial_nonce`. Accept either, per
            // `~/bsv/bsv-rs/src/auth/peer.rs:190-200`.
            let server_nonce_b64 = match server_response
                .initial_nonce
                .as_deref()
                .or(server_response.nonce.as_deref())
            {
                Some(n) => n.to_string(),
                None => {
                    return Response::error(
                        "InitialResponse missing both initial_nonce and nonce".to_string(),
                        502,
                    )
                }
            };
            let handshake_round_trip_ms = js_sys::Date::now() - t_handshake_start;

            // Application-layer round-trip.
            // Use a unique message_box name per request so concurrent runs
            // don't collide on ack routing. Canonical convention per
            // `~/bsv/bsv-messagebox-cloudflare-public/src/message_hub.rs:996`:
            // server constructs `roomId = "{identity_key}-{messageBox}"`.
            // For joinRoom we pass the full roomId string; for sendMessage
            // we pass JUST the messageBox suffix and the server reconstructs
            // the roomId. The sendMessageAck-<roomId> event uses the
            // server-constructed roomId, which is byte-identical to the
            // joinRoom roomId we constructed locally.
            let now_ms = js_sys::Date::now() as u64;
            let message_box = format!("h34-{now_ms}");
            let room_id = format!("{client_pub_hex}-{message_box}");
            let message_id = format!("h34-test-{now_ms}");
            let body_text = format!("envelope-roundtrip-{room_id}");

            // (1) joinRoom — signed General with envelope {eventName:
            // "joinRoom", data: roomId}.
            let t_join_start = js_sys::Date::now();
            let join_data = serde_json::json!(room_id);
            let joined = match emit_signed_general(
                &transport,
                &wallet,
                &server_identity,
                &server_nonce_b64,
                "joinRoom",
                &join_data,
            )
            .await
            {
                Ok(g) => g,
                Err(e) => return Response::error(format!("emit joinRoom: {e:?}"), 502),
            };
            let join_round_trip_ms = js_sys::Date::now() - t_join_start;

            // (2) sendMessage — signed General with envelope:
            //   {eventName: "sendMessage", data: {roomId, message: {messageId, body}}}
            let t_send_start_msg = js_sys::Date::now();
            // Canonical Socket.IO sendMessage envelope shape per
            // `~/bsv/bsv-messagebox-cloudflare-public/src/message_hub.rs:952-998`:
            // `data` is `{messageBox, message: {messageId, recipient, body},
            // payment?}`. Server constructs `roomId = "{identity}-{messageBox}"`
            // and emits `sendMessageAck-<roomId>` on success or `messageFailed`
            // on validation error. For the self-roundtrip we use our own
            // pubkey as the recipient.
            let send_data = serde_json::json!({
                "messageBox": message_box,
                "message": {
                    "messageId": message_id,
                    "recipient": client_pub_hex,
                    "body": body_text,
                }
            });
            let sent = match emit_signed_general(
                &transport,
                &wallet,
                &server_identity,
                &server_nonce_b64,
                "sendMessage",
                &send_data,
            )
            .await
            {
                Ok(g) => g,
                Err(e) => return Response::error(format!("emit sendMessage: {e:?}"), 502),
            };

            // (3) Drain inbound events until we see sendMessageAck for
            // OUR roomId. Other events (e.g. server's deferred
            // `authenticated` follow-up per
            // `~/bsv/bsv-messagebox-cloudflare-public/src/engineio/auth.rs:49-66`)
            // are recorded but don't break the loop.
            let expected_ack = format!("sendMessageAck-{room_id}");
            let mut intermediate_events: Vec<String> = Vec::new();
            let ack_event = loop {
                let ev = match app_event_rx.next().await {
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
            let ack_round_trip_ms = js_sys::Date::now() - t_send_start_msg;
            let elapsed_ms = js_sys::Date::now() - t_start;

            Response::from_json(&serde_json::json!({
                "socketio_status": "envelope_roundtripped",
                "relay": relay,
                "engineio_sid": handshake.sid,
                "client_identity": client_pub_hex,
                "server_identity": server_identity_hex,
                "room_id": room_id,
                "sent_message_id": message_id,
                "sent_body": body_text,
                "ack_event_name": ack_event.event_name,
                "ack_data": ack_event.data,
                "intermediate_events": intermediate_events,
                "join_round_trip_ms": join_round_trip_ms,
                "ack_round_trip_ms": ack_round_trip_ms,
                "handshake_round_trip_ms": handshake_round_trip_ms,
                "elapsed_ms": elapsed_ms,
                // For tests that diff the wire bytes against canonical
                // TS — these are the EXACT bytes we sent on the wire.
                "joined_payload_bytes_len": joined.payload_bytes.len(),
                "sent_payload_bytes_len": sent.payload_bytes.len(),
                "gate": "H-3.4",
            }))
        })
        // H-3.5a gate: DO scaffolding. Forwards `/relay-via-do/identity`
        // to the EngineIoSessionDo bound as `ENGINEIO_SESSION_DO` in
        // wrangler.toml. The DO is keyed by `id_from_name("cosigner-test-1")`
        // (per-identity topology lock — audit §11.1; future Phase I
        // injects real cosigner IDs from the DKG ceremony output). Two
        // consecutive curls MUST return the same `client_identity` hex
        // because the DO loads its priv from the stable
        // `SERVER_PRIVATE_KEY` secret every fetch.
        //
        // Empirical harness: `wrangler deploy` + curl against the deployed
        // worker URL. NO local `wrangler dev` simulation — per the locked
        // H-3.5 discipline, the truth is the deployed CF runtime.
        .get_async("/relay-via-do/identity", |req, ctx| async move {
            let namespace = match ctx.env.durable_object("ENGINEIO_SESSION_DO") {
                Ok(ns) => ns,
                Err(e) => {
                    return Response::error(
                        format!("missing ENGINEIO_SESSION_DO binding: {e:?}"),
                        500,
                    )
                }
            };
            let id = match namespace.id_from_name("cosigner-test-1") {
                Ok(id) => id,
                Err(e) => return Response::error(format!("id_from_name failed: {e:?}"), 500),
            };
            let stub = match id.get_stub() {
                Ok(s) => s,
                Err(e) => return Response::error(format!("get_stub failed: {e:?}"), 500),
            };
            stub.fetch_with_request(req).await
        })
        .run(req, env)
        .await
}
