//! **H-4.4 native transport live-relay proof.**
//!
//! Drives the FULL Engine.IO 4 + Socket.IO 5 + BRC-103 handshake against
//! the live Calhoun relay through the NATIVE substrate
//! ([`bsv_mpc_messagebox::transport_native`] — `tokio-tungstenite` +
//! `reqwest`) plugged into the UPSTREAM bsv-rs 0.3.10 `socketio`
//! transport. Uses the canonical `Peer`-driven flow (no manual
//! `InitialRequest`/snoop): `peer.to_peer(...)` auto-initiates the
//! BRC-103 handshake and signs the General internally.
//!
//! Sequence:
//!   1. Engine.IO polling handshake (`reqwest` GET) → `sid`.
//!   2. WS upgrade (`tokio_tungstenite::connect_async`) → `2probe`/
//!      `3probe`/`5` dance.
//!   3. Socket.IO CONNECT to the default namespace `/` (via the
//!      [`SocketIoSink`] + [`SocketIoFrameSource`] trait impls).
//!   4. Wire `bsv::auth::Peer` over `bsv::auth::SocketIoTransport<WsSender>`;
//!      spawn the upstream `run_dispatch` loop (`tokio::spawn` — the
//!      `WsHandle`/`WsSender`/callback are all `Send` on native).
//!   5. `peer.to_peer(joinRoom envelope, None, 20s)` — initiates the
//!      handshake AND sends the first signed General. `Ok(())` proves
//!      the entire native canonical path end-to-end.
//!   6. Best-effort: print the server identity learned from the first
//!      inbound General (`AppEvent.sender`), the canonical TS pattern.
//!
//! Gated on `MESSAGEBOX_RELAY_URL` + `#[ignore]` so CI doesn't depend on
//! relay uptime. Run with:
//!
//! ```bash
//! MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
//!   cargo test -p bsv-mpc-messagebox --test transport_native_handshake \
//!   -- --ignored --nocapture
//! ```

use std::time::Duration;

use bsv::auth::transports::socketio::build_envelope_payload;
use bsv::auth::transports::socketio::codec::{EngineIoPacket, SocketIoPacket};
use bsv::auth::SocketIoTransport;
use bsv::auth::{
    install_app_event_listener, run_dispatch, Peer, PeerOptions, SocketIoFrameSource, SocketIoSink,
};
use bsv::primitives::ec::PrivateKey;
use bsv::wallet::ProtoWallet;
use bsv_mpc_messagebox::transport_native::{polling_handshake, WsHandle};
use futures::StreamExt;
use rand::RngCore;
use serde_json::json;

fn fresh_priv() -> PrivateKey {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0] |= 0x01;
    PrivateKey::from_bytes(&b).expect("fresh priv must be valid")
}

#[tokio::test]
#[ignore = "requires MESSAGEBOX_RELAY_URL + a live relay"]
async fn native_brc103_handshake_via_canonical_to_peer() {
    let Ok(relay) = std::env::var("MESSAGEBOX_RELAY_URL") else {
        eprintln!("MESSAGEBOX_RELAY_URL not set — skipping native handshake proof");
        return;
    };

    // 1. Engine.IO 4 polling handshake.
    let handshake = polling_handshake(&relay).await.expect("polling handshake");
    println!("engineio sid       = {}", handshake.sid);
    println!("upgrades           = {:?}", handshake.upgrades);

    // 2. WS upgrade (2probe → 3probe → 5).
    let mut ws = WsHandle::open_and_upgrade(&relay, &handshake.sid)
        .await
        .expect("ws open + upgrade");
    println!("probe round-trip   = {:.1}ms", ws.probe_round_trip_ms());

    // 3. Socket.IO 5 CONNECT to default namespace `/`, via the trait
    // impls (sink = outbound, ws = inbound frame source).
    let sink = ws.sender();
    sink.send_socketio(&SocketIoPacket::Connect {
        nsp: "/".to_string(),
        data: None,
    })
    .expect("send Socket.IO CONNECT");
    loop {
        match ws.recv_engineio().await.expect("recv during CONNECT") {
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
    println!("socketio status    = connected");

    // 4. Upstream SocketIoTransport<WsSender> + Peer.
    let transport = SocketIoTransport::new(sink.clone());
    let callback = transport.callback_handle();
    let dispatch_sink = sink.clone();

    let client_priv = fresh_priv();
    let client_pub_hex = client_priv.public_key().to_hex();
    let wallet = ProtoWallet::new(Some(client_priv));
    let peer = Peer::new(PeerOptions {
        wallet,
        transport,
        certificates_to_request: None,
        session_manager: None,
        auto_persist_last_session: true,
        originator: Some("h-4.4-native".to_string()),
    });
    peer.start();

    // Inbound application events (server-emitted Generals). The sender of
    // the first such event is the server identity (canonical TS pattern).
    let (mut events, _cb_id) = install_app_event_listener(&peer).await;

    // Spawn the upstream dispatch loop — pumps inbound authMessage frames
    // into the Peer callback so `to_peer`'s handshake wait completes.
    tokio::spawn(run_dispatch(ws, dispatch_sink, callback));

    // 5. Canonical send: joinRoom. `to_peer(_, None, _)` auto-initiates
    // the BRC-103 handshake (InitialRequest → InitialResponse processed
    // by the dispatch loop) and signs+sends the General internally. Ok
    // here proves the entire native canonical path end-to-end.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let message_box = format!("h44-{now_ms}");
    let room_id = format!("{client_pub_hex}-{message_box}");

    tokio::time::timeout(
        Duration::from_secs(20),
        peer.to_peer(
            &build_envelope_payload("joinRoom", &json!(room_id)),
            None,
            Some(20_000),
        ),
    )
    .await
    .expect("to_peer(joinRoom) timed out — BRC-103 handshake did not complete")
    .expect("to_peer(joinRoom) failed");

    println!("client_identity    = {client_pub_hex}");
    println!("joinRoom sent       = {room_id} (handshake + signed General OK)");

    // 6. Best-effort: surface the server identity from the first inbound
    // General. Not all relays echo a General for joinRoom alone, so this
    // is informational — the deterministic gate is the to_peer Ok above.
    match tokio::time::timeout(Duration::from_secs(8), events.next()).await {
        Ok(Some(ev)) => {
            let server_identity_hex = ev.sender.to_hex();
            println!("server_identity    = {server_identity_hex}");
            println!("first event_name   = {}", ev.event_name);
            assert!(
                !server_identity_hex.is_empty(),
                "server identity must be non-empty"
            );
            assert_ne!(
                server_identity_hex, client_pub_hex,
                "server identity must differ from client identity"
            );
        }
        Ok(None) => println!("(inbound event channel closed before an event arrived)"),
        Err(_) => println!("(no inbound General within 8s — joinRoom may not echo; handshake still proven by to_peer Ok)"),
    }
}
