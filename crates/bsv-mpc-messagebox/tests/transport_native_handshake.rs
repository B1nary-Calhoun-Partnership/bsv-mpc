//! **H-4.3 native transport live-relay proof.**
//!
//! Drives the FULL Engine.IO 4 + Socket.IO 5 + BRC-103 handshake against
//! the live Calhoun relay through the NATIVE substrate
//! ([`bsv_mpc_messagebox::transport_native`] — `tokio-tungstenite` +
//! `reqwest`), mirroring the wasm32 path proven in
//! `poc/poc17-cf-outbound-ws` (`/brc103-handshake`).
//!
//! Sequence:
//!   1. Engine.IO polling handshake (`reqwest` GET) → `sid`.
//!   2. WS upgrade (`tokio_tungstenite::connect_async`) → `2probe`/
//!      `3probe`/`5` dance.
//!   3. Socket.IO CONNECT to the default namespace `/`.
//!   4. Wire `bsv::auth::Peer` over [`SocketIoTransport`]; spawn the
//!      native `run_dispatch` loop (`tokio::spawn` — the future is
//!      `Send`).
//!   5. Send a manual `InitialRequest` (Path 2 — avoids `Peer`'s private
//!      `initiate_handshake`).
//!   6. Snoop the server's `InitialResponse` off the dispatch loop and
//!      print `server_identity`.
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

use bsv::auth::transports::Transport;
use bsv::auth::types::{AuthMessage, MessageType};
use bsv::auth::{Peer, PeerOptions};
use bsv::primitives::ec::PrivateKey;
use bsv::primitives::to_base64;
use bsv::wallet::ProtoWallet;
use bsv_mpc_messagebox::engineio::codec::{EngineIoPacket, SocketIoPacket};
use bsv_mpc_messagebox::transport_native::{polling_handshake, WsHandle};
use bsv_mpc_messagebox::transport_socketio::{run_dispatch, SocketIoTransport};
use futures::channel::oneshot;
use rand::RngCore;

fn fresh_priv() -> PrivateKey {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0] |= 0x01;
    PrivateKey::from_bytes(&b).expect("fresh priv must be valid")
}

#[tokio::test]
#[ignore = "requires MESSAGEBOX_RELAY_URL + a live relay"]
async fn native_brc103_handshake_prints_server_identity() {
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

    // 3. Socket.IO 5 CONNECT to default namespace `/`.
    ws.send_socketio(&SocketIoPacket::Connect {
        nsp: "/".to_string(),
        data: None,
    })
    .expect("send Socket.IO CONNECT");
    loop {
        match ws.recv_engineio().await.expect("recv during CONNECT") {
            EngineIoPacket::Ping(payload) => {
                let _ = ws.send_engineio(&EngineIoPacket::Pong(payload));
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

    // 4. SocketIoTransport + Peer. `transport` is Clone (Arc-shared
    // callback + cloneable sender), so one clone goes to `Peer::new` and
    // we keep this one to send the manual InitialRequest.
    let sender = ws.sender();
    let transport = SocketIoTransport::new(sender.clone());
    let callback = transport.callback_handle();
    let (snoop_tx, snoop_rx) = oneshot::channel::<AuthMessage>();

    // Spawn the native dispatch loop. The future is `Send` because the
    // native `WsHandle`/`WsSender` + the `TransportCallback` Arc are all
    // `Send` (unlike the wasm32 path's `spawn_local`).
    tokio::spawn(run_dispatch(ws, sender, callback, Some(snoop_tx)));

    let client_priv = fresh_priv();
    let client_pub_hex = client_priv.public_key().to_hex();
    let wallet = ProtoWallet::new(Some(client_priv));
    let peer = Peer::new(PeerOptions {
        wallet,
        transport: transport.clone(),
        certificates_to_request: None,
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("h-4.3-native".to_string()),
    });
    peer.start();

    // 5. Manual InitialRequest (unsigned protocol bootstrap).
    let my_identity = peer.get_identity_key().await.expect("peer identity key");
    let mut nonce_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let mut initial_req = AuthMessage::new(MessageType::InitialRequest, my_identity);
    initial_req.initial_nonce = Some(to_base64(&nonce_bytes));
    transport
        .send(&initial_req)
        .await
        .expect("send InitialRequest");

    // 6. Await the server's InitialResponse via the dispatch snoop.
    let server_response = tokio::time::timeout(Duration::from_secs(20), snoop_rx)
        .await
        .expect("BRC-103 handshake timed out")
        .expect("snoop canceled before InitialResponse");
    let server_identity_hex = server_response.identity_key.to_hex();

    println!("client_identity    = {client_pub_hex}");
    println!("server_identity    = {server_identity_hex}");

    assert!(
        !server_identity_hex.is_empty(),
        "server identity must be non-empty"
    );
    assert_ne!(
        server_identity_hex, client_pub_hex,
        "server identity must differ from client identity"
    );
}
