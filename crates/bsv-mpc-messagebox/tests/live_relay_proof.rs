//! **Live-relay end-to-end proof** for the MessageBox transport AND the
//! canonical wire foundation from PR #1.
//!
//! Exercises the full stack against `https://rust-message-box.dev-a3e.workers.dev`
//! (Calhoun's deployed `bsv-messagebox-cloudflare` instance):
//!
//! 1. Build a canonical `MessageEnvelope` from `bsv-mpc-core` (PR #1).
//! 2. Wrap it as a MessageBox body via `wire::wrap_envelope_to_body`.
//! 3. `bsv-rs::Peer::start` + auto-handshake on first `to_peer`.
//! 4. `POST /sendMessage` to send the envelope to ourselves (BRC-104
//!    SimplifiedFetchTransport signing via `Peer`).
//! 5. `POST /listMessages` to read it back.
//! 6. `wire::unwrap_body_to_envelope` to decode_strict (§05.9.1).
//! 7. `assert_eq!` original == round-tripped (byte-for-byte).
//! 8. `POST /acknowledgeMessage` to clean up.
//!
//! Gated on `MESSAGEBOX_RELAY_URL` env var being set so accidental network
//! calls in CI don't depend on relay uptime. To run:
//!
//! ```bash
//! MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
//!   cargo test -p bsv-mpc-messagebox --test live_relay_proof -- --nocapture
//! ```
//!
//! This test is the practical proof of correctness for **both** the
//! canonical-wire module shipped in PR #1 (MessageEnvelope encode/decode,
//! BRC-78, BRC-31) and the MessageBox transport here in #2.

use std::sync::Arc;
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::envelope::{MessageEnvelope, ENVELOPE_VERSION_V1};
use bsv_mpc_core::types::SessionId;
use bsv_mpc_messagebox::auth::MessageBoxAuth;
use bsv_mpc_messagebox::http;
use bsv_mpc_messagebox::types::{MessagePayload, SendMessageRequest, BOX_SIGN};
use bsv_mpc_messagebox::wire;
use bsv_mpc_messagebox::{
    subscribe, InboundEnvelopeEvent, InboundVia, WsSubscription,
};
use rand::RngCore;

fn relay_url() -> Option<String> {
    std::env::var("MESSAGEBOX_RELAY_URL").ok()
}

fn fresh_priv() -> PrivateKey {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0] |= 0x01;
    PrivateKey::from_bytes(&b).expect("fresh priv must be valid")
}

fn sample_envelope() -> MessageEnvelope {
    MessageEnvelope {
        version: ENVELOPE_VERSION_V1,
        session_id: SessionId([0x7a; 32]),
        joint_pubkey: {
            let mut p = [0u8; 33];
            p[0] = 0x02;
            p[32] = 0x55;
            p
        },
        phase: "sign".into(),
        round: 1,
        from_party: 0,
        to_party: 1,
        inner: b"live-relay-proof-inner-payload".to_vec(),
        sender_sig_brc31: vec![0x30, 0x44, 0x02, 0x20, 0xab, 0xcd],
        execution_id_prefix: [0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22],
        correlation_id: Some("live-proof-corr".into()),
        traceparent: None,
    }
}

#[tokio::test]
async fn live_relay_round_trip_canonical_envelope() {
    let Some(relay_url) = relay_url() else {
        eprintln!(
            "MESSAGEBOX_RELAY_URL not set — skipping live-relay proof. \
             To run: MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
             cargo test -p bsv-mpc-messagebox --test live_relay_proof -- --nocapture"
        );
        return;
    };

    let _ = tracing_subscriber::fmt::try_init();

    // Fresh identity each run (avoids residue collisions across runs).
    let our_priv = fresh_priv();

    let auth = MessageBoxAuth::new(&relay_url, our_priv).expect("MessageBoxAuth::new must succeed");
    auth.start();
    let identity_hex = auth
        .identity_hex()
        .await
        .expect("identity_hex must succeed");
    eprintln!("✔ MessageBoxAuth ready: our identity = {identity_hex}");

    // Step 1: build canonical envelope from PR #1's bsv-mpc-core.
    let envelope = sample_envelope();
    let canonical_bytes = envelope.encode_canonical();
    eprintln!(
        "✔ encoded canonical envelope: {} bytes",
        canonical_bytes.len()
    );

    // Step 2: wrap as MessageBox body (lowercase hex string inside JSON).
    let body = wire::wrap_envelope_to_body(&envelope);

    // Step 3: POST /sendMessage to ourselves.
    let msg_id = format!(
        "live-proof-{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    let send_req = SendMessageRequest {
        message: MessagePayload {
            recipient: Some(identity_hex.clone()),
            recipients: None,
            message_box: BOX_SIGN.to_string(),
            message_id: Some(msg_id.clone()),
            body,
        },
        payment: None,
    };
    let send_resp = http::send_message(&auth, &send_req)
        .await
        .expect("POST /sendMessage MUST succeed against the live relay");
    assert_eq!(send_resp.status, "success");
    assert_eq!(send_resp.messages.len(), 1);
    assert_eq!(send_resp.messages[0].recipient, identity_hex);
    eprintln!(
        "✔ sent: message_id={} recipient={}",
        send_resp.messages[0].message_id, send_resp.messages[0].recipient
    );

    // Step 4: drain our own mailbox via /listMessages.
    let list_resp = http::list_messages(&auth, BOX_SIGN)
        .await
        .expect("POST /listMessages MUST succeed");
    assert_eq!(list_resp.status, "success");
    assert!(
        !list_resp.messages.is_empty(),
        "listMessages MUST return our just-sent message"
    );

    let received = list_resp
        .messages
        .iter()
        .find(|m| m.message_id == send_resp.messages[0].message_id)
        .expect("our just-sent message MUST appear in listMessages");
    eprintln!(
        "✔ received: message_id={} sender={}",
        received.message_id, received.sender
    );
    assert_eq!(received.sender, identity_hex, "sender field must echo us");

    // Step 5: unwrap the server-wrapped body back to a canonical envelope.
    // This exercises PR #1's `MessageEnvelope::decode_strict` end-to-end
    // (re-encode equivalence check per §05.9.1 runs inside) + peels the
    // server's `{"message": <body>}` wrap.
    let round_tripped =
        wire::unwrap_inbound_body(&received.body).expect("unwrap_inbound_body MUST succeed");

    // Step 6: assert byte-for-byte equality with what we sent.
    assert_eq!(round_tripped, envelope, "envelope must round-trip exactly");
    assert_eq!(
        round_tripped.encode_canonical(),
        canonical_bytes,
        "byte-equivalent re-encode (§05.9.1) preserved across the live MessageBox relay"
    );
    eprintln!(
        "✔ envelope round-trip is byte-exact ({} bytes)",
        canonical_bytes.len()
    );

    // Step 7: clean up.
    let ack_resp = http::acknowledge_messages(&auth, std::slice::from_ref(&received.message_id))
        .await
        .expect("POST /acknowledgeMessage MUST succeed");
    assert_eq!(ack_resp.status, "success");
    eprintln!("✔ acknowledged + deleted: {}", received.message_id);
}

/// Second live-relay scenario for the M1 sprint: WebSocket subscribe
/// (task #13) end-to-end against the deployed Calhoun relay. Covers:
///
/// 1. Alice subscribes to `mpc-sign` via WS.
/// 2. Bob (separate identity) sends a canonical envelope via HTTP
///    `/sendMessage`; Alice receives it **live** over the WS push
///    bridge within a tight deadline. `via == WsPush`. Byte-exact.
/// 3. Alice drops the WS (`shutdown().await`).
/// 4. Bob sends a second envelope while Alice is offline; the relay
///    persists it in D1 but has no live socket to push to.
/// 5. Alice re-subscribes. The pre-pump backfill drains the missed
///    envelope via HTTP `/listMessages`. `via == Backfill`. Byte-exact.
///
/// This is the merge gate for task #13: any drift in the WS handshake,
/// the BRC-31 upgrade-signing, the room-naming convention, the
/// inbound-event parser, or the body-shape normalization fails here.
#[tokio::test]
async fn live_relay_ws_subscribe_receives_push_then_backfill() {
    let Some(relay_url) = relay_url() else {
        eprintln!("MESSAGEBOX_RELAY_URL not set — skipping WS subscribe proof.");
        return;
    };
    let _ = tracing_subscriber::fmt::try_init();

    // ----- Identities (Alice subscribes, Bob sends) -----
    let alice = Arc::new(
        MessageBoxAuth::new(&relay_url, fresh_priv()).expect("MessageBoxAuth::new(alice)"),
    );
    alice.start();
    let alice_pub = alice.identity_hex().await.expect("alice identity_hex");

    let bob =
        MessageBoxAuth::new(&relay_url, fresh_priv()).expect("MessageBoxAuth::new(bob)");
    bob.start();
    let bob_pub = bob.identity_hex().await.expect("bob identity_hex");

    eprintln!("✔ alice = {alice_pub}");
    eprintln!("✔ bob   = {bob_pub}");

    // ----- Scenario 1: live WS push -----
    let mut sub: WsSubscription = subscribe(alice.clone(), vec![BOX_SIGN.to_string()])
        .await
        .expect("alice subscribe MUST succeed (backfill+connect+join inline)");
    eprintln!("✔ alice subscribed to {BOX_SIGN} via WS (handshake done inline)");

    let envelope1 = sample_envelope();
    let envelope1_bytes = envelope1.encode_canonical();
    let msg_id_1 = format!(
        "ws-proof-push-{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    let send1 = http::send_message(
        &bob,
        &SendMessageRequest {
            message: MessagePayload {
                recipient: Some(alice_pub.clone()),
                recipients: None,
                message_box: BOX_SIGN.to_string(),
                message_id: Some(msg_id_1.clone()),
                body: wire::wrap_envelope_to_body(&envelope1),
            },
            payment: None,
        },
    )
    .await
    .expect("bob → alice send #1 MUST succeed");
    assert_eq!(send1.status, "success");
    eprintln!("✔ bob sent #1 to alice: message_id={msg_id_1}");

    let event = wait_for(&mut sub, &msg_id_1, Duration::from_secs(10))
        .await
        .expect("WS push for #1 MUST arrive within 10s");
    assert_eq!(
        event.via,
        InboundVia::WsPush,
        "first envelope MUST arrive via live WS push (not backfill)"
    );
    assert_eq!(event.sender, bob_pub, "sender field MUST be bob");
    assert_eq!(event.message_box, BOX_SIGN);
    let round1 =
        wire::unwrap_inbound_body(&event.body).expect("unwrap_inbound_body #1 MUST succeed");
    assert_eq!(
        round1, envelope1,
        "WS-pushed envelope MUST round-trip byte-exact"
    );
    assert_eq!(
        round1.encode_canonical(),
        envelope1_bytes,
        "byte-equivalent re-encode (§05.9.1) preserved across the live WS push"
    );
    eprintln!(
        "✔ alice received #1 LIVE via WS push (via={:?}, {} bytes byte-exact)",
        event.via,
        envelope1_bytes.len()
    );

    // ACK the live one so it doesn't pollute the offline-then-reconnect
    // backfill scenario below.
    http::acknowledge_messages(&alice, std::slice::from_ref(&event.message_id))
        .await
        .expect("ack #1 MUST succeed");

    // ----- Scenario 2: offline → reconnect → backfill -----
    sub.shutdown().await;
    eprintln!("✔ alice WS shut down (offline)");

    let envelope2 = {
        let mut e = sample_envelope();
        e.session_id = SessionId([0x33; 32]);
        e.inner = b"backfill-envelope-payload".to_vec();
        e.correlation_id = Some("ws-proof-backfill".into());
        e
    };
    let envelope2_bytes = envelope2.encode_canonical();
    let msg_id_2 = format!(
        "ws-proof-backfill-{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    let send2 = http::send_message(
        &bob,
        &SendMessageRequest {
            message: MessagePayload {
                recipient: Some(alice_pub.clone()),
                recipients: None,
                message_box: BOX_SIGN.to_string(),
                message_id: Some(msg_id_2.clone()),
                body: wire::wrap_envelope_to_body(&envelope2),
            },
            payment: None,
        },
    )
    .await
    .expect("bob → alice send #2 (alice offline) MUST succeed at the relay");
    assert_eq!(send2.status, "success");
    eprintln!("✔ bob sent #2 while alice offline: message_id={msg_id_2}");

    let mut sub2: WsSubscription =
        subscribe(alice.clone(), vec![BOX_SIGN.to_string()])
            .await
            .expect("alice re-subscribe MUST succeed");
    eprintln!("✔ alice re-subscribed; backfill drained before pump started");

    let event2 = wait_for(&mut sub2, &msg_id_2, Duration::from_secs(10))
        .await
        .expect("backfill for #2 MUST arrive within 10s of re-subscribe");
    assert_eq!(
        event2.via,
        InboundVia::Backfill,
        "missed-while-offline envelope MUST arrive via backfill (not WsPush)"
    );
    assert_eq!(event2.sender, bob_pub);
    let round2 =
        wire::unwrap_inbound_body(&event2.body).expect("unwrap_inbound_body #2 MUST succeed");
    assert_eq!(
        round2, envelope2,
        "backfilled envelope MUST round-trip byte-exact"
    );
    assert_eq!(
        round2.encode_canonical(),
        envelope2_bytes,
        "byte-equivalent re-encode (§05.9.1) preserved across the backfill path"
    );
    eprintln!(
        "✔ alice received #2 via BACKFILL on reconnect (via={:?}, {} bytes byte-exact)",
        event2.via,
        envelope2_bytes.len()
    );

    // Clean up.
    http::acknowledge_messages(&alice, std::slice::from_ref(&event2.message_id))
        .await
        .expect("ack #2 MUST succeed");
    sub2.shutdown().await;
    eprintln!("✔ done — WS subscribe + backfill scenarios both byte-exact");
}

/// Pull events off the subscription until we see one with the target
/// `message_id`. Skips foreign messages (residue from a prior crashed
/// run, dedup spillover from the other test in this file, etc.).
/// Surfaces non-stream errors immediately.
async fn wait_for(
    sub: &mut WsSubscription,
    want_message_id: &str,
    timeout: Duration,
) -> Result<InboundEnvelopeEvent, String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "timed out after {timeout:?} waiting for message_id={want_message_id}"
            ));
        }
        let item = tokio::time::timeout(remaining, sub.inbound.recv())
            .await
            .map_err(|_| format!("timeout waiting for {want_message_id}"))?
            .ok_or_else(|| {
                format!("subscription stream closed before {want_message_id} arrived")
            })?;
        let event = item.map_err(|e| format!("subscription error: {e}"))?;
        if event.message_id == want_message_id {
            return Ok(event);
        }
        eprintln!(
            "(skipping unrelated event: message_id={} via={:?})",
            event.message_id, event.via
        );
    }
}
