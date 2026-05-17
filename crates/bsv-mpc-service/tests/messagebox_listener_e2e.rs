//! **Within-stack live-relay e2e** for the bsv-mpc-service
//! MessageBoxListener (Phase C). Proves the dispatcher primitive
//! end-to-end against the deployed Calhoun relay
//! (`rust-message-box.dev-a3e.workers.dev`):
//!
//! Bob runs a `MessageBoxListener` with a closure handler that echoes
//! every inbound `RoundMessage` back to its sender. Alice manually
//! sends a `RoundMessage` to Bob and subscribes to her own inbox.
//! Within a tight deadline, Alice receives Bob's echo as a
//! `DecodedRoundMessage` whose `.round_msg` matches what she sent,
//! byte-for-byte (session_id, round, from, to, payload). `via=WsPush`.
//! `.sender_pub` matches Bob.
//!
//! This is the merge gate for Phase C — any drift in the listener's
//! handler dispatch, the response wrap+send path, or the inbound
//! envelope decode fails here.
//!
//! Gated on `MESSAGEBOX_RELAY_URL` so accidental network calls in CI
//! don't depend on relay uptime.

use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::envelope::WrapParams;
use bsv_mpc_core::types::{RoundMessage, SessionId, ShareIndex};
use bsv_mpc_messagebox::types::BOX_DKG;
use bsv_mpc_messagebox::{DecodedRoundMessage, MessageBoxClient, RoundMessageSubscription};
use bsv_mpc_service::{HandlerFuture, MessageBoxListener, OutgoingRoundMessage};
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

/// Test box used for this scenario. Picked the `mpc-dkg` constant so
/// that the message_box plumbed through `DecodedRoundMessage.message_box`
/// is visibly the box we subscribed to.
const TEST_BOX: &str = BOX_DKG;

#[tokio::test]
async fn live_relay_listener_echoes_round_message_to_sender() {
    let Some(relay_url) = relay_url() else {
        eprintln!(
            "MESSAGEBOX_RELAY_URL not set — skipping listener e2e. \
             To run: MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
             cargo test -p bsv-mpc-service --test messagebox_listener_e2e -- --nocapture"
        );
        return;
    };
    let _ = tracing_subscriber::fmt::try_init();

    // ----- Identities -----
    let alice = MessageBoxClient::new(&relay_url, fresh_priv()).expect("alice client");
    let bob = MessageBoxClient::new(&relay_url, fresh_priv()).expect("bob client");
    let alice_pub = alice.identity_hex().await.expect("alice identity_hex");
    let bob_pub = bob.identity_hex().await.expect("bob identity_hex");
    eprintln!("✔ alice = {alice_pub}");
    eprintln!("✔ bob   = {bob_pub}");

    // ----- Alice subscribes (manual; she's the test driver, not a Listener) -----
    let mut alice_sub: RoundMessageSubscription = alice
        .subscribe_round_messages(TEST_BOX)
        .await
        .expect("alice subscribe MUST succeed");
    eprintln!("✔ alice subscribed (driver path)");

    // ----- Bob starts a Listener with an echo handler -----
    // The handler captures Bob's view of the conversation: each
    // inbound RoundMessage gets echoed back to its sender as a fresh
    // RoundMessage (round+1, party swap). This is intentionally
    // SYNTHETIC ceremony logic — Phase C is the dispatcher primitive,
    // not real cggmp24 (that's Phase D).
    let bob_listener = MessageBoxListener::start(
        bob.clone(),
        TEST_BOX,
        |inbound: DecodedRoundMessage| -> HandlerFuture {
            Box::pin(async move {
                let sender_pub_hex = inbound.sender_pub.to_hex();
                let echoed = RoundMessage {
                    session_id: inbound.round_msg.session_id,
                    round: inbound.round_msg.round + 1,
                    // Swap party roles for the response.
                    from: inbound.round_msg.to.unwrap_or(ShareIndex(0)),
                    to: Some(inbound.round_msg.from),
                    payload: inbound.round_msg.payload.clone(),
                };
                Ok(vec![OutgoingRoundMessage {
                    recipient_pub_hex: sender_pub_hex,
                    message_box: inbound.message_box.clone(),
                    round_msg: echoed,
                    params: WrapParams {
                        to_party: inbound.round_msg.from.0,
                        joint_pubkey: [0u8; 33],
                        phase: "dkg".into(),
                        execution_id_prefix: [0u8; 8],
                        correlation_id: Some("phase-c-echo".into()),
                        traceparent: None,
                    },
                }])
            })
        },
    )
    .await
    .expect("bob MessageBoxListener::start MUST succeed");
    eprintln!("✔ bob listener started (echo handler)");

    // ----- Alice fires the initial round-0 message -----
    let initial = RoundMessage {
        session_id: SessionId([0x9a; 32]),
        round: 0,
        from: ShareIndex(0),
        to: Some(ShareIndex(1)),
        payload: b"phase-c-dispatcher-primitive-byte-exact".to_vec(),
    };
    let initial_payload = initial.payload.clone();
    let initial_session = initial.session_id;
    let initial_round_outbound = initial.round;

    let send_msg_id = alice
        .send_round_message(
            &bob_pub,
            TEST_BOX,
            &initial,
            WrapParams {
                to_party: 1,
                joint_pubkey: [0u8; 33],
                phase: "dkg".into(),
                execution_id_prefix: [0u8; 8],
                correlation_id: Some("phase-c-alice-init".into()),
                traceparent: None,
            },
        )
        .await
        .expect("alice initial send MUST succeed");
    eprintln!("✔ alice sent round-0 RoundMessage to bob: message_id={send_msg_id}");

    // ----- Alice waits for Bob's echo on her own subscription -----
    let echo = wait_for_echo(
        &mut alice_sub,
        initial_session,
        initial_round_outbound + 1, // bob's handler emits round+1
        Duration::from_secs(10),
    )
    .await
    .expect("bob's echo MUST arrive within 10s");

    assert_eq!(echo.sender_pub.to_hex(), bob_pub, "sender MUST be bob");
    assert_eq!(echo.message_box, TEST_BOX);
    assert_eq!(
        echo.round_msg.session_id, initial_session,
        "session_id MUST round-trip through the listener"
    );
    assert_eq!(
        echo.round_msg.round,
        initial_round_outbound + 1,
        "bob's handler emitted round+1"
    );
    assert_eq!(
        echo.round_msg.from,
        ShareIndex(1),
        "echo `from` is bob's party (the original `to`)"
    );
    assert_eq!(
        echo.round_msg.to,
        Some(ShareIndex(0)),
        "echo `to` is alice's party (the original `from`)"
    );
    assert_eq!(
        echo.round_msg.payload, initial_payload,
        "echoed payload MUST match alice's initial send byte-exact"
    );
    eprintln!(
        "✔ alice received bob's echo ({} payload bytes byte-exact, via={:?})",
        echo.round_msg.payload.len(),
        echo.via,
    );

    // ----- Cleanup -----
    alice
        .acknowledge(std::slice::from_ref(&echo.message_id))
        .await
        .expect("ack MUST succeed");
    tokio::time::timeout(Duration::from_secs(5), bob_listener.shutdown())
        .await
        .expect("bob listener shutdown MUST complete within 5s");
    tokio::time::timeout(Duration::from_secs(5), alice_sub.shutdown())
        .await
        .expect("alice subscription shutdown MUST complete within 5s");
    eprintln!("✔ Phase C dispatcher primitive proven end-to-end");
}

async fn wait_for_echo(
    sub: &mut RoundMessageSubscription,
    want_session: SessionId,
    want_round: u8,
    timeout: Duration,
) -> Result<DecodedRoundMessage, String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "timed out after {timeout:?} waiting for echo (session={}, round={})",
                hex::encode(want_session.as_bytes()),
                want_round
            ));
        }
        let item = tokio::time::timeout(remaining, sub.next())
            .await
            .map_err(|_| format!("timeout waiting for echo round={want_round}"))?
            .ok_or_else(|| "subscription stream closed before echo arrived".to_string())?;
        let decoded = item.map_err(|e| format!("subscription error: {e}"))?;
        if decoded.round_msg.session_id == want_session && decoded.round_msg.round == want_round {
            return Ok(decoded);
        }
        eprintln!(
            "(skipping unrelated DecodedRoundMessage: session={} round={} via={:?})",
            hex::encode(decoded.round_msg.session_id.as_bytes()),
            decoded.round_msg.round,
            decoded.via,
        );
    }
}
