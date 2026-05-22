//! **Within-stack 2-of-2 DKG e2e via MessageBox** — Phase D merge gate.
//!
//! Boots Alice + Bob as in-process bsv-mpc-service participants:
//! each owns a `MessageBoxClient` (live BRC-31 identity against the
//! deployed Calhoun relay), a `DkgHandler` (real `DkgCoordinator`
//! wired in), and a `MessageBoxListener` (Phase C dispatcher
//! primitive). Both call `DkgHandler::initiate`, ship their round-1
//! messages, and wait for ceremony completion. The merge gate is
//! **byte-identical `joint_pubkey` on both sides** + share persisted
//! to each side's `SqliteShareStorage`.
//!
//! ## Why this is the right test under the spec interpretation
//!
//! Per MPC-Spec §06.7 a "cosigner" is a participating party holding a
//! share, identified by its CHIP-published `transport.inbox_url`.
//! Two bsv-mpc cosigners doing 2-of-2 over MessageBox exercises every
//! load-bearing piece of the cross-cosigner wire:
//!
//! - Canonical CBOR envelope encode + strict decode (§05.9.1)
//! - BRC-78 ECIES + BRC-31 sender sig on every round message (§05.5/.6)
//! - Canonical ExecutionId per §02.4 (keygen carve-out: joint_pubkey
//!   all-zero before DKG completes)
//! - §06.4 WebSocket transport (typed RoundMessage subscription)
//! - §06.12 heartbeat + reconnect (latent — DKG completes in <1s of
//!   wire time so reconnect path isn't normally exercised here)
//! - `bsv-mpc-service::messagebox::MessageBoxListener` dispatch
//!   correctness (Phase C)
//! - Real cggmp24 4-round keygen + 3-round auxinfo (Phase D)
//!
//! ## Runtime
//!
//! Gated on `MESSAGEBOX_RELAY_URL` so CI doesn't depend on relay
//! uptime. Setup-dominant cost is Paillier safe-prime generation
//! (`PregeneratedPrimes::<SecurityLevel128>::generate`) — ~30-60s per
//! party in parallel, so total setup ~60s. DKG itself takes ~1-2s
//! once primes are seeded. Run with:
//!
//! ```bash
//! MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
//!   cargo test -p bsv-mpc-service \
//!     --test dkg_via_messagebox_e2e -- --nocapture --test-threads=1
//! ```
//!
//! Total wall-clock should land around 70-90s end-to-end.

use std::sync::Arc;
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::types::{SessionId, ThresholdConfig};
use bsv_mpc_messagebox::types::BOX_DKG;
use bsv_mpc_messagebox::MessageBoxClient;
use bsv_mpc_service::storage::SqliteShareStorage;
use bsv_mpc_service::{DkgHandler, MessageBoxListener};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::PregeneratedPrimes;
use rand::RngCore;
use tempfile::TempDir;

fn relay_url() -> Option<String> {
    std::env::var("MESSAGEBOX_RELAY_URL").ok()
}

fn fresh_priv() -> PrivateKey {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0] |= 0x01;
    PrivateKey::from_bytes(&b).expect("fresh priv must be valid")
}

fn fresh_storage() -> (Arc<std::sync::RwLock<SqliteShareStorage>>, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = SqliteShareStorage::open(dir.path().to_str().unwrap()).expect("open");
    (Arc::new(std::sync::RwLock::new(storage)), dir)
}

#[tokio::test]
async fn within_stack_2of2_dkg_byte_identical_joint_pubkey() {
    let Some(relay_url) = relay_url() else {
        eprintln!(
            "MESSAGEBOX_RELAY_URL not set — skipping Phase D DKG e2e. \
             To run: MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
             cargo test -p bsv-mpc-service --test dkg_via_messagebox_e2e \
             -- --nocapture --test-threads=1"
        );
        return;
    };
    let _ = tracing_subscriber::fmt::try_init();
    let t0 = std::time::Instant::now();

    // ----- Identities + storage -----
    let alice_client = MessageBoxClient::new(&relay_url, fresh_priv()).expect("alice client");
    let bob_client = MessageBoxClient::new(&relay_url, fresh_priv()).expect("bob client");
    let alice_pub = alice_client
        .identity_hex()
        .await
        .expect("alice identity_hex");
    let bob_pub = bob_client.identity_hex().await.expect("bob identity_hex");
    eprintln!("✔ alice = {alice_pub}");
    eprintln!("✔ bob   = {bob_pub}");

    let (alice_storage, _alice_dir) = fresh_storage();
    let (bob_storage, _bob_dir) = fresh_storage();

    // ----- Pre-generate Paillier primes (slow — the dominant cost) -----
    // Generating two sets in parallel cuts wall-clock roughly in half.
    eprintln!("(generating Paillier safe primes — this is the slow step, ~30-90s)");
    let primes_t0 = std::time::Instant::now();
    let (alice_primes, bob_primes) = tokio::task::spawn_blocking(|| {
        let alice = std::thread::spawn(|| {
            PregeneratedPrimes::<SecurityLevel128>::generate(&mut rand::rngs::OsRng)
        });
        let bob = std::thread::spawn(|| {
            PregeneratedPrimes::<SecurityLevel128>::generate(&mut rand::rngs::OsRng)
        });
        (
            alice.join().expect("alice prime thread panicked"),
            bob.join().expect("bob prime thread panicked"),
        )
    })
    .await
    .expect("prime gen task panicked");
    eprintln!("✔ generated primes in {:?}", primes_t0.elapsed());

    // ----- Build handlers + seed primes -----
    let config = ThresholdConfig::new(2, 2).expect("valid 2-of-2 config");
    let session_id = {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        SessionId(b)
    };
    eprintln!(
        "✔ ceremony session_id = {}",
        hex::encode(session_id.as_bytes())
    );

    let alice_handler = DkgHandler::new(config, 0, alice_storage.clone());
    let bob_handler = DkgHandler::new(config, 1, bob_storage.clone());
    alice_handler.seed_primes_for(session_id, alice_primes);
    bob_handler.seed_primes_for(session_id, bob_primes);

    // ----- Start listeners FIRST (so no inbound message is missed
    //       between initiate and subscription) -----
    let alice_listener =
        MessageBoxListener::start(alice_client.clone(), BOX_DKG, alice_handler.handler_fn())
            .await
            .expect("alice listener");
    let bob_listener =
        MessageBoxListener::start(bob_client.clone(), BOX_DKG, bob_handler.handler_fn())
            .await
            .expect("bob listener");
    eprintln!("✔ both listeners live");

    // ----- Both sides initiate (sequential — order doesn't matter,
    //       both run init() and produce their round-1 messages) -----
    let (alice_completion, alice_initial_outbound) = alice_handler
        .initiate(session_id, vec![(1, bob_pub.clone())])
        .await
        .expect("alice initiate");
    let (bob_completion, bob_initial_outbound) = bob_handler
        .initiate(session_id, vec![(0, alice_pub.clone())])
        .await
        .expect("bob initiate");
    assert!(!alice_initial_outbound.is_empty(), "alice round-1 outbound");
    assert!(!bob_initial_outbound.is_empty(), "bob round-1 outbound");
    eprintln!(
        "✔ initiated — alice has {} round-1 outbound msgs, bob has {}",
        alice_initial_outbound.len(),
        bob_initial_outbound.len()
    );

    // ----- Ship the round-1 messages over the wire -----
    let dkg_t0 = std::time::Instant::now();
    for out in alice_initial_outbound {
        alice_client
            .send_round_message(
                &out.recipient_pub_hex,
                &out.message_box,
                &out.round_msg,
                out.params,
            )
            .await
            .expect("alice round-1 send");
    }
    for out in bob_initial_outbound {
        bob_client
            .send_round_message(
                &out.recipient_pub_hex,
                &out.message_box,
                &out.round_msg,
                out.params,
            )
            .await
            .expect("bob round-1 send");
    }
    eprintln!("✔ round-1 shipped — listeners now drive the ceremony");

    // ----- Wait for both completions in parallel (DKG takes ~1-2s of
    //       wire time once primes are pre-seeded; budget 5min as a
    //       generous safety) -----
    let dkg_timeout = Duration::from_secs(300);
    let (alice_res, bob_res) = tokio::join!(
        tokio::time::timeout(dkg_timeout, alice_completion),
        tokio::time::timeout(dkg_timeout, bob_completion),
    );
    let alice_dkg = alice_res
        .expect("alice DKG MUST complete within timeout")
        .expect("alice completion channel MUST not be dropped");
    let bob_dkg = bob_res
        .expect("bob DKG MUST complete within timeout")
        .expect("bob completion channel MUST not be dropped");
    eprintln!("✔ both ceremonies complete in {:?}", dkg_t0.elapsed());

    // ----- THE MERGE GATE: byte-identical joint_pubkey on both sides -----
    assert_eq!(
        alice_dkg.joint_key.compressed, bob_dkg.joint_key.compressed,
        "joint_pubkey MUST be byte-identical on both cosigners — \
         this is the proof that DKG over MessageBox actually agreed."
    );
    assert_eq!(
        alice_dkg.joint_key.address, bob_dkg.joint_key.address,
        "BSV address derived from joint_pubkey MUST match on both sides"
    );
    eprintln!(
        "✔✔ JOINT KEY AGREED — joint_pubkey={} address={}",
        hex::encode(&alice_dkg.joint_key.compressed),
        alice_dkg.joint_key.address
    );

    // ----- Verify shares were persisted to each side's storage -----
    let session_hex = alice_dkg.session_id.hex();
    {
        let store = alice_storage.read().unwrap();
        let stored = store
            .get_share(&session_hex)
            .expect("storage get_share")
            .expect("alice share MUST be persisted");
        assert_eq!(stored.share_index.0, 0, "alice's stored share has index 0");
    }
    {
        let store = bob_storage.read().unwrap();
        let stored = store
            .get_share(&session_hex)
            .expect("storage get_share")
            .expect("bob share MUST be persisted");
        assert_eq!(stored.share_index.0, 1, "bob's stored share has index 1");
    }
    eprintln!("✔ shares persisted on both sides (session {session_hex})");

    // ----- Sanity: both handlers cleaned up the coordinator slot -----
    assert_eq!(alice_handler.live_session_count(), 0);
    assert_eq!(bob_handler.live_session_count(), 0);

    // ----- Cleanup -----
    tokio::time::timeout(Duration::from_secs(10), alice_listener.shutdown())
        .await
        .expect("alice listener shutdown");
    tokio::time::timeout(Duration::from_secs(10), bob_listener.shutdown())
        .await
        .expect("bob listener shutdown");
    eprintln!(
        "✔ done — total wall-clock {:?} (primes-dominated)",
        t0.elapsed()
    );
}
