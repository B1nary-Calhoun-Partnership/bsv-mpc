//! **#98 hermetic repro — an early-arriving return share must NOT be lost.**
//!
//! Drives a real 2-of-2 presign through TWO production [`PresignHandler`]s wired by
//! an in-memory bus, with NO live relay. The bus models the deployed transport's
//! load-bearing property faithfully: **each message is delivered exactly once and
//! is never re-delivered** — because the live [`bsv_mpc_service::MessageBoxListener`]
//! `run_loop` ACKs every inbound the instant the handler returns, regardless of
//! outcome, so the relay GCs it. A handler path that "drops" a message (returns
//! `Ok` without consuming it, trusting a future re-delivery) therefore loses it
//! for good.
//!
//! ## The bug this guards
//!
//! A cosigner ships its BRC-2 return ciphertext (`RETURN_SHARE_ROUND`) the instant
//! IT finishes round 3. Under reordered/parallel delivery (the device's n-party
//! presign-over-relay) that ciphertext can reach the coordinator BEFORE the
//! coordinator's own round 3 completes and opens its collection slot. The old
//! `collect_return_share` returned `Ok(())` there — intending the relay to "leave
//! it un-acked for redelivery" — but the listener had already acked it, so it was
//! gone: the coordinator never collected it, the `PresigBundle` never assembled,
//! and the device timed out 600s "awaiting PresigBundle assembly". The fix BUFFERS
//! the early return share and replays it when the collection slot opens.
//!
//! This repro deterministically forces that ordering (return share delivered to the
//! coordinator before its completing round-3 message) and asserts the bundle still
//! assembles. WITHOUT the buffer+replay fix it deadlocks (no bundle) — a true RED.
//!
//! Hermetic + fast (a 2-of-2 DKG via the `round_based` sim with Blum test primes,
//! then an in-process presign); runs as a normal `cargo test` gate.

use std::collections::VecDeque;
use std::time::Duration;

use bsv::primitives::ec::{PrivateKey, PublicKey};
use bsv_mpc_core::types::{EncryptedShare, PolicyId, SessionId, ShareIndex, ThresholdConfig};
use bsv_mpc_messagebox::{DecodedRoundMessage, InboundVia};
use bsv_mpc_service::{
    InMemoryBundleStore, OutgoingRoundMessage, PresignHandler, PresignHandlerConfig, PresignOutcome,
};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use rand::RngCore;

// ── round_based sim plumbing (mirrors presigning.rs / poc tests) ───────────────
#[pin_project::pin_project]
struct BufferedSink<M, Inner> {
    #[pin]
    messages: VecDeque<M>,
    #[pin]
    inner: Inner,
}
type BufferedDelivery<M, D> = (
    <D as round_based::Delivery<M>>::Receive,
    BufferedSink<round_based::Outgoing<M>, <D as round_based::Delivery<M>>::Send>,
);
impl<M: Unpin, Inner: futures::Sink<M>> futures::Sink<M> for BufferedSink<M, Inner> {
    type Error = Inner::Error;
    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn start_send(self: std::pin::Pin<&mut Self>, item: M) -> std::result::Result<(), Self::Error> {
        self.project().messages.get_mut().push_back(item);
        Ok(())
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        while !self.messages.is_empty() {
            let mut p = self.as_mut().project();
            let mut inner = p.inner;
            std::task::ready!(inner.as_mut().poll_ready(cx))?;
            if let Some(item) = p.messages.pop_front() {
                inner.as_mut().start_send(item)?;
            }
        }
        self.project().inner.poll_flush(cx)
    }
    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        self.project().inner.poll_close(cx)
    }
}
fn buffer_outgoing<M, D, R>(
    party: round_based::MpcParty<M, D, R>,
) -> round_based::MpcParty<M, BufferedDelivery<M, D>, R>
where
    M: Unpin,
    D: round_based::Delivery<M>,
    R: round_based::runtime::AsyncRuntime,
{
    party.map_delivery(|d| {
        let (i, o) = d.split();
        (
            i,
            BufferedSink {
                messages: VecDeque::new(),
                inner: o,
            },
        )
    })
}

fn generate_blum_prime(rng: &mut impl rand::RngCore, bits_size: u32) -> cggmp24::backend::Integer {
    use cggmp24::backend::Integer;
    loop {
        let n = Integer::generate_prime(rng, bits_size);
        if n.mod_u(4) == 3 {
            break n;
        }
    }
}
fn gen_test_primes(rng: &mut impl rand::RngCore) -> cggmp24::PregeneratedPrimes<SecurityLevel128> {
    use cggmp24::security_level::SecurityLevel;
    let b = SecurityLevel128::RSA_PRIME_BITLEN;
    cggmp24::PregeneratedPrimes::try_from([
        generate_blum_prime(rng, b),
        generate_blum_prime(rng, b),
        generate_blum_prime(rng, b),
        generate_blum_prime(rng, b),
    ])
    .expect("primes have wrong bit size")
}

/// 2-of-2 DKG (keygen + auxinfo) via the sim → 2 complete key shares.
async fn run_dkg_2of2() -> Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> {
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    let (n, t) = (2u16, 2u16);
    let eid_bytes: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid_bytes);
    let incomplete = round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut r = rand::rngs::OsRng;
        async move {
            cggmp24::keygen::<Secp256k1>(eid, i, n)
                .set_threshold(t)
                .start(&mut r, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    let eid_bytes_aux: [u8; 32] = rng.gen();
    let eid_aux = ExecutionId::new(&eid_bytes_aux);
    let primes: Vec<_> = (0..n).map(|_| gen_test_primes(&mut rng)).collect();
    let aux = round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut r = rand::rngs::OsRng;
        let pregenerated = primes[usize::from(i)].clone();
        async move {
            cggmp24::aux_info_gen(eid_aux, i, n, pregenerated)
                .start(&mut r, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    incomplete
        .into_iter()
        .zip(aux)
        .map(|(s, a)| cggmp24::KeyShare::from_parts((s, a)).expect("key share validation"))
        .collect()
}

fn fresh_priv() -> PrivateKey {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0] |= 0x01;
    PrivateKey::from_bytes(&b).unwrap()
}

fn to_encrypted(
    ks: &cggmp24::KeyShare<Secp256k1, SecurityLevel128>,
    index: u16,
    config: ThresholdConfig,
    session: SessionId,
) -> EncryptedShare {
    EncryptedShare {
        nonce: vec![0u8; 12],
        ciphertext: serde_json::to_vec(ks).expect("key share serializes"),
        session_id: session,
        share_index: ShareIndex(index),
        config,
        joint_pubkey_compressed: ks.core.shared_public_key.to_bytes(true).to_vec(),
    }
}

/// A message in flight on the in-memory bus: who emitted it, where it goes, and
/// the wrapped wire content.
struct InFlight {
    sender_party: u16,
    recipient_party: u16,
    out: OutgoingRoundMessage,
}

/// Is this a §06.17.2 return-channel ciphertext (the `presig_return_*` mailbox)?
fn is_return_share(o: &OutgoingRoundMessage) -> bool {
    o.message_box.starts_with("presig_return_")
}

/// **The repro.** 2-of-2 presign through the real `PresignHandler`s over an
/// in-memory, deliver-exactly-once bus. The delivery policy ALWAYS ships a pending
/// return share to the coordinator before any protocol message — so the
/// cosigner's return ciphertext reaches the coordinator BEFORE the coordinator's
/// own completing round-3 message, exactly the deployed reordering. The bundle
/// MUST still assemble (it only does because the coordinator now BUFFERS the early
/// return share and replays it when its round-3 opens the collection slot).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn early_return_share_is_buffered_not_lost() {
    let key_shares = run_dkg_2of2().await;
    let config = ThresholdConfig::new(2, 2).unwrap();
    let session = SessionId::from_str_hash("early-return-share-repro");
    let participants = vec![0u16, 1u16];

    // Party 0 = coordinator (assembles the bundle); party 1 = cosigner.
    let priv0 = fresh_priv();
    let priv1 = fresh_priv();
    let pub0: PublicKey = priv0.public_key();
    let pub1: PublicKey = priv1.public_key();
    let hex0 = pub0.to_hex();
    let hex1 = pub1.to_hex();
    let party_of_hex = |h: &str| -> u16 {
        if h == hex0 {
            0
        } else if h == hex1 {
            1
        } else {
            panic!("unknown recipient hex {h}")
        }
    };
    let pub_of = |p: u16| -> PublicKey {
        if p == 0 {
            pub0.clone()
        } else {
            pub1.clone()
        }
    };

    let store0 = std::sync::Arc::new(InMemoryBundleStore::new());
    let h0 = PresignHandler::new(PresignHandlerConfig {
        my_party_index: 0,
        coordinator_party: 0,
        parties_at_keygen: participants.clone(),
        policy_id: PolicyId([0x11; 32]),
        identity_priv: priv0.clone(),
        at_rest_root: [0x42; 32],
        bundle_store: store0.clone(),
    });
    let h1 = PresignHandler::new(PresignHandlerConfig {
        my_party_index: 1,
        coordinator_party: 0,
        parties_at_keygen: participants.clone(),
        policy_id: PolicyId([0x11; 32]),
        identity_priv: priv1.clone(),
        at_rest_root: [0x42; 32],
        bundle_store: std::sync::Arc::new(InMemoryBundleStore::new()),
    });

    let share0 = to_encrypted(&key_shares[0], 0, config, session);
    let share1 = to_encrypted(&key_shares[1], 1, config, session);

    // Initiate both (registers the SM slot + round-1 outbound).
    let (rx0, out0) = h0
        .initiate(session, share0, vec![(1, hex1.clone())])
        .await
        .expect("coordinator initiate");
    let (rx1, out1) = h1
        .initiate(session, share1, vec![(0, hex0.clone())])
        .await
        .expect("cosigner initiate");

    let dispatch0 = h0.handler_fn();
    let dispatch1 = h1.handler_fn();

    // Seed the bus with both parties' round-1 outbound.
    let mut bus: VecDeque<InFlight> = VecDeque::new();
    let seed = |sender: u16, outs: Vec<OutgoingRoundMessage>, bus: &mut VecDeque<InFlight>| {
        for o in outs {
            let recipient = party_of_hex(&o.recipient_pub_hex);
            bus.push_back(InFlight {
                sender_party: sender,
                recipient_party: recipient,
                out: o,
            });
        }
    };
    seed(0, out0, &mut bus);
    seed(1, out1, &mut bus);

    let mut msg_ctr: u64 = 0;
    let mut steps = 0u32;
    let mut coord_bundle: Option<PresignOutcome> = None;
    let mut rx0 = rx0;
    let mut rx1 = rx1;

    while coord_bundle.is_none() {
        steps += 1;
        assert!(
            steps < 2_000,
            "step budget exceeded — DEADLOCK (no bundle assembled)"
        );

        // Did the coordinator already assemble (a replay during a prior dispatch
        // may have fired it)?
        if let Ok(outcome) = rx0.try_recv() {
            coord_bundle = Some(outcome);
            break;
        }

        assert!(
            !bus.is_empty(),
            "DEADLOCK: bus empty but no bundle — an in-flight message was lost \
             (the early-return-share drop bug)"
        );

        // DELIVERY POLICY (forces the deployed reordering deterministically):
        //   1. Deliver any pending return share FIRST — so the cosigner's return
        //      ciphertext reaches the coordinator BEFORE the coordinator's own
        //      completing round-3 message.
        //   2. Else prefer NON-coordinator-bound messages — so the cosigner races
        //      ahead and COMPLETES round 3 (emitting its return share) while the
        //      coordinator still has its completing round-3 inbound pending.
        //   3. Else FIFO (the only-coordinator-bound case keeps the coordinator
        //      advancing, just one round behind).
        // Net effect: return-share → coordinator (slot still absent → must buffer)
        // → THEN the coordinator's round-3 (opens slot → replays the buffer).
        let idx = bus
            .iter()
            .position(|m| is_return_share(&m.out))
            .or_else(|| bus.iter().position(|m| m.recipient_party != 0))
            .unwrap_or(0);
        let InFlight {
            sender_party,
            recipient_party,
            out,
        } = bus.remove(idx).unwrap();

        msg_ctr += 1;
        let dm = DecodedRoundMessage {
            message_id: format!("m{msg_ctr}"),
            message_box: out.message_box.clone(),
            sender_pub: pub_of(sender_party),
            round_msg: out.round_msg.clone(),
            via: InboundVia::WsPush,
        };

        let produced = if recipient_party == 0 {
            dispatch0(dm).await.expect("coordinator dispatch")
        } else {
            dispatch1(dm).await.expect("cosigner dispatch")
        };
        seed(recipient_party, produced, &mut bus);
    }

    // The coordinator assembled + persisted the bundle.
    match coord_bundle.expect("coordinator must yield an outcome") {
        PresignOutcome::BundlePersisted(b) => {
            assert_eq!(b.parties_at_keygen, participants);
            assert_eq!(b.joint_pubkey.len(), 33);
            // Positional cosigner_encrypted_shares: slot 1 (the cosigner) is filled.
            assert_eq!(b.cosigner_encrypted_shares.len(), 2);
            assert!(
                !b.cosigner_encrypted_shares[1].is_empty(),
                "cosigner's return ciphertext MUST be collected at positional index 1"
            );
            assert!(
                !b.presig_bytes.is_empty(),
                "coordinator's own sealed presig share must be present"
            );
            assert_eq!(
                store0.len(),
                1,
                "the assembled bundle must be persisted to the coordinator's store"
            );
        }
        PresignOutcome::ReturnShipped => {
            panic!("coordinator unexpectedly produced a cosigner outcome")
        }
    }

    // The cosigner shipped its return ciphertext (fired during the run).
    match tokio::time::timeout(Duration::from_secs(1), &mut rx1).await {
        Ok(Ok(PresignOutcome::ReturnShipped)) => {}
        other => panic!("cosigner must have shipped its return share, got {other:?}"),
    }
}
