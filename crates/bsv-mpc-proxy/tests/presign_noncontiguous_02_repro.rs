//! **HERMETIC reproduction of the deterministic `{0,2}` presign-over-relay
//! timeout.** No network, no relay, no mainnet — runs in well under a second.
//!
//! It wires TWO real `PresignHandler`s (the exact production type) with an
//! IN-PROCESS router that mirrors precisely what the MessageBox relay does on
//! the wire: each handler's `wrap_protocol` emits `OutgoingRoundMessage`s
//! carrying ABSOLUTE keygen indices in `round_msg.{from,to}`; the router turns
//! each into the `DecodedRoundMessage` the relay would deliver and feeds it to
//! the recipient handler's `handler_fn` (which calls `dispatch_one` →
//! absolute→position translation → `drive_protocol` → `process_generate_round`
//! → `wrap_protocol`). So this exercises EXACTLY the wrap/dispatch/route layer
//! the bug lives in, for the non-contiguous subset `{0,2}` with the coordinator
//! at SM-position 1 (party 2) and the cosigner at SM-position 0 (party 0).
//!
//! Topology = the failing mainnet topology:
//!   parties_at_keygen = [0, 2], coordinator_party = 2, cosigner_party = 0.
//!
//! The control case `{0,1}` (coordinator = party 1) is asserted to PASS in the
//! same harness, isolating the defect to the non-contiguous translation.
//!
//! Run:
//! ```bash
//! cargo test -p bsv-mpc-proxy --test presign_noncontiguous_02_repro -- --nocapture
//! ```

use std::collections::VecDeque;
use std::sync::Arc;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::types::{
    EncryptedShare, PolicyId, SessionId, ShareIndex, ThresholdConfig,
};
use bsv_mpc_messagebox::{DecodedRoundMessage, InboundVia};
use bsv_mpc_service::{
    InMemoryBundleStore, OutgoingRoundMessage, PresignHandler, PresignHandlerConfig,
    PresignOutcome,
};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use rand::RngCore;

// ─── round_based simulator buffered-sink helpers (mirror of the core tests) ───
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
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn start_send(
        self: std::pin::Pin<&mut Self>,
        item: M,
    ) -> std::result::Result<(), Self::Error> {
        self.project().messages.get_mut().push_back(item);
        Ok(())
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        while !self.messages.is_empty() {
            let mut projection = self.as_mut().project();
            let mut inner = projection.inner;
            std::task::ready!(inner.as_mut().poll_ready(cx))?;
            if let Some(item) = projection.messages.pop_front() {
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
    party.map_delivery(|delivery| {
        let (incoming, outgoing) = delivery.split();
        let buffered_outgoing = BufferedSink {
            messages: VecDeque::new(),
            inner: outgoing,
        };
        (incoming, buffered_outgoing)
    })
}
fn generate_blum_prime(rng: &mut impl rand::RngCore, bits: u32) -> cggmp24::backend::Integer {
    use cggmp24::backend::Integer;
    loop {
        let n = Integer::generate_prime(rng, bits);
        if n.mod_u(4) == 3 {
            break n;
        }
    }
}
fn pregenerated_primes(
    rng: &mut impl rand::RngCore,
) -> cggmp24::PregeneratedPrimes<SecurityLevel128> {
    use cggmp24::security_level::SecurityLevel;
    let bits = SecurityLevel128::RSA_PRIME_BITLEN;
    let primes = [
        generate_blum_prime(rng, bits),
        generate_blum_prime(rng, bits),
        generate_blum_prime(rng, bits),
        generate_blum_prime(rng, bits),
    ];
    cggmp24::PregeneratedPrimes::try_from(primes).expect("primes")
}

/// `t`-of-`n` DKG via the sim → `n` complete signing-ready key shares.
async fn run_dkg(n: u16, t: u16) -> Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> {
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid_bytes);
    let incomplete = round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut prng = rand::rngs::OsRng;
        async move {
            cggmp24::keygen::<Secp256k1>(eid, i, n)
                .set_threshold(t)
                .start(&mut prng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();
    let eid_aux_bytes: [u8; 32] = rng.gen();
    let eid_aux = ExecutionId::new(&eid_aux_bytes);
    let primes: Vec<_> = (0..n).map(|_| pregenerated_primes(&mut rng)).collect();
    let aux = round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut prng = rand::rngs::OsRng;
        let pregenerated = primes[usize::from(i)].clone();
        async move {
            cggmp24::aux_info_gen(eid_aux, i, n, pregenerated)
                .start(&mut prng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();
    incomplete
        .into_iter()
        .zip(aux)
        .map(|(s, a)| cggmp24::KeyShare::from_parts((s, a)).expect("key share valid"))
        .collect()
}

fn wrap_key_share(
    key_share: &cggmp24::KeyShare<Secp256k1, SecurityLevel128>,
    index: u16,
    config: ThresholdConfig,
    session_id: SessionId,
) -> EncryptedShare {
    EncryptedShare {
        nonce: vec![0u8; 12],
        ciphertext: serde_json::to_vec(key_share).expect("serialize key share"),
        session_id,
        share_index: ShareIndex(index),
        config,
        joint_pubkey_compressed: key_share.core.shared_public_key.to_bytes(true).to_vec(),
    }
}

fn fresh_priv() -> PrivateKey {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0] |= 0x01;
    PrivateKey::from_bytes(&b).expect("fresh priv")
}

/// `to_party == 0xFFFF` is the §05.4.6 broadcast sentinel (see
/// `bsv_mpc_core::envelope::TO_PARTY_BROADCAST`).
const TO_PARTY_BROADCAST: u16 = 0xFFFF;

/// Convert an `OutgoingRoundMessage` into the `DecodedRoundMessage` the relay
/// would deliver — applying the EXACT canonical-envelope wire transform the
/// relay performs (`wrap_round_message` on send, `unwrap_envelope_to_round_message`
/// on receive). The crucial fidelity point the bug hinges on: on the wire,
/// `round_msg.to` is NOT carried by the RoundMessage — it is reconstructed on
/// decode from `env.to_party`, which the sender set from **`params.to_party`**,
/// NOT from `round_msg.to`. So `round_msg.from` survives but `round_msg.to` is
/// REPLACED by `params.to_party` (with `0xFFFF` → broadcast `None`).
fn deliver(out: &OutgoingRoundMessage, sender_pub_hex: &str, seq: &mut u64) -> DecodedRoundMessage {
    *seq += 1;
    let sender_pub = bsv::PublicKey::from_hex(sender_pub_hex).expect("sender pub hex");
    let mut round_msg = out.round_msg.clone();
    // Mirror unwrap_envelope_to_round_message: `to` comes from env.to_party
    // (= params.to_party at send), NOT from round_msg.to.
    round_msg.to = if out.params.to_party == TO_PARTY_BROADCAST {
        None
    } else {
        Some(ShareIndex(out.params.to_party))
    };
    DecodedRoundMessage {
        message_id: format!("m{seq}"),
        message_box: out.message_box.clone(),
        sender_pub,
        round_msg,
        via: InboundVia::WsPush,
    }
}

/// Drive a presign ceremony between an in-process coordinator + cosigner over an
/// in-process router that mirrors the relay wire. Returns the assembled bundle
/// (or panics with a stall trace if the SM produces 0 outbound / deadlocks).
#[allow(clippy::too_many_arguments)]
async fn drive_presign(
    parties_at_keygen: Vec<u16>,
    coordinator_party: u16,
    cosigner_party: u16,
    coord_share: EncryptedShare,
    cosigner_share: EncryptedShare,
    session_id: SessionId,
    label: &str,
) -> Option<bsv_mpc_core::types::PresigBundle> {
    let policy_id = PolicyId([0x09; 32]);
    let at_rest_root = [0x42u8; 32];

    let coord_identity = fresh_priv();
    let cosigner_identity = fresh_priv();
    let coord_pub_hex = coord_identity.public_key().to_hex();
    let cosigner_pub_hex = cosigner_identity.public_key().to_hex();

    let bundle_store = Arc::new(InMemoryBundleStore::new());

    let coord = PresignHandler::new(PresignHandlerConfig {
        my_party_index: coordinator_party,
        coordinator_party,
        parties_at_keygen: parties_at_keygen.clone(),
        policy_id,
        identity_priv: coord_identity.clone(),
        at_rest_root,
        bundle_store: bundle_store.clone(),
    });
    let cosigner = PresignHandler::new(PresignHandlerConfig {
        my_party_index: cosigner_party,
        coordinator_party,
        parties_at_keygen: parties_at_keygen.clone(),
        policy_id,
        identity_priv: cosigner_identity.clone(),
        at_rest_root: [0u8; 32],
        bundle_store: Arc::new(InMemoryBundleStore::new()),
    });

    let coord_fn = coord.handler_fn();
    let cosigner_fn = cosigner.handler_fn();

    // Initiate both (registers ceremony slots + produces round-1).
    let (mut coord_rx, coord_round1) = coord
        .initiate(
            session_id,
            coord_share,
            vec![(cosigner_party, cosigner_pub_hex.clone())],
        )
        .await
        .expect("coord initiate");
    let (_cosigner_rx, cosigner_round1) = cosigner
        .initiate(
            session_id,
            cosigner_share,
            vec![(coordinator_party, coord_pub_hex.clone())],
        )
        .await
        .expect("cosigner initiate");

    // Work queue of (recipient_is_coordinator, DecodedRoundMessage).
    let mut seq = 0u64;
    let mut queue: VecDeque<(bool, DecodedRoundMessage)> = VecDeque::new();

    // The coordinator's round-1 is addressed to the cosigner; vice versa.
    for out in &coord_round1 {
        eprintln!(
            "[{label}] COORD round-1 wire from={} to={:?} round={} -> cosigner",
            out.round_msg.from.0, out.round_msg.to.map(|t| t.0), out.round_msg.round
        );
        queue.push_back((false, deliver(out, &coord_pub_hex, &mut seq)));
    }
    for out in &cosigner_round1 {
        eprintln!(
            "[{label}] COSIGNER round-1 wire from={} to={:?} round={} -> coord",
            out.round_msg.from.0, out.round_msg.to.map(|t| t.0), out.round_msg.round
        );
        queue.push_back((true, deliver(out, &cosigner_pub_hex, &mut seq)));
    }

    let mut steps = 0;
    while let Some((to_coord, msg)) = queue.pop_front() {
        steps += 1;
        assert!(steps < 1000, "[{label}] router did not converge (deadlock)");

        // Check for completion first (non-blocking).
        if let Ok(outcome) = coord_rx.try_recv() {
            match outcome {
                PresignOutcome::BundlePersisted(b) => {
                    eprintln!("[{label}] ✔ coordinator persisted bundle");
                    return Some(*b);
                }
                PresignOutcome::ReturnShipped => panic!("[{label}] coord got cosigner outcome"),
            }
        }

        let (who, sender_pub_hex, produced) = if to_coord {
            let out = coord_fn(msg).await.expect("coord dispatch");
            ("COORD", coord_pub_hex.clone(), out)
        } else {
            let out = cosigner_fn(msg).await.expect("cosigner dispatch");
            ("COSIGNER", cosigner_pub_hex.clone(), out)
        };
        eprintln!("[{label}] {who} produced {} outbound", produced.len());

        for out in &produced {
            // Route by recipient identity: if it's the coordinator's pub, the
            // coordinator receives it; otherwise the cosigner does.
            let recipient_is_coord = out.recipient_pub_hex == coord_pub_hex;
            eprintln!(
                "[{label}]   {who} -> {} wire from={} to={:?} round={} box={}",
                if recipient_is_coord { "COORD" } else { "COSIGNER" },
                out.round_msg.from.0,
                out.round_msg.to.map(|t| t.0),
                out.round_msg.round,
                out.message_box,
            );
            queue.push_back((recipient_is_coord, deliver(out, &sender_pub_hex, &mut seq)));
        }
    }

    // Drain any final completion the last step produced.
    if let Ok(PresignOutcome::BundlePersisted(b)) = coord_rx.try_recv() {
        eprintln!("[{label}] ✔ coordinator persisted bundle (post-drain)");
        return Some(*b);
    }
    None
}

/// **CONTROL: `{0,1}` contiguous, coordinator = party 1.** Must pass.
#[tokio::test]
async fn presign_relay_contiguous_01_passes() {
    let _ = tracing_subscriber::fmt::try_init();
    let config = ThresholdConfig::new(2, 2).expect("2-of-2");
    let shares = run_dkg(2, 2).await;
    let session = SessionId::from_str_hash("repro-01-contiguous");
    let coord_share = wrap_key_share(&shares[1], 1, config, session);
    let cosigner_share = wrap_key_share(&shares[0], 0, config, session);

    let bundle = drive_presign(
        vec![0, 1],
        1, // coordinator = party 1
        0, // cosigner = party 0
        coord_share,
        cosigner_share,
        session,
        "01",
    )
    .await;
    assert!(bundle.is_some(), "CONTROL {{0,1}} presign MUST assemble a bundle");
}

/// **REPRO: `{0,2}` non-contiguous, coordinator = party 2 (SM-position 1).**
/// This is the failing mainnet topology. Before the fix it stalls (coordinator
/// produces 0 outbound) and the router fails to converge.
#[tokio::test]
async fn presign_relay_noncontiguous_02_repro() {
    let _ = tracing_subscriber::fmt::try_init();
    let config = ThresholdConfig::new(2, 3).expect("2-of-3");
    let shares = run_dkg(3, 2).await;
    let session = SessionId::from_str_hash("repro-02-noncontiguous");
    // parties_at_keygen = [0,2]: position 0 = party 0 (cosigner),
    //                            position 1 = party 2 (coordinator).
    let coord_share = wrap_key_share(&shares[2], 2, config, session);
    let cosigner_share = wrap_key_share(&shares[0], 0, config, session);

    let bundle = drive_presign(
        vec![0, 2],
        2, // coordinator = party 2 (SM-position 1)
        0, // cosigner = party 0 (SM-position 0)
        coord_share,
        cosigner_share,
        session,
        "02",
    )
    .await;
    assert!(
        bundle.is_some(),
        "REPRO {{0,2}} presign MUST assemble a bundle (coordinator at SM-position 1)"
    );
}
