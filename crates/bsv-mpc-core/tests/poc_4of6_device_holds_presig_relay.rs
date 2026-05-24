//! **POC: god-tier §1 "device holds t−1 shares" — the PRESIGNED relay combine
//! path (issue #38 implement).**
//!
//! The keystone `poc_4of6_device_holds_3.rs` proved a 4-of-6 device-holds-3
//! subset signs+verifies via the FULL 4-round protocol. The deployed reality,
//! though, is the **1-round presigned relay path**: the device issues a partial
//! per co-located party from correlated presignatures, the external cosigner
//! issues its one partial over the relay, and the combiner sums all `t`.
//!
//! This test exercises the EXACT presigned combine the production relay uses —
//! [`SigningCoordinator::sign_with_presignature`] for the device's PRIMARY party
//! plus the new [`SigningCoordinator::add_local_presig_partial`] for its OTHER
//! co-located parties, then [`SigningCoordinator::process_round`] folding in the
//! external cosigner's partial — and proves:
//!
//!   1. A 4-of-6 DKG → 6 shares, one joint pubkey.
//!   2. A 4-party presign over the subset `{0,1,2,3}` → 4 correlated presigs
//!      sharing one `PresignaturePublicData`.
//!   3. The DEVICE holds `{0,1,2}` (3 = t−1). It primes the combiner with
//!      party 0's presig and ADDS parties 1 & 2's partials locally (never on the
//!      wire). The external cosigner (party 3) issues its partial from its own
//!      correlated presig. `process_round` combines all 4 → a signature that is
//!      low-s (BIP-62) and VERIFIES under the joint pubkey.
//!   4. The SAME path with a BRC-42 offset (§06.20) → a signature that verifies
//!      under `child_pub = joint + offset·G` and NOT under the base joint key.
//!   5. NEGATIVE: device-alone (parties {0,1,2}, 3 < t=4) cannot combine — only
//!      3 of the 4 commitment slots are filled, so `process_round` stays pending
//!      and never yields a signature.
//!
//! No new crypto: each device party's partial is one more deterministic
//! `issue_partial_signature` over a correlated presig; the combiner sums them in
//! commitment order exactly as the 2-party relay does.
//!
//! Run (≈3 min — 6-party DKG + auxinfo with Blum test primes):
//! ```bash
//! cargo test -p bsv-mpc-core --test poc_4of6_device_holds_presig_relay -- --ignored --nocapture
//! ```

use std::collections::VecDeque;

use bsv::primitives::ec::{PublicKey, Signature};
use bsv_mpc_core::signing::{
    issue_partial_signature_json, issue_partial_signature_json_with_offset, SigningCoordinator,
    SigningRoundResult,
};
use bsv_mpc_core::types::{
    EncryptedShare, SessionId, ShareIndex, SigningResult, ThresholdConfig,
};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use generic_ec::{Point, Scalar};

// ──────────────────────────────────────────────────────────────────────────
// Buffered sink for the round_based simulation (mirrors the keystone POC).
// ──────────────────────────────────────────────────────────────────────────
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

// ──────────────────────────────────────────────────────────────────────────
// Blum test-prime generation + full t-of-n DKG (mirrors the keystone POC).
// ──────────────────────────────────────────────────────────────────────────
fn generate_blum_prime(rng: &mut impl rand::RngCore, bits_size: u32) -> cggmp24::backend::Integer {
    use cggmp24::backend::Integer;
    loop {
        let n = Integer::generate_prime(rng, bits_size);
        if n.mod_u(4) == 3 {
            break n;
        }
    }
}
fn generate_test_primes(
    rng: &mut impl rand::RngCore,
) -> cggmp24::key_refresh::PregeneratedPrimes<SecurityLevel128> {
    use cggmp24::security_level::SecurityLevel;
    let bitsize = SecurityLevel128::RSA_PRIME_BITLEN;
    let primes = [
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
    ];
    cggmp24::key_refresh::PregeneratedPrimes::try_from(primes).expect("primes have wrong bit size")
}
fn dkg_key_shares(n: u16, t: u16) -> Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> {
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rand::Rng::gen(&mut rng);
    let eid = ExecutionId::new(&eid_bytes);
    let incomplete_shares = round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut party_rng = rand::rngs::OsRng;
        async move {
            cggmp24::keygen::<Secp256k1>(eid, i, n)
                .set_threshold(t)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    let eid_bytes: [u8; 32] = rand::Rng::gen(&mut rng);
    let eid_aux = ExecutionId::new(&eid_bytes);
    let primes: Vec<_> = (0..n).map(|_| generate_test_primes(&mut rng)).collect();
    let aux_infos = round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut party_rng = rand::rngs::OsRng;
        let pregenerated = primes[usize::from(i)].clone();
        async move {
            cggmp24::aux_info_gen(eid_aux, i, n, pregenerated)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    incomplete_shares
        .into_iter()
        .zip(aux_infos)
        .map(|(share, aux)| {
            cggmp24::KeyShare::<Secp256k1, SecurityLevel128>::from_parts((share, aux))
                .expect("key share validation should pass")
        })
        .collect()
}

/// The cggmp24 presign output tuple — structurally identical to the crate's
/// internal `presigning::PresignOutput` (same `TypeId`), so a `Box<dyn Any>`
/// built from this downcasts correctly inside the coordinator.
type PresignOut = (
    cggmp24::Presignature<Secp256k1>,
    cggmp24::signing::PresignaturePublicData<Secp256k1>,
);

/// Run a `participants`-party presign over the cggmp24 sim, returning each
/// party's `(Presignature, PresignaturePublicData)` positionally by signing
/// index (= position within `participants`). Mirrors `PresigningManager` but
/// runs all parties in-process.
fn presign_subset(
    shares: &[cggmp24::KeyShare<Secp256k1, SecurityLevel128>],
    participants: &[u16],
) -> Vec<PresignOut> {
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rand::Rng::gen(&mut rng);
    let eid = ExecutionId::new(&eid_bytes);
    let pv = participants.to_vec();
    let selected: Vec<_> = participants
        .iter()
        .map(|&i| shares[usize::from(i)].clone())
        .collect();
    round_based::sim::run_with_setup(selected.iter(), |i, party, share| {
        let party = buffer_outgoing(party);
        let mut r = rand::rngs::OsRng;
        let p = pv.clone();
        async move {
            cggmp24::signing(eid, i, &p, share)
                .generate_presignature(&mut r, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec()
}

/// Minimal `EncryptedShare` carrying a cggmp24 `KeyShare` (plaintext ciphertext)
/// plus the canonical joint pubkey. The presigned combine uses only the
/// `share_index` (signing-index lookup) and `config`/joint pubkey — not the key
/// material — so a plaintext-JSON ciphertext is sufficient for this hermetic proof.
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

/// `SigningResult` (raw r||s) → `bsv::primitives::ec::Signature`.
fn to_bsv_sig(res: &SigningResult) -> Signature {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&res.r);
    s.copy_from_slice(&res.s);
    Signature::new(r, s)
}

/// Box a presign output for a coordinator (type-erased, exactly as
/// `PresigningManager::take_raw` hands it over).
fn boxed(out: PresignOut) -> Box<dyn std::any::Any + Send> {
    Box::new(out)
}

/// Drive the DEVICE-HOLDS combine for the 4-of-6 subset `{0,1,2,3}`: the device
/// holds {0,1,2} (party 0 primary + 1,2 added locally), the external cosigner is
/// party 3. `offset` threads the §06.20 BRC-42 shift through every signer.
/// Returns the combined `SigningResult`.
fn device_holds_combine(
    device_shares: &[EncryptedShare; 3], // parties 0,1,2 (positional)
    presigs: Vec<PresignOut>,            // positional by signing index 0..4
    config: ThresholdConfig,
    participants: &[u16],
    sighash: &[u8; 32],
    offset: Option<[u8; 32]>,
) -> SigningRoundResult {
    let mut it = presigs.into_iter();
    let p0 = it.next().unwrap();
    let p1 = it.next().unwrap();
    let p2 = it.next().unwrap();
    let p3 = it.next().unwrap();

    let sign_session = SessionId::from_str_hash("device-holds-presig-relay-sign");
    let mut coord = SigningCoordinator::new(
        sign_session,
        device_shares[0].clone(),
        config,
        participants.to_vec(),
    );
    // Device PRIMARY (party 0, signing index 0): prime the presigned path. The
    // offset is applied to its presig AND the shared public data (once).
    coord
        .sign_with_presignature_with_offset(sighash, boxed(p0), offset)
        .expect("prime primary presig");
    // Device co-located parties 1 & 2 — added locally, never on the wire.
    coord
        .add_local_presig_partial(1, boxed(p1), offset)
        .expect("add device party 1 partial");
    coord
        .add_local_presig_partial(2, boxed(p2), offset)
        .expect("add device party 2 partial");

    // External cosigner (party 3): issue its partial from ITS OWN correlated
    // presig (same primitive the deployed worker `/sign-relay` runs), then feed
    // it to the combiner as the relayed round message.
    let presig3_json = serde_json::to_vec(&p3.0).expect("serialize cosigner presig");
    let partial3 = match offset {
        Some(off) => issue_partial_signature_json_with_offset(&presig3_json, sighash, Some(off)),
        None => issue_partial_signature_json(&presig3_json, sighash),
    }
    .expect("cosigner issues partial");
    let cosigner_msg = bsv_mpc_core::types::RoundMessage {
        session_id: sign_session,
        round: 1,
        from: ShareIndex(3),
        to: Some(ShareIndex(0)),
        payload: partial3,
    };
    coord
        .process_round(vec![cosigner_msg])
        .expect("combine all 4 partials")
}

// #[ignore]: 6-party DKG + auxinfo runs ~3 min even with Blum test primes — run
// on demand (see the module-doc Run line), not as a per-commit regression guard.
#[tokio::test]
#[ignore]
async fn device_holds_3_presigned_relay_combine_signs_and_verifies() {
    let t: u16 = 4;
    let n: u16 = 6;
    let config = ThresholdConfig::new(t, n).expect("4-of-6 config");
    let participants: Vec<u16> = vec![0, 1, 2, 3];
    let dkg_session = SessionId::from_str_hash("device-holds-presig-relay-dkg");

    // ── 1. 4-of-6 DKG → 6 shares, one joint pubkey. ──────────────────────────
    eprintln!("(running 4-of-6 DKG via cggmp24 sim — keygen + auxinfo with Blum test primes)");
    let shares = dkg_key_shares(n, t);
    assert_eq!(shares.len(), 6, "4-of-6 DKG must produce 6 key shares");
    let joint_point = shares[0].core.shared_public_key;
    for (i, sh) in shares.iter().enumerate() {
        assert_eq!(
            sh.core.shared_public_key, joint_point,
            "party {i} disagrees on the joint public key"
        );
    }
    let compressed = joint_point.to_bytes(true);
    let mut joint_arr = [0u8; 33];
    joint_arr.copy_from_slice(&compressed);
    let joint_pub = PublicKey::from_bytes(&joint_arr).expect("joint pubkey is a valid point");
    eprintln!("✔ 4-of-6 DKG: joint_pubkey={}", hex::encode(&compressed));

    let device_shares: [EncryptedShare; 3] = [
        to_encrypted(&shares[0], 0, config, dkg_session),
        to_encrypted(&shares[1], 1, config, dkg_session),
        to_encrypted(&shares[2], 2, config, dkg_session),
    ];

    let sighash: [u8; 32] = [0x42u8; 32];

    // ── 2. BASE KEY: 4-party presign → device-holds combine → verify. ────────
    eprintln!("(4-party presign over {{0,1,2,3}} + device-holds presigned combine — base key)");
    let presigs = presign_subset(&shares, &participants);
    assert_eq!(presigs.len(), 4, "4-party presign must yield 4 presigs");
    let result = device_holds_combine(
        &device_shares,
        presigs,
        config,
        &participants,
        &sighash,
        None,
    );
    let sig = match result {
        SigningRoundResult::Complete(s) => s,
        SigningRoundResult::NextRound(_) => panic!("base-key combine did not complete"),
    };
    let bsv_sig = to_bsv_sig(&sig);
    assert!(bsv_sig.is_low_s(), "MPC signature MUST be low-s (BIP-62)");
    assert!(
        joint_pub.verify(&sighash, &bsv_sig),
        "device-holds-3 presigned 4-of-6 signature MUST verify under the joint pubkey"
    );
    eprintln!("✔ base-key device-holds-3 presigned signature is low-s AND verifies under joint pubkey");

    // ── 3. BRC-42 OFFSET (§06.20): same path → verifies under child key. ─────
    eprintln!("(device-holds presigned combine with a BRC-42 offset — verifies under child key)");
    let offset: [u8; 32] = {
        let mut o = [0u8; 32];
        o[31] = 0x07; // small non-zero scalar
        o
    };
    let off_scalar = Scalar::<Secp256k1>::from_be_bytes_mod_order(offset);
    let child_point = joint_point + Point::<Secp256k1>::generator() * off_scalar;
    let child_compressed = child_point.to_bytes(true);
    let mut child_arr = [0u8; 33];
    child_arr.copy_from_slice(&child_compressed);
    let child_pub = PublicKey::from_bytes(&child_arr).expect("child pubkey is a valid point");

    let presigs_off = presign_subset(&shares, &participants);
    let result_off = device_holds_combine(
        &device_shares,
        presigs_off,
        config,
        &participants,
        &sighash,
        Some(offset),
    );
    let sig_off = match result_off {
        SigningRoundResult::Complete(s) => s,
        SigningRoundResult::NextRound(_) => panic!("offset combine did not complete"),
    };
    let bsv_sig_off = to_bsv_sig(&sig_off);
    assert!(bsv_sig_off.is_low_s(), "offset signature MUST be low-s");
    assert!(
        child_pub.verify(&sighash, &bsv_sig_off),
        "device-holds offset signature MUST verify under child_pub = joint + offset·G"
    );
    assert!(
        !joint_pub.verify(&sighash, &bsv_sig_off),
        "offset signature MUST NOT verify under the BASE joint key (it signs the child key)"
    );
    eprintln!("✔ BRC-42-offset device-holds-3 signature verifies under child key, NOT the base key");

    // ── 4. NEGATIVE: device-alone {0,1,2} (3 < t=4) cannot combine. ──────────
    // Only 3 of the 4 commitment slots are filled → process is never invoked
    // with the cosigner's partial, so no signature can be produced. We assert
    // that priming + the two local additions leave the combine PENDING (a probe
    // process_round with no further partials yields NextRound, never Complete).
    eprintln!("(NEGATIVE: device-alone {{0,1,2}} — 3<t=4 — cannot complete a 4-of-6 signature)");
    let presigs_neg = presign_subset(&shares, &participants);
    let mut it = presigs_neg.into_iter();
    let (np0, np1, np2) = (it.next().unwrap(), it.next().unwrap(), it.next().unwrap());
    let sign_session = SessionId::from_str_hash("device-alone-neg");
    let mut coord = SigningCoordinator::new(
        sign_session,
        device_shares[0].clone(),
        config,
        participants.clone(),
    );
    coord
        .sign_with_presignature(&sighash, boxed(np0))
        .expect("prime primary");
    coord
        .add_local_presig_partial(1, boxed(np1), None)
        .expect("add party 1");
    coord
        .add_local_presig_partial(2, boxed(np2), None)
        .expect("add party 2");
    // No cosigner partial. A probe round with no new partials must stay pending
    // (3 of 4 slots filled) — the device alone CANNOT produce the 4-of-6 sig.
    match coord.process_round(vec![]).expect("probe round") {
        SigningRoundResult::NextRound(msgs) => {
            assert!(msgs.is_empty(), "no outgoing expected on the presigned wait path");
            eprintln!("✔ NEGATIVE: device-alone {{0,1,2}} stays PENDING (3<t=4) — cannot sign alone");
        }
        SigningRoundResult::Complete(_) => {
            panic!("SECURITY VIOLATION: device-alone {{0,1,2}} (3<t=4) produced a 4-of-6 signature");
        }
    }

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════════╗");
    eprintln!("║  POC §1 — DEVICE-HOLDS-3 of 4-of-6 — PRESIGNED RELAY COMBINE        ║");
    eprintln!("╠══════════════════════════════════════════════════════════════════╣");
    eprintln!("║  • 4-party presign → device issues 3 partials + 1 external          ║");
    eprintln!("║  • base key: low-s, verifies under joint pubkey                     ║");
    eprintln!("║  • BRC-42 offset: verifies under child key, NOT base key            ║");
    eprintln!("║  • device-alone {{0,1,2}} (3<4) cannot complete — stays pending     ║");
    eprintln!("║  • add_local_presig_partial: NO new crypto, one more issue_partial  ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════╝");
}
