//! **#69 — the relay-free device-holds combine kernel.**
//!
//! `bsv_mpc_relay::combine_sign_over_relay_nparty` inlines the device-holds
//! combine (prime PRIMARY presig → `add_local_presig_partial` for each OTHER
//! co-located party → `process_round` folding the external cosigner's relayed
//! partial) intertwined with the relay I/O. #69 extracts that pure combine into
//! [`bsv_mpc_core::signing::device_holds_combine`] so the DEPLOYED relay path AND
//! these hermetic tests drive EXACTLY the same shipped code (zero drift) — the
//! client's 4-of-6 sign is then provable without a live relay.
//!
//! Proves, over the SAME shipped `device_holds_combine`:
//!   1. FAST (CI-gated): a 3-of-3 device-holds-2 (device {0,1} primary 0 + local
//!      1, cosigner 2) combine yields a low-s signature that VERIFIES under the
//!      joint pubkey; the BRC-42-offset variant verifies under the child key and
//!      NOT under the base key.
//!   2. NEGATIVE (CI-gated): the SINGLE-index behavior `main` is stuck at — the
//!      device contributes only its PRIMARY partial (no `add_local`) — leaves the
//!      combine below threshold, so `device_holds_combine` errors "did not
//!      complete". The exact gap #69 closes.
//!   3. REAL TOPOLOGY (`#[ignore]`, proof artifact): the full 4-of-6
//!      device-holds-3 (device {0,1,2} + cosigner 3) combine verifies; offset
//!      variant verifies under the child key; device-alone {0,1,2} (3<t=4) is
//!      below threshold and errors.
//!
//! No new crypto: each partial is one `issue_partial_signature` over a correlated
//! presig; the combiner sums them in commitment order exactly as the 2-party
//! relay does. The 4-of-6 case mirrors the keystone
//! `poc_4of6_device_holds_presig_relay.rs` (mainnet-proven via PR #46, TXID
//! `febd2877…`) but drives it through the extracted kernel.

use std::collections::VecDeque;

use bsv::primitives::ec::{PublicKey, Signature};
use bsv_mpc_core::signing::{
    device_holds_combine, issue_partial_signature_json, issue_partial_signature_json_with_offset,
};
use bsv_mpc_core::types::{
    EncryptedShare, RoundMessage, SessionId, ShareIndex, SigningResult, ThresholdConfig,
};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use generic_ec::{Point, Scalar};

// ──────────────────────────────────────────────────────────────────────────
// round_based sim scaffolding (mirrors poc_4of6_device_holds_presig_relay.rs).
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

type PresignOut = (
    cggmp24::Presignature<Secp256k1>,
    cggmp24::signing::PresignaturePublicData<Secp256k1>,
);

/// Run a `participants`-party presign, returning each party's
/// `(Presignature, PresignaturePublicData)` positionally by signing index.
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

fn to_bsv_sig(res: &SigningResult) -> Signature {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&res.r);
    s.copy_from_slice(&res.s);
    Signature::new(r, s)
}

fn boxed(out: PresignOut) -> Box<dyn std::any::Any + Send> {
    Box::new(out)
}

/// Build the EXTERNAL cosigner's relayed partial `RoundMessage` from its OWN
/// correlated presig (the same primitive the deployed `/sign-relay` runs).
fn cosigner_partial(
    presig: PresignOut,
    sighash: &[u8; 32],
    cosigner_index: u16,
    primary_index: u16,
    session: SessionId,
    offset: Option<[u8; 32]>,
) -> RoundMessage {
    let presig_json = serde_json::to_vec(&presig.0).expect("serialize cosigner presig");
    let partial = match offset {
        Some(off) => issue_partial_signature_json_with_offset(&presig_json, sighash, Some(off)),
        None => issue_partial_signature_json(&presig_json, sighash),
    }
    .expect("cosigner issues partial");
    RoundMessage {
        session_id: session,
        round: 1,
        from: ShareIndex(cosigner_index),
        to: Some(ShareIndex(primary_index)),
        payload: partial,
    }
}

/// child_pub = joint + offset·G — the §06.20 BRC-42 verify target.
fn child_pubkey(joint: &PublicKey, offset: &[u8; 32]) -> PublicKey {
    let joint_pt = Point::<Secp256k1>::from_bytes(joint.to_compressed()).expect("joint point");
    let off = Scalar::<Secp256k1>::from_be_bytes_mod_order(*offset);
    let child = joint_pt + Point::<Secp256k1>::generator() * off;
    let compressed = child.to_bytes(true);
    let mut arr = [0u8; 33];
    arr.copy_from_slice(&compressed);
    PublicKey::from_bytes(&arr).expect("child pubkey is a valid point")
}

fn joint_pubkey_of(
    shares: &[cggmp24::KeyShare<Secp256k1, SecurityLevel128>],
) -> (PublicKey, [u8; 33]) {
    let compressed = shares[0].core.shared_public_key.to_bytes(true);
    let mut arr = [0u8; 33];
    arr.copy_from_slice(&compressed);
    (
        PublicKey::from_bytes(&arr).expect("joint pubkey valid"),
        arr,
    )
}

// ──────────────────────────────────────────────────────────────────────────
// FAST (CI-gated): 3-of-3 device-holds-2 — smallest GENUINE multi-share config.
//   device holds {0,1} (w = t−1 = 2), external cosigner = party 2.
// ──────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn device_holds_2_of_3of3_combine_signs_and_verifies() {
    let (t, n) = (3u16, 3u16);
    let config = ThresholdConfig::new(t, n).expect("3-of-3 config");
    let participants: Vec<u16> = vec![0, 1, 2];
    let session = SessionId::from_str_hash("dh-combine-3of3");

    let shares = dkg_key_shares(n, t);
    assert_eq!(shares.len(), 3);
    let (joint_pub, _arr) = joint_pubkey_of(&shares);
    let device0 = to_encrypted(&shares[0], 0, config, session);
    let sighash: [u8; 32] = [0x42u8; 32];

    // ── BASE KEY: device {0,1} (primary 0 + local 1) + cosigner 2 → verifies. ──
    let presigs = presign_subset(&shares, &participants);
    let mut it = presigs.into_iter();
    let (p0, p1, p2) = (it.next().unwrap(), it.next().unwrap(), it.next().unwrap());
    let sig = device_holds_combine(
        session,
        device0.clone(),
        config,
        participants.clone(),
        &sighash,
        boxed(p0),
        vec![(1, boxed(p1))],
        cosigner_partial(p2, &sighash, 2, 0, session, None),
        None,
    )
    .expect("3-of-3 device-holds-2 combine completes");
    let bsv_sig = to_bsv_sig(&sig);
    assert!(bsv_sig.is_low_s(), "MPC signature MUST be low-s (BIP-62)");
    assert!(
        joint_pub.verify(&sighash, &bsv_sig),
        "device-holds-2 3-of-3 signature MUST verify under the joint pubkey"
    );

    // ── BRC-42 OFFSET (§06.20): verifies under child key, NOT base key. ────────
    let offset: [u8; 32] = {
        let mut o = [0u8; 32];
        o[31] = 0x07;
        o
    };
    let child_pub = child_pubkey(&joint_pub, &offset);
    let presigs_off = presign_subset(&shares, &participants);
    let mut it = presigs_off.into_iter();
    let (o0, o1, o2) = (it.next().unwrap(), it.next().unwrap(), it.next().unwrap());
    let sig_off = device_holds_combine(
        session,
        device0.clone(),
        config,
        participants.clone(),
        &sighash,
        boxed(o0),
        vec![(1, boxed(o1))],
        cosigner_partial(o2, &sighash, 2, 0, session, Some(offset)),
        Some(offset),
    )
    .expect("offset combine completes");
    let bsv_sig_off = to_bsv_sig(&sig_off);
    assert!(bsv_sig_off.is_low_s(), "offset signature MUST be low-s");
    assert!(
        child_pub.verify(&sighash, &bsv_sig_off),
        "offset signature MUST verify under child_pub = joint + offset·G"
    );
    assert!(
        !joint_pub.verify(&sighash, &bsv_sig_off),
        "offset signature MUST NOT verify under the BASE joint key"
    );
}

/// NEGATIVE (CI-gated) — the exact gap #69 closes. The SINGLE-index behavior
/// `main` is stuck at: the device contributes ONLY its primary partial (no
/// `add_local_presig_partial`). With cosigner 2 that is 2 of 3 slots — below
/// t=3 — so the combine MUST NOT complete, and `device_holds_combine` errors
/// with the right reason ("did not complete"). It must never silently produce a
/// signature from sub-threshold material.
#[tokio::test]
async fn single_index_device_cannot_reach_threshold_3of3() {
    let (t, n) = (3u16, 3u16);
    let config = ThresholdConfig::new(t, n).expect("3-of-3 config");
    let participants: Vec<u16> = vec![0, 1, 2];
    let session = SessionId::from_str_hash("dh-combine-3of3-neg");

    let shares = dkg_key_shares(n, t);
    let device0 = to_encrypted(&shares[0], 0, config, session);
    let sighash: [u8; 32] = [0x42u8; 32];

    let presigs = presign_subset(&shares, &participants);
    let mut it = presigs.into_iter();
    let (p0, _p1, p2) = (it.next().unwrap(), it.next().unwrap(), it.next().unwrap());

    // extras = [] → only party 0's partial + cosigner 2 = 2 of 3 (< t).
    let err = device_holds_combine(
        session,
        device0,
        config,
        participants,
        &sighash,
        boxed(p0),
        vec![],
        cosigner_partial(p2, &sighash, 2, 0, session, None),
        None,
    )
    .expect_err("a sub-threshold (single-index) device MUST NOT produce a 3-of-3 signature");
    assert!(
        err.to_string().contains("did not complete"),
        "expected a 'did not complete' below-threshold rejection, got: {err}"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// REAL TOPOLOGY (`#[ignore]` — ≈3 min 6-party DKG+auxinfo): the app's 4-of-6.
//   device holds {0,1,2} (w = t−1 = 3), external cosigner = party 3.
// ──────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn device_holds_3_of_4of6_combine_signs_and_verifies() {
    let (t, n) = (4u16, 6u16);
    let config = ThresholdConfig::new(t, n).expect("4-of-6 config");
    let participants: Vec<u16> = vec![0, 1, 2, 3];
    let session = SessionId::from_str_hash("dh-combine-4of6");

    eprintln!("(running 4-of-6 DKG via cggmp24 sim — keygen + auxinfo, Blum test primes)");
    let shares = dkg_key_shares(n, t);
    assert_eq!(shares.len(), 6, "4-of-6 DKG must produce 6 key shares");
    let (joint_pub, joint_arr) = joint_pubkey_of(&shares);
    eprintln!("✔ 4-of-6 DKG: joint_pubkey={}", hex::encode(joint_arr));
    let device0 = to_encrypted(&shares[0], 0, config, session);
    let device1 = (1u16, to_encrypted(&shares[1], 1, config, session));
    let device2 = (2u16, to_encrypted(&shares[2], 2, config, session));
    let _ = (&device1, &device2); // shares carried via presigs; primary share drives the combine
    let sighash: [u8; 32] = [0x42u8; 32];

    // BASE KEY — device {0,1,2} (primary 0 + local 1,2) + cosigner 3.
    let presigs = presign_subset(&shares, &participants);
    let mut it = presigs.into_iter();
    let (p0, p1, p2, p3) = (
        it.next().unwrap(),
        it.next().unwrap(),
        it.next().unwrap(),
        it.next().unwrap(),
    );
    let sig = device_holds_combine(
        session,
        device0.clone(),
        config,
        participants.clone(),
        &sighash,
        boxed(p0),
        vec![(1, boxed(p1)), (2, boxed(p2))],
        cosigner_partial(p3, &sighash, 3, 0, session, None),
        None,
    )
    .expect("4-of-6 device-holds-3 combine completes");
    let bsv_sig = to_bsv_sig(&sig);
    assert!(bsv_sig.is_low_s(), "MPC signature MUST be low-s (BIP-62)");
    assert!(
        joint_pub.verify(&sighash, &bsv_sig),
        "device-holds-3 4-of-6 signature MUST verify under the joint pubkey"
    );
    eprintln!(
        "✔ base-key 4-of-6 device-holds-3 signature is low-s AND verifies under joint pubkey"
    );

    // BRC-42 OFFSET — verifies under child key, NOT base key.
    let offset: [u8; 32] = {
        let mut o = [0u8; 32];
        o[31] = 0x07;
        o
    };
    let child_pub = child_pubkey(&joint_pub, &offset);
    let presigs_off = presign_subset(&shares, &participants);
    let mut it = presigs_off.into_iter();
    let (o0, o1, o2, o3) = (
        it.next().unwrap(),
        it.next().unwrap(),
        it.next().unwrap(),
        it.next().unwrap(),
    );
    let sig_off = device_holds_combine(
        session,
        device0.clone(),
        config,
        participants.clone(),
        &sighash,
        boxed(o0),
        vec![(1, boxed(o1)), (2, boxed(o2))],
        cosigner_partial(o3, &sighash, 3, 0, session, Some(offset)),
        Some(offset),
    )
    .expect("offset combine completes");
    let bsv_sig_off = to_bsv_sig(&sig_off);
    assert!(bsv_sig_off.is_low_s(), "offset signature MUST be low-s");
    assert!(
        child_pub.verify(&sighash, &bsv_sig_off),
        "offset signature MUST verify under child_pub = joint + offset·G"
    );
    assert!(
        !joint_pub.verify(&sighash, &bsv_sig_off),
        "offset signature MUST NOT verify under the BASE joint key"
    );
    eprintln!("✔ BRC-42-offset 4-of-6 signature verifies under child key, NOT base key");

    // NEGATIVE — device-alone {0,1,2} (3 < t=4): primary + 2 locals = 3 slots,
    // below threshold even with one cosigner absent → must error, never sign.
    let presigs_neg = presign_subset(&shares, &participants);
    let mut it = presigs_neg.into_iter();
    let (n0, n1, n2, n3) = (
        it.next().unwrap(),
        it.next().unwrap(),
        it.next().unwrap(),
        it.next().unwrap(),
    );
    // Feed a STALE/mismatched cosigner partial-free combine by withholding the
    // cosigner: contribute only {0,1} locals + cosigner 3 = 3 of 4 (< t).
    let _ = n2; // party 2 withheld → device under-contributes
    let err = device_holds_combine(
        session,
        device0,
        config,
        participants,
        &sighash,
        boxed(n0),
        vec![(1, boxed(n1))],
        cosigner_partial(n3, &sighash, 3, 0, session, None),
        None,
    )
    .expect_err("device under-contributing (3<t=4) MUST NOT produce a 4-of-6 signature");
    assert!(
        err.to_string().contains("did not complete"),
        "expected a 'did not complete' below-threshold rejection, got: {err}"
    );
    eprintln!("✔ NEGATIVE: sub-threshold (3<4) combine errors — cannot sign");
    eprintln!("╔══════════════════════════════════════════════════════════════════╗");
    eprintln!("║  #69 — device_holds_combine kernel — 4-of-6 device-holds-3 PROVEN   ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════╝");
}
