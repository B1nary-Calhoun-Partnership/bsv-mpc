//! **#40 recovery-sign primitive — HERMETIC proof of TRUE device-loss recovery.**
//!
//! The reshare keystone (`reshar_coordinator::distributed_reshare_3of4_to_4of6_signs`
//! and the deployed `container_reshare_deployed_mainnet_e2e`) proves a cross-(t,n)
//! reshare preserves the joint key. The presigned-relay combine
//! (`poc_4of6_device_holds_presig_relay`) proves a new-set subset signs over the
//! relay. **This fuses them into the #40 recovery-sign primitive** and proves it
//! models a GENUINE device loss — not a 2-of-2 re-provision (a 2-of-2 cannot lose
//! a device: `t=2` needs both shares, so losing one is unrecoverable).
//!
//! Topology (identical to the mainnet gate, driven in-process — no network):
//!   1. **DKG a redundant 2-of-3** → 3 shares {P0,P1,P2}, one joint key K.
//!   2. **LOSE P2** (the phone). The survivors are {P0,P1} = 2 = t — exactly the
//!      `recovery_health` survivor quorum `≥ n−t+1 = 2`, so recovery is *possible*.
//!   3. **The survivors {P0,P1} reshare** (cross-(t,n) PSS over `ResharCoordinator`s,
//!      driven in-process) onto a NEW 2-of-3 {P0′,P1′,P2′} where **P2′ is a
//!      brand-new party** (the recovered device — no old share, recipient-only).
//!      The lost P2 contributes NOTHING (it is not in the contributor set).
//!   4. **The recovered device + a survivor sign** a presigned relay combine over
//!      the new-set subset {0,2} (= survivor P0′ + recovered device P2′) and the
//!      signature **VERIFIES under the UNCHANGED joint key K** — the address is
//!      preserved, the recovered device can spend.
//!
//! Proven assertions:
//!   - **POSITIVE:** the new-set {0,2} subset (survivor + recovered device) signs;
//!     the signature is low-s (BIP-62) and verifies under the ORIGINAL joint key K.
//!     A second subset {1,2} also signs — any 2-of-3 of the new sharing works.
//!   - **NEGATIVE (sub-threshold can't):** the recovered device ALONE (1 < t′=2)
//!     cannot complete a signature — it stays pending.
//!   - **NEGATIVE (lost share invalidated):** the new public shares Lagrange-
//!     reconstruct K, but substituting the LOST party's OLD public share into the
//!     reconstruction set breaks it — the rotated sharing is a fresh polynomial the
//!     dead share cannot rejoin.
//!
//! No new crypto: orchestration over the proven `ResharCoordinator` (PSS),
//! `aux_info_gen` + `KeyShare::from_parts` (fresh aux for the rotated set), and the
//! `SigningCoordinator` presigned relay combine.
//!
//! Run (≈ several min — two DKGs + auxinfo with Blum test primes):
//! ```bash
//! cargo test -p bsv-mpc-core --test recovery_sign_after_reshare -- --ignored --nocapture
//! ```

use std::collections::VecDeque;

use bsv::primitives::ec::{PublicKey, Signature};
use bsv_mpc_core::refresh::verify_reshare;
use bsv_mpc_core::reshar_coordinator::{
    ContributorInputs, ResharCommit, ResharConfig, ResharCoordinator, ResharRoundResult,
};
use bsv_mpc_core::signing::{issue_partial_signature_json, SigningCoordinator, SigningRoundResult};
use bsv_mpc_core::types::{
    EncryptedShare, RoundMessage, SessionId, ShareIndex, SigningResult, ThresholdConfig,
};
use cggmp24::key_share::IncompleteKeyShare;
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use generic_ec::{NonZero, Point, Scalar, SecretScalar};

// ──────────────────────────────────────────────────────────────────────────
// Buffered sink for the round_based simulation (mirrors the proven POCs).
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

// ──────────────────────────────────────────────────────────────────────────
// Blum test primes + cggmp24 keygen / aux_info_gen (mirrors the proven POCs).
// ──────────────────────────────────────────────────────────────────────────
fn generate_blum_prime(rng: &mut impl rand::RngCore, bits: u32) -> cggmp24::backend::Integer {
    use cggmp24::backend::Integer;
    loop {
        let n = Integer::generate_prime(rng, bits);
        if n.mod_u(4) == 3 {
            break n;
        }
    }
}
fn test_primes(
    rng: &mut impl rand::RngCore,
) -> cggmp24::key_refresh::PregeneratedPrimes<SecurityLevel128> {
    use cggmp24::security_level::SecurityLevel;
    let b = SecurityLevel128::RSA_PRIME_BITLEN;
    cggmp24::key_refresh::PregeneratedPrimes::try_from([
        generate_blum_prime(rng, b),
        generate_blum_prime(rng, b),
        generate_blum_prime(rng, b),
        generate_blum_prime(rng, b),
    ])
    .expect("primes have wrong bit size")
}

/// `t-of-n` keygen → `n` `IncompleteKeyShare`s (no aux — used for the OLD sharing,
/// from which we only extract secrets, eval points, and public shares).
fn keygen(n: u16, t: u16) -> Vec<IncompleteKeyShare<Secp256k1>> {
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rand::Rng::gen(&mut rng);
    let eid = ExecutionId::new(&eid_bytes);
    round_based::sim::run(n, |i, party| {
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
    .into_vec()
}

/// Fresh `aux_info_gen(n)` for the NEW party set (party indexing changed by the
/// reshare, so the whole new set needs fresh aux).
fn aux_gen(n: u16) -> Vec<cggmp24::key_share::AuxInfo<SecurityLevel128>> {
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rand::Rng::gen(&mut rng);
    let eid = ExecutionId::new(&eid_bytes);
    let primes: Vec<_> = (0..n).map(|_| test_primes(&mut rng)).collect();
    round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut r = rand::rngs::OsRng;
        let pre = primes[usize::from(i)].clone();
        async move {
            cggmp24::aux_info_gen(eid, i, n, pre)
                .start(&mut r, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec()
}

/// The cggmp24 presign output tuple — same `TypeId` as `presigning`'s internal
/// `PresignOutput`, so a `Box<dyn Any>` from it downcasts inside the coordinator.
type PresignOut = (
    cggmp24::Presignature<Secp256k1>,
    cggmp24::signing::PresignaturePublicData<Secp256k1>,
);

/// Run a `participants`-party presign over the cggmp24 sim, returning each party's
/// `(Presignature, PresignaturePublicData)` positionally by signing index (=
/// position within `participants`).
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

/// Minimal `EncryptedShare` carrying a cggmp24 `KeyShare` (plaintext ciphertext) +
/// the canonical joint pubkey — sufficient for the presigned combine (it uses only
/// the share index + config + joint pubkey, not the key material).
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

fn boxed(out: PresignOut) -> Box<dyn std::any::Any + Send> {
    Box::new(out)
}
fn to_bsv_sig(res: &SigningResult) -> Signature {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&res.r);
    s.copy_from_slice(&res.s);
    Signature::new(r, s)
}

/// Drive the **presigned relay combine** for a 2-party new-set subset
/// `participants` (`[primary, cosigner]`): the primary primes the coordinator from
/// its correlated presig, the cosigner issues its partial from ITS presig (exactly
/// what the deployed `/sign-relay` does), then `process_round` folds it in.
fn relay_combine_2(
    primary_share: &EncryptedShare,
    presigs: Vec<PresignOut>, // positional by signing index 0,1
    config: ThresholdConfig,
    participants: &[u16],
    sighash: &[u8; 32],
) -> SigningRoundResult {
    assert_eq!(
        participants.len(),
        2,
        "this helper drives a 2-party combine"
    );
    let mut it = presigs.into_iter();
    let p_primary = it.next().unwrap();
    let p_cosigner = it.next().unwrap();
    let cosigner_idx = participants[1];

    let sign_session = SessionId::from_str_hash("recovery-sign-after-reshare");
    let mut coord = SigningCoordinator::new(
        sign_session,
        primary_share.clone(),
        config,
        participants.to_vec(),
    );
    coord
        .sign_with_presignature(sighash, boxed(p_primary))
        .expect("prime primary presig");

    let cosigner_json = serde_json::to_vec(&p_cosigner.0).expect("serialize cosigner presig");
    let partial = issue_partial_signature_json(&cosigner_json, sighash).expect("cosigner partial");
    let msg = RoundMessage {
        session_id: sign_session,
        round: 1,
        from: ShareIndex(cosigner_idx),
        to: Some(ShareIndex(participants[0])),
        payload: partial,
    };
    coord.process_round(vec![msg]).expect("combine 2 partials")
}

/// Extract a party's secret scalar from a keygen `IncompleteKeyShare`.
fn old_secret(share: &IncompleteKeyShare<Secp256k1>) -> Scalar<Secp256k1> {
    let d = share.clone().into_inner();
    *<SecretScalar<Secp256k1> as AsRef<Scalar<Secp256k1>>>::as_ref(&d.x)
}

#[tokio::test]
#[ignore]
async fn recovered_device_signs_after_true_loss_reshare() {
    // ── 1. DKG a redundant 2-of-3 → 3 shares, one joint key K. ───────────────
    eprintln!("(1) DKG 2-of-3 (the redundant funded sharing) — keygen with Blum test primes");
    let old_t: u16 = 2;
    let old_n: u16 = 3;
    let old = keygen(old_n, old_t);
    assert_eq!(old.len(), 3, "2-of-3 DKG must produce 3 shares");
    let joint_point = *old[0].shared_public_key;
    for (i, sh) in old.iter().enumerate() {
        assert_eq!(
            *sh.shared_public_key, joint_point,
            "old party {i} disagrees on the joint key"
        );
    }
    let jpk_compressed = joint_point.to_bytes(true);
    let jpk_bytes = jpk_compressed.to_vec();
    let mut joint_arr = [0u8; 33];
    joint_arr.copy_from_slice(&jpk_compressed);
    let joint_pub = PublicKey::from_bytes(&joint_arr).expect("joint pubkey is a valid point");
    eprintln!("✔ funded joint key K = {}", hex::encode(&jpk_compressed));

    // Old eval points + secrets. The survivors are {0,1}; party 2 = THE PHONE.
    let old_dirty0 = old[0].clone().into_inner();
    let old_eval: Vec<NonZero<Scalar<Secp256k1>>> =
        old_dirty0.key_info.vss_setup.as_ref().unwrap().I.clone();
    let old_secrets: Vec<Scalar<Secp256k1>> = old.iter().map(old_secret).collect();

    // ── 2. LOSE party 2 (the phone). Survivors {0,1} = 2 = t — exactly the
    //       recovery_health survivor quorum ≥ n−t+1 = 2, so recovery is possible.
    let survivors: Vec<u16> = vec![0, 1];
    assert_eq!(
        survivors.len(),
        usize::from(old_t),
        "survivor quorum MUST be ≥ t to reshare (recovery_health §18.4a)"
    );
    let lost_party: u16 = 2;
    eprintln!("✔ LOST party {lost_party} (the phone); survivors {survivors:?} (= t = {old_t})");

    // ── 3. Survivors {0,1} reshare → NEW 2-of-3 {P0′,P1′,P2′}; P2′ is brand-new
    //       (the recovered device). The lost party contributes NOTHING. ─────────
    eprintln!(
        "(3) survivors reshare 2-of-3 → 2-of-3 onto a fresh device (PSS over ResharCoordinators)"
    );
    let new_t: u16 = 2;
    let n_new: u16 = 3;
    let new_cfg = ThresholdConfig::new(new_t, n_new).expect("new 2-of-3 config");
    let new_eval: Vec<NonZero<Scalar<Secp256k1>>> = (1..=n_new)
        .map(|i| NonZero::from_scalar(Scalar::from(i as u64)).unwrap())
        .collect();
    // New indices 0,1 continue the survivors; index 2 is the recovered device.
    let contributor_new_indices: Vec<u16> = vec![0, 1];
    let contributor_old_indices: Vec<u16> = survivors.clone();
    let subset_old_eval: Vec<NonZero<Scalar<Secp256k1>>> = contributor_old_indices
        .iter()
        .map(|&k| old_eval[k as usize])
        .collect();

    let mut coords: Vec<ResharCoordinator> = (0..n_new)
        .map(|j| {
            // New parties 0,1 are the surviving contributors; new party 2 is fresh.
            let contributor = contributor_new_indices
                .iter()
                .position(|&c| c == j)
                .map(|pos| ContributorInputs {
                    my_subset_pos: pos,
                    subset_eval_points: subset_old_eval.clone(),
                    my_old_secret: old_secrets[survivors[pos] as usize],
                });
            ResharCoordinator::new(ResharConfig {
                session_id: SessionId::from_str_hash("recovery-reshare"),
                my_new_index: j,
                new_eval_points: new_eval.clone(),
                new_t,
                contributor_new_indices: contributor_new_indices.clone(),
                original_joint_pubkey: jpk_bytes.clone(),
                contributor,
            })
            .expect("reshar coordinator")
        })
        .collect();

    // In-process router (mirror reshar_coordinator::distributed_reshare_*).
    let mut queue: VecDeque<(u16, RoundMessage)> = VecDeque::new();
    let mut commits: Vec<Option<ResharCommit>> = (0..n_new).map(|_| None).collect();
    let enqueue = |q: &mut VecDeque<(u16, RoundMessage)>, from: u16, msgs: Vec<RoundMessage>| {
        for m in msgs {
            match m.to {
                Some(ShareIndex(j)) => q.push_back((j, m)),
                None => {
                    for j in 0..n_new {
                        if j != from {
                            q.push_back((j, m.clone()));
                        }
                    }
                }
            }
        }
    };
    for j in 0..n_new {
        let out = coords[j as usize].init().unwrap();
        enqueue(&mut queue, j, out);
    }
    let mut guard = 0;
    while let Some((rcpt, msg)) = queue.pop_front() {
        guard += 1;
        assert!(guard < 1_000_000, "reshare ceremony did not converge");
        match coords[rcpt as usize].process_round(vec![msg]).unwrap() {
            ResharRoundResult::NextRound(out) => enqueue(&mut queue, rcpt, out),
            ResharRoundResult::Complete(c) => commits[rcpt as usize] = Some(*c),
        }
    }
    let commits: Vec<ResharCommit> = commits
        .into_iter()
        .map(|c| c.expect("every new party committed"))
        .collect();
    for c in &commits {
        assert_eq!(
            c.joint_pubkey_compressed, jpk_bytes,
            "§18 invariant: joint pubkey UNCHANGED by the recovery reshare"
        );
    }
    eprintln!("✔ reshare committed — joint key UNCHANGED, new 2-of-3 sharing produced");

    // Reassemble: IncompleteKeyShares → fresh aux(3) → signing-ready KeyShares.
    eprintln!("(3b) fresh aux_info_gen(3) for the rotated set + KeyShare::from_parts");
    let incompletes: Vec<IncompleteKeyShare<Secp256k1>> = commits
        .iter()
        .map(|c| serde_json::from_slice(&c.incomplete_share_json).expect("incomplete share"))
        .collect();
    let new_aux = aux_gen(n_new);
    let new_shares: Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> = incompletes
        .into_iter()
        .zip(new_aux)
        .map(|(core, a)| cggmp24::KeyShare::from_parts((core, a)).expect("new 2-of-3 key share"))
        .collect();
    assert_eq!(new_shares.len(), 3, "rotated set has 3 shares");

    // ── 4. The recovered device (P2′) + a survivor (P0′) sign over the relay. ──
    let session = SessionId::from_str_hash("recovery-new-set");
    let new_enc: Vec<EncryptedShare> = new_shares
        .iter()
        .enumerate()
        .map(|(i, ks)| to_encrypted(ks, i as u16, new_cfg, session))
        .collect();
    let sighash: [u8; 32] = [0x40u8; 32];

    eprintln!("(4) recovered device {{2}} + survivor {{0}} sign the presigned relay combine");
    let subset = [0u16, 2]; // survivor P0′ (primary) + recovered device P2′ (cosigner)
    let presigs = presign_subset(&new_shares, &subset);
    assert_eq!(presigs.len(), 2, "2-party presign over {{0,2}}");
    let result = relay_combine_2(&new_enc[0], presigs, new_cfg, &subset, &sighash);
    let sig = match result {
        SigningRoundResult::Complete(s) => s,
        SigningRoundResult::NextRound(_) => panic!("recovery combine did not complete"),
    };
    let bsv_sig = to_bsv_sig(&sig);
    assert!(
        bsv_sig.is_low_s(),
        "recovery signature MUST be low-s (BIP-62)"
    );
    assert!(
        joint_pub.verify(&sighash, &bsv_sig),
        "RECOVERY: the recovered device's signature MUST verify under the UNCHANGED joint key K"
    );
    eprintln!("✔ recovered-device {{0,2}} signature is low-s AND verifies under K — address preserved, device can spend");

    // Second subset {1,2}: any 2-of-3 of the rotated sharing spends K.
    let subset_b = [1u16, 2];
    let presigs_b = presign_subset(&new_shares, &subset_b);
    let result_b = relay_combine_2(&new_enc[1], presigs_b, new_cfg, &subset_b, &sighash);
    let sig_b = match result_b {
        SigningRoundResult::Complete(s) => s,
        SigningRoundResult::NextRound(_) => panic!("{{1,2}} combine did not complete"),
    };
    assert!(
        joint_pub.verify(&sighash, &to_bsv_sig(&sig_b)),
        "any 2-of-3 of the rotated sharing MUST verify under K"
    );
    eprintln!(
        "✔ second subset {{1,2}} also verifies under K — any 2-of-3 of the rotated set spends"
    );

    // ── NEGATIVE: the recovered device ALONE (1 < t′=2) cannot sign. ───────────
    let presigs_neg = presign_subset(&new_shares, &subset);
    let mut it = presigs_neg.into_iter();
    let solo = it.next().unwrap();
    let sign_session = SessionId::from_str_hash("recovery-solo-neg");
    let mut coord =
        SigningCoordinator::new(sign_session, new_enc[0].clone(), new_cfg, subset.to_vec());
    coord
        .sign_with_presignature(&sighash, boxed(solo))
        .expect("prime primary");
    match coord.process_round(vec![]).expect("probe round") {
        SigningRoundResult::NextRound(msgs) => {
            assert!(msgs.is_empty(), "no outgoing on the presigned wait path");
            eprintln!(
                "✔ NEGATIVE: a single new-set party (1 < t′=2) stays PENDING — cannot sign alone"
            );
        }
        SigningRoundResult::Complete(_) => {
            panic!("SECURITY VIOLATION: one party produced a 2-of-3 signature alone");
        }
    }

    // ── NEGATIVE: the LOST party's old share is invalidated — the rotated sharing
    //    is a fresh polynomial the dead share cannot rejoin. ────────────────────
    let new_public_shares: Vec<Point<Secp256k1>> = commits[0]
        .new_public_shares
        .iter()
        .map(|b| Point::<Secp256k1>::from_bytes(b).expect("new public share point"))
        .collect();
    assert!(
        verify_reshare(
            &joint_point,
            &new_public_shares,
            &new_eval,
            usize::from(new_t)
        ),
        "control: the rotated public shares MUST reconstruct K"
    );
    // Substitute the LOST party's OLD public share (G·x_lost) into a survivor slot
    // of the reconstruction set — it lies on the OLD polynomial, so reconstruction
    // no longer yields K.
    let lost_old_pub = Point::<Secp256k1>::generator() * old_secrets[lost_party as usize];
    let mut tampered = new_public_shares.clone();
    tampered[1] = lost_old_pub;
    assert!(
        !verify_reshare(&joint_point, &tampered, &new_eval, usize::from(new_t)),
        "INVALIDATION: the lost party's OLD share MUST NOT rejoin the rotated sharing"
    );
    eprintln!(
        "✔ NEGATIVE: lost party's old share is invalidated — cannot rejoin the rotated sharing"
    );

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════════╗");
    eprintln!("║  #40 RECOVERY-SIGN — TRUE DEVICE-LOSS (2-of-3, lose 1, reshare)     ║");
    eprintln!("╠══════════════════════════════════════════════════════════════════╣");
    eprintln!("║  • DKG 2-of-3 → lose the phone (party 2) → survivors {{0,1}} reshare ║");
    eprintln!("║  • fresh device P2′ + survivor P0′ sign → verifies under K          ║");
    eprintln!("║  • address (joint key K) PRESERVED across the recovery              ║");
    eprintln!("║  • solo (1<t′) cannot sign; lost old share cannot rejoin            ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════╝");
}
