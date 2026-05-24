//! **POC: god-tier §1 "device holds t−1 shares" — 4-of-6 realizability.**
//!
//! KEYSTONE realizability proof for the §1 scheme:
//!
//!   A single physical **DEVICE** possesses **3 of the 6** key shares
//!   (indices 0,1,2). External parties hold shares 3, 4, and 5. Daily signing is
//!   the device's 3 shares + **ONE** external party → a 4-of-6 subset `{0,1,2,3}`.
//!
//! Hypothesis under test: a normal 4-of-6 CGGMP'24 DKG produces 6 shares; "who
//! holds which" is *just possession*; signing already accepts ANY t-subset — so
//! this needs **NO new crypto and NO core change**, only orchestration.
//!
//! What this hermetic test proves (fast — uses Blum test primes, no network):
//!   1. A 4-of-6 DKG (6 parties) → 6 KeyShares that ALL agree on ONE joint pubkey.
//!   2. The DEVICE is modeled as the holder of shares {0,1,2} (kept together).
//!   3. The 4-of-6 subset {0,1,2,3} (device's 3 + 1 external) signs a fixed
//!      sighash; the result converts to a `bsv::primitives::ec::Signature`, is
//!      low-s (BIP-62), and VERIFIES under the joint pubkey.
//!   4. NEGATIVE control: the device-alone 3-of-6 subset {0,1,2} (below t=4) must
//!      NOT produce a valid 4-of-6 signature — proving "nothing the user holds
//!      signs alone" (§1 security property).
//!
//! Run:
//! ```bash
//! cargo test -p bsv-mpc-core --test poc_4of6_device_holds_3 -- --ignored --nocapture
//! ```

use std::collections::VecDeque;

use bsv::primitives::ec::{PublicKey, Signature};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::signing::PrehashedDataToSign;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;

// ──────────────────────────────────────────────────────────────────────────
// Buffered sink for the round_based simulation (mirrors dkg.rs / the proxy
// reshare e2e — collects outgoing messages then flushes them, which the sim
// harness requires).
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
// Blum test-prime generation (mirrors `dkg::generate_test_primes` — fast vs
// safe primes; auxinfo ZK compute is identical so this is sound for a POC).
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

// ──────────────────────────────────────────────────────────────────────────
// Full t-of-n DKG via the cggmp24 simulation (keygen + auxinfo + combine).
// Mirrors `signing.rs`'s in-file `dkg_key_shares` helper, generalized.
// Returns `n` complete KeyShares (positional: index i = party i).
// ──────────────────────────────────────────────────────────────────────────
fn dkg_key_shares(n: u16, t: u16) -> Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> {
    let mut rng = rand::rngs::OsRng;

    // Step 1: Keygen (threshold-t, n parties).
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

    // Step 2: Aux info generation (Paillier params for signing).
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

    // Step 3: Combine into complete KeyShares.
    incomplete_shares
        .into_iter()
        .zip(aux_infos)
        .map(|(share, aux)| {
            cggmp24::KeyShare::<Secp256k1, SecurityLevel128>::from_parts((share, aux))
                .expect("key share validation should pass")
        })
        .collect()
}

/// Sign a 32-byte prehashed sighash with the given `participants` subset of the
/// DKG KeyShares, returning the cggmp24 signature. Generalized from the proxy
/// reshare e2e's `sign_2of3` — identical pattern, arbitrary subset size.
///
/// `shares` is positional: `shares[i]` is party `i`'s KeyShare.
async fn sign_subset(
    shares: &[cggmp24::KeyShare<Secp256k1, SecurityLevel128>],
    participants: &[u16],
    sighash: &[u8; 32],
) -> cggmp24::Signature<Secp256k1> {
    use generic_ec::Scalar;
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rand::Rng::gen(&mut rng);
    let eid = ExecutionId::new(&eid_bytes);
    let pv = participants.to_vec();
    let scalar = Scalar::<Secp256k1>::from_be_bytes_mod_order(*sighash);
    let data = PrehashedDataToSign::from_scalar(scalar).insecure_assume_preimage_known();
    let selected: Vec<_> = participants
        .iter()
        .map(|&i| shares[usize::from(i)].clone())
        .collect();
    round_based::sim::run_with_setup(selected.iter(), |i, party, share| {
        let party = buffer_outgoing(party);
        let mut r = rand::rngs::OsRng;
        let p = pv.clone();
        async move { cggmp24::signing(eid, i, &p, share).sign(&mut r, party, &data).await }
    })
    .unwrap()
    .expect_ok()
    .expect_eq()
}

/// cggmp24 `Signature` → `bsv::primitives::ec::Signature` (raw r||s).
fn to_bsv_sig(sig: &cggmp24::Signature<Secp256k1>) -> Signature {
    use generic_ec::Scalar;
    let r: Scalar<Secp256k1> = sig.r.into();
    let r_bytes = r.to_be_bytes();
    let s_bytes = sig.s.as_ref().to_be_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(r_bytes.as_bytes());
    s.copy_from_slice(s_bytes.as_bytes());
    Signature::new(r, s)
}

// #[ignore]: keystone realizability proof, not a per-commit regression guard.
// 6-party DKG + auxinfo ZK compute runs ~3min even with Blum test primes, so it
// is run on demand (see the Run line in the module doc) to keep CI fast.
#[tokio::test]
#[ignore]
async fn poc_4of6_device_holds_3_signs_and_verifies() {
    let t: u16 = 4;
    let n: u16 = 6;

    // ── 1. Run a 4-of-6 DKG (6 parties) → 6 shares; assert ONE joint pubkey. ──
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
    assert_eq!(compressed.len(), 33);
    let mut joint_arr = [0u8; 33];
    joint_arr.copy_from_slice(&compressed);
    let joint_pub = PublicKey::from_bytes(&joint_arr).expect("joint pubkey is a valid point");
    eprintln!(
        "✔ 4-of-6 DKG: 6 shares all agree on joint_pubkey={}",
        hex::encode(&compressed)
    );

    // ── 2. Model the DEVICE as the holder of shares {0,1,2}. ──────────────────
    // The "device" is a single physical thing that simply KEEPS these 3 shares
    // together (e.g. in its secure storage). External parties hold 3, 4, 5.
    // Possession is the ONLY thing that distinguishes device-shares from
    // external-shares — the DKG is a vanilla 4-of-6 and produced 6 identical-
    // status shares. No share is "special" cryptographically.
    let device_shares: [u16; 3] = [0, 1, 2];
    let external_shares: [u16; 3] = [3, 4, 5];
    eprintln!(
        "✔ DEVICE holds shares {device_shares:?}; externals hold {external_shares:?} (possession only)"
    );

    // ── 3. Daily sign with the 4-of-6 subset {0,1,2,3} (device's 3 + 1 ext). ──
    let sighash: [u8; 32] = [0x42u8; 32]; // fixed test sighash
    eprintln!("(signing with 4-of-6 subset {{0,1,2,3}} = device's 3 + 1 external)");
    let sig = sign_subset(&shares, &[0, 1, 2, 3], &sighash).await;
    let bsv_sig = to_bsv_sig(&sig);

    assert!(
        bsv_sig.is_low_s(),
        "MPC signature MUST be low-s (BIP-62; cggmp24 normalizes)"
    );
    assert!(
        joint_pub.verify(&sighash, &bsv_sig),
        "4-of-6 subset {{0,1,2,3}} signature MUST verify under the joint pubkey"
    );
    eprintln!("✔ 4-of-6 {{0,1,2,3}} signature is low-s AND verifies under the joint pubkey");

    // Sanity: a DIFFERENT valid 4-subset (device's 3 + a different external)
    // also signs+verifies — confirming "any external completes the device".
    let sig2 = sign_subset(&shares, &[0, 1, 2, 5], &sighash).await;
    let bsv_sig2 = to_bsv_sig(&sig2);
    assert!(bsv_sig2.is_low_s());
    assert!(
        joint_pub.verify(&sighash, &bsv_sig2),
        "alternate 4-of-6 subset {{0,1,2,5}} must also verify (any external completes the device)"
    );
    eprintln!("✔ alternate 4-of-6 {{0,1,2,5}} also verifies (any external completes the device)");

    // ── 4. NEGATIVE control: device-alone {0,1,2} (3-of-6, below t=4). ────────
    // §1 security property: "nothing the user holds signs alone." The device's
    // 3 shares are 1 short of the threshold (t=4). cggmp24 signing with a
    // 3-element participant subset of a t=4 sharing MUST NOT yield a valid 4-of-6
    // signature. We run it under catch_unwind (the sim panics/errors on a
    // sub-threshold participant set) and assert that EITHER it failed to produce
    // a signature, OR — if it somehow produced bytes — those bytes do NOT verify
    // under the joint pubkey. Both outcomes confirm sub-threshold is rejected.
    eprintln!("(NEGATIVE control: device-alone 3-of-6 subset {{0,1,2}} — must NOT sign for the 4-of-6 key)");
    let shares_for_neg = shares.clone();
    let neg_sighash = sighash;
    // Run on a SEPARATE OS thread with its OWN runtime so this genuinely
    // exercises the sub-threshold (3<t=4) signing path. We must NOT nest a
    // `block_on` inside this `#[tokio::test]` worker thread (that would error
    // with "Cannot start a runtime from within a runtime" and mask the real
    // result). `JoinHandle::join` returns `Err` if the thread panicked — which
    // is exactly how a sim abort on a sub-threshold participant set surfaces.
    let neg = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("rt");
        rt.block_on(async { sign_subset(&shares_for_neg, &[0, 1, 2], &neg_sighash).await })
    })
    .join();

    match neg {
        Err(_) => {
            // The cggmp24 sim panicked on the sub-threshold (3 < t=4) participant
            // set — sub-threshold signing is rejected. This is the expected and
            // correct §1 outcome.
            eprintln!("✔ NEGATIVE control: device-alone {{0,1,2}} (3<t=4) was REJECTED (sim aborted) — device cannot sign alone");
        }
        Ok(sig_neg) => {
            // It returned *something* — prove it is NOT a valid signature for the
            // 4-of-6 joint key (reject for the right reason: wrong/under-threshold
            // sharing cannot produce a key-valid signature).
            let bsv_neg = to_bsv_sig(&sig_neg);
            assert!(
                !joint_pub.verify(&sighash, &bsv_neg),
                "SECURITY VIOLATION: device-alone {{0,1,2}} (3<t=4) produced a signature that \
                 VERIFIES under the joint pubkey — the threshold would be broken"
            );
            eprintln!("✔ NEGATIVE control: device-alone {{0,1,2}} produced bytes that do NOT verify under the joint pubkey — device cannot sign alone");
        }
    }

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════════╗");
    eprintln!("║  POC §1 — DEVICE-HOLDS-3 of 4-of-6 — CONFIRMED                      ║");
    eprintln!("╠══════════════════════════════════════════════════════════════════╣");
    eprintln!("║  • 4-of-6 DKG → 6 shares, one joint pubkey                          ║");
    eprintln!("║  • device {{0,1,2}} + 1 external = 4-of-6 → low-s, verifies         ║");
    eprintln!("║  • device-alone {{0,1,2}} (3<4) CANNOT sign for the joint key       ║");
    eprintln!("║  • NO new crypto, NO bsv-mpc-core change — orchestration only       ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════╝");
}
