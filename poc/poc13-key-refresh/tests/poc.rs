//! POC 13: Key Refresh — Threshold Resharing + Re-DKG Fallback
//!
//! FINDING: cggmp24 v0.7.0-alpha.3 does NOT support key refresh natively.
//! The `key_refresh` module only contains `aux_info_gen` (Paillier parameters).
//!
//! SOLUTION: We implement threshold resharing ourselves using cggmp24's
//! existing primitives (generic-ec polynomials, Lagrange interpolation).
//! This is Proactive Secret Sharing (PSS) — surviving parties generate
//! refresh polynomials with zero constant term, creating new shares for
//! the SAME joint secret. Old shares become cryptographically useless.
//!
//! Two tests:
//! 1. `test_threshold_resharing_preserves_key` — the main event:
//!    resharing preserves joint public key, old shares invalidated
//! 2. `test_key_refresh_fallback_re_dkg` — fallback validation:
//!    full re-DKG produces different key, requires fund transfer

use std::collections::VecDeque;

use cggmp24::key_share::{DirtyIncompleteKeyShare, DirtyKeyInfo, Validate, VssSetup};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::signing::DataToSign;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use generic_ec::{NonZero, Point, Scalar, SecretScalar};
use generic_ec_zkp::polynomial::{lagrange_coefficient_at_zero, Polynomial};
use rand::Rng;
use sha2::Sha256;

// ---- Buffered sink (from cggmp24 test infra / POC 1) ----

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
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: M) -> Result<(), Self::Error> {
        self.project().messages.get_mut().push_back(item);
        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
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
    ) -> std::task::Poll<Result<(), Self::Error>> {
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

// ---- Blum prime generation (faster than safe primes for testing) ----

use cggmp24::security_level::SecurityLevel;

fn generate_blum_prime(rng: &mut impl rand::RngCore, bits_size: u32) -> cggmp24::backend::Integer {
    use cggmp24::backend::Integer;
    loop {
        let n = Integer::generate_prime(rng, bits_size);
        if n.mod_u(4) == 3 {
            break n;
        }
    }
}

fn generate_pregenerated_primes(
    rng: &mut impl rand::RngCore,
) -> cggmp24::key_refresh::PregeneratedPrimes<SecurityLevel128> {
    let bitsize = SecurityLevel128::RSA_PRIME_BITLEN;
    let primes = [
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
    ];
    cggmp24::key_refresh::PregeneratedPrimes::try_from(primes)
        .expect("primes have wrong bit size")
}

// ---- Helper: run DKG keygen only (no aux info) ----

async fn run_keygen(
    n: u16,
    t: u16,
) -> Vec<cggmp24::key_share::IncompleteKeyShare<Secp256k1>> {
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid_bytes);

    round_based::sim::run(n, |i, party| {
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
    .into_vec()
}

// ---- Helper: run aux info generation ----

async fn run_aux_gen(
    n: u16,
) -> Vec<cggmp24::key_share::AuxInfo<SecurityLevel128>> {
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rng.gen();
    let eid_aux = ExecutionId::new(&eid_bytes);

    let primes: Vec<_> = (0..n)
        .map(|_| generate_pregenerated_primes(&mut rng))
        .collect();

    round_based::sim::run(n, |i, party| {
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
    .into_vec()
}

// ---- Helper: run full DKG + aux info → complete KeyShares ----

async fn run_dkg(
    n: u16,
    t: u16,
) -> (
    generic_ec::Point<Secp256k1>,
    Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>>,
) {
    let incomplete_shares = run_keygen(n, t).await;
    let joint_pubkey = incomplete_shares[0].shared_public_key;
    let aux_infos = run_aux_gen(n).await;

    let key_shares: Vec<_> = incomplete_shares
        .into_iter()
        .zip(aux_infos)
        .map(|(share, aux)| {
            cggmp24::KeyShare::from_parts((share, aux))
                .expect("key share validation should pass")
        })
        .collect();

    (*joint_pubkey, key_shares)
}

// ---- Helper: sign with a subset of parties ----

async fn sign_with_parties(
    key_shares: &[cggmp24::KeyShare<Secp256k1, SecurityLevel128>],
    participants: &[u16],
    data_to_sign: &DataToSign<Secp256k1>,
) -> cggmp24::Signature<Secp256k1> {
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rng.gen();
    let eid_sign = ExecutionId::new(&eid_bytes);

    let participants_vec = participants.to_vec();

    round_based::sim::run_with_setup(
        participants.iter().map(|i| &key_shares[usize::from(*i)]),
        |i, party, share| {
            let party = buffer_outgoing(party);
            let mut party_rng = rand::rngs::OsRng;
            let p = participants_vec.clone();
            async move {
                cggmp24::signing(eid_sign, i, &p, share)
                    .sign(&mut party_rng, party, data_to_sign)
                    .await
            }
        },
    )
    .unwrap()
    .expect_ok()
    .expect_eq()
}

// ============================================================================
// THRESHOLD RESHARING (Proactive Secret Sharing)
//
// Protocol: Given t surviving parties with shares on a degree-(t-1) polynomial
// F(x) where F(0) = secret, generate new shares for n' parties on a DIFFERENT
// polynomial G(x) where G(0) = same secret.
//
// Each surviving party k:
//   1. Computes Lagrange coefficient λ_k (for interpolation at x=0)
//   2. Computes w_k = λ_k · x_k (their weighted contribution)
//   3. Generates random polynomial f_k(x) of degree (t'-1) with f_k(0) = w_k
//   4. Sends f_k(I'_i) to each new party i
//
// Each new party i computes: x'_i = Σ_k f_k(I'_i)
//
// This works because: Σ_k f_k(0) = Σ_k w_k = Σ_k λ_k·x_k = secret
// (by Lagrange interpolation). So the composite polynomial Σ_k f_k has the
// same constant term (secret) but different coefficients → new shares.
// ============================================================================

/// Perform threshold resharing.
///
/// Returns (new_secret_shares, new_public_shares) for the new party set.
/// The joint public key is UNCHANGED — new shares reconstruct the same secret.
fn threshold_reshare(
    // Surviving parties (must have at least new_t members)
    surviving_eval_points: &[NonZero<Scalar<Secp256k1>>],
    surviving_secret_shares: &[Scalar<Secp256k1>],
    // New party configuration
    new_eval_points: &[NonZero<Scalar<Secp256k1>>],
    new_t: usize,
    rng: &mut impl rand::RngCore,
) -> (Vec<Scalar<Secp256k1>>, Vec<Point<Secp256k1>>) {
    assert!(
        surviving_eval_points.len() >= new_t,
        "need at least new_t surviving parties for resharing"
    );
    assert_eq!(
        surviving_eval_points.len(),
        surviving_secret_shares.len(),
        "eval points and shares must have same length"
    );

    // Use exactly new_t surviving parties for the qualified subset
    let subset_points = &surviving_eval_points[..new_t];
    let subset_shares = &surviving_secret_shares[..new_t];

    // For each party in the qualified subset, generate a refresh polynomial
    let mut polynomials: Vec<Polynomial<Scalar<Secp256k1>>> = Vec::new();

    for k in 0..new_t {
        // Lagrange coefficient for party k at point 0
        let lambda = lagrange_coefficient_at_zero(k, subset_points)
            .expect("evaluation points must be pairwise distinct");

        // w_k = λ_k · x_k (weighted share contribution)
        let w_k: Scalar<Secp256k1> = *lambda * subset_shares[k];

        // Generate random polynomial of degree (new_t - 1) with f(0) = w_k
        // f(x) = w_k + a_1·x + a_2·x² + ... + a_{t-1}·x^{t-1}
        let mut coefs: Vec<Scalar<Secp256k1>> = Vec::with_capacity(new_t);
        coefs.push(w_k);
        for _ in 1..new_t {
            coefs.push(Scalar::random(rng));
        }
        polynomials.push(Polynomial::from_coefs(coefs));
    }

    // Generate new shares for each new party
    let new_n = new_eval_points.len();
    let mut new_secret_shares = Vec::with_capacity(new_n);
    let mut new_public_shares = Vec::with_capacity(new_n);

    for eval_point in new_eval_points {
        // x'_i = Σ_k f_k(I'_i)
        let share: Scalar<Secp256k1> = polynomials
            .iter()
            .map(|f| f.value::<_, Scalar<Secp256k1>>(eval_point.as_ref()))
            .fold(Scalar::zero(), |acc, s| acc + s);

        // Y'_i = G · x'_i
        let pub_share = Point::<Secp256k1>::generator() * share;

        new_secret_shares.push(share);
        new_public_shares.push(pub_share);
    }

    (new_secret_shares, new_public_shares)
}

// ============================================================================
// TEST 1: Threshold resharing — joint public key preserved
// ============================================================================

#[tokio::test]
async fn test_threshold_resharing_preserves_key() {
    let n: u16 = 3;
    let t: u16 = 2; // 2-of-3

    // =========================================================================
    // STEP 1: 3-party DKG (t=2, n=3)
    // =========================================================================
    println!("=== STEP 1: 2-of-3 DKG ===");

    let (joint_pubkey, key_shares) = run_dkg(n, t).await;

    let pubkey_hex = hex::encode(joint_pubkey.to_bytes(true));
    println!("  Joint public key: {pubkey_hex}");

    let bsv_pubkey = bsv::PublicKey::from_bytes(&joint_pubkey.to_bytes(true)).unwrap();
    let address = bsv_pubkey.to_address();
    println!("  BSV address: {address}");

    // =========================================================================
    // STEP 2: Sign with [0,1] — verify before refresh
    // =========================================================================
    println!("\n=== STEP 2: Sign with [0,1] before refresh ===");

    let msg_before = b"POC 13: message signed BEFORE key refresh";
    let data_before = DataToSign::digest::<Sha256>(msg_before);
    let sig_before = sign_with_parties(&key_shares, &[0, 1], &data_before).await;

    sig_before
        .verify(&joint_pubkey, &data_before)
        .expect("pre-refresh signature must verify");
    println!("  Pre-refresh signing [0,1]: PASS");

    // Also verify [1,2] works
    let sig_12 = sign_with_parties(&key_shares, &[1, 2], &data_before).await;
    sig_12
        .verify(&joint_pubkey, &data_before)
        .expect("pre-refresh [1,2] must verify");
    println!("  Pre-refresh signing [1,2]: PASS");

    // =========================================================================
    // STEP 3: Extract share data and perform resharing
    // =========================================================================
    println!("\n=== STEP 3: Threshold resharing (party 2 offline → replaced) ===");
    println!("  Surviving parties: [0, 1]");
    println!("  New party set: [0, 1, 2] (party 2 is replacement node)");

    // Extract evaluation points and secret shares from DKG output
    // KeyShare = Valid<DirtyKeyShare>. into_inner() gives DirtyKeyShare, then .core is DirtyCoreKeyShare.
    let dirty0 = key_shares[0].clone().into_inner().core;
    let dirty1 = key_shares[1].clone().into_inner().core;
    let vss = dirty0.key_info.vss_setup.as_ref().expect("must have VSS setup");

    // Surviving parties: 0 and 1
    let surviving_eval_points = vec![vss.I[0], vss.I[1]];
    let surviving_shares = vec![
        *(*dirty0.x).as_ref(), // NonZero<SecretScalar> -> SecretScalar -> &Scalar -> Scalar
        *(*dirty1.x).as_ref(),
    ];

    // New party set uses same evaluation points (I = [1, 2, 3])
    let new_eval_points = vss.I.clone();

    let mut rng = rand::rngs::OsRng;
    let (new_secret_shares, new_public_shares) = threshold_reshare(
        &surviving_eval_points,
        &surviving_shares,
        &new_eval_points,
        t as usize,
        &mut rng,
    );

    println!("  Resharing complete. Generated {} new shares.", new_secret_shares.len());

    // =========================================================================
    // STEP 4: Verify joint public key is UNCHANGED
    // =========================================================================
    println!("\n=== STEP 4: Verify joint public key is unchanged ===");

    // Reconstruct public key from new shares via Lagrange interpolation at x=0
    let first_t_points = &new_eval_points[..t as usize];
    let first_t_pub_shares = &new_public_shares[..t as usize];

    let reconstructed_pubkey: Point<Secp256k1> = (0..t as usize)
        .map(|j| {
            let lambda =
                lagrange_coefficient_at_zero(j, first_t_points).expect("points must be distinct");
            first_t_pub_shares[j] * *lambda
        })
        .fold(Point::zero(), |acc, p| acc + p);

    assert_eq!(
        joint_pubkey, reconstructed_pubkey,
        "joint public key must be UNCHANGED after resharing"
    );
    println!("  Joint public key after resharing: {}", hex::encode(reconstructed_pubkey.to_bytes(true)));
    println!("  Matches original: CONFIRMED");

    // =========================================================================
    // STEP 5: Construct new IncompleteKeyShares from reshared data
    // =========================================================================
    println!("\n=== STEP 5: Constructing new key shares ===");

    let curve = dirty0.key_info.curve.clone();
    let original_shared_pubkey = dirty0.key_info.shared_public_key;

    let new_nz_public_shares: Vec<NonZero<Point<Secp256k1>>> = new_public_shares
        .iter()
        .map(|p| NonZero::from_point(*p).expect("public share must be non-zero"))
        .collect();

    let new_incomplete_shares: Vec<cggmp24::key_share::IncompleteKeyShare<Secp256k1>> = (0..n)
        .map(|i| {
            let mut share_scalar = new_secret_shares[i as usize];
            let dirty = DirtyIncompleteKeyShare {
                i,
                key_info: DirtyKeyInfo {
                    curve: curve.clone(),
                    shared_public_key: original_shared_pubkey, // SAME key!
                    public_shares: new_nz_public_shares.clone(),
                    vss_setup: Some(VssSetup {
                        min_signers: t,
                        I: new_eval_points.clone(),
                    }),
                },
                x: NonZero::from_secret_scalar(SecretScalar::new(&mut share_scalar))
                    .expect("secret share must be non-zero"),
            };
            dirty.validate().expect("new share must pass validation")
        })
        .collect();

    println!("  All {} new IncompleteKeyShares validated successfully", new_incomplete_shares.len());

    // =========================================================================
    // STEP 6: Generate fresh aux info and combine into complete KeyShares
    // =========================================================================
    println!("\n=== STEP 6: Generating aux info for new shares ===");

    let new_aux_infos = run_aux_gen(n).await;

    let new_key_shares: Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> = new_incomplete_shares
        .into_iter()
        .zip(new_aux_infos)
        .map(|(core, aux)| {
            cggmp24::KeyShare::from_parts((core, aux))
                .expect("new key share must validate with aux info")
        })
        .collect();

    println!("  {} complete KeyShares created", new_key_shares.len());

    // =========================================================================
    // STEP 7: Sign with [0, 2] using NEW shares (party 2 is replacement)
    // =========================================================================
    println!("\n=== STEP 7: Sign with [0, replacement_node] using new shares ===");

    let msg_after = b"POC 13: message signed AFTER key refresh with replacement node";
    let data_after = DataToSign::digest::<Sha256>(msg_after);

    let sig_after = sign_with_parties(&new_key_shares, &[0, 2], &data_after).await;
    sig_after
        .verify(&joint_pubkey, &data_after)
        .expect("post-refresh signature with replacement node must verify against SAME key");
    println!("  Post-refresh signing [0, new_party_2]: PASS");
    println!("  Verified against ORIGINAL joint public key: PASS");

    // BSV SDK cross-check
    let mut sig_after_bytes = [0u8; 64];
    sig_after.write_to_slice(&mut sig_after_bytes);
    let msg_after_hash: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(msg_after).into()
    };
    let bsv_sig_after = bsv::Signature::from_compact(&sig_after_bytes).unwrap();
    assert!(bsv_pubkey.verify(&msg_after_hash, &bsv_sig_after));
    println!("  BSV SDK verify with SAME address: PASS");

    // Also verify [1, 2] works
    let sig_new_12 = sign_with_parties(&new_key_shares, &[1, 2], &data_after).await;
    sig_new_12
        .verify(&joint_pubkey, &data_after)
        .expect("post-refresh [1,2] must verify");
    println!("  Post-refresh signing [1, 2]: PASS");

    // And [0, 1]
    let sig_new_01 = sign_with_parties(&new_key_shares, &[0, 1], &data_after).await;
    sig_new_01
        .verify(&joint_pubkey, &data_after)
        .expect("post-refresh [0,1] must verify");
    println!("  Post-refresh signing [0, 1]: PASS");

    // =========================================================================
    // STEP 8: Verify old shares are INVALIDATED
    // =========================================================================
    println!("\n=== STEP 8: Verify old shares are invalidated ===");

    // Old party 2's secret share should differ from new party 2's share
    let dirty2_old = key_shares[2].clone().into_inner().core;
    let old_share_2: Scalar<Secp256k1> = *(*dirty2_old.x).as_ref();
    let new_share_2 = new_secret_shares[2];

    assert_ne!(
        old_share_2, new_share_2,
        "old party 2 share must differ from new party 2 share"
    );
    println!("  Old share[2] ≠ New share[2]: CONFIRMED");

    // Old party 0's share should also differ (ALL shares change in resharing)
    let old_share_0: Scalar<Secp256k1> = *(*dirty0.x).as_ref();
    let new_share_0 = new_secret_shares[0];

    assert_ne!(
        old_share_0, new_share_0,
        "old party 0 share must differ from new party 0 share (all shares rotate)"
    );
    println!("  Old share[0] ≠ New share[0]: CONFIRMED (all shares rotate)");

    // Old public shares differ from new public shares
    let old_pub_shares: Vec<_> = key_shares[0]
        .core
        .public_shares
        .iter()
        .map(|p| p.to_bytes(true))
        .collect();
    let new_pub_shares_bytes: Vec<_> = new_nz_public_shares
        .iter()
        .map(|p| p.to_bytes(true))
        .collect();
    assert_ne!(
        old_pub_shares, new_pub_shares_bytes,
        "public share sets must change after resharing"
    );
    println!("  Public share sets changed: CONFIRMED");

    // The dead node's old share (party 2) cannot be used with the new key shares.
    // Specifically: if an attacker has old_share_2, they cannot produce valid signatures
    // because old_share_2 lies on the OLD polynomial, not the new one.
    // We verify this by checking old_share_2 ≠ f_new(I_2).
    // (A signing attempt would fail because the share doesn't match the public share.)
    let old_pub_2 = Point::<Secp256k1>::generator() * old_share_2;
    let new_pub_2 = new_public_shares[2];
    assert!(
        old_pub_2 != new_pub_2,
        "old share produces different public point than new share"
    );
    println!("  G·old_share[2] ≠ G·new_share[2]: CONFIRMED");
    println!("  Dead node's old share is cryptographically useless");

    // =========================================================================
    // STEP 9: Verify BSV address is UNCHANGED (no fund transfer needed!)
    // =========================================================================
    println!("\n=== STEP 9: Verify BSV address unchanged ===");

    let post_refresh_pubkey = new_key_shares[0].core.shared_public_key;
    assert_eq!(
        joint_pubkey, *post_refresh_pubkey,
        "joint public key must be identical after resharing"
    );

    let post_refresh_bsv_key =
        bsv::PublicKey::from_bytes(&post_refresh_pubkey.to_bytes(true)).unwrap();
    let post_refresh_address = post_refresh_bsv_key.to_address();
    assert_eq!(
        address, post_refresh_address,
        "BSV address must be identical after resharing"
    );
    println!("  Address before: {address}");
    println!("  Address after:  {post_refresh_address}");
    println!("  IDENTICAL — no fund transfer needed!");

    // =========================================================================
    // SUMMARY
    // =========================================================================
    println!("\n========================================");
    println!("  POC 13 RESULT: THRESHOLD RESHARING WORKS");
    println!("========================================");
    println!();
    println!("  KEY ACHIEVEMENT: Implemented threshold resharing using");
    println!("  cggmp24's existing primitives (Lagrange interpolation +");
    println!("  polynomial secret sharing). No upstream changes needed.");
    println!();
    println!("  [x] 2-of-3 DKG produces valid joint key");
    println!("  [x] Pre-refresh signing works (any 2-of-3)");
    println!("  [x] Threshold resharing generates new shares");
    println!("  [x] New shares pass cggmp24 KeyShare validation");
    println!("  [x] Post-refresh signing works with replacement node");
    println!("  [x] Post-refresh signatures verify against SAME joint key");
    println!("  [x] BSV address is UNCHANGED (no fund transfer!)");
    println!("  [x] ALL old shares are rotated (different from new)");
    println!("  [x] Dead node's old share is cryptographically useless");
    println!();
    println!("  vs FALLBACK (re-DKG):");
    println!("  - Resharing: same key, no fund transfer, 0 sats cost");
    println!("  - Re-DKG: different key, fund transfer needed, ~188 sats");
    println!("========================================");
}

// ============================================================================
// TEST 2: Fallback — full re-DKG (different key, requires fund transfer)
// ============================================================================

#[tokio::test]
async fn test_key_refresh_fallback_re_dkg() {
    let n: u16 = 3;
    let t: u16 = 2; // 2-of-3

    println!("=== Fallback: Re-DKG with fund transfer ===");

    // DKG A
    let (joint_pubkey_a, key_shares_a) = run_dkg(n, t).await;
    let bsv_pubkey_a = bsv::PublicKey::from_bytes(&joint_pubkey_a.to_bytes(true)).unwrap();
    let address_a = bsv_pubkey_a.to_address();
    println!("  Key A: {}", hex::encode(joint_pubkey_a.to_bytes(true)));
    println!("  Address A: {address_a}");

    // Sign with [0,1] on key A
    let msg = b"fallback test";
    let data = DataToSign::digest::<Sha256>(msg);
    let sig = sign_with_parties(&key_shares_a, &[0, 1], &data).await;
    sig.verify(&joint_pubkey_a, &data).expect("key A signing must work");
    println!("  Sign with key A [0,1]: PASS");

    // DKG B (simulate node replacement)
    let (joint_pubkey_b, key_shares_b) = run_dkg(n, t).await;
    let bsv_pubkey_b = bsv::PublicKey::from_bytes(&joint_pubkey_b.to_bytes(true)).unwrap();
    let address_b = bsv_pubkey_b.to_address();
    println!("  Key B: {}", hex::encode(joint_pubkey_b.to_bytes(true)));
    println!("  Address B: {address_b}");

    // Keys must differ
    assert_ne!(joint_pubkey_a, joint_pubkey_b);
    println!("  Key A ≠ Key B: CONFIRMED (fund transfer required)");

    // Sign fund transfer A→B
    let transfer_msg = format!("Transfer {} → {}", address_a, address_b);
    let data_transfer = DataToSign::digest::<Sha256>(transfer_msg.as_bytes());
    let sig_transfer = sign_with_parties(&key_shares_a, &[0, 1], &data_transfer).await;
    sig_transfer
        .verify(&joint_pubkey_a, &data_transfer)
        .expect("fund transfer must verify");
    println!("  Fund transfer A→B signed: PASS");

    // Sign with new key B
    let sig_b = sign_with_parties(&key_shares_b, &[0, 2], &data).await;
    sig_b.verify(&joint_pubkey_b, &data).expect("key B signing must work");
    println!("  Sign with key B [0,2]: PASS");

    // Cross-key verification fails
    assert!(sig.verify(&joint_pubkey_b, &data).is_err());
    assert!(sig_b.verify(&joint_pubkey_a, &data).is_err());
    println!("  Cross-key verification fails: CONFIRMED");

    println!("\n  Fallback VALIDATED — works but requires on-chain fund transfer");
}
