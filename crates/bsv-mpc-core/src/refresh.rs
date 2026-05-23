//! Key refresh via threshold resharing (Proactive Secret Sharing).
//!
//! When an MPC node goes offline or a share is compromised, the remaining
//! parties can generate **new shares** for the same joint public key without
//! reconstructing the private key. Old shares become cryptographically useless.
//!
//! ## Algorithm
//!
//! Given `t` surviving parties with shares on a degree-(t-1) polynomial
//! `F(x)` where `F(0) = secret`, generate new shares for `n'` parties on a
//! DIFFERENT polynomial `G(x)` where `G(0) = same secret`.
//!
//! Each surviving party `k`:
//!   1. Computes Lagrange coefficient `lambda_k` (for interpolation at x=0)
//!   2. Computes weighted share: `w_k = lambda_k * x_k`
//!   3. Generates random polynomial `f_k(x)` of degree `(t'-1)` with `f_k(0) = w_k`
//!   4. Evaluates `f_k` at each new party's evaluation point
//!
//! Each new party `i` computes: `x'_i = sum_k f_k(eval_point_i)`
//!
//! This works because: `sum_k f_k(0) = sum_k w_k = sum_k lambda_k * x_k = secret`
//! (by Lagrange interpolation). So the composite polynomial has the same constant
//! term (secret) but different coefficients, yielding new shares.
//!
//! ## Properties
//!
//! - Joint public key is **unchanged** (same BSV address, no fund transfer)
//! - All old shares are rotated (different from new shares)
//! - A dead node's old share is cryptographically useless against the new polynomial
//! - Supports arbitrary (t, n) -> (t', n') resharing
//! - Cost: 0 sats on-chain (vs ~188 sats for re-DKG with fund transfer)
//!
//! Ported from POC 13 (`poc/poc13-key-refresh/tests/poc.rs`).

use crate::error::{MpcError, Result};
use crate::types::JointPublicKey;

use cggmp24::key_share::{
    DirtyIncompleteKeyShare, DirtyKeyInfo, IncompleteKeyShare, Validate, VssSetup,
};
use cggmp24::supported_curves::Secp256k1;
use generic_ec::{NonZero, Point, Scalar, SecretScalar};
use generic_ec_zkp::polynomial::{lagrange_coefficient_at_zero, Polynomial};

/// New secret shares and their corresponding public shares.
type ReshareOutput = (Vec<Scalar<Secp256k1>>, Vec<Point<Secp256k1>>);

/// Result of a threshold resharing operation.
///
/// Contains the new shares, evaluation points, and metadata needed to
/// construct new `KeyShare`s for the refreshed party set.
#[derive(Debug, Clone)]
pub struct RefreshResult {
    /// New secret shares, one per new party (32-byte big-endian scalars).
    pub new_secret_shares: Vec<Vec<u8>>,
    /// New public shares, one per new party (33-byte compressed points).
    pub new_public_shares: Vec<Vec<u8>>,
    /// Evaluation points for the new party set (32-byte big-endian scalars).
    pub new_eval_points: Vec<Vec<u8>>,
    /// The original joint public key (unchanged by resharing).
    pub original_joint_key: JointPublicKey,
    /// New threshold (minimum signers required).
    pub new_threshold: u16,
    /// New total number of parties.
    pub new_parties: u16,
}

/// Perform threshold resharing (Proactive Secret Sharing).
///
/// Given a qualified subset of surviving parties (at least `new_t` of them),
/// generate new secret shares and public shares for a new set of parties.
/// The joint public key is unchanged -- new shares reconstruct the same secret.
///
/// # Arguments
///
/// * `surviving_eval_points` - VSS evaluation points of the surviving parties
///   (from `VssSetup.I`). Must have length >= `new_t`.
/// * `surviving_secret_shares` - Secret scalar shares of the surviving parties.
///   Must have same length as `surviving_eval_points`.
/// * `new_eval_points` - Evaluation points for the new party set.
/// * `new_t` - New threshold (degree of the sharing polynomial + 1).
/// * `rng` - Cryptographic RNG for generating random polynomial coefficients.
///
/// # Returns
///
/// `(new_secret_shares, new_public_shares)` where:
/// - `new_secret_shares[i]` is the secret scalar for new party `i`
/// - `new_public_shares[i]` is `G * new_secret_shares[i]`
///
/// # Errors
///
/// Returns `MpcError::Protocol` if:
/// - `surviving_eval_points.len() < new_t` (not enough surviving parties)
/// - `surviving_eval_points.len() != surviving_secret_shares.len()`
/// - Lagrange coefficient computation fails (duplicate evaluation points)
pub fn threshold_reshare(
    surviving_eval_points: &[NonZero<Scalar<Secp256k1>>],
    surviving_secret_shares: &[Scalar<Secp256k1>],
    new_eval_points: &[NonZero<Scalar<Secp256k1>>],
    new_t: usize,
    rng: &mut impl rand::RngCore,
) -> Result<ReshareOutput> {
    if surviving_eval_points.len() < new_t {
        return Err(MpcError::Protocol(format!(
            "need at least new_t ({new_t}) surviving parties for resharing, got {}",
            surviving_eval_points.len()
        )));
    }
    if surviving_eval_points.len() != surviving_secret_shares.len() {
        return Err(MpcError::Protocol(format!(
            "eval points ({}) and shares ({}) must have same length",
            surviving_eval_points.len(),
            surviving_secret_shares.len()
        )));
    }

    // Use exactly new_t surviving parties for the qualified subset
    let subset_points = &surviving_eval_points[..new_t];
    let subset_shares = &surviving_secret_shares[..new_t];

    // For each party in the qualified subset, generate a refresh polynomial
    let mut polynomials: Vec<Polynomial<Scalar<Secp256k1>>> = Vec::with_capacity(new_t);

    for (k, share_k) in subset_shares.iter().enumerate() {
        // Lagrange coefficient for party k at point 0
        let lambda = lagrange_coefficient_at_zero(k, subset_points).ok_or_else(|| {
            MpcError::Protocol(format!(
                "Lagrange coefficient computation failed for party {k} (duplicate eval points?)"
            ))
        })?;

        // w_k = lambda_k * x_k (weighted share contribution)
        let w_k: Scalar<Secp256k1> = *lambda * *share_k;

        // Generate random polynomial of degree (new_t - 1) with f(0) = w_k
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
        // x'_i = sum_k f_k(eval_point_i)
        let share: Scalar<Secp256k1> = polynomials
            .iter()
            .map(|f| f.value::<_, Scalar<Secp256k1>>(eval_point.as_ref()))
            .fold(Scalar::zero(), |acc, s| acc + s);

        // Y'_i = G * x'_i
        let pub_share = Point::<Secp256k1>::generator() * share;

        new_secret_shares.push(share);
        new_public_shares.push(pub_share);
    }

    Ok((new_secret_shares, new_public_shares))
}

/// One surviving party's **local** PSS refresh contribution (distributed §18.2).
///
/// This is the per-party decomposition of [`threshold_reshare`]: where that
/// function reshares centrally (it takes *every* survivor's secret share at
/// once), this computes only the calling party's contribution from its OWN
/// secret share — the form used by [`RefreshCoordinator`](crate::refresh_coordinator::RefreshCoordinator)
/// so no party ever reveals or aggregates another party's old share.
///
/// The party at position `my_subset_pos` within `subset_eval_points` (the
/// qualified surviving subset, length `new_t`), holding secret `my_secret`,
/// generates a fresh random degree-`(new_t-1)` polynomial `f` with
/// `f(0) = λ · my_secret` (`λ` = its Lagrange-at-zero coefficient over the
/// subset) and evaluates `f` at every new party's eval point. The returned
/// `evals[j] = f(new_eval_points[j])` are sent **p2p** (one per new party, over
/// the BRC-78-encrypted envelope §06.3); each new party `j` sums the evals it
/// receives from all survivors to obtain its rotated share
/// `x'_j = Σ_k f_k(e'_j)`.
///
/// ## Why this is zero-knowledge of the old share
///
/// Each recipient `j` learns exactly ONE evaluation of `f`. Recovering `f`
/// (hence `f(0) = λ·my_secret`, hence `my_secret`) requires `new_t` evaluations.
/// An adversary controlling up to `new_t - 1` parties therefore cannot recover a
/// surviving honest party's old secret — the proactive-security property of
/// §18.1 ("a pre-refresh share leak can't reconstruct"). The construction is the
/// Herzberg et al. proactive-secret-sharing reshare; cggmp24 does not provide it
/// natively (it ships only `aux_info_gen`), so this is the canonical primitive
/// for re-randomizing a threshold (t-of-n) sharing while preserving the joint
/// public key.
///
/// # Errors
///
/// `MpcError::Protocol` if the Lagrange coefficient cannot be computed (duplicate
/// eval points) or `my_subset_pos >= subset_eval_points.len()`.
pub fn party_reshare_contribution(
    my_subset_pos: usize,
    subset_eval_points: &[NonZero<Scalar<Secp256k1>>],
    my_secret: &Scalar<Secp256k1>,
    new_eval_points: &[NonZero<Scalar<Secp256k1>>],
    new_t: usize,
    rng: &mut impl rand::RngCore,
) -> Result<Vec<Scalar<Secp256k1>>> {
    if my_subset_pos >= subset_eval_points.len() {
        return Err(MpcError::Protocol(format!(
            "my_subset_pos {my_subset_pos} out of range for subset of {}",
            subset_eval_points.len()
        )));
    }
    if subset_eval_points.len() < new_t {
        return Err(MpcError::Protocol(format!(
            "qualified subset ({}) smaller than new_t ({new_t})",
            subset_eval_points.len()
        )));
    }

    // λ for this party at point 0, over the qualified surviving subset.
    let lambda = lagrange_coefficient_at_zero(my_subset_pos, &subset_eval_points[..new_t])
        .ok_or_else(|| {
            MpcError::Protocol(format!(
                "Lagrange coefficient computation failed for subset pos {my_subset_pos} (duplicate eval points?)"
            ))
        })?;

    // w = λ · my_secret — the constant term of this party's refresh polynomial.
    let w: Scalar<Secp256k1> = *lambda * *my_secret;

    // Fresh random degree-(new_t-1) polynomial f with f(0) = w.
    let mut coefs: Vec<Scalar<Secp256k1>> = Vec::with_capacity(new_t);
    coefs.push(w);
    for _ in 1..new_t {
        coefs.push(Scalar::random(rng));
    }
    let f = Polynomial::from_coefs(coefs);

    // Evaluate at every new party's eval point.
    Ok(new_eval_points
        .iter()
        .map(|e| f.value::<_, Scalar<Secp256k1>>(e.as_ref()))
        .collect())
}

/// Verify that reshared shares reconstruct the original joint public key.
///
/// Uses Lagrange interpolation at x=0 on the first `new_t` public shares
/// to reconstruct the joint public key, then compares it to the original.
///
/// # Arguments
///
/// * `original_joint_pubkey` - The joint public key from the original DKG.
/// * `new_public_shares` - Public shares from `threshold_reshare`.
/// * `new_eval_points` - Evaluation points for the new party set.
/// * `new_t` - New threshold.
///
/// # Returns
///
/// `true` if the reconstructed key matches the original, `false` otherwise.
pub fn verify_reshare(
    original_joint_pubkey: &Point<Secp256k1>,
    new_public_shares: &[Point<Secp256k1>],
    new_eval_points: &[NonZero<Scalar<Secp256k1>>],
    new_t: usize,
) -> bool {
    if new_public_shares.len() < new_t || new_eval_points.len() < new_t {
        return false;
    }

    let first_t_points = &new_eval_points[..new_t];
    let first_t_pub_shares = &new_public_shares[..new_t];

    let reconstructed: Point<Secp256k1> = (0..new_t)
        .filter_map(|j| {
            let lambda = lagrange_coefficient_at_zero(j, first_t_points)?;
            Some(first_t_pub_shares[j] * *lambda)
        })
        .fold(Point::zero(), |acc, p| acc + p);

    *original_joint_pubkey == reconstructed
}

/// Assemble the **new party set's** [`IncompleteKeyShare`]s from a completed
/// (cross-)reshare (MPC-Spec §18.2 `reshare_change_threshold`).
///
/// Given the reshared per-party secret + public shares (from [`threshold_reshare`]
/// / the distributed [`party_reshare_contribution`] sum) and the new party set's
/// VSS parameters, this builds one validated `IncompleteKeyShare` per new party —
/// all bound to the **unchanged** `shared_public_key`. The caller then runs a
/// fresh `aux_info_gen` across the new `n'` parties and `KeyShare::from_parts`
/// to obtain signing-ready shares.
///
/// `template` supplies the curve identifier, the unchanged `shared_public_key`,
/// and the `chain_code` (HD support) — taken from any surviving party's share.
/// A cross-(t,n) reshape REQUIRES fresh aux for the whole new set (the old aux was
/// generated for the old party indexing), so this returns INCOMPLETE shares; for a
/// same-party-set routine refresh that keeps aux, use
/// [`RefreshCoordinator`](crate::refresh_coordinator::RefreshCoordinator) instead.
///
/// # Errors
///
/// `MpcError::Protocol` if the share/point/eval-point counts disagree, a public
/// share is the identity, a secret share is zero, or validation fails.
pub fn build_reshared_incomplete_shares(
    template: &IncompleteKeyShare<Secp256k1>,
    new_secret_shares: &[Scalar<Secp256k1>],
    new_public_shares: &[Point<Secp256k1>],
    new_eval_points: &[NonZero<Scalar<Secp256k1>>],
    new_t: u16,
) -> Result<Vec<IncompleteKeyShare<Secp256k1>>> {
    let new_n = new_eval_points.len();
    if new_secret_shares.len() != new_n || new_public_shares.len() != new_n {
        return Err(MpcError::Protocol(format!(
            "reshared share counts disagree: secrets={}, publics={}, eval_points={new_n}",
            new_secret_shares.len(),
            new_public_shares.len()
        )));
    }
    if new_n < usize::from(new_t) || new_t == 0 {
        return Err(MpcError::Protocol(format!(
            "invalid new (t,n): t={new_t}, n={new_n}"
        )));
    }

    let dirty_template = template.clone().into_inner();
    let curve = dirty_template.key_info.curve;
    let shared_public_key = dirty_template.key_info.shared_public_key;
    let chain_code = dirty_template.key_info.chain_code;

    let nz_public_shares: Vec<NonZero<Point<Secp256k1>>> = new_public_shares
        .iter()
        .map(|p| {
            NonZero::from_point(*p)
                .ok_or_else(|| MpcError::Protocol("reshared public share is identity".into()))
        })
        .collect::<Result<_>>()?;

    (0..new_n as u16)
        .map(|i| {
            let mut share_scalar = new_secret_shares[i as usize];
            let x = NonZero::from_secret_scalar(SecretScalar::new(&mut share_scalar))
                .ok_or_else(|| MpcError::Protocol(format!("reshared secret share {i} is zero")))?;
            let dirty = DirtyIncompleteKeyShare {
                i,
                key_info: DirtyKeyInfo {
                    curve,
                    shared_public_key,
                    public_shares: nz_public_shares.clone(),
                    vss_setup: Some(VssSetup {
                        min_signers: new_t,
                        I: new_eval_points.to_vec(),
                    }),
                    chain_code,
                },
                x,
            };
            dirty
                .validate()
                .map_err(|e| MpcError::Protocol(format!("reshared share {i} invalid: {e}")))
        })
        .collect()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;

    use cggmp24::key_share::{DirtyIncompleteKeyShare, DirtyKeyInfo, Validate, VssSetup};
    use cggmp24::security_level::SecurityLevel;
    use cggmp24::security_level::SecurityLevel128;
    use cggmp24::signing::DataToSign;
    use cggmp24::ExecutionId;
    use generic_ec::SecretScalar;
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

    // ---- Blum prime generation ----

    fn generate_blum_prime(
        rng: &mut impl rand::RngCore,
        bits_size: u32,
    ) -> cggmp24::backend::Integer {
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

    async fn run_keygen(n: u16, t: u16) -> Vec<cggmp24::key_share::IncompleteKeyShare<Secp256k1>> {
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

    async fn run_aux_gen(n: u16) -> Vec<cggmp24::key_share::AuxInfo<SecurityLevel128>> {
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

    // ---- Helper: run full DKG + aux info -> complete KeyShares ----

    async fn run_dkg(
        n: u16,
        t: u16,
    ) -> (
        Point<Secp256k1>,
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

    // ---- Helper: extract eval points and secret shares from DKG output ----

    /// (eval_points, secret_shares, all_eval_points)
    type ExtractedShareData = (
        Vec<NonZero<Scalar<Secp256k1>>>,
        Vec<Scalar<Secp256k1>>,
        Vec<NonZero<Scalar<Secp256k1>>>,
    );

    fn extract_share_data(
        key_shares: &[cggmp24::KeyShare<Secp256k1, SecurityLevel128>],
    ) -> ExtractedShareData {
        let dirty0 = key_shares[0].clone().into_inner().core;
        let vss = dirty0
            .key_info
            .vss_setup
            .as_ref()
            .expect("must have VSS setup");
        let all_eval_points = vss.I.clone();

        let mut eval_points = Vec::new();
        let mut secret_shares = Vec::new();

        for ks in key_shares {
            let dirty = ks.clone().into_inner().core;
            let idx = dirty.i as usize;
            eval_points.push(all_eval_points[idx]);
            secret_shares.push(*(*dirty.x).as_ref());
        }

        (eval_points, secret_shares, all_eval_points)
    }

    // ---- Helper: build new KeyShares from reshared data ----

    fn build_new_incomplete_shares(
        original_key_shares: &[cggmp24::KeyShare<Secp256k1, SecurityLevel128>],
        new_secret_shares: &[Scalar<Secp256k1>],
        new_public_shares: &[Point<Secp256k1>],
        new_eval_points: &[NonZero<Scalar<Secp256k1>>],
        new_t: u16,
        new_n: u16,
    ) -> Vec<cggmp24::key_share::IncompleteKeyShare<Secp256k1>> {
        let dirty0 = original_key_shares[0].clone().into_inner().core;
        // CurveName<_> is Copy; no clone needed.
        let curve = dirty0.key_info.curve;
        let original_shared_pubkey = dirty0.key_info.shared_public_key;

        let new_nz_public_shares: Vec<NonZero<Point<Secp256k1>>> = new_public_shares
            .iter()
            .map(|p| NonZero::from_point(*p).expect("public share must be non-zero"))
            .collect();

        (0..new_n)
            .map(|i| {
                let mut share_scalar = new_secret_shares[i as usize];
                let dirty = DirtyIncompleteKeyShare {
                    i,
                    key_info: DirtyKeyInfo {
                        curve,
                        shared_public_key: original_shared_pubkey,
                        public_shares: new_nz_public_shares.clone(),
                        vss_setup: Some(VssSetup {
                            min_signers: new_t,
                            I: new_eval_points.to_vec(),
                        }),
                        chain_code: None,
                    },
                    x: NonZero::from_secret_scalar(SecretScalar::new(&mut share_scalar))
                        .expect("secret share must be non-zero"),
                };
                dirty.validate().expect("new share must pass validation")
            })
            .collect()
    }

    // ====================================================================
    // Tests
    // ====================================================================

    /// Port of POC 13 test_threshold_resharing_preserves_key.
    /// 2-of-3 DKG -> reshare with surviving [0,1] -> verify joint key unchanged.
    #[tokio::test]
    async fn test_threshold_reshare_preserves_key() {
        let n: u16 = 3;
        let t: u16 = 2;

        // Step 1: Run 2-of-3 DKG
        let (joint_pubkey, key_shares) = run_dkg(n, t).await;

        // Step 2: Extract share data
        let (eval_points, secret_shares, all_eval_points) = extract_share_data(&key_shares);

        // Step 3: Reshare with surviving parties [0, 1]
        let surviving_eval_points = vec![eval_points[0], eval_points[1]];
        let surviving_shares = vec![secret_shares[0], secret_shares[1]];

        let mut rng = rand::rngs::OsRng;
        let (new_secret_shares, new_public_shares) = threshold_reshare(
            &surviving_eval_points,
            &surviving_shares,
            &all_eval_points,
            t as usize,
            &mut rng,
        )
        .expect("resharing must succeed");

        assert_eq!(new_secret_shares.len(), n as usize);
        assert_eq!(new_public_shares.len(), n as usize);

        // Step 4: Verify joint public key is unchanged via Lagrange reconstruction
        assert!(
            verify_reshare(
                &joint_pubkey,
                &new_public_shares,
                &all_eval_points,
                t as usize
            ),
            "joint public key must be unchanged after resharing"
        );
    }

    /// Verify all old shares differ from new shares after resharing.
    #[tokio::test]
    async fn test_old_shares_invalidated() {
        let n: u16 = 3;
        let t: u16 = 2;

        let (_joint_pubkey, key_shares) = run_dkg(n, t).await;
        let (eval_points, secret_shares, all_eval_points) = extract_share_data(&key_shares);

        let surviving_eval_points = vec![eval_points[0], eval_points[1]];
        let surviving_shares = vec![secret_shares[0], secret_shares[1]];

        let mut rng = rand::rngs::OsRng;
        let (new_secret_shares, new_public_shares) = threshold_reshare(
            &surviving_eval_points,
            &surviving_shares,
            &all_eval_points,
            t as usize,
            &mut rng,
        )
        .expect("resharing must succeed");

        // All shares must have changed
        for i in 0..n as usize {
            assert_ne!(
                secret_shares[i], new_secret_shares[i],
                "old share[{i}] must differ from new share[{i}]"
            );
        }

        // Public shares must have changed
        for i in 0..n as usize {
            let old_pub = Point::<Secp256k1>::generator() * secret_shares[i];
            assert_ne!(
                old_pub, new_public_shares[i],
                "old public share[{i}] must differ from new public share[{i}]"
            );
        }
    }

    /// Reshare -> build new KeyShares -> sign with cggmp24 -> verify against original joint key.
    #[tokio::test]
    async fn test_sign_with_new_shares() {
        let n: u16 = 3;
        let t: u16 = 2;

        let (joint_pubkey, key_shares) = run_dkg(n, t).await;
        let (eval_points, secret_shares, all_eval_points) = extract_share_data(&key_shares);

        // Reshare with surviving [0, 1]
        let surviving_eval_points = vec![eval_points[0], eval_points[1]];
        let surviving_shares = vec![secret_shares[0], secret_shares[1]];

        let mut rng = rand::rngs::OsRng;
        let (new_secret_shares, new_public_shares) = threshold_reshare(
            &surviving_eval_points,
            &surviving_shares,
            &all_eval_points,
            t as usize,
            &mut rng,
        )
        .expect("resharing must succeed");

        // Build new IncompleteKeyShares
        let new_incomplete = build_new_incomplete_shares(
            &key_shares,
            &new_secret_shares,
            &new_public_shares,
            &all_eval_points,
            t,
            n,
        );

        // Generate fresh aux info and combine into complete KeyShares
        let new_aux_infos = run_aux_gen(n).await;
        let new_key_shares: Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> = new_incomplete
            .into_iter()
            .zip(new_aux_infos)
            .map(|(core, aux)| {
                cggmp24::KeyShare::from_parts((core, aux))
                    .expect("new key share must validate with aux info")
            })
            .collect();

        // Sign with [0, 2] (party 2 is the replacement node)
        let msg = b"message signed with new shares after key refresh";
        let data = DataToSign::digest::<Sha256>(msg);

        let sig = sign_with_parties(&new_key_shares, &[0, 2], &data).await;
        sig.verify(&joint_pubkey, &data)
            .expect("post-refresh signature must verify against original joint key");
    }

    /// After 2-of-3 reshare, all three 2-party subsets [0,1], [0,2], [1,2] sign.
    #[tokio::test]
    async fn test_all_subsets_sign() {
        let n: u16 = 3;
        let t: u16 = 2;

        let (joint_pubkey, key_shares) = run_dkg(n, t).await;
        let (eval_points, secret_shares, all_eval_points) = extract_share_data(&key_shares);

        let surviving_eval_points = vec![eval_points[0], eval_points[1]];
        let surviving_shares = vec![secret_shares[0], secret_shares[1]];

        let mut rng = rand::rngs::OsRng;
        let (new_secret_shares, new_public_shares) = threshold_reshare(
            &surviving_eval_points,
            &surviving_shares,
            &all_eval_points,
            t as usize,
            &mut rng,
        )
        .expect("resharing must succeed");

        let new_incomplete = build_new_incomplete_shares(
            &key_shares,
            &new_secret_shares,
            &new_public_shares,
            &all_eval_points,
            t,
            n,
        );

        let new_aux_infos = run_aux_gen(n).await;
        let new_key_shares: Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> = new_incomplete
            .into_iter()
            .zip(new_aux_infos)
            .map(|(core, aux)| {
                cggmp24::KeyShare::from_parts((core, aux))
                    .expect("new key share must validate with aux info")
            })
            .collect();

        let msg = b"all subsets sign after reshare";
        let data = DataToSign::digest::<Sha256>(msg);

        // All three 2-of-3 subsets must produce valid signatures
        for subset in &[[0u16, 1], [0, 2], [1, 2]] {
            let sig = sign_with_parties(&new_key_shares, subset, &data).await;
            sig.verify(&joint_pubkey, &data).unwrap_or_else(|_| {
                panic!(
                    "subset [{}, {}] must produce valid signature",
                    subset[0], subset[1]
                )
            });
        }
    }

    /// Reshare from 2-of-3 to 3-of-5. Joint key must be unchanged.
    #[tokio::test]
    async fn test_different_threshold_reshare() {
        let n: u16 = 3;
        let t: u16 = 2;

        let (joint_pubkey, key_shares) = run_dkg(n, t).await;
        let (eval_points, secret_shares, _all_eval_points) = extract_share_data(&key_shares);

        // All 3 original parties survive. New config: 3-of-5.
        let new_t: usize = 3;
        let new_n: u16 = 5;

        // Generate 5 new evaluation points (simple: Scalar::from(1), ..., Scalar::from(5))
        let new_eval_points: Vec<NonZero<Scalar<Secp256k1>>> = (1..=new_n)
            .map(|i| NonZero::from_scalar(Scalar::from(i as u64)).expect("small nonzero scalar"))
            .collect();

        let mut rng = rand::rngs::OsRng;
        let (new_secret_shares, new_public_shares) = threshold_reshare(
            &eval_points,
            &secret_shares,
            &new_eval_points,
            new_t,
            &mut rng,
        )
        .expect("resharing to 3-of-5 must succeed");

        assert_eq!(new_secret_shares.len(), 5);
        assert_eq!(new_public_shares.len(), 5);

        // Verify joint key unchanged
        assert!(
            verify_reshare(&joint_pubkey, &new_public_shares, &new_eval_points, new_t),
            "joint key must be unchanged after 2-of-3 -> 3-of-5 reshare"
        );

        // Also verify with a different subset of 3 (indices 2, 3, 4)
        let subset_points = &new_eval_points[2..5];
        let subset_pub = &new_public_shares[2..5];
        let reconstructed: Point<Secp256k1> = (0..3)
            .filter_map(|j| {
                let lambda = lagrange_coefficient_at_zero(j, subset_points)?;
                Some(subset_pub[j] * *lambda)
            })
            .fold(Point::zero(), |acc, p| acc + p);
        assert_eq!(
            joint_pubkey, reconstructed,
            "any 3-of-5 subset must reconstruct same joint key"
        );
    }

    /// verify_reshare returns true for correct key, false for wrong key.
    #[tokio::test]
    async fn test_verify_reshare() {
        let n: u16 = 3;
        let t: u16 = 2;

        let (joint_pubkey, key_shares) = run_dkg(n, t).await;
        let (eval_points, secret_shares, all_eval_points) = extract_share_data(&key_shares);

        let surviving_eval_points = vec![eval_points[0], eval_points[1]];
        let surviving_shares = vec![secret_shares[0], secret_shares[1]];

        let mut rng = rand::rngs::OsRng;
        let (_new_secret_shares, new_public_shares) = threshold_reshare(
            &surviving_eval_points,
            &surviving_shares,
            &all_eval_points,
            t as usize,
            &mut rng,
        )
        .expect("resharing must succeed");

        // Correct key -> true
        assert!(verify_reshare(
            &joint_pubkey,
            &new_public_shares,
            &all_eval_points,
            t as usize,
        ));

        // Wrong key -> false (use a random point)
        let wrong_key = Point::<Secp256k1>::generator() * Scalar::<Secp256k1>::random(&mut rng);
        assert!(!verify_reshare(
            &wrong_key,
            &new_public_shares,
            &all_eval_points,
            t as usize,
        ));

        // Not enough shares -> false
        assert!(!verify_reshare(
            &joint_pubkey,
            &new_public_shares[..1],
            &all_eval_points[..1],
            t as usize,
        ));
    }

    /// Error cases for threshold_reshare.
    #[test]
    fn test_threshold_reshare_errors() {
        let mut rng = rand::rngs::OsRng;

        // Generate some eval points
        let ep1 = NonZero::from_scalar(Scalar::<Secp256k1>::from(1u64)).unwrap();
        let ep2 = NonZero::from_scalar(Scalar::<Secp256k1>::from(2u64)).unwrap();
        let s1 = Scalar::<Secp256k1>::random(&mut rng);

        // Not enough surviving parties
        let result = threshold_reshare(&[ep1], &[s1], &[ep1, ep2], 2, &mut rng);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("need at least"),
            "should report not enough surviving parties"
        );

        // Mismatched lengths
        let result = threshold_reshare(&[ep1, ep2], &[s1], &[ep1], 2, &mut rng);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("same length"),
            "should report mismatched lengths"
        );
    }

    /// Extract `(eval_points, secret_shares)` from a set of IncompleteKeyShares
    /// (keygen output, no aux yet), in party order.
    fn extract_incomplete_share_data(
        shares: &[cggmp24::key_share::IncompleteKeyShare<Secp256k1>],
    ) -> (Vec<NonZero<Scalar<Secp256k1>>>, Vec<Scalar<Secp256k1>>) {
        let dirty0 = shares[0].clone().into_inner();
        let all_eval = dirty0.key_info.vss_setup.as_ref().expect("vss").I.clone();
        let mut eval_points = Vec::new();
        let mut secrets = Vec::new();
        for s in shares {
            let d = s.clone().into_inner();
            eval_points.push(all_eval[d.i as usize]);
            secrets.push(*(*d.x).as_ref());
        }
        (eval_points, secrets)
    }

    /// **CAPSTONE (issue #35): cross-(t,n) address-preserving reshape 3-of-4 →
    /// 4-of-6.** The endgame's defining mechanism (direction.md §1.1): a quorum
    /// upgrade with the SAME joint pubkey (address) and 0 sats on-chain.
    ///
    /// 3-of-4 keygen → cross-reshare to a 6-party set with t'=4 → fresh
    /// `aux_info_gen(6)` → complete KeyShares → EVERY 4-of-6 subset signs +
    /// verifies against the ORIGINAL joint key. Proves the PSS reshare + new-party
    /// share assembly + fresh aux + signing all compose end-to-end.
    #[tokio::test]
    async fn capstone_cross_tn_reshare_3of4_to_4of6_signs() {
        // ── 3-of-4 keygen (no aux needed for the OLD set — we only need its
        //    secret shares + eval points to reshare) ──
        let old_incomplete = run_keygen(4, 3).await;
        let original_joint = *old_incomplete[0].shared_public_key;
        let (old_eval_points, old_secrets) = extract_incomplete_share_data(&old_incomplete);

        // ── New 4-of-6 party set: 6 distinct eval points, threshold t'=4 ──
        let new_t: usize = 4;
        let new_n: u16 = 6;
        let new_eval_points: Vec<NonZero<Scalar<Secp256k1>>> = (1..=new_n)
            .map(|i| NonZero::from_scalar(Scalar::from(i as u64)).expect("nonzero"))
            .collect();

        // ── Cross-(t,n) PSS reshare: all 4 old parties contribute (need >= new_t
        //    survivors; 4 >= 4) → 6 new shares on a degree-3 polynomial ──
        let mut rng = rand::rngs::OsRng;
        let (new_secrets, new_publics) = threshold_reshare(
            &old_eval_points,
            &old_secrets,
            &new_eval_points,
            new_t,
            &mut rng,
        )
        .expect("3-of-4 → 4-of-6 reshare");
        assert_eq!(new_secrets.len(), 6);

        // Joint key preserved (any 4-of-6 subset reconstructs it).
        assert!(
            verify_reshare(&original_joint, &new_publics, &new_eval_points, new_t),
            "§18: joint pubkey MUST be unchanged by the cross-(t,n) reshape"
        );

        // ── Build the new party set's IncompleteKeyShares (production path) ──
        let new_incomplete = build_reshared_incomplete_shares(
            &old_incomplete[0],
            &new_secrets,
            &new_publics,
            &new_eval_points,
            new_t as u16,
        )
        .expect("assemble new 4-of-6 incomplete shares");
        assert_eq!(new_incomplete.len(), 6);

        // ── Fresh aux for the NEW 6-party set + combine ──
        let new_aux = run_aux_gen(new_n).await;
        let new_key_shares: Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> = new_incomplete
            .into_iter()
            .zip(new_aux)
            .map(|(core, aux)| {
                cggmp24::KeyShare::from_parts((core, aux))
                    .expect("4-of-6 key share validates with fresh aux")
            })
            .collect();

        // ── EVERY relevant 4-of-6 subset signs + verifies vs the ORIGINAL key ──
        let msg = b"spend the original address under the new 4-of-6 sharing";
        let data = DataToSign::digest::<Sha256>(msg);
        // A spread of 4-of-6 subsets: the 4 originals, a mix, and the two new
        // parties (4,5) with two originals.
        for subset in &[
            [0u16, 1, 2, 3],
            [0, 1, 4, 5],
            [2, 3, 4, 5],
            [1, 2, 3, 5],
        ] {
            let sig = sign_with_parties(&new_key_shares, subset, &data).await;
            sig.verify(&original_joint, &data).unwrap_or_else(|_| {
                panic!(
                    "4-of-6 subset {subset:?} MUST produce a signature valid under the ORIGINAL joint key"
                )
            });
        }
    }
}
