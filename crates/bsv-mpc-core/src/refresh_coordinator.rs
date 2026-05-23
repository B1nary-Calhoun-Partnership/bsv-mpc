//! Distributed key-refresh **ceremony coordinator** (MPC-Spec §18.2 routine
//! resharing, RR-001).
//!
//! Each party runs one [`RefreshCoordinator`] and drives it through the 2-round
//! Proactive-Secret-Sharing (PSS) reshare with [`init`](RefreshCoordinator::init)
//! followed by [`process_round`](RefreshCoordinator::process_round) until
//! [`RefreshRoundResult::Complete`]. The output is a **rotated** key share for
//! the **same joint public key** — old shares become cryptographically useless
//! against the new sharing polynomial, no funds move, 0 sats on-chain.
//!
//! Mirrors the [`DkgCoordinator`](crate::dkg::DkgCoordinator) /
//! [`SigningCoordinator`](crate::signing::SigningCoordinator) shape so the
//! service handler + proxy coordinator can drive it identically over the
//! canonical MessageBox transport.
//!
//! ## Why this is hand-rolled PSS and not a cggmp24 SM
//!
//! cggmp24 (every pinned revision) exposes only `aux_info_gen` — there is **no**
//! native secret-share-re-randomizing refresh state machine. Re-randomizing a
//! threshold (t-of-n) sharing while preserving the joint public key is the
//! Herzberg et al. PSS construction, built here on
//! [`party_reshare_contribution`](crate::refresh::party_reshare_contribution)
//! (POC 13). This is also the only construction that reaches the address-
//! preserving cross-(t,n) reshape on the product roadmap, so the primitives are
//! kept fully `(t,n)`-general even though v1 wires the same-party-set rotation.
//!
//! ## Protocol (2 rounds)
//!
//! Let the qualified contributor subset be the `new_t` lowest party indices.
//!
//! - **Round 1 (p2p):** each contributor `k` derives a fresh degree-`(new_t-1)`
//!   polynomial `f_k` with `f_k(0) = λ_k·x_k` (its own old secret only) and sends
//!   `f_k(e_j)` privately to every other party `j` (BRC-78-encrypted envelope
//!   §06.3). It keeps `f_k(e_k)` for itself. Non-contributors send nothing.
//! - After round 1 each party `j` sets `x'_j = Σ_k f_k(e_j)` and broadcasts its
//!   new public share `Y'_j = G·x'_j`.
//! - **Round 2 (broadcast):** collect every `Y'_j`. Commit is gated on
//!   [`verify_reshare`](crate::refresh::verify_reshare): the new public shares
//!   MUST Lagrange-reconstruct the *unchanged* joint public key, else the
//!   ceremony aborts (the corruption-detection guard). On success, rebuild the
//!   rotated `KeyShare` keeping the existing aux-info and return it.
//!
//! ## Aux-info
//!
//! Auxiliary info (Paillier / ring-Pedersen params) is **kept** across a routine
//! refresh: it is independent of the secret share `x_i` and the upstream library
//! explicitly blesses reuse. Routine refresh re-randomizes the *sharing
//! polynomial* (§18.2 "fresh polynomial"); rotating aux too is a heavier full-
//! proactive variant, out of scope for v1.

use std::collections::BTreeMap;

use cggmp24::key_share::{KeyShare, Validate};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use generic_ec::{NonZero, Point, Scalar, SecretScalar};

use crate::error::{MpcError, Result};
use crate::refresh::{party_reshare_contribution, verify_reshare};
use crate::types::{EncryptedShare, RoundMessage, SessionId, ShareIndex};

/// Round tags on the wire (`RoundMessage.round`).
const ROUND_CONTRIBUTION: u8 = 1;
const ROUND_PUBSHARE: u8 = 2;

/// The committed result of a successful refresh ceremony.
#[derive(Debug, Clone)]
pub struct RefreshCommit {
    /// The party's **rotated** key share. `ciphertext` is the serialized cggmp24
    /// `KeyShare` JSON (same convention as [`SigningCoordinator`]); all other
    /// metadata (session_id, share_index, config, joint_pubkey) is preserved.
    ///
    /// [`SigningCoordinator`]: crate::signing::SigningCoordinator
    pub rotated_share: EncryptedShare,
    /// The joint public key (33-byte compressed) — UNCHANGED by the refresh.
    /// Surfaced so the caller can assert the invariant + drive §06.18 invalidation.
    pub joint_pubkey_compressed: Vec<u8>,
    /// The new public shares (33-byte compressed each), in party-index order.
    /// Operational / audit visibility; the secret shares never leave a party.
    pub new_public_shares: Vec<Vec<u8>>,
}

/// Result of processing a refresh round.
#[derive(Debug)]
pub enum RefreshRoundResult {
    /// Need another round; contains outgoing messages to send (may be empty).
    NextRound(Vec<RoundMessage>),
    /// The ceremony is complete with the rotated share.
    Complete(Box<RefreshCommit>),
}

/// One party's participation in a distributed §18.2 refresh ceremony.
pub struct RefreshCoordinator {
    session_id: SessionId,
    my_index: u16,

    // ── Decoded from the input share (held only for the ceremony) ─────────
    /// The original complete key share (used to rebuild the rotated one, keeping
    /// aux-info + the unchanged joint pubkey).
    original_key_share: KeyShare<Secp256k1, SecurityLevel128>,
    /// Original share metadata, carried through onto the rotated share.
    original_share_meta: EncryptedShare,
    /// All parties' VSS evaluation points, indexed by party index.
    all_eval_points: Vec<NonZero<Scalar<Secp256k1>>>,
    /// The unchanged joint public key.
    original_joint_pubkey: Point<Secp256k1>,
    /// New threshold (= min_signers; same as old for routine refresh).
    new_t: usize,
    /// Total parties.
    n: usize,
    /// This party's own old secret share.
    my_secret: Scalar<Secp256k1>,

    // ── Protocol state ───────────────────────────────────────────────────
    current_round: u8,
    /// Whether this party is one of the `new_t` contributors.
    am_i_contributor: bool,
    /// This party's own contribution to its OWN new share (`f_me(e_me)`), or 0
    /// if it is not a contributor.
    self_contribution: Scalar<Secp256k1>,
    /// Round-1 evals received from OTHER contributors, keyed by sender index.
    received_evals: BTreeMap<u16, Scalar<Secp256k1>>,
    /// How many round-1 evals to expect (number of OTHER contributors).
    expected_round1: usize,
    /// Set once round 1 finalizes; the broadcast Y'_me has been emitted.
    round1_done: bool,
    /// New public shares collected in round 2 (incl. this party's own), by index.
    received_pubshares: BTreeMap<u16, Point<Secp256k1>>,
    /// This party's rotated secret share, set when round 1 finalizes.
    my_new_share: Option<Scalar<Secp256k1>>,
}

impl RefreshCoordinator {
    /// Build a coordinator for `session_id`.
    ///
    /// * `share` — this party's current key share. `share.ciphertext` MUST be the
    ///   serialized cggmp24 `KeyShare` JSON (the same form
    ///   [`SigningCoordinator::sign_*`] consumes).
    /// * `participants` — the surviving parties participating in the reshare, in
    ///   canonical ascending order. For v1 routine refresh this MUST be the full
    ///   party set `[0, 1, … n-1]` (same-party-set rotation). The `new_t` lowest
    ///   indices act as the qualified contributor subset.
    ///
    /// # Errors
    ///
    /// `MpcError::Protocol` if the share JSON cannot be decoded, lacks VSS setup,
    /// `participants` is not the full party set, or this party is not a participant.
    ///
    /// [`SigningCoordinator::sign_*`]: crate::signing::SigningCoordinator
    pub fn new(
        session_id: SessionId,
        share: EncryptedShare,
        participants: Vec<u16>,
    ) -> Result<Self> {
        let key_share: KeyShare<Secp256k1, SecurityLevel128> =
            serde_json::from_slice(&share.ciphertext).map_err(|e| {
                MpcError::Protocol(format!("refresh: failed to deserialize key share: {e}"))
            })?;

        let core = &key_share.core;
        let my_index = core.i;
        let vss = core.key_info.vss_setup.as_ref().ok_or_else(|| {
            MpcError::Protocol("refresh: key share has no VSS setup (non-threshold key)".into())
        })?;
        let all_eval_points: Vec<NonZero<Scalar<Secp256k1>>> = vss.I.clone();
        let new_t = usize::from(vss.min_signers);
        let n = all_eval_points.len();

        // v1 routine refresh: same party set. Require the full set so party
        // indices line up 1:1 with eval points / public_shares positions.
        let mut expected_set: Vec<u16> = (0..n as u16).collect();
        let mut got = participants.clone();
        got.sort_unstable();
        expected_set.sort_unstable();
        if got != expected_set {
            return Err(MpcError::Protocol(format!(
                "refresh v1 requires the full party set {expected_set:?} (same-(t,n) rotation); \
                 got participants {participants:?}. Cross-(t,n) reshape is a planned extension."
            )));
        }
        if usize::from(my_index) >= n {
            return Err(MpcError::Protocol(format!(
                "refresh: my_index {my_index} out of range for {n} parties"
            )));
        }

        let original_joint_pubkey: Point<Secp256k1> = *core.key_info.shared_public_key;
        let my_secret: Scalar<Secp256k1> =
            *<SecretScalar<Secp256k1> as AsRef<Scalar<Secp256k1>>>::as_ref(&core.x);

        let am_i_contributor = usize::from(my_index) < new_t;
        let expected_round1 = if am_i_contributor { new_t - 1 } else { new_t };

        Ok(Self {
            session_id,
            my_index,
            original_key_share: key_share,
            original_share_meta: share,
            all_eval_points,
            original_joint_pubkey,
            new_t,
            n,
            my_secret,
            current_round: 0,
            am_i_contributor,
            self_contribution: Scalar::zero(),
            received_evals: BTreeMap::new(),
            expected_round1,
            round1_done: false,
            received_pubshares: BTreeMap::new(),
            my_new_share: None,
        })
    }

    /// Begin the ceremony: emit this party's round-1 contribution messages (one
    /// p2p eval per other party for a contributor; empty for a non-contributor).
    pub fn init(&mut self) -> Result<Vec<RoundMessage>> {
        if self.current_round != 0 {
            return Err(MpcError::Protocol(
                "refresh: init() called more than once".into(),
            ));
        }
        self.current_round = ROUND_CONTRIBUTION;

        if !self.am_i_contributor {
            return Ok(vec![]);
        }

        // Contributor: f_me with f_me(0) = λ·my_secret, evaluated at every party.
        let mut rng = rand::rngs::OsRng;
        let evals = party_reshare_contribution(
            usize::from(self.my_index),
            &self.all_eval_points,
            &self.my_secret,
            &self.all_eval_points,
            self.new_t,
            &mut rng,
        )?;

        self.self_contribution = evals[usize::from(self.my_index)];

        let mut out = Vec::with_capacity(self.n - 1);
        for (j, eval) in evals.iter().enumerate() {
            if j as u16 == self.my_index {
                continue;
            }
            out.push(RoundMessage {
                session_id: self.session_id,
                round: ROUND_CONTRIBUTION,
                from: ShareIndex(self.my_index),
                to: Some(ShareIndex(j as u16)),
                payload: scalar_to_bytes(eval),
            });
        }
        Ok(out)
    }

    /// Feed incoming round messages; advance the protocol. Returns the next
    /// outbound batch (possibly empty) or the completed [`RefreshCommit`].
    pub fn process_round(&mut self, incoming: Vec<RoundMessage>) -> Result<RefreshRoundResult> {
        if self.current_round == 0 {
            return Err(MpcError::Protocol(
                "refresh: process_round() before init()".into(),
            ));
        }
        for msg in incoming {
            self.ingest(msg)?;
        }

        let mut outbound = Vec::new();

        // Finalize round 1 once all contributor evals are in (emit Y'_me once).
        if !self.round1_done && self.received_evals.len() >= self.expected_round1 {
            outbound.push(self.finalize_round1());
        }

        // Complete once round 1 is done and every party's public share is in.
        if self.round1_done && self.received_pubshares.len() == self.n {
            let commit = self.finalize()?;
            return Ok(RefreshRoundResult::Complete(Box::new(commit)));
        }

        Ok(RefreshRoundResult::NextRound(outbound))
    }

    /// True once the ceremony has produced the rotated share.
    pub fn is_complete(&self) -> bool {
        self.round1_done && self.received_pubshares.len() == self.n && self.my_new_share.is_some()
    }

    // ── internals ─────────────────────────────────────────────────────────

    fn ingest(&mut self, msg: RoundMessage) -> Result<()> {
        let from = msg.from.0;
        if from == self.my_index {
            return Ok(()); // never count our own echo
        }
        match msg.round {
            ROUND_CONTRIBUTION => {
                // Only the `new_t` lowest indices are contributors.
                if usize::from(from) < self.new_t {
                    let scalar = scalar_from_bytes(&msg.payload)?;
                    self.received_evals.insert(from, scalar);
                }
            }
            ROUND_PUBSHARE => {
                let point = point_from_bytes(&msg.payload)?;
                self.received_pubshares.insert(from, point);
            }
            other => {
                return Err(MpcError::Protocol(format!(
                    "refresh: unexpected round tag {other}"
                )));
            }
        }
        Ok(())
    }

    /// Compute the rotated share `x'_me = self + Σ received`, its public share,
    /// and the broadcast message carrying `Y'_me`.
    fn finalize_round1(&mut self) -> RoundMessage {
        let mut new_share = self.self_contribution;
        for v in self.received_evals.values() {
            new_share += *v;
        }
        let my_pubshare = Point::<Secp256k1>::generator() * new_share;

        self.my_new_share = Some(new_share);
        self.received_pubshares.insert(self.my_index, my_pubshare);
        self.round1_done = true;
        self.current_round = ROUND_PUBSHARE;

        RoundMessage {
            session_id: self.session_id,
            round: ROUND_PUBSHARE,
            from: ShareIndex(self.my_index),
            to: None, // broadcast
            payload: point_to_bytes(&my_pubshare),
        }
    }

    /// Verify the reshare reconstructs the original joint key, then rebuild the
    /// rotated `KeyShare` (new secret + new public shares, SAME aux-info).
    fn finalize(&mut self) -> Result<RefreshCommit> {
        // Ordered public-share vector, party 0..n.
        let mut ordered: Vec<Point<Secp256k1>> = Vec::with_capacity(self.n);
        for i in 0..self.n as u16 {
            let p = self.received_pubshares.get(&i).ok_or_else(|| {
                MpcError::Protocol(format!("refresh: missing public share for party {i}"))
            })?;
            ordered.push(*p);
        }

        // §18.2 / corruption-detection gate: the new public shares MUST
        // Lagrange-reconstruct the UNCHANGED joint public key.
        if !verify_reshare(
            &self.original_joint_pubkey,
            &ordered,
            &self.all_eval_points,
            self.new_t,
        ) {
            return Err(MpcError::Protocol(
                "refresh: reshare verification FAILED — new public shares do not reconstruct the \
                 original joint public key (a party contributed inconsistent material); aborting \
                 without rotating the share"
                    .into(),
            ));
        }

        let mut new_share = self
            .my_new_share
            .ok_or_else(|| MpcError::Protocol("refresh: rotated share not computed".into()))?;

        // Rebuild: keep everything (aux-info, i, shared_public_key, VSS I,
        // min_signers); swap only the secret share + the public-share vector.
        let mut dirty = self.original_key_share.clone().into_inner();
        dirty.core.x = NonZero::from_secret_scalar(SecretScalar::new(&mut new_share))
            .ok_or_else(|| MpcError::Protocol("refresh: rotated secret share is zero".into()))?;
        let nz_pubshares: Vec<NonZero<Point<Secp256k1>>> = ordered
            .iter()
            .map(|p| {
                NonZero::from_point(*p)
                    .ok_or_else(|| MpcError::Protocol("refresh: public share is identity".into()))
            })
            .collect::<Result<_>>()?;
        dirty.core.key_info.public_shares = nz_pubshares;

        let rotated_ks: KeyShare<Secp256k1, SecurityLevel128> = dirty
            .validate()
            .map_err(|e| MpcError::Protocol(format!("refresh: rotated key share invalid: {e}")))?;

        let rotated_json = serde_json::to_vec(&rotated_ks).map_err(|e| {
            MpcError::Protocol(format!("refresh: serialize rotated key share: {e}"))
        })?;

        let joint_pubkey_compressed = self.original_joint_pubkey.to_bytes(true).to_vec();

        // Carry all metadata; swap only the ciphertext (the rotated KeyShare).
        let mut rotated_share = self.original_share_meta.clone();
        rotated_share.ciphertext = rotated_json;
        if rotated_share.joint_pubkey_compressed.is_empty() {
            rotated_share.joint_pubkey_compressed = joint_pubkey_compressed.clone();
        }

        let new_public_shares = ordered.iter().map(|p| p.to_bytes(true).to_vec()).collect();

        Ok(RefreshCommit {
            rotated_share,
            joint_pubkey_compressed,
            new_public_shares,
        })
    }
}

// ── scalar / point wire encoding (32-byte BE scalar, 33-byte compressed point) ──

fn scalar_to_bytes(s: &Scalar<Secp256k1>) -> Vec<u8> {
    s.to_be_bytes().as_bytes().to_vec()
}

fn scalar_from_bytes(b: &[u8]) -> Result<Scalar<Secp256k1>> {
    let arr: [u8; 32] = b
        .try_into()
        .map_err(|_| MpcError::Protocol(format!("refresh: bad scalar length {}", b.len())))?;
    Scalar::<Secp256k1>::from_be_bytes(arr)
        .map_err(|_| MpcError::Protocol("refresh: invalid scalar bytes".into()))
}

fn point_to_bytes(p: &Point<Secp256k1>) -> Vec<u8> {
    p.to_bytes(true).to_vec()
}

fn point_from_bytes(b: &[u8]) -> Result<Point<Secp256k1>> {
    Point::<Secp256k1>::from_bytes(b)
        .map_err(|_| MpcError::Protocol("refresh: invalid compressed point bytes".into()))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ThresholdConfig;

    use std::collections::VecDeque;

    use cggmp24::security_level::SecurityLevel128;
    use cggmp24::signing::DataToSign;
    use cggmp24::ExecutionId;
    use rand::Rng;
    use sha2::Sha256;

    // ---- cggmp24 sim infra (mirrors refresh.rs / signing.rs test infra) ----

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
            (
                incoming,
                BufferedSink {
                    messages: VecDeque::new(),
                    inner: outgoing,
                },
            )
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

    /// Run a full DKG (keygen + aux) → `n` complete cggmp24 KeyShares + joint pk.
    async fn run_dkg(
        n: u16,
        t: u16,
    ) -> (
        Point<Secp256k1>,
        Vec<KeyShare<Secp256k1, SecurityLevel128>>,
    ) {
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
        let joint = *incomplete[0].shared_public_key;

        let eid_aux_bytes: [u8; 32] = rng.gen();
        let eid_aux = ExecutionId::new(&eid_aux_bytes);
        let primes: Vec<_> = (0..n).map(|_| pregenerated_primes(&mut rng)).collect();
        let aux = round_based::sim::run(n, |i, party| {
            let party = buffer_outgoing(party);
            let mut prng = rand::rngs::OsRng;
            let pre = primes[usize::from(i)].clone();
            async move { cggmp24::aux_info_gen(eid_aux, i, n, pre).start(&mut prng, party).await }
        })
        .unwrap()
        .expect_ok()
        .into_vec();

        let shares = incomplete
            .into_iter()
            .zip(aux)
            .map(|(s, a)| cggmp24::KeyShare::from_parts((s, a)).expect("valid key share"))
            .collect();
        (joint, shares)
    }

    /// Sign with a subset and verify against `joint`.
    async fn sign_and_verify(
        shares: &[KeyShare<Secp256k1, SecurityLevel128>],
        participants: &[u16],
        joint: &Point<Secp256k1>,
        msg: &[u8],
    ) {
        let mut rng = rand::rngs::OsRng;
        let eid_bytes: [u8; 32] = rng.gen();
        let eid = ExecutionId::new(&eid_bytes);
        let pv = participants.to_vec();
        let data = DataToSign::<Secp256k1>::digest::<Sha256>(msg);
        let sig = round_based::sim::run_with_setup(
            participants.iter().map(|i| &shares[usize::from(*i)]),
            |i, party, share| {
                let party = buffer_outgoing(party);
                let mut prng = rand::rngs::OsRng;
                let p = pv.clone();
                async move {
                    cggmp24::signing(eid, i, &p, share)
                        .sign(&mut prng, party, &data)
                        .await
                }
            },
        )
        .unwrap()
        .expect_ok()
        .expect_eq();
        sig.verify(joint, &data)
            .expect("post-refresh signature must verify against the ORIGINAL joint key");
    }

    fn key_share_to_encrypted(
        ks: &KeyShare<Secp256k1, SecurityLevel128>,
        t: u16,
        n: u16,
    ) -> EncryptedShare {
        EncryptedShare {
            nonce: Vec::new(),
            ciphertext: serde_json::to_vec(ks).expect("serialize key share"),
            session_id: SessionId::from_str_hash("refresh-coordinator-test"),
            share_index: ShareIndex(ks.core.i),
            config: ThresholdConfig::new(t, n).unwrap(),
            joint_pubkey_compressed: ks.core.key_info.shared_public_key.to_bytes(true).to_vec(),
        }
    }

    fn secret_of(ks: &KeyShare<Secp256k1, SecurityLevel128>) -> Scalar<Secp256k1> {
        *<SecretScalar<Secp256k1> as AsRef<Scalar<Secp256k1>>>::as_ref(&ks.core.x)
    }

    /// Drive `n` coordinators through the full ceremony with an in-memory router.
    /// Returns the per-party commits in party-index order.
    fn run_refresh_ceremony(shares: Vec<EncryptedShare>, n: u16) -> Vec<RefreshCommit> {
        let mut coords: Vec<RefreshCoordinator> = shares
            .into_iter()
            .map(|s| {
                let participants: Vec<u16> = (0..n).collect();
                RefreshCoordinator::new(SessionId::from_str_hash("refresh-cer"), s, participants)
                    .expect("coordinator")
            })
            .collect();

        // (recipient_index, message)
        let mut queue: VecDeque<(u16, RoundMessage)> = VecDeque::new();
        let mut commits: Vec<Option<RefreshCommit>> = (0..n).map(|_| None).collect();

        let enqueue = |queue: &mut VecDeque<(u16, RoundMessage)>, from: u16, msgs: Vec<RoundMessage>| {
            for m in msgs {
                match m.to {
                    Some(ShareIndex(j)) => queue.push_back((j, m)),
                    None => {
                        for j in 0..n {
                            if j != from {
                                queue.push_back((j, m.clone()));
                            }
                        }
                    }
                }
            }
        };

        for i in 0..n {
            let out = coords[usize::from(i)].init().expect("init");
            enqueue(&mut queue, i, out);
        }

        let mut guard = 0;
        while let Some((recipient, msg)) = queue.pop_front() {
            guard += 1;
            assert!(guard < 100_000, "refresh ceremony did not converge");
            let from = msg.from.0;
            match coords[usize::from(recipient)]
                .process_round(vec![msg])
                .expect("process_round")
            {
                RefreshRoundResult::NextRound(out) => {
                    let _ = from;
                    enqueue(&mut queue, recipient, out);
                }
                RefreshRoundResult::Complete(c) => {
                    commits[usize::from(recipient)] = Some(*c);
                }
            }
        }

        commits
            .into_iter()
            .map(|c| c.expect("every party must complete"))
            .collect()
    }

    fn rotated_key_shares(
        commits: &[RefreshCommit],
    ) -> Vec<KeyShare<Secp256k1, SecurityLevel128>> {
        commits
            .iter()
            .map(|c| {
                serde_json::from_slice(&c.rotated_share.ciphertext).expect("rotated key share JSON")
            })
            .collect()
    }

    #[tokio::test]
    async fn refresh_2of2_preserves_joint_key_rotates_and_signs() {
        let (t, n) = (2u16, 2u16);
        let (joint, orig) = run_dkg(n, t).await;
        let old_secrets: Vec<_> = orig.iter().map(secret_of).collect();
        let shares: Vec<_> = orig.iter().map(|k| key_share_to_encrypted(k, t, n)).collect();

        let commits = run_refresh_ceremony(shares, n);

        // Every party reports the SAME joint pubkey, unchanged.
        let jpk = joint.to_bytes(true).to_vec();
        for c in &commits {
            assert_eq!(c.joint_pubkey_compressed, jpk, "joint pubkey must be unchanged");
        }

        let rotated = rotated_key_shares(&commits);

        // Joint key reconstructs from rotated shares (proven via signing below),
        // and every secret share actually rotated.
        for (i, ks) in rotated.iter().enumerate() {
            assert_eq!(*ks.core.key_info.shared_public_key, joint, "shared pubkey unchanged");
            assert_ne!(secret_of(ks), old_secrets[i], "secret share[{i}] must rotate");
        }

        // The rotated shares sign and verify against the ORIGINAL joint key.
        sign_and_verify(&rotated, &[0, 1], &joint, b"sign after 2-of-2 refresh").await;
    }

    #[tokio::test]
    async fn refresh_2of3_same_config_all_subsets_sign() {
        let (t, n) = (2u16, 3u16);
        let (joint, orig) = run_dkg(n, t).await;
        let old_secrets: Vec<_> = orig.iter().map(secret_of).collect();
        let shares: Vec<_> = orig.iter().map(|k| key_share_to_encrypted(k, t, n)).collect();

        let commits = run_refresh_ceremony(shares, n);
        let rotated = rotated_key_shares(&commits);

        for (i, ks) in rotated.iter().enumerate() {
            assert_eq!(*ks.core.key_info.shared_public_key, joint);
            assert_ne!(secret_of(ks), old_secrets[i], "secret share[{i}] must rotate");
        }

        // ALL three 2-of-3 subsets sign with the rotated shares (incl. party 2,
        // the non-contributor whose share is purely received contributions).
        for subset in [[0u16, 1], [0, 2], [1, 2]] {
            sign_and_verify(&rotated, &subset, &joint, b"sign after 2-of-3 refresh").await;
        }
    }

    #[tokio::test]
    async fn refresh_aborts_when_a_pubshare_is_corrupted() {
        // The verify_reshare commit-gate must reject a tampered public share so a
        // corrupted reshare can NEVER rotate the stored key (§18.2 guard).
        let (t, n) = (2u16, 2u16);
        let (_joint, orig) = run_dkg(n, t).await;
        let shares: Vec<_> = orig.iter().map(|k| key_share_to_encrypted(k, t, n)).collect();

        let mut c0 = RefreshCoordinator::new(
            SessionId::from_str_hash("corrupt"),
            shares[0].clone(),
            vec![0, 1],
        )
        .unwrap();
        let mut c1 = RefreshCoordinator::new(
            SessionId::from_str_hash("corrupt"),
            shares[1].clone(),
            vec![0, 1],
        )
        .unwrap();

        // Round 1: exchange contributions honestly.
        let out0 = c0.init().unwrap();
        let out1 = c1.init().unwrap();
        // Deliver party1's eval to party0, party0's eval to party1.
        let r0 = c0.process_round(out1).unwrap(); // c0 finalizes round1 → emits Y'_0
        let _r1 = c1.process_round(out0).unwrap();

        // Take party0's broadcast Y'_0 and CORRUPT it before delivering to party1.
        let mut y0 = match r0 {
            RefreshRoundResult::NextRound(mut v) => v.remove(0),
            RefreshRoundResult::Complete(_) => panic!("c0 should not be complete yet"),
        };
        // Flip the corrupted point to a different valid curve point.
        let bogus = Point::<Secp256k1>::generator() * Scalar::<Secp256k1>::from(424242u64);
        y0.payload = point_to_bytes(&bogus);

        // Party1 now has both pubshares (its own + the corrupted Y'_0) → finalize
        // MUST abort on the verify_reshare gate, NOT rotate.
        let res = c1.process_round(vec![y0]);
        assert!(
            res.is_err(),
            "corrupted public share must abort the reshare (verify_reshare gate)"
        );
        assert!(
            res.unwrap_err().to_string().contains("verification FAILED"),
            "abort must cite the reshare verification gate"
        );
    }

    #[test]
    fn scalar_and_point_wire_roundtrip() {
        let mut rng = rand::rngs::OsRng;
        let s = Scalar::<Secp256k1>::random(&mut rng);
        assert_eq!(scalar_from_bytes(&scalar_to_bytes(&s)).unwrap(), s);
        let p = Point::<Secp256k1>::generator() * s;
        assert_eq!(point_from_bytes(&point_to_bytes(&p)).unwrap(), p);
        assert!(scalar_from_bytes(&[0u8; 31]).is_err(), "bad length rejected");
    }

    #[tokio::test]
    async fn rejects_partial_party_set() {
        // v1 requires the full party set; a strict subset must be rejected loudly.
        let (t, n) = (2u16, 3u16);
        let (_joint, orig) = run_dkg(n, t).await;
        let share0 = key_share_to_encrypted(&orig[0], t, n);
        let err = RefreshCoordinator::new(
            SessionId::from_str_hash("partial"),
            share0,
            vec![0, 1], // missing party 2
        )
        .err()
        .expect("partial party set must be rejected");
        assert!(err.to_string().contains("full party set"));
    }
}
