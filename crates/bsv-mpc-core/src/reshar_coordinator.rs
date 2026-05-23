//! Distributed **cross-(t,n) reshare** ceremony coordinator (MPC-Spec §18.2
//! `reshare_change_threshold`) — the endgame's address-preserving quorum upgrade
//! (e.g. 3-of-4 → 4-of-6, `direction.md` §1.1).
//!
//! The asymmetric sibling of [`RefreshCoordinator`](crate::refresh_coordinator):
//! where refresh re-randomizes the SAME party set keeping aux, this reshares from
//! an OLD set to a DIFFERENT NEW `(t', n')` set, preserving the joint pubkey. A
//! brand-new party joins with no old share and no aux. Because the party indexing
//! changes, the whole new set needs FRESH aux — so each party's PSS output here is
//! an **`IncompleteKeyShare`**; the caller then runs `aux_info_gen(n')` across the
//! new set and `KeyShare::from_parts` to obtain signing-ready shares.
//!
//! ## Protocol (PSS phase, 2 rounds)
//!
//! Contributors are the `new_t` designated survivors (continuing parties holding
//! old shares). Each contributor `k`:
//! - **Round 1 (p2p):** derives `f_k` (degree `new_t-1`, `f_k(0)=λ_k·x_k^old`,
//!   `λ_k` over the contributor subset's OLD eval points) and sends `f_k(e'_j)`
//!   privately to every other NEW party `j`; keeps `f_k(e'_me)`.
//! - After round 1 each NEW party `j` sets `x'_j = Σ_k f_k(e'_j)` and broadcasts
//!   `Y'_j = G·x'_j`.
//! - **Round 2 (broadcast):** collect every `Y'_j`; commit is gated on
//!   [`verify_reshare`](crate::refresh::verify_reshare) (the new public shares MUST
//!   reconstruct the UNCHANGED joint key), then build this party's
//!   `IncompleteKeyShare`.
//!
//! No party ever reveals its old secret: each recipient learns one evaluation of
//! `f_k` (recovering `f_k` needs `new_t`), so an adversary controlling `< new_t`
//! parties cannot recover an honest contributor's old share (the §18.1 property).

use std::collections::BTreeMap;

use cggmp24::supported_curves::Secp256k1;
use generic_ec::{NonZero, Point, Scalar};

use crate::error::{MpcError, Result};
use crate::refresh::{build_reshared_incomplete_share_for, party_reshare_contribution, verify_reshare};
use crate::types::{RoundMessage, SessionId, ShareIndex};

const ROUND_CONTRIBUTION: u8 = 1;
const ROUND_PUBSHARE: u8 = 2;

/// Inputs for a party that contributes old key material to the reshare.
#[derive(Clone)]
pub struct ContributorInputs {
    /// This contributor's position within the contributor subset (for its λ).
    pub my_subset_pos: usize,
    /// The contributor subset's OLD eval points (length `new_t`), ascending by
    /// the subset's canonical order. Used to compute each λ at zero.
    pub subset_eval_points: Vec<NonZero<Scalar<Secp256k1>>>,
    /// This contributor's OLD secret share.
    pub my_old_secret: Scalar<Secp256k1>,
}

/// Construction config for [`ResharCoordinator`].
pub struct ResharConfig {
    pub session_id: SessionId,
    /// This party's index in the NEW party set.
    pub my_new_index: u16,
    /// The NEW set's VSS eval points (party order), length `n'`.
    pub new_eval_points: Vec<NonZero<Scalar<Secp256k1>>>,
    /// The NEW threshold `t'`.
    pub new_t: u16,
    /// The NEW-set indices of the `new_t` contributors (who send round-1 evals).
    pub contributor_new_indices: Vec<u16>,
    /// The UNCHANGED joint public key (33-byte compressed) — the reshare invariant.
    pub original_joint_pubkey: Vec<u8>,
    /// Old-key inputs, present iff this party is a contributor.
    pub contributor: Option<ContributorInputs>,
}

/// The committed PSS output for one new party — an `IncompleteKeyShare` awaiting
/// fresh aux.
#[derive(Debug, Clone)]
pub struct ResharCommit {
    /// Serialized cggmp24 `IncompleteKeyShare` (rotated secret + new public shares
    /// + new VSS), bound to the unchanged joint pubkey. Needs `aux_info_gen(n')`.
    pub incomplete_share_json: Vec<u8>,
    /// The joint pubkey (33-byte compressed) — UNCHANGED.
    pub joint_pubkey_compressed: Vec<u8>,
    /// New public shares (33-byte compressed each), party order.
    pub new_public_shares: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub enum ResharRoundResult {
    NextRound(Vec<RoundMessage>),
    Complete(Box<ResharCommit>),
}

/// One party's participation in a distributed cross-(t,n) reshare.
pub struct ResharCoordinator {
    session_id: SessionId,
    my_new_index: u16,
    new_eval_points: Vec<NonZero<Scalar<Secp256k1>>>,
    new_t: u16,
    n_new: usize,
    contributor_new_indices: Vec<u16>,
    original_joint_pubkey: Point<Secp256k1>,
    original_joint_pubkey_bytes: Vec<u8>,
    contributor: Option<ContributorInputs>,

    current_round: u8,
    self_contribution: Scalar<Secp256k1>,
    received_evals: BTreeMap<u16, Scalar<Secp256k1>>,
    expected_round1: usize,
    round1_done: bool,
    received_pubshares: BTreeMap<u16, Point<Secp256k1>>,
    my_new_share: Option<Scalar<Secp256k1>>,
}

impl ResharCoordinator {
    pub fn new(config: ResharConfig) -> Result<Self> {
        let n_new = config.new_eval_points.len();
        if usize::from(config.my_new_index) >= n_new {
            return Err(MpcError::Protocol(format!(
                "my_new_index {} out of range for {n_new} new parties",
                config.my_new_index
            )));
        }
        if config.contributor_new_indices.len() != usize::from(config.new_t) {
            return Err(MpcError::Protocol(format!(
                "contributor set size {} must equal new_t {}",
                config.contributor_new_indices.len(),
                config.new_t
            )));
        }
        let original_joint_pubkey = Point::<Secp256k1>::from_bytes(&config.original_joint_pubkey)
            .map_err(|_| MpcError::Protocol("reshar: invalid joint pubkey bytes".into()))?;
        let am_i_contributor = config.contributor_new_indices.contains(&config.my_new_index);
        if am_i_contributor != config.contributor.is_some() {
            return Err(MpcError::Protocol(
                "reshar: contributor inputs must be present iff my_new_index is a contributor".into(),
            ));
        }
        // Round-1 evals expected from OTHER contributors.
        let expected_round1 = config.contributor_new_indices.len() - usize::from(am_i_contributor);

        Ok(Self {
            session_id: config.session_id,
            my_new_index: config.my_new_index,
            new_eval_points: config.new_eval_points,
            new_t: config.new_t,
            n_new,
            contributor_new_indices: config.contributor_new_indices,
            original_joint_pubkey,
            original_joint_pubkey_bytes: config.original_joint_pubkey,
            contributor: config.contributor,
            current_round: 0,
            self_contribution: Scalar::zero(),
            received_evals: BTreeMap::new(),
            expected_round1,
            round1_done: false,
            received_pubshares: BTreeMap::new(),
            my_new_share: None,
        })
    }

    /// Emit this party's round-1 contributions (empty for a non-contributor).
    pub fn init(&mut self) -> Result<Vec<RoundMessage>> {
        if self.current_round != 0 {
            return Err(MpcError::Protocol("reshar: init() called twice".into()));
        }
        self.current_round = ROUND_CONTRIBUTION;

        let Some(c) = self.contributor.clone() else {
            return Ok(vec![]);
        };
        let mut rng = rand::rngs::OsRng;
        let evals = party_reshare_contribution(
            c.my_subset_pos,
            &c.subset_eval_points,
            &c.my_old_secret,
            &self.new_eval_points,
            usize::from(self.new_t),
            &mut rng,
        )?;
        self.self_contribution = evals[usize::from(self.my_new_index)];

        let mut out = Vec::with_capacity(self.n_new - 1);
        for (j, eval) in evals.iter().enumerate() {
            if j as u16 == self.my_new_index {
                continue;
            }
            out.push(RoundMessage {
                session_id: self.session_id,
                round: ROUND_CONTRIBUTION,
                from: ShareIndex(self.my_new_index),
                to: Some(ShareIndex(j as u16)),
                payload: scalar_to_bytes(eval),
            });
        }
        Ok(out)
    }

    pub fn process_round(&mut self, incoming: Vec<RoundMessage>) -> Result<ResharRoundResult> {
        if self.current_round == 0 {
            return Err(MpcError::Protocol("reshar: process_round before init".into()));
        }
        for msg in incoming {
            self.ingest(msg)?;
        }

        let mut outbound = Vec::new();
        if !self.round1_done && self.received_evals.len() >= self.expected_round1 {
            outbound.push(self.finalize_round1());
        }
        if self.round1_done && self.received_pubshares.len() == self.n_new {
            return Ok(ResharRoundResult::Complete(Box::new(self.finalize()?)));
        }
        Ok(ResharRoundResult::NextRound(outbound))
    }

    fn ingest(&mut self, msg: RoundMessage) -> Result<()> {
        let from = msg.from.0;
        if from == self.my_new_index {
            return Ok(());
        }
        match msg.round {
            ROUND_CONTRIBUTION => {
                if self.contributor_new_indices.contains(&from) {
                    self.received_evals.insert(from, scalar_from_bytes(&msg.payload)?);
                }
            }
            ROUND_PUBSHARE => {
                self.received_pubshares
                    .insert(from, point_from_bytes(&msg.payload)?);
            }
            other => return Err(MpcError::Protocol(format!("reshar: bad round tag {other}"))),
        }
        Ok(())
    }

    fn finalize_round1(&mut self) -> RoundMessage {
        let mut new_share = self.self_contribution;
        for v in self.received_evals.values() {
            new_share += *v;
        }
        let my_pub = Point::<Secp256k1>::generator() * new_share;
        self.my_new_share = Some(new_share);
        self.received_pubshares.insert(self.my_new_index, my_pub);
        self.round1_done = true;
        self.current_round = ROUND_PUBSHARE;
        RoundMessage {
            session_id: self.session_id,
            round: ROUND_PUBSHARE,
            from: ShareIndex(self.my_new_index),
            to: None,
            payload: point_to_bytes(&my_pub),
        }
    }

    fn finalize(&mut self) -> Result<ResharCommit> {
        let mut ordered = Vec::with_capacity(self.n_new);
        for i in 0..self.n_new as u16 {
            let p = self
                .received_pubshares
                .get(&i)
                .ok_or_else(|| MpcError::Protocol(format!("reshar: missing pubshare {i}")))?;
            ordered.push(*p);
        }
        if !verify_reshare(
            &self.original_joint_pubkey,
            &ordered,
            &self.new_eval_points,
            usize::from(self.new_t),
        ) {
            return Err(MpcError::Protocol(
                "reshar: reshare verification FAILED — new public shares do not reconstruct the \
                 original joint pubkey; aborting without producing a share"
                    .into(),
            ));
        }
        let new_share = self
            .my_new_share
            .ok_or_else(|| MpcError::Protocol("reshar: new share not computed".into()))?;
        let shared_pub = NonZero::from_point(self.original_joint_pubkey)
            .ok_or_else(|| MpcError::Protocol("reshar: joint pubkey is identity".into()))?;
        let incomplete = build_reshared_incomplete_share_for(
            self.my_new_index,
            shared_pub,
            new_share,
            &ordered,
            &self.new_eval_points,
            self.new_t,
        )?;
        let incomplete_share_json = serde_json::to_vec(&incomplete)
            .map_err(|e| MpcError::Protocol(format!("reshar: serialize incomplete share: {e}")))?;
        Ok(ResharCommit {
            incomplete_share_json,
            joint_pubkey_compressed: self.original_joint_pubkey_bytes.clone(),
            new_public_shares: ordered.iter().map(|p| p.to_bytes(true).to_vec()).collect(),
        })
    }
}

fn scalar_to_bytes(s: &Scalar<Secp256k1>) -> Vec<u8> {
    s.to_be_bytes().as_bytes().to_vec()
}
fn scalar_from_bytes(b: &[u8]) -> Result<Scalar<Secp256k1>> {
    let arr: [u8; 32] = b
        .try_into()
        .map_err(|_| MpcError::Protocol(format!("reshar: bad scalar length {}", b.len())))?;
    Scalar::<Secp256k1>::from_be_bytes(arr)
        .map_err(|_| MpcError::Protocol("reshar: invalid scalar".into()))
}
fn point_to_bytes(p: &Point<Secp256k1>) -> Vec<u8> {
    p.to_bytes(true).to_vec()
}
fn point_from_bytes(b: &[u8]) -> Result<Point<Secp256k1>> {
    Point::<Secp256k1>::from_bytes(b)
        .map_err(|_| MpcError::Protocol("reshar: invalid point".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    use cggmp24::security_level::SecurityLevel128;
    use cggmp24::signing::DataToSign;
    use cggmp24::ExecutionId;
    use generic_ec::SecretScalar;
    use rand::Rng;
    use sha2::Sha256;

    // ── cggmp24 sim infra (mirror of refresh.rs) ──
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
        fn poll_ready(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::result::Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn start_send(self: std::pin::Pin<&mut Self>, item: M) -> std::result::Result<(), Self::Error> {
            self.project().messages.get_mut().push_back(item);
            Ok(())
        }
        fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::result::Result<(), Self::Error>> {
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
        fn poll_close(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::result::Result<(), Self::Error>> {
            self.project().inner.poll_close(cx)
        }
    }
    fn buffer_outgoing<M, D, R>(party: round_based::MpcParty<M, D, R>) -> round_based::MpcParty<M, BufferedDelivery<M, D>, R>
    where M: Unpin, D: round_based::Delivery<M>, R: round_based::runtime::AsyncRuntime {
        party.map_delivery(|d| {
            let (incoming, outgoing) = d.split();
            (incoming, BufferedSink { messages: VecDeque::new(), inner: outgoing })
        })
    }
    fn blum(rng: &mut impl rand::RngCore, bits: u32) -> cggmp24::backend::Integer {
        use cggmp24::backend::Integer;
        loop {
            let n = Integer::generate_prime(rng, bits);
            if n.mod_u(4) == 3 { break n; }
        }
    }
    fn primes(rng: &mut impl rand::RngCore) -> cggmp24::key_refresh::PregeneratedPrimes<SecurityLevel128> {
        use cggmp24::security_level::SecurityLevel;
        let b = SecurityLevel128::RSA_PRIME_BITLEN;
        cggmp24::key_refresh::PregeneratedPrimes::try_from([blum(rng,b),blum(rng,b),blum(rng,b),blum(rng,b)]).expect("primes")
    }
    async fn keygen(n: u16, t: u16) -> Vec<cggmp24::key_share::IncompleteKeyShare<Secp256k1>> {
        let mut rng = rand::rngs::OsRng;
        let eid_bytes: [u8;32] = rng.gen();
        let eid = ExecutionId::new(&eid_bytes);
        round_based::sim::run(n, |i, party| {
            let party = buffer_outgoing(party);
            let mut r = rand::rngs::OsRng;
            async move { cggmp24::keygen::<Secp256k1>(eid, i, n).set_threshold(t).start(&mut r, party).await }
        }).unwrap().expect_ok().into_vec()
    }
    async fn aux_gen(n: u16) -> Vec<cggmp24::key_share::AuxInfo<SecurityLevel128>> {
        let mut rng = rand::rngs::OsRng;
        let eid_bytes: [u8;32] = rng.gen();
        let eid = ExecutionId::new(&eid_bytes);
        let pr: Vec<_> = (0..n).map(|_| primes(&mut rng)).collect();
        round_based::sim::run(n, |i, party| {
            let party = buffer_outgoing(party);
            let mut r = rand::rngs::OsRng;
            let pre = pr[usize::from(i)].clone();
            async move { cggmp24::aux_info_gen(eid, i, n, pre).start(&mut r, party).await }
        }).unwrap().expect_ok().into_vec()
    }
    async fn sign_verify(shares: &[cggmp24::KeyShare<Secp256k1, SecurityLevel128>], parts: &[u16], joint: &Point<Secp256k1>, msg: &[u8]) {
        let mut rng = rand::rngs::OsRng;
        let eid_bytes: [u8;32] = rng.gen();
        let eid = ExecutionId::new(&eid_bytes);
        let pv = parts.to_vec();
        let data = DataToSign::<Secp256k1>::digest::<Sha256>(msg);
        let sig = round_based::sim::run_with_setup(parts.iter().map(|i| &shares[usize::from(*i)]), |i, party, share| {
            let party = buffer_outgoing(party);
            let mut r = rand::rngs::OsRng;
            let p = pv.clone();
            async move { cggmp24::signing(eid, i, &p, share).sign(&mut r, party, &data).await }
        }).unwrap().expect_ok().expect_eq();
        sig.verify(joint, &data).expect("post-reshare sig must verify vs ORIGINAL joint key");
    }

    /// **#35b — DISTRIBUTED cross-(t,n) reshare 3-of-4 → 4-of-6.** Drives 6
    /// `ResharCoordinator`s through the PSS rounds via an in-process router (no
    /// party holds another's old secret — only `party_reshare_contribution`
    /// evaluations cross the wire), then fresh `aux_info_gen(6)` + sign. Proves the
    /// distributed wire ceremony produces a working new sharing of the SAME key.
    #[tokio::test]
    async fn distributed_reshare_3of4_to_4of6_signs() {
        // OLD 3-of-4 keygen → eval points + secrets.
        let old = keygen(4, 3).await;
        let original_joint = *old[0].shared_public_key;
        let jpk_bytes = original_joint.to_bytes(true).to_vec();
        let old_dirty0 = old[0].clone().into_inner();
        let old_eval: Vec<NonZero<Scalar<Secp256k1>>> =
            old_dirty0.key_info.vss_setup.as_ref().unwrap().I.clone();
        let old_secrets: Vec<Scalar<Secp256k1>> = old
            .iter()
            .map(|s| {
                let d = s.clone().into_inner();
                let ep = old_eval[d.i as usize];
                let _ = ep;
                *<SecretScalar<Secp256k1> as AsRef<Scalar<Secp256k1>>>::as_ref(&d.x)
            })
            .collect();

        // NEW 4-of-6: 6 fresh eval points, contributors = the 4 continuing parties.
        let new_t: u16 = 4;
        let n_new: u16 = 6;
        let new_eval: Vec<NonZero<Scalar<Secp256k1>>> =
            (1..=n_new).map(|i| NonZero::from_scalar(Scalar::from(i as u64)).unwrap()).collect();
        let contributor_new_indices: Vec<u16> = (0..new_t).collect(); // parties 0..3 continue + contribute
        // Contributor subset's OLD eval points (for λ): the 4 old parties' eval points.
        let subset_old_eval: Vec<NonZero<Scalar<Secp256k1>>> = (0..new_t)
            .map(|k| old_eval[k as usize])
            .collect();

        // Build 6 coordinators.
        let mut coords: Vec<ResharCoordinator> = (0..n_new)
            .map(|j| {
                let contributor = if (j as usize) < usize::from(new_t) {
                    Some(ContributorInputs {
                        my_subset_pos: j as usize,
                        subset_eval_points: subset_old_eval.clone(),
                        my_old_secret: old_secrets[j as usize],
                    })
                } else {
                    None
                };
                ResharCoordinator::new(ResharConfig {
                    session_id: SessionId::from_str_hash("reshar-test"),
                    my_new_index: j,
                    new_eval_points: new_eval.clone(),
                    new_t,
                    contributor_new_indices: contributor_new_indices.clone(),
                    original_joint_pubkey: jpk_bytes.clone(),
                    contributor,
                })
                .expect("coordinator")
            })
            .collect();

        // Router (mirror refresh_coordinator::run_refresh_ceremony).
        let mut queue: VecDeque<(u16, RoundMessage)> = VecDeque::new();
        let mut commits: Vec<Option<ResharCommit>> = (0..n_new).map(|_| None).collect();
        let enqueue = |q: &mut VecDeque<(u16, RoundMessage)>, from: u16, msgs: Vec<RoundMessage>| {
            for m in msgs {
                match m.to {
                    Some(ShareIndex(j)) => q.push_back((j, m)),
                    None => for j in 0..n_new { if j != from { q.push_back((j, m.clone())); } },
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
            assert!(guard < 1_000_000, "ceremony did not converge");
            match coords[rcpt as usize].process_round(vec![msg]).unwrap() {
                ResharRoundResult::NextRound(out) => enqueue(&mut queue, rcpt, out),
                ResharRoundResult::Complete(c) => commits[rcpt as usize] = Some(*c),
            }
        }
        let commits: Vec<ResharCommit> = commits.into_iter().map(|c| c.expect("all complete")).collect();

        // Every party reports the unchanged joint pubkey.
        for c in &commits {
            assert_eq!(c.joint_pubkey_compressed, jpk_bytes, "joint pubkey unchanged");
        }

        // Reassemble IncompleteKeyShares → fresh aux(6) → KeyShares → sign.
        let incompletes: Vec<cggmp24::key_share::IncompleteKeyShare<Secp256k1>> = commits
            .iter()
            .map(|c| serde_json::from_slice(&c.incomplete_share_json).expect("incomplete share"))
            .collect();
        let aux = aux_gen(n_new).await;
        let key_shares: Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> = incompletes
            .into_iter()
            .zip(aux)
            .map(|(core, a)| cggmp24::KeyShare::from_parts((core, a)).expect("4-of-6 key share"))
            .collect();

        let msg = b"distributed reshare 3-of-4 -> 4-of-6, spend original address";
        for subset in &[[0u16, 1, 2, 3], [0, 1, 4, 5], [2, 3, 4, 5]] {
            sign_verify(&key_shares, subset, &original_joint, msg).await;
        }
    }
}
