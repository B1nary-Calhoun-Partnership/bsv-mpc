//! Background presignature stockpiling for low-latency online signing.
//!
//! Presignatures are the key optimization in CGGMP'24. By running the expensive
//! nonce generation and proof exchange *before* the message to sign is known,
//! the actual online signing phase reduces to a single round of communication.
//!
//! ## Presigning Protocol (3 rounds)
//!
//! The offline presigning protocol generates a presignature `(k, R)` where:
//! - `k` is a secret nonce shared across the signing group (no party knows the full `k`)
//! - `R = k * G` is the corresponding public nonce point
//!
//! The 3 rounds are:
//!
//! 1. **Round 1**: Each party generates a random nonce share `k_i` and a
//!    random masking value `gamma_i`. Broadcasts commitments to both.
//!
//! 2. **Round 2**: Decommit values. Each pair of parties runs a multiplicative-
//!    to-additive (MtA) sub-protocol to convert their multiplicative shares
//!    `k_i * gamma_j` into additive shares. This is the most computationally
//!    expensive step (Paillier-based MtA).
//!
//! 3. **Round 3**: Each party broadcasts `delta_i = k_i * gamma_i + sum(MtA shares)`.
//!    The joint `delta = sum(delta_i)` allows computing `R = delta^-1 * Gamma`
//!    where `Gamma = sum(gamma_i * G)`.
//!
//! ## Stockpiling Strategy
//!
//! The `PresigningManager` maintains a pool of ready-to-use presignatures.
//! When the pool drops below half capacity, new presignatures should be
//! generated in the background. This ensures signing requests are never
//! blocked waiting for the 3-round offline phase.
//!
//! ## Architecture (Phase G inline)
//!
//! Like `DkgCoordinator` and `SigningCoordinator`, the presigning manager
//! hosts its `round_based::StateMachine` directly on the struct (Phase G).
//! The SM is `!Send` (`Rc<RefCell<_>>` internally) but that's fine inline —
//! we drive it via the shared [`crate::dkg::drive_inline`] kernel without
//! any thread or mpsc bridge.
//!
//! ## Usage
//!
//! ```ignore
//! let mut mgr = PresigningManager::new(session_id, share, participants, 10);
//!
//! // Start presignature generation
//! let msgs = mgr.init_generate()?;
//! transport.broadcast(msgs).await;
//!
//! loop {
//!     let incoming = transport.receive_round().await;
//!     match mgr.process_generate_round(incoming)? {
//!         PresigningRoundResult::NextRound(msgs) => transport.send_all(msgs).await,
//!         PresigningRoundResult::Complete(_) => break, // presig added to pool
//!     }
//! }
//!
//! // Consume for signing
//! if let Some(presig) = mgr.take() {
//!     coordinator.sign(&sighash, Some(presig))?;
//! }
//! ```

use std::collections::VecDeque;

use cggmp24::security_level::SecurityLevel128;
use cggmp24::signing::PresignaturePublicData;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use round_based::state_machine::StateMachine;
use sha2::{Digest, Sha256};

use crate::dkg::{drive_inline, DriveStep, WireMessage};
use crate::error::{MpcError, Result};
use crate::types::{EncryptedShare, Presignature, RoundMessage, SessionId};

// ---------------------------------------------------------------------------
// Inline-SM type alias (Phase G)
// ---------------------------------------------------------------------------

/// Output type of the presigning SM: a `(Presignature, PresignaturePublicData)`
/// tuple on success, `SigningError` on failure. The output is type-erased
/// into `Box<dyn Any + Send>` when stored in the manager's `raw_pool`
/// because `PresignaturePublicData` doesn't implement `Serialize`.
pub(crate) type PresignOutput = (
    cggmp24::Presignature<Secp256k1>,
    PresignaturePublicData<Secp256k1>,
);

/// Boxed `StateMachine` for the presigning sub-protocol. Shares the wire
/// `Msg` type with the signing coordinator (both come from the same
/// cggmp24 SigningBuilder), but the Output differs (presignature tuple
/// vs final Signature).
type PresigningSm = Box<
    dyn StateMachine<
        Output = std::result::Result<PresignOutput, cggmp24::SigningError>,
        Msg = cggmp24::signing::msg::Msg<Secp256k1, Sha256>,
    >,
>;

// ---------------------------------------------------------------------------
// PresigningRoundResult
// ---------------------------------------------------------------------------

/// Result of processing a presigning round.
#[derive(Debug)]
pub enum PresigningRoundResult {
    /// The protocol needs another round. Contains outgoing messages to send.
    NextRound(Vec<RoundMessage>),
    /// Presigning is complete (the presignature was added to the pool). Carries the
    /// FINAL-round outgoing messages produced in the SAME drive as completion — they
    /// MUST still be sent to peers. Under reordered delivery a party can receive every
    /// peer's last-round message before it emits its own, so its final send and its
    /// completion coincide in one drive; dropping those messages stalls every peer
    /// that still needs this party's final round (the #98 n-party presign deadlock).
    Complete(Vec<RoundMessage>),
}

// ---------------------------------------------------------------------------
// Presigning generation state
// ---------------------------------------------------------------------------

/// Tracks the state of an in-progress presigning generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GenerateState {
    /// No generation in progress.
    Idle,
    /// Generation is running (SM active).
    Running,
}

// ---------------------------------------------------------------------------
// PresigningManager
// ---------------------------------------------------------------------------

/// Manages a pool of presignatures for a single MPC session.
///
/// The manager tracks available presignatures and provides methods to generate
/// new ones and consume them for signing. Presignatures are consumed in FIFO
/// order (oldest first).
///
/// # Generation (Phase G inline)
///
/// 1. Call [`init_generate`](Self::init_generate) to construct the
///    cggmp24 presigning SM and drive it through round 1.
/// 2. Call [`process_generate_round`](Self::process_generate_round) with
///    incoming messages until it returns `Complete`.
/// 3. The presignature is automatically added to the pool on completion.
pub struct PresigningManager {
    /// Pool of ready-to-use presignatures (FIFO order).
    /// The `Presignature` wrapper stores metadata; the actual cggmp24 presignature
    /// objects are stored in `raw_pool` at the corresponding index.
    pool: Vec<Presignature>,
    /// Type-erased cggmp24 presignature objects corresponding to each entry in `pool`.
    /// Each entry is a `Box<(cggmp24::Presignature<E>, PresignaturePublicData<E>)>`.
    /// These can't be serialized because `PresignaturePublicData` doesn't impl `Serialize`.
    raw_pool: Vec<Box<dyn std::any::Any + Send>>,
    /// Maximum number of presignatures to maintain in the pool.
    max_pool_size: usize,
    /// The MPC session these presignatures belong to.
    session_id: SessionId,
    /// This party's encrypted key share (needed for presigning).
    share: EncryptedShare,
    /// Participants in the signing group (party indices from DKG).
    participants: Vec<u16>,
    /// Counter for generating unique execution IDs per presigning invocation.
    eid_counter: u64,
    /// Current round during generation.
    current_round: u8,
    /// Current generation state.
    generate_state: GenerateState,

    /// The active presigning state machine (Phase G inline architecture).
    /// `None` when no generation is in progress.
    presigning_sm: Option<PresigningSm>,
    /// Incoming wire messages buffered across `process_generate_round`
    /// calls.
    wire_buffer: VecDeque<WireMessage>,
    /// Monotonic message id for `round_based::Incoming<M>::id`.
    next_msg_id: u64,
}

// SAFETY: `PresigningManager` is structurally `!Send` because the
// cggmp24 state machine it holds (`Box<dyn StateMachine<...>>`) carries
// `Rc<RefCell<_>>` internal state. The `Rc` is `!Send` only because
// reference counting is non-atomic; the manager is otherwise safe to
// move between threads provided no two threads access it at once.
// Callers in `bsv-mpc-{service,proxy,worker}` serialize access via a
// `Mutex` (or by moving into a single `spawn_blocking` closure), so the
// invariant is upheld. See the same comment on `dkg::DkgCoordinator`.
unsafe impl Send for PresigningManager {}

impl PresigningManager {
    /// Create a new presigning manager with an empty pool.
    ///
    /// # Arguments
    ///
    /// * `session_id` — The MPC session to generate presignatures for.
    /// * `share` — This party's encrypted key share.
    /// * `participants` — Party indices participating in the signing group.
    /// * `max_pool_size` — Maximum number of presignatures to stockpile.
    pub fn new(
        session_id: SessionId,
        share: EncryptedShare,
        participants: Vec<u16>,
        max_pool_size: usize,
    ) -> Self {
        Self {
            pool: Vec::with_capacity(max_pool_size),
            raw_pool: Vec::with_capacity(max_pool_size),
            max_pool_size,
            session_id,
            share,
            participants,
            eid_counter: 0,
            current_round: 0,
            generate_state: GenerateState::Idle,
            presigning_sm: None,
            wire_buffer: VecDeque::new(),
            next_msg_id: 0,
        }
    }

    /// Start a new presignature generation (3-round protocol).
    ///
    /// Constructs the cggmp24 presigning `StateMachine` inline on this
    /// manager and drives it through round 1, returning the collected
    /// outgoing messages.
    ///
    /// Only one generation can be in progress at a time.
    ///
    /// # Errors
    ///
    /// Returns [`MpcError::Protocol`] if a generation is already in progress,
    /// the pool is full, or the SM fails to construct.
    pub fn init_generate(&mut self) -> Result<Vec<RoundMessage>> {
        if self.generate_state != GenerateState::Idle {
            return Err(MpcError::Protocol(
                "presigning generation already in progress".into(),
            ));
        }

        if self.pool.len() >= self.max_pool_size {
            return Err(MpcError::Protocol(
                "presignature pool is already full".into(),
            ));
        }

        let my_signing_index = self.signing_index()?;

        // Canonical ExecutionId per MPC-Spec §02.2 with phase=Presign and
        // the joint pubkey from the share. The eid_counter is mixed in so
        // multiple presig generations within the same session produce
        // distinct EIDs (CGGMP'24 forbids EID reuse).
        self.eid_counter += 1;
        let canonical_eid =
            crate::canonical::canonical_execution_id(&crate::canonical::ExecutionParams::new_v1(
                crate::canonical::PhaseTag::Presign,
                self.session_id,
                crate::signing::share_joint_pubkey_or_zero(&self.share, "presigning"),
            ));
        let eid_bytes = {
            let mut hasher = Sha256::new();
            hasher.update(canonical_eid);
            hasher.update(self.eid_counter.to_be_bytes());
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&hasher.finalize());
            bytes
        };

        // Decode KeyShare up front so caller-side errors surface as
        // MpcError::Protocol. KeyShare derives Clone — move an owned
        // copy into the closure so the resulting SM is 'static and can
        // be Boxed as a struct field.
        let key_share: cggmp24::KeyShare<Secp256k1, SecurityLevel128> =
            serde_json::from_slice(&self.share.ciphertext)
                .map_err(|e| MpcError::Protocol(format!("failed to deserialize key share: {e}")))?;
        let participants_owned = self.participants.clone();

        // Presign-topology diagnostic (`presign_index_diverge` target). Surfaces
        // the cggmp24 KeyShare's INTERNAL party index `i`, its VSS eval-point set
        // `I`, the `public_shares` length, the computed signing position, and the
        // participants subset `S` — exactly the values `cggmp24::signing(eid, i,
        // S, key_share)` reconciles via `utils::subset(S, …)`. A non-contiguous
        // subset (e.g. {0,2}) is correct iff `I`/`public_shares` are full-length-n
        // and absolutely indexed; a reshared share is verified to carry the SAME
        // topology as a fresh-DKG share here (see
        // `presign_noncontiguous_02_reshared_realrelay_e2e`). Emitted at trace so
        // it is silent by default; enable with `RUST_LOG=presign_index_diverge=trace`.
        if tracing::enabled!(target: "presign_index_diverge", tracing::Level::TRACE) {
            let dirty = &key_share.core;
            let vss = dirty.key_info.vss_setup.as_ref();
            let vss_i_hex: Vec<String> = vss
                .map(|v| {
                    v.I.iter()
                        .map(|p| hex::encode(p.as_ref().to_be_bytes()))
                        .collect()
                })
                .unwrap_or_default();
            tracing::trace!(
                target: "presign_index_diverge",
                share_index = self.share.share_index.0,
                keyshare_internal_i = dirty.i,
                signing_index = my_signing_index,
                participants = ?participants_owned,
                vss_min_signers = vss.map(|v| v.min_signers).unwrap_or(0),
                vss_i_len = vss.map(|v| v.I.len()).unwrap_or(0),
                public_shares_len = dirty.key_info.public_shares.len(),
                vss_I = ?vss_i_hex,
                "presign init_generate: cggmp24 KeyShare index topology"
            );
        }

        // #98 context-mismatch localizer: fingerprint the SHARED inputs the round1b
        // `pi_enc_elg` proof binds — the ExecutionId (`sid`), the joint pubkey, and a
        // digest of the GLOBAL aux-info (`aux.N` + `pedersen_params`). EVERY party of
        // one ceremony MUST produce the identical fingerprint; a divergence under an
        // `EncProofOfK` abort pinpoints the failure to a sid/joint-key/aux mismatch
        // (a stale persisted wallet vs the cosigner's recovered share) rather than the
        // protocol code. No-op unless armed; native-only (`presig_timing` uses
        // `Instant`, and presign generation never runs on the wasm worker).
        #[cfg(not(target_arch = "wasm32"))]
        {
            let eid6 = hex::encode(&eid_bytes[..6]);
            let jpk = crate::signing::share_joint_pubkey_or_zero(&self.share, "presigning");
            let jpk6 = hex::encode(&jpk[..6]);
            let aux6 = {
                let mut h = Sha256::new();
                if let Ok(b) = serde_json::to_vec(&key_share.aux.N) {
                    h.update(&b);
                }
                if let Ok(b) = serde_json::to_vec(&key_share.aux.pedersen_params) {
                    h.update(&b);
                }
                hex::encode(&h.finalize()[..6])
            };
            crate::presig_timing::record_context(format!("eid={eid6} jpk={jpk6} aux={aux6}"));
        }

        let sm: PresigningSm = Box::new(round_based::state_machine::wrap_protocol(
            move |party| async move {
                let eid = ExecutionId::new(&eid_bytes);
                cggmp24::signing(eid, my_signing_index, &participants_owned, &key_share)
                    .generate_presignature(&mut rand::rngs::OsRng, party)
                    .await
            },
        ));
        self.presigning_sm = Some(sm);

        self.generate_state = GenerateState::Running;
        self.current_round = 1;

        let mut outgoing = Vec::new();
        match self.drive_presigning(&mut outgoing)? {
            None => Ok(outgoing),
            Some(_presig) => Err(MpcError::Protocol(
                "presigning completed without any rounds (unexpected)".into(),
            )),
        }
    }

    /// Process incoming messages for the current presigning round.
    ///
    /// Buffers incoming payloads, drives the SM, and on completion adds
    /// the resulting presignature to the pool. Returns
    /// [`PresigningRoundResult::Complete`] when the presignature is
    /// ready, or [`PresigningRoundResult::NextRound`] otherwise.
    pub fn process_generate_round(
        &mut self,
        messages: Vec<RoundMessage>,
    ) -> Result<PresigningRoundResult> {
        if self.generate_state != GenerateState::Running {
            return Err(MpcError::Protocol(
                "process_generate_round() called but no generation in progress".into(),
            ));
        }

        for msg in &messages {
            self.buffer_incoming_payload(&msg.payload)?;
        }

        let mut outgoing = Vec::new();
        match self.drive_presigning(&mut outgoing)? {
            None => {
                self.current_round += 1;
                Ok(PresigningRoundResult::NextRound(outgoing))
            }
            Some(presig_output) => {
                tracing::info!(
                    party = self.share.share_index.0,
                    pool_size = self.pool.len() + 1,
                    max = self.max_pool_size,
                    "presigning protocol complete, adding to pool"
                );

                self.generate_state = GenerateState::Idle;
                self.current_round = 0;

                let presig_id = {
                    let mut hasher = Sha256::new();
                    hasher.update(b"presig-");
                    hasher.update(self.session_id.as_bytes());
                    hasher.update(self.eid_counter.to_be_bytes());
                    hex::encode(hasher.finalize())
                };

                let presig = Presignature {
                    id: presig_id,
                    session_id: self.session_id,
                    // PresignaturePublicData doesn't implement Serialize;
                    // the actual presig objects are stored in raw_pool.
                    data: vec![],
                    created_at: chrono::Utc::now(),
                };

                self.pool.push(presig);
                let boxed: Box<dyn std::any::Any + Send> = Box::new(presig_output);
                self.raw_pool.push(boxed);

                // Hand the caller the final-round outgoing produced in this same drive
                // so it is still sent to peers (see `PresigningRoundResult::Complete`).
                Ok(PresigningRoundResult::Complete(outgoing))
            }
        }
    }

    /// Take one presignature from the pool for use in online signing.
    ///
    /// Presignatures are consumed in FIFO order (oldest first). Each
    /// presignature can only be used once — reusing a presignature would
    /// leak the private key (nonce reuse attack).
    ///
    /// Returns `None` if the pool is empty.
    pub fn take(&mut self) -> Option<Presignature> {
        if self.pool.is_empty() {
            None
        } else {
            if !self.raw_pool.is_empty() {
                self.raw_pool.remove(0);
            }
            Some(self.pool.remove(0))
        }
    }

    /// Take the raw cggmp24 presignature data for use in signing.
    ///
    /// Returns the type-erased presignature output from the oldest entry.
    /// The concrete type is `(cggmp24::Presignature<E>, PresignaturePublicData<E>)`.
    /// The caller must downcast using the appropriate concrete type.
    ///
    /// Also removes the corresponding `Presignature` wrapper from the pool.
    pub fn take_raw(&mut self) -> Option<(Presignature, Box<dyn std::any::Any + Send>)> {
        if self.pool.is_empty() || self.raw_pool.is_empty() {
            None
        } else {
            let presig = self.pool.remove(0);
            let raw = self.raw_pool.remove(0);
            Some((presig, raw))
        }
    }

    /// Manually add a presignature to the pool.
    ///
    /// Useful when presignatures are generated externally (e.g., via
    /// `round_based::sim` in tests). No raw data is stored — only the
    /// metadata wrapper.
    pub fn add(&mut self, presig: Presignature) {
        self.pool.push(presig);
    }

    /// Get the current number of available presignatures.
    pub fn pool_size(&self) -> usize {
        self.pool.len()
    }

    /// Check whether the pool should be replenished.
    ///
    /// Returns `true` if the pool has fewer than half its maximum capacity.
    pub fn should_replenish(&self) -> bool {
        self.pool.len() < self.max_pool_size / 2
    }

    /// Get the maximum pool size.
    pub fn max_pool_size(&self) -> usize {
        self.max_pool_size
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Check if a generation is currently in progress.
    pub fn is_generating(&self) -> bool {
        self.generate_state == GenerateState::Running
    }

    // -----------------------------------------------------------------------
    // Internal: inline-SM drive helpers (Phase G)
    // -----------------------------------------------------------------------

    /// Drive the presigning SM until it needs more input or completes.
    fn drive_presigning(
        &mut self,
        outgoing: &mut Vec<RoundMessage>,
    ) -> Result<Option<PresignOutput>> {
        // Capture immutable copies before taking the &mut on wire_buffer /
        // next_msg_id (avoids borrow-checker conflict with `self.*`).
        let signing_idx = self.signing_index()?;
        let session_id = self.session_id;
        let current_round = self.current_round;

        let mut sm = self
            .presigning_sm
            .take()
            .ok_or_else(|| MpcError::Protocol("drive_presigning: SM not present".into()))?;

        let result = drive_inline(
            sm.as_mut(),
            &mut self.wire_buffer,
            &mut self.next_msg_id,
            signing_idx,
            session_id,
            current_round,
            outgoing,
            "presigning",
            &MpcError::Protocol,
        );

        match result? {
            DriveStep::NeedsInput => {
                self.presigning_sm = Some(sm);
                Ok(None)
            }
            DriveStep::Complete(presig_output) => Ok(Some(presig_output)),
        }
    }

    /// Compute this party's signing-time index (position within
    /// `participants`). Errors if our share index isn't in the list.
    fn signing_index(&self) -> Result<u16> {
        self.participants
            .iter()
            .position(|&p| p == self.share.share_index.0)
            .map(|p| p as u16)
            .ok_or_else(|| {
                MpcError::Protocol(format!(
                    "share index {} not found in participants {:?}",
                    self.share.share_index.0, self.participants
                ))
            })
    }

    /// Decode one incoming `RoundMessage` payload onto the internal wire
    /// buffer. Accepts either a single `WireMessage` JSON or a bundled
    /// JSON array.
    fn buffer_incoming_payload(&mut self, wire_bytes: &[u8]) -> Result<()> {
        if wire_bytes.first() == Some(&b'[') {
            let bundle: Vec<WireMessage> = serde_json::from_slice(wire_bytes).map_err(|e| {
                MpcError::Protocol(format!("failed to deserialize bundled incoming: {e}"))
            })?;
            self.wire_buffer.extend(bundle);
        } else {
            let wire: WireMessage = serde_json::from_slice(wire_bytes)
                .map_err(|e| MpcError::Protocol(format!("failed to deserialize incoming: {e}")))?;
            self.wire_buffer.push_back(wire);
        }
        Ok(())
    }
}

/// Serialize the cggmp24 presignature from a [`PresigningManager::take_raw`]
/// box, ready to ship into a remote party's presignature pool (the cosigner DO
/// via `/ceremony/ingest-presig`). The bytes are exactly what
/// [`crate::signing::issue_partial_signature_json`] consumes — the public data
/// is dropped (only the combiner needs it, and it is not `Serialize`).
///
/// **SECURITY (ADR-018):** a presignature alone is sufficient to *issue that
/// party's partial* (`issue_partial_signature_json` takes no key share). So a
/// party's presignature MUST only be shipped from that party's own host
/// directly to its pool — `Presignature_A` flows **cosigner/container → DO**,
/// never via the proxy. A proxy holding both `Presignature_A` and
/// `Presignature_B` could issue both partials and forge a full signature alone,
/// defeating the threshold.
pub fn serialize_party_presignature(raw: Box<dyn std::any::Any + Send>) -> Result<Vec<u8>> {
    let output = raw.downcast::<PresignOutput>().map_err(|_| {
        MpcError::Serialization("raw presignature box is not a PresignOutput".into())
    })?;
    let (presig, _public_data) = *output;
    serde_json::to_vec(&presig)
        .map_err(|e| MpcError::Serialization(format!("serialize presignature: {e}")))
}

/// Like [`serialize_party_presignature`] but ALSO returns the durable CBOR of
/// the shared `PresignaturePublicData` + the `Gamma` commitment hex — for the
/// coordinator to persist in `PresigBundle.{commitments, gamma_hex}` (§06.17.1)
/// so it can reconstruct and combine across a restart (#25). The cosigner-side
/// (`PresignOutput` not serializable cross-crate) downcast must happen here in
/// `bsv-mpc-core`. Returns `(presig_json, public_data_cbor, gamma_hex)`.
pub fn serialize_party_presig_with_public_data(
    raw: Box<dyn std::any::Any + Send>,
) -> Result<(Vec<u8>, Vec<u8>, String)> {
    let output = raw.downcast::<PresignOutput>().map_err(|_| {
        MpcError::Serialization("raw presignature box is not a PresignOutput".into())
    })?;
    let (presig, public_data) = *output;
    let presig_json = serde_json::to_vec(&presig)
        .map_err(|e| MpcError::Serialization(format!("serialize presignature: {e}")))?;
    let public_data_cbor = crate::signing::serialize_presig_public_data(&public_data)?;
    let gamma_hex = hex::encode(public_data.Gamma.to_bytes(true));
    Ok((presig_json, public_data_cbor, gamma_hex))
}

/// Inverse of [`serialize_party_presig_with_public_data`]: reconstruct a raw
/// `PresignOutput` box from a party's serialized presignature JSON + the SHARED
/// `PresignaturePublicData` CBOR (`PresigBundle.commitments`).
///
/// Used by the device-holds-(t−1) client (#69 / #86). After a genuine n-party
/// presign over the relay assembles a [`crate::types::PresigBundle`], the device
/// reconstructs the raw `(Presignature, PublicData)` box for EACH of its `w`
/// co-located parties — pairing that party's presignature (its own from the
/// unsealed `presig_bytes`, or a co-located party's from a BRC-2-decrypted
/// `cosigner_encrypted_shares` entry) with the shared public data — so the boxes
/// feed [`crate::signing::SigningCoordinator::sign_with_presignature`] /
/// `add_local_presig_partial` (the device-holds combine) byte-identically to a
/// live [`PresigningManager::take_raw`] box.
///
/// The public data is the agreed presign transcript (shared by every party), so a
/// single `commitments` blob reconstructs every party's box — the same property
/// [`crate::signing::SigningCoordinator::sign_from_bundle`] relies on.
pub fn deserialize_party_presig_with_public_data(
    presig_json: &[u8],
    public_data_cbor: &[u8],
) -> Result<Box<dyn std::any::Any + Send>> {
    let presig: cggmp24::Presignature<Secp256k1> = serde_json::from_slice(presig_json)
        .map_err(|e| MpcError::Serialization(format!("deserialize presignature: {e}")))?;
    let public_data = crate::signing::deserialize_presig_public_data(public_data_cbor)?;
    let output: PresignOutput = (presig, public_data);
    Ok(Box::new(output))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ShareIndex, ThresholdConfig};
    use std::collections::VecDeque;

    // ---- Buffered sink for simulation (from POC 1 / dkg.rs tests) ----

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

    // ---- Blum prime utilities (same as dkg.rs / signing.rs tests) ----

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
    ) -> cggmp24::PregeneratedPrimes<SecurityLevel128> {
        use cggmp24::security_level::SecurityLevel;
        let bitsize = SecurityLevel128::RSA_PRIME_BITLEN;
        let primes = [
            generate_blum_prime(rng, bitsize),
            generate_blum_prime(rng, bitsize),
            generate_blum_prime(rng, bitsize),
            generate_blum_prime(rng, bitsize),
        ];
        cggmp24::PregeneratedPrimes::try_from(primes).expect("primes have wrong bit size")
    }

    /// Run DKG for 2-of-2 via sim, returning complete key shares.
    async fn run_dkg_2of2() -> Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> {
        use rand::Rng;

        let mut rng = rand::rngs::OsRng;
        let n: u16 = 2;
        let t: u16 = 2;

        let eid_bytes: [u8; 32] = rng.gen();
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

        let eid_bytes_aux: [u8; 32] = rng.gen();
        let eid_aux = ExecutionId::new(&eid_bytes_aux);

        let primes: Vec<_> = (0..n)
            .map(|_| generate_pregenerated_primes(&mut rng))
            .collect();

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
                cggmp24::KeyShare::from_parts((share, aux))
                    .expect("key share validation should pass")
            })
            .collect()
    }

    /// Run an `n`-of-`n` DKG (keygen + aux info) via the round-based sim, returning
    /// complete key shares. Generalizes [`run_dkg_2of2`] for the n-party reorder repro.
    async fn run_dkg(n: u16, t: u16) -> Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> {
        use rand::Rng;
        let mut rng = rand::rngs::OsRng;

        let eid_bytes: [u8; 32] = rng.gen();
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

        let eid_bytes_aux: [u8; 32] = rng.gen();
        let eid_aux = ExecutionId::new(&eid_bytes_aux);
        let primes: Vec<_> = (0..n)
            .map(|_| generate_pregenerated_primes(&mut rng))
            .collect();
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
                cggmp24::KeyShare::from_parts((share, aux)).expect("key share validation")
            })
            .collect()
    }

    /// **Repro for the deployed n-party presign deadlock (#98).** The egress-NAT
    /// WS-push path delivers round messages REORDERED; the in-process sim tests deliver
    /// in-order, masking it. This drives a real n-of-n presign through our
    /// `PresigningManager`/`drive_inline`, but feeds each party its inbound in
    /// ADVERSARIAL order — the pending message with the HIGHEST wire-round first — so
    /// every SM repeatedly sees future-round messages before current-round ones,
    /// exercising the out-of-order buffer. A correct transport must still complete.
    #[tokio::test]
    async fn nparty_presign_survives_reordered_delivery() {
        // Deliver `msgs` from `sender` to recipients (broadcast → every other party;
        // p2p → the named `to`). Full n-of-n → signing position == party index.
        fn push_routed(
            sender: usize,
            msgs: Vec<RoundMessage>,
            np: usize,
            pending: &mut Vec<(usize, RoundMessage)>,
        ) {
            for m in msgs {
                match m.to {
                    Some(ShareIndex(to)) => pending.push((to as usize, m)),
                    None => {
                        for r in 0..np {
                            if r != sender {
                                pending.push((r, m.clone()));
                            }
                        }
                    }
                }
            }
        }

        let n: u16 = 3;
        let key_shares = run_dkg(n, n).await;
        let session_id = SessionId::from_str_hash("presign-reorder-repro");
        let config = ThresholdConfig::new(n, n).unwrap();
        let participants: Vec<u16> = (0..n).collect();
        let np = n as usize;
        let mut mgrs: Vec<PresigningManager> = (0..n)
            .map(|i| {
                PresigningManager::new(
                    session_id,
                    wrap_key_share(&key_shares[i as usize], i, config, &session_id),
                    participants.clone(),
                    5,
                )
            })
            .collect();
        let mut done = vec![false; np];

        let mut pending: Vec<(usize, RoundMessage)> = Vec::new();
        for (s, mgr) in mgrs.iter_mut().enumerate() {
            let out = mgr.init_generate().unwrap();
            push_routed(s, out, np, &mut pending);
        }

        let mut steps = 0u32;
        while !done.iter().all(|&d| d) {
            steps += 1;
            assert!(steps < 10_000, "step budget exceeded (livelock?)");
            assert!(
                !pending.is_empty(),
                "DEADLOCK: no pending messages but parties incomplete (done={done:?})"
            );
            // Adversarial reorder: take the HIGHEST-round pending message.
            let idx = pending
                .iter()
                .enumerate()
                .max_by_key(|(_, (_, m))| m.round)
                .map(|(i, _)| i)
                .unwrap();
            let (recipient, msg) = pending.remove(idx);
            if done[recipient] {
                continue;
            }
            match mgrs[recipient].process_generate_round(vec![msg]) {
                Ok(PresigningRoundResult::NextRound(out)) => {
                    push_routed(recipient, out, np, &mut pending)
                }
                // The fix under test: the completing party's final-round messages are
                // STILL routed to peers — without this the test deadlocks (done=[F,T,F]).
                Ok(PresigningRoundResult::Complete(out)) => {
                    push_routed(recipient, out, np, &mut pending);
                    done[recipient] = true
                }
                Err(e) => panic!("party {recipient} SM error on reordered delivery: {e}"),
            }
        }
        assert!(done.iter().all(|&d| d), "all parties must complete");
    }

    /// Wrap a cggmp24 KeyShare into our EncryptedShare format (placeholder encryption).
    fn wrap_key_share(
        key_share: &cggmp24::KeyShare<Secp256k1, SecurityLevel128>,
        index: u16,
        config: ThresholdConfig,
        session_id: &SessionId,
    ) -> EncryptedShare {
        let key_share_json = serde_json::to_vec(key_share).expect("key share should serialize");
        EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: key_share_json,
            session_id: *session_id,
            share_index: ShareIndex(index),
            config,
            joint_pubkey_compressed: key_share.core.shared_public_key.to_bytes(true).to_vec(),
        }
    }

    // ---- Pool management tests ----

    #[test]
    fn pool_management_basic() {
        let session_id = SessionId::from_str_hash("test-session");
        let config = ThresholdConfig::new(2, 2).unwrap();
        let share = EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: vec![],
            session_id,
            share_index: ShareIndex(0),
            config,
            joint_pubkey_compressed: Vec::new(),
        };

        let mut mgr = PresigningManager::new(session_id, share, vec![0, 1], 10);

        assert_eq!(mgr.pool_size(), 0);
        assert!(mgr.should_replenish());
        assert_eq!(mgr.max_pool_size(), 10);
        assert!(mgr.take().is_none());
    }

    #[test]
    fn pool_fifo_order() {
        let session_id = SessionId::from_str_hash("test-session");
        let config = ThresholdConfig::new(2, 2).unwrap();
        let share = EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: vec![],
            session_id,
            share_index: ShareIndex(0),
            config,
            joint_pubkey_compressed: Vec::new(),
        };

        let mut mgr = PresigningManager::new(session_id, share, vec![0, 1], 10);

        // Add presignatures with different IDs
        for i in 0..3 {
            mgr.add(Presignature {
                id: format!("presig-{i}"),
                session_id,
                data: vec![i as u8],
                created_at: chrono::Utc::now(),
            });
        }

        assert_eq!(mgr.pool_size(), 3);

        // Take in FIFO order
        let p0 = mgr.take().unwrap();
        assert_eq!(p0.id, "presig-0");
        let p1 = mgr.take().unwrap();
        assert_eq!(p1.id, "presig-1");
        let p2 = mgr.take().unwrap();
        assert_eq!(p2.id, "presig-2");
        assert!(mgr.take().is_none());
    }

    #[test]
    fn should_replenish_threshold() {
        let session_id = SessionId::from_str_hash("test-session");
        let config = ThresholdConfig::new(2, 2).unwrap();
        let share = EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: vec![],
            session_id,
            share_index: ShareIndex(0),
            config,
            joint_pubkey_compressed: Vec::new(),
        };

        let mut mgr = PresigningManager::new(session_id, share, vec![0, 1], 10);

        // Pool < 5 (half of 10) → should replenish
        assert!(mgr.should_replenish());

        // Add 5 presignatures → at threshold, no replenish
        for i in 0..5 {
            mgr.add(Presignature {
                id: format!("presig-{i}"),
                session_id,
                data: vec![],
                created_at: chrono::Utc::now(),
            });
        }
        assert!(!mgr.should_replenish());

        // Take one → below threshold → should replenish
        mgr.take();
        assert!(mgr.should_replenish());
    }

    #[test]
    fn init_generate_fails_when_already_generating() {
        let session_id = SessionId::from_str_hash("test-session");
        let config = ThresholdConfig::new(2, 2).unwrap();
        let share = EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: vec![],
            session_id,
            share_index: ShareIndex(0),
            config,
            joint_pubkey_compressed: Vec::new(),
        };

        let mut mgr = PresigningManager::new(session_id, share, vec![0, 1], 10);

        // Force state to Running to simulate in-progress generation
        mgr.generate_state = GenerateState::Running;

        let result = mgr.init_generate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("already in progress"));
    }

    #[test]
    fn process_generate_round_fails_when_idle() {
        let session_id = SessionId::from_str_hash("test-session");
        let config = ThresholdConfig::new(2, 2).unwrap();
        let share = EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: vec![],
            session_id,
            share_index: ShareIndex(0),
            config,
            joint_pubkey_compressed: Vec::new(),
        };

        let mut mgr = PresigningManager::new(session_id, share, vec![0, 1], 10);

        let result = mgr.process_generate_round(vec![]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("no generation in progress"));
    }

    // ---- Integration test: two managers exchange messages to generate a presignature ----

    #[tokio::test]
    async fn two_managers_generate_presignature() {
        let key_shares = run_dkg_2of2().await;

        let session_id = SessionId::from_str_hash("presign-test-session");
        let config = ThresholdConfig::new(2, 2).unwrap();
        let participants = vec![0u16, 1u16];

        let share_0 = wrap_key_share(&key_shares[0], 0, config, &session_id);
        let share_1 = wrap_key_share(&key_shares[1], 1, config, &session_id);

        let mut mgr_0 = PresigningManager::new(session_id, share_0, participants.clone(), 5);
        let mut mgr_1 = PresigningManager::new(session_id, share_1, participants.clone(), 5);

        // Both managers start presigning
        let msgs_0 = mgr_0.init_generate().unwrap();
        let msgs_1 = mgr_1.init_generate().unwrap();

        assert!(
            !msgs_0.is_empty(),
            "manager 0 should produce initial messages"
        );
        assert!(
            !msgs_1.is_empty(),
            "manager 1 should produce initial messages"
        );
        assert!(mgr_0.is_generating());
        assert!(mgr_1.is_generating());

        // Exchange messages round by round
        let mut outgoing_0 = msgs_0;
        let mut outgoing_1 = msgs_1;

        for _round in 0..20 {
            // Feed manager 0's messages to manager 1 and vice versa
            let result_0 = mgr_0.process_generate_round(outgoing_1.clone()).unwrap();
            let result_1 = mgr_1.process_generate_round(outgoing_0.clone()).unwrap();

            match (result_0, result_1) {
                (PresigningRoundResult::Complete(_), PresigningRoundResult::Complete(_)) => {
                    // Both completed
                    break;
                }
                (PresigningRoundResult::NextRound(m0), PresigningRoundResult::NextRound(m1)) => {
                    outgoing_0 = m0;
                    outgoing_1 = m1;
                }
                (PresigningRoundResult::Complete(_), PresigningRoundResult::NextRound(m1)) => {
                    // Manager 0 completed first, feed remaining to manager 1
                    outgoing_0 = vec![];
                    outgoing_1 = m1;
                }
                (PresigningRoundResult::NextRound(m0), PresigningRoundResult::Complete(_)) => {
                    outgoing_0 = m0;
                    outgoing_1 = vec![];
                }
            }
        }

        // Both managers should have a presignature in their pool
        assert_eq!(mgr_0.pool_size(), 1, "manager 0 should have 1 presignature");
        assert_eq!(mgr_1.pool_size(), 1, "manager 1 should have 1 presignature");
        assert!(!mgr_0.is_generating());
        assert!(!mgr_1.is_generating());

        // Take the presignatures (with raw data)
        let (presig_0, raw_0) = mgr_0.take_raw().unwrap();
        let (presig_1, raw_1) = mgr_1.take_raw().unwrap();

        // Verify presignature metadata
        assert_eq!(presig_0.session_id, session_id);
        assert_eq!(presig_1.session_id, session_id);
        assert!(!presig_0.id.is_empty(), "presig 0 should have an ID");
        assert!(!presig_1.id.is_empty(), "presig 1 should have an ID");

        // Raw data should exist (type-erased cggmp24 presignature objects)
        let _ = raw_0;
        let _ = raw_1;

        // Pool should be empty now
        assert!(mgr_0.take().is_none());
        assert!(mgr_1.take().is_none());
        assert!(mgr_0.should_replenish());
    }

    #[tokio::test]
    async fn generate_multiple_presignatures() {
        let key_shares = run_dkg_2of2().await;

        let session_id = SessionId::from_str_hash("multi-presign-session");
        let config = ThresholdConfig::new(2, 2).unwrap();
        let participants = vec![0u16, 1u16];

        let share_0 = wrap_key_share(&key_shares[0], 0, config, &session_id);
        let share_1 = wrap_key_share(&key_shares[1], 1, config, &session_id);

        let mut mgr_0 = PresigningManager::new(session_id, share_0, participants.clone(), 5);
        let mut mgr_1 = PresigningManager::new(session_id, share_1, participants.clone(), 5);

        // Generate 2 presignatures
        for gen_idx in 0..2 {
            let msgs_0 = mgr_0.init_generate().unwrap();
            let msgs_1 = mgr_1.init_generate().unwrap();

            let mut outgoing_0 = msgs_0;
            let mut outgoing_1 = msgs_1;

            for _round in 0..20 {
                let result_0 = mgr_0.process_generate_round(outgoing_1.clone()).unwrap();
                let result_1 = mgr_1.process_generate_round(outgoing_0.clone()).unwrap();

                match (result_0, result_1) {
                    (PresigningRoundResult::Complete(_), PresigningRoundResult::Complete(_)) => {
                        break
                    }
                    (
                        PresigningRoundResult::NextRound(m0),
                        PresigningRoundResult::NextRound(m1),
                    ) => {
                        outgoing_0 = m0;
                        outgoing_1 = m1;
                    }
                    (PresigningRoundResult::Complete(_), PresigningRoundResult::NextRound(m1)) => {
                        outgoing_0 = vec![];
                        outgoing_1 = m1;
                    }
                    (PresigningRoundResult::NextRound(m0), PresigningRoundResult::Complete(_)) => {
                        outgoing_0 = m0;
                        outgoing_1 = vec![];
                    }
                }
            }

            assert_eq!(
                mgr_0.pool_size(),
                gen_idx + 1,
                "manager 0 should have {} presignatures after gen {}",
                gen_idx + 1,
                gen_idx
            );
        }

        // Both managers should have 2 presignatures with unique IDs
        assert_eq!(mgr_0.pool_size(), 2);
        let p0 = mgr_0.take().unwrap();
        let p1 = mgr_0.take().unwrap();
        assert_ne!(p0.id, p1.id, "presignature IDs should be unique");
    }

    /// **#4a gate** — `serialize_party_presignature` extracts a *usable*
    /// `Presignature_A` from a `PresigningManager::take_raw` box: the serialized
    /// bytes, fed through `issue_partial_signature_json` (the DO's light op) and
    /// combined with party 1's coordinator, yield a **BSV-valid** 2-of-2
    /// signature under the joint key. This is the provisioning pipeline the
    /// container will run before shipping `Presignature_A` to the DO pool.
    #[tokio::test]
    async fn serialize_party_presignature_drives_valid_2of2_signature() {
        use crate::signing::{
            issue_partial_signature_json, SigningCoordinator, SigningRoundResult,
        };

        let key_shares = run_dkg_2of2().await;
        let session_id = SessionId::from_str_hash("ser-presig-gate");
        let config = ThresholdConfig::new(2, 2).unwrap();
        let participants = vec![0u16, 1u16];
        let share_0 = wrap_key_share(&key_shares[0], 0, config, &session_id);
        let share_1 = wrap_key_share(&key_shares[1], 1, config, &session_id);

        // Generate one correlated presignature pair (party 0 = "cosigner").
        let mut mgr_0 = PresigningManager::new(session_id, share_0, participants.clone(), 1);
        let mut mgr_1 =
            PresigningManager::new(session_id, share_1.clone(), participants.clone(), 1);
        let mut out_0 = mgr_0.init_generate().unwrap();
        let mut out_1 = mgr_1.init_generate().unwrap();
        for _ in 0..20 {
            let r0 = mgr_0.process_generate_round(out_1.clone()).unwrap();
            let r1 = mgr_1.process_generate_round(out_0.clone()).unwrap();
            match (r0, r1) {
                (PresigningRoundResult::Complete(_), PresigningRoundResult::Complete(_)) => break,
                (PresigningRoundResult::NextRound(m0), PresigningRoundResult::NextRound(m1)) => {
                    out_0 = m0;
                    out_1 = m1;
                }
                (PresigningRoundResult::Complete(_), PresigningRoundResult::NextRound(m1)) => {
                    out_0 = vec![];
                    out_1 = m1;
                }
                (PresigningRoundResult::NextRound(m0), PresigningRoundResult::Complete(_)) => {
                    out_0 = m0;
                    out_1 = vec![];
                }
            }
        }
        assert_eq!(mgr_0.pool_size(), 1);
        assert_eq!(mgr_1.pool_size(), 1);

        // Party 0 (cosigner): extract + serialize Presignature_A via the helper.
        let (_meta_a, raw_a) = mgr_0.take_raw().unwrap();
        let presig_a_json =
            super::serialize_party_presignature(raw_a).expect("serialize_party_presignature");
        assert!(
            !presig_a_json.is_empty(),
            "serialized presignature must be non-empty"
        );

        // Party 1 (combiner): keep the full raw box.
        let (_meta_b, raw_b) = mgr_1.take_raw().unwrap();

        let message_hash: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(b"#4a serialize-presig gate");
            let mut b = [0u8; 32];
            b.copy_from_slice(&h.finalize());
            b
        };

        // DO light op: issue party-0's partial from the serialized presig only.
        let partial_a_json = issue_partial_signature_json(&presig_a_json, &message_hash)
            .expect("issue partial from serialized Presignature_A");
        let msg_a = RoundMessage {
            session_id,
            round: 1,
            from: ShareIndex(0),
            to: None,
            payload: partial_a_json,
        };

        // Combiner: issue its own partial + combine.
        let mut combiner = SigningCoordinator::new(session_id, share_1, config, participants);
        combiner
            .sign_with_presignature(&message_hash, raw_b)
            .expect("combiner issues its partial");
        let sig = match combiner.process_round(vec![msg_a]).expect("combine") {
            SigningRoundResult::Complete(s) => s,
            _ => panic!("combiner did not complete in 1 round"),
        };

        // BSV-valid under the joint pubkey.
        let pubkey_bytes = key_shares[0].core.shared_public_key.to_bytes(true);
        let bsv_pubkey = bsv::PublicKey::from_bytes(&pubkey_bytes).unwrap();
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&sig.r);
        sig_bytes[32..].copy_from_slice(&sig.s);
        let bsv_sig = bsv::Signature::from_compact(&sig_bytes).unwrap();
        assert!(
            bsv_pubkey.verify(&message_hash, &bsv_sig),
            "the helper-serialized Presignature_A MUST drive a BSV-valid 2-of-2 signature"
        );
    }

    /// **#86 reconstruct gate** — the inverse [`deserialize_party_presig_with_public_data`]
    /// rebuilds a raw `PresignOutput` box that is FUNCTIONALLY IDENTICAL to a live
    /// `take_raw()` box: a 2-of-2 combine driven by the RECONSTRUCTED box yields a
    /// BSV-valid signature under the joint key, and re-serializing it reproduces the
    /// exact same bytes (zero drift). This is the device-holds reconstruction
    /// (#69 step 7a): the device rebuilds its co-located parties' raw boxes from the
    /// assembled `PresigBundle` (presig JSON + shared commitments CBOR) and combines
    /// locally — never holding a live in-memory presig tuple across the relay.
    #[tokio::test]
    async fn deserialize_presig_with_public_data_reconstructs_usable_box() {
        use crate::signing::{
            issue_partial_signature_json, SigningCoordinator, SigningRoundResult,
        };

        let key_shares = run_dkg_2of2().await;
        let session_id = SessionId::from_str_hash("reconstruct-presig-gate");
        let config = ThresholdConfig::new(2, 2).unwrap();
        let participants = vec![0u16, 1u16];
        let share_0 = wrap_key_share(&key_shares[0], 0, config, &session_id);
        let share_1 = wrap_key_share(&key_shares[1], 1, config, &session_id);

        // One correlated presignature pair (party 0 = cosigner, party 1 = combiner).
        let mut mgr_0 = PresigningManager::new(session_id, share_0, participants.clone(), 1);
        let mut mgr_1 =
            PresigningManager::new(session_id, share_1.clone(), participants.clone(), 1);
        let mut out_0 = mgr_0.init_generate().unwrap();
        let mut out_1 = mgr_1.init_generate().unwrap();
        for _ in 0..20 {
            let r0 = mgr_0.process_generate_round(out_1.clone()).unwrap();
            let r1 = mgr_1.process_generate_round(out_0.clone()).unwrap();
            match (r0, r1) {
                (PresigningRoundResult::Complete(_), PresigningRoundResult::Complete(_)) => break,
                (PresigningRoundResult::NextRound(m0), PresigningRoundResult::NextRound(m1)) => {
                    out_0 = m0;
                    out_1 = m1;
                }
                (PresigningRoundResult::Complete(_), PresigningRoundResult::NextRound(m1)) => {
                    out_0 = vec![];
                    out_1 = m1;
                }
                (PresigningRoundResult::NextRound(m0), PresigningRoundResult::Complete(_)) => {
                    out_0 = m0;
                    out_1 = vec![];
                }
            }
        }

        // Party 0 (cosigner): serialize Presignature_A (presig only).
        let (_meta_a, raw_a) = mgr_0.take_raw().unwrap();
        let presig_a_json = super::serialize_party_presignature(raw_a).unwrap();

        // Party 1 (combiner): serialize WITH public data, then RECONSTRUCT the box
        // from (presig JSON + commitments CBOR) — the device-holds reconstruction.
        let (_meta_b, raw_b) = mgr_1.take_raw().unwrap();
        let (presig_b_json, commitments_cbor, gamma_hex) =
            super::serialize_party_presig_with_public_data(raw_b).unwrap();
        assert!(!gamma_hex.is_empty());
        let raw_b_reconstructed =
            super::deserialize_party_presig_with_public_data(&presig_b_json, &commitments_cbor)
                .expect("reconstruct combiner raw box from bundle bytes");

        // Re-serializing the reconstructed box reproduces the SAME bytes (zero drift).
        let (presig_b_json2, commitments_cbor2, gamma_hex2) =
            super::serialize_party_presig_with_public_data(raw_b_reconstructed)
                .expect("re-serialize reconstructed box");
        assert_eq!(
            presig_b_json, presig_b_json2,
            "presig JSON round-trips byte-identically"
        );
        assert_eq!(
            commitments_cbor, commitments_cbor2,
            "commitments CBOR round-trips byte-identically"
        );
        assert_eq!(gamma_hex, gamma_hex2, "gamma hex round-trips identically");

        // Reconstruct AGAIN (the first was consumed re-serializing) and drive a real
        // combine with it → BSV-valid signature under the joint key.
        let raw_b_for_sign =
            super::deserialize_party_presig_with_public_data(&presig_b_json, &commitments_cbor)
                .expect("reconstruct combiner raw box (sign)");
        let message_hash: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(b"#86 reconstruct gate");
            let mut b = [0u8; 32];
            b.copy_from_slice(&h.finalize());
            b
        };
        let partial_a_json = issue_partial_signature_json(&presig_a_json, &message_hash).unwrap();
        let msg_a = RoundMessage {
            session_id,
            round: 1,
            from: ShareIndex(0),
            to: None,
            payload: partial_a_json,
        };
        let mut combiner = SigningCoordinator::new(session_id, share_1, config, participants);
        combiner
            .sign_with_presignature(&message_hash, raw_b_for_sign)
            .expect("combiner issues its partial from the RECONSTRUCTED box");
        let sig = match combiner.process_round(vec![msg_a]).unwrap() {
            SigningRoundResult::Complete(s) => s,
            _ => panic!("combiner did not complete in 1 round"),
        };
        let pubkey_bytes = key_shares[0].core.shared_public_key.to_bytes(true);
        let bsv_pubkey = bsv::PublicKey::from_bytes(&pubkey_bytes).unwrap();
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&sig.r);
        sig_bytes[32..].copy_from_slice(&sig.s);
        let bsv_sig = bsv::Signature::from_compact(&sig_bytes).unwrap();
        assert!(
            bsv_pubkey.verify(&message_hash, &bsv_sig),
            "a RECONSTRUCTED presig box MUST drive a BSV-valid 2-of-2 signature"
        );
    }

    /// NEGATIVE — malformed inputs to the inverse are rejected with the right
    /// reason, never silently producing a junk box.
    #[test]
    fn deserialize_party_presig_rejects_malformed_inputs() {
        // Presig JSON is parsed FIRST, so a bad presig surfaces as a presignature
        // serialization error (regardless of the public-data bytes).
        let err = super::deserialize_party_presig_with_public_data(b"not-json", b"\x80")
            .expect_err("malformed presig JSON must be rejected");
        match err {
            MpcError::Serialization(msg) => assert!(
                msg.contains("presignature"),
                "error must name the presignature: {msg}"
            ),
            other => panic!("expected Serialization error, got {other:?}"),
        }
        // Empty inputs error too — never a silent success.
        assert!(super::deserialize_party_presig_with_public_data(b"", b"").is_err());
    }
}
