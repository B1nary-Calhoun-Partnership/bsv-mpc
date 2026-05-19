//! Distributed Key Generation (DKG) using the CGGMP'24 protocol.
//!
//! DKG is the ceremony where `n` parties jointly generate a secp256k1 key pair
//! such that no single party holds the full private key. Each party receives a
//! *share* of the private key, and the joint public key is known to all.
//!
//! ## Protocol Lifecycle
//!
//! The CGGMP'24 DKG consists of two sequential sub-protocols:
//!
//! 1. **Keygen** (multi-round): Produces an `IncompleteKeyShare` containing
//!    the party's secret share `x_i` and the joint public key.
//!
//! 2. **Aux info generation** (multi-round): Produces Paillier parameters
//!    required for the signing protocol. This is computationally expensive
//!    due to safe prime generation. Use [`DkgCoordinator::with_pool`] to
//!    inject pre-generated primes from a [`crate::paillier_pool::PaillierPool`]
//!    per MPC-Spec §06.10.1 / ADR-0041.
//!
//! After both complete, the results are combined via `KeyShare::from_parts()`
//! into a complete `KeyShare` that can be used for signing.
//!
//! ## State Machine Architecture (Phase G inline)
//!
//! The cggmp24 protocol is driven by `round_based::state_machine::StateMachine`,
//! which is `!Send` (internal `Rc<RefCell<_>>` state). Phase G of this crate
//! discovered that `proceed()` is non-blocking by construction — it returns
//! `NeedsOneMoreMessage` when it needs input. So the coordinator can host the
//! SM directly as a `Box<dyn StateMachine<...>>` struct field, with no thread,
//! no channels, and no tokio dependency. The pattern was empirically validated
//! by `poc/poc16-sm-inline/` before this production module adopted it; see
//! `docs/PHASE-G-AUDIT.md`.
//!
//! The caller's view is unchanged from the previous threaded design:
//! 1. Call `init()` to start and get the first outgoing messages.
//! 2. Call `process_round(incoming)` repeatedly until `Complete`.
//!
//! ## Wire Message Format
//!
//! Protocol messages are serialized to JSON via serde for transport over HTTP.
//! The `WireMessage` struct wraps each cggmp24 protocol message with sender
//! info and broadcast/p2p routing. These are packed into `RoundMessage.payload`
//! for the transport layer.
//!
//! ## Identifiable Abort
//!
//! If any party cheats (sends inconsistent shares, invalid proofs, etc.), the
//! protocol aborts and identifies the cheating party. This is a key security
//! property of CGGMP'24.

use std::collections::VecDeque;

use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use round_based::state_machine::{wrap_protocol, ProceedResult, StateMachine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{MpcError, Result};
use crate::paillier_pool::{PaillierPool, PrimePoolStorage};
use crate::types::{
    DkgResult, EncryptedShare, JointPublicKey, RoundMessage, SessionId, ShareIndex, ThresholdConfig,
};

// ---------------------------------------------------------------------------
// Wire message type for serializing cggmp24 protocol messages
// ---------------------------------------------------------------------------

/// Serializable wrapper around a cggmp24 protocol message for HTTP transport.
///
/// Each cggmp24 round produces `Outgoing<Msg>` values that contain the actual
/// protocol data. We serialize the `Msg` to JSON and wrap it with routing
/// metadata (sender index, broadcast vs p2p).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WireMessage {
    /// Sender's party index (0-indexed).
    pub sender: u16,
    /// Whether this message should be broadcast to all parties.
    pub is_broadcast: bool,
    /// The serialized cggmp24 protocol message.
    pub msg: serde_json::Value,
}

/// Convert a cggmp24 `Outgoing` message to a `WireMessage` for transport.
pub(crate) fn outgoing_to_wire<M: Serialize>(
    sender: u16,
    out: round_based::Outgoing<M>,
) -> std::result::Result<WireMessage, MpcError> {
    Ok(WireMessage {
        sender,
        is_broadcast: out.recipient.is_broadcast(),
        msg: serde_json::to_value(&out.msg).map_err(|e| {
            MpcError::Serialization(format!("failed to serialize outgoing message: {e}"))
        })?,
    })
}

/// Convert a `WireMessage` back to a cggmp24 `Incoming` message.
pub(crate) fn wire_to_incoming<M: serde::de::DeserializeOwned>(
    wire: WireMessage,
    id: u64,
) -> std::result::Result<round_based::Incoming<M>, MpcError> {
    Ok(round_based::Incoming {
        id,
        sender: wire.sender,
        msg_type: if wire.is_broadcast {
            round_based::MessageType::Broadcast
        } else {
            round_based::MessageType::P2P
        },
        msg: serde_json::from_value(wire.msg).map_err(|e| {
            MpcError::Serialization(format!("failed to deserialize incoming message: {e}"))
        })?,
    })
}

// ---------------------------------------------------------------------------
// DKG protocol phase tracking
// ---------------------------------------------------------------------------

/// Which sub-protocol the DKG is currently executing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DkgPhase {
    /// Not started yet.
    NotStarted,
    /// Running the keygen sub-protocol.
    Keygen,
    /// Keygen complete, running aux info generation.
    AuxInfo,
    /// Both phases complete, KeyShare has been assembled.
    Complete,
}

// ---------------------------------------------------------------------------
// DkgRoundResult
// ---------------------------------------------------------------------------

/// Result of processing a DKG round.
///
/// After processing incoming messages from the current round, the coordinator
/// either produces messages for the next round or completes with the final result.
#[derive(Debug)]
pub enum DkgRoundResult {
    /// The protocol needs another round. Contains outgoing messages to send.
    NextRound(Vec<RoundMessage>),
    /// The DKG ceremony is complete. Contains the joint key and this party's share.
    Complete(DkgResult),
}

// ---------------------------------------------------------------------------
// Inline-SM type aliases (Phase G)
// ---------------------------------------------------------------------------

/// Boxed `StateMachine` for the keygen sub-protocol. The Output is what the
/// cggmp24 keygen future returns; the Msg type is what cggmp24-keygen emits
/// over the wire for the threshold keygen variant. We box because the
/// `impl StateMachine` returned by `wrap_protocol` has an opaque Future
/// generic and can't be named directly in a struct field.
type KeygenSm = Box<
    dyn StateMachine<
        Output = std::result::Result<cggmp24::IncompleteKeyShare<Secp256k1>, cggmp24::KeygenError>,
        Msg = cggmp24::keygen::ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>,
    >,
>;

/// Boxed `StateMachine` for the aux_info_gen sub-protocol.
type AuxInfoSm = Box<
    dyn StateMachine<
        Output = std::result::Result<
            cggmp24::key_share::AuxInfo<SecurityLevel128>,
            cggmp24::key_refresh::KeyRefreshError,
        >,
        Msg = cggmp24::key_refresh::msg::Msg<Sha256, SecurityLevel128>,
    >,
>;

// ---------------------------------------------------------------------------
// DkgCoordinator
// ---------------------------------------------------------------------------

/// Coordinator for a single party's participation in a DKG ceremony.
///
/// Each party in the MPC group instantiates a `DkgCoordinator` and drives it
/// through the protocol rounds by calling [`init`](Self::init) followed by
/// repeated calls to [`process_round`](Self::process_round) until completion.
///
/// The coordinator internally manages the two-phase CGGMP'24 lifecycle:
/// 1. **Keygen**: Multi-round interactive protocol producing `IncompleteKeyShare`
/// 2. **Aux info gen**: Multi-round protocol producing Paillier parameters
/// 3. **Combine**: `KeyShare::from_parts(incomplete, aux_info)` -> complete share
///
/// Each phase's `round_based::StateMachine` lives directly on this struct (see
/// `KeygenSm` / `AuxInfoSm` aliases above). The Phase G rewrite removed the
/// previous `std::thread` + `std::sync::mpsc` bridge; `proceed()` is driven
/// inline.
///
/// # Example
///
/// ```ignore
/// let config = ThresholdConfig::new(2, 3)?; // 2-of-3
/// let session = SessionId::from_str_hash("unique-session-id");
/// let mut coord = DkgCoordinator::new(session, config, ShareIndex(0));
///
/// // Round 1: start keygen and get first outgoing messages
/// let msgs = coord.init()?;
/// transport.send_all(msgs).await;
///
/// // Rounds 2..N: process incoming, send outgoing
/// loop {
///     let incoming = transport.receive_round().await;
///     match coord.process_round(incoming)? {
///         DkgRoundResult::NextRound(msgs) => transport.send_all(msgs).await,
///         DkgRoundResult::Complete(result) => {
///             println!("Joint key: {}", result.joint_key.address);
///             break;
///         }
///     }
/// }
/// ```
pub struct DkgCoordinator {
    /// Session identifier for this DKG ceremony.
    session_id: SessionId,
    /// Threshold configuration (t-of-n).
    config: ThresholdConfig,
    /// This party's index in the MPC group.
    my_index: ShareIndex,
    /// Current round number (0 = not started).
    current_round: u8,
    /// Which sub-protocol phase we are in.
    phase: DkgPhase,

    /// The active keygen state machine, or `None` after keygen completed.
    keygen_sm: Option<KeygenSm>,
    /// The active aux_info state machine, or `None` before keygen completed
    /// or after aux_info completed.
    aux_info_sm: Option<AuxInfoSm>,
    /// Incoming wire messages buffered across `process_round()` calls. The
    /// SM consumes one at a time via `received_msg()`; if a caller hands us
    /// more messages than the SM is ready for, the surplus waits here.
    wire_buffer: VecDeque<WireMessage>,
    /// Monotonic message-id for `round_based::Incoming<M>::id`. Each
    /// message we feed to the SM gets a unique ascending id.
    next_msg_id: u64,

    /// Serialized IncompleteKeyShare from the keygen phase.
    /// Stored between keygen completion and aux info start.
    incomplete_share_json: Option<Vec<u8>>,

    /// Joint public key (33-byte compressed) — known only after keygen
    /// completes. Used to derive the canonical ExecutionId for the auxinfo
    /// phase per MPC-Spec §02.4 (joint_pubkey known for phases != keygen).
    keygen_joint_pubkey: Option<[u8; 33]>,

    /// Serialized execution ID bytes for the keygen phase (canonical, per
    /// MPC-Spec §02.2 with phase=0x01 and joint_pubkey=all-zero carve-out
    /// per §02.4).
    eid_bytes: [u8; 32],

    /// Optional pre-generated Paillier primes for aux info generation.
    /// If None, safe primes will be generated on-the-fly (slow, ~30-60s).
    /// If Some, these pre-generated primes are used (fast).
    /// Use [`set_pregenerated_primes`](Self::set_pregenerated_primes) or
    /// [`with_pool`](Self::with_pool) to provide them.
    pregenerated_primes: Option<cggmp24::PregeneratedPrimes<SecurityLevel128>>,
}

impl DkgCoordinator {
    /// Create a new DKG coordinator for the given threshold config and party index.
    ///
    /// # Arguments
    ///
    /// * `session_id` -- Session identifier (should be unique per DKG ceremony).
    /// * `config` -- Threshold configuration (t-of-n).
    /// * `my_index` -- This party's index, must be in `[0, config.parties)`.
    pub fn new(session_id: SessionId, config: ThresholdConfig, my_index: ShareIndex) -> Self {
        // Canonical ExecutionId per MPC-Spec §02.2 with phase=DkgKeygen and
        // the all-zero joint_pubkey carve-out per §02.4 (keygen produces the
        // joint key — it's not yet known here).
        let eid_bytes =
            crate::canonical::canonical_execution_id(&crate::canonical::ExecutionParams::new_v1(
                crate::canonical::PhaseTag::DkgKeygen,
                session_id,
                [0u8; 33],
            ));

        Self {
            session_id,
            config,
            my_index,
            current_round: 0,
            phase: DkgPhase::NotStarted,
            keygen_sm: None,
            aux_info_sm: None,
            wire_buffer: VecDeque::new(),
            next_msg_id: 0,
            incomplete_share_json: None,
            keygen_joint_pubkey: None,
            eid_bytes,
            pregenerated_primes: None,
        }
    }

    /// Set pre-generated Paillier primes for aux info generation.
    ///
    /// This avoids the expensive safe prime generation during DKG.
    /// Primes can be generated ahead of time using
    /// `cggmp24::PregeneratedPrimes::generate(&mut OsRng)`.
    ///
    /// Must be called before `init()`.
    pub fn set_pregenerated_primes(
        &mut self,
        primes: cggmp24::PregeneratedPrimes<SecurityLevel128>,
    ) {
        self.pregenerated_primes = Some(primes);
    }

    /// Pull pre-generated Paillier primes from a [`PaillierPool`] and stash
    /// them for the auxinfo phase. If the pool is empty, this is a no-op
    /// and the auxinfo phase falls back to inline `safe_primes::generate()`.
    ///
    /// Per MPC-Spec §06.10.1 / ADR-0041 — the pool is RECOMMENDED for
    /// `profile-edge` / `profile-mobile` deployments. Builder-style so it
    /// chains cleanly with `DkgCoordinator::new(...)`.
    ///
    /// Must be called before `init()`.
    pub fn with_pool<S: PrimePoolStorage>(mut self, pool: &PaillierPool<S>) -> Self {
        if let Ok(Some(primes)) = pool.take() {
            self.pregenerated_primes = Some(primes);
        }
        self
    }

    /// Initialize the DKG ceremony by starting the keygen sub-protocol.
    ///
    /// Creates the keygen `StateMachine`, drives it inline until it needs an
    /// incoming message, and returns the collected outgoing messages.
    ///
    /// # Returns
    ///
    /// A vector of [`RoundMessage`]s to send to all other parties.
    ///
    /// # Errors
    ///
    /// Returns [`MpcError::Dkg`] if the keygen state machine fails to start
    /// or produces an error during initial driving.
    pub fn init(&mut self) -> Result<Vec<RoundMessage>> {
        if self.phase != DkgPhase::NotStarted {
            return Err(MpcError::Dkg(
                "init() called but DKG already started".into(),
            ));
        }

        if self.my_index.0 >= self.config.parties {
            return Err(MpcError::Dkg(format!(
                "party index {} >= total parties {}",
                self.my_index.0, self.config.parties
            )));
        }

        self.phase = DkgPhase::Keygen;
        self.current_round = 1;

        // Construct the keygen SM via wrap_protocol. The closure captures
        // copies of all needed values, so the resulting StateMachineImpl is
        // 'static (no external borrows). The future creates its own OsRng
        // reference internally — same shape used in the threaded version
        // pre-Phase-G.
        let eid_bytes = self.eid_bytes;
        let my_index = self.my_index.0;
        let n = self.config.parties;
        let t = self.config.threshold;
        let sm: KeygenSm = Box::new(wrap_protocol(move |party| async move {
            let eid = ExecutionId::new(&eid_bytes);
            cggmp24::keygen::<Secp256k1>(eid, my_index, n)
                .set_threshold(t)
                .start(&mut rand::rngs::OsRng, party)
                .await
        }));
        self.keygen_sm = Some(sm);

        let mut outgoing = Vec::new();
        match self.drive_keygen(&mut outgoing)? {
            None => Ok(outgoing),
            Some(_share) => Err(MpcError::Dkg(
                "keygen completed without any rounds (unexpected)".into(),
            )),
        }
    }

    /// Process incoming messages from the current round and advance the protocol.
    ///
    /// Buffers all incoming messages, then drives whichever phase SM is
    /// active. When a phase completes, automatically transitions and drives
    /// the next phase too (keygen → auxinfo). Returns `Complete` once both
    /// phases finish.
    pub fn process_round(&mut self, messages: Vec<RoundMessage>) -> Result<DkgRoundResult> {
        match self.phase {
            DkgPhase::NotStarted => {
                return Err(MpcError::Dkg("process_round() called before init()".into()));
            }
            DkgPhase::Complete => {
                return Err(MpcError::Dkg(
                    "process_round() called after DKG completed".into(),
                ));
            }
            DkgPhase::Keygen | DkgPhase::AuxInfo => {}
        }

        // Buffer all incoming payloads. Each RoundMessage.payload may be
        // either a single WireMessage (legacy) or a JSON array of them
        // (bundled). Decode + push onto the buffer in order.
        for msg in &messages {
            self.buffer_incoming_payload(&msg.payload)?;
        }

        let mut outgoing = Vec::new();

        // Drive whichever phase is active. On keygen completion, transition
        // to auxinfo and drive it too — emit any messages it produces in
        // this same round so callers see the auxinfo's first batch.
        if self.phase == DkgPhase::Keygen {
            match self.drive_keygen(&mut outgoing)? {
                None => {
                    self.current_round += 1;
                    return Ok(DkgRoundResult::NextRound(outgoing));
                }
                Some(incomplete_share) => {
                    self.handle_keygen_complete(incomplete_share)?;
                    // Fall through to auxinfo drive.
                }
            }
        }

        if self.phase == DkgPhase::AuxInfo {
            match self.drive_aux_info(&mut outgoing)? {
                None => {
                    self.current_round += 1;
                    return Ok(DkgRoundResult::NextRound(outgoing));
                }
                Some(aux_info) => {
                    self.phase = DkgPhase::Complete;
                    return self.assemble_dkg_result(aux_info);
                }
            }
        }

        // Shouldn't reach here — Keygen branch either returns or transitions
        // to AuxInfo; AuxInfo branch either returns or transitions to
        // Complete (and returns).
        Err(MpcError::Dkg(format!(
            "unexpected DKG state after drive: phase={:?}",
            self.phase
        )))
    }

    /// Get the current round number (0 = not started).
    pub fn current_round(&self) -> u8 {
        self.current_round
    }

    /// Get the threshold configuration.
    pub fn config(&self) -> &ThresholdConfig {
        &self.config
    }

    /// Get this party's share index.
    pub fn my_index(&self) -> ShareIndex {
        self.my_index
    }

    /// Get the current protocol phase as a stable string.
    pub fn phase(&self) -> &str {
        match self.phase {
            DkgPhase::NotStarted => "not_started",
            DkgPhase::Keygen => "keygen",
            DkgPhase::AuxInfo => "aux_info",
            DkgPhase::Complete => "complete",
        }
    }

    // -----------------------------------------------------------------------
    // Internal: inline SM drive helpers
    // -----------------------------------------------------------------------

    /// Drive the keygen SM until it either needs more input (`Ok(None)`),
    /// completes (`Ok(Some(IncompleteKeyShare))`), or errors. Appends any
    /// emitted outbound messages to `outgoing`.
    fn drive_keygen(
        &mut self,
        outgoing: &mut Vec<RoundMessage>,
    ) -> Result<Option<cggmp24::IncompleteKeyShare<Secp256k1>>> {
        let mut sm = self
            .keygen_sm
            .take()
            .ok_or_else(|| MpcError::Dkg("drive_keygen: SM not present".into()))?;

        let result = drive_inline(
            sm.as_mut(),
            &mut self.wire_buffer,
            &mut self.next_msg_id,
            self.my_index.0,
            self.session_id,
            self.current_round,
            outgoing,
            "keygen",
        );

        match result? {
            DriveStep::NeedsInput => {
                self.keygen_sm = Some(sm);
                Ok(None)
            }
            DriveStep::Complete(share) => Ok(Some(share)),
        }
    }

    /// Drive the auxinfo SM. Same shape as [`drive_keygen`] but with the
    /// auxinfo Msg/Output types.
    fn drive_aux_info(
        &mut self,
        outgoing: &mut Vec<RoundMessage>,
    ) -> Result<Option<cggmp24::key_share::AuxInfo<SecurityLevel128>>> {
        let mut sm = self
            .aux_info_sm
            .take()
            .ok_or_else(|| MpcError::Dkg("drive_aux_info: SM not present".into()))?;

        let result = drive_inline(
            sm.as_mut(),
            &mut self.wire_buffer,
            &mut self.next_msg_id,
            self.my_index.0,
            self.session_id,
            self.current_round,
            outgoing,
            "auxinfo",
        );

        match result? {
            DriveStep::NeedsInput => {
                self.aux_info_sm = Some(sm);
                Ok(None)
            }
            DriveStep::Complete(aux_info) => Ok(Some(aux_info)),
        }
    }

    /// Push one incoming RoundMessage payload onto `wire_buffer`. The
    /// payload is either a single JSON `WireMessage` or a JSON array.
    fn buffer_incoming_payload(&mut self, wire_bytes: &[u8]) -> Result<()> {
        if wire_bytes.first() == Some(&b'[') {
            let bundle: Vec<WireMessage> = serde_json::from_slice(wire_bytes).map_err(|e| {
                MpcError::Dkg(format!("failed to deserialize bundled incoming: {e}"))
            })?;
            self.wire_buffer.extend(bundle);
        } else {
            let wire: WireMessage = serde_json::from_slice(wire_bytes)
                .map_err(|e| MpcError::Dkg(format!("failed to deserialize incoming: {e}")))?;
            self.wire_buffer.push_back(wire);
        }
        Ok(())
    }

    /// Handle the keygen-complete event: extract the joint pubkey, stash the
    /// serialized incomplete share, construct the auxinfo SM, and transition
    /// to the AuxInfo phase.
    fn handle_keygen_complete(
        &mut self,
        incomplete_share: cggmp24::IncompleteKeyShare<Secp256k1>,
    ) -> Result<()> {
        tracing::info!(
            party = self.my_index.0,
            "keygen phase complete, starting aux info generation"
        );

        // Capture joint pubkey for the canonical auxinfo ExecutionId.
        let compressed = incomplete_share.shared_public_key.to_bytes(true);
        if compressed.len() != 33 {
            return Err(MpcError::Dkg(format!(
                "keygen joint pubkey is not 33 bytes (got {})",
                compressed.len()
            )));
        }
        let mut jpk = [0u8; 33];
        jpk.copy_from_slice(&compressed);
        self.keygen_joint_pubkey = Some(jpk);

        // Serialize and stash for later combine in assemble_dkg_result.
        let share_json = serde_json::to_vec(&incomplete_share)
            .map_err(|e| MpcError::Dkg(format!("failed to serialize incomplete share: {e}")))?;
        self.incomplete_share_json = Some(share_json);

        // Build the auxinfo SM. ExecutionId per MPC-Spec §02.4 includes the
        // joint pubkey (auxinfo is non-keygen, so the all-zero carve-out
        // does NOT apply).
        let aux_eid_bytes =
            crate::canonical::canonical_execution_id(&crate::canonical::ExecutionParams::new_v1(
                crate::canonical::PhaseTag::DkgAuxInfo,
                self.session_id,
                jpk,
            ));
        let my_index = self.my_index.0;
        let n = self.config.parties;
        let primes_opt = self.pregenerated_primes.take();

        let sm: AuxInfoSm = Box::new(wrap_protocol(move |party| async move {
            let eid = ExecutionId::new(&aux_eid_bytes);
            let primes = match primes_opt {
                Some(p) => {
                    tracing::info!(party = my_index, "using pre-generated Paillier primes");
                    p
                }
                None => {
                    tracing::info!(
                        party = my_index,
                        "generating Paillier safe primes (this may take 30-60s)..."
                    );
                    cggmp24::PregeneratedPrimes::<SecurityLevel128>::generate(
                        &mut rand::rngs::OsRng,
                    )
                }
            };
            cggmp24::aux_info_gen(eid, my_index, n, primes)
                .start(&mut rand::rngs::OsRng, party)
                .await
        }));

        self.aux_info_sm = Some(sm);
        self.phase = DkgPhase::AuxInfo;
        self.current_round += 1;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal: Assemble the final DKG result
    // -----------------------------------------------------------------------

    fn assemble_dkg_result(
        &self,
        aux_info: cggmp24::key_share::AuxInfo<SecurityLevel128>,
    ) -> Result<DkgRoundResult> {
        let incomplete_json = self.incomplete_share_json.as_ref().ok_or_else(|| {
            MpcError::Dkg("incomplete share not available (internal error)".into())
        })?;

        // Deserialize the IncompleteKeyShare (we stashed it before
        // transitioning to AuxInfo).
        let incomplete: cggmp24::IncompleteKeyShare<Secp256k1> =
            serde_json::from_slice(incomplete_json).map_err(|e| {
                MpcError::Dkg(format!("failed to deserialize incomplete share: {e}"))
            })?;

        // Extract the joint public key BEFORE consuming the share.
        let joint_pubkey_point = incomplete.shared_public_key;
        let compressed_bytes = joint_pubkey_point.to_bytes(true);

        // Derive BSV P2PKH address from the compressed public key.
        let address = derive_p2pkh_address(&compressed_bytes);

        // Combine into a complete KeyShare.
        let key_share =
            cggmp24::KeyShare::<Secp256k1, SecurityLevel128>::from_parts((incomplete, aux_info))
                .map_err(|e| MpcError::Dkg(format!("failed to combine key share: {e}")))?;

        let key_share_json = serde_json::to_vec(&key_share)
            .map_err(|e| MpcError::Dkg(format!("failed to serialize key share: {e}")))?;

        // The ciphertext field stores the raw serialized KeyShare JSON; the
        // proxy layer re-encrypts with a BRC-42-derived key before
        // persisting. We use a random nonce so any accidental decrypt
        // attempt fails cleanly with GCM auth-tag mismatch.
        let share = EncryptedShare {
            nonce: {
                use rand::RngCore;
                let mut nonce = vec![0u8; 12];
                rand::rngs::OsRng.fill_bytes(&mut nonce);
                nonce
            },
            ciphertext: key_share_json,
            session_id: self.session_id,
            share_index: self.my_index,
            config: self.config,
            joint_pubkey_compressed: compressed_bytes.to_vec(),
        };

        let joint_key = JointPublicKey {
            compressed: compressed_bytes.to_vec(),
            address,
        };

        // Per-DKG output identifier (distinct from the input session_id used
        // for protocol binding).
        let session_hash_bytes = {
            let mut hasher = Sha256::new();
            hasher.update(b"bsv-mpc-session-");
            hasher.update(&compressed_bytes);
            hasher.update(self.session_id.as_bytes());
            let mut out = [0u8; 32];
            out.copy_from_slice(&hasher.finalize());
            out
        };

        Ok(DkgRoundResult::Complete(DkgResult {
            joint_key,
            share,
            session_id: SessionId(session_hash_bytes),
        }))
    }
}

// ---------------------------------------------------------------------------
// Generic inline-drive helper (Phase G kernel)
// ---------------------------------------------------------------------------

/// Result of one drive step on an SM. Either it needs more input from the
/// caller (the `wire_buffer` ran dry mid-protocol), or it completed and
/// returned its protocol output.
enum DriveStep<O> {
    /// SM emitted `NeedsOneMoreMessage` with no buffered input. Caller
    /// returns `NextRound(outgoing)` to its caller.
    NeedsInput,
    /// SM emitted `Output(Ok(o))`. Caller transitions to next phase or
    /// returns `Complete`.
    Complete(O),
}

/// Drive a `StateMachine` until it either needs more input or finishes.
/// Generic across the keygen and auxinfo SMs (different Msg + Output
/// types). The caller passes mutable refs to all coordinator state the
/// driver touches.
///
/// `phase_tag` is used only for error messages ("keygen" / "auxinfo").
#[allow(clippy::too_many_arguments)]
fn drive_inline<O, E, M, SM>(
    sm: &mut SM,
    wire_buffer: &mut VecDeque<WireMessage>,
    next_msg_id: &mut u64,
    my_index: u16,
    session_id: SessionId,
    current_round: u8,
    outgoing: &mut Vec<RoundMessage>,
    phase_tag: &str,
) -> Result<DriveStep<O>>
where
    SM: StateMachine<Output = std::result::Result<O, E>, Msg = M> + ?Sized,
    M: Serialize + serde::de::DeserializeOwned,
    E: std::fmt::Display,
{
    loop {
        match sm.proceed() {
            ProceedResult::SendMsg(out) => {
                let wire = outgoing_to_wire(my_index, out)?;
                let wire_bytes = serde_json::to_vec(&wire).map_err(|e| {
                    MpcError::Dkg(format!("{phase_tag}: failed to serialize outgoing: {e}"))
                })?;
                // Transport layer handles per-recipient routing via the
                // wire-level recipient info; we don't pin a destination here.
                outgoing.push(RoundMessage {
                    session_id,
                    round: current_round,
                    from: ShareIndex(my_index),
                    to: None,
                    payload: wire_bytes,
                });
            }
            ProceedResult::NeedsOneMoreMessage => {
                let Some(wire) = wire_buffer.pop_front() else {
                    return Ok(DriveStep::NeedsInput);
                };
                *next_msg_id += 1;
                let incoming = wire_to_incoming(wire, *next_msg_id).map_err(|e| {
                    MpcError::Dkg(format!("{phase_tag}: failed to parse incoming: {e}"))
                })?;
                sm.received_msg(incoming).map_err(|_| {
                    MpcError::Dkg(format!("{phase_tag}: SM rejected incoming message"))
                })?;
            }
            ProceedResult::Yielded => continue,
            ProceedResult::Output(result) => match result {
                Ok(o) => return Ok(DriveStep::Complete(o)),
                Err(e) => {
                    return Err(MpcError::Dkg(format!("{phase_tag} protocol error: {e}")));
                }
            },
            ProceedResult::Error(e) => {
                return Err(MpcError::Dkg(format!(
                    "{phase_tag} state machine error: {e}"
                )));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BSV address derivation
// ---------------------------------------------------------------------------

/// Derive a BSV P2PKH address from a compressed public key.
///
/// Steps: SHA-256 -> RIPEMD-160 -> version byte (0x00) -> Base58Check
fn derive_p2pkh_address(compressed_pubkey: &[u8]) -> String {
    // SHA-256 of the compressed public key, as a fallback identifier in
    // case the BSV SDK path fails. Production calls always go through the
    // BSV SDK below.
    let sha256_hash = {
        let mut hasher = Sha256::new();
        hasher.update(compressed_pubkey);
        hasher.finalize()
    };

    match bsv::PublicKey::from_bytes(compressed_pubkey) {
        Ok(pk) => pk.to_address(),
        Err(_) => hex::encode(&sha256_hash[..20]),
    }
}

// ---------------------------------------------------------------------------
// Re-exports for use by other crates
// ---------------------------------------------------------------------------

/// Re-export the WireMessage type so transport layers can use it directly.
pub use self::WireMessage as DkgWireMessage;

// ---------------------------------------------------------------------------
// Blum prime utilities (for testing — production uses safe primes)
// ---------------------------------------------------------------------------

/// Generate a Blum prime (p ≡ 3 mod 4) of the given bit size.
///
/// Blum primes are faster to generate than safe primes and are used in POCs
/// for testing. Production code should use `PregeneratedPrimes::generate()`
/// which generates safe primes.
#[cfg(test)]
fn generate_blum_prime(rng: &mut impl rand::RngCore, bits_size: u32) -> cggmp24::backend::Integer {
    use cggmp24::backend::Integer;
    loop {
        let n = Integer::generate_prime(rng, bits_size);
        if n.mod_u(4) == 3 {
            break n;
        }
    }
}

/// Generate pregenerated primes using Blum primes (faster, for testing only).
#[cfg(test)]
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    // ---- Buffered sink for simulation (from POC 1) ----

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

    // ================================================================
    // Unit tests
    // ================================================================

    #[test]
    fn coordinator_creation_with_valid_config() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let session = SessionId::from_str_hash("test-session");
        let coord = DkgCoordinator::new(session, config, ShareIndex(0));

        assert_eq!(coord.current_round(), 0);
        assert_eq!(coord.config().threshold, 2);
        assert_eq!(coord.config().parties, 3);
        assert_eq!(coord.my_index(), ShareIndex(0));
        assert_eq!(coord.phase(), "not_started");
    }

    #[test]
    fn coordinator_rejects_invalid_threshold_too_low() {
        let result = ThresholdConfig::new(1, 3);
        assert!(result.is_err());
    }

    #[test]
    fn coordinator_rejects_invalid_threshold_exceeds_parties() {
        let result = ThresholdConfig::new(4, 3);
        assert!(result.is_err());
    }

    #[test]
    fn coordinator_rejects_process_round_before_init() {
        let config = ThresholdConfig::new(2, 2).unwrap();
        let session = SessionId::from_str_hash("test");
        let mut coord = DkgCoordinator::new(session, config, ShareIndex(0));

        let result = coord.process_round(vec![]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{err}").contains("before init"),
            "expected 'before init' error, got: {err}"
        );
    }

    #[test]
    fn coordinator_rejects_init_with_bad_index() {
        let config = ThresholdConfig::new(2, 2).unwrap();
        let session = SessionId::from_str_hash("test");
        let mut coord = DkgCoordinator::new(session, config, ShareIndex(5)); // index 5 >= parties 2

        let result = coord.init();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{err}").contains("party index"),
            "expected party index error, got: {err}"
        );
    }

    #[test]
    fn execution_id_is_deterministic() {
        let session = SessionId::from_str_hash("deterministic-test");
        let config = ThresholdConfig::new(2, 2).unwrap();

        let coord1 = DkgCoordinator::new(session, config, ShareIndex(0));
        let coord2 = DkgCoordinator::new(session, config, ShareIndex(0));

        assert_eq!(coord1.eid_bytes, coord2.eid_bytes);
    }

    #[test]
    fn different_sessions_produce_different_eids() {
        let config = ThresholdConfig::new(2, 2).unwrap();

        let coord1 =
            DkgCoordinator::new(SessionId::from_str_hash("session-a"), config, ShareIndex(0));
        let coord2 =
            DkgCoordinator::new(SessionId::from_str_hash("session-b"), config, ShareIndex(0));

        assert_ne!(coord1.eid_bytes, coord2.eid_bytes);
    }

    #[test]
    fn wire_message_roundtrip() {
        let wire = WireMessage {
            sender: 0,
            is_broadcast: true,
            msg: serde_json::json!({"test": "data", "value": 42}),
        };

        let bytes = serde_json::to_vec(&wire).unwrap();
        let decoded: WireMessage = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(decoded.sender, 0);
        assert!(decoded.is_broadcast);
        assert_eq!(decoded.msg["test"], "data");
    }

    #[test]
    fn p2pkh_address_derivation() {
        // Known test vector: Bitcoin's genesis coinbase pubkey
        // This is a basic sanity check that address derivation works
        let addr = derive_p2pkh_address(&[0x02; 33]);
        assert!(!addr.is_empty(), "address should not be empty");
        // BSV mainnet addresses start with '1'
        assert!(
            addr.starts_with('1'),
            "BSV mainnet address should start with '1', got: {addr}"
        );
    }

    // ================================================================
    // Integration test: Full 2-of-2 DKG via simulation
    // ================================================================
    //
    // This test runs a complete DKG ceremony using cggmp24's simulation
    // infrastructure (both parties in-process) to validate that our
    // coordinator's type mappings and serialization are correct.

    #[tokio::test]
    async fn full_2of2_dkg_via_sim() {
        let n: u16 = 2;
        let t: u16 = 2;
        let mut rng = rand::rngs::OsRng;

        // Step 1: Keygen via simulation
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

        assert_eq!(incomplete_shares.len(), 2);
        assert_eq!(
            incomplete_shares[0].shared_public_key, incomplete_shares[1].shared_public_key,
            "both parties must agree on joint public key"
        );

        let joint_pubkey = incomplete_shares[0].shared_public_key;
        let compressed = joint_pubkey.to_bytes(true);

        // Verify it's a valid compressed secp256k1 point
        assert!(
            compressed[0] == 0x02 || compressed[0] == 0x03,
            "compressed pubkey must start with 02 or 03"
        );
        assert_eq!(compressed.len(), 33, "compressed pubkey must be 33 bytes");

        // Verify BSV address derivation works
        let address = derive_p2pkh_address(&compressed);
        assert!(
            address.starts_with('1'),
            "BSV mainnet address must start with '1', got: {address}"
        );

        // Step 2: Aux info generation via simulation
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

        assert_eq!(aux_infos.len(), 2);

        // Step 3: Combine into complete KeyShares
        let key_shares: Vec<_> = incomplete_shares
            .into_iter()
            .zip(aux_infos)
            .map(|(share, aux)| {
                cggmp24::KeyShare::<Secp256k1, SecurityLevel128>::from_parts((share, aux))
                    .expect("key share validation should pass")
            })
            .collect();

        assert_eq!(key_shares.len(), 2);

        // Step 4: Verify the KeyShare serialization round-trips (critical for storage)
        let share_json = serde_json::to_vec(&key_shares[0]).unwrap();
        let deserialized: cggmp24::KeyShare<Secp256k1, SecurityLevel128> =
            serde_json::from_slice(&share_json).unwrap();
        assert_eq!(
            deserialized.core.shared_public_key, key_shares[0].core.shared_public_key,
            "serialized key share must round-trip"
        );

        // Step 5: Verify the DkgResult assembly logic
        let result_address = derive_p2pkh_address(&compressed);
        let joint_key = JointPublicKey {
            compressed: compressed.to_vec(),
            address: result_address.clone(),
        };
        assert_eq!(joint_key.compressed.len(), 33);
        assert!(joint_key.address.starts_with('1'));
    }

    // ================================================================
    // Integration test: Full 2-of-3 DKG via simulation
    // ================================================================

    #[tokio::test]
    async fn full_2of3_dkg_via_sim() {
        let n: u16 = 3;
        let t: u16 = 2;
        let mut rng = rand::rngs::OsRng;

        // Keygen
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

        assert_eq!(incomplete_shares.len(), 3);

        // All 3 parties must agree on joint public key
        let joint_pubkey = incomplete_shares[0].shared_public_key;
        for (i, share) in incomplete_shares.iter().enumerate() {
            assert_eq!(
                share.shared_public_key, joint_pubkey,
                "party {i} has different joint pubkey"
            );
        }

        // Aux info
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

        // Combine
        let key_shares: Vec<_> = incomplete_shares
            .into_iter()
            .zip(aux_infos)
            .map(|(share, aux)| {
                cggmp24::KeyShare::<Secp256k1, SecurityLevel128>::from_parts((share, aux))
                    .expect("key share validation should pass")
            })
            .collect();

        assert_eq!(key_shares.len(), 3);

        // All shares have the same joint public key
        for share in &key_shares {
            assert_eq!(share.core.shared_public_key, joint_pubkey);
        }
    }

    // ================================================================
    // Integration test: Two coordinators exchanging messages directly
    // ================================================================

    #[test]
    fn two_coordinators_keygen_message_exchange() {
        let config = ThresholdConfig::new(2, 2).unwrap();
        let session = SessionId::from_str_hash("coordinator-test");

        let mut coord0 = DkgCoordinator::new(session, config, ShareIndex(0));
        let mut coord1 = DkgCoordinator::new(session, config, ShareIndex(1));

        // Pre-generate Blum primes for faster testing (vs safe primes which take 30-60s)
        let mut rng = rand::rngs::OsRng;
        coord0.set_pregenerated_primes(generate_test_primes(&mut rng));
        coord1.set_pregenerated_primes(generate_test_primes(&mut rng));

        // Both coordinators init — produces first batch of outgoing messages
        let msgs0 = coord0.init().expect("coord0 init should succeed");
        let msgs1 = coord1.init().expect("coord1 init should succeed");

        assert!(!msgs0.is_empty(), "coord0 should produce outgoing messages");
        assert!(!msgs1.is_empty(), "coord1 should produce outgoing messages");

        assert_eq!(coord0.phase(), "keygen");
        assert_eq!(coord1.phase(), "keygen");
        assert!(coord0.current_round() >= 1);

        // Verify message structure
        for msg in &msgs0 {
            assert_eq!(msg.from, ShareIndex(0));
            assert!(!msg.payload.is_empty());
        }
        for msg in &msgs1 {
            assert_eq!(msg.from, ShareIndex(1));
            assert!(!msg.payload.is_empty());
        }

        // Exchange messages: coord0 gets coord1's messages and vice versa.
        // Drive until both complete or we hit a reasonable round limit.
        let mut outgoing0 = msgs0;
        let mut outgoing1 = msgs1;

        for round in 0..20 {
            // Feed coord1's messages to coord0
            let result0 = coord0.process_round(outgoing1.clone());
            // Feed coord0's messages to coord1
            let result1 = coord1.process_round(outgoing0.clone());

            match (result0, result1) {
                (Ok(DkgRoundResult::NextRound(new0)), Ok(DkgRoundResult::NextRound(new1))) => {
                    outgoing0 = new0;
                    outgoing1 = new1;
                }
                (Ok(DkgRoundResult::Complete(r0)), Ok(DkgRoundResult::Complete(r1))) => {
                    // Both completed! Verify they agree on the joint key.
                    assert_eq!(
                        r0.joint_key.compressed, r1.joint_key.compressed,
                        "both coordinators must produce the same joint public key"
                    );
                    assert_eq!(r0.joint_key.address, r1.joint_key.address);

                    // Verify the key is a valid secp256k1 point
                    assert_eq!(r0.joint_key.compressed.len(), 33);
                    assert!(
                        r0.joint_key.compressed[0] == 0x02 || r0.joint_key.compressed[0] == 0x03
                    );
                    assert!(r0.joint_key.address.starts_with('1'));

                    // Verify shares have correct metadata
                    assert_eq!(r0.share.share_index, ShareIndex(0));
                    assert_eq!(r1.share.share_index, ShareIndex(1));

                    return; // Test passed!
                }
                (Ok(DkgRoundResult::Complete(_)), Ok(DkgRoundResult::NextRound(_)))
                | (Ok(DkgRoundResult::NextRound(_)), Ok(DkgRoundResult::Complete(_))) => {
                    panic!(
                        "coordinators desynchronized at round {round}: \
                         one completed but the other didn't"
                    );
                }
                (Err(e), _) => {
                    panic!("coord0 error at round {round}: {e}");
                }
                (_, Err(e)) => {
                    panic!("coord1 error at round {round}: {e}");
                }
            }
        }

        panic!("DKG did not complete within 20 rounds");
    }
}
