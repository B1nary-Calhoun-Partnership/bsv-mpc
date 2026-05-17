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
//!    due to safe prime generation.
//!
//! After both complete, the results are combined via `KeyShare::from_parts()`
//! into a complete `KeyShare` that can be used for signing.
//!
//! ## State Machine Architecture
//!
//! The cggmp24 protocol is driven by `round_based::state_machine::StateMachine`,
//! which is `!Send` (cannot cross tokio task boundaries). The coordinator solves
//! this by running the SM in a dedicated `std::thread`, bridged to the async
//! caller via `std::sync::mpsc` channels.
//!
//! The caller's view is simple:
//! 1. Call `init()` to start and get the first outgoing messages.
//! 2. Call `process_round(incoming)` repeatedly until `Complete`.
//!
//! Internally, each call feeds messages to the SM thread and collects its output.
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

use std::sync::mpsc;
use std::thread;

use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use round_based::state_machine::{ProceedResult, StateMachine};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tracing;

use crate::error::{MpcError, Result};
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
// Channel message types between coordinator and SM thread
// ---------------------------------------------------------------------------

/// Messages sent from the coordinator to the SM thread.
enum SmInbound {
    /// Feed an incoming wire message to the state machine.
    IncomingMessage(Vec<u8>),
}

/// Messages sent from the SM thread back to the coordinator.
enum SmOutbound {
    /// The SM produced an outgoing wire message.
    OutgoingMessage(Vec<u8>),
    /// The SM needs one more incoming message before it can proceed.
    NeedsMessage,
    /// The keygen sub-protocol completed. Contains the serialized IncompleteKeyShare.
    KeygenComplete(Vec<u8>),
    /// The aux info sub-protocol completed. Contains the serialized AuxInfo.
    AuxInfoComplete(Vec<u8>),
    /// The SM encountered an error.
    Error(String),
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
/// Each phase runs as a `round_based::StateMachine` in a dedicated thread
/// (the SM is `!Send`), communicating with this coordinator via channels.
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

    // Channel handles for communicating with the SM thread.
    // These are None before init() and after completion.
    /// Send incoming messages to the SM thread.
    sm_tx: Option<mpsc::Sender<SmInbound>>,
    /// Receive outgoing messages and status from the SM thread.
    sm_rx: Option<mpsc::Receiver<SmOutbound>>,
    /// Handle to the SM thread (for join on completion or error).
    sm_thread: Option<thread::JoinHandle<()>>,

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
    /// Use `set_pregenerated_primes()` to provide them.
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
            sm_tx: None,
            sm_rx: None,
            sm_thread: None,
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

    /// Initialize the DKG ceremony by starting the keygen sub-protocol.
    ///
    /// This spawns a background thread running the cggmp24 keygen state machine,
    /// then collects and returns the first batch of outgoing messages.
    ///
    /// # Returns
    ///
    /// A vector of [`RoundMessage`]s to send to all other parties.
    ///
    /// # Errors
    ///
    /// Returns [`MpcError::Dkg`] if the keygen state machine fails to start.
    pub fn init(&mut self) -> Result<Vec<RoundMessage>> {
        if self.phase != DkgPhase::NotStarted {
            return Err(MpcError::Dkg(
                "init() called but DKG already started".into(),
            ));
        }

        // Validate party index is in range
        if self.my_index.0 >= self.config.parties {
            return Err(MpcError::Dkg(format!(
                "party index {} >= total parties {}",
                self.my_index.0, self.config.parties
            )));
        }

        self.phase = DkgPhase::Keygen;
        self.current_round = 1;

        self.start_keygen_sm()?;
        self.collect_outgoing_messages()
    }

    /// Process incoming messages from the current round and advance the protocol.
    ///
    /// This feeds the incoming messages to the running state machine and collects
    /// its outgoing messages. When a sub-protocol completes (keygen or aux info),
    /// the coordinator automatically transitions to the next phase.
    ///
    /// # Arguments
    ///
    /// * `messages` -- All messages received for the current round from other parties.
    ///
    /// # Returns
    ///
    /// [`DkgRoundResult::NextRound`] with outgoing messages, or
    /// [`DkgRoundResult::Complete`] with the final DKG result.
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

        // Feed all incoming messages to the SM thread
        let tx = self
            .sm_tx
            .as_ref()
            .ok_or_else(|| MpcError::Dkg("SM channel not available (internal error)".into()))?;

        for msg in &messages {
            let wire_bytes = &msg.payload;
            tx.send(SmInbound::IncomingMessage(wire_bytes.clone()))
                .map_err(|e| MpcError::Dkg(format!("failed to send to SM thread: {e}")))?;
        }

        // Collect outgoing messages from the SM
        self.collect_round_result()
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

    /// Get the current protocol phase.
    pub fn phase(&self) -> &str {
        match self.phase {
            DkgPhase::NotStarted => "not_started",
            DkgPhase::Keygen => "keygen",
            DkgPhase::AuxInfo => "aux_info",
            DkgPhase::Complete => "complete",
        }
    }

    // -----------------------------------------------------------------------
    // Internal: Start the keygen state machine in a background thread
    // -----------------------------------------------------------------------

    fn start_keygen_sm(&mut self) -> Result<()> {
        let (inbound_tx, inbound_rx) = mpsc::channel::<SmInbound>();
        let (outbound_tx, outbound_rx) = mpsc::channel::<SmOutbound>();

        let eid_bytes = self.eid_bytes;
        let my_index = self.my_index.0;
        let n = self.config.parties;
        let t = self.config.threshold;

        let thread_handle = thread::Builder::new()
            .name(format!("dkg-keygen-{my_index}"))
            .spawn(move || {
                run_keygen_sm(eid_bytes, my_index, n, t, inbound_rx, outbound_tx);
            })
            .map_err(|e| MpcError::Dkg(format!("failed to spawn keygen thread: {e}")))?;

        self.sm_tx = Some(inbound_tx);
        self.sm_rx = Some(outbound_rx);
        self.sm_thread = Some(thread_handle);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal: Start the aux info state machine in a background thread
    // -----------------------------------------------------------------------

    fn start_aux_info_sm(&mut self) -> Result<()> {
        let (inbound_tx, inbound_rx) = mpsc::channel::<SmInbound>();
        let (outbound_tx, outbound_rx) = mpsc::channel::<SmOutbound>();

        // Canonical ExecutionId per MPC-Spec §02.2 for phase=DkgAuxInfo.
        // §02.4 requires the keygen-output joint pubkey here (auxinfo is
        // a non-keygen phase, so the all-zero carve-out does NOT apply).
        let joint_pubkey = self.keygen_joint_pubkey.ok_or_else(|| {
            MpcError::Dkg(
                "keygen joint pubkey not captured — start_aux_info_sm called \
                 before KeygenComplete (internal error)"
                    .into(),
            )
        })?;
        let aux_eid_bytes =
            crate::canonical::canonical_execution_id(&crate::canonical::ExecutionParams::new_v1(
                crate::canonical::PhaseTag::DkgAuxInfo,
                self.session_id,
                joint_pubkey,
            ));

        let my_index = self.my_index.0;
        let n = self.config.parties;
        let primes = self.pregenerated_primes.take();

        let thread_handle = thread::Builder::new()
            .name(format!("dkg-auxinfo-{my_index}"))
            .spawn(move || {
                run_aux_info_sm(aux_eid_bytes, my_index, n, primes, inbound_rx, outbound_tx);
            })
            .map_err(|e| MpcError::Dkg(format!("failed to spawn aux info thread: {e}")))?;

        // Drop old channel handles (keygen thread already exited)
        self.sm_tx = Some(inbound_tx);
        self.sm_rx = Some(outbound_rx);
        self.sm_thread = Some(thread_handle);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal: Collect outgoing messages from the SM thread
    // -----------------------------------------------------------------------

    /// Collect the initial batch of outgoing messages after starting a phase.
    fn collect_outgoing_messages(&mut self) -> Result<Vec<RoundMessage>> {
        let rx = self
            .sm_rx
            .as_ref()
            .ok_or_else(|| MpcError::Dkg("SM channel not available (internal error)".into()))?;

        let mut outgoing = Vec::new();

        loop {
            let msg = rx.recv().map_err(|e| {
                MpcError::Dkg(format!("SM thread channel closed unexpectedly: {e}"))
            })?;

            match msg {
                SmOutbound::OutgoingMessage(wire_bytes) => {
                    outgoing.push(self.wire_bytes_to_round_message(wire_bytes)?);
                }
                SmOutbound::NeedsMessage => {
                    // SM is waiting for incoming messages — return what we have
                    break;
                }
                SmOutbound::KeygenComplete(_share_json) => {
                    // Keygen finished on first call — unusual but handle it.
                    // This shouldn't happen for threshold keygen which always needs
                    // at least one round of message exchange.
                    return Err(MpcError::Dkg(
                        "keygen completed without any rounds (unexpected)".into(),
                    ));
                }
                SmOutbound::AuxInfoComplete(_) => {
                    return Err(MpcError::Dkg(
                        "aux info completed on first call (unexpected)".into(),
                    ));
                }
                SmOutbound::Error(e) => {
                    return Err(MpcError::Dkg(e));
                }
            }
        }

        Ok(outgoing)
    }

    /// Collect messages after feeding incoming messages for a round.
    /// Handles phase transitions (keygen -> aux_info -> complete).
    fn collect_round_result(&mut self) -> Result<DkgRoundResult> {
        let rx = self
            .sm_rx
            .as_ref()
            .ok_or_else(|| MpcError::Dkg("SM channel not available (internal error)".into()))?;

        let mut outgoing = Vec::new();

        loop {
            let msg = rx.recv().map_err(|e| {
                MpcError::Dkg(format!("SM thread channel closed unexpectedly: {e}"))
            })?;

            match msg {
                SmOutbound::OutgoingMessage(wire_bytes) => {
                    outgoing.push(self.wire_bytes_to_round_message(wire_bytes)?);
                }
                SmOutbound::NeedsMessage => {
                    // SM needs more input — return outgoing messages collected so far
                    self.current_round += 1;
                    return Ok(DkgRoundResult::NextRound(outgoing));
                }
                SmOutbound::KeygenComplete(share_json) => {
                    tracing::info!(
                        party = self.my_index.0,
                        "keygen phase complete, starting aux info generation"
                    );

                    // Capture the joint pubkey from the keygen output so the
                    // auxinfo phase can derive its canonical ExecutionId per
                    // MPC-Spec §02.4. Deserialize just to peek at
                    // `shared_public_key`; the bytes stay stored for
                    // assemble_dkg_result.
                    let peek: cggmp24::IncompleteKeyShare<Secp256k1> =
                        serde_json::from_slice(&share_json).map_err(|e| {
                            MpcError::Dkg(format!(
                                "failed to peek joint pubkey from keygen output: {e}"
                            ))
                        })?;
                    let compressed = peek.shared_public_key.to_bytes(true);
                    if compressed.len() != 33 {
                        return Err(MpcError::Dkg(format!(
                            "keygen joint pubkey is not 33 bytes (got {})",
                            compressed.len()
                        )));
                    }
                    let mut jpk = [0u8; 33];
                    jpk.copy_from_slice(&compressed);
                    self.keygen_joint_pubkey = Some(jpk);

                    // Store the incomplete share and clean up keygen thread
                    self.incomplete_share_json = Some(share_json);
                    self.cleanup_sm_thread();

                    // Transition to aux info phase
                    self.phase = DkgPhase::AuxInfo;
                    self.start_aux_info_sm()?;

                    // Collect the first outgoing messages from aux info
                    let aux_msgs = self.collect_outgoing_messages()?;

                    // Combine any remaining keygen outgoing msgs with aux info msgs
                    outgoing.extend(aux_msgs);
                    self.current_round += 1;

                    return Ok(DkgRoundResult::NextRound(outgoing));
                }
                SmOutbound::AuxInfoComplete(aux_info_json) => {
                    tracing::info!(
                        party = self.my_index.0,
                        "aux info phase complete, assembling KeyShare"
                    );

                    self.cleanup_sm_thread();
                    self.phase = DkgPhase::Complete;

                    // Assemble the final DKG result
                    return self.assemble_dkg_result(aux_info_json);
                }
                SmOutbound::Error(e) => {
                    self.cleanup_sm_thread();
                    return Err(MpcError::Dkg(e));
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal: Convert wire bytes to RoundMessage
    // -----------------------------------------------------------------------

    fn wire_bytes_to_round_message(&self, wire_bytes: Vec<u8>) -> Result<RoundMessage> {
        // Peek at the wire message to extract routing info
        let wire: WireMessage = serde_json::from_slice(&wire_bytes)
            .map_err(|e| MpcError::Dkg(format!("failed to parse wire message: {e}")))?;

        Ok(RoundMessage {
            session_id: self.session_id,
            round: self.current_round,
            from: ShareIndex(wire.sender),
            to: if wire.is_broadcast {
                None
            } else {
                // For p2p messages in a 2-party setup, the recipient is the other party.
                // In general, we don't know the specific recipient from WireMessage alone,
                // since round_based::Outgoing uses Recipient enum which may specify an index.
                // The transport layer handles routing based on the to field.
                None // Let transport layer figure out routing from the wire message itself
            },
            payload: wire_bytes,
        })
    }

    // -----------------------------------------------------------------------
    // Internal: Assemble the final DKG result
    // -----------------------------------------------------------------------

    fn assemble_dkg_result(&self, aux_info_json: Vec<u8>) -> Result<DkgRoundResult> {
        let incomplete_json = self.incomplete_share_json.as_ref().ok_or_else(|| {
            MpcError::Dkg("incomplete share not available (internal error)".into())
        })?;

        // Deserialize the IncompleteKeyShare
        let incomplete: cggmp24::IncompleteKeyShare<Secp256k1> =
            serde_json::from_slice(incomplete_json).map_err(|e| {
                MpcError::Dkg(format!("failed to deserialize incomplete share: {e}"))
            })?;

        // Deserialize the AuxInfo
        let aux_info: cggmp24::key_share::AuxInfo<SecurityLevel128> =
            serde_json::from_slice(&aux_info_json)
                .map_err(|e| MpcError::Dkg(format!("failed to deserialize aux info: {e}")))?;

        // Extract the joint public key BEFORE consuming the share
        let joint_pubkey_point = incomplete.shared_public_key;
        let compressed_bytes = joint_pubkey_point.to_bytes(true);

        // Derive BSV P2PKH address from the compressed public key
        let address = derive_p2pkh_address(&compressed_bytes);

        // Combine into a complete KeyShare
        let key_share =
            cggmp24::KeyShare::<Secp256k1, SecurityLevel128>::from_parts((incomplete, aux_info))
                .map_err(|e| MpcError::Dkg(format!("failed to combine key share: {e}")))?;

        // Serialize the complete KeyShare for storage
        let key_share_json = serde_json::to_vec(&key_share)
            .map_err(|e| MpcError::Dkg(format!("failed to serialize key share: {e}")))?;

        // Encrypt the key share for persistent storage.
        // We use a placeholder encryption key here — the caller should re-encrypt
        // with a proper BRC-42 derived key before persisting.
        // NOTE: The ciphertext is NOT actually encrypted here — it contains
        // the raw serialized KeyShare JSON. The caller (proxy layer) must
        // re-encrypt with a BRC-42 derived key before persisting.
        // We use a random nonce (not zeros) so that any accidental attempt
        // to decrypt with a real key fails cleanly with GCM auth tag mismatch.
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

        // Compute session ID as SHA-256 of the joint public key bytes
        // (in production this would include the full DKG transcript)
        // Re-derive the DKG-output session_id by hashing the joint pubkey
        // with the input session_id. This is a per-DKG "output identifier"
        // distinct from the input session_id used for protocol binding.
        // (Wire-canonical SessionId for the *next* ceremony is computed at
        // its boundary via `crate::canonical::canonical_session_id`.)
        let session_hash_bytes = {
            let mut hasher = sha2::Sha256::new();
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

    // -----------------------------------------------------------------------
    // Internal: Thread cleanup
    // -----------------------------------------------------------------------

    fn cleanup_sm_thread(&mut self) {
        // Drop the sender to signal the thread to exit
        self.sm_tx.take();
        self.sm_rx.take();

        // Join the thread if it's still running
        if let Some(handle) = self.sm_thread.take() {
            // Don't block indefinitely — the thread should exit quickly
            // once its channel is dropped
            let _ = handle.join();
        }
    }
}

impl Drop for DkgCoordinator {
    fn drop(&mut self) {
        self.cleanup_sm_thread();
    }
}

// ---------------------------------------------------------------------------
// State machine thread functions
// ---------------------------------------------------------------------------

/// Run the keygen state machine in a dedicated thread.
///
/// This function blocks the thread, driving the SM via `proceed()` and
/// communicating with the coordinator via channels.
fn run_keygen_sm(
    eid_bytes: [u8; 32],
    my_index: u16,
    n: u16,
    t: u16,
    inbound_rx: mpsc::Receiver<SmInbound>,
    outbound_tx: mpsc::Sender<SmOutbound>,
) {
    let eid = ExecutionId::new(&eid_bytes);

    // Create the keygen state machine via wrap_protocol
    let mut sm = round_based::state_machine::wrap_protocol(|party| async move {
        cggmp24::keygen::<Secp256k1>(eid, my_index, n)
            .set_threshold(t)
            .start(&mut rand::rngs::OsRng, party)
            .await
    });

    let mut msg_id: u64 = 0;
    let mut wire_buffer: std::collections::VecDeque<WireMessage> =
        std::collections::VecDeque::new();

    loop {
        match sm.proceed() {
            ProceedResult::SendMsg(outgoing) => {
                let wire = match outgoing_to_wire(my_index, outgoing) {
                    Ok(w) => w,
                    Err(e) => {
                        let _ = outbound_tx.send(SmOutbound::Error(format!(
                            "keygen: failed to create wire message: {e}"
                        )));
                        return;
                    }
                };
                let wire_bytes = match serde_json::to_vec(&wire) {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = outbound_tx.send(SmOutbound::Error(format!(
                            "keygen: failed to serialize outgoing: {e}"
                        )));
                        return;
                    }
                };
                if outbound_tx
                    .send(SmOutbound::OutgoingMessage(wire_bytes))
                    .is_err()
                {
                    return; // Coordinator dropped its receiver
                }
            }
            ProceedResult::NeedsOneMoreMessage => {
                let wire = if let Some(w) = wire_buffer.pop_front() {
                    w
                } else {
                    if outbound_tx.send(SmOutbound::NeedsMessage).is_err() {
                        return;
                    }
                    let inbound = match inbound_rx.recv() {
                        Ok(msg) => msg,
                        Err(_) => return,
                    };
                    match inbound {
                        SmInbound::IncomingMessage(wire_bytes) => {
                            let mut wires: std::collections::VecDeque<WireMessage> =
                                if wire_bytes.first() == Some(&b'[') {
                                    match serde_json::from_slice::<Vec<WireMessage>>(&wire_bytes) {
                                        Ok(v) => v.into(),
                                        Err(e) => {
                                            let _ = outbound_tx.send(SmOutbound::Error(format!(
                                            "keygen: failed to deserialize bundled incoming: {e}"
                                        )));
                                            return;
                                        }
                                    }
                                } else {
                                    match serde_json::from_slice::<WireMessage>(&wire_bytes) {
                                        Ok(w) => {
                                            let mut d = std::collections::VecDeque::new();
                                            d.push_back(w);
                                            d
                                        }
                                        Err(e) => {
                                            let _ = outbound_tx.send(SmOutbound::Error(format!(
                                                "keygen: failed to deserialize incoming: {e}"
                                            )));
                                            return;
                                        }
                                    }
                                };
                            let first = match wires.pop_front() {
                                Some(w) => w,
                                None => {
                                    let _ = outbound_tx
                                        .send(SmOutbound::Error("keygen: empty bundle".into()));
                                    return;
                                }
                            };
                            wire_buffer.extend(wires);
                            first
                        }
                    }
                };
                msg_id += 1;
                let incoming = match wire_to_incoming(wire, msg_id) {
                    Ok(inc) => inc,
                    Err(e) => {
                        let _ = outbound_tx.send(SmOutbound::Error(format!(
                            "keygen: failed to parse incoming message: {e}"
                        )));
                        return;
                    }
                };
                if sm.received_msg(incoming).is_err() {
                    let _ = outbound_tx.send(SmOutbound::Error(
                        "keygen: SM rejected incoming message".into(),
                    ));
                    return;
                }
            }
            ProceedResult::Yielded => {}
            ProceedResult::Output(result) => {
                match result {
                    Ok(incomplete_share) => {
                        let share_json = match serde_json::to_vec(&incomplete_share) {
                            Ok(j) => j,
                            Err(e) => {
                                let _ = outbound_tx.send(SmOutbound::Error(format!(
                                    "keygen: failed to serialize share: {e}"
                                )));
                                return;
                            }
                        };
                        let _ = outbound_tx.send(SmOutbound::KeygenComplete(share_json));
                    }
                    Err(e) => {
                        let _ = outbound_tx
                            .send(SmOutbound::Error(format!("keygen protocol error: {e:?}")));
                    }
                }
                return;
            }
            ProceedResult::Error(e) => {
                let _ = outbound_tx.send(SmOutbound::Error(format!(
                    "keygen state machine error: {e}"
                )));
                return;
            }
        }
    }
}

/// Run the aux info generation state machine in a dedicated thread.
///
/// This generates Paillier primes (expensive!) and then runs the
/// aux info protocol to produce `AuxInfo`.
fn run_aux_info_sm(
    eid_bytes: [u8; 32],
    my_index: u16,
    n: u16,
    pregenerated_primes: Option<cggmp24::PregeneratedPrimes<SecurityLevel128>>,
    inbound_rx: mpsc::Receiver<SmInbound>,
    outbound_tx: mpsc::Sender<SmOutbound>,
) {
    let eid = ExecutionId::new(&eid_bytes);

    // Use pre-generated primes if provided, otherwise generate safe primes.
    // Safe prime generation is the EXPENSIVE part — can take 10-60 seconds.
    let pregenerated = match pregenerated_primes {
        Some(primes) => {
            tracing::info!(party = my_index, "using pre-generated Paillier primes");
            primes
        }
        None => {
            tracing::info!(
                party = my_index,
                "generating Paillier safe primes (this may take 30-60s)..."
            );
            let primes =
                cggmp24::PregeneratedPrimes::<SecurityLevel128>::generate(&mut rand::rngs::OsRng);
            tracing::info!(party = my_index, "Paillier prime generation complete");
            primes
        }
    };

    // Create the aux info state machine
    let mut sm = round_based::state_machine::wrap_protocol(|party| async move {
        cggmp24::aux_info_gen(eid, my_index, n, pregenerated)
            .start(&mut rand::rngs::OsRng, party)
            .await
    });

    let mut msg_id: u64 = 0;
    let mut wire_buffer: std::collections::VecDeque<WireMessage> =
        std::collections::VecDeque::new();

    loop {
        match sm.proceed() {
            ProceedResult::SendMsg(outgoing) => {
                let wire = match outgoing_to_wire(my_index, outgoing) {
                    Ok(w) => w,
                    Err(e) => {
                        let _ = outbound_tx.send(SmOutbound::Error(format!(
                            "auxinfo: failed to create wire message: {e}"
                        )));
                        return;
                    }
                };
                let wire_bytes = match serde_json::to_vec(&wire) {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = outbound_tx.send(SmOutbound::Error(format!(
                            "auxinfo: failed to serialize outgoing: {e}"
                        )));
                        return;
                    }
                };
                if outbound_tx
                    .send(SmOutbound::OutgoingMessage(wire_bytes))
                    .is_err()
                {
                    return;
                }
            }
            ProceedResult::NeedsOneMoreMessage => {
                let wire = if let Some(w) = wire_buffer.pop_front() {
                    w
                } else {
                    if outbound_tx.send(SmOutbound::NeedsMessage).is_err() {
                        return;
                    }
                    let inbound = match inbound_rx.recv() {
                        Ok(msg) => msg,
                        Err(_) => return,
                    };
                    match inbound {
                        SmInbound::IncomingMessage(wire_bytes) => {
                            let mut wires: std::collections::VecDeque<WireMessage> =
                                if wire_bytes.first() == Some(&b'[') {
                                    match serde_json::from_slice::<Vec<WireMessage>>(&wire_bytes) {
                                        Ok(v) => v.into(),
                                        Err(e) => {
                                            let _ = outbound_tx.send(SmOutbound::Error(format!(
                                            "auxinfo: failed to deserialize bundled incoming: {e}"
                                        )));
                                            return;
                                        }
                                    }
                                } else {
                                    match serde_json::from_slice::<WireMessage>(&wire_bytes) {
                                        Ok(w) => {
                                            let mut d = std::collections::VecDeque::new();
                                            d.push_back(w);
                                            d
                                        }
                                        Err(e) => {
                                            let _ = outbound_tx.send(SmOutbound::Error(format!(
                                                "auxinfo: failed to deserialize incoming: {e}"
                                            )));
                                            return;
                                        }
                                    }
                                };
                            let first = match wires.pop_front() {
                                Some(w) => w,
                                None => {
                                    let _ = outbound_tx
                                        .send(SmOutbound::Error("auxinfo: empty bundle".into()));
                                    return;
                                }
                            };
                            wire_buffer.extend(wires);
                            first
                        }
                    }
                };
                msg_id += 1;
                let incoming = match wire_to_incoming(wire, msg_id) {
                    Ok(inc) => inc,
                    Err(e) => {
                        let _ = outbound_tx.send(SmOutbound::Error(format!(
                            "auxinfo: failed to parse incoming message: {e}"
                        )));
                        return;
                    }
                };
                if sm.received_msg(incoming).is_err() {
                    let _ = outbound_tx.send(SmOutbound::Error(
                        "auxinfo: SM rejected incoming message".into(),
                    ));
                    return;
                }
            }
            ProceedResult::Yielded => {}
            ProceedResult::Output(result) => {
                match result {
                    Ok(aux_info) => {
                        let aux_json = match serde_json::to_vec(&aux_info) {
                            Ok(j) => j,
                            Err(e) => {
                                let _ = outbound_tx.send(SmOutbound::Error(format!(
                                    "auxinfo: failed to serialize aux info: {e}"
                                )));
                                return;
                            }
                        };
                        let _ = outbound_tx.send(SmOutbound::AuxInfoComplete(aux_json));
                    }
                    Err(e) => {
                        let _ = outbound_tx
                            .send(SmOutbound::Error(format!("aux info protocol error: {e:?}")));
                    }
                }
                return;
            }
            ProceedResult::Error(e) => {
                let _ = outbound_tx.send(SmOutbound::Error(format!(
                    "aux info state machine error: {e}"
                )));
                return;
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
    use sha2::Sha256 as Sha256Hasher;

    // Step 1: SHA-256 of the compressed public key
    let sha256_hash = {
        let mut hasher = Sha256Hasher::new();
        hasher.update(compressed_pubkey);
        hasher.finalize()
    };

    // Step 2: RIPEMD-160 of the SHA-256 hash
    // We implement RIPEMD-160 manually since we don't want to pull in another
    // dependency. Instead, use the BSV SDK if available, or compute inline.
    // For now, use a simple approach: the BSV SDK's PublicKey handles this.
    //
    // Try to use bsv::PublicKey for address derivation (most reliable).
    match bsv::PublicKey::from_bytes(compressed_pubkey) {
        Ok(pk) => pk.to_address(),
        Err(_) => {
            // Fallback: return hex of the pubkey hash if BSV SDK fails
            // (should not happen for valid secp256k1 points)
            hex::encode(&sha256_hash[..20])
        }
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
    //
    // It does NOT test the coordinator's channel-based architecture
    // (that requires the HTTP transport pattern from POC 5).
    // Instead, it validates the underlying crypto works end-to-end.

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
    //
    // This is the most important test — it validates that our coordinator
    // API works correctly for 2-party DKG with message exchange.
    // We run two DkgCoordinators and manually relay messages between them.

    #[test]
    fn two_coordinators_keygen_message_exchange() {
        // This test validates that init() produces messages and that the
        // coordinator state machine can be driven through the keygen phase.
        // We use two coordinators and relay messages between them.

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
                    // One completed before the other — this can happen during
                    // the keygen→auxinfo transition. Keep driving.
                    // In practice, both parties should complete in the same round
                    // but the aux info phase transition may desync by one round.
                    panic!(
                        "coordinators desynchronized at round {round}: \
                         one completed but the other didn't"
                    );
                }
                (Err(e), _) => {
                    // Keygen or aux info error — this is expected behavior
                    // during the first round exchange if messages are in wrong format.
                    // For this basic test, any error is interesting info.
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
