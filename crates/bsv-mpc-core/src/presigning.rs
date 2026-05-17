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
//! ## Usage
//!
//! The presigning protocol is cooperative — it requires communication with
//! other parties. The manager exposes an `init_generate` / `process_generate_round`
//! API (same pattern as `DkgCoordinator` and `SigningCoordinator`) so the
//! transport layer can relay messages.
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
//!         PresigningRoundResult::Complete => break, // presig added to pool
//!     }
//! }
//!
//! // Consume for signing
//! if let Some(presig) = mgr.take() {
//!     coordinator.sign(&sighash, Some(presig))?;
//! }
//! ```

use std::sync::mpsc;
use std::thread;

use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use round_based::state_machine::{ProceedResult, StateMachine};
use sha2::Digest;

use crate::dkg::{outgoing_to_wire, wire_to_incoming, WireMessage};
use crate::error::{MpcError, Result};
use crate::types::{EncryptedShare, Presignature, RoundMessage, SessionId, ShareIndex};

// ---------------------------------------------------------------------------
// Channel message types between manager and SM thread
// ---------------------------------------------------------------------------

/// Messages sent from the manager to the SM thread.
enum SmInbound {
    /// Feed an incoming wire message to the state machine.
    IncomingMessage(Vec<u8>),
}

/// Messages sent from the SM thread back to the manager.
enum SmOutbound {
    /// The SM produced an outgoing wire message.
    OutgoingMessage(Vec<u8>),
    /// The SM needs one more incoming message before it can proceed.
    NeedsMessage,
    /// Presigning protocol completed successfully.
    /// The presignature data is passed as `Box<dyn Any + Send>` because
    /// cggmp24's `PresignaturePublicData` doesn't implement `Serialize`.
    /// The concrete type is `(cggmp24::Presignature<E>, PresignaturePublicData<E>)`.
    PresigningComplete(Box<dyn std::any::Any + Send>),
    /// The SM encountered an error.
    Error(String),
}

// ---------------------------------------------------------------------------
// PresigningRoundResult
// ---------------------------------------------------------------------------

/// Result of processing a presigning round.
#[derive(Debug)]
pub enum PresigningRoundResult {
    /// The protocol needs another round. Contains outgoing messages to send.
    NextRound(Vec<RoundMessage>),
    /// Presigning is complete. The presignature has been added to the pool.
    Complete,
}

// ---------------------------------------------------------------------------
// Presigning generation state
// ---------------------------------------------------------------------------

/// Tracks the state of an in-progress presigning generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GenerateState {
    /// No generation in progress.
    Idle,
    /// Generation is running (SM thread active).
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
/// # Generation
///
/// Presignature generation uses the same SM thread bridge pattern as
/// `DkgCoordinator` and `SigningCoordinator`:
///
/// 1. Call [`init_generate`](Self::init_generate) to start the presigning SM.
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

    // SM bridge (active during generation)
    /// Send incoming messages to the SM thread.
    sm_tx: Option<mpsc::Sender<SmInbound>>,
    /// Receive outgoing messages and status from the SM thread.
    sm_rx: Option<mpsc::Receiver<SmOutbound>>,
    /// Handle to the SM thread.
    sm_thread: Option<thread::JoinHandle<()>>,
}

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
            sm_tx: None,
            sm_rx: None,
            sm_thread: None,
        }
    }

    /// Start a new presignature generation (3-round protocol).
    ///
    /// Spawns the SM thread running cggmp24's presigning state machine,
    /// collects initial outgoing messages, and returns them for broadcast.
    ///
    /// Only one generation can be in progress at a time. Call
    /// [`process_generate_round`](Self::process_generate_round) to drive
    /// the protocol to completion.
    ///
    /// # Errors
    ///
    /// Returns [`MpcError::Protocol`] if a generation is already in progress,
    /// the pool is full, or the SM fails to start.
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

        // Validate our share index is in the participants list
        let _my_signing_index = self
            .participants
            .iter()
            .position(|&p| p == self.share.share_index.0)
            .ok_or_else(|| {
                MpcError::Protocol(format!(
                    "share index {} not found in participants {:?}",
                    self.share.share_index.0, self.participants
                ))
            })? as u16;

        self.generate_state = GenerateState::Running;
        self.current_round = 1;

        self.start_presigning_sm()?;
        self.collect_outgoing_messages()
    }

    /// Process incoming messages for the current presigning round.
    ///
    /// Feeds messages to the SM thread and collects results. When the SM
    /// completes, the presignature is automatically added to the pool and
    /// `PresigningRoundResult::Complete` is returned.
    ///
    /// # Arguments
    ///
    /// * `messages` — All messages received for the current round from other parties.
    ///
    /// # Returns
    ///
    /// [`PresigningRoundResult::NextRound`] with outgoing messages, or
    /// [`PresigningRoundResult::Complete`] when the presignature is ready.
    pub fn process_generate_round(
        &mut self,
        messages: Vec<RoundMessage>,
    ) -> Result<PresigningRoundResult> {
        if self.generate_state != GenerateState::Running {
            return Err(MpcError::Protocol(
                "process_generate_round() called but no generation in progress".into(),
            ));
        }

        // Feed all incoming messages to the SM thread
        let tx = self.sm_tx.as_ref().ok_or_else(|| {
            MpcError::Protocol("SM channel not available (internal error)".into())
        })?;

        for msg in &messages {
            tx.send(SmInbound::IncomingMessage(msg.payload.clone()))
                .map_err(|e| {
                    MpcError::Protocol(format!("failed to send to presigning SM thread: {e}"))
                })?;
        }

        self.collect_round_result()
    }

    /// Take one presignature from the pool for use in online signing.
    ///
    /// Presignatures are consumed in FIFO order (oldest first). Each
    /// presignature can only be used once — reusing a presignature would
    /// leak the private key (nonce reuse attack).
    ///
    /// Returns `None` if the pool is empty. In that case, the caller should
    /// either wait for generation to complete or fall back to the 4-round
    /// interactive signing protocol.
    pub fn take(&mut self) -> Option<Presignature> {
        if self.pool.is_empty() {
            None
        } else {
            // Remove from both pools in FIFO order (oldest first).
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
    /// `round_based::sim` in tests) and need to be added to the pool.
    /// No raw data is stored — only the metadata wrapper.
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
    /// The caller should trigger background presigning when this returns `true`.
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
    // Internal: Start the presigning state machine in a background thread
    // -----------------------------------------------------------------------

    fn start_presigning_sm(&mut self) -> Result<()> {
        let (inbound_tx, inbound_rx) = mpsc::channel::<SmInbound>();
        let (outbound_tx, outbound_rx) = mpsc::channel::<SmOutbound>();

        let my_signing_index = self
            .participants
            .iter()
            .position(|&p| p == self.share.share_index.0)
            .ok_or_else(|| {
                MpcError::Protocol(format!(
                    "share index {} not found in participants {:?}",
                    self.share.share_index.0, self.participants
                ))
            })? as u16;

        // Canonical ExecutionId per MPC-Spec §02.2 with phase=Presign and
        // the joint pubkey from the share. The eid_counter is mixed in via
        // a per-generation per-pool nonce so multiple presig generations
        // within the same session produce distinct EIDs.
        //
        // CGGMP'24 forbids EID reuse across protocol executions — so we
        // sub-derive: canonical_eid_pre = canonical(Phase=Presign, joint_pk)
        // and then mix in the counter via SHA-256.
        self.eid_counter += 1;
        let canonical_eid =
            crate::canonical::canonical_execution_id(&crate::canonical::ExecutionParams::new_v1(
                crate::canonical::PhaseTag::Presign,
                self.session_id,
                crate::signing::share_joint_pubkey_or_zero(&self.share, "presigning"),
            ));
        let eid_bytes = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(canonical_eid);
            hasher.update(self.eid_counter.to_be_bytes());
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&hasher.finalize());
            bytes
        };

        let participants = self.participants.clone();
        let key_share_json = self.share.ciphertext.clone();
        let party_index = self.share.share_index.0;

        let thread_handle = thread::Builder::new()
            .name(format!("presigning-{party_index}"))
            .spawn(move || {
                run_presigning_sm(
                    eid_bytes,
                    my_signing_index,
                    participants,
                    key_share_json,
                    inbound_rx,
                    outbound_tx,
                );
            })
            .map_err(|e| MpcError::Protocol(format!("failed to spawn presigning thread: {e}")))?;

        self.sm_tx = Some(inbound_tx);
        self.sm_rx = Some(outbound_rx);
        self.sm_thread = Some(thread_handle);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal: Collect outgoing messages from the SM thread
    // -----------------------------------------------------------------------

    fn collect_outgoing_messages(&mut self) -> Result<Vec<RoundMessage>> {
        let rx = self.sm_rx.as_ref().ok_or_else(|| {
            MpcError::Protocol("SM channel not available (internal error)".into())
        })?;

        let mut outgoing = Vec::new();

        loop {
            let msg = rx.recv().map_err(|e| {
                MpcError::Protocol(format!(
                    "presigning SM thread channel closed unexpectedly: {e}"
                ))
            })?;

            match msg {
                SmOutbound::OutgoingMessage(wire_bytes) => {
                    outgoing.push(self.wire_bytes_to_round_message(wire_bytes)?);
                }
                SmOutbound::NeedsMessage => {
                    break;
                }
                SmOutbound::PresigningComplete(_) => {
                    return Err(MpcError::Protocol(
                        "presigning completed without any rounds (unexpected)".into(),
                    ));
                }
                SmOutbound::Error(e) => {
                    return Err(MpcError::Protocol(e));
                }
            }
        }

        Ok(outgoing)
    }

    /// Collect messages after feeding incoming messages for a round.
    fn collect_round_result(&mut self) -> Result<PresigningRoundResult> {
        let rx = self.sm_rx.as_ref().ok_or_else(|| {
            MpcError::Protocol("SM channel not available (internal error)".into())
        })?;

        let mut outgoing = Vec::new();

        loop {
            let msg = rx.recv().map_err(|e| {
                MpcError::Protocol(format!(
                    "presigning SM thread channel closed unexpectedly: {e}"
                ))
            })?;

            match msg {
                SmOutbound::OutgoingMessage(wire_bytes) => {
                    outgoing.push(self.wire_bytes_to_round_message(wire_bytes)?);
                }
                SmOutbound::NeedsMessage => {
                    self.current_round += 1;
                    return Ok(PresigningRoundResult::NextRound(outgoing));
                }
                SmOutbound::PresigningComplete(presig_output) => {
                    tracing::info!(
                        party = self.share.share_index.0,
                        pool_size = self.pool.len() + 1,
                        max = self.max_pool_size,
                        "presigning protocol complete, adding to pool"
                    );

                    self.cleanup_sm_thread();
                    self.generate_state = GenerateState::Idle;
                    self.current_round = 0;

                    // Create a Presignature wrapper and add to pool
                    let presig_id = {
                        let mut hasher = sha2::Sha256::new();
                        hasher.update(b"presig-");
                        hasher.update(self.session_id.as_bytes());
                        hasher.update(self.eid_counter.to_be_bytes());
                        hex::encode(hasher.finalize())
                    };

                    let presig = Presignature {
                        id: presig_id,
                        session_id: self.session_id,
                        // Data is empty because cggmp24's PresignaturePublicData
                        // doesn't implement Serialize. The actual presig objects
                        // are stored in raw_pool.
                        data: vec![],
                        created_at: chrono::Utc::now(),
                    };

                    self.pool.push(presig);
                    self.raw_pool.push(presig_output);

                    return Ok(PresigningRoundResult::Complete);
                }
                SmOutbound::Error(e) => {
                    self.cleanup_sm_thread();
                    self.generate_state = GenerateState::Idle;
                    self.current_round = 0;
                    return Err(MpcError::Protocol(e));
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal: Convert wire bytes to RoundMessage
    // -----------------------------------------------------------------------

    fn wire_bytes_to_round_message(&self, wire_bytes: Vec<u8>) -> Result<RoundMessage> {
        let wire: WireMessage = serde_json::from_slice(&wire_bytes)
            .map_err(|e| MpcError::Protocol(format!("failed to parse wire message: {e}")))?;

        Ok(RoundMessage {
            session_id: self.session_id,
            round: self.current_round,
            from: ShareIndex(wire.sender),
            to: None,
            payload: wire_bytes,
        })
    }

    // -----------------------------------------------------------------------
    // Internal: Thread cleanup
    // -----------------------------------------------------------------------

    fn cleanup_sm_thread(&mut self) {
        self.sm_tx.take();
        self.sm_rx.take();

        if let Some(handle) = self.sm_thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for PresigningManager {
    fn drop(&mut self) {
        self.cleanup_sm_thread();
    }
}

// ---------------------------------------------------------------------------
// State machine thread function
// ---------------------------------------------------------------------------

/// Run the presigning state machine in a dedicated thread.
///
/// This function blocks the thread, driving the SM via `proceed()` and
/// communicating with the manager via channels. Same pattern as
/// `run_signing_sm` in `signing.rs` and `run_keygen_sm` in `dkg.rs`.
fn run_presigning_sm(
    eid_bytes: [u8; 32],
    my_signing_index: u16,
    participants: Vec<u16>,
    key_share_json: Vec<u8>,
    inbound_rx: mpsc::Receiver<SmInbound>,
    outbound_tx: mpsc::Sender<SmOutbound>,
) {
    // Deserialize key share
    let key_share: cggmp24::KeyShare<Secp256k1, SecurityLevel128> =
        match serde_json::from_slice(&key_share_json) {
            Ok(ks) => ks,
            Err(e) => {
                let _ = outbound_tx.send(SmOutbound::Error(format!(
                    "failed to deserialize key share: {e}"
                )));
                return;
            }
        };

    let eid = ExecutionId::new(&eid_bytes);

    // Create the presigning state machine via wrap_protocol.
    let mut sm = round_based::state_machine::wrap_protocol(|party| async move {
        cggmp24::signing(eid, my_signing_index, &participants, &key_share)
            .generate_presignature(&mut rand::rngs::OsRng, party)
            .await
    });

    let mut msg_id: u64 = 0;

    loop {
        match sm.proceed() {
            ProceedResult::SendMsg(outgoing) => {
                let wire = match outgoing_to_wire(my_signing_index, outgoing) {
                    Ok(w) => w,
                    Err(e) => {
                        let _ = outbound_tx.send(SmOutbound::Error(format!(
                            "presigning: failed to create wire message: {e}"
                        )));
                        return;
                    }
                };
                let wire_bytes = match serde_json::to_vec(&wire) {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = outbound_tx.send(SmOutbound::Error(format!(
                            "presigning: failed to serialize outgoing: {e}"
                        )));
                        return;
                    }
                };
                if outbound_tx
                    .send(SmOutbound::OutgoingMessage(wire_bytes))
                    .is_err()
                {
                    return; // Manager dropped its receiver
                }
            }
            ProceedResult::NeedsOneMoreMessage => {
                // Tell manager we need input
                if outbound_tx.send(SmOutbound::NeedsMessage).is_err() {
                    return;
                }

                // Wait for incoming message from manager
                let inbound = match inbound_rx.recv() {
                    Ok(msg) => msg,
                    Err(_) => return, // Channel closed
                };

                match inbound {
                    SmInbound::IncomingMessage(wire_bytes) => {
                        msg_id += 1;
                        let wire: WireMessage = match serde_json::from_slice(&wire_bytes) {
                            Ok(w) => w,
                            Err(e) => {
                                let _ = outbound_tx.send(SmOutbound::Error(format!(
                                    "presigning: failed to deserialize incoming: {e}"
                                )));
                                return;
                            }
                        };
                        let incoming = match wire_to_incoming(wire, msg_id) {
                            Ok(inc) => inc,
                            Err(e) => {
                                let _ = outbound_tx.send(SmOutbound::Error(format!(
                                    "presigning: failed to parse incoming message: {e}"
                                )));
                                return;
                            }
                        };
                        if sm.received_msg(incoming).is_err() {
                            let _ = outbound_tx.send(SmOutbound::Error(
                                "presigning: SM rejected incoming message".into(),
                            ));
                            return;
                        }
                    }
                }
            }
            ProceedResult::Yielded => {
                // SM made progress but isn't done yet — keep looping
            }
            ProceedResult::Output(result) => {
                match result {
                    Ok(presig_output) => {
                        // Box the presignature output as dyn Any + Send.
                        // cggmp24's PresignaturePublicData doesn't implement Serialize,
                        // so we pass the raw objects through the channel.
                        let boxed: Box<dyn std::any::Any + Send> = Box::new(presig_output);
                        let _ = outbound_tx.send(SmOutbound::PresigningComplete(boxed));
                    }
                    Err(e) => {
                        let _ = outbound_tx.send(SmOutbound::Error(format!(
                            "presigning protocol error: {e:?}"
                        )));
                    }
                }
                return;
            }
            ProceedResult::Error(e) => {
                let _ = outbound_tx.send(SmOutbound::Error(format!(
                    "presigning state machine error: {e}"
                )));
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ThresholdConfig;
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
                (PresigningRoundResult::Complete, PresigningRoundResult::Complete) => {
                    // Both completed
                    break;
                }
                (PresigningRoundResult::NextRound(m0), PresigningRoundResult::NextRound(m1)) => {
                    outgoing_0 = m0;
                    outgoing_1 = m1;
                }
                (PresigningRoundResult::Complete, PresigningRoundResult::NextRound(m1)) => {
                    // Manager 0 completed first, feed remaining to manager 1
                    outgoing_0 = vec![];
                    outgoing_1 = m1;
                }
                (PresigningRoundResult::NextRound(m0), PresigningRoundResult::Complete) => {
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
        // We can't inspect the contents without knowing the concrete type,
        // but we verify they were successfully generated.
        // Raw data exists — we can't easily name the concrete type for downcast
        // but its presence proves the presigning protocol completed successfully.
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
                    (PresigningRoundResult::Complete, PresigningRoundResult::Complete) => break,
                    (
                        PresigningRoundResult::NextRound(m0),
                        PresigningRoundResult::NextRound(m1),
                    ) => {
                        outgoing_0 = m0;
                        outgoing_1 = m1;
                    }
                    (PresigningRoundResult::Complete, PresigningRoundResult::NextRound(m1)) => {
                        outgoing_0 = vec![];
                        outgoing_1 = m1;
                    }
                    (PresigningRoundResult::NextRound(m0), PresigningRoundResult::Complete) => {
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
}
