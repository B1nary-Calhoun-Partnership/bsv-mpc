//! Threshold ECDSA signing using the CGGMP'24 protocol.
//!
//! This module implements the online signing phase where `t` out of `n` parties
//! cooperate to produce a valid ECDSA signature over a BSV transaction sighash.
//! The resulting signature is indistinguishable from a single-signer ECDSA
//! signature — the blockchain cannot tell MPC was used.
//!
//! ## Two Signing Modes
//!
//! ### 1. With Presignature (1 round) — future
//!
//! If a presignature is available from the offline phase, online signing requires
//! only **1 round** of communication. This path requires the
//! `insecure-assume-preimage-known` feature on cggmp24 (because BSV sighashes
//! are pre-hashed). Currently not implemented in the coordinator — use the full
//! protocol path instead.
//!
//! ### 2. Without Presignature (4 rounds) — implemented
//!
//! The full interactive protocol runs as an inline `round_based::StateMachine`
//! held directly on the coordinator (Phase G architecture, mirroring
//! `dkg.rs`). The `proceed()` API is non-blocking — it returns
//! `NeedsOneMoreMessage` when it needs input — so no thread or mpsc channels
//! are needed. The SM lives in `signing_sm: Option<SigningSm>` and is driven
//! via the shared [`crate::dkg::drive_inline`] kernel.
//!
//! ## BSV Signature Format
//!
//! The output signature is:
//! - DER-encoded for inclusion in BSV Script (`OP_CHECKSIG`).
//! - Raw `(r, s)` components (32 bytes each) for applications needing them.
//! - Recovery ID for public key recovery (used by some protocols).
//!
//! The signature uses **low-s normalization** (BIP-62) to ensure only the
//! canonical form is produced, as required by BSV consensus rules.
//! cggmp24 auto-normalizes to low-S.

use std::collections::VecDeque;

use cggmp24::security_level::SecurityLevel128;
use cggmp24::signing::PrehashedDataToSign;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use generic_ec::Scalar;
use round_based::state_machine::StateMachine;
use sha2::{Digest, Sha256};

use crate::dkg::{drive_inline, DriveStep, WireMessage};
use crate::error::{MpcError, Result};
use crate::types::{
    EncryptedShare, Presignature, RoundMessage, SessionId, ShareIndex, SigningResult,
    ThresholdConfig,
};

/// Extract the joint pubkey from a share or fall back to all-zero bytes.
///
/// Pre-canonical (legacy) shares may have an empty `joint_pubkey_compressed`.
/// In that case the canonical formula is still well-defined with `[0;33]`,
/// but cross-impl ceremonies will abort at round 1 — we emit a warning so
/// the configuration error is visible in logs.
pub(crate) fn share_joint_pubkey_or_zero(share: &EncryptedShare, ctx: &'static str) -> [u8; 33] {
    if share.joint_pubkey_compressed.len() == 33 {
        let mut out = [0u8; 33];
        out.copy_from_slice(&share.joint_pubkey_compressed);
        out
    } else {
        tracing::warn!(
            phase = ctx,
            len = share.joint_pubkey_compressed.len(),
            "share missing canonical joint_pubkey_compressed — falling back to [0;33] \
             (cross-impl ceremony will abort at round 1; fill the field from DkgResult)"
        );
        [0u8; 33]
    }
}

// ---------------------------------------------------------------------------
// SigningRoundResult
// ---------------------------------------------------------------------------

/// Result of processing a signing round.
#[derive(Debug)]
pub enum SigningRoundResult {
    /// The protocol needs another round. Contains outgoing messages to send.
    NextRound(Vec<RoundMessage>),
    /// Signing is complete. Contains the ECDSA signature and participation proof.
    Complete(SigningResult),
}

// ---------------------------------------------------------------------------
// Signing mode tracking
// ---------------------------------------------------------------------------

/// Which signing mode the coordinator is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigningMode {
    /// Not started yet.
    NotStarted,
    /// Running the full 4-round SM-based signing protocol.
    FullProtocol,
    /// Signing is complete.
    Complete,
}

// ---------------------------------------------------------------------------
// Inline-SM type alias (Phase G)
// ---------------------------------------------------------------------------

/// Boxed `StateMachine` for the signing sub-protocol. The Output is what
/// the cggmp24 signing future returns (raw `Signature<Secp256k1>` on success);
/// the Msg type is what cggmp24-signing emits over the wire. Boxed because
/// `wrap_protocol`'s `impl StateMachine` has an opaque Future generic.
type SigningSm = Box<
    dyn StateMachine<
        Output = std::result::Result<cggmp24::Signature<Secp256k1>, cggmp24::SigningError>,
        Msg = cggmp24::signing::msg::Msg<Secp256k1, Sha256>,
    >,
>;

// ---------------------------------------------------------------------------
// SigningCoordinator
// ---------------------------------------------------------------------------

/// Coordinator for a single party's participation in a threshold signing ceremony.
///
/// Each participating signer instantiates a `SigningCoordinator` with their
/// encrypted key share and drives it through the protocol. The coordinator
/// decrypts the share in memory only for the duration of signing.
///
/// # Example (pseudocode)
///
/// ```ignore
/// // Full protocol: interactive signing (4 rounds)
/// let mut coord = SigningCoordinator::new(session_id, share, config, vec![0, 1]);
/// let msgs = coord.init_round(&sighash, None)?;
/// transport.broadcast(msgs).await;
/// loop {
///     let incoming = transport.receive_round().await;
///     match coord.process_round(incoming)? {
///         SigningRoundResult::NextRound(msgs) => transport.send_all(msgs).await,
///         SigningRoundResult::Complete(result) => break,
///     }
/// }
/// ```
pub struct SigningCoordinator {
    /// The MPC session this signing operation belongs to.
    session_id: SessionId,
    /// This party's encrypted key share.
    share: EncryptedShare,
    /// Threshold configuration.
    config: ThresholdConfig,
    /// Current round number (0 = not started).
    current_round: u8,
    /// Participants in this signing ceremony (party indices from DKG).
    participants: Vec<u16>,
    /// Deterministic execution ID bytes derived from session ID.
    eid_bytes: [u8; 32],
    /// Current signing mode.
    mode: SigningMode,

    /// The active signing state machine, held directly on the coordinator
    /// (Phase G inline architecture). `None` before `init_round()` and
    /// after the SM completes / errors.
    signing_sm: Option<SigningSm>,
    /// Incoming wire messages buffered across `process_round()` calls.
    /// Inputs are decoded once and queued; the SM consumes them one at a
    /// time via `received_msg()`.
    wire_buffer: VecDeque<WireMessage>,
    /// Monotonic message id for `round_based::Incoming<M>::id`.
    next_msg_id: u64,

    /// The message hash being signed (captured in `init_round`, used by
    /// `assemble_signing_result` to build the SigningResult).
    message_hash: Option<[u8; 32]>,
}

impl SigningCoordinator {
    /// Create a new signing coordinator.
    ///
    /// # Arguments
    ///
    /// * `session_id` -- The MPC session (from DKG).
    /// * `share` -- This party's encrypted key share.
    /// * `config` -- Threshold configuration.
    /// * `participants` -- Party indices participating in this signing ceremony
    ///   (indices as assigned during DKG, e.g. `[0, 1]` for a 2-of-2).
    pub fn new(
        session_id: SessionId,
        share: EncryptedShare,
        config: ThresholdConfig,
        participants: Vec<u16>,
    ) -> Self {
        // Canonical ExecutionId per MPC-Spec §02.2 with phase=Sign and the
        // joint pubkey carried on the share.
        let joint_pk_arr = share_joint_pubkey_or_zero(&share, "signing");
        let eid_bytes =
            crate::canonical::canonical_execution_id(&crate::canonical::ExecutionParams::new_v1(
                crate::canonical::PhaseTag::Sign,
                session_id,
                joint_pk_arr,
            ));

        Self {
            session_id,
            share,
            config,
            current_round: 0,
            participants,
            eid_bytes,
            mode: SigningMode::NotStarted,
            signing_sm: None,
            wire_buffer: VecDeque::new(),
            next_msg_id: 0,
            message_hash: None,
        }
    }

    /// Sign a message hash, optionally using a presignature for the fast path.
    ///
    /// Currently only the full protocol path is supported (presignature is
    /// ignored if provided — presigned path requires the
    /// `insecure-assume-preimage-known` feature on cggmp24).
    ///
    /// # Arguments
    ///
    /// * `message_hash` -- The 32-byte SHA-256d sighash of the BSV transaction input.
    /// * `_presignature` -- Reserved for future presigned path (currently ignored).
    /// * `hmac_offset` -- Optional BRC-42 additive shift for HD-derived signing.
    pub fn sign(
        &mut self,
        message_hash: &[u8; 32],
        _presignature: Option<Presignature>,
        hmac_offset: Option<[u8; 32]>,
    ) -> Result<Vec<RoundMessage>> {
        // TODO: When cggmp24 `insecure-assume-preimage-known` feature is enabled,
        // implement the presigned path here using issue_partial_signature + combine.
        self.init_round(message_hash, hmac_offset)
    }

    /// Start the signing protocol (Round 1).
    ///
    /// Constructs the cggmp24 signing `StateMachine` and drives it inline
    /// until it needs incoming messages, then returns the collected outgoing
    /// batch.
    ///
    /// # Arguments
    ///
    /// * `message_hash` -- The 32-byte SHA-256d sighash of the BSV transaction input.
    /// * `hmac_offset` -- Optional BRC-42 additive shift for HD-derived signing.
    pub fn init_round(
        &mut self,
        message_hash: &[u8; 32],
        hmac_offset: Option<[u8; 32]>,
    ) -> Result<Vec<RoundMessage>> {
        if self.mode != SigningMode::NotStarted {
            return Err(MpcError::Signing(
                "init_round() called but signing already started".into(),
            ));
        }

        // Map this party's share index to its signing-time index within the
        // participants list (cggmp24 wants the position, not the global share
        // index).
        let my_signing_index = self
            .participants
            .iter()
            .position(|&p| p == self.share.share_index.0)
            .ok_or_else(|| {
                MpcError::Signing(format!(
                    "share index {} not found in participants {:?}",
                    self.share.share_index.0, self.participants
                ))
            })? as u16;

        self.message_hash = Some(*message_hash);
        self.mode = SigningMode::FullProtocol;
        self.current_round = 1;

        // Decode the key share UP FRONT so caller-side errors (broken
        // share JSON) surface as MpcError::Signing instead of a panic
        // inside the SM future. KeyShare derives Clone (via the upstream
        // DirtyKeyShare + Valid newtype), so we can move an owned copy
        // into the closure to keep the SM 'static.
        let key_share: cggmp24::KeyShare<Secp256k1, SecurityLevel128> =
            serde_json::from_slice(&self.share.ciphertext)
                .map_err(|e| MpcError::Signing(format!("failed to deserialize key share: {e}")))?;

        // Construct the signing SM. The closure captures owned copies of
        // every input (participants, key_share, message_hash, offset) so
        // the returned `StateMachineImpl<...>` is 'static — storable in a
        // Box<dyn ... + 'static> struct field.
        let eid_bytes = self.eid_bytes;
        let participants_owned = self.participants.clone();
        let msg_hash = *message_hash;
        let hmac_offset_owned = hmac_offset;

        let sm: SigningSm = Box::new(round_based::state_machine::wrap_protocol(
            move |party| async move {
                let eid = ExecutionId::new(&eid_bytes);

                let scalar = Scalar::<Secp256k1>::from_be_bytes_mod_order(msg_hash);
                let data_to_sign = PrehashedDataToSign::from_scalar(scalar);

                let mut builder =
                    cggmp24::signing(eid, my_signing_index, &participants_owned, &key_share);
                if let Some(offset_bytes) = hmac_offset_owned {
                    let offset_scalar = Scalar::<Secp256k1>::from_be_bytes_mod_order(offset_bytes);
                    builder = builder.set_additive_shift(offset_scalar);
                }

                builder
                    .sign(&mut rand::rngs::OsRng, party, &data_to_sign)
                    .await
            },
        ));
        self.signing_sm = Some(sm);

        let mut outgoing = Vec::new();
        match self.drive_signing(&mut outgoing)? {
            None => Ok(outgoing),
            Some(_signature) => Err(MpcError::Signing(
                "signing completed without any rounds (unexpected)".into(),
            )),
        }
    }

    /// Process incoming messages from the current signing round.
    pub fn process_round(&mut self, messages: Vec<RoundMessage>) -> Result<SigningRoundResult> {
        match self.mode {
            SigningMode::NotStarted => {
                return Err(MpcError::Signing(
                    "process_round() called before init_round()".into(),
                ));
            }
            SigningMode::Complete => {
                return Err(MpcError::Signing(
                    "process_round() called after signing completed".into(),
                ));
            }
            SigningMode::FullProtocol => {}
        }

        for msg in &messages {
            self.buffer_incoming_payload(&msg.payload)?;
        }

        let mut outgoing = Vec::new();
        match self.drive_signing(&mut outgoing)? {
            None => {
                self.current_round += 1;
                Ok(SigningRoundResult::NextRound(outgoing))
            }
            Some(signature) => {
                self.mode = SigningMode::Complete;
                self.assemble_signing_result(signature)
            }
        }
    }

    /// Get the current round number (0 = not started).
    pub fn current_round(&self) -> u8 {
        self.current_round
    }

    /// Get the threshold configuration.
    pub fn config(&self) -> &ThresholdConfig {
        &self.config
    }

    // -----------------------------------------------------------------------
    // Internal: inline drive helpers
    // -----------------------------------------------------------------------

    /// Drive the signing SM until it needs more input or completes.
    fn drive_signing(
        &mut self,
        outgoing: &mut Vec<RoundMessage>,
    ) -> Result<Option<cggmp24::Signature<Secp256k1>>> {
        // Compute the wire-time sender index up front so we don't hold
        // an immutable borrow of `self` while drive_inline holds mutable
        // borrows of `self.wire_buffer` / `self.next_msg_id`. The wire
        // SENDER for outgoing messages is this party's signing-time index
        // (its position within `participants`), matching the convention
        // the previous threaded bridge in run_signing_sm used.
        let signing_idx = self.signing_index()?;
        let session_id = self.session_id;
        let current_round = self.current_round;

        let mut sm = self
            .signing_sm
            .take()
            .ok_or_else(|| MpcError::Signing("drive_signing: SM not present".into()))?;

        let result = drive_inline(
            sm.as_mut(),
            &mut self.wire_buffer,
            &mut self.next_msg_id,
            signing_idx,
            session_id,
            current_round,
            outgoing,
            "signing",
            &MpcError::Signing,
        );

        match result? {
            DriveStep::NeedsInput => {
                self.signing_sm = Some(sm);
                Ok(None)
            }
            DriveStep::Complete(signature) => Ok(Some(signature)),
        }
    }

    /// Compute this party's signing-time index (position within
    /// `participants`). Centralized so init_round and drive_signing agree.
    fn signing_index(&self) -> Result<u16> {
        self.participants
            .iter()
            .position(|&p| p == self.share.share_index.0)
            .map(|p| p as u16)
            .ok_or_else(|| {
                MpcError::Signing(format!(
                    "share index {} not found in participants {:?}",
                    self.share.share_index.0, self.participants
                ))
            })
    }

    /// Decode one incoming `RoundMessage` payload and append onto the
    /// internal wire buffer. The payload is either a single
    /// `WireMessage` JSON or a bundled array.
    fn buffer_incoming_payload(&mut self, wire_bytes: &[u8]) -> Result<()> {
        if wire_bytes.first() == Some(&b'[') {
            let bundle: Vec<WireMessage> = serde_json::from_slice(wire_bytes).map_err(|e| {
                MpcError::Signing(format!("failed to deserialize bundled incoming: {e}"))
            })?;
            self.wire_buffer.extend(bundle);
        } else {
            let wire: WireMessage = serde_json::from_slice(wire_bytes)
                .map_err(|e| MpcError::Signing(format!("failed to deserialize incoming: {e}")))?;
            self.wire_buffer.push_back(wire);
        }
        Ok(())
    }

    /// Convert the cggmp24 signature into a [`SigningResult`].
    fn assemble_signing_result(
        &self,
        sig: cggmp24::Signature<Secp256k1>,
    ) -> Result<SigningRoundResult> {
        let message_hash = self
            .message_hash
            .ok_or_else(|| MpcError::Signing("message hash not set (internal error)".into()))?;

        let mut sig_bytes = [0u8; 64];
        sig.write_to_slice(&mut sig_bytes);

        let result = sig_bytes_to_signing_result(
            &sig_bytes,
            &self.session_id,
            self.share.share_index,
            &message_hash,
            &self.participants,
        );

        Ok(SigningRoundResult::Complete(result))
    }
}

// ---------------------------------------------------------------------------
// Signature conversion helpers
// ---------------------------------------------------------------------------

/// Convert raw 64-byte r||s signature to a `SigningResult` with DER encoding
/// and participation proof.
fn sig_bytes_to_signing_result(
    sig_bytes: &[u8; 64],
    session_id: &SessionId,
    _share_index: ShareIndex,
    message_hash: &[u8; 32],
    participants: &[u16],
) -> SigningResult {
    let r = sig_bytes[..32].to_vec();
    let s = sig_bytes[32..].to_vec();

    // DER encode
    let signature = der_encode_signature(&r, &s);

    // Recovery ID (default 0 -- proper recovery ID computation requires the nonce point,
    // which cggmp24 does not expose. For BSV OP_CHECKSIG this is not needed.)
    let recovery_id = 0;

    // Create a placeholder participation proof.
    // In production, the proxy layer will provide proper 33-byte agent/node keys.
    // Here we use a minimal proof since we don't have real identity keys.
    let proof = crate::types::ParticipationProof {
        session_hash: {
            let mut hasher = Sha256::new();
            hasher.update(b"bsv-mpc-signing-proof-");
            hasher.update(session_id.as_bytes());
            hasher.finalize().to_vec()
        },
        agent_identity: vec![0x02; 33], // placeholder
        participating_nodes: participants
            .iter()
            .map(|&p| {
                let mut node_id = vec![0x02; 33];
                node_id[32] = p as u8;
                node_id
            })
            .collect(),
        signing_hash: message_hash.to_vec(),
        fee_txid: None,
        timestamp: chrono::Utc::now(),
    };

    SigningResult {
        signature,
        r,
        s,
        recovery_id,
        proof,
    }
}

/// DER-encode an ECDSA signature from raw r, s values (32 bytes each).
///
/// Produces a DER SEQUENCE containing two INTEGERs:
/// ```text
/// 30 <total_len> 02 <r_len> <r_bytes> 02 <s_len> <s_bytes>
/// ```
fn der_encode_signature(r: &[u8], s: &[u8]) -> Vec<u8> {
    fn der_integer(val: &[u8]) -> Vec<u8> {
        // Strip leading zeros (but keep at least one byte)
        let mut trimmed = val;
        while trimmed.len() > 1 && trimmed[0] == 0 {
            trimmed = &trimmed[1..];
        }
        // Add padding byte if high bit is set (would be interpreted as negative)
        let needs_padding = trimmed[0] & 0x80 != 0;
        let len = trimmed.len() + if needs_padding { 1 } else { 0 };
        let mut result = vec![0x02, len as u8];
        if needs_padding {
            result.push(0x00);
        }
        result.extend_from_slice(trimmed);
        result
    }

    let r_der = der_integer(r);
    let s_der = der_integer(s);
    let total_len = r_der.len() + s_der.len();

    let mut sig = vec![0x30, total_len as u8];
    sig.extend(r_der);
    sig.extend(s_der);
    sig
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

    // ---- Blum prime utilities (same as dkg.rs tests) ----

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
        cggmp24::key_refresh::PregeneratedPrimes::try_from(primes)
            .expect("primes have wrong bit size")
    }

    // ---- Helper: DKG via sim to produce key shares ----

    fn dkg_key_shares(n: u16, t: u16) -> Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> {
        let mut rng = rand::rngs::OsRng;

        // Step 1: Keygen
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

        // Step 2: Aux info generation
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

        // Step 3: Combine
        incomplete_shares
            .into_iter()
            .zip(aux_infos)
            .map(|(share, aux)| {
                cggmp24::KeyShare::<Secp256k1, SecurityLevel128>::from_parts((share, aux))
                    .expect("key share validation should pass")
            })
            .collect()
    }

    /// Wrap a KeyShare into an EncryptedShare (placeholder — raw JSON, not actually encrypted).
    fn key_share_to_encrypted(
        key_share: &cggmp24::KeyShare<Secp256k1, SecurityLevel128>,
        index: u16,
        config: ThresholdConfig,
    ) -> EncryptedShare {
        let key_share_json = serde_json::to_vec(key_share).expect("key share must serialize");
        EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: key_share_json,
            session_id: SessionId::from_str_hash("test-signing-session"),
            share_index: ShareIndex(index),
            config,
            joint_pubkey_compressed: key_share.core.shared_public_key.to_bytes(true).to_vec(),
        }
    }

    // ================================================================
    // Unit tests
    // ================================================================

    #[test]
    fn coordinator_creation() {
        let config = ThresholdConfig::new(2, 2).unwrap();
        let share = EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: vec![],
            session_id: SessionId::from_str_hash("test"),
            share_index: ShareIndex(0),
            config,
            joint_pubkey_compressed: Vec::new(),
        };

        let coord =
            SigningCoordinator::new(SessionId::from_str_hash("test"), share, config, vec![0, 1]);

        assert_eq!(coord.current_round(), 0);
        assert_eq!(coord.config().threshold, 2);
        assert_eq!(coord.config().parties, 2);
    }

    #[test]
    fn signing_invalid_share_index() {
        let config = ThresholdConfig::new(2, 2).unwrap();
        let share = EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: vec![],
            session_id: SessionId::from_str_hash("test"),
            share_index: ShareIndex(5), // not in participants
            config,
            joint_pubkey_compressed: Vec::new(),
        };

        let mut coord =
            SigningCoordinator::new(SessionId::from_str_hash("test"), share, config, vec![0, 1]);

        let result = coord.init_round(&[0u8; 32], None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{err}").contains("not found in participants"),
            "expected 'not found in participants' error, got: {err}"
        );
    }

    #[test]
    fn process_round_before_init_fails() {
        let config = ThresholdConfig::new(2, 2).unwrap();
        let share = EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: vec![],
            session_id: SessionId::from_str_hash("test"),
            share_index: ShareIndex(0),
            config,
            joint_pubkey_compressed: Vec::new(),
        };

        let mut coord =
            SigningCoordinator::new(SessionId::from_str_hash("test"), share, config, vec![0, 1]);

        let result = coord.process_round(vec![]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{err}").contains("before init"),
            "expected 'before init' error, got: {err}"
        );
    }

    #[test]
    fn execution_id_is_deterministic() {
        let config = ThresholdConfig::new(2, 2).unwrap();
        let share = EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: vec![],
            session_id: SessionId::from_str_hash("test"),
            share_index: ShareIndex(0),
            config,
            joint_pubkey_compressed: Vec::new(),
        };

        let coord1 = SigningCoordinator::new(
            SessionId::from_str_hash("deterministic-test"),
            share.clone(),
            config,
            vec![0, 1],
        );
        let coord2 = SigningCoordinator::new(
            SessionId::from_str_hash("deterministic-test"),
            share,
            config,
            vec![0, 1],
        );

        assert_eq!(coord1.eid_bytes, coord2.eid_bytes);
    }

    #[test]
    fn different_sessions_produce_different_eids() {
        let config = ThresholdConfig::new(2, 2).unwrap();
        let share = EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: vec![],
            session_id: SessionId::from_str_hash("test"),
            share_index: ShareIndex(0),
            config,
            joint_pubkey_compressed: Vec::new(),
        };

        let coord1 = SigningCoordinator::new(
            SessionId::from_str_hash("session-a"),
            share.clone(),
            config,
            vec![0, 1],
        );
        let coord2 = SigningCoordinator::new(
            SessionId::from_str_hash("session-b"),
            share,
            config,
            vec![0, 1],
        );

        assert_ne!(coord1.eid_bytes, coord2.eid_bytes);
    }

    #[test]
    fn der_encode_known_values() {
        // Known r, s values -- verify DER encoding
        let r = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let s = vec![
            0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        let der = der_encode_signature(&r, &s);

        // Verify SEQUENCE tag
        assert_eq!(der[0], 0x30);

        // r has leading zeros that should be stripped, leaving 31 bytes starting at 0x01
        // s starts with 0x80 which needs a padding byte

        // Parse r integer
        assert_eq!(der[2], 0x02); // INTEGER tag for r
        let r_len = der[3] as usize;
        let r_data = &der[4..4 + r_len];
        // Leading zeros stripped
        assert_eq!(r_data[0], 0x01);

        // Parse s integer
        let s_offset = 4 + r_len;
        assert_eq!(der[s_offset], 0x02); // INTEGER tag for s
        let s_len = der[s_offset + 1] as usize;
        let s_data = &der[s_offset + 2..s_offset + 2 + s_len];
        // High bit set, so padding byte added
        assert_eq!(s_data[0], 0x00);
        assert_eq!(s_data[1], 0x80);
    }

    #[test]
    fn der_encode_no_padding_needed() {
        // r and s both start with values < 0x80 and no leading zeros
        let r = vec![0x7f; 32];
        let s = vec![0x01; 32];

        let der = der_encode_signature(&r, &s);

        // Both should be encoded without padding
        assert_eq!(der[0], 0x30);
        assert_eq!(der[2], 0x02); // r tag
        assert_eq!(der[3], 32); // r length (no padding, no stripping)
    }

    // ================================================================
    // Integration test: Full 2-of-2 signing via simulation
    // ================================================================

    #[tokio::test]
    async fn full_2of2_signing_via_sim() {
        // This test validates end-to-end: DKG -> signing -> BSV SDK verify
        // Uses round_based::sim to run both parties in-process.

        let n: u16 = 2;
        let t: u16 = 2;

        // Step 1: DKG to get key shares
        let key_shares = dkg_key_shares(n, t);
        assert_eq!(key_shares.len(), 2);

        // Step 2: Sign via simulation (validates cggmp24 signing API)
        let mut rng = rand::rngs::OsRng;
        let eid_bytes: [u8; 32] = rand::Rng::gen(&mut rng);
        let eid_sign = ExecutionId::new(&eid_bytes);

        let message_hash: [u8; 32] = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(b"test message for signing");
            let result = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&result);
            bytes
        };

        let scalar = Scalar::<Secp256k1>::from_be_bytes_mod_order(message_hash);
        let data_to_sign = PrehashedDataToSign::from_scalar(scalar);

        let participants: Vec<u16> = vec![0, 1];

        let sig = round_based::sim::run_with_setup(
            participants.iter().map(|i| &key_shares[usize::from(*i)]),
            |i, party, share| {
                let party = buffer_outgoing(party);
                let mut party_rng = rand::rngs::OsRng;
                let participants = participants.clone();
                async move {
                    cggmp24::signing(eid_sign, i, &participants, share)
                        .sign(&mut party_rng, party, &data_to_sign)
                        .await
                }
            },
        )
        .unwrap()
        .expect_ok()
        .expect_eq();

        // Verify with cggmp24
        sig.verify(&key_shares[0].core.shared_public_key, &data_to_sign)
            .expect("cggmp24 internal verification should pass");

        // Verify with BSV SDK
        let mut sig_bytes = [0u8; 64];
        sig.write_to_slice(&mut sig_bytes);

        let pubkey_bytes = key_shares[0].core.shared_public_key.to_bytes(true);
        let bsv_pubkey = bsv::PublicKey::from_bytes(&pubkey_bytes)
            .expect("BSV SDK should accept the public key");

        let bsv_sig = bsv::Signature::from_compact(&sig_bytes)
            .expect("BSV SDK should accept the compact signature");

        let valid = bsv_pubkey.verify(&message_hash, &bsv_sig);
        assert!(valid, "BSV SDK verification must pass");
    }

    // ================================================================
    // Integration test: Two SigningCoordinators exchanging messages
    // ================================================================

    #[test]
    fn two_coordinators_signing_message_exchange() {
        // Full integration test: DKG + coordinator-based signing with message relay.
        // This is the most important test — validates the SM bridge works for signing.

        let n: u16 = 2;
        let t: u16 = 2;
        let config = ThresholdConfig::new(t, n).unwrap();

        // Step 1: DKG via sim
        let key_shares = dkg_key_shares(n, t);

        // Step 2: Create signing coordinators
        let session = SessionId::from_str_hash("signing-coordinator-test");
        let participants = vec![0u16, 1];

        let share0 = key_share_to_encrypted(&key_shares[0], 0, config);
        let share1 = key_share_to_encrypted(&key_shares[1], 1, config);

        let mut coord0 = SigningCoordinator::new(session, share0, config, participants.clone());
        let mut coord1 = SigningCoordinator::new(session, share1, config, participants);

        // Message hash to sign
        let message_hash: [u8; 32] = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(b"coordinator test message");
            let result = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&result);
            bytes
        };

        // Step 3: Init both coordinators
        let msgs0 = coord0
            .init_round(&message_hash, None)
            .expect("coord0 init should succeed");
        let msgs1 = coord1
            .init_round(&message_hash, None)
            .expect("coord1 init should succeed");

        assert!(!msgs0.is_empty(), "coord0 should produce outgoing messages");
        assert!(!msgs1.is_empty(), "coord1 should produce outgoing messages");

        // Step 4: Exchange messages until both complete
        let mut outgoing0 = msgs0;
        let mut outgoing1 = msgs1;

        for round in 0..20 {
            let result0 = coord0.process_round(outgoing1.clone());
            let result1 = coord1.process_round(outgoing0.clone());

            match (result0, result1) {
                (
                    Ok(SigningRoundResult::NextRound(new0)),
                    Ok(SigningRoundResult::NextRound(new1)),
                ) => {
                    outgoing0 = new0;
                    outgoing1 = new1;
                }
                (Ok(SigningRoundResult::Complete(r0)), Ok(SigningRoundResult::Complete(r1))) => {
                    // Both completed! Verify signatures match.
                    assert_eq!(r0.r, r1.r, "both coordinators must produce the same r");
                    assert_eq!(r0.s, r1.s, "both coordinators must produce the same s");
                    assert_eq!(r0.signature, r1.signature, "DER signatures must match");

                    // Verify DER signature structure
                    assert_eq!(r0.signature[0], 0x30, "DER SEQUENCE tag");

                    // Verify with BSV SDK
                    let pubkey_bytes = key_shares[0].core.shared_public_key.to_bytes(true);
                    let bsv_pubkey = bsv::PublicKey::from_bytes(&pubkey_bytes)
                        .expect("BSV SDK should accept the public key");

                    let mut sig_compact = [0u8; 64];
                    sig_compact[..32].copy_from_slice(&r0.r);
                    sig_compact[32..].copy_from_slice(&r0.s);

                    let bsv_sig = bsv::Signature::from_compact(&sig_compact)
                        .expect("BSV SDK should accept the signature");

                    let valid = bsv_pubkey.verify(&message_hash, &bsv_sig);
                    assert!(valid, "BSV SDK verification must pass");

                    return; // Test passed!
                }
                (Ok(SigningRoundResult::Complete(_)), Ok(SigningRoundResult::NextRound(_)))
                | (Ok(SigningRoundResult::NextRound(_)), Ok(SigningRoundResult::Complete(_))) => {
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

        panic!("signing did not complete within 20 rounds");
    }

    // ================================================================
    // Integration test: sign() convenience method
    // ================================================================

    #[test]
    fn sign_convenience_without_presig() {
        // Verify sign(hash, None) is equivalent to init_round(hash)

        let n: u16 = 2;
        let t: u16 = 2;
        let config = ThresholdConfig::new(t, n).unwrap();
        let key_shares = dkg_key_shares(n, t);

        let session = SessionId::from_str_hash("sign-convenience-test");
        let participants = vec![0u16, 1];

        let share0 = key_share_to_encrypted(&key_shares[0], 0, config);
        let share1 = key_share_to_encrypted(&key_shares[1], 1, config);

        // Use sign() for coord0 and init_round() for coord1
        let mut coord0 = SigningCoordinator::new(session, share0, config, participants.clone());
        let mut coord1 = SigningCoordinator::new(session, share1, config, participants);

        let message_hash: [u8; 32] = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(b"sign convenience test");
            let result = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&result);
            bytes
        };

        // sign() without presig = init_round()
        let msgs0 = coord0
            .sign(&message_hash, None, None)
            .expect("coord0 sign should succeed");
        let msgs1 = coord1
            .init_round(&message_hash, None)
            .expect("coord1 init should succeed");

        assert!(!msgs0.is_empty());
        assert!(!msgs1.is_empty());

        // Drive to completion
        let mut outgoing0 = msgs0;
        let mut outgoing1 = msgs1;

        for round in 0..20 {
            let result0 = coord0.process_round(outgoing1.clone());
            let result1 = coord1.process_round(outgoing0.clone());

            match (result0, result1) {
                (
                    Ok(SigningRoundResult::NextRound(new0)),
                    Ok(SigningRoundResult::NextRound(new1)),
                ) => {
                    outgoing0 = new0;
                    outgoing1 = new1;
                }
                (Ok(SigningRoundResult::Complete(r0)), Ok(SigningRoundResult::Complete(r1))) => {
                    assert_eq!(r0.r, r1.r);
                    assert_eq!(r0.s, r1.s);

                    // BSV SDK verify
                    let pubkey_bytes = key_shares[0].core.shared_public_key.to_bytes(true);
                    let bsv_pubkey = bsv::PublicKey::from_bytes(&pubkey_bytes).unwrap();
                    let mut sig_compact = [0u8; 64];
                    sig_compact[..32].copy_from_slice(&r0.r);
                    sig_compact[32..].copy_from_slice(&r0.s);
                    let bsv_sig = bsv::Signature::from_compact(&sig_compact).unwrap();
                    assert!(bsv_pubkey.verify(&message_hash, &bsv_sig));

                    return;
                }
                (Ok(SigningRoundResult::Complete(_)), Ok(SigningRoundResult::NextRound(_)))
                | (Ok(SigningRoundResult::NextRound(_)), Ok(SigningRoundResult::Complete(_))) => {
                    panic!("desync at round {round}");
                }
                (Err(e), _) => panic!("coord0 error at round {round}: {e}"),
                (_, Err(e)) => panic!("coord1 error at round {round}: {e}"),
            }
        }

        panic!("signing did not complete within 20 rounds");
    }

    // ================================================================
    // Integration test: Presigning + 1-round signing via simulation
    // ================================================================

    #[tokio::test]
    async fn presigning_and_combine_via_sim() {
        // Validates the presigning path works at the cggmp24 level.
        // Note: The coordinator presigned path is not yet implemented because
        // issue_partial_signature requires DataToSign (not PrehashedDataToSign).
        // This test uses DataToSign::digest directly.

        use cggmp24::signing::DataToSign;

        let n: u16 = 2;
        let t: u16 = 2;

        let key_shares = dkg_key_shares(n, t);
        let mut rng = rand::rngs::OsRng;

        // Generate presignatures via sim
        let eid_bytes: [u8; 32] = rand::Rng::gen(&mut rng);
        let eid_presign = ExecutionId::new(&eid_bytes);

        let participants: Vec<u16> = vec![0, 1];

        let presigs = round_based::sim::run_with_setup(
            participants.iter().map(|i| &key_shares[usize::from(*i)]),
            |i, party, share| {
                let party = buffer_outgoing(party);
                let mut party_rng = rand::rngs::OsRng;
                let participants = participants.clone();
                async move {
                    cggmp24::signing(eid_presign, i, &participants, share)
                        .generate_presignature(&mut party_rng, party)
                        .await
                }
            },
        )
        .unwrap()
        .expect_ok()
        .into_vec();

        assert_eq!(presigs.len(), 2);

        // All commitments must match
        assert_eq!(presigs[0].1, presigs[1].1, "commitments must match");
        let (_, commitments) = presigs[0].clone();

        // Sign using partial signatures (DataToSign::digest because
        // issue_partial_signature requires DataToSign)
        let message = b"presigned message for test";
        let data_to_sign = DataToSign::digest::<sha2::Sha256>(message);

        let partial_signatures: Vec<_> = presigs
            .into_iter()
            .map(|(presig, _)| presig.issue_partial_signature(data_to_sign))
            .collect();

        let sig =
            cggmp24::PartialSignature::combine(&partial_signatures, &commitments, data_to_sign)
                .expect("partial signature combination should produce a signature");

        // Verify with cggmp24
        sig.verify(&key_shares[0].core.shared_public_key, &data_to_sign)
            .expect("presigned signature should verify");

        // Verify with BSV SDK
        let mut sig_bytes = [0u8; 64];
        sig.write_to_slice(&mut sig_bytes);

        let pubkey_bytes = key_shares[0].core.shared_public_key.to_bytes(true);
        let bsv_pubkey = bsv::PublicKey::from_bytes(&pubkey_bytes)
            .expect("BSV SDK should accept the public key");

        // Compute the message hash (SHA-256) that the BSV SDK expects
        let message_hash: [u8; 32] = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(message);
            let result = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&result);
            bytes
        };

        let bsv_sig = bsv::Signature::from_compact(&sig_bytes)
            .expect("BSV SDK should accept presigned signature");

        let valid = bsv_pubkey.verify(&message_hash, &bsv_sig);
        assert!(valid, "BSV SDK presigned verification must pass");
    }
}
