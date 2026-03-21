//! Threshold ECDSA signing using the CGGMP'24 protocol.
//!
//! This module implements the online signing phase where `t` out of `n` parties
//! cooperate to produce a valid ECDSA signature over a BSV transaction sighash.
//! The resulting signature is indistinguishable from a single-signer ECDSA
//! signature — the blockchain cannot tell MPC was used.
//!
//! ## Two Signing Modes
//!
//! ### 1. With Presignature (1 round)
//!
//! If a presignature is available from the offline phase, online signing requires
//! only **1 round** of communication:
//!
//! 1. Each party computes their partial signature using the presignature and the
//!    message hash, then broadcasts it.
//! 2. Any party can combine `t` partial signatures into the final ECDSA signature.
//!
//! This is the fast path. The presignature already contains the group's nonce `k`
//! and related proofs, so the online phase only needs to incorporate the message.
//!
//! ### 2. Without Presignature (4 rounds)
//!
//! If no presignature is available, the full interactive protocol runs:
//!
//! 1. **Round 1**: Each party generates a nonce share `k_i` and broadcasts a
//!    commitment to it.
//! 2. **Round 2**: Decommit nonces, verify, compute joint nonce point `R`.
//! 3. **Round 3**: Each party computes partial signature `s_i` using their key
//!    share and nonce share, broadcasts with zero-knowledge proof.
//! 4. **Round 4**: Verify partial signatures, combine into final `(r, s)`.
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

use crate::error::Result;
use crate::types::{
    EncryptedShare, Presignature, RoundMessage, SessionId, SigningResult, ThresholdConfig,
};

/// Result of processing a signing round.
#[derive(Debug)]
pub enum SigningRoundResult {
    /// The protocol needs another round. Contains outgoing messages to send.
    NextRound(Vec<RoundMessage>),
    /// Signing is complete. Contains the ECDSA signature and participation proof.
    Complete(SigningResult),
}

/// Coordinator for a single party's participation in a threshold signing ceremony.
///
/// Each participating signer instantiates a `SigningCoordinator` with their
/// encrypted key share and drives it through the protocol. The coordinator
/// decrypts the share in memory only for the duration of signing.
///
/// # Example (pseudocode)
///
/// ```ignore
/// // Fast path: sign with presignature (1 round)
/// let coord = SigningCoordinator::new(session_id, share, config);
/// let result = coord.sign(&sighash, Some(presig)).await?;
/// // result.signature is DER-encoded, ready for BSV Script
///
/// // Slow path: interactive signing (4 rounds)
/// let mut coord = SigningCoordinator::new(session_id, share, config);
/// let msg = coord.init_round(&sighash).await?;
/// transport.broadcast(msg).await;
/// loop {
///     let incoming = transport.receive_round().await;
///     match coord.process_round(incoming).await? {
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
    // TODO: Add cggmp24 signing state fields:
    // - `signing_state: Option<cggmp24::SigningState>` — running protocol state
    // - `message_hash: Option<[u8; 32]>` — the sighash being signed
    // - `decrypted_share: Option<zeroize::Zeroizing<Vec<u8>>>` — share decrypted in memory (zeroized on drop)
    // - `partial_sigs: Vec<Option<Vec<u8>>>` — collected partial signatures
}

impl SigningCoordinator {
    /// Create a new signing coordinator.
    ///
    /// # Arguments
    ///
    /// * `session_id` — The MPC session (from DKG).
    /// * `share` — This party's encrypted key share.
    /// * `config` — Threshold configuration.
    pub fn new(session_id: SessionId, share: EncryptedShare, config: ThresholdConfig) -> Self {
        Self {
            session_id,
            share,
            config,
            current_round: 0,
        }
    }

    /// Sign a message hash using a presignature (1-round fast path).
    ///
    /// This is the preferred signing method when a presignature is available.
    /// The presignature contains the precomputed nonce and related proofs,
    /// so signing reduces to a single broadcast round.
    ///
    /// If `presignature` is `None`, this falls back to the 4-round interactive
    /// protocol internally (equivalent to calling `init_round` + `process_round`).
    ///
    /// # Arguments
    ///
    /// * `message_hash` — The 32-byte SHA-256d sighash of the BSV transaction input.
    /// * `presignature` — Optional presignature for 1-round signing.
    ///
    /// # Returns
    ///
    /// A [`SigningResult`] containing the DER signature, raw (r, s), recovery ID,
    /// and participation proof.
    pub async fn sign(
        &self,
        message_hash: &[u8; 32],
        presignature: Option<Presignature>,
    ) -> Result<SigningResult> {
        todo!(
            "cggmp24 integration: \
             1. Decrypt key share using BRC-42 derived encryption key \
             2. If presignature is Some: \
                a. Deserialize presignature data into cggmp24 presigning state \
                b. Compute partial signature: s_i = k_i^-1 * (message_hash + r * x_i) mod n \
                   where k_i is from the presignature and x_i is our key share \
                c. Broadcast partial signature (1 round) \
                d. Collect t partial signatures and combine: s = sum(s_i) mod n \
                e. Apply low-s normalization (BIP-62): if s > n/2, s = n - s \
             3. If presignature is None: \
                a. Run full 4-round interactive protocol (delegate to init_round/process_round) \
             4. DER-encode the final (r, s) signature \
             5. Compute recovery_id from the nonce point R \
             6. Create ParticipationProof with session hash, signing hash, node identities \
             7. Zeroize decrypted share from memory \
             8. Return SigningResult {{ signature, r, s, recovery_id, proof }} \
             \
             Message hash: {:?}, session: {}, has presig: {}",
            message_hash,
            self.session_id,
            presignature.is_some()
        )
    }

    /// Start the interactive signing protocol (Round 1) without a presignature.
    ///
    /// This initiates the 4-round signing flow. The party generates a nonce
    /// share `k_i`, commits to it, and produces a broadcast message.
    ///
    /// # Arguments
    ///
    /// * `message_hash` — The 32-byte SHA-256d sighash of the BSV transaction input.
    ///
    /// # Returns
    ///
    /// A [`RoundMessage`] to broadcast to all participating signers.
    pub async fn init_round(&mut self, message_hash: &[u8; 32]) -> Result<RoundMessage> {
        todo!(
            "cggmp24 integration: \
             1. Decrypt key share using BRC-42 derived encryption key \
             2. Store message_hash in self for later rounds \
             3. Generate random nonce share k_i using OsRng \
             4. Compute nonce commitment = SHA-256(k_i * G) where G is secp256k1 generator \
             5. Initialize cggmp24 signing state machine \
             6. Return RoundMessage with round=0, from=share.share_index, to=None, \
                payload=serialized_commitment \
             \
             Message hash: {:?}, session: {}",
            message_hash,
            self.session_id
        )
    }

    /// Process incoming messages from the current signing round.
    ///
    /// See the module-level documentation for what each round does.
    ///
    /// # Arguments
    ///
    /// * `messages` — All messages received for the current round from other signers.
    ///
    /// # Returns
    ///
    /// [`SigningRoundResult::NextRound`] with outgoing messages, or
    /// [`SigningRoundResult::Complete`] with the final signature.
    pub async fn process_round(
        &mut self,
        messages: Vec<RoundMessage>,
    ) -> Result<SigningRoundResult> {
        todo!(
            "cggmp24 integration: \
             1. Feed {} incoming messages into cggmp24 signing state machine \
             2. Verify zero-knowledge proofs for round {} \
             3. If verification fails, produce identifiable abort \
             4. If round < 3 (0-indexed), advance state and produce outgoing messages \
             5. If round == 3 (final round): \
                a. Combine t partial signatures: s = sum(lambda_i * s_i) mod n \
                   where lambda_i are Lagrange interpolation coefficients \
                b. Compute r from the joint nonce point R: r = R.x mod n \
                c. Verify the final signature against the joint public key \
                d. Apply low-s normalization (BIP-62) \
                e. DER-encode the signature \
                f. Create participation proof \
                g. Zeroize all sensitive material (nonce shares, decrypted key share) \
                h. Return SigningRoundResult::Complete(SigningResult) \
             6. Return SigningRoundResult::NextRound(outgoing_messages)",
            messages.len(),
            self.current_round
        )
    }

    /// Get the current round number.
    pub fn current_round(&self) -> u8 {
        self.current_round
    }
}
