//! Shared types used across all MPC protocol modules.
//!
//! These types define the data structures exchanged between protocol participants
//! and stored persistently. All types derive `Serialize`/`Deserialize` for
//! transport over the wire and storage to disk.

use serde::{Deserialize, Serialize};

/// MPC session identifier, derived as the SHA-256 hash of the DKG transcript.
///
/// The session ID uniquely binds a group of share-holders to the key they
/// generated together. It is used to look up shares, presignatures, and
/// participation proofs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub String);

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Index of a share-holder in the MPC group (0-indexed).
///
/// In a t-of-n scheme, each party is assigned a unique index in `[0, n)`.
/// This index determines their position in the Shamir secret sharing polynomial
/// evaluation and is used to route point-to-point protocol messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShareIndex(pub u16);

impl std::fmt::Display for ShareIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Threshold configuration: t-of-n.
///
/// Defines how many parties (`threshold`) out of the total (`parties`) must
/// cooperate to produce a valid signature. The threshold must satisfy
/// `2 <= threshold <= parties`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Minimum number of signers required to produce a signature.
    pub threshold: u16,
    /// Total number of share-holders in the MPC group.
    pub parties: u16,
}

impl ThresholdConfig {
    /// Create a new threshold configuration, validating constraints.
    ///
    /// Returns `Err` if `threshold < 2` or `threshold > parties`.
    pub fn new(threshold: u16, parties: u16) -> crate::Result<Self> {
        if threshold < 2 || threshold > parties {
            return Err(crate::MpcError::InvalidThreshold {
                t: threshold,
                n: parties,
            });
        }
        Ok(Self { threshold, parties })
    }
}

/// The joint public key produced by DKG — the agent's BSV address.
///
/// After a successful DKG ceremony, all parties hold shares of the private key
/// corresponding to this public key. The public key is a standard compressed
/// secp256k1 point and can be used to derive a P2PKH BSV address.
///
/// Key derivation uses BRC-42 (not BIP-32). See `hd.rs` and
/// ~/bsv/BRCs/key-derivation/0042.md for the derivation algorithm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JointPublicKey {
    /// Compressed 33-byte secp256k1 public key (02/03 prefix + 32-byte x-coordinate).
    pub compressed: Vec<u8>,
    /// BSV address derived from this key (Base58Check P2PKH).
    pub address: String,
}

/// Encrypted key share for persistent storage.
///
/// Shares are encrypted with AES-256-GCM using a key derived via BRC-42
/// (HMAC-SHA256 of the root wallet key + session ID). The encrypted share
/// can be safely stored on disk or synced to a backup service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedShare {
    /// AES-256-GCM nonce (12 bytes). Randomly generated per encryption.
    pub nonce: Vec<u8>,
    /// AES-256-GCM ciphertext (share data + 16-byte auth tag).
    pub ciphertext: Vec<u8>,
    /// Session this share belongs to.
    pub session_id: SessionId,
    /// This holder's index in the MPC group.
    pub share_index: ShareIndex,
    /// Threshold configuration for the group.
    pub config: ThresholdConfig,
}

/// A completed presignature ready for one-round online signing.
///
/// Presignatures are generated during the offline phase (3 rounds between
/// parties) and consumed during online signing (1 round). Each presignature
/// can be used exactly once. Stockpiling presignatures in advance reduces
/// signing latency from 4 rounds to 1 round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Presignature {
    /// Unique identifier for this presignature (UUID or hash).
    pub id: String,
    /// Session this presignature was generated for.
    pub session_id: SessionId,
    /// Serialized cggmp24 presigning state (opaque bytes).
    ///
    /// This contains the party's share of the nonce `k` and related
    /// zero-knowledge proofs. The format is defined by the cggmp24 crate.
    pub data: Vec<u8>,
    /// When this presignature was created (UTC).
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// A BRC-18 participation proof for on-chain fee distribution.
///
/// After a threshold signing ceremony completes, each participating node
/// produces a participation proof. This proof can be serialized to an
/// OP_RETURN output and included in a BSV transaction, creating an
/// immutable on-chain record of which nodes contributed to the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipationProof {
    /// SHA-256 hash of the signing session transcript.
    pub session_hash: Vec<u8>,
    /// This agent's identity key (33-byte compressed secp256k1 public key).
    pub agent_identity: Vec<u8>,
    /// Identity keys of all nodes that participated in this signing ceremony.
    pub participating_nodes: Vec<Vec<u8>>,
    /// SHA-256 hash of the message (sighash) that was signed.
    pub signing_hash: Vec<u8>,
    /// Transaction ID of the fee distribution output, if already broadcast.
    pub fee_txid: Option<String>,
    /// When this proof was created (UTC).
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// An MPC protocol round message exchanged between nodes.
///
/// The CGGMP'24 protocol proceeds in rounds. Each round, parties exchange
/// messages containing commitments, shares, and zero-knowledge proofs.
/// Messages can be either broadcast (sent to all parties) or point-to-point
/// (sent to a specific party).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundMessage {
    /// Which MPC session this message belongs to.
    pub session_id: SessionId,
    /// Round number within the protocol (0-indexed).
    pub round: u8,
    /// Sender's share index.
    pub from: ShareIndex,
    /// Intended recipient. `None` means this is a broadcast message.
    pub to: Option<ShareIndex>,
    /// Protocol message payload (opaque bytes, serialized cggmp24 data).
    pub payload: Vec<u8>,
}

/// Result of a successful DKG ceremony.
///
/// Contains everything a party needs after DKG: the joint public key
/// (shared by all parties), their encrypted share (private to them),
/// and the session ID that binds it all together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgResult {
    /// The joint public key that all parties share.
    pub joint_key: JointPublicKey,
    /// This party's encrypted key share.
    pub share: EncryptedShare,
    /// Session identifier (SHA-256 of the DKG transcript).
    pub session_id: SessionId,
}

/// Result of a successful threshold signing operation.
///
/// Contains the ECDSA signature in multiple formats (DER, raw r/s, recovery ID)
/// plus the participation proof for on-chain fee distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningResult {
    /// DER-encoded ECDSA signature (suitable for BSV Script).
    pub signature: Vec<u8>,
    /// Raw `r` value (32 bytes, big-endian).
    pub r: Vec<u8>,
    /// Raw `s` value (32 bytes, big-endian).
    pub s: Vec<u8>,
    /// Recovery ID (0 or 1), used for public key recovery from the signature.
    pub recovery_id: u8,
    /// Participation proof recording which nodes contributed to this signature.
    pub proof: ParticipationProof,
}
