//! Shared types used across all MPC protocol modules.
//!
//! These types define the data structures exchanged between protocol participants
//! and stored persistently. All types derive `Serialize`/`Deserialize` for
//! transport over the wire and storage to disk.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// MPC session identifier — the 32-byte SessionId per MPC-Spec §04.
///
/// Wire encoding (JSON): lowercase hex, no `0x` prefix, exactly 64 chars.
/// In-memory: raw bytes for direct use in the canonical ExecutionId formula
/// (§02), the SessionId formula (§04), and storage key paths.
///
/// Construct via [`SessionId::from_hex`] (boundary parse) or directly from
/// raw bytes when computing per [`crate::canonical::canonical_session_id`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; 32]);

impl SessionId {
    /// Construct a SessionId from 32 raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parse a SessionId from its 64-char lowercase-hex wire form.
    ///
    /// Mixed case is rejected — wire format is normative lowercase per §04
    /// canonical-encoding discipline. Length not equal to 64 hex chars is
    /// rejected.
    pub fn from_hex(s: &str) -> crate::Result<Self> {
        if s.len() != 64 {
            return Err(crate::MpcError::Serialization(format!(
                "SessionId hex must be 64 chars, got {}",
                s.len()
            )));
        }
        if s.bytes().any(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(crate::MpcError::Serialization(
                "SessionId hex must be lowercase 0-9a-f".into(),
            ));
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out)
            .map_err(|e| crate::MpcError::Serialization(format!("SessionId hex decode: {e}")))?;
        Ok(Self(out))
    }

    /// Render to lowercase hex (no prefix, 64 chars).
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Raw 32-byte slice — feed directly to canonical formulas.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// **Migration helper:** derive a SessionId by hashing an arbitrary
    /// server-side token string. Used by HTTP-layer routing tokens that
    /// pre-date the §04 canonical SessionId formula.
    ///
    /// NOT a substitute for [`crate::canonical::canonical_session_id`] —
    /// real ceremony binding MUST use the canonical formula. This helper
    /// exists only so legacy `SessionId(uuid_string)` sites keep working
    /// during the wire-canonical migration (MPC-Spec #3, ADR-0004).
    pub fn from_str_hash(token: &str) -> Self {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"bsv-mpc-legacy-session-token-v0");
        h.update(token.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        Self(out)
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.hex())
    }
}

impl Serialize for SessionId {
    fn serialize<S: Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        ser.serialize_str(&self.hex())
    }
}

impl<'de> Deserialize<'de> for SessionId {
    fn deserialize<D: Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        let s = <String as Deserialize>::deserialize(de)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
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
///
/// Carries the joint public key in cleartext (`joint_pubkey_compressed`) so
/// coordinators built from a stored share can derive the canonical
/// ExecutionId per MPC-Spec §02 without round-tripping to the DKG result.
/// The joint pubkey is public information — no secret leakage.
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
    /// Joint public key for this share (33-byte compressed secp256k1).
    /// Empty (`Vec::new()`) only during DKG keygen before the joint key is
    /// known; callers MUST fill in from `DkgResult.joint_key.compressed`
    /// before persisting or using for sign/presign.
    #[serde(default)]
    pub joint_pubkey_compressed: Vec<u8>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_hex_roundtrip() {
        let bytes = [
            0xf2, 0x5e, 0x7c, 0x5e, 0x56, 0x0e, 0x01, 0x92, 0x6d, 0xfb, 0xfd, 0x70, 0xf3, 0x94,
            0x03, 0x52, 0xc1, 0x34, 0x9e, 0x1e, 0x69, 0xa2, 0xf1, 0x7c, 0x16, 0x68, 0xbd, 0xa9,
            0x88, 0x01, 0x4e, 0x0b,
        ];
        let sid = SessionId(bytes);
        let h = sid.hex();
        assert_eq!(
            h,
            "f25e7c5e560e01926dfbfd70f3940352c1349e1e69a2f17c1668bda988014e0b"
        );
        let parsed = SessionId::from_hex(&h).unwrap();
        assert_eq!(sid, parsed);
    }

    #[test]
    fn session_id_serde_as_hex() {
        let sid = SessionId([0xab; 32]);
        let j = serde_json::to_string(&sid).unwrap();
        assert_eq!(j, format!("\"{}\"", "ab".repeat(32)));
        let back: SessionId = serde_json::from_str(&j).unwrap();
        assert_eq!(back, sid);
    }

    #[test]
    fn session_id_rejects_short_hex() {
        assert!(SessionId::from_hex("deadbeef").is_err());
    }

    #[test]
    fn session_id_rejects_mixed_case() {
        let s = "F25E7C5E560E01926DFBFD70F3940352C1349E1E69A2F17C1668BDA988014E0B";
        assert!(SessionId::from_hex(s).is_err());
    }

    #[test]
    fn session_id_rejects_non_hex() {
        let s = "g25e7c5e560e01926dfbfd70f3940352c1349e1e69a2f17c1668bda988014e0b";
        assert!(SessionId::from_hex(s).is_err());
    }
}
