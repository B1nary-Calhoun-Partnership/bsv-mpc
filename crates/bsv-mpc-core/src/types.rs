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

/// Canonical policy hash a presig is bound to (per MPC-Spec §09).
///
/// 32-byte hash of the active PolicyManifest. Serializes as a CBOR byte string
/// (`bstr32`) — see [`PresigBundle`]. One third of the §06.17.1 binding triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PolicyId(pub [u8; 32]);

impl PolicyId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

// `bstr32` wire shape: serialize the raw 32 bytes as a CBOR byte string, not an
// array-of-int. Mirrors the custom-impl pattern used by `SessionId` above.
impl Serialize for PolicyId {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serde_bytes::serialize(&self.0[..], serializer)
    }
}

impl<'de> Deserialize<'de> for PolicyId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let bytes: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            serde::de::Error::invalid_length(bytes.len(), &"32-byte policy_id")
        })?;
        Ok(Self(arr))
    }
}

/// The §06.17.1 **binding triple**: a presig is consumable only when all three
/// match the current ceremony. Used to enforce §06.18 mandatory invalidation —
/// any divergence (policy update, joint-pubkey change, cosigner-subset change)
/// makes the bound bundle stale.
///
/// `joint_pubkey` is the 33-byte compressed secp256k1 point; `parties_at_keygen`
/// is the cosigner subset (party indices) in canonical (ascending) order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresigBinding {
    pub policy_id: PolicyId,
    pub joint_pubkey: Vec<u8>,
    pub parties_at_keygen: Vec<u16>,
}

/// A §06.18 mandatory-invalidation trigger. Each variant carries the prior /
/// current binding value it scopes deletion by, mapping 1:1 to the §06.18 table
/// and the `bundles_invalidated_total{reason}` label (refresh|subset|policy|rekey).
#[derive(Debug, Clone)]
pub enum InvalidationTrigger<'a> {
    /// Share refresh commit (§18) — purge ALL bundles for the refreshed joint
    /// pubkey (their shares are now stale). Reason label: `refresh`.
    ShareRefresh { joint_pubkey: &'a [u8] },
    /// Joint-pubkey change, e.g. post-recovery rekeying (§18) — purge all
    /// bundles for the prior joint pubkey. Reason label: `rekey`.
    JointPubkeyChange { prior_joint_pubkey: &'a [u8] },
    /// Cosigner subset change / operator replacement (§13.7) — purge bundles
    /// bound to the prior subset (ascending order). Reason label: `subset`.
    CosignerSubsetChange { prior_subset: &'a [u16] },
    /// Policy manifest update (§09) — purge bundles whose `policy_id` no longer
    /// matches the current manifest. Reason label: `policy`.
    PolicyUpdate { current_policy_id: PolicyId },
}

/// Coordinator's stored unit per successful presign session (MPC-Spec §06.17.1,
/// ADR-0030). The coordinator holds its OWN plaintext presig share
/// (`presig_bytes`, protected by the at-rest layer — §06.17.1) alongside one
/// opaque BRC-2 ciphertext per cosigner (`cosigner_encrypted_shares`); it MUST
/// NOT be able to read a cosigner's share at rest.
///
/// Byte fields use `serde_bytes` so a CBOR encoding (ADR-0030 §125 — wire-stable
/// for cross-instance migration / operator handoff per §13.7) emits `bstr` /
/// `bstr32` / `bstr33` rather than arrays-of-int. Field order is fixed and the
/// encoding is deterministic; see [`PresigBundle::to_cbor`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresigBundle {
    /// Unique per presig; canonical form = the presign session_id.
    pub presig_id: String,
    /// Coordinator's own serialized presig share (plaintext at rest under the
    /// coordinator's at-rest encryption — §06.17.1).
    #[serde(with = "serde_bytes")]
    pub presig_bytes: Vec<u8>,
    /// One BRC-2 ciphertext per cosigner, indexed positionally by party order in
    /// `parties_at_keygen`. Opaque to the coordinator until sign-time (§06.20).
    pub cosigner_encrypted_shares: Vec<serde_bytes::ByteBuf>,
    /// Shared Gamma commitment (hex).
    pub gamma_hex: String,
    /// Serialized PresignaturePublicData commitments (CBOR).
    #[serde(with = "serde_bytes")]
    pub commitments: Vec<u8>,
    /// Canonical policy hash this presig is bound to (§09). Binding-triple member.
    pub policy_id: PolicyId,
    /// Joint pubkey (33-byte compressed) this presig is bound to. Binding-triple member.
    #[serde(with = "serde_bytes")]
    pub joint_pubkey: Vec<u8>,
    /// Cosigner subset (party indices) this presig is bound to. Binding-triple member.
    pub parties_at_keygen: Vec<u16>,
    /// Unix timestamp (seconds) — operational only; NOT security-load-bearing.
    pub generated_at: u64,
}

impl PresigBundle {
    /// The §06.17.1 binding triple `(policy_id, joint_pubkey, parties_at_keygen)`.
    pub fn binding(&self) -> PresigBinding {
        PresigBinding {
            policy_id: self.policy_id,
            joint_pubkey: self.joint_pubkey.clone(),
            parties_at_keygen: self.parties_at_keygen.clone(),
        }
    }

    /// True iff this bundle is consumable under the given current binding — i.e.
    /// ALL three triple members match. Any single-axis divergence returns false
    /// (the §06.18 invalidation conditions). Party-subset comparison is
    /// order-sensitive; callers MUST pass `parties_at_keygen` in canonical
    /// (ascending) order, matching how the bundle was generated.
    pub fn matches_binding(&self, current: &PresigBinding) -> bool {
        self.policy_id == current.policy_id
            && self.joint_pubkey == current.joint_pubkey
            && self.parties_at_keygen == current.parties_at_keygen
    }

    /// Whether this bundle MUST be deleted under the given §06.18 trigger.
    ///
    /// A bundle MUST NOT be consumable across an invalidation boundary; this is
    /// the predicate the coordinator applies on each trigger (and, defense in
    /// depth, the consume path re-checks via [`PresigBundle::matches_binding`]).
    pub fn invalidated_by(&self, trigger: &InvalidationTrigger) -> bool {
        match trigger {
            InvalidationTrigger::ShareRefresh { joint_pubkey } => {
                self.joint_pubkey == *joint_pubkey
            }
            InvalidationTrigger::JointPubkeyChange { prior_joint_pubkey } => {
                self.joint_pubkey == *prior_joint_pubkey
            }
            InvalidationTrigger::CosignerSubsetChange { prior_subset } => {
                self.parties_at_keygen == *prior_subset
            }
            InvalidationTrigger::PolicyUpdate { current_policy_id } => {
                self.policy_id != *current_policy_id
            }
        }
    }

    /// Canonical string form of the binding triple for storage indexing /
    /// invalidation queries (item 4/6): `(policy_id_hex, joint_pubkey_hex,
    /// parties_csv)`. `parties_csv` is the ascending-ordered party indices joined
    /// by `,` — the canonical subset key §06.18 matches against. These are the
    /// exact values the worker's `mpc_presig_bundles` binding columns hold.
    pub fn storage_columns(&self) -> (String, String, String) {
        let parties_csv = self
            .parties_at_keygen
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        (
            self.policy_id.hex(),
            hex::encode(&self.joint_pubkey),
            parties_csv,
        )
    }

    /// Deterministic CBOR encoding (ADR-0030 §125). Field order is fixed by the
    /// struct definition and ciborium does not reorder, so re-encoding an
    /// identical bundle yields byte-identical output — the migration/handoff
    /// stability property §13.7 relies on.
    pub fn to_cbor(&self) -> crate::Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf)
            .map_err(|e| crate::MpcError::Serialization(format!("PresigBundle CBOR encode: {e}")))?;
        Ok(buf)
    }

    /// Inverse of [`PresigBundle::to_cbor`].
    pub fn from_cbor(bytes: &[u8]) -> crate::Result<Self> {
        ciborium::de::from_reader(bytes)
            .map_err(|e| crate::MpcError::Serialization(format!("PresigBundle CBOR decode: {e}")))
    }
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

    // ---- §06.17.1 PresigBundle + binding triple (ADR-0030) ----

    fn sample_bundle() -> PresigBundle {
        PresigBundle {
            presig_id: "presig-test-vector-001".to_string(),
            presig_bytes: vec![0xaa; 48],
            cosigner_encrypted_shares: vec![
                serde_bytes::ByteBuf::from(vec![0x01, 0x02, 0x03]),
                serde_bytes::ByteBuf::from(vec![0x04, 0x05]),
            ],
            gamma_hex: "02deadbeef".to_string(),
            commitments: vec![0xcb; 16],
            policy_id: PolicyId([0x11; 32]),
            joint_pubkey: vec![0x02; 33],
            parties_at_keygen: vec![0, 1, 2],
            generated_at: 1_716_000_000,
        }
    }

    #[test]
    fn presig_bundle_cbor_roundtrip_byte_stable() {
        let b = sample_bundle();
        // Deterministic: re-encoding the identical bundle yields identical bytes
        // (the §13.7 migration/handoff stability property).
        let c1 = b.to_cbor().unwrap();
        let c2 = b.to_cbor().unwrap();
        assert_eq!(c1, c2, "CBOR encoding must be byte-stable across runs");
        // Round-trips back to an equal struct.
        let decoded = PresigBundle::from_cbor(&c1).unwrap();
        assert_eq!(decoded, b, "CBOR round-trip must preserve the bundle");
    }

    #[test]
    fn policy_id_encodes_as_cbor_byte_string() {
        // bstr32 wire shape: 0x58 0x20 == CBOR byte-string, length 32. If PolicyId
        // serialized as an array-of-int (the serde default for [u8;32]) this fails.
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&PolicyId([0x11; 32]), &mut buf).unwrap();
        assert_eq!(buf[0], 0x58, "expected CBOR byte-string major type (0x58)");
        assert_eq!(buf[1], 0x20, "expected length 32");
        assert_eq!(buf.len(), 2 + 32);
    }

    #[test]
    fn storage_columns_are_canonical() {
        let b = sample_bundle();
        let (policy_hex, jpk_hex, parties_csv) = b.storage_columns();
        assert_eq!(policy_hex, "11".repeat(32));
        assert_eq!(jpk_hex, "02".repeat(33));
        assert_eq!(parties_csv, "0,1,2");
    }

    #[test]
    fn matches_binding_true_only_when_all_three_match() {
        let b = sample_bundle();
        // Exact binding extracted from the bundle matches.
        assert!(b.matches_binding(&b.binding()));
    }

    #[test]
    fn invalidated_by_each_06_18_trigger() {
        let b = sample_bundle(); // joint_pubkey [0x02;33], parties [0,1,2], policy [0x11;32]

        // Share refresh for THIS joint pubkey → invalidated; a different one → not.
        assert!(b.invalidated_by(&InvalidationTrigger::ShareRefresh {
            joint_pubkey: &[0x02; 33],
        }));
        assert!(!b.invalidated_by(&InvalidationTrigger::ShareRefresh {
            joint_pubkey: &[0x03; 33],
        }));

        // Joint-pubkey change (rekey) — same predicate on the prior pubkey.
        assert!(b.invalidated_by(&InvalidationTrigger::JointPubkeyChange {
            prior_joint_pubkey: &[0x02; 33],
        }));
        assert!(!b.invalidated_by(&InvalidationTrigger::JointPubkeyChange {
            prior_joint_pubkey: &[0x03; 33],
        }));

        // Subset change — bound to the prior subset → invalidated; other subset → not.
        assert!(b.invalidated_by(&InvalidationTrigger::CosignerSubsetChange {
            prior_subset: &[0, 1, 2],
        }));
        assert!(!b.invalidated_by(&InvalidationTrigger::CosignerSubsetChange {
            prior_subset: &[0, 1, 3],
        }));

        // Policy update — invalidated when the current policy DIFFERS from the
        // bundle's bound policy; NOT invalidated when it still matches.
        assert!(b.invalidated_by(&InvalidationTrigger::PolicyUpdate {
            current_policy_id: PolicyId([0x22; 32]),
        }));
        assert!(!b.invalidated_by(&InvalidationTrigger::PolicyUpdate {
            current_policy_id: PolicyId([0x11; 32]),
        }));
    }

    #[test]
    fn pool_invalidation_purges_exactly_the_matching_bundles() {
        // §06.18 "delete ALL PresigBundle rows where ANY trigger fires", applied
        // to a heterogeneous pool. This is the selection semantics the storage
        // layer's invalidate_* methods implement; here we prove it end-to-end on
        // an in-memory pool via the core predicate.
        let mk = |jpk: u8, parties: Vec<u16>, policy: u8| {
            let mut b = sample_bundle();
            b.joint_pubkey = vec![jpk; 33];
            b.parties_at_keygen = parties;
            b.policy_id = PolicyId([policy; 32]);
            b
        };
        let pool = [
            mk(0x02, vec![0, 1, 2], 0x11), // A: current everything
            mk(0x02, vec![0, 1, 3], 0x11), // B: prior subset
            mk(0x03, vec![0, 1, 2], 0x11), // C: prior joint pubkey
            mk(0x02, vec![0, 1, 2], 0x77), // D: stale policy
        ];

        // Policy update to 0x11 → only D (policy 0x77) is purged.
        let trig = InvalidationTrigger::PolicyUpdate { current_policy_id: PolicyId([0x11; 32]) };
        let survivors: Vec<_> = pool.iter().filter(|b| !b.invalidated_by(&trig)).collect();
        assert_eq!(survivors.len(), 3);
        assert!(survivors.iter().all(|b| b.policy_id == PolicyId([0x11; 32])));

        // Subset change away from [0,1,3] → only B is purged.
        let trig = InvalidationTrigger::CosignerSubsetChange { prior_subset: &[0, 1, 3] };
        let survivors: Vec<_> = pool.iter().filter(|b| !b.invalidated_by(&trig)).collect();
        assert_eq!(survivors.len(), 3);
        assert!(survivors.iter().all(|b| b.parties_at_keygen != [0u16, 1, 3]));

        // Joint-pubkey change from 0x03 → only C is purged.
        let trig = InvalidationTrigger::JointPubkeyChange { prior_joint_pubkey: &[0x03; 33] };
        let survivors: Vec<_> = pool.iter().filter(|b| !b.invalidated_by(&trig)).collect();
        assert_eq!(survivors.len(), 3);
        assert!(survivors.iter().all(|b| b.joint_pubkey != [0x03u8; 33]));

        // Share refresh of 0x02 → A, B, D all purged (3 of 4); only C survives.
        let trig = InvalidationTrigger::ShareRefresh { joint_pubkey: &[0x02; 33] };
        let survivors: Vec<_> = pool.iter().filter(|b| !b.invalidated_by(&trig)).collect();
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].joint_pubkey, [0x03u8; 33]);
    }

    #[test]
    fn stale_bundle_is_not_consumable_after_a_policy_change() {
        // Consume-time guard (§06.18 "re-validates against the current manifest"):
        // a bundle generated under the old policy must fail matches_binding once
        // the live policy changes — even if invalidation deletion lagged.
        let b = sample_bundle();
        let mut current = b.binding();
        current.policy_id = PolicyId([0x99; 32]); // policy moved on
        assert!(
            !b.matches_binding(&current),
            "a bundle under a stale policy must not be consumable"
        );
    }

    #[test]
    fn matches_binding_false_on_any_single_axis_mismatch() {
        let b = sample_bundle();
        let base = b.binding();

        // Axis 1: policy_id differs.
        let mut m = base.clone();
        m.policy_id = PolicyId([0x22; 32]);
        assert!(!b.matches_binding(&m), "policy_id mismatch must invalidate");

        // Axis 2: joint_pubkey differs.
        let mut m = base.clone();
        m.joint_pubkey = vec![0x03; 33];
        assert!(!b.matches_binding(&m), "joint_pubkey mismatch must invalidate");

        // Axis 3: cosigner subset differs (membership).
        let mut m = base.clone();
        m.parties_at_keygen = vec![0, 1, 3];
        assert!(!b.matches_binding(&m), "subset mismatch must invalidate");

        // Axis 3b: subset reordered (order-sensitive — must NOT match).
        let mut m = base.clone();
        m.parties_at_keygen = vec![2, 1, 0];
        assert!(
            !b.matches_binding(&m),
            "reordered subset must invalidate (canonical-order requirement)"
        );

        // Sanity: the unmodified base still matches.
        assert!(b.matches_binding(&base));
    }
}
