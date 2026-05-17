//! Canonical wire-format helpers per MPC-Spec §02 (ExecutionId) and §04 (SessionId).
//!
//! These functions are the single source of truth for the wire-compat tags
//! threaded through every cggmp24 transcript hash and every BRC-22 audit
//! envelope. Both implementations (bsv-mpc, rust-mpc) MUST produce
//! byte-identical outputs from identical inputs — that's the merge gate.
//!
//! See `~/bsv/mpc/MPC-Spec/02-execution-id.md` and `04-session-id.md` for the
//! normative spec. Conformance vectors live in
//! `tests/fixtures/02-execution-id.json` and `tests/fixtures/04-session-id.json`
//! (vendored from the MPC-Spec repo so this crate compiles standalone).

use sha2::{Digest, Sha256};

use crate::error::{MpcError, Result};
use crate::types::SessionId;

// ---------------------------------------------------------------------------
// §02 Canonical ExecutionId
// ---------------------------------------------------------------------------

/// 18-byte ASCII domain separator for §02 ExecutionId — no terminator, no
/// length prefix. Locked by MPC-Spec §02.5.
pub const EXECUTION_ID_DOMAIN: &[u8] = b"calhoun-binary-mpc";

/// MPC-spec version byte for `mpc-spec-v1`. Bumped only by spec-version bump.
pub const SPEC_VERSION_V1: u8 = 0x01;

/// Algorithm tag (§02.3 / §01).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlgorithmTag {
    Cggmp24 = 0x01,
    // Dkls23 = 0x02 — reserved for spec v2
    // Frost = 0x03 — reserved for spec v3
}

/// Phase tag (§02.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PhaseTag {
    DkgKeygen = 0x01,
    DkgAuxInfo = 0x02,
    Presign = 0x03,
    Sign = 0x04,
    Ecdh = 0x05,
    Refresh = 0x06,
}

impl PhaseTag {
    /// The §05 envelope text-string spelling for this phase.
    pub fn envelope_str(self) -> &'static str {
        match self {
            Self::DkgKeygen => "dkg-keygen",
            Self::DkgAuxInfo => "dkg-auxinfo",
            Self::Presign => "presign",
            Self::Sign => "sign",
            Self::Ecdh => "ecdh",
            Self::Refresh => "refresh",
        }
    }
}

/// Inputs to the canonical ExecutionId formula per §02.2.
///
/// `joint_pubkey` is 33 zero bytes during DKG keygen (phase `0x01`) per §02.4;
/// otherwise it's the canonical compressed encoding (33 bytes, prefix `0x02`/
/// `0x03`) of the joint public key produced by the prior DKG.
#[derive(Debug, Clone, Copy)]
pub struct ExecutionParams {
    pub version: u8,
    pub algorithm: AlgorithmTag,
    pub phase: PhaseTag,
    pub session_id: SessionId,
    pub joint_pubkey: [u8; 33],
}

impl ExecutionParams {
    /// Convenience: build params for the common case (`mpc-spec-v1`, cggmp24,
    /// caller picks phase). Caller is responsible for passing the all-zero
    /// joint_pubkey during DKG keygen per §02.4.
    pub fn new_v1(phase: PhaseTag, session_id: SessionId, joint_pubkey: [u8; 33]) -> Self {
        Self {
            version: SPEC_VERSION_V1,
            algorithm: AlgorithmTag::Cggmp24,
            phase,
            session_id,
            joint_pubkey,
        }
    }
}

/// Compute the canonical 32-byte ExecutionId per MPC-Spec §02.2.
///
/// Formula: `SHA-256(domain (18B) || version (1B) || alg (1B) || phase (1B) ||
/// session_id (32B) || joint_pubkey (33B))` — 86-byte preimage, 32-byte output.
pub fn canonical_execution_id(params: &ExecutionParams) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(EXECUTION_ID_DOMAIN);
    h.update([params.version]);
    h.update([params.algorithm as u8]);
    h.update([params.phase as u8]);
    h.update(params.session_id.0);
    h.update(params.joint_pubkey);
    let out = h.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

// ---------------------------------------------------------------------------
// §04 Canonical SessionId
// ---------------------------------------------------------------------------

/// 29-byte ASCII domain separator for §04 SessionId. Locked by §04.2.
pub const SESSION_ID_DOMAIN: &[u8] = b"calhoun-binary-mpc-session-v1";

/// Ceremony kind byte (§04.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CeremonyKind {
    Dkg = 0x01,
    Sign = 0x02,
    Presign = 0x03,
    Ecdh = 0x04,
    Refresh = 0x05,
    PartyReplacement = 0x06,
    ThresholdChange = 0x07,
}

/// Inputs to the canonical SessionId formula per §04.2.
///
/// `participants` MUST contain every participating cosigner's BRC-31 identity
/// pubkey including the initiator's; duplicates are forbidden. This helper
/// sorts them lex-ascending per §04.6 — callers MAY pass unsorted.
#[derive(Debug, Clone)]
pub struct SessionParams {
    pub initiator_identity: [u8; 33],
    pub participants: Vec<[u8; 33]>,
    pub threshold: u16,
    pub kind: CeremonyKind,
    pub nonce: [u8; 32],
    pub payload_digest: [u8; 32],
}

impl SessionParams {
    fn sorted_participants(&self) -> Result<Vec<[u8; 33]>> {
        let mut v = self.participants.clone();
        v.sort();
        for w in v.windows(2) {
            if w[0] == w[1] {
                return Err(MpcError::InvalidConfig(
                    "SessionParams.participants contains duplicate identity".into(),
                ));
            }
        }
        Ok(v)
    }
}

/// Compute the canonical 32-byte SessionId per MPC-Spec §04.2.
///
/// Formula: `SHA-256(domain (29B) || initiator (33B) || sorted_participants
/// (33*n B) || threshold (u16 LE) || kind (1B) || nonce (32B) || payload_digest
/// (32B))` → 32-byte output.
///
/// Errors:
/// - `InvalidConfig` if `participants` contains duplicates (§04.6).
/// - `InvalidConfig` if `nonce` is all-zero (§04.9).
pub fn canonical_session_id(params: &SessionParams) -> Result<SessionId> {
    if params.nonce == [0u8; 32] {
        return Err(MpcError::InvalidConfig(
            "SessionParams.nonce must be non-zero per §04.9".into(),
        ));
    }
    let sorted = params.sorted_participants()?;

    let mut h = Sha256::new();
    h.update(SESSION_ID_DOMAIN);
    h.update(params.initiator_identity);
    for p in &sorted {
        h.update(p);
    }
    h.update(params.threshold.to_le_bytes());
    h.update([params.kind as u8]);
    h.update(params.nonce);
    h.update(params.payload_digest);
    let out = h.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    Ok(SessionId(bytes))
}

// ---------------------------------------------------------------------------
// §04.5 Payload-digest helpers
// ---------------------------------------------------------------------------

/// Payload digest for the Sign ceremony kind (§04.5): the 32-byte sighash
/// itself.
pub fn payload_digest_sign(sighash: &[u8; 32]) -> [u8; 32] {
    *sighash
}

/// Payload digest for the DKG ceremony kind (§04.5):
/// `SHA-256("genesis" || canonical_cbor(policy_manifest))`.
///
/// Pass the policy manifest already-canonicalized (empty CBOR map `0xa0` for
/// the genesis-empty-manifest case in §04.10.2).
pub fn payload_digest_dkg(canonical_cbor_policy_manifest: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"genesis");
    h.update(canonical_cbor_policy_manifest);
    let out = h.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

/// Payload digest for the Presign ceremony kind (§04.5):
/// `SHA-256("presig-pool" || pool_id (32B))`.
pub fn payload_digest_presign(pool_id: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"presig-pool");
    h.update(pool_id);
    let out = h.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

/// Payload digest for the ECDH ceremony kind (§04.5):
/// `SHA-256("ecdh" || counterparty_pub (33B) || canonical_cbor(invoice_string))`.
pub fn payload_digest_ecdh(counterparty_pub: &[u8; 33], canonical_cbor_invoice: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ecdh");
    h.update(counterparty_pub);
    h.update(canonical_cbor_invoice);
    let out = h.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

/// Payload digest for the Refresh ceremony kind (§04.5):
/// `SHA-256("refresh" || joint_pubkey (33B) || epoch (u64 LE))`.
pub fn payload_digest_refresh(joint_pubkey: &[u8; 33], epoch: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"refresh");
    h.update(joint_pubkey);
    h.update(epoch.to_le_bytes());
    let out = h.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(s: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(s);
        let out = h.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&out);
        bytes
    }

    fn from_hex_33(s: &str) -> [u8; 33] {
        let mut out = [0u8; 33];
        hex::decode_to_slice(s, &mut out).unwrap();
        out
    }

    // ---- §02 vector A: sign phase, joint key known ----
    #[test]
    fn execution_id_vector_a_sign_phase() {
        let session_bytes = sha(b"test-vector-A");
        let joint_pk =
            from_hex_33("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let params = ExecutionParams::new_v1(PhaseTag::Sign, SessionId(session_bytes), joint_pk);
        let eid = canonical_execution_id(&params);
        assert_eq!(
            hex::encode(eid),
            "7286fe7b26a8ef9af0f42c517f53963d642602965b341cc0002084b1e801e883"
        );
    }

    // ---- §02 vector B: keygen phase, all-zero joint key carve-out ----
    #[test]
    fn execution_id_vector_b_keygen_carve_out() {
        let session_bytes = sha(b"test-vector-B");
        let params =
            ExecutionParams::new_v1(PhaseTag::DkgKeygen, SessionId(session_bytes), [0u8; 33]);
        let eid = canonical_execution_id(&params);
        assert_eq!(
            hex::encode(eid),
            "3bf98ecfaaabc27c71aabfd5d1a41533df7b8e5421f24ca2df5e200f82b0040a"
        );
    }

    // ---- §02 vector C: refresh phase ----
    #[test]
    fn execution_id_vector_c_refresh() {
        let session_bytes = sha(b"test-vector-C");
        let joint_pk =
            from_hex_33("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let params = ExecutionParams::new_v1(PhaseTag::Refresh, SessionId(session_bytes), joint_pk);
        let eid = canonical_execution_id(&params);
        assert_eq!(
            hex::encode(eid),
            "163ca28a96cee2da1c572c58be0bad3d501099a31f81cd4b3753f8bd02faa5c3"
        );
    }

    // ---- §04 vector A: routine 2-of-3 sign ----
    #[test]
    fn session_id_vector_a_sign_2of3() {
        let p1 = from_hex_33("020000000000000000000000000000000000000000000000000000000000000001");
        let p2 = from_hex_33("020000000000000000000000000000000000000000000000000000000000000002");
        let p3 = from_hex_33("020000000000000000000000000000000000000000000000000000000000000003");
        let nonce = sha(b"nonce-A");
        let payload = sha(b"sighash-A");
        let params = SessionParams {
            initiator_identity: p1,
            participants: vec![p1, p2, p3],
            threshold: 2,
            kind: CeremonyKind::Sign,
            nonce,
            payload_digest: payload,
        };
        let sid = canonical_session_id(&params).unwrap();
        assert_eq!(
            sid.hex(),
            "5be3c18ab094f090c92be1bac47bee388ab8ead59b987679d9bef53547a16108"
        );
    }

    // ---- §04 vector B: DKG with on-chain anchor + empty policy manifest ----
    #[test]
    fn session_id_vector_b_dkg_with_anchor() {
        let p1 = from_hex_33("020000000000000000000000000000000000000000000000000000000000000001");
        let p2 = from_hex_33("020000000000000000000000000000000000000000000000000000000000000002");
        let p3 = from_hex_33("020000000000000000000000000000000000000000000000000000000000000003");
        let nonce = sha(b"block-800000-anchor");
        // canonical_cbor({}) = 0xa0
        let payload = payload_digest_dkg(&[0xa0]);
        assert_eq!(
            hex::encode(payload),
            "f7dc1bd2af02a533ab389c8f67eb4c9c5c49d9c40932129bc2bf6f07b111f232"
        );
        let params = SessionParams {
            initiator_identity: p1,
            participants: vec![p1, p2, p3],
            threshold: 2,
            kind: CeremonyKind::Dkg,
            nonce,
            payload_digest: payload,
        };
        let sid = canonical_session_id(&params).unwrap();
        assert_eq!(
            sid.hex(),
            "e0af05e32667e3553df110a1ff621a5fe7b449b5c515e6886b4b2e38270e6a0f"
        );
    }

    // ---- §04 negative: sort-order invariance (passing unsorted -> same result) ----
    #[test]
    fn session_id_sorts_participants() {
        let p1 = from_hex_33("020000000000000000000000000000000000000000000000000000000000000001");
        let p2 = from_hex_33("020000000000000000000000000000000000000000000000000000000000000002");
        let p3 = from_hex_33("020000000000000000000000000000000000000000000000000000000000000003");
        let nonce = sha(b"nonce-A");
        let payload = sha(b"sighash-A");

        let sorted = SessionParams {
            initiator_identity: p1,
            participants: vec![p1, p2, p3],
            threshold: 2,
            kind: CeremonyKind::Sign,
            nonce,
            payload_digest: payload,
        };
        let unsorted = SessionParams {
            initiator_identity: p1,
            participants: vec![p3, p1, p2],
            threshold: 2,
            kind: CeremonyKind::Sign,
            nonce,
            payload_digest: payload,
        };
        assert_eq!(
            canonical_session_id(&sorted).unwrap(),
            canonical_session_id(&unsorted).unwrap(),
        );
    }

    // ---- §04.9 forbidden: zero-nonce ----
    #[test]
    fn session_id_rejects_zero_nonce() {
        let p1 = from_hex_33("020000000000000000000000000000000000000000000000000000000000000001");
        let params = SessionParams {
            initiator_identity: p1,
            participants: vec![p1],
            threshold: 2,
            kind: CeremonyKind::Sign,
            nonce: [0u8; 32],
            payload_digest: [0u8; 32],
        };
        assert!(canonical_session_id(&params).is_err());
    }

    // ---- §04.6 forbidden: duplicate participants ----
    #[test]
    fn session_id_rejects_duplicate_participants() {
        let p1 = from_hex_33("020000000000000000000000000000000000000000000000000000000000000001");
        let params = SessionParams {
            initiator_identity: p1,
            participants: vec![p1, p1],
            threshold: 2,
            kind: CeremonyKind::Sign,
            nonce: sha(b"x"),
            payload_digest: sha(b"y"),
        };
        assert!(canonical_session_id(&params).is_err());
    }

    // ---- §02.6 preimage byte-count discipline ----
    #[test]
    fn execution_id_preimage_is_86_bytes() {
        // Verify by reconstructing the preimage by hand for vector A.
        let session_bytes = sha(b"test-vector-A");
        let joint_pk =
            from_hex_33("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let mut preimage = Vec::new();
        preimage.extend_from_slice(EXECUTION_ID_DOMAIN);
        preimage.push(SPEC_VERSION_V1);
        preimage.push(AlgorithmTag::Cggmp24 as u8);
        preimage.push(PhaseTag::Sign as u8);
        preimage.extend_from_slice(&session_bytes);
        preimage.extend_from_slice(&joint_pk);
        assert_eq!(preimage.len(), 86);
        assert_eq!(EXECUTION_ID_DOMAIN.len(), 18);

        let params = ExecutionParams::new_v1(PhaseTag::Sign, SessionId(session_bytes), joint_pk);
        assert_eq!(canonical_execution_id(&params), sha(&preimage));
    }
}
