//! BRC-18 participation proofs for on-chain fee distribution.
//!
//! When multiple MPC nodes cooperate to sign a BSV transaction, the question
//! arises: who should receive the signing fee? Participation proofs provide
//! a verifiable on-chain record of which nodes contributed to each signing
//! ceremony, enabling fair fee distribution.
//!
//! ## Proof Structure
//!
//! A participation proof is a BRC-18 OP_RETURN output containing:
//!
//! ```text
//! OP_FALSE OP_RETURN
//!   <protocol_id: "bsv-mpc-participation">
//!   <session_hash: 32 bytes>
//!   <signing_hash: 32 bytes>
//!   <agent_identity: 33 bytes>
//!   <participant_count: varint>
//!   <participant_1_identity: 33 bytes>
//!   ...
//!   <participant_n_identity: 33 bytes>
//!   <fee_txid: 32 bytes (optional)>
//!   <timestamp: 8 bytes (unix millis)>
//! ```
//!
//! ## Fee Distribution
//!
//! The fee distribution model is simple: each participating node gets an equal
//! share of the signing fee. The participation proof makes this auditable:
//!
//! 1. Transaction is signed by `t` of `n` nodes.
//! 2. Each participating node creates a participation proof.
//! 3. The fee output is split equally among the `t` participants.
//! 4. The proof is included as an OP_RETURN in the same transaction (or a
//!    separate proof transaction).
//!
//! ## Verification
//!
//! Anyone can verify a participation proof by:
//! 1. Checking the session_hash matches a known DKG session.
//! 2. Checking the signing_hash matches the signed transaction's sighash.
//! 3. Verifying that the listed participants are valid members of the session.
//! 4. Checking the fee_txid output distributes funds to the listed participants.

use sha2::{Digest, Sha256};
use std::collections::HashSet;

use crate::types::{ParticipationProof, SessionId};

/// Protocol identifier pushed into the OP_RETURN output.
///
/// This string is used by overlay topic managers and indexers to filter
/// participation proofs from other OP_RETURN data.
const PROTOCOL_ID: &[u8] = b"bsv-mpc-participation";

/// Create a participation proof for a signing ceremony.
///
/// This should be called by each participating node after a successful
/// threshold signing operation.
///
/// # Arguments
///
/// * `session_id` — The MPC session (from DKG).
/// * `agent_key` — This agent's 33-byte compressed secp256k1 identity key.
/// * `nodes` — Identity keys of all nodes that participated in this signing.
/// * `signing_hash` — The 32-byte hash of the message that was signed.
/// * `fee_txid` — Optional transaction ID of the fee distribution output.
///
/// # Returns
///
/// A [`ParticipationProof`] that can be serialized to OP_RETURN via
/// [`proof_to_op_return`].
pub fn create_participation_proof(
    session_id: &SessionId,
    agent_key: &[u8],
    nodes: &[Vec<u8>],
    signing_hash: &[u8; 32],
    fee_txid: Option<&str>,
) -> crate::Result<ParticipationProof> {
    // Validate agent key is a 33-byte compressed secp256k1 pubkey.
    if agent_key.len() != 33 {
        return Err(crate::MpcError::Protocol(format!(
            "agent_key must be 33 bytes, got {}",
            agent_key.len()
        )));
    }
    if agent_key[0] != 0x02 && agent_key[0] != 0x03 {
        return Err(crate::MpcError::Protocol(format!(
            "agent_key must start with 0x02 or 0x03, got 0x{:02x}",
            agent_key[0]
        )));
    }

    // Validate participating nodes are non-empty.
    if nodes.is_empty() {
        return Err(crate::MpcError::Protocol(
            "participating nodes must not be empty".into(),
        ));
    }

    // Validate each node key is a 33-byte compressed pubkey.
    for (i, node) in nodes.iter().enumerate() {
        if node.len() != 33 {
            return Err(crate::MpcError::Protocol(format!(
                "node {i} key must be 33 bytes, got {}",
                node.len()
            )));
        }
        if node[0] != 0x02 && node[0] != 0x03 {
            return Err(crate::MpcError::Protocol(format!(
                "node {i} key must start with 0x02 or 0x03, got 0x{:02x}",
                node[0]
            )));
        }
    }

    // Check for duplicate nodes.
    let mut seen = HashSet::new();
    for node in nodes {
        if !seen.insert(node.as_slice()) {
            return Err(crate::MpcError::Protocol(
                "duplicate node in participating_nodes".into(),
            ));
        }
    }

    // Agent must be in participants.
    if !nodes.iter().any(|n| n.as_slice() == agent_key) {
        return Err(crate::MpcError::Protocol(
            "agent_key must appear in participating_nodes".into(),
        ));
    }

    // Compute session_hash = SHA-256(session_id string bytes).
    // This binds the proof to a specific DKG session.
    let session_hash = {
        let mut hasher = Sha256::new();
        hasher.update(session_id.0.as_bytes());
        hasher.finalize().to_vec()
    };

    Ok(ParticipationProof {
        session_hash,
        agent_identity: agent_key.to_vec(),
        participating_nodes: nodes.to_vec(),
        signing_hash: signing_hash.to_vec(),
        fee_txid: fee_txid.map(String::from),
        timestamp: chrono::Utc::now(),
    })
}

/// Push data onto a script buffer using proper Bitcoin PUSHDATA encoding.
///
/// Bitcoin Script uses specific opcodes for pushing data depending on length:
/// - 0 bytes: OP_0 (0x00)
/// - 1-75 bytes: single byte length prefix, then data
/// - 76-255 bytes: OP_PUSHDATA1 (0x4c) + 1-byte length + data
/// - 256-65535 bytes: OP_PUSHDATA2 (0x4d) + 2-byte LE length + data
fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len == 0 {
        // Push empty: OP_0.
        script.push(0x00);
    } else if len <= 75 {
        // Direct push: single byte length prefix.
        script.push(len as u8);
        script.extend_from_slice(data);
    } else if len <= 255 {
        // OP_PUSHDATA1: 0x4c + 1-byte length.
        script.push(0x4c);
        script.push(len as u8);
        script.extend_from_slice(data);
    } else if len <= 65535 {
        // OP_PUSHDATA2: 0x4d + 2-byte little-endian length.
        script.push(0x4d);
        script.extend_from_slice(&(len as u16).to_le_bytes());
        script.extend_from_slice(data);
    }
    // Data > 65535 bytes is not practical for OP_RETURN outputs.
    // Bitcoin's standard OP_RETURN limit is much smaller.
    // We omit OP_PUSHDATA4 since it would never be needed here.
}

/// Serialize a participation proof to BRC-18 OP_RETURN format.
///
/// The output is a byte vector suitable for inclusion as the scriptPubKey
/// of an OP_RETURN output in a BSV transaction.
///
/// # Wire Format
///
/// ```text
/// OP_FALSE (0x00)
/// OP_RETURN (0x6a)
/// PUSH "bsv-mpc-participation" (protocol ID)
/// PUSH <session_hash> (32 bytes)
/// PUSH <signing_hash> (32 bytes)
/// PUSH <agent_identity> (33 bytes)
/// PUSH <participant_count> (varint)
/// PUSH <participant_1> (33 bytes)
/// ...
/// PUSH <participant_n> (33 bytes)
/// PUSH <fee_txid> (32 bytes, or empty if None)
/// PUSH <timestamp> (8 bytes, big-endian unix millis)
/// ```
pub fn proof_to_op_return(proof: &ParticipationProof) -> Vec<u8> {
    let mut script = Vec::new();

    // OP_FALSE (0x00) + OP_RETURN (0x6a) — marks this output as unspendable.
    script.push(0x00);
    script.push(0x6a);

    // Field: protocol ID ("bsv-mpc-participation", 21 bytes).
    push_data(&mut script, PROTOCOL_ID);

    // Field: session_hash (32 bytes).
    push_data(&mut script, &proof.session_hash);

    // Field: signing_hash (32 bytes).
    push_data(&mut script, &proof.signing_hash);

    // Field: agent_identity (33 bytes).
    push_data(&mut script, &proof.agent_identity);

    // Field: participant_count as a single byte pushed.
    // Node count fits in a single byte (max 255 participants).
    let count = proof.participating_nodes.len() as u8;
    push_data(&mut script, &[count]);

    // Fields: each participant's 33-byte identity key.
    for node in &proof.participating_nodes {
        push_data(&mut script, node);
    }

    // Field: fee_txid. If present, decode hex to 32 bytes. If absent, push empty.
    match &proof.fee_txid {
        Some(txid) => {
            // Convert hex txid to 32 raw bytes.
            let txid_bytes = hex_to_bytes(txid);
            push_data(&mut script, &txid_bytes);
        }
        None => {
            // Push empty (OP_0) to indicate no fee txid.
            push_data(&mut script, &[]);
        }
    }

    // Field: timestamp as 8-byte big-endian unix milliseconds.
    let millis = proof.timestamp.timestamp_millis() as u64;
    push_data(&mut script, &millis.to_be_bytes());

    script
}

/// Verify the structural integrity of a participation proof.
///
/// This performs local validation only (no on-chain lookups):
///
/// 1. `session_hash` is exactly 32 bytes.
/// 2. `signing_hash` is exactly 32 bytes.
/// 3. `agent_identity` is exactly 33 bytes (compressed secp256k1 pubkey).
/// 4. All entries in `participating_nodes` are exactly 33 bytes.
/// 5. `agent_identity` appears in `participating_nodes`.
/// 6. No duplicate entries in `participating_nodes`.
///
/// # Returns
///
/// `true` if all structural checks pass, `false` otherwise.
pub fn verify_participation_proof(proof: &ParticipationProof) -> bool {
    // 1. session_hash must be exactly 32 bytes (SHA-256 output).
    if proof.session_hash.len() != 32 {
        return false;
    }

    // 2. signing_hash must be exactly 32 bytes.
    if proof.signing_hash.len() != 32 {
        return false;
    }

    // 3. agent_identity must be exactly 33 bytes with valid compressed pubkey prefix.
    if !is_valid_compressed_pubkey(&proof.agent_identity) {
        return false;
    }

    // 4. participating_nodes must be non-empty.
    if proof.participating_nodes.is_empty() {
        return false;
    }

    // 5. Every node key must be a valid 33-byte compressed pubkey.
    for node in &proof.participating_nodes {
        if !is_valid_compressed_pubkey(node) {
            return false;
        }
    }

    // 6. agent_identity must appear in participating_nodes.
    if !proof.participating_nodes.contains(&proof.agent_identity) {
        return false;
    }

    // 7. No duplicate entries in participating_nodes.
    // Collect into a HashSet of byte slices and check the count matches.
    let unique: HashSet<&[u8]> = proof.participating_nodes.iter().map(|v| v.as_slice()).collect();
    if unique.len() != proof.participating_nodes.len() {
        return false;
    }

    // 8. If fee_txid is present, it must be a valid 64-character hex string
    //    (representing a 32-byte transaction ID).
    if let Some(ref txid) = proof.fee_txid {
        if txid.len() != 64 || !txid.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }

    // 9. Timestamp must not be zero (unix epoch = 1970-01-01, unreasonable for
    //    any real MPC operation).
    if proof.timestamp.timestamp_millis() == 0 {
        return false;
    }

    true
}

/// Check if a byte slice is a valid compressed secp256k1 public key format.
///
/// A compressed public key is exactly 33 bytes: a prefix byte (0x02 or 0x03)
/// followed by the 32-byte x-coordinate. This function checks only the format,
/// not whether the point is actually on the secp256k1 curve.
fn is_valid_compressed_pubkey(key: &[u8]) -> bool {
    key.len() == 33 && (key[0] == 0x02 || key[0] == 0x03)
}

/// Convert a hex string to raw bytes.
///
/// Returns an empty vec if the input is not valid hex or has odd length.
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    if hex.len() % 2 != 0 {
        return Vec::new();
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut i = 0;
    while i < hex.len() {
        match u8::from_str_radix(&hex[i..i + 2], 16) {
            Ok(b) => bytes.push(b),
            Err(_) => return Vec::new(),
        }
        i += 2;
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: generate a fake 33-byte compressed pubkey with prefix 0x02.
    fn fake_pubkey(seed: u8) -> Vec<u8> {
        let mut key = vec![0x02];
        key.extend_from_slice(&[seed; 32]);
        key
    }

    /// Helper: generate a fake 33-byte compressed pubkey with prefix 0x03.
    fn fake_pubkey_03(seed: u8) -> Vec<u8> {
        let mut key = vec![0x03];
        key.extend_from_slice(&[seed; 32]);
        key
    }

    /// Helper: a valid 32-byte hash.
    fn fake_hash(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    /// Helper: a valid 64-char hex txid.
    fn fake_txid() -> &'static str {
        "aabbccddee0011223344556677889900aabbccddee0011223344556677889900"
    }

    /// Helper: create a valid proof.
    fn valid_proof() -> ParticipationProof {
        let session = SessionId("test-session".to_string());
        let agent = fake_pubkey(0xAA);
        let nodes = vec![fake_pubkey(0xAA), fake_pubkey(0xBB)];
        create_participation_proof(&session, &agent, &nodes, &fake_hash(0x11), Some(fake_txid()))
            .expect("valid_proof helper should not fail")
    }

    // ----------------------------------------------------------------
    // create_participation_proof tests
    // ----------------------------------------------------------------

    #[test]
    fn create_proof_with_valid_inputs() {
        let session = SessionId("my-session-id".to_string());
        let agent = fake_pubkey(0x01);
        let nodes = vec![fake_pubkey(0x01), fake_pubkey(0x02)];
        let signing_hash = fake_hash(0xFF);

        let proof = create_participation_proof(
            &session,
            &agent,
            &nodes,
            &signing_hash,
            Some(fake_txid()),
        )
        .expect("should succeed with valid inputs");

        assert_eq!(proof.session_hash.len(), 32);
        assert_eq!(proof.agent_identity, agent);
        assert_eq!(proof.participating_nodes.len(), 2);
        assert_eq!(proof.signing_hash, signing_hash.to_vec());
        assert!(proof.fee_txid.is_some());
        assert_eq!(proof.fee_txid.as_deref(), Some(fake_txid()));
    }

    #[test]
    fn create_proof_without_fee_txid() {
        let session = SessionId("no-fee-session".to_string());
        let agent = fake_pubkey(0x01);
        let nodes = vec![fake_pubkey(0x01)];
        let signing_hash = fake_hash(0xAA);

        let proof = create_participation_proof(&session, &agent, &nodes, &signing_hash, None)
            .expect("should succeed without fee txid");

        assert!(proof.fee_txid.is_none());
    }

    #[test]
    fn session_hash_is_sha256_of_session_id() {
        let session = SessionId("deterministic-session".to_string());
        let agent = fake_pubkey(0x01);
        let nodes = vec![fake_pubkey(0x01)];
        let signing_hash = fake_hash(0x00);

        let proof = create_participation_proof(&session, &agent, &nodes, &signing_hash, None)
            .expect("should succeed");

        // Independently compute expected hash.
        let mut hasher = Sha256::new();
        hasher.update(b"deterministic-session");
        let expected = hasher.finalize().to_vec();

        assert_eq!(proof.session_hash, expected);
    }

    // ----------------------------------------------------------------
    // verify_participation_proof tests
    // ----------------------------------------------------------------

    #[test]
    fn verify_valid_proof_returns_true() {
        let proof = valid_proof();
        assert!(verify_participation_proof(&proof));
    }

    #[test]
    fn verify_rejects_wrong_length_session_hash() {
        let mut proof = valid_proof();
        proof.session_hash = vec![0u8; 31]; // too short
        assert!(!verify_participation_proof(&proof));

        proof.session_hash = vec![0u8; 33]; // too long
        assert!(!verify_participation_proof(&proof));
    }

    #[test]
    fn verify_rejects_wrong_length_signing_hash() {
        let mut proof = valid_proof();
        proof.signing_hash = vec![0u8; 16]; // too short
        assert!(!verify_participation_proof(&proof));
    }

    #[test]
    fn verify_rejects_wrong_length_agent_key() {
        let mut proof = valid_proof();
        proof.agent_identity = vec![0x02; 32]; // 32 bytes, not 33
        assert!(!verify_participation_proof(&proof));
    }

    #[test]
    fn verify_rejects_invalid_pubkey_prefix_04() {
        let mut proof = valid_proof();
        // Uncompressed prefix 0x04 is not valid for compressed keys.
        proof.agent_identity[0] = 0x04;
        // Also update in participating_nodes so the "agent in participants" check
        // doesn't mask this failure.
        proof.participating_nodes[0][0] = 0x04;
        assert!(!verify_participation_proof(&proof));
    }

    #[test]
    fn verify_rejects_invalid_node_key_prefix() {
        let mut proof = valid_proof();
        // Second node has invalid prefix.
        proof.participating_nodes[1] = {
            let mut key = vec![0x05]; // invalid prefix
            key.extend_from_slice(&[0xBB; 32]);
            key
        };
        assert!(!verify_participation_proof(&proof));
    }

    #[test]
    fn verify_rejects_wrong_length_node_key() {
        let mut proof = valid_proof();
        proof.participating_nodes[1] = vec![0x02; 20]; // too short
        assert!(!verify_participation_proof(&proof));
    }

    #[test]
    fn verify_rejects_duplicate_node_keys() {
        let mut proof = valid_proof();
        // Make both nodes identical.
        proof.participating_nodes[1] = proof.participating_nodes[0].clone();
        assert!(!verify_participation_proof(&proof));
    }

    #[test]
    fn verify_rejects_agent_not_in_participants() {
        let mut proof = valid_proof();
        // Change agent to a key not in the nodes list.
        proof.agent_identity = fake_pubkey(0xFF);
        assert!(!verify_participation_proof(&proof));
    }

    #[test]
    fn verify_rejects_empty_participants() {
        let mut proof = valid_proof();
        proof.participating_nodes.clear();
        assert!(!verify_participation_proof(&proof));
    }

    #[test]
    fn verify_rejects_invalid_fee_txid_length() {
        let mut proof = valid_proof();
        proof.fee_txid = Some("abcd".to_string()); // too short
        assert!(!verify_participation_proof(&proof));
    }

    #[test]
    fn verify_rejects_non_hex_fee_txid() {
        let mut proof = valid_proof();
        // 64 chars but contains 'g' which is not hex.
        proof.fee_txid = Some("gg".repeat(32));
        assert!(!verify_participation_proof(&proof));
    }

    #[test]
    fn verify_accepts_no_fee_txid() {
        let mut proof = valid_proof();
        proof.fee_txid = None;
        assert!(verify_participation_proof(&proof));
    }

    #[test]
    fn verify_accepts_prefix_03_pubkeys() {
        let session = SessionId("session-03".to_string());
        let agent = fake_pubkey_03(0xCC);
        let nodes = vec![fake_pubkey_03(0xCC), fake_pubkey(0xDD)];
        let proof =
            create_participation_proof(&session, &agent, &nodes, &fake_hash(0x22), None)
                .expect("should succeed with 0x03 prefix");
        assert!(verify_participation_proof(&proof));
    }

    // ----------------------------------------------------------------
    // proof_to_op_return tests
    // ----------------------------------------------------------------

    #[test]
    fn op_return_starts_with_op_false_op_return() {
        let proof = valid_proof();
        let script = proof_to_op_return(&proof);

        assert!(script.len() >= 2);
        assert_eq!(script[0], 0x00, "first byte must be OP_FALSE");
        assert_eq!(script[1], 0x6a, "second byte must be OP_RETURN");
    }

    #[test]
    fn op_return_contains_protocol_id() {
        let proof = valid_proof();
        let script = proof_to_op_return(&proof);

        // After OP_FALSE (0x00) and OP_RETURN (0x6a), the next push is the
        // protocol ID. Length prefix for 21 bytes is just 0x15 (21).
        assert_eq!(script[2], 21, "protocol ID length prefix should be 21");
        assert_eq!(
            &script[3..24],
            b"bsv-mpc-participation",
            "protocol ID content should match"
        );
    }

    #[test]
    fn op_return_has_reasonable_length() {
        let proof = valid_proof();
        let script = proof_to_op_return(&proof);

        // With 2 nodes:
        // 2 (prefix) + 1+21 (proto) + 1+32 (session) + 1+32 (signing)
        // + 1+33 (agent) + 1+1 (count) + 2*(1+33) (nodes) + 1+32 (fee_txid)
        // + 1+8 (timestamp)
        // = 2 + 22 + 33 + 33 + 34 + 2 + 68 + 33 + 9 = 236
        assert!(
            script.len() > 200 && script.len() < 300,
            "script length {} should be in reasonable range for 2-node proof",
            script.len()
        );
    }

    #[test]
    fn op_return_without_fee_txid_uses_op_0() {
        let session = SessionId("no-fee".to_string());
        let agent = fake_pubkey(0x01);
        let nodes = vec![fake_pubkey(0x01)];
        let proof =
            create_participation_proof(&session, &agent, &nodes, &fake_hash(0x00), None)
                .expect("should succeed");
        let script = proof_to_op_return(&proof);

        // The script should still be well-formed with an OP_0 for the fee_txid.
        assert_eq!(script[0], 0x00);
        assert_eq!(script[1], 0x6a);

        // Verify we can find the empty push (0x00) in the expected position.
        // With 1 node, fee_txid is at byte offset:
        // 2 + (1+21) + (1+32) + (1+32) + (1+33) + (1+1) + (1+33) = 160
        // At offset 160 we expect 0x00 (OP_0 for empty push).
        let fee_offset = 2 + 22 + 33 + 33 + 34 + 2 + 34;
        assert_eq!(
            script[fee_offset], 0x00,
            "fee_txid field should be OP_0 (empty push) when None"
        );
    }

    #[test]
    fn op_return_with_fee_txid_includes_32_bytes() {
        let proof = valid_proof();
        let script = proof_to_op_return(&proof);

        // The fee_txid hex decodes to 32 bytes. Find it in the script.
        // With 2 nodes, fee_txid is at byte offset:
        // 2 + 22 + 33 + 33 + 34 + 2 + 2*(34) = 194
        let fee_offset = 2 + 22 + 33 + 33 + 34 + 2 + 68;
        assert_eq!(
            script[fee_offset], 32,
            "fee_txid push length should be 32 bytes"
        );
    }

    #[test]
    fn op_return_timestamp_is_8_bytes_big_endian() {
        let proof = valid_proof();
        let script = proof_to_op_return(&proof);

        // The last push should be 8 bytes (timestamp).
        // Length prefix is 0x08, then 8 bytes of big-endian millis.
        let len = script.len();
        assert_eq!(script[len - 9], 8, "timestamp length prefix should be 8");

        // Read the 8 bytes and verify they decode to a reasonable timestamp.
        let ts_bytes: [u8; 8] = script[len - 8..].try_into().expect("8 bytes");
        let millis = u64::from_be_bytes(ts_bytes);
        // Should be a recent timestamp (after 2024-01-01 in millis).
        assert!(millis > 1_704_067_200_000, "timestamp should be recent");
    }

    // ----------------------------------------------------------------
    // push_data encoding tests
    // ----------------------------------------------------------------

    #[test]
    fn push_data_empty_produces_op_0() {
        let mut buf = Vec::new();
        push_data(&mut buf, &[]);
        assert_eq!(buf, vec![0x00]);
    }

    #[test]
    fn push_data_1_to_75_bytes_uses_direct_push() {
        for len in 1..=75 {
            let data = vec![0x42u8; len];
            let mut buf = Vec::new();
            push_data(&mut buf, &data);
            assert_eq!(buf[0], len as u8, "length prefix for {} bytes", len);
            assert_eq!(&buf[1..], &data[..]);
        }
    }

    #[test]
    fn push_data_76_bytes_uses_pushdata1() {
        let data = vec![0x42u8; 76];
        let mut buf = Vec::new();
        push_data(&mut buf, &data);
        assert_eq!(buf[0], 0x4c, "OP_PUSHDATA1");
        assert_eq!(buf[1], 76, "1-byte length");
        assert_eq!(&buf[2..], &data[..]);
    }

    #[test]
    fn push_data_255_bytes_uses_pushdata1() {
        let data = vec![0x42u8; 255];
        let mut buf = Vec::new();
        push_data(&mut buf, &data);
        assert_eq!(buf[0], 0x4c, "OP_PUSHDATA1");
        assert_eq!(buf[1], 255, "1-byte length");
        assert_eq!(&buf[2..], &data[..]);
    }

    #[test]
    fn push_data_256_bytes_uses_pushdata2() {
        let data = vec![0x42u8; 256];
        let mut buf = Vec::new();
        push_data(&mut buf, &data);
        assert_eq!(buf[0], 0x4d, "OP_PUSHDATA2");
        let len_bytes = u16::from_le_bytes([buf[1], buf[2]]);
        assert_eq!(len_bytes, 256, "2-byte LE length");
        assert_eq!(&buf[3..], &data[..]);
    }

    // ----------------------------------------------------------------
    // hex_to_bytes tests
    // ----------------------------------------------------------------

    #[test]
    fn hex_to_bytes_valid() {
        assert_eq!(hex_to_bytes("aabb"), vec![0xaa, 0xbb]);
        assert_eq!(hex_to_bytes("00ff"), vec![0x00, 0xff]);
        assert_eq!(hex_to_bytes(""), Vec::<u8>::new());
    }

    #[test]
    fn hex_to_bytes_invalid() {
        assert!(hex_to_bytes("xyz").is_empty());
        assert!(hex_to_bytes("a").is_empty()); // odd length
    }

    // ----------------------------------------------------------------
    // Round-trip and integration tests
    // ----------------------------------------------------------------

    #[test]
    fn create_verify_round_trip() {
        let session = SessionId("round-trip-test".to_string());
        let agent = fake_pubkey(0x01);
        let nodes = vec![fake_pubkey(0x01), fake_pubkey(0x02), fake_pubkey(0x03)];
        let signing_hash = fake_hash(0xCC);

        let proof =
            create_participation_proof(&session, &agent, &nodes, &signing_hash, Some(fake_txid()))
                .expect("should succeed");

        assert!(
            verify_participation_proof(&proof),
            "freshly created proof should verify"
        );
    }

    #[test]
    fn create_serialize_and_verify_all_work_together() {
        let session = SessionId("integration".to_string());
        let agent = fake_pubkey_03(0x10);
        let nodes = vec![fake_pubkey_03(0x10), fake_pubkey(0x20)];
        let signing_hash = fake_hash(0x99);

        let proof = create_participation_proof(
            &session,
            &agent,
            &nodes,
            &signing_hash,
            Some(fake_txid()),
        )
        .expect("should succeed");

        // Verify the proof passes structural validation.
        assert!(verify_participation_proof(&proof));

        // Serialize to OP_RETURN.
        let script = proof_to_op_return(&proof);

        // Basic sanity: starts with OP_FALSE OP_RETURN.
        assert_eq!(script[0], 0x00);
        assert_eq!(script[1], 0x6a);

        // Protocol ID is present.
        assert_eq!(script[2], 21);
        assert_eq!(&script[3..24], b"bsv-mpc-participation");
    }

    #[test]
    fn proof_with_many_nodes() {
        let session = SessionId("many-nodes".to_string());
        let agent = fake_pubkey(0x01);
        let mut nodes = vec![fake_pubkey(0x01)];
        for i in 2..=10u8 {
            nodes.push(fake_pubkey(i));
        }

        let proof =
            create_participation_proof(&session, &agent, &nodes, &fake_hash(0xDD), None)
                .expect("should succeed with many nodes");

        assert!(verify_participation_proof(&proof));
        let script = proof_to_op_return(&proof);
        assert!(!script.is_empty());
    }
}
