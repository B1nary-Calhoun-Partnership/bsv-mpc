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

use crate::types::{ParticipationProof, SessionId};

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
) -> ParticipationProof {
    todo!(
        "Create participation proof: \
         1. Compute session_hash = SHA-256(session_id.0.as_bytes()) \
         2. Clone agent_key into agent_identity (validate 33 bytes) \
         3. Clone all node keys into participating_nodes (validate each is 33 bytes) \
         4. Copy signing_hash into proof \
         5. Convert fee_txid Option<&str> to Option<String> \
         6. Set timestamp = chrono::Utc::now() \
         7. Return ParticipationProof {{ \
                session_hash, \
                agent_identity: agent_key.to_vec(), \
                participating_nodes: nodes.to_vec(), \
                signing_hash: signing_hash.to_vec(), \
                fee_txid: fee_txid.map(String::from), \
                timestamp, \
            }} \
         \
         Session: {}, agent key: {} bytes, {} participating nodes",
        session_id,
        agent_key.len(),
        nodes.len()
    )
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
    todo!(
        "Serialize participation proof to OP_RETURN: \
         1. Start with OP_FALSE (0x00) + OP_RETURN (0x6a) \
         2. Push protocol ID: 'bsv-mpc-participation' as length-prefixed bytes \
         3. Push session_hash (32 bytes) \
         4. Push signing_hash (32 bytes) \
         5. Push agent_identity (33 bytes) \
         6. Push participant count as varint \
         7. For each participant, push their 33-byte identity key \
         8. Push fee_txid (32 bytes) or empty push (0x00) if None \
         9. Push timestamp as 8-byte big-endian unix milliseconds \
         10. Use Bitcoin-style PUSHDATA opcodes for each field: \
             - 0x01-0x4b: direct push (length byte + data) for data <= 75 bytes \
             - 0x4c + 1-byte len: OP_PUSHDATA1 for data 76-255 bytes \
             - 0x4d + 2-byte len: OP_PUSHDATA2 for data 256-65535 bytes \
         \
         Proof has {} participants, fee_txid: {:?}",
        proof.participating_nodes.len(),
        proof.fee_txid
    )
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
    todo!(
        "Verify participation proof structure: \
         1. Check session_hash.len() == 32 \
         2. Check signing_hash.len() == 32 \
         3. Check agent_identity.len() == 33 \
         4. Check agent_identity[0] is 0x02 or 0x03 (valid compressed pubkey prefix) \
         5. For each node in participating_nodes: \
            a. Check node.len() == 33 \
            b. Check node[0] is 0x02 or 0x03 \
         6. Check agent_identity appears in participating_nodes \
         7. Check no duplicates in participating_nodes \
            (collect into HashSet, check len == original len) \
         8. Check participating_nodes is non-empty \
         9. If fee_txid is Some, check it's a valid 64-char hex string \
         10. Return true if all checks pass \
         \
         Proof: session_hash={} bytes, {} nodes",
        proof.session_hash.len(),
        proof.participating_nodes.len()
    )
}
