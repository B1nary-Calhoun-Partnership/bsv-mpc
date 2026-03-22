//! Participation proof publication and querying on the BSV overlay network.
//!
//! After a threshold signing ceremony completes, each participating node
//! produces a `ParticipationProof` (from `bsv-mpc-core`). This module handles
//! publishing those proofs to the `tm_mpc_signing` overlay topic as BRC-18
//! OP_RETURN transactions, and querying published proofs for fee settlement.
//!
//! ## Proof Format (BRC-18 OP_RETURN)
//!
//! ```text
//! OP_FALSE OP_RETURN
//!   <protocol_prefix>     # "mpc-proof" (UTF-8)
//!   <version>             # 0x01
//!   <session_hash>        # 32 bytes (SHA-256 of signing session transcript)
//!   <agent_identity>      # 33 bytes (signer's compressed pubkey)
//!   <participating_count> # varint (number of signers)
//!   <signing_hash>        # 32 bytes (the sighash that was signed)
//!   <timestamp>           # 8 bytes (Unix timestamp, big-endian)
//!   <signature>           # ~72 bytes (DER ECDSA signature over above fields)
//! ```
//!
//! The signature is produced by the agent's identity key over the concatenation
//! of all preceding fields, proving that the agent actually participated.
//!
//! ## Fee Settlement
//!
//! Proofs are counted per node over epoch periods (e.g., daily or weekly).
//! Fee distribution is proportional: a node with 60% of the proofs in an epoch
//! receives 60% of the collected fees for that epoch.

use bsv_mpc_core::types::ParticipationProof;
use crate::error::OverlayError;
use crate::types::{FeeSettlement, NodeFeeShare, OverlayProof, MPC_TOPIC};

/// Current proof serialization version.
const PROOF_VERSION: u8 = 1;

/// Protocol prefix for MPC participation proofs in OP_RETURN.
const PROOF_PREFIX: &[u8] = b"mpc-proof";

/// Publish a participation proof to the `tm_mpc_signing` overlay topic.
///
/// Creates a BRC-18 OP_RETURN transaction containing the proof data, signs it
/// with the agent's identity key, and submits it to the overlay network via
/// BRC-22 `/submit`.
///
/// # Flow
///
/// 1. Serialize the proof to BRC-18 OP_RETURN format (see module docs).
/// 2. Sign the serialized data with the agent's identity key.
/// 3. Build a BSV transaction with the OP_RETURN output.
/// 4. Submit to the overlay via `POST {overlay_url}/submit`.
/// 5. Return the `OverlayProof` with the resulting transaction ID.
///
/// # Arguments
///
/// * `overlay_url` - Base URL of the overlay node
/// * `proof` - The participation proof from the signing ceremony
///
/// # Errors
///
/// Returns `OverlayError::SubmissionRejected` if the overlay rejects the proof
/// transaction (e.g., invalid signature, duplicate proof).
pub async fn publish_proof(
    overlay_url: &str,
    proof: &ParticipationProof,
) -> Result<OverlayProof, OverlayError> {
    todo!(
        "1. Serialize the proof to OP_RETURN format:\n\
             let mut data = Vec::new();\n\
             data.extend_from_slice(PROOF_PREFIX);\n\
             data.push(PROOF_VERSION);\n\
             data.extend_from_slice(&proof.session_hash);  // 32 bytes\n\
             data.extend_from_slice(&proof.agent_identity); // 33 bytes\n\
             data.push(proof.participating_nodes.len() as u8);\n\
             data.extend_from_slice(&proof.signing_hash);  // 32 bytes\n\
             data.extend_from_slice(&proof.timestamp.timestamp().to_be_bytes()); // 8 bytes\n\
         2. Sign the data with the agent's identity key (ECDSA/secp256k1)\n\
         3. Append the DER signature to data\n\
         4. Build OP_RETURN script: OP_FALSE OP_RETURN <data>\n\
         5. Create a BSV transaction with this output (+ funding input)\n\
         6. Submit to overlay:\n\
             POST {overlay_url}/submit\n\
             Body: {{\n\
                 \"rawTx\": \"<hex tx>\",\n\
                 \"topics\": [\"tm_mpc_signing\"]\n\
             }}\n\
         7. Parse response for txid\n\
         8. Return OverlayProof {{ proof, txid, vout: 0, block_height: None }}"
    )
}

/// Query participation proofs for a specific node from the overlay.
///
/// Looks up proofs published by the given node, optionally filtered by
/// a start timestamp. Used for fee settlement calculations and reputation queries.
///
/// # Arguments
///
/// * `overlay_url` - Base URL of the overlay node
/// * `node_identity` - BRC-31 identity key of the node to query (hex)
/// * `since` - Only return proofs published after this timestamp (optional)
///
/// # Returns
///
/// A vector of `OverlayProof` structs, sorted by timestamp ascending.
pub async fn query_proofs(
    overlay_url: &str,
    node_identity: &str,
    since: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<Vec<OverlayProof>, OverlayError> {
    todo!(
        "1. Build the lookup query:\n\
             POST {overlay_url}/lookup\n\
             Body: {{\n\
                 \"service\": \"ls_mpc_proofs\",\n\
                 \"query\": {{\n\
                     \"node\": \"{node_identity}\",\n\
                     \"since\": \"<since_iso8601>\"  // optional\n\
                 }}\n\
             }}\n\
         2. Parse the response as a list of UTXO references\n\
         3. For each UTXO, fetch the raw transaction\n\
         4. Parse the OP_RETURN output to extract the ParticipationProof\n\
         5. Verify the proof signature against the node's identity key\n\
         6. Construct OverlayProof with txid and vout\n\
         7. Sort by timestamp ascending\n\
         8. Return the list"
    )
}

/// Count participation proofs for multiple nodes over an epoch.
///
/// Queries the overlay for proofs from each node within the given time range,
/// returning (identity_key, count) pairs. This is the core data needed for
/// proportional fee settlement.
///
/// # Arguments
///
/// * `overlay_url` - Base URL of the overlay node
/// * `node_identities` - List of node identity keys to count proofs for
/// * `epoch_start` - Start of the counting period (inclusive)
/// * `epoch_end` - End of the counting period (exclusive)
///
/// # Returns
///
/// A vector of (identity_key, proof_count) pairs. Nodes with zero proofs
/// in the epoch are included with count 0.
pub async fn count_proofs_by_node(
    overlay_url: &str,
    node_identities: &[String],
    epoch_start: chrono::DateTime<chrono::Utc>,
    epoch_end: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<(String, u64)>, OverlayError> {
    todo!(
        "1. For each node_identity in node_identities:\n\
             a. query_proofs(overlay_url, identity, Some(epoch_start)).await?\n\
             b. Filter to proofs where timestamp < epoch_end\n\
             c. Count the remaining proofs\n\
         2. Return Vec<(identity_key, count)>\n\
         \n\
         Optimization: if the overlay supports batch queries, use a single\n\
         request instead of N individual queries."
    )
}

/// Calculate fee settlement for an epoch based on participation proof counts.
///
/// Takes the proof counts from [`count_proofs_by_node`] and the total fees
/// collected, then distributes fees proportionally.
///
/// # Arguments
///
/// * `proof_counts` - Per-node proof counts from `count_proofs_by_node`
/// * `total_fees_sats` - Total fees collected in the epoch
/// * `epoch_start` - Start of the epoch
/// * `epoch_end` - End of the epoch
///
/// # Returns
///
/// A `FeeSettlement` struct with per-node breakdowns. If the total proof
/// count is zero, all fees go to the first node (or remain undistributed).
pub fn calculate_settlement(
    proof_counts: &[(String, u64)],
    total_fees_sats: u64,
    epoch_start: chrono::DateTime<chrono::Utc>,
    epoch_end: chrono::DateTime<chrono::Utc>,
) -> FeeSettlement {
    let total_proofs: u64 = proof_counts.iter().map(|(_, c)| c).sum();

    let node_shares: Vec<NodeFeeShare> = proof_counts
        .iter()
        .map(|(identity_key, count)| {
            let fee_sats = if total_proofs > 0 {
                // Proportional distribution, rounding down.
                // Remainder goes to the node with the most proofs.
                (total_fees_sats * count) / total_proofs
            } else {
                0
            };
            NodeFeeShare {
                identity_key: identity_key.clone(),
                proof_count: *count,
                fee_sats,
            }
        })
        .collect();

    FeeSettlement {
        epoch_start,
        epoch_end,
        total_fees_sats,
        node_shares,
    }
}

/// Parse a participation proof from a raw OP_RETURN script.
///
/// Validates the proof prefix, version, and signature. Used when processing
/// UTXO data returned from overlay lookups.
///
/// # Arguments
///
/// * `script` - Raw OP_RETURN script bytes
///
/// # Errors
///
/// Returns `OverlayError::InvalidChipToken` if the script is not a valid
/// MPC participation proof (wrong prefix, version, or invalid signature).
pub fn parse_proof_from_script(script: &[u8]) -> Result<ParticipationProof, OverlayError> {
    todo!(
        "1. Verify script starts with OP_FALSE OP_RETURN\n\
         2. Extract the data payload after OP_RETURN\n\
         3. Verify prefix == PROOF_PREFIX (b\"mpc-proof\")\n\
         4. Verify version == PROOF_VERSION (0x01)\n\
         5. Extract fields:\n\
             session_hash: bytes[offset..offset+32]\n\
             agent_identity: bytes[offset..offset+33]\n\
             participating_count: varint\n\
             signing_hash: bytes[offset..offset+32]\n\
             timestamp: i64 from 8 bytes big-endian\n\
         6. Extract the DER signature (remaining bytes)\n\
         7. Verify the signature against agent_identity pubkey\n\
             over the concatenation of all preceding fields\n\
         8. Construct and return ParticipationProof"
    )
}
