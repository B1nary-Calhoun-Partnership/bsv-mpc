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
use crate::types::{FeeSettlement, NodeFeeShare, OverlayProof};

/// Current proof serialization version.
/// Used when proof publication is implemented (Beta milestone).
#[allow(dead_code)]
const PROOF_VERSION: u8 = 1;

/// Protocol prefix for MPC participation proofs in OP_RETURN.
/// Used when proof publication is implemented (Beta milestone).
#[allow(dead_code)]
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
    _overlay_url: &str,
    _proof: &ParticipationProof,
) -> Result<OverlayProof, OverlayError> {
    // Proof publication deferred to Beta milestone.
    // Requires: BRC-31 auth headers, funded UTXO for the OP_RETURN tx,
    // and a live overlay node accepting tm_mpc_signing submissions.
    Err(OverlayError::SubmissionRejected(
        "proof publication deferred to Beta".into(),
    ))
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
    _overlay_url: &str,
    _node_identity: &str,
    _since: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<Vec<OverlayProof>, OverlayError> {
    // Proof querying deferred to Beta milestone.
    // Returns empty results until overlay lookup integration is complete.
    Ok(vec![])
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
    _overlay_url: &str,
    node_identities: &[String],
    _epoch_start: chrono::DateTime<chrono::Utc>,
    _epoch_end: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<(String, u64)>, OverlayError> {
    // Proof counting deferred to Beta milestone.
    // Returns zero counts for all nodes until overlay lookup is implemented.
    Ok(node_identities
        .iter()
        .map(|id| (id.clone(), 0u64))
        .collect())
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
pub fn parse_proof_from_script(_script: &[u8]) -> Result<ParticipationProof, OverlayError> {
    // Proof parsing deferred to Beta milestone.
    // Requires full OP_RETURN deserialization and ECDSA signature verification.
    Err(OverlayError::InvalidProof(
        "proof script parsing not yet implemented".into(),
    ))
}
