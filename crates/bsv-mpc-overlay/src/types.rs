//! Shared types for the MPC overlay network module.
//!
//! These types define the data structures used for node advertisement,
//! discovery, and participation proof publication on the BSV overlay network.

use serde::{Deserialize, Serialize};

/// The overlay topic name for MPC signing.
///
/// All CHIP tokens (node advertisements) and participation proofs are published
/// to this topic. Overlay nodes that host this topic index and serve lookups
/// for MPC-related data.
///
/// The `tm_` prefix follows the BSV overlay convention for "topic manager"
/// topics that require custom admission logic.
pub const MPC_TOPIC: &str = "tm_mpc_signing";

/// An MPC node advertisement (parsed from a CHIP token on the overlay).
///
/// CHIP tokens (BRC-23) are BRC-48 PushDrop outputs that advertise a service
/// on the overlay network. For MPC signing, the CHIP token contains the node's
/// identity key, service domain, supported configurations, and pricing.
///
/// These tokens are discovered via SLAP lookup (BRC-24) and used to find
/// suitable signing partners for threshold ceremonies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcNodeInfo {
    /// BRC-31 identity key of the node operator (33-byte compressed secp256k1, hex).
    ///
    /// This key is used for mutual authentication when connecting to the node's
    /// Key Share Service. It is also the key that signs participation proofs.
    pub identity_key: String,

    /// HTTPS domain of the Key Share Service (e.g., "mpc.example.com").
    ///
    /// The MPC Proxy connects to `https://{domain}/dkg/init`, `/sign/init`, etc.
    /// Must support TLS and BRC-31 Authrite authentication.
    pub domain: String,

    /// Supported elliptic curves.
    ///
    /// For BSV, this is always `["secp256k1"]`. The field exists for forward
    /// compatibility with multi-curve threshold schemes.
    pub curves: Vec<String>,

    /// Supported threshold configurations (e.g., `["2-of-2", "2-of-3", "3-of-5"]`).
    ///
    /// Format: `"{t}-of-{n}"` where `t` is the threshold and `n` is the total parties.
    pub threshold_configs: Vec<String>,

    /// Fee per signing ceremony in satoshis.
    ///
    /// This is the amount the node charges for participating in one threshold
    /// signing operation. Fees are settled via participation proof counting
    /// at the end of each epoch.
    pub fee_sats: u64,

    /// Node software version (semver).
    pub version: String,

    /// When this CHIP token was published to the overlay (UTC).
    pub published_at: chrono::DateTime<chrono::Utc>,

    /// Optional maximum presignatures this node is willing to stockpile per agent.
    ///
    /// Presignature generation is computationally expensive. Nodes may limit
    /// how many they will generate in advance for any single agent.
    pub max_presignatures: Option<u32>,

    /// Optional minimum balance (in satoshis) required to initiate DKG.
    ///
    /// Nodes may require proof of funds before committing resources to a
    /// DKG ceremony that generates a new key share.
    pub min_balance_sats: Option<u64>,
}

/// Query parameters for discovering MPC nodes on the overlay network.
///
/// All fields are optional. If no filters are provided, all MPC nodes are
/// returned (up to `limit`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveryQuery {
    /// Required elliptic curve (default: "secp256k1").
    ///
    /// Only nodes that support this curve will be returned.
    pub curve: Option<String>,

    /// Required threshold configuration (e.g., "2-of-3").
    ///
    /// Only nodes that advertise this threshold config will be returned.
    pub threshold: Option<String>,

    /// Maximum acceptable fee per signing in satoshis.
    ///
    /// Nodes with `fee_sats` exceeding this value are filtered out.
    pub max_fee_sats: Option<u64>,

    /// Maximum number of results to return.
    ///
    /// Default is 20 if not specified.
    pub limit: Option<usize>,
}

/// A signed participation proof published to the BSV overlay network.
///
/// After a threshold signing ceremony completes, each participating node
/// produces a `ParticipationProof` (from `bsv-mpc-core`). This struct
/// wraps that proof with its on-chain transaction reference.
///
/// Participation proofs serve two purposes:
///
/// 1. **Fee distribution**: Nodes count their proofs over an epoch to determine
///    their share of fees. More signatures = more revenue.
///
/// 2. **Reputation**: Nodes with more participation proofs have demonstrated
///    reliability. Discovery queries can sort by proof count as a reputation signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayProof {
    /// The BRC-18 participation proof data.
    pub proof: bsv_mpc_core::types::ParticipationProof,

    /// Transaction ID of the proof on the BSV blockchain.
    ///
    /// The proof is stored as an OP_RETURN output in this transaction.
    /// Can be verified by fetching the raw transaction and parsing the output.
    pub txid: String,

    /// Output index in the transaction containing the OP_RETURN proof.
    pub vout: u32,

    /// Block height where this proof was mined (if confirmed).
    ///
    /// `None` if the proof transaction is still in the mempool.
    pub block_height: Option<u64>,
}

/// A fee settlement summary for an epoch.
///
/// Generated by counting participation proofs per node over a time period,
/// then calculating proportional fee distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeSettlement {
    /// Start of the epoch (UTC).
    pub epoch_start: chrono::DateTime<chrono::Utc>,
    /// End of the epoch (UTC).
    pub epoch_end: chrono::DateTime<chrono::Utc>,
    /// Total fees collected during the epoch (in satoshis).
    pub total_fees_sats: u64,
    /// Per-node breakdown: (identity_key, proof_count, fee_share_sats).
    pub node_shares: Vec<NodeFeeShare>,
}

/// A single node's fee share in a settlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeFeeShare {
    /// Node's BRC-31 identity key (hex).
    pub identity_key: String,
    /// Number of participation proofs in the epoch.
    pub proof_count: u64,
    /// This node's share of fees (in satoshis), proportional to proof count.
    pub fee_sats: u64,
}
