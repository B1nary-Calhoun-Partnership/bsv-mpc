//! CHIP token creation and parsing for MPC node advertisement.
//!
//! CHIP (Content Host Identity Protocol, BRC-23) tokens are BRC-48 PushDrop
//! outputs that advertise a service on the BSV overlay network. For MPC signing,
//! a CHIP token declares:
//!
//! - The node operator's BRC-31 identity key
//! - The HTTPS domain of the Key Share Service
//! - The `tm_mpc_signing` topic name
//! - Extended capabilities (curves, thresholds, fees)
//!
//! ## PushDrop Script Layout
//!
//! ```text
//! OP_PUSH <signing_pubkey>    # BRC-42 derived key for CHIP topic
//! OP_PUSH "CHIP"              # Protocol identifier
//! OP_PUSH <identity_key>      # 33-byte compressed secp256k1 pubkey
//! OP_PUSH <domain>            # HTTPS domain (e.g., "mpc.example.com")
//! OP_PUSH "tm_mpc_signing"    # Topic name
//! OP_PUSH <capabilities_json> # Extended fields (curves, thresholds, fees)
//! OP_DROP OP_DROP ...          # Clean stack
//! OP_CHECKSIG                 # Verify BRC-42 signature
//! ```
//!
//! ## BRC-42 Key Derivation
//!
//! The CHIP token is signed with a key derived via BRC-42:
//! - `protocol_id`: `[2, "CHIP"]`
//! - `key_id`: `"tm_mpc_signing"`
//! - `counterparty`: `"anyone"` (the generator point 1*G)
//!
//! This allows anyone to verify the token without knowing the signer's
//! private key, while binding it to the signer's identity.

use crate::error::OverlayError;
use crate::types::{MpcNodeInfo, MPC_TOPIC};
use serde::{Deserialize, Serialize};

/// Extended capabilities included in the CHIP token's OP_RETURN data.
///
/// This JSON structure is stored as the last PushDrop field and contains
/// all the information that doesn't fit in the fixed CHIP fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChipCapabilities {
    /// Supported elliptic curves.
    pub curves: Vec<String>,
    /// Supported threshold configurations.
    pub threshold_configs: Vec<String>,
    /// Fee per signing in satoshis.
    pub fee_sats: u64,
    /// Node software version.
    pub version: String,
    /// Maximum presignatures per agent (optional).
    pub max_presignatures: Option<u32>,
    /// Minimum balance for DKG (optional).
    pub min_balance_sats: Option<u64>,
}

/// Create a CHIP token (BRC-23, BRC-48 PushDrop) advertising this node as
/// an MPC signing service.
///
/// The token is a spendable UTXO containing a PushDrop script with:
/// 1. A BRC-42 derived signing key (protocol `[2, "CHIP"]`, key `"tm_mpc_signing"`)
/// 2. The node's identity key and service domain
/// 3. Extended capabilities as a JSON blob
///
/// The resulting script can be included in a transaction output and submitted
/// to the overlay network via [`publish_chip_token`].
///
/// # Arguments
///
/// * `identity_key` - The node operator's 33-byte compressed secp256k1 public key
/// * `domain` - HTTPS domain of the Key Share Service
/// * `node_info` - Full node information including capabilities and pricing
///
/// # Returns
///
/// Serialized PushDrop script bytes suitable for inclusion in a transaction output.
pub fn create_chip_token(
    identity_key: &[u8; 33],
    domain: &str,
    node_info: &MpcNodeInfo,
) -> Result<Vec<u8>, OverlayError> {
    let _capabilities = ChipCapabilities {
        curves: node_info.curves.clone(),
        threshold_configs: node_info.threshold_configs.clone(),
        fee_sats: node_info.fee_sats,
        version: node_info.version.clone(),
        max_presignatures: node_info.max_presignatures,
        min_balance_sats: node_info.min_balance_sats,
    };

    todo!(
        "1. Derive the signing key via BRC-42:\n\
             protocol_id = [2, \"CHIP\"]\n\
             key_id = \"tm_mpc_signing\"\n\
             counterparty = \"anyone\" (generator point 02...G)\n\
         2. Build the PushDrop script fields:\n\
             field[0] = derived_pubkey (33 bytes)\n\
             field[1] = b\"CHIP\"\n\
             field[2] = identity_key (33 bytes)\n\
             field[3] = domain.as_bytes()\n\
             field[4] = b\"tm_mpc_signing\"\n\
             field[5] = serde_json::to_vec(&capabilities)\n\
         3. Construct the PushDrop script:\n\
             OP_PUSH field[0]\n\
             OP_PUSH field[1] ... field[5]\n\
             OP_5 OP_DROP (clean stack)\n\
             OP_CHECKSIG\n\
         4. Sign the script with the BRC-42 derived private key\n\
         5. Return the serialized script bytes"
    )
}

/// Parse a CHIP token from a BRC-48 PushDrop script.
///
/// Extracts the node's identity key, domain, and capabilities from the
/// PushDrop fields. Verifies the BRC-42 signature to ensure the token
/// was created by the claimed identity.
///
/// # Arguments
///
/// * `script` - Raw script bytes from a transaction output
///
/// # Returns
///
/// Parsed `MpcNodeInfo` if the script is a valid MPC CHIP token.
///
/// # Errors
///
/// Returns `OverlayError::InvalidChipToken` if:
/// - The script is not a valid PushDrop format
/// - The topic field is not `"tm_mpc_signing"`
/// - The BRC-42 signature verification fails
/// - The capabilities JSON is malformed
pub fn parse_chip_token(script: &[u8]) -> Result<MpcNodeInfo, OverlayError> {
    todo!(
        "1. Parse the PushDrop script to extract fields\n\
         2. Verify field count >= 5\n\
         3. Check field[1] == b\"CHIP\"\n\
         4. Check field[4] == b\"tm_mpc_signing\"\n\
         5. Extract identity_key from field[2] (33 bytes -> hex)\n\
         6. Extract domain from field[3] (UTF-8 string)\n\
         7. Parse capabilities from field[5] (JSON)\n\
         8. Verify the BRC-42 signature:\n\
             a. Derive the expected signing pubkey from identity_key\n\
                using protocol [2, \"CHIP\"], key \"tm_mpc_signing\"\n\
             b. Verify the PushDrop CHECKSIG against this key\n\
         9. Construct and return MpcNodeInfo"
    )
}

/// Submit a CHIP token to the overlay network via BRC-22 transaction submission.
///
/// The token must be wrapped in a complete BSV transaction before submission.
/// The overlay node will:
///
/// 1. Validate the transaction (standard BSV rules)
/// 2. Check that it contains a valid CHIP output for the `tm_mpc_signing` topic
/// 3. Run the topic manager's admission logic (signature verification, etc.)
/// 4. Index the token for SLAP/CLAP lookup
///
/// # Arguments
///
/// * `overlay_url` - Base URL of the overlay node (e.g., "https://overlay.example.com")
/// * `token_tx` - Serialized BSV transaction containing the CHIP output
///
/// # Errors
///
/// Returns `OverlayError::SubmissionRejected` if the overlay node rejects the
/// transaction (invalid format, duplicate, or failed admission).
pub async fn publish_chip_token(
    overlay_url: &str,
    token_tx: &[u8],
) -> Result<(), OverlayError> {
    todo!(
        "1. Build the BRC-22 submission request:\n\
             POST {overlay_url}/submit\n\
             Content-Type: application/json\n\
             Body: {{\n\
                 \"rawTx\": \"<hex-encoded token_tx>\",\n\
                 \"topics\": [\"tm_mpc_signing\"],\n\
                 \"outputs\": [0]\n\
             }}\n\
         2. Include BRC-31 auth headers (identity of the submitter)\n\
         3. Send the request via reqwest\n\
         4. Check response status:\n\
             - 200: submission accepted, token indexed\n\
             - 400: invalid transaction format\n\
             - 409: duplicate token (already indexed)\n\
             - 422: admission rejected (bad signature, wrong topic)\n\
         5. Parse response for confirmation"
    )
}

/// Revoke a CHIP token by spending its UTXO.
///
/// Since CHIP tokens are spendable PushDrop outputs, spending the UTXO
/// effectively removes the advertisement from the overlay. The overlay node
/// will detect the spend and remove the token from its index.
///
/// This is used when a node is shutting down or changing its service domain.
///
/// # Arguments
///
/// * `overlay_url` - Base URL of the overlay node
/// * `token_txid` - Transaction ID of the CHIP token to revoke
/// * `token_vout` - Output index of the CHIP token
///
/// # Returns
///
/// Transaction ID of the spending transaction.
pub async fn revoke_chip_token(
    overlay_url: &str,
    token_txid: &str,
    token_vout: u32,
) -> Result<String, OverlayError> {
    todo!(
        "1. Fetch the CHIP token UTXO (txid:vout)\n\
         2. Build a transaction that spends the CHIP output\n\
             - Input: the CHIP UTXO with PushDrop unlock\n\
             - Output: change back to node's address\n\
         3. Sign with the BRC-42 derived key (same derivation as creation)\n\
         4. Submit via BRC-22: POST {overlay_url}/submit\n\
         5. Return the spending transaction ID"
    )
}
