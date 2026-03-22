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
//! The MPC CHIP token extends the standard 4-field SHIP admin token (BRC-23)
//! with a 5th capabilities field:
//!
//! ```text
//! <signing_pubkey> OP_CHECKSIG
//! OP_PUSH "SHIP"              # Protocol identifier
//! OP_PUSH <identity_key>      # 33-byte compressed secp256k1 pubkey
//! OP_PUSH <domain>            # HTTPS domain (e.g., "mpc.example.com")
//! OP_PUSH "tm_mpc_signing"    # Topic name
//! OP_PUSH <capabilities_json> # Extended fields (curves, thresholds, fees)
//! OP_2DROP OP_2DROP OP_DROP   # Clean stack (5 fields)
//! ```
//!
//! The locking key is the identity key itself (owner can spend/revoke).
//! The standard 4-field format (without capabilities) is also accepted
//! when parsing, with defaults applied for missing capabilities.

use crate::error::OverlayError;
use crate::types::{MpcNodeInfo, MPC_TOPIC};
use bsv::overlay::{create_overlay_admin_token, decode_overlay_admin_token, Protocol};
use bsv::primitives::PublicKey;
use bsv::script::templates::PushDrop;
use bsv::script::LockingScript;
use serde::{Deserialize, Serialize};

/// Extended capabilities included in the CHIP token's PushDrop data.
///
/// This JSON structure is stored as the 5th PushDrop field and contains
/// all the information that doesn't fit in the fixed CHIP fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_presignatures: Option<u32>,
    /// Minimum balance for DKG (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_balance_sats: Option<u64>,
}

/// Create a CHIP token (BRC-23, BRC-48 PushDrop) advertising this node as
/// an MPC signing service.
///
/// The token is a PushDrop locking script with 5 fields:
/// 1. Protocol ("SHIP")
/// 2. Identity key (33-byte compressed pubkey)
/// 3. Domain (HTTPS URL)
/// 4. Topic ("tm_mpc_signing")
/// 5. Capabilities JSON (curves, thresholds, fees, version)
///
/// The locking key is the identity key, so only the node operator can
/// spend (revoke) the token.
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
    // Validate inputs
    if domain.is_empty() {
        return Err(OverlayError::InvalidChipToken(
            "domain must not be empty".into(),
        ));
    }
    if node_info.fee_sats == 0 {
        return Err(OverlayError::InvalidChipToken(
            "fee_sats must be greater than 0".into(),
        ));
    }

    // Parse identity key
    let pubkey = PublicKey::from_bytes(identity_key).map_err(|e| {
        OverlayError::InvalidChipToken(format!("invalid identity key: {}", e))
    })?;

    // Build capabilities JSON
    let capabilities = ChipCapabilities {
        curves: node_info.curves.clone(),
        threshold_configs: node_info.threshold_configs.clone(),
        fee_sats: node_info.fee_sats,
        version: node_info.version.clone(),
        max_presignatures: node_info.max_presignatures,
        min_balance_sats: node_info.min_balance_sats,
    };
    let capabilities_json = serde_json::to_vec(&capabilities)?;

    // Build 5-field PushDrop: SHIP | identity_key | domain | tm_mpc_signing | capabilities
    // This extends the standard 4-field overlay admin token format with capabilities.
    let fields = vec![
        b"SHIP".to_vec(),
        identity_key.to_vec(),
        domain.as_bytes().to_vec(),
        MPC_TOPIC.as_bytes().to_vec(),
        capabilities_json,
    ];

    let pushdrop = PushDrop::new(pubkey, fields);
    let script = pushdrop.lock();

    Ok(script.to_binary())
}

/// Parse a CHIP token from a BRC-48 PushDrop script.
///
/// Accepts both:
/// - 5-field MPC tokens (with capabilities JSON)
/// - 4-field standard SHIP tokens (with default capabilities)
///
/// For 4-field tokens, defaults are applied: secp256k1 curve, 2-of-2 threshold,
/// 100 sats fee, version "0.0.0".
///
/// # Arguments
///
/// * `script_bytes` - Raw script bytes from a transaction output
///
/// # Returns
///
/// Parsed `MpcNodeInfo` if the script is a valid MPC CHIP token.
///
/// # Errors
///
/// Returns `OverlayError::InvalidChipToken` if:
/// - The script is not a valid PushDrop format
/// - The protocol field is not "SHIP"
/// - The topic field is not "tm_mpc_signing"
/// - The identity key is not a valid 33-byte compressed pubkey
/// - The capabilities JSON is malformed (for 5-field tokens)
pub fn parse_chip_token(script_bytes: &[u8]) -> Result<MpcNodeInfo, OverlayError> {
    // Parse script from binary
    let script = LockingScript::from_binary(script_bytes).map_err(|e| {
        OverlayError::InvalidChipToken(format!("invalid script: {}", e))
    })?;

    // Decode PushDrop fields
    let pushdrop = PushDrop::decode(&script).map_err(|e| {
        OverlayError::InvalidChipToken(format!("not a valid PushDrop: {}", e))
    })?;

    let fields = &pushdrop.fields;

    // Must have at least 4 fields (standard SHIP token)
    if fields.len() < 4 {
        return Err(OverlayError::InvalidChipToken(format!(
            "expected at least 4 fields, got {}",
            fields.len()
        )));
    }

    // Field 0: Protocol must be "SHIP"
    let protocol_str = std::str::from_utf8(&fields[0]).map_err(|_| {
        OverlayError::InvalidChipToken("protocol field is not valid UTF-8".into())
    })?;
    if protocol_str != "SHIP" {
        return Err(OverlayError::InvalidChipToken(format!(
            "expected protocol SHIP, got {}",
            protocol_str
        )));
    }

    // Field 1: Identity key (33-byte compressed pubkey)
    let identity_key_bytes = &fields[1];
    if identity_key_bytes.len() != 33 {
        return Err(OverlayError::InvalidChipToken(format!(
            "identity key must be 33 bytes, got {}",
            identity_key_bytes.len()
        )));
    }
    let identity_pubkey = PublicKey::from_bytes(identity_key_bytes).map_err(|e| {
        OverlayError::InvalidChipToken(format!("invalid identity key: {}", e))
    })?;
    let identity_key_hex = identity_pubkey.to_hex();

    // Field 2: Domain
    let domain = std::str::from_utf8(&fields[2])
        .map_err(|_| OverlayError::InvalidChipToken("domain field is not valid UTF-8".into()))?
        .to_string();
    if domain.is_empty() {
        return Err(OverlayError::InvalidChipToken(
            "domain must not be empty".into(),
        ));
    }

    // Field 3: Topic must be "tm_mpc_signing"
    let topic = std::str::from_utf8(&fields[3]).map_err(|_| {
        OverlayError::InvalidChipToken("topic field is not valid UTF-8".into())
    })?;
    if topic != MPC_TOPIC {
        return Err(OverlayError::InvalidChipToken(format!(
            "expected topic {}, got {}",
            MPC_TOPIC, topic
        )));
    }

    // Field 4 (optional): Capabilities JSON
    let (curves, threshold_configs, fee_sats, version, max_presignatures, min_balance_sats) =
        if fields.len() >= 5 {
            let caps: ChipCapabilities = serde_json::from_slice(&fields[4]).map_err(|e| {
                OverlayError::InvalidChipToken(format!("invalid capabilities JSON: {}", e))
            })?;
            (
                caps.curves,
                caps.threshold_configs,
                caps.fee_sats,
                caps.version,
                caps.max_presignatures,
                caps.min_balance_sats,
            )
        } else {
            // Defaults for standard 4-field SHIP tokens
            (
                vec!["secp256k1".to_string()],
                vec!["2-of-2".to_string()],
                100,
                "0.0.0".to_string(),
                None,
                None,
            )
        };

    Ok(MpcNodeInfo {
        identity_key: identity_key_hex,
        domain,
        curves,
        threshold_configs,
        fee_sats,
        version,
        published_at: chrono::Utc::now(),
        max_presignatures,
        min_balance_sats,
    })
}

/// Create a standard SHIP admin token using the SDK.
///
/// This creates the standard 4-field overlay admin token (BRC-23) without
/// the extended capabilities field. Useful for interoperability with standard
/// overlay tooling.
///
/// # Arguments
///
/// * `identity_key` - The node operator's compressed secp256k1 public key
/// * `domain` - HTTPS domain of the Key Share Service
///
/// # Returns
///
/// Serialized PushDrop script bytes.
pub fn create_ship_admin_token(
    identity_key: &[u8; 33],
    domain: &str,
) -> Result<Vec<u8>, OverlayError> {
    let pubkey = PublicKey::from_bytes(identity_key).map_err(|e| {
        OverlayError::InvalidChipToken(format!("invalid identity key: {}", e))
    })?;

    let script = create_overlay_admin_token(Protocol::Ship, &pubkey, domain, MPC_TOPIC);

    Ok(script.to_binary())
}

/// Parse a standard 4-field SHIP admin token using the SDK.
///
/// This is a convenience wrapper around `decode_overlay_admin_token` that
/// validates the token is for the `tm_mpc_signing` topic.
///
/// # Arguments
///
/// * `script_bytes` - Raw script bytes from a transaction output
///
/// # Returns
///
/// The decoded overlay admin token data.
pub fn parse_ship_admin_token(
    script_bytes: &[u8],
) -> Result<bsv::overlay::OverlayAdminTokenData, OverlayError> {
    let script = LockingScript::from_binary(script_bytes).map_err(|e| {
        OverlayError::InvalidChipToken(format!("invalid script: {}", e))
    })?;

    let token = decode_overlay_admin_token(&script).map_err(|e| {
        OverlayError::InvalidChipToken(format!("not a valid admin token: {}", e))
    })?;

    if token.protocol != Protocol::Ship {
        return Err(OverlayError::InvalidChipToken(format!(
            "expected SHIP protocol, got {}",
            token.protocol
        )));
    }

    if token.topic_or_service != MPC_TOPIC {
        return Err(OverlayError::InvalidChipToken(format!(
            "expected topic {}, got {}",
            MPC_TOPIC, token.topic_or_service
        )));
    }

    Ok(token)
}

/// Submit a CHIP token to the overlay network via BRC-22 transaction submission.
///
/// The token must be wrapped in a complete BSV transaction (as BEEF) before
/// submission. The overlay node will validate the transaction, check that it
/// contains a valid CHIP output for the `tm_mpc_signing` topic, run admission
/// logic, and index the token for SLAP/CLAP lookup.
///
/// # Arguments
///
/// * `overlay_url` - Base URL of the overlay node (e.g., "https://overlay.example.com")
/// * `token_tx` - Serialized BSV transaction (BEEF format) containing the CHIP output
///
/// # Errors
///
/// Returns `OverlayError::SubmissionRejected` if the overlay node rejects the
/// transaction (invalid format, duplicate, or failed admission).
pub async fn publish_chip_token(
    overlay_url: &str,
    token_tx: &[u8],
) -> Result<(), OverlayError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let token_hex = hex::encode(token_tx);

    let body = serde_json::json!({
        "rawTx": token_hex,
        "topics": [MPC_TOPIC],
        "outputs": [0]
    });

    let url = format!("{}/submit", overlay_url.trim_end_matches('/'));

    tracing::debug!("Publishing CHIP token to {}", url);

    let resp = client
        .post(&url)
        .json(&body)
        .header("Content-Type", "application/json")
        // TODO: Add BRC-31 auth headers for authenticated submission
        .send()
        .await
        .map_err(|e| OverlayError::Unreachable(format!("failed to reach overlay: {}", e)))?;

    let status = resp.status();
    if status.is_success() {
        tracing::info!("CHIP token published successfully to {}", overlay_url);
        Ok(())
    } else {
        let body_text = resp.text().await.unwrap_or_default();
        Err(OverlayError::SubmissionRejected(format!(
            "HTTP {}: {}",
            status, body_text
        )))
    }
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
    // TODO: Full implementation requires:
    // 1. Fetch the CHIP token UTXO (txid:vout) from WoC or local state
    // 2. Build a transaction that spends the CHIP output using PushDrop::unlock()
    //    - Input: the CHIP UTXO with P2PK signature
    //    - Output: change back to node's address (minus mining fee)
    // 3. Sign with the identity key (the PushDrop locking key)
    // 4. Submit the spending tx via overlay /submit
    // 5. Return the spending txid
    //
    // The actual tx construction requires the node's private key and UTXO data,
    // which will be available when bsv-mpc-proxy integrates with the overlay crate.
    let _ = overlay_url;
    Err(OverlayError::SubmissionRejected(format!(
        "CHIP token revocation not yet implemented (txid: {}, vout: {}). \
         Requires signing with identity key to spend PushDrop UTXO.",
        token_txid, token_vout
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv::primitives::PrivateKey;

    /// Helper to create a test MpcNodeInfo.
    fn test_node_info() -> MpcNodeInfo {
        MpcNodeInfo {
            identity_key: "02".to_string() + &"aa".repeat(32),
            domain: "https://mpc.example.com".to_string(),
            curves: vec!["secp256k1".to_string()],
            threshold_configs: vec!["2-of-2".to_string(), "2-of-3".to_string()],
            fee_sats: 500,
            version: "0.1.0".to_string(),
            published_at: chrono::Utc::now(),
            max_presignatures: Some(100),
            min_balance_sats: Some(10_000),
        }
    }

    #[test]
    fn test_create_parse_roundtrip() {
        let key = PrivateKey::random();
        let pubkey = key.public_key();
        let compressed = pubkey.to_compressed();
        let domain = "https://mpc-us-1.example.com";

        let node_info = test_node_info();

        let script_bytes = create_chip_token(&compressed, domain, &node_info).unwrap();
        assert!(!script_bytes.is_empty());

        let parsed = parse_chip_token(&script_bytes).unwrap();
        assert_eq!(parsed.identity_key, pubkey.to_hex());
        assert_eq!(parsed.domain, domain);
        assert_eq!(parsed.curves, vec!["secp256k1"]);
        assert_eq!(parsed.threshold_configs, vec!["2-of-2", "2-of-3"]);
        assert_eq!(parsed.fee_sats, 500);
        assert_eq!(parsed.version, "0.1.0");
        assert_eq!(parsed.max_presignatures, Some(100));
        assert_eq!(parsed.min_balance_sats, Some(10_000));
    }

    #[test]
    fn test_create_parse_minimal_config() {
        let key = PrivateKey::random();
        let compressed = key.public_key().to_compressed();

        let node_info = MpcNodeInfo {
            identity_key: String::new(),
            domain: "https://node.example.com".to_string(),
            curves: vec!["secp256k1".to_string()],
            threshold_configs: vec!["2-of-2".to_string()],
            fee_sats: 100,
            version: "1.0.0".to_string(),
            published_at: chrono::Utc::now(),
            max_presignatures: None,
            min_balance_sats: None,
        };

        let script_bytes =
            create_chip_token(&compressed, "https://node.example.com", &node_info).unwrap();
        let parsed = parse_chip_token(&script_bytes).unwrap();

        assert_eq!(parsed.fee_sats, 100);
        assert!(parsed.max_presignatures.is_none());
        assert!(parsed.min_balance_sats.is_none());
    }

    #[test]
    fn test_create_parse_various_thresholds() {
        let key = PrivateKey::random();
        let compressed = key.public_key().to_compressed();

        let configs = vec![
            vec!["2-of-2".to_string()],
            vec!["2-of-3".to_string(), "3-of-5".to_string()],
            vec![
                "2-of-2".to_string(),
                "2-of-3".to_string(),
                "3-of-5".to_string(),
                "5-of-9".to_string(),
            ],
        ];

        for threshold_configs in configs {
            let node_info = MpcNodeInfo {
                identity_key: String::new(),
                domain: "https://test.example.com".to_string(),
                curves: vec!["secp256k1".to_string()],
                threshold_configs: threshold_configs.clone(),
                fee_sats: 200,
                version: "0.2.0".to_string(),
                published_at: chrono::Utc::now(),
                max_presignatures: None,
                min_balance_sats: None,
            };

            let bytes =
                create_chip_token(&compressed, "https://test.example.com", &node_info).unwrap();
            let parsed = parse_chip_token(&bytes).unwrap();
            assert_eq!(parsed.threshold_configs, threshold_configs);
        }
    }

    #[test]
    fn test_create_parse_various_fees() {
        let key = PrivateKey::random();
        let compressed = key.public_key().to_compressed();

        for fee in [1, 50, 100, 500, 1000, 10_000, 1_000_000] {
            let node_info = MpcNodeInfo {
                identity_key: String::new(),
                domain: "https://test.example.com".to_string(),
                curves: vec!["secp256k1".to_string()],
                threshold_configs: vec!["2-of-2".to_string()],
                fee_sats: fee,
                version: "0.1.0".to_string(),
                published_at: chrono::Utc::now(),
                max_presignatures: None,
                min_balance_sats: None,
            };

            let bytes =
                create_chip_token(&compressed, "https://test.example.com", &node_info).unwrap();
            let parsed = parse_chip_token(&bytes).unwrap();
            assert_eq!(parsed.fee_sats, fee);
        }
    }

    #[test]
    fn test_invalid_empty_domain() {
        let key = PrivateKey::random();
        let compressed = key.public_key().to_compressed();
        let node_info = test_node_info();

        let result = create_chip_token(&compressed, "", &node_info);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("domain must not be empty"));
    }

    #[test]
    fn test_invalid_zero_fee() {
        let key = PrivateKey::random();
        let compressed = key.public_key().to_compressed();

        let mut node_info = test_node_info();
        node_info.fee_sats = 0;

        let result = create_chip_token(&compressed, "https://test.example.com", &node_info);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("fee_sats must be greater than 0"));
    }

    #[test]
    fn test_invalid_identity_key() {
        let bad_key = [0u8; 33]; // All zeros is not a valid compressed pubkey
        let node_info = test_node_info();

        let result = create_chip_token(&bad_key, "https://test.example.com", &node_info);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid identity key"));
    }

    #[test]
    fn test_parse_invalid_script() {
        // Random garbage bytes
        let result = parse_chip_token(&[0x01, 0x02, 0x03]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_wrong_topic() {
        let key = PrivateKey::random();
        let pubkey = key.public_key();

        // Create a SHIP token with wrong topic
        let fields = vec![
            b"SHIP".to_vec(),
            pubkey.to_compressed().to_vec(),
            b"https://test.example.com".to_vec(),
            b"tm_other_topic".to_vec(),
        ];
        let pushdrop = PushDrop::new(pubkey, fields);
        let script = pushdrop.lock();

        let result = parse_chip_token(&script.to_binary());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("expected topic tm_mpc_signing"));
    }

    #[test]
    fn test_parse_wrong_protocol() {
        let key = PrivateKey::random();
        let pubkey = key.public_key();

        // Create a SLAP token (wrong protocol)
        let fields = vec![
            b"SLAP".to_vec(),
            pubkey.to_compressed().to_vec(),
            b"https://test.example.com".to_vec(),
            b"tm_mpc_signing".to_vec(),
        ];
        let pushdrop = PushDrop::new(pubkey, fields);
        let script = pushdrop.lock();

        let result = parse_chip_token(&script.to_binary());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("expected protocol SHIP"));
    }

    #[test]
    fn test_parse_4_field_standard_token() {
        // A standard 4-field SHIP admin token (no capabilities) should parse
        // with defaults
        let key = PrivateKey::random();
        let pubkey = key.public_key();
        let domain = "https://basic-node.example.com";

        let script = create_overlay_admin_token(Protocol::Ship, &pubkey, domain, MPC_TOPIC);

        let parsed = parse_chip_token(&script.to_binary()).unwrap();
        assert_eq!(parsed.identity_key, pubkey.to_hex());
        assert_eq!(parsed.domain, domain);
        // Defaults for missing capabilities
        assert_eq!(parsed.curves, vec!["secp256k1"]);
        assert_eq!(parsed.threshold_configs, vec!["2-of-2"]);
        assert_eq!(parsed.fee_sats, 100);
        assert_eq!(parsed.version, "0.0.0");
        assert!(parsed.max_presignatures.is_none());
        assert!(parsed.min_balance_sats.is_none());
    }

    #[test]
    fn test_ship_admin_token_sdk_roundtrip() {
        let key = PrivateKey::random();
        let compressed = key.public_key().to_compressed();
        let domain = "https://mpc.example.com";

        let bytes = create_ship_admin_token(&compressed, domain).unwrap();
        let token = parse_ship_admin_token(&bytes).unwrap();

        assert_eq!(token.protocol, Protocol::Ship);
        assert_eq!(token.domain, domain);
        assert_eq!(token.topic_or_service, MPC_TOPIC);
        assert_eq!(token.identity_key.to_compressed(), compressed);
    }

    #[test]
    fn test_pushdrop_field_count() {
        // Verify that our 5-field token has exactly 5 decoded fields
        let key = PrivateKey::random();
        let pubkey = key.public_key();
        let compressed = pubkey.to_compressed();
        let node_info = test_node_info();

        let script_bytes =
            create_chip_token(&compressed, "https://test.example.com", &node_info).unwrap();
        let script = LockingScript::from_binary(&script_bytes).unwrap();
        let pushdrop = PushDrop::decode(&script).unwrap();

        assert_eq!(pushdrop.fields.len(), 5);
        assert_eq!(std::str::from_utf8(&pushdrop.fields[0]).unwrap(), "SHIP");
        assert_eq!(pushdrop.fields[1].len(), 33);
        assert_eq!(
            std::str::from_utf8(&pushdrop.fields[3]).unwrap(),
            MPC_TOPIC
        );
    }

    #[test]
    fn test_capabilities_json_roundtrip() {
        let caps = ChipCapabilities {
            curves: vec!["secp256k1".to_string()],
            threshold_configs: vec!["2-of-3".to_string()],
            fee_sats: 250,
            version: "0.3.0".to_string(),
            max_presignatures: Some(50),
            min_balance_sats: Some(5000),
        };

        let json = serde_json::to_vec(&caps).unwrap();
        let decoded: ChipCapabilities = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded, caps);
    }

    #[test]
    fn test_multiple_nodes_distinct_tokens() {
        // Multiple nodes creating tokens should produce distinct scripts
        let mut scripts = Vec::new();
        for _ in 0..3 {
            let key = PrivateKey::random();
            let compressed = key.public_key().to_compressed();
            let node_info = test_node_info();

            let bytes =
                create_chip_token(&compressed, "https://node.example.com", &node_info).unwrap();
            scripts.push(bytes);
        }

        // All scripts should be different (different identity keys)
        assert_ne!(scripts[0], scripts[1]);
        assert_ne!(scripts[1], scripts[2]);
        assert_ne!(scripts[0], scripts[2]);
    }
}
