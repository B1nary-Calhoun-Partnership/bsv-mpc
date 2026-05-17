//! Proxy configuration.
//!
//! All settings are loaded from environment variables prefixed with `MPC_`.
//! The proxy is designed for container deployment where env vars are the
//! standard configuration mechanism.
//!
//! ## Required
//!
//! - `MPC_SHARE_PATH` — Path to the AES-256-GCM encrypted share file produced
//!   during DKG. This file contains this party's secret share of the joint
//!   signing key.
//!
//! ## Optional
//!
//! | Variable | Default | Description |
//! |----------|---------|-------------|
//! | `MPC_PROXY_PORT` | `3322` | Port to bind the BRC-100 HTTP server |
//! | `MPC_KSS_URL` | `https://kss.lobsterfarm.com` | Key Share Service endpoint |
//! | `MPC_FEE_SATS` | `1000` | Fee per signing operation (satoshis) |
//! | `MPC_FEE_ADDRESSES` | (empty) | Comma-separated multisig addresses for fee collection |
//! | `MPC_FEE_THRESHOLD` | (none) | Fee multisig threshold, e.g. `"2-of-3"` |
//! | `MPC_MAX_PRESIGS` | `20` | Maximum presignatures to stockpile |
//! | `MPC_ENCRYPTION_KEY` | (none) | Hex-encoded AES-256 key for share decryption |
//! | `MPC_ARC_API_KEY` | TAAL mainnet key | ARC API key for TAAL broadcasting |
//! | `MPC_THRESHOLD_CONFIGS` | `2-of-2,2-of-3` | Comma-separated threshold configs this cosigner supports (`/capabilities` advertises these) |
//! | `MPC_MIN_BALANCE_SATS` | (none) | Optional minimum balance required before this cosigner will participate in DKG (`/capabilities` advertises this) |

use serde::Deserialize;

/// MPC Signing Proxy configuration.
///
/// Loaded from environment variables. See module-level docs for the full list.
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    /// Port to listen on (default: 3322, matching bsv-wallet-cli).
    pub port: u16,

    /// URL of the Key Share Service — the remote party in the 2PC protocol.
    ///
    /// The KSS holds its own share of the joint signing key and participates
    /// in every signing ceremony. It never learns the full private key.
    pub kss_url: String,

    /// Path to the AES-256-GCM encrypted share file.
    ///
    /// This file is produced during the DKG ceremony and contains this party's
    /// secret share. It is encrypted at rest with the key from `encryption_key`
    /// (or a key derived during DKG if `encryption_key` is not set).
    pub share_path: String,

    /// Fee per MPC signing operation in satoshis (default: 1000).
    ///
    /// This fee is injected as an additional output in every `createAction`
    /// transaction. It compensates the MPC node operators for their
    /// participation in the signing ceremony.
    pub fee_per_signing: u64,

    /// Addresses that receive the signing fee.
    ///
    /// If multiple addresses are provided and `fee_threshold` is set, the fee
    /// output uses a bare multisig (P2MS) script. Otherwise, the fee is split
    /// equally into individual P2PKH outputs.
    pub fee_addresses: Vec<String>,

    /// Multisig threshold for fee collection (e.g., `"2-of-3"`).
    ///
    /// When set, the fee output is a bare P2MS script requiring `t` of the
    /// `fee_addresses` to spend. When unset, fees are split into P2PKH outputs.
    pub fee_threshold: Option<String>,

    /// Maximum number of presignatures to keep in the pool (default: 20).
    ///
    /// The background replenishment task generates presignatures during idle
    /// time, up to this limit. Higher values improve latency under burst load
    /// but consume more memory and KSS bandwidth.
    pub max_presignatures: usize,

    /// Hex-encoded AES-256 key for decrypting the share file.
    ///
    /// If not set, the proxy attempts to derive the decryption key from the
    /// DKG session metadata. In production, always set this explicitly.
    pub encryption_key: Option<String>,

    /// ARC API key for TAAL broadcasting (Bearer token).
    ///
    /// GorillaPool requires BEEF format (Extended Format) but no API key.
    /// TAAL requires this Bearer token for authentication.
    /// Defaults to a mainnet key if not set.
    pub arc_api_key: String,

    /// Threshold configurations this cosigner advertises support for via
    /// `GET /capabilities`. Default: `["2-of-2", "2-of-3"]`. Discovery
    /// clients filter by these.
    pub threshold_configs: Vec<String>,

    /// Optional minimum balance (in satoshis) required before this cosigner
    /// will participate in DKG. Advertised via `GET /capabilities`. `None`
    /// means no minimum.
    pub min_balance_sats: Option<u64>,
}

impl ProxyConfig {
    /// Load configuration from environment variables.
    ///
    /// Returns an error if required variables are missing or values fail to parse.
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            port: std::env::var("MPC_PROXY_PORT")
                .unwrap_or_else(|_| "3322".into())
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid MPC_PROXY_PORT: {e}"))?,

            kss_url: std::env::var("MPC_KSS_URL")
                .unwrap_or_else(|_| "https://kss.lobsterfarm.com".into()),

            share_path: std::env::var("MPC_SHARE_PATH").unwrap_or_else(|_| "share.enc".into()),

            fee_per_signing: std::env::var("MPC_FEE_SATS")
                .unwrap_or_else(|_| "1000".into())
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid MPC_FEE_SATS: {e}"))?,

            fee_addresses: std::env::var("MPC_FEE_ADDRESSES")
                .map(|s| s.split(',').map(|a| a.trim().to_string()).collect())
                .unwrap_or_default(),

            fee_threshold: std::env::var("MPC_FEE_THRESHOLD").ok(),

            max_presignatures: std::env::var("MPC_MAX_PRESIGS")
                .unwrap_or_else(|_| "20".into())
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid MPC_MAX_PRESIGS: {e}"))?,

            encryption_key: std::env::var("MPC_ENCRYPTION_KEY").ok(),

            arc_api_key: std::env::var("MPC_ARC_API_KEY")
                .unwrap_or_else(|_| "<REDACTED-ARC-API-KEY>".into()),

            threshold_configs: std::env::var("MPC_THRESHOLD_CONFIGS")
                .map(|s| {
                    s.split(',')
                        .map(|c| c.trim().to_string())
                        .filter(|c| !c.is_empty())
                        .collect()
                })
                .unwrap_or_else(|_| vec!["2-of-2".to_string(), "2-of-3".to_string()]),

            min_balance_sats: match std::env::var("MPC_MIN_BALANCE_SATS") {
                Ok(s) => Some(
                    s.parse()
                        .map_err(|e| anyhow::anyhow!("Invalid MPC_MIN_BALANCE_SATS: {e}"))?,
                ),
                Err(_) => None,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        // Clear any env vars that might interfere.
        std::env::remove_var("MPC_PROXY_PORT");
        std::env::remove_var("MPC_KSS_URL");
        std::env::remove_var("MPC_SHARE_PATH");
        std::env::remove_var("MPC_FEE_SATS");
        std::env::remove_var("MPC_FEE_ADDRESSES");
        std::env::remove_var("MPC_FEE_THRESHOLD");
        std::env::remove_var("MPC_MAX_PRESIGS");
        std::env::remove_var("MPC_ENCRYPTION_KEY");
        std::env::remove_var("MPC_ARC_API_KEY");
        std::env::remove_var("MPC_THRESHOLD_CONFIGS");
        std::env::remove_var("MPC_MIN_BALANCE_SATS");

        let config = ProxyConfig::from_env().unwrap();
        assert_eq!(config.port, 3322);
        assert_eq!(config.kss_url, "https://kss.lobsterfarm.com");
        assert_eq!(config.share_path, "share.enc");
        assert_eq!(config.fee_per_signing, 1000);
        assert!(config.fee_addresses.is_empty());
        assert!(config.fee_threshold.is_none());
        assert_eq!(config.max_presignatures, 20);
        assert!(config.encryption_key.is_none());
        assert_eq!(config.arc_api_key, "<REDACTED-ARC-API-KEY>");
        assert_eq!(config.threshold_configs, vec!["2-of-2", "2-of-3"]);
        assert!(config.min_balance_sats.is_none());
    }

    #[test]
    fn threshold_configs_parses_comma_separated() {
        std::env::set_var("MPC_THRESHOLD_CONFIGS", "2-of-3, 3-of-5,5-of-9 ");
        let config = ProxyConfig::from_env().unwrap();
        std::env::remove_var("MPC_THRESHOLD_CONFIGS");
        assert_eq!(config.threshold_configs, vec!["2-of-3", "3-of-5", "5-of-9"]);
    }

    #[test]
    fn min_balance_sats_parses_when_set() {
        std::env::set_var("MPC_MIN_BALANCE_SATS", "10000");
        let config = ProxyConfig::from_env().unwrap();
        std::env::remove_var("MPC_MIN_BALANCE_SATS");
        assert_eq!(config.min_balance_sats, Some(10_000));
    }
}
