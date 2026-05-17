//! MPC node discovery via SLAP/CLAP overlay lookup.
//!
//! Discovers MPC signing nodes by querying the BSV overlay network. The
//! discovery flow follows the BSV overlay lookup protocol stack:
//!
//! 1. **SLAP (BRC-24)**: Query SLAP trackers to find overlay nodes hosting
//!    SHIP lookup services for the `tm_mpc_signing` topic.
//!
//! 2. **SHIP (BRC-22)**: Query those overlay nodes for SHIP admin tokens
//!    advertising MPC signing services.
//!
//! 3. **Parse**: Extract `MpcNodeInfo` from the CHIP token PushDrop scripts.
//!
//! 4. **Filter**: Apply query parameters (curve, threshold, max fee).
//!
//! 5. **Rank**: Sort by fee (cheapest first), deduplicate by identity key.
//!
//! ## Example
//!
//! ```rust,no_run
//! use bsv_mpc_overlay::discovery;
//! use bsv_mpc_overlay::types::DiscoveryQuery;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let nodes = discovery::discover_nodes(
//!     "https://overlay.example.com",
//!     &DiscoveryQuery {
//!         curve: Some("secp256k1".into()),
//!         threshold: Some("2-of-2".into()),
//!         max_fee_sats: Some(1000),
//!         limit: Some(5),
//!     },
//! ).await?;
//!
//! // Pick the cheapest node with the best reputation
//! if let Some(best) = nodes.first() {
//!     println!("Best node: {} @ {}", best.identity_key, best.domain);
//! }
//! # Ok(())
//! # }
//! ```

use crate::chip;
use crate::error::OverlayError;
use crate::types::{DiscoveryQuery, MpcNodeInfo, MPC_TOPIC};
use bsv::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, NetworkPreset,
};
use bsv::transaction::Transaction;
use std::collections::HashMap;

/// The SLAP lookup service name for MPC signing.
///
/// Overlay nodes that host SHIP tokens for `tm_mpc_signing` advertise
/// themselves under this service name via SLAP.
pub const MPC_LOOKUP_SERVICE: &str = "ls_mpc_signing";

/// Discover MPC nodes from the BSV overlay network.
///
/// Uses the SDK's `LookupResolver` to query SLAP trackers for SHIP hosts,
/// then queries those hosts for SHIP admin tokens advertising `tm_mpc_signing`.
/// Each output is parsed as a CHIP token to extract `MpcNodeInfo`.
///
/// # Flow
///
/// 1. Create a `LookupResolver` with mainnet preset (or custom overlay URL).
/// 2. Build a `LookupQuestion` for `ls_ship` with topics `["tm_mpc_signing"]`.
/// 3. Call `resolver.query()` which handles SLAP discovery + parallel host queries.
/// 4. Parse each returned UTXO as a CHIP token via `chip::parse_chip_token()`.
/// 5. Filter by query parameters (curve, threshold, max_fee).
/// 6. Deduplicate by identity_key (keep most recent `published_at`).
/// 7. Sort by `fee_sats` ascending (cheapest first).
/// 8. Truncate to `query.limit` results (default 20).
///
/// # Arguments
///
/// * `overlay_url` - Base URL of an overlay node (used for custom resolver config,
///   or pass empty string to use default mainnet SLAP trackers)
/// * `query` - Filter and pagination parameters
///
/// # Errors
///
/// Returns `OverlayError::NoNodesFound` if no nodes match the query after filtering.
/// Returns `OverlayError::LookupFailed` if the overlay query fails.
pub async fn discover_nodes(
    overlay_url: &str,
    query: &DiscoveryQuery,
) -> Result<Vec<MpcNodeInfo>, OverlayError> {
    let limit = query.limit.unwrap_or(20);
    let default_curve = "secp256k1".to_string();
    let curve = query.curve.as_ref().unwrap_or(&default_curve);

    // Build resolver config — use custom SLAP trackers if overlay_url is provided,
    // otherwise default mainnet trackers.
    let config = if overlay_url.is_empty() {
        LookupResolverConfig {
            network_preset: NetworkPreset::Mainnet,
            ..Default::default()
        }
    } else {
        let mut additional = HashMap::new();
        additional.insert("ls_ship".to_string(), vec![overlay_url.to_string()]);
        LookupResolverConfig {
            network_preset: NetworkPreset::Mainnet,
            additional_hosts: Some(additional),
            ..Default::default()
        }
    };

    let resolver = LookupResolver::new(config);

    // Query for SHIP tokens advertising tm_mpc_signing
    // This is the pattern from POC 14 test 6
    let question = LookupQuestion::new("ls_ship", serde_json::json!({"topics": [MPC_TOPIC]}));

    let answer = resolver.query(&question, Some(10_000)).await.map_err(|e| {
        OverlayError::LookupFailed(format!("SHIP lookup for {} failed: {}", MPC_TOPIC, e))
    })?;

    // Parse results
    let mut nodes: Vec<MpcNodeInfo> = Vec::new();

    match answer {
        LookupAnswer::OutputList { outputs } => {
            tracing::debug!("Got {} output(s) for {} lookup", outputs.len(), MPC_TOPIC);

            for output in outputs {
                // Parse BEEF to get the transaction
                let tx = match Transaction::from_beef(&output.beef, None) {
                    Ok(tx) => tx,
                    Err(e) => {
                        tracing::warn!("Failed to parse BEEF from output: {}", e);
                        continue;
                    }
                };

                // Get the locking script at the output index
                let locking_script = match tx.outputs.get(output.output_index as usize) {
                    Some(out) => &out.locking_script,
                    None => {
                        tracing::warn!(
                            "Output index {} out of bounds (tx has {} outputs)",
                            output.output_index,
                            tx.outputs.len()
                        );
                        continue;
                    }
                };

                // Parse as canonical 5-field signed SHIP token (Path A).
                // Capabilities (curves, fee_sats, threshold_configs, version)
                // are NOT in the token — they're served by each cosigner at
                // GET https://{domain}/capabilities. Until task #16 wires
                // the side-channel fetch, fill placeholder values; this
                // keeps the type contract intact but `discover_nodes` will
                // not return real capabilities yet (only identity + domain
                // are trustworthy in the returned MpcNodeInfo). All filters
                // that depend on capabilities (curve / threshold / fee)
                // will pass-through the placeholder defaults — once #16
                // lands, real values flow through.
                let script_bytes = locking_script.to_binary();
                match chip::parse_chip_token(&script_bytes) {
                    Ok(token_info) => nodes.push(MpcNodeInfo {
                        identity_key: token_info.identity_key,
                        domain: token_info.domain,
                        // TODO(#16): fetch the next 5 fields from GET {domain}/capabilities.
                        curves: vec!["secp256k1".to_string()],
                        threshold_configs: vec!["2-of-2".to_string(), "2-of-3".to_string()],
                        fee_sats: 0,
                        version: "0.0.0".to_string(),
                        published_at: chrono::Utc::now(),
                        max_presignatures: None,
                        min_balance_sats: None,
                    }),
                    Err(e) => {
                        tracing::trace!("Output is not a valid signed MPC CHIP token: {}", e);
                    }
                }
            }
        }
        LookupAnswer::Freeform { result } => {
            tracing::debug!("Got freeform response for {} lookup: {}", MPC_TOPIC, result);
        }
        LookupAnswer::Formula { formulas } => {
            tracing::debug!(
                "Got formula response for {} lookup with {} entries",
                MPC_TOPIC,
                formulas.len()
            );
        }
    }

    // Filter by query parameters
    let filtered: Vec<MpcNodeInfo> = nodes
        .into_iter()
        .filter(|node| {
            // Curve filter
            if !node.curves.contains(curve) {
                return false;
            }
            // Threshold filter
            if let Some(ref threshold) = query.threshold {
                if !node.threshold_configs.contains(threshold) {
                    return false;
                }
            }
            // Max fee filter
            if let Some(max_fee) = query.max_fee_sats {
                if node.fee_sats > max_fee {
                    return false;
                }
            }
            true
        })
        .collect();

    // Deduplicate by identity_key (keep the most recently published)
    let mut deduped: HashMap<String, MpcNodeInfo> = HashMap::new();
    for node in filtered {
        let entry = deduped
            .entry(node.identity_key.clone())
            .or_insert_with(|| node.clone());
        if node.published_at > entry.published_at {
            *entry = node;
        }
    }

    // Sort by fee_sats ascending (cheapest first)
    let mut result: Vec<MpcNodeInfo> = deduped.into_values().collect();
    result.sort_by_key(|n| n.fee_sats);

    // Truncate to limit
    result.truncate(limit);

    if result.is_empty() {
        return Err(OverlayError::NoNodesFound);
    }

    Ok(result)
}

/// Get the reputation score for a specific node.
///
/// Reputation is measured by the number of participation proofs the node
/// has published to the `tm_mpc_signing` overlay topic. More proofs indicate
/// a more active and reliable signing participant.
///
/// # Arguments
///
/// * `overlay_url` - Base URL of the overlay node
/// * `identity_key` - The node's BRC-31 identity key (hex)
///
/// # Returns
///
/// The number of participation proofs published by this node.
pub async fn node_reputation(overlay_url: &str, identity_key: &str) -> Result<u64, OverlayError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let body = serde_json::json!({
        "service": "ls_mpc_proofs",
        "query": {
            "node": identity_key
        }
    });

    let url = format!("{}/lookup", overlay_url.trim_end_matches('/'));

    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| OverlayError::Unreachable(format!("failed to reach overlay: {}", e)))?;

    if !resp.status().is_success() {
        return Err(OverlayError::LookupFailed(format!(
            "proof lookup returned HTTP {}",
            resp.status()
        )));
    }

    // Try to parse as LookupAnswer
    let answer: LookupAnswer = resp.json().await.map_err(|e| {
        OverlayError::LookupFailed(format!("failed to parse proof lookup response: {}", e))
    })?;

    match answer {
        LookupAnswer::OutputList { outputs } => Ok(outputs.len() as u64),
        _ => Ok(0),
    }
}

/// Verify that a discovered node is reachable and healthy.
///
/// Performs an HTTP health check against the node's Key Share Service.
/// This is a lightweight liveness check -- it does not verify the node's
/// shares or capabilities.
///
/// # Arguments
///
/// * `node` - The discovered node to health-check
///
/// # Returns
///
/// `true` if the node's `/health` endpoint returns a 200 status.
pub async fn verify_node_health(node: &MpcNodeInfo) -> Result<bool, OverlayError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    // Build the health check URL. The domain may or may not include the scheme.
    let url = if node.domain.starts_with("http://") || node.domain.starts_with("https://") {
        format!("{}/health", node.domain.trim_end_matches('/'))
    } else {
        format!("https://{}/health", node.domain.trim_end_matches('/'))
    };

    tracing::debug!("Health check: GET {}", url);

    match client.get(&url).send().await {
        Ok(resp) => {
            let healthy = resp.status().is_success();
            if healthy {
                tracing::debug!("Node {} is healthy", node.domain);
            } else {
                tracing::debug!("Node {} returned HTTP {}", node.domain, resp.status());
            }
            Ok(healthy)
        }
        Err(e) => {
            tracing::debug!("Node {} health check failed: {}", node.domain, e);
            Ok(false)
        }
    }
}

/// Discover nodes and verify their health, returning only reachable nodes.
///
/// Convenience function that combines [`discover_nodes`] with
/// [`verify_node_health`], running health checks concurrently with bounded
/// parallelism.
///
/// # Arguments
///
/// * `overlay_url` - Base URL of the overlay node
/// * `query` - Discovery query parameters
/// * `max_concurrent_checks` - Maximum number of concurrent health checks (default 5)
///
/// # Returns
///
/// Only nodes that pass both discovery filtering and health verification.
pub async fn discover_healthy_nodes(
    overlay_url: &str,
    query: &DiscoveryQuery,
    max_concurrent_checks: Option<usize>,
) -> Result<Vec<MpcNodeInfo>, OverlayError> {
    let max_concurrent = max_concurrent_checks.unwrap_or(5);

    let nodes = discover_nodes(overlay_url, query).await?;

    // Run health checks with bounded concurrency using chunks
    let mut healthy_nodes: Vec<MpcNodeInfo> = Vec::new();

    for chunk in nodes.chunks(max_concurrent) {
        let checks: Vec<_> = chunk
            .iter()
            .map(|node| {
                let node = node.clone();
                async move {
                    let healthy = verify_node_health(&node).await.unwrap_or(false);
                    (node, healthy)
                }
            })
            .collect();

        let results = futures::future::join_all(checks).await;

        for (node, healthy) in results {
            if healthy {
                healthy_nodes.push(node);
            }
        }
    }

    if healthy_nodes.is_empty() {
        return Err(OverlayError::NoNodesFound);
    }

    Ok(healthy_nodes)
}

/// Filter and rank a list of nodes by the given query.
///
/// This is a pure function (no network) useful for client-side filtering
/// of nodes returned from a local registry or cached discovery result.
///
/// # Arguments
///
/// * `nodes` - List of nodes to filter
/// * `query` - Filter and pagination parameters
///
/// # Returns
///
/// Filtered, deduplicated, and sorted nodes.
pub fn filter_and_rank_nodes(nodes: Vec<MpcNodeInfo>, query: &DiscoveryQuery) -> Vec<MpcNodeInfo> {
    let limit = query.limit.unwrap_or(20);
    let default_curve = "secp256k1".to_string();
    let curve = query.curve.as_ref().unwrap_or(&default_curve);

    // Filter
    let filtered: Vec<MpcNodeInfo> = nodes
        .into_iter()
        .filter(|node| {
            if !node.curves.contains(curve) {
                return false;
            }
            if let Some(ref threshold) = query.threshold {
                if !node.threshold_configs.contains(threshold) {
                    return false;
                }
            }
            if let Some(max_fee) = query.max_fee_sats {
                if node.fee_sats > max_fee {
                    return false;
                }
            }
            true
        })
        .collect();

    // Deduplicate by identity_key
    let mut deduped: HashMap<String, MpcNodeInfo> = HashMap::new();
    for node in filtered {
        let entry = deduped
            .entry(node.identity_key.clone())
            .or_insert_with(|| node.clone());
        if node.published_at > entry.published_at {
            *entry = node;
        }
    }

    // Sort by fee ascending
    let mut result: Vec<MpcNodeInfo> = deduped.into_values().collect();
    result.sort_by_key(|n| n.fee_sats);
    result.truncate(limit);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(
        key: &str,
        domain: &str,
        fee: u64,
        curves: Vec<&str>,
        thresholds: Vec<&str>,
    ) -> MpcNodeInfo {
        MpcNodeInfo {
            identity_key: key.to_string(),
            domain: domain.to_string(),
            curves: curves.into_iter().map(String::from).collect(),
            threshold_configs: thresholds.into_iter().map(String::from).collect(),
            fee_sats: fee,
            version: "0.1.0".to_string(),
            published_at: chrono::Utc::now(),
            max_presignatures: None,
            min_balance_sats: None,
        }
    }

    #[test]
    fn test_filter_by_curve() {
        let nodes = vec![
            make_node("key1", "a.com", 100, vec!["secp256k1"], vec!["2-of-2"]),
            make_node("key2", "b.com", 200, vec!["ed25519"], vec!["2-of-2"]),
            make_node(
                "key3",
                "c.com",
                150,
                vec!["secp256k1", "ed25519"],
                vec!["2-of-2"],
            ),
        ];

        let query = DiscoveryQuery {
            curve: Some("secp256k1".to_string()),
            ..Default::default()
        };

        let result = filter_and_rank_nodes(nodes, &query);
        assert_eq!(result.len(), 2);
        assert!(result
            .iter()
            .all(|n| n.curves.contains(&"secp256k1".to_string())));
    }

    #[test]
    fn test_filter_by_threshold() {
        let nodes = vec![
            make_node("key1", "a.com", 100, vec!["secp256k1"], vec!["2-of-2"]),
            make_node("key2", "b.com", 200, vec!["secp256k1"], vec!["2-of-3"]),
            make_node(
                "key3",
                "c.com",
                150,
                vec!["secp256k1"],
                vec!["2-of-2", "2-of-3"],
            ),
        ];

        let query = DiscoveryQuery {
            threshold: Some("2-of-3".to_string()),
            ..Default::default()
        };

        let result = filter_and_rank_nodes(nodes, &query);
        assert_eq!(result.len(), 2);
        assert!(result
            .iter()
            .all(|n| n.threshold_configs.contains(&"2-of-3".to_string())));
    }

    #[test]
    fn test_filter_by_max_fee() {
        let nodes = vec![
            make_node("key1", "a.com", 100, vec!["secp256k1"], vec!["2-of-2"]),
            make_node("key2", "b.com", 500, vec!["secp256k1"], vec!["2-of-2"]),
            make_node("key3", "c.com", 200, vec!["secp256k1"], vec!["2-of-2"]),
        ];

        let query = DiscoveryQuery {
            max_fee_sats: Some(200),
            ..Default::default()
        };

        let result = filter_and_rank_nodes(nodes, &query);
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|n| n.fee_sats <= 200));
    }

    #[test]
    fn test_sort_by_fee_ascending() {
        let nodes = vec![
            make_node("key1", "a.com", 500, vec!["secp256k1"], vec!["2-of-2"]),
            make_node("key2", "b.com", 100, vec!["secp256k1"], vec!["2-of-2"]),
            make_node("key3", "c.com", 300, vec!["secp256k1"], vec!["2-of-2"]),
        ];

        let query = DiscoveryQuery::default();
        let result = filter_and_rank_nodes(nodes, &query);

        assert_eq!(result.len(), 3);
        assert!(result[0].fee_sats <= result[1].fee_sats);
        assert!(result[1].fee_sats <= result[2].fee_sats);
    }

    #[test]
    fn test_deduplicate_by_identity_key() {
        let now = chrono::Utc::now();
        let earlier = now - chrono::Duration::hours(1);

        let nodes = vec![
            MpcNodeInfo {
                identity_key: "key1".to_string(),
                domain: "old.com".to_string(),
                curves: vec!["secp256k1".to_string()],
                threshold_configs: vec!["2-of-2".to_string()],
                fee_sats: 100,
                version: "0.1.0".to_string(),
                published_at: earlier,
                max_presignatures: None,
                min_balance_sats: None,
            },
            MpcNodeInfo {
                identity_key: "key1".to_string(),
                domain: "new.com".to_string(),
                curves: vec!["secp256k1".to_string()],
                threshold_configs: vec!["2-of-2".to_string()],
                fee_sats: 200,
                version: "0.2.0".to_string(),
                published_at: now,
                max_presignatures: None,
                min_balance_sats: None,
            },
            make_node("key2", "other.com", 150, vec!["secp256k1"], vec!["2-of-2"]),
        ];

        let query = DiscoveryQuery::default();
        let result = filter_and_rank_nodes(nodes, &query);

        assert_eq!(result.len(), 2);
        // The deduped key1 should be the newer one
        let key1_node = result.iter().find(|n| n.identity_key == "key1").unwrap();
        assert_eq!(key1_node.domain, "new.com");
        assert_eq!(key1_node.version, "0.2.0");
    }

    #[test]
    fn test_limit_results() {
        let nodes: Vec<MpcNodeInfo> = (0..10)
            .map(|i| {
                make_node(
                    &format!("key{}", i),
                    &format!("node{}.com", i),
                    100 + i * 10,
                    vec!["secp256k1"],
                    vec!["2-of-2"],
                )
            })
            .collect();

        let query = DiscoveryQuery {
            limit: Some(3),
            ..Default::default()
        };

        let result = filter_and_rank_nodes(nodes, &query);
        assert_eq!(result.len(), 3);
        // Should be the 3 cheapest
        assert_eq!(result[0].fee_sats, 100);
        assert_eq!(result[1].fee_sats, 110);
        assert_eq!(result[2].fee_sats, 120);
    }

    #[test]
    fn test_combined_filters() {
        let nodes = vec![
            make_node("key1", "a.com", 100, vec!["secp256k1"], vec!["2-of-2"]),
            make_node("key2", "b.com", 500, vec!["secp256k1"], vec!["2-of-3"]),
            make_node(
                "key3",
                "c.com",
                200,
                vec!["secp256k1"],
                vec!["2-of-2", "2-of-3"],
            ),
            make_node("key4", "d.com", 300, vec!["ed25519"], vec!["2-of-3"]),
        ];

        let query = DiscoveryQuery {
            curve: Some("secp256k1".to_string()),
            threshold: Some("2-of-3".to_string()),
            max_fee_sats: Some(400),
            limit: Some(10),
        };

        let result = filter_and_rank_nodes(nodes, &query);
        // Only key3 matches: secp256k1 + 2-of-3 + fee 200 <= 400
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].identity_key, "key3");
    }

    #[test]
    fn test_empty_nodes_returns_empty() {
        let query = DiscoveryQuery::default();
        let result = filter_and_rank_nodes(vec![], &query);
        assert!(result.is_empty());
    }

    #[test]
    fn test_no_filters_returns_all() {
        let nodes = vec![
            make_node("key1", "a.com", 100, vec!["secp256k1"], vec!["2-of-2"]),
            make_node("key2", "b.com", 200, vec!["secp256k1"], vec!["2-of-3"]),
        ];

        let query = DiscoveryQuery::default();
        let result = filter_and_rank_nodes(nodes, &query);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_mpc_lookup_service_name() {
        assert_eq!(MPC_LOOKUP_SERVICE, "ls_mpc_signing");
    }
}
