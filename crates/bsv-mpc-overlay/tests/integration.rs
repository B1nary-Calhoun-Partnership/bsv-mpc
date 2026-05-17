//! Integration tests for bsv-mpc-overlay CHIP token and discovery.
//!
//! These tests validate the full register/discover/deregister flow using a
//! local Axum registry server (no real overlay network needed).
//!
//! Ported from POC 14 test 7 pattern (local_registry module).

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use bsv_mpc_overlay::chip;
use bsv_mpc_overlay::discovery;
use bsv_mpc_overlay::types::{DiscoveryQuery, MpcNodeInfo, MPC_TOPIC};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// ============================================================================
// Local registry: minimal in-memory overlay mock
// ============================================================================

/// A registered node advertisement.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodeAdvertisement {
    identity_key: String,
    domain: String,
    topic: String,
    fee_sats: u64,
    threshold_configs: Vec<String>,
}

/// Registry state: topic -> list of node advertisements.
type RegistryState = Arc<RwLock<HashMap<String, Vec<NodeAdvertisement>>>>;

/// BRC-24-style lookup request.
#[derive(Debug, Deserialize)]
struct LookupRequest {
    service: String,
    query: LookupQuery,
}

#[derive(Debug, Deserialize)]
struct LookupQuery {
    #[serde(default)]
    topics: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    node: Option<String>,
}

/// Lookup response.
#[derive(Debug, Serialize, Deserialize)]
struct LookupResponse {
    nodes: Vec<NodeAdvertisement>,
}

/// Register request.
#[derive(Debug, Deserialize)]
struct RegisterRequest {
    identity_key: String,
    domain: String,
    topic: String,
    #[serde(default = "default_fee")]
    fee_sats: u64,
    #[serde(default)]
    threshold_configs: Vec<String>,
}

fn default_fee() -> u64 {
    100
}

/// Deregister request.
#[derive(Debug, Deserialize)]
struct DeregisterRequest {
    identity_key: String,
    topic: String,
}

/// POST /submit -- register a node advertisement
async fn handle_submit(
    State(state): State<RegistryState>,
    Json(req): Json<RegisterRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let ad = NodeAdvertisement {
        identity_key: req.identity_key,
        domain: req.domain,
        topic: req.topic.clone(),
        fee_sats: req.fee_sats,
        threshold_configs: req.threshold_configs,
    };

    let mut registry = state.write().unwrap();
    registry.entry(req.topic).or_default().push(ad);

    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "success"})),
    )
}

/// POST /lookup -- BRC-24-style lookup
async fn handle_lookup(
    State(state): State<RegistryState>,
    Json(req): Json<LookupRequest>,
) -> Json<LookupResponse> {
    let registry = state.read().unwrap();
    let mut nodes = Vec::new();

    if req.service == "ls_ship" {
        for topic in &req.query.topics {
            if let Some(ads) = registry.get(topic) {
                nodes.extend(ads.iter().cloned());
            }
        }
    }

    Json(LookupResponse { nodes })
}

/// POST /deregister -- remove a node advertisement
async fn handle_deregister(
    State(state): State<RegistryState>,
    Json(req): Json<DeregisterRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let mut registry = state.write().unwrap();
    let mut removed = false;

    if let Some(ads) = registry.get_mut(&req.topic) {
        let before = ads.len();
        ads.retain(|ad| ad.identity_key != req.identity_key);
        removed = ads.len() < before;
    }

    let status = if removed { "removed" } else { "not_found" };
    (StatusCode::OK, Json(serde_json::json!({"status": status})))
}

/// Build the local registry Axum router.
fn build_registry(state: RegistryState) -> Router {
    Router::new()
        .route("/submit", post(handle_submit))
        .route("/lookup", post(handle_lookup))
        .route("/deregister", post(handle_deregister))
        .with_state(state)
}

// ============================================================================
// Integration test: full register/discover/deregister flow
// ============================================================================

#[tokio::test]
async fn test_local_registry_register_discover_deregister() {
    // Start local registry server
    let state: RegistryState = Arc::new(RwLock::new(HashMap::new()));
    let router = build_registry(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    let client = reqwest::Client::new();

    // Step 1: Register 3 MPC nodes
    let nodes = vec![
        ("02aaa1", "https://mpc-us-1.example.com", 100u64),
        ("02bbb2", "https://mpc-eu-1.example.com", 200u64),
        ("02ccc3", "https://mpc-ap-1.example.com", 150u64),
    ];

    for (key, domain, fee) in &nodes {
        let resp = client
            .post(format!("{}/submit", base_url))
            .json(&serde_json::json!({
                "identity_key": key,
                "domain": domain,
                "topic": MPC_TOPIC,
                "fee_sats": fee,
                "threshold_configs": ["2-of-2"]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    // Step 2: Discover all MPC nodes
    let resp = client
        .post(format!("{}/lookup", base_url))
        .json(&serde_json::json!({
            "service": "ls_ship",
            "query": {"topics": [MPC_TOPIC]}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let result: LookupResponse = resp.json().await.unwrap();
    assert_eq!(result.nodes.len(), 3);

    // Step 3: Query unrelated topic should return empty
    let resp = client
        .post(format!("{}/lookup", base_url))
        .json(&serde_json::json!({
            "service": "ls_ship",
            "query": {"topics": ["tm_other"]}
        }))
        .send()
        .await
        .unwrap();
    let result: LookupResponse = resp.json().await.unwrap();
    assert_eq!(result.nodes.len(), 0);

    // Step 4: Deregister EU node
    let resp = client
        .post(format!("{}/deregister", base_url))
        .json(&serde_json::json!({
            "identity_key": "02bbb2",
            "topic": MPC_TOPIC
        }))
        .send()
        .await
        .unwrap();
    let result: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(result["status"], "removed");

    // Step 5: Verify 2 nodes remain
    let resp = client
        .post(format!("{}/lookup", base_url))
        .json(&serde_json::json!({
            "service": "ls_ship",
            "query": {"topics": [MPC_TOPIC]}
        }))
        .send()
        .await
        .unwrap();
    let result: LookupResponse = resp.json().await.unwrap();
    assert_eq!(result.nodes.len(), 2);

    let remaining: Vec<&str> = result
        .nodes
        .iter()
        .map(|n| n.identity_key.as_str())
        .collect();
    assert!(!remaining.contains(&"02bbb2"));
    assert!(remaining.contains(&"02aaa1"));
    assert!(remaining.contains(&"02ccc3"));

    // Step 6: Deregister non-existent node
    let resp = client
        .post(format!("{}/deregister", base_url))
        .json(&serde_json::json!({
            "identity_key": "02ddd4",
            "topic": MPC_TOPIC
        }))
        .send()
        .await
        .unwrap();
    let result: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(result["status"], "not_found");
}

// ============================================================================
// CHIP token integration: create tokens and filter using discovery logic
// ============================================================================

#[test]
fn test_chip_token_create_and_filter_pipeline() {
    use bsv::primitives::PrivateKey;

    // Post-Path-A flow: CHIP tokens carry only (identity_key, domain). The
    // capabilities (curves, fee_sats, threshold_configs) live on each
    // cosigner's /capabilities endpoint and are fetched after token
    // validation by discovery.rs (TODO #16). This test mirrors the real
    // flow: create + parse the canonical 5-field signed token, then merge
    // with simulated capabilities to produce the MpcNodeInfo that
    // filter_and_rank_nodes consumes.
    let configs = vec![
        ("https://us1.com", 100u64, vec!["2-of-2"], vec!["secp256k1"]),
        ("https://eu1.com", 500, vec!["2-of-3"], vec!["secp256k1"]),
        (
            "https://ap1.com",
            200,
            vec!["2-of-2", "2-of-3"],
            vec!["secp256k1"],
        ),
        ("https://us2.com", 300, vec!["3-of-5"], vec!["secp256k1"]),
        ("https://eu2.com", 150, vec!["2-of-2"], vec!["ed25519"]),
    ];

    let mut nodes: Vec<MpcNodeInfo> = Vec::new();
    for (domain, fee, thresholds, curves) in &configs {
        let key = PrivateKey::random();

        // Create + parse a real signed CHIP token. This is the part the
        // overlay actually carries.
        let bytes = chip::create_chip_token(&key, domain).unwrap();
        let token = chip::parse_chip_token(&bytes).unwrap();

        // Merge with simulated /capabilities response.
        nodes.push(MpcNodeInfo {
            identity_key: token.identity_key,
            domain: token.domain,
            curves: curves.iter().map(|s| s.to_string()).collect(),
            threshold_configs: thresholds.iter().map(|s| s.to_string()).collect(),
            fee_sats: *fee,
            version: "0.1.0".to_string(),
            published_at: chrono::Utc::now(),
            max_presignatures: None,
            min_balance_sats: None,
        });
    }

    // Filter: secp256k1 + 2-of-2 + max 300 sats
    let query = DiscoveryQuery {
        curve: Some("secp256k1".to_string()),
        threshold: Some("2-of-2".to_string()),
        max_fee_sats: Some(300),
        limit: Some(10),
    };

    let result = discovery::filter_and_rank_nodes(nodes, &query);

    // Should match: us1 (100, secp256k1, 2-of-2), ap1 (200, secp256k1, 2-of-2+2-of-3)
    // Should NOT match: eu1 (500 > 300), us2 (no 2-of-2), eu2 (ed25519)
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].fee_sats, 100); // Cheapest first
    assert_eq!(result[1].fee_sats, 200);
}

// ============================================================================
// E2E tests (real mainnet overlay, #[ignore])
// ============================================================================

#[tokio::test]
#[ignore = "requires network: hits live mainnet SLAP trackers"]
async fn test_live_slap_tracker_reachability() {
    use bsv::overlay::NetworkPreset;

    let trackers = NetworkPreset::Mainnet.slap_trackers();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    let mut reachable = 0;

    for tracker_url in &trackers {
        let url = format!("{}/lookup", tracker_url);
        let query = serde_json::json!({
            "service": "ls_slap",
            "query": {}
        });

        if let Ok(resp) = client
            .post(&url)
            .json(&query)
            .header("X-Aggregation", "yes")
            .send()
            .await
        {
            let status = resp.status();
            if status.is_success() || status.as_u16() == 400 {
                reachable += 1;
            }
        }
    }

    assert!(reachable > 0, "At least one SLAP tracker must be reachable");
}

#[tokio::test]
#[ignore = "requires network: queries live mainnet overlay for tm_mpc_signing"]
async fn test_live_lookup_resolver_tm_mpc_signing() {
    use bsv::overlay::{
        LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, NetworkPreset,
    };

    let resolver = LookupResolver::new(LookupResolverConfig {
        network_preset: NetworkPreset::Mainnet,
        ..Default::default()
    });

    let question = LookupQuestion::new("ls_ship", serde_json::json!({"topics": [MPC_TOPIC]}));

    // This should succeed (possibly with 0 outputs if nobody registered yet)
    match resolver.query(&question, Some(10_000)).await {
        Ok(answer) => match &answer {
            LookupAnswer::OutputList { outputs } => {
                // 0 outputs is valid (nobody registered MPC nodes yet)
                assert!(outputs.len() < 10_000, "Reasonable number of outputs");
            }
            LookupAnswer::Freeform { .. } => {
                // Also acceptable
            }
            LookupAnswer::Formula { .. } => {
                // Also acceptable
            }
        },
        Err(e) => {
            // Lookup failure is acceptable if no hosts serve ls_ship for this topic
            let msg = e.to_string();
            assert!(
                msg.contains("No competent") || msg.contains("backing off"),
                "Unexpected lookup error: {}",
                msg
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires network: health check against a known live endpoint"]
async fn test_live_health_check() {
    // Use a known live BSV endpoint for health checking
    let node = MpcNodeInfo {
        identity_key: "02dummy".to_string(),
        domain: "https://overlay-us-1.bsvb.tech".to_string(),
        curves: vec!["secp256k1".to_string()],
        threshold_configs: vec!["2-of-2".to_string()],
        fee_sats: 100,
        version: "0.1.0".to_string(),
        published_at: chrono::Utc::now(),
        max_presignatures: None,
        min_balance_sats: None,
    };

    // The overlay tracker may or may not have a /health endpoint,
    // but verify_node_health should not panic or error
    let result = discovery::verify_node_health(&node).await;
    assert!(
        result.is_ok(),
        "Health check should not error: {:?}",
        result
    );
}
