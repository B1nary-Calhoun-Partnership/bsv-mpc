//! Proxy-side **arm-the-container** helpers for §18.2 cross-(t,n) reshare over the
//! relay (issue #35c pt2, CONTAINER target).
//!
//! The symmetric sibling of [`crate::relay_refresh`]: the orchestration itself
//! lives in [`crate::bridge::MpcBridge::reshare_change_threshold_over_relay`] (the
//! proxy plays the new-set parties 1 and 2 in-process); this module only:
//!
//! 1. Fetches the container's relay identity (`GET /reshare-relay/identity`).
//! 2. Arms the container as new-set party 0 (`POST /reshare-relay/init`,
//!    BRC-31-signed) — it runs phase A (throwaway DKG) + phase B (PSS) for its own
//!    party and stores the rotated new-(t,n) share on commit.
//!
//! Arming is fire-able async (the bridge spawns it) so the relay can sync all
//! parties while the proxy drives its own; the bridge awaits the HTTP response.

use bsv_mpc_core::error::{MpcError, Result};

/// Canonical BRC-31 request signer (same shape as `relay_refresh::RequestSigner`).
pub type RequestSigner<'a> =
    &'a (dyn Fn(&str, &str, &[u8]) -> Result<Vec<(String, String)>> + Send + Sync);

/// A new-set peer's relay identity, as sent to the container's `peers` field.
#[derive(serde::Serialize, Clone)]
pub struct ReshareRelayPeer {
    pub index: u16,
    pub pub_hex: String,
}

/// Everything the container needs to play its new-set party in the reshare.
pub struct ContainerArm {
    /// The container's `/reshare-relay/init` URL.
    pub url: String,
    /// The share's `agent_id` (joint pubkey hex K) for owner-authz (§08.1).
    pub agent_id: String,
    /// The throwaway-DKG session_id (hex).
    pub dkg_session_hex: String,
    /// The PSS reshare session_id (hex).
    pub reshare_session_hex: String,
    /// The container's index in the NEW party set.
    pub my_new_index: u16,
    /// The NEW threshold `t'`.
    pub new_threshold: u16,
    /// The NEW party count `n'`.
    pub new_parties: u16,
    /// The NEW set's VSS eval points (party order), 32-byte BE scalar hex each.
    pub new_eval_points_hex: Vec<String>,
    /// The NEW-set indices of the contributors.
    pub contributor_new_indices: Vec<u16>,
    /// The OLD-set indices of the same contributors (canonical ascending).
    pub contributor_old_indices: Vec<u16>,
    /// All OTHER new-set parties' relay identities (the proxy's in-process parties).
    pub peers: Vec<ReshareRelayPeer>,
}

#[derive(serde::Deserialize)]
struct ArmResponse {
    peer_pub_hex: String,
}

/// GET the container's `/reshare-relay/identity` (read-only) → its relay identity hex.
pub async fn fetch_peer_identity(init_url: &str) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct IdResponse {
        peer_pub_hex: String,
    }
    let url = init_url.replace("/reshare-relay/init", "/reshare-relay/identity");
    let resp = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .map_err(|e| MpcError::Protocol(format!("fetch reshare peer identity: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let txt = resp.text().await.unwrap_or_default();
        return Err(MpcError::Protocol(format!(
            "/reshare-relay/identity returned {status}: {txt}"
        )));
    }
    let parsed: IdResponse = resp
        .json()
        .await
        .map_err(|e| MpcError::Protocol(format!("parse reshare identity response: {e}")))?;
    Ok(parsed.peer_pub_hex)
}

/// POST `/reshare-relay/init`, BRC-31-signed over the canonical wire. Returns the
/// container's relay identity hex (must match the earlier `fetch_peer_identity`).
///
/// Uses a long-timeout client (the container runs BOTH ceremony phases — including
/// safe-prime generation for its throwaway DKG — before its completion task, but
/// it RESPONDS as soon as it has armed both phases; the timeout is defensive).
pub async fn arm_container(
    arm: &ContainerArm,
    request_signer: RequestSigner<'_>,
    timeout: std::time::Duration,
) -> Result<String> {
    let body = serde_json::json!({
        "agent_id": arm.agent_id,
        "dkg_session": arm.dkg_session_hex,
        "reshare_session": arm.reshare_session_hex,
        "my_new_index": arm.my_new_index,
        "new_threshold": arm.new_threshold,
        "new_parties": arm.new_parties,
        "new_eval_points_hex": arm.new_eval_points_hex,
        "contributor_new_indices": arm.contributor_new_indices,
        "contributor_old_indices": arm.contributor_old_indices,
        "peers": arm.peers,
    });
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| MpcError::Serialization(format!("serialize reshare-relay/init: {e}")))?;
    let path = reqwest::Url::parse(&arm.url)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| "/reshare-relay/init".to_string());

    let http = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| MpcError::Protocol(format!("build reshare http client: {e}")))?;
    let mut builder = http
        .post(&arm.url)
        .header("content-type", "application/json")
        .body(body_bytes.clone());
    for (name, value) in request_signer("POST", &path, &body_bytes)? {
        builder = builder.header(name, value);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| MpcError::Protocol(format!("arm reshare peer request: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let txt = resp.text().await.unwrap_or_default();
        return Err(MpcError::Protocol(format!(
            "container /reshare-relay/init returned {status}: {txt}"
        )));
    }
    let parsed: ArmResponse = resp
        .json()
        .await
        .map_err(|e| MpcError::Protocol(format!("parse reshare-relay/init response: {e}")))?;
    Ok(parsed.peer_pub_hex)
}
