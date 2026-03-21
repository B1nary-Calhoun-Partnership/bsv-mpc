//! Axum request handlers for the self-hosted MPC Key Share Service.
//!
//! These handlers are functionally identical to the CF Worker handlers in
//! `bsv-mpc-worker::api`, but use axum extractors instead of `worker::Request`
//! and local SQLite instead of Durable Object SQLite.
//!
//! ## Shared Protocol Logic
//!
//! Both the Worker and self-hosted versions delegate to `bsv-mpc-core` for
//! the actual MPC protocol logic. The only differences are:
//!
//! 1. **Storage backend**: SQLite file vs. Durable Object SQLite
//! 2. **HTTP framework**: axum vs. `worker` crate
//! 3. **Auth context**: Both use BRC-31, but session storage differs

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use bsv_mpc_core::types::{RoundMessage, ThresholdConfig};
use serde::{Deserialize, Serialize};

use crate::AppState;

// ── Request / Response Types ──────────────────────────────────────────────
//
// These mirror the types in bsv-mpc-worker::api. In a future refactor, these
// could be extracted into a shared crate (bsv-mpc-api-types) to eliminate
// duplication. For now, they are duplicated to keep the crates independent.

/// Request body for `POST /dkg/init`.
#[derive(Debug, Deserialize)]
pub struct DkgInitRequest {
    /// BRC-31 identity key of the requesting agent (33-byte hex).
    pub agent_id: String,
    /// Desired threshold configuration.
    pub config: ThresholdConfig,
    /// Optional human-readable label for this DKG session.
    pub label: Option<String>,
}

/// Response from `POST /dkg/init`.
#[derive(Debug, Serialize)]
pub struct DkgInitResponse {
    /// Temporary session ID for this DKG ceremony.
    pub session_id: String,
    /// This party's round 1 message.
    pub round_message: RoundMessage,
    /// Total expected rounds.
    pub total_rounds: u8,
}

/// Request body for `POST /dkg/round`.
#[derive(Debug, Deserialize)]
pub struct DkgRoundRequest {
    /// DKG session ID from `/dkg/init`.
    pub session_id: String,
    /// Incoming round message from the other party.
    pub round_message: RoundMessage,
}

/// Response from `POST /dkg/round`.
#[derive(Debug, Serialize)]
pub struct DkgRoundResponse {
    pub session_id: String,
    pub round_message: Option<RoundMessage>,
    pub complete: bool,
    pub joint_pubkey: Option<bsv_mpc_core::types::JointPublicKey>,
}

/// Request body for `POST /sign/init`.
#[derive(Debug, Deserialize)]
pub struct SignInitRequest {
    /// Agent requesting signing.
    pub agent_id: String,
    /// MPC session ID from DKG.
    pub session_id: String,
    /// Sighash to sign (32 bytes, hex).
    pub sighash: String,
    /// Whether to consume a presignature for single-round signing.
    pub use_presignature: bool,
}

/// Response from `POST /sign/init`.
#[derive(Debug, Serialize)]
pub struct SignInitResponse {
    pub signing_session_id: String,
    pub round_message: RoundMessage,
    pub using_presignature: bool,
    pub total_rounds: u8,
}

/// Request body for `POST /sign/round`.
#[derive(Debug, Deserialize)]
pub struct SignRoundRequest {
    pub signing_session_id: String,
    pub round_message: RoundMessage,
}

/// Response from `POST /sign/round`.
#[derive(Debug, Serialize)]
pub struct SignRoundResponse {
    pub signing_session_id: String,
    pub round_message: Option<RoundMessage>,
    pub complete: bool,
    pub signature: Option<bsv_mpc_core::types::SigningResult>,
}

/// Request body for `POST /presign/init`.
#[derive(Debug, Deserialize)]
pub struct PresignInitRequest {
    pub agent_id: String,
    pub session_id: String,
    /// Number of presignatures to generate (max 100).
    pub count: u16,
}

/// Response from `POST /presign/init`.
#[derive(Debug, Serialize)]
pub struct PresignInitResponse {
    pub presign_session_id: String,
    pub round_messages: Vec<RoundMessage>,
    pub total_rounds: u8,
}

/// Request body for `POST /presign/round`.
#[derive(Debug, Deserialize)]
pub struct PresignRoundRequest {
    pub presign_session_id: String,
    pub round_messages: Vec<RoundMessage>,
}

/// Response from `POST /presign/round`.
#[derive(Debug, Serialize)]
pub struct PresignRoundResponse {
    pub presign_session_id: String,
    pub round_messages: Option<Vec<RoundMessage>>,
    pub complete: bool,
    pub presignatures_generated: Option<u16>,
}

/// Response from `GET /health`.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub share_count: usize,
    pub total_presignatures: u64,
    pub uptime_seconds: i64,
    pub data_dir: String,
}

// ── Handlers ──────────────────────────────────────────────────────────────

/// `POST /dkg/init` — Start a Distributed Key Generation ceremony.
///
/// Validates BRC-31 auth, creates a DKG coordinator, generates round 1,
/// persists intermediate state, and returns the round 1 message.
pub async fn handle_dkg_init(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DkgInitRequest>,
) -> impl IntoResponse {
    todo!(
        "1. Verify BRC-31 auth from request headers\n\
         2. Validate config: threshold >= 2, threshold <= parties\n\
         3. Create DKG coordinator: bsv_mpc_core::dkg::Coordinator::new(body.config)\n\
         4. Generate round 1: coordinator.round1()\n\
         5. Generate session_id (UUID or random)\n\
         6. storage.write().store_dkg_state(state)\n\
         7. Return (StatusCode::OK, Json(DkgInitResponse))"
    );

    #[allow(unreachable_code)]
    (StatusCode::OK, Json(serde_json::json!({})))
}

/// `POST /dkg/round` — Process a DKG round message.
pub async fn handle_dkg_round(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DkgRoundRequest>,
) -> impl IntoResponse {
    todo!(
        "1. Verify BRC-31 auth\n\
         2. Load DKG state: storage.read().get_dkg_state(&body.session_id)\n\
         3. Reconstruct coordinator from persisted state\n\
         4. Process round: coordinator.process_round(body.round_message)\n\
         5. If complete:\n\
              a. Finalize: coordinator.finalize() -> DkgResult\n\
              b. Store share: storage.write().store_share(agent_id, &result.share)\n\
              c. Clean up: storage.write().delete_dkg_state(&body.session_id)\n\
              d. Return DkgRoundResponse {{ complete: true, joint_pubkey: Some(...) }}\n\
         6. Else:\n\
              a. Generate next round message\n\
              b. Persist updated state\n\
              c. Return DkgRoundResponse {{ round_message: Some(...), complete: false }}"
    );

    #[allow(unreachable_code)]
    (StatusCode::OK, Json(serde_json::json!({})))
}

/// `POST /sign/init` — Start a threshold signing ceremony.
pub async fn handle_sign_init(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SignInitRequest>,
) -> impl IntoResponse {
    todo!(
        "1. Verify BRC-31 auth, check agent owns the share\n\
         2. Load share: storage.read().get_share(&body.agent_id)\n\
         3. Parse sighash: hex::decode(&body.sighash), verify 32 bytes\n\
         4. If use_presignature:\n\
              a. Try storage.write().consume_presignature(&body.agent_id)\n\
              b. If Some(presig): create online signing coordinator (1 round)\n\
              c. If None: fall back to full protocol (4 rounds)\n\
         5. Else: create full signing coordinator\n\
         6. Generate round 1 message\n\
         7. Persist signing state\n\
         8. Return SignInitResponse"
    );

    #[allow(unreachable_code)]
    (StatusCode::OK, Json(serde_json::json!({})))
}

/// `POST /sign/round` — Process a signing round message.
pub async fn handle_sign_round(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SignRoundRequest>,
) -> impl IntoResponse {
    todo!(
        "1. Verify BRC-31 auth\n\
         2. Load signing state\n\
         3. Process round message\n\
         4. If complete:\n\
              a. Extract signature (DER, r, s, recovery_id)\n\
              b. Generate participation proof\n\
              c. Clean up signing state\n\
              d. Return SignRoundResponse {{ complete: true, signature: Some(...) }}\n\
         5. Else:\n\
              a. Generate next round message\n\
              b. Persist updated state\n\
              c. Return SignRoundResponse {{ round_message: Some(...), complete: false }}"
    );

    #[allow(unreachable_code)]
    (StatusCode::OK, Json(serde_json::json!({})))
}

/// `POST /presign/init` — Start a presigning batch.
pub async fn handle_presign_init(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PresignInitRequest>,
) -> impl IntoResponse {
    todo!(
        "1. Verify BRC-31 auth\n\
         2. Validate count <= 100\n\
         3. Load share\n\
         4. Create presigning coordinators (one per requested presig)\n\
         5. Generate round 1 messages for each\n\
         6. Persist coordinator states\n\
         7. Return PresignInitResponse"
    );

    #[allow(unreachable_code)]
    (StatusCode::OK, Json(serde_json::json!({})))
}

/// `POST /presign/round` — Process a presigning round.
pub async fn handle_presign_round(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PresignRoundRequest>,
) -> impl IntoResponse {
    todo!(
        "1. Verify BRC-31 auth\n\
         2. Load presigning coordinator states\n\
         3. Process round messages for each coordinator\n\
         4. If all complete:\n\
              a. Store completed presignatures\n\
              b. Clean up intermediate state\n\
              c. Return PresignRoundResponse {{ complete: true, presignatures_generated: Some(n) }}\n\
         5. Else:\n\
              a. Generate next round messages\n\
              b. Persist updated states\n\
              c. Return PresignRoundResponse {{ round_messages: Some(...), complete: false }}"
    );

    #[allow(unreachable_code)]
    (StatusCode::OK, Json(serde_json::json!({})))
}

/// `GET /health` — Liveness check with operational metrics.
pub async fn handle_health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let uptime = chrono::Utc::now()
        .signed_duration_since(state.started_at)
        .num_seconds();

    let response = HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        share_count: 0, // TODO: state.storage.read().share_count().unwrap_or(0)
        total_presignatures: 0, // TODO: sum across all agents
        uptime_seconds: uptime,
        data_dir: state.data_dir.clone(),
    };

    (StatusCode::OK, Json(response))
}

/// `GET /shares/:agent_id` — Get share metadata (no secrets).
pub async fn handle_get_share_metadata(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    todo!(
        "1. Verify BRC-31 auth, check requester == agent_id\n\
         2. storage.read().get_share_metadata(&agent_id)\n\
         3. Return 200 with ShareMetadata or 404 if not found"
    );

    #[allow(unreachable_code)]
    (StatusCode::OK, Json(serde_json::json!({})))
}

/// `POST /.well-known/auth` — BRC-31 Authrite handshake.
///
/// Mutual authentication key exchange. The client sends its identity key and
/// nonce; the server responds with its own identity key and nonce.
pub async fn handle_authrite(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    todo!(
        "1. Extract client identityKey and nonce from body\n\
         2. Generate server nonce (32 bytes, crypto random)\n\
         3. Store auth session: (client_key, client_nonce, server_nonce, timestamp)\n\
         4. Return {{ identityKey: server_key, nonce: server_nonce, certificates: [] }}"
    );

    #[allow(unreachable_code)]
    (StatusCode::OK, Json(serde_json::json!({})))
}
