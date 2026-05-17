//! Axum request handlers for the self-hosted MPC Key Share Service.
//!
//! These handlers are functionally identical to the CF Worker handlers in
//! `bsv-mpc-worker::api`, but use axum extractors instead of `worker::Request`
//! and local storage instead of Durable Object SQLite.
//!
//! ## Shared Protocol Logic
//!
//! Both the Worker and self-hosted versions delegate to `bsv-mpc-core` for
//! the actual MPC protocol logic. The only differences are:
//!
//! 1. **Storage backend**: In-memory HashMap (production: local SQLite) vs DO SQLite
//! 2. **HTTP framework**: axum vs `worker` crate
//! 3. **State management**: `Arc<AppState>` with `RwLock` vs global statics

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use bsv_mpc_core::dkg::{DkgCoordinator, DkgRoundResult};
use bsv_mpc_core::presigning::{PresigningManager, PresigningRoundResult};
use bsv_mpc_core::signing::{SigningCoordinator, SigningRoundResult};
use bsv_mpc_core::types::{RoundMessage, SessionId, ShareIndex, ThresholdConfig};
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::AppState;

// ── Live Coordinator State ────────────────────────────────────────────────
//
// Same pattern as bsv-mpc-worker: coordinators contain threads and channels,
// so they're kept alive in memory between requests.

/// Wrapper to hold live coordinator sessions.
/// In production, these could be stored in AppState or use a session manager.
struct CoordinatorStore {
    dkg: HashMap<String, DkgCoordinator>,
    signing: HashMap<String, SigningCoordinator>,
    presigning: HashMap<String, PresigningManager>,
}

static COORDINATOR_STORE: std::sync::LazyLock<Mutex<CoordinatorStore>> =
    std::sync::LazyLock::new(|| {
        Mutex::new(CoordinatorStore {
            dkg: HashMap::new(),
            signing: HashMap::new(),
            presigning: HashMap::new(),
        })
    });

// ── Request / Response Types ──────────────────────────────────────────────
//
// These mirror the types in bsv-mpc-worker::api. In a future refactor, these
// could be extracted into a shared crate (bsv-mpc-api-types) to eliminate
// duplication. For now, they are duplicated to keep the crates independent.

/// Request body for `POST /dkg/init`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
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
#[allow(dead_code)]
pub struct SignInitRequest {
    /// Agent requesting signing.
    pub agent_id: String,
    /// MPC session ID from DKG.
    pub session_id: String,
    /// Sighash to sign (32 bytes, hex).
    pub sighash: String,
    /// Whether to consume a presignature for single-round signing.
    pub use_presignature: bool,
    /// Optional BRC-42 HMAC offset for derived key signing (32 bytes, hex).
    /// When set, the signing produces a signature for the derived child key
    /// (root_pub + G * offset) rather than the root key.
    #[serde(default)]
    pub hmac_offset: Option<String>,
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
#[allow(dead_code)]
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

/// Request body for `POST /ecdh`.
#[derive(Debug, Deserialize)]
pub struct EcdhRequest {
    /// The agent requesting the partial ECDH (must own the share).
    pub agent_id: String,
    /// The counterparty public key (33-byte hex compressed secp256k1).
    pub counterparty_pub: String,
}

/// Response from `POST /ecdh`.
#[derive(Debug, Serialize)]
pub struct EcdhResponse {
    /// The partial ECDH result: counterparty_pub * share_scalar (33-byte hex).
    pub partial: String,
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

// ── Helpers ───────────────────────────────────────────────────────────────

/// Generate a unique session ID with the given prefix.
fn generate_session_id(prefix: &str) -> Result<String, String> {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).map_err(|e| format!("entropy error: {e}"))?;
    let hash = sha2::Sha256::digest(buf);
    Ok(format!("{}-{}", prefix, hex::encode(&hash[..16])))
}

/// Helper to create a typed error response.
fn err_response(
    status: StatusCode,
    msg: impl std::fmt::Display,
) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({"error": msg.to_string()})))
}

/// Bundle multiple outgoing RoundMessages into a single transport RoundMessage.
fn bundle_outgoing_messages(messages: &[RoundMessage]) -> Result<RoundMessage, String> {
    if messages.is_empty() {
        return Err("no outgoing messages to bundle".to_string());
    }

    let values: Vec<serde_json::Value> = messages
        .iter()
        .map(|m| {
            serde_json::from_slice(&m.payload)
                .map_err(|e| format!("failed to parse wire message: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let bundled_payload = serde_json::to_vec(&values)
        .map_err(|e| format!("failed to serialize bundled messages: {e}"))?;

    let first = &messages[0];
    Ok(RoundMessage {
        session_id: first.session_id.clone(),
        round: first.round,
        from: first.from,
        to: None,
        payload: bundled_payload,
    })
}

// ── Handlers ──────────────────────────────────────────────────────────────

/// `POST /dkg/init` — Start a Distributed Key Generation ceremony.
pub async fn handle_dkg_init(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DkgInitRequest>,
) -> impl IntoResponse {
    // TODO: Verify BRC-31 auth
    let config = match ThresholdConfig::new(body.config.threshold, body.config.parties) {
        Ok(c) => c,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, e),
    };

    let session_id_str = match generate_session_id("dkg") {
        Ok(id) => id,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    let session_id = SessionId(session_id_str.clone());
    let mut coordinator = DkgCoordinator::new(session_id, config, ShareIndex(0));

    let messages = match coordinator.init() {
        Ok(msgs) => msgs,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    let round_message = match bundle_outgoing_messages(&messages) {
        Ok(rm) => rm,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    if let Ok(mut store) = COORDINATOR_STORE.lock() {
        store.dkg.insert(session_id_str.clone(), coordinator);
    }

    let _ = state; // AppState available for future use
    (StatusCode::OK, Json(serde_json::to_value(DkgInitResponse {
        session_id: session_id_str,
        round_message,
        total_rounds: 4,
    }).unwrap_or_default()))
}

/// `POST /dkg/round` — Process a DKG round message.
pub async fn handle_dkg_round(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DkgRoundRequest>,
) -> impl IntoResponse {
    // Pass the bundled message directly — the SM thread handles unbundling
    // JSON array payloads internally (same pattern as signing).
    let incoming = vec![body.round_message];

    let result = {
        let mut store = match COORDINATOR_STORE.lock() {
            Ok(s) => s,
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        };

        let coordinator = match store.dkg.get_mut(&body.session_id) {
            Some(c) => c,
            None => return err_response(StatusCode::NOT_FOUND, format!("DKG session not found: {}", body.session_id)),
        };

        match coordinator.process_round(incoming) {
            Ok(r) => r,
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        }
    };

    match result {
        DkgRoundResult::NextRound(messages) => {
            let round_message = match bundle_outgoing_messages(&messages) {
                Ok(rm) => rm,
                Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
            };
            (StatusCode::OK, Json(serde_json::to_value(DkgRoundResponse {
                session_id: body.session_id,
                round_message: Some(round_message),
                complete: false,
                joint_pubkey: None,
            }).unwrap_or_default()))
        }
        DkgRoundResult::Complete(dkg_result) => {
            // Store share
            if let Ok(mut storage) = state.storage.write() {
                let _ = storage.store_share(&dkg_result.session_id.0, &dkg_result.share);
            }
            // Clean up coordinator
            if let Ok(mut store) = COORDINATOR_STORE.lock() {
                store.dkg.remove(&body.session_id);
            }
            (StatusCode::OK, Json(serde_json::to_value(DkgRoundResponse {
                session_id: dkg_result.session_id.0.clone(),
                round_message: None,
                complete: true,
                joint_pubkey: Some(dkg_result.joint_key),
            }).unwrap_or_default()))
        }
    }
}

/// `POST /sign/init` — Start a threshold signing ceremony.
pub async fn handle_sign_init(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SignInitRequest>,
) -> impl IntoResponse {
    let share = match state.storage.read() {
        Ok(storage) => match storage.get_share(&body.agent_id) {
            Ok(Some(s)) => s,
            Ok(None) => return err_response(StatusCode::NOT_FOUND, format!("No share for agent: {}", body.agent_id)),
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        },
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    let sighash_bytes = match hex::decode(&body.sighash) {
        Ok(b) => b,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, format!("invalid sighash hex: {e}")),
    };
    if sighash_bytes.len() != 32 {
        return err_response(StatusCode::BAD_REQUEST, format!("sighash must be 32 bytes, got {}", sighash_bytes.len()));
    }
    let mut sighash = [0u8; 32];
    sighash.copy_from_slice(&sighash_bytes);

    let signing_session_id = match generate_session_id("sign") {
        Ok(id) => id,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    // Parse optional BRC-42 HMAC offset for derived key signing
    let hmac_offset: Option<[u8; 32]> = match &body.hmac_offset {
        Some(hex_str) => {
            let bytes = match hex::decode(hex_str) {
                Ok(b) => b,
                Err(e) => return err_response(StatusCode::BAD_REQUEST, format!("invalid hmac_offset hex: {e}")),
            };
            if bytes.len() != 32 {
                return err_response(StatusCode::BAD_REQUEST, format!("hmac_offset must be 32 bytes, got {}", bytes.len()));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(arr)
        }
        None => None,
    };

    let session_id = SessionId(body.session_id);
    let config = share.config;
    let participants: Vec<u16> = (0..config.parties).collect();
    let mut coordinator = SigningCoordinator::new(session_id, share, config, participants);

    let messages = match coordinator.sign(&sighash, None, hmac_offset) {
        Ok(msgs) => msgs,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    let round_message = match bundle_outgoing_messages(&messages) {
        Ok(rm) => rm,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    if let Ok(mut store) = COORDINATOR_STORE.lock() {
        store.signing.insert(signing_session_id.clone(), coordinator);
    }

    (StatusCode::OK, Json(serde_json::to_value(SignInitResponse {
        signing_session_id,
        round_message,
        using_presignature: false,
        total_rounds: 4,
    }).unwrap_or_default()))
}

/// `POST /sign/round` — Process a signing round message.
pub async fn handle_sign_round(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<SignRoundRequest>,
) -> impl IntoResponse {
    // Pass the bundled message directly to the coordinator — the SM thread
    // handles unbundling JSON array payloads internally via VecDeque buffer.
    let incoming = vec![body.round_message];

    let result = {
        let mut store = match COORDINATOR_STORE.lock() {
            Ok(s) => s,
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        };

        let coordinator = match store.signing.get_mut(&body.signing_session_id) {
            Some(c) => c,
            None => return err_response(StatusCode::NOT_FOUND, format!("Signing session not found: {}", body.signing_session_id)),
        };

        match coordinator.process_round(incoming) {
            Ok(r) => r,
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        }
    };

    match result {
        SigningRoundResult::NextRound(messages) => {
            let round_message = if messages.is_empty() {
                None
            } else {
                Some(bundle_outgoing_messages(&messages).unwrap_or_else(|e| {
                    tracing::warn!("bundle error (non-fatal): {e}");
                    messages.into_iter().next().unwrap()
                }))
            };
            (StatusCode::OK, Json(serde_json::to_value(SignRoundResponse {
                signing_session_id: body.signing_session_id,
                round_message,
                complete: false,
                signature: None,
            }).unwrap_or_default()))
        }
        SigningRoundResult::Complete(signing_result) => {
            if let Ok(mut store) = COORDINATOR_STORE.lock() {
                store.signing.remove(&body.signing_session_id);
            }
            (StatusCode::OK, Json(serde_json::to_value(SignRoundResponse {
                signing_session_id: body.signing_session_id,
                round_message: None,
                complete: true,
                signature: Some(signing_result),
            }).unwrap_or_default()))
        }
    }
}

/// `POST /presign/init` — Start a presigning batch.
pub async fn handle_presign_init(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PresignInitRequest>,
) -> impl IntoResponse {
    if body.count == 0 || body.count > 100 {
        return err_response(StatusCode::BAD_REQUEST, "count must be between 1 and 100");
    }

    let share = match state.storage.read() {
        Ok(storage) => match storage.get_share(&body.agent_id) {
            Ok(Some(s)) => s,
            Ok(None) => return err_response(StatusCode::NOT_FOUND, format!("No share for agent: {}", body.agent_id)),
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        },
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    let presign_session_id = match generate_session_id("presign") {
        Ok(id) => id,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    let session_id = SessionId(body.session_id);
    let participants: Vec<u16> = (0..share.config.parties).collect();
    let mut manager = PresigningManager::new(session_id, share, participants, body.count as usize);

    let messages = match manager.init_generate() {
        Ok(msgs) => msgs,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    if let Ok(mut store) = COORDINATOR_STORE.lock() {
        store.presigning.insert(presign_session_id.clone(), manager);
    }

    (StatusCode::OK, Json(serde_json::to_value(PresignInitResponse {
        presign_session_id,
        round_messages: messages,
        total_rounds: 3,
    }).unwrap_or_default()))
}

/// `POST /presign/round` — Process a presigning round.
pub async fn handle_presign_round(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<PresignRoundRequest>,
) -> impl IntoResponse {
    let result = {
        let mut store = match COORDINATOR_STORE.lock() {
            Ok(s) => s,
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        };

        let manager = match store.presigning.get_mut(&body.presign_session_id) {
            Some(m) => m,
            None => return err_response(StatusCode::NOT_FOUND, format!("Presigning session not found: {}", body.presign_session_id)),
        };

        match manager.process_generate_round(body.round_messages) {
            Ok(r) => r,
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        }
    };

    match result {
        PresigningRoundResult::NextRound(messages) => {
            (StatusCode::OK, Json(serde_json::to_value(PresignRoundResponse {
                presign_session_id: body.presign_session_id,
                round_messages: Some(messages),
                complete: false,
                presignatures_generated: None,
            }).unwrap_or_default()))
        }
        PresigningRoundResult::Complete => {
            if let Ok(mut store) = COORDINATOR_STORE.lock() {
                store.presigning.remove(&body.presign_session_id);
            }
            (StatusCode::OK, Json(serde_json::to_value(PresignRoundResponse {
                presign_session_id: body.presign_session_id,
                round_messages: None,
                complete: true,
                presignatures_generated: Some(1),
            }).unwrap_or_default()))
        }
    }
}

/// `POST /ecdh` — Compute partial ECDH for BRC-42 key derivation.
///
/// Returns `counterparty_pub * share_scalar` for the specified agent's share.
pub async fn handle_ecdh(
    State(state): State<Arc<AppState>>,
    Json(body): Json<EcdhRequest>,
) -> impl IntoResponse {
    // TODO: Verify BRC-31 auth and agent authorization

    // Parse counterparty public key
    let cp_bytes = match hex::decode(&body.counterparty_pub) {
        Ok(b) => b,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, format!("invalid counterparty_pub hex: {e}")),
    };
    let counterparty_pub = match bsv::primitives::ec::PublicKey::from_bytes(&cp_bytes) {
        Ok(pk) => pk,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, format!("invalid counterparty_pub: {e}")),
    };

    // Load the agent's share
    let share = match state.storage.read() {
        Ok(storage) => match storage.get_share(&body.agent_id) {
            Ok(Some(s)) => s,
            Ok(None) => return err_response(StatusCode::NOT_FOUND, format!("No share for agent: {}", body.agent_id)),
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        },
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    // Extract scalar and compute partial ECDH
    let scalar = match bsv_mpc_core::ecdh::parse_share_scalar(&share.ciphertext) {
        Ok(s) => s,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to parse share scalar: {e}")),
    };

    let partial = match bsv_mpc_core::ecdh::compute_partial_ecdh_point(&counterparty_pub, &scalar) {
        Ok(p) => p,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, format!("partial ECDH failed: {e}")),
    };

    (StatusCode::OK, Json(serde_json::to_value(EcdhResponse {
        partial: hex::encode(partial.to_compressed()),
    }).unwrap_or_default()))
}

/// `GET /health` — Liveness check with operational metrics.
pub async fn handle_health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let uptime = chrono::Utc::now()
        .signed_duration_since(state.started_at)
        .num_seconds();

    let (share_count, total_presignatures) = match state.storage.read() {
        Ok(storage) => (
            storage.share_count().unwrap_or(0),
            // Sum presignature counts across all agents
            storage.list_agents().unwrap_or_default().iter()
                .map(|a| storage.presignature_count(a).unwrap_or(0))
                .sum(),
        ),
        Err(_) => (0, 0),
    };

    let response = HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        share_count,
        total_presignatures,
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
    // TODO: Verify BRC-31 auth, check requester == agent_id
    match state.storage.read() {
        Ok(storage) => match storage.get_share_metadata(&agent_id) {
            Ok(Some(metadata)) => (StatusCode::OK, Json(serde_json::to_value(metadata).unwrap_or_default())),
            Ok(None) => err_response(StatusCode::NOT_FOUND, format!("No share for agent: {agent_id}")),
            Err(e) => err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        },
        Err(e) => err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// `POST /.well-known/auth` — BRC-31 Authrite handshake (stub).
pub async fn handle_authrite(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let _client_key = body.get("identityKey").and_then(|v| v.as_str()).unwrap_or("");
    let _client_nonce = body.get("nonce").and_then(|v| v.as_str()).unwrap_or("");

    // TODO: Implement full BRC-31 handshake
    (StatusCode::OK, Json(serde_json::json!({
        "identityKey": "000000000000000000000000000000000000000000000000000000000000000000",
        "nonce": "development-stub-nonce",
        "certificates": []
    })))
}
