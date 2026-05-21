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
    http::{HeaderMap, StatusCode},
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

/// A live DKG ceremony plus the authenticated identity that initiated it. The
/// `owner_identity` (§08.1) is captured at `/dkg/init` from the verified caller
/// and recorded against the share at DKG-complete, so later `/sign`, `/presign`,
/// `/ecdh` can be gated to that identity.
struct DkgSession {
    coordinator: DkgCoordinator,
    owner_identity: String,
}

/// Wrapper to hold live coordinator sessions.
/// In production, these could be stored in AppState or use a session manager.
struct CoordinatorStore {
    dkg: HashMap<String, DkgSession>,
    signing: HashMap<String, SigningCoordinator>,
    presigning: HashMap<String, PresigningManager>,
    /// presign_session_id → joint-key `agent_id`, so on completion we ship
    /// `Presignature_A` to the DO pool keyed by the right joint key (#7).
    presign_agent: HashMap<String, String>,
}

static COORDINATOR_STORE: std::sync::LazyLock<Mutex<CoordinatorStore>> =
    std::sync::LazyLock::new(|| {
        Mutex::new(CoordinatorStore {
            dkg: HashMap::new(),
            signing: HashMap::new(),
            presigning: HashMap::new(),
            presign_agent: HashMap::new(),
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

/// §08.1 owner-authz: reject (403) unless the authenticated `caller` is the
/// share's recorded owner. Returns `None` when authorized (no bound owner, or
/// caller == owner). The storage lock is read here so the decision is made on
/// the live owner binding before any share material is touched.
fn authz_owner(
    state: &AppState,
    caller: &crate::auth::CallerIdentity,
    agent_id: &str,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let owner = match state.storage.read() {
        Ok(storage) => storage.get_share_owner(agent_id).ok().flatten(),
        Err(e) => {
            return Some(err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("owner lookup failed: {e}"),
            ))
        }
    };
    crate::auth::authz_owner_or_reject(caller.as_opt(), owner.as_deref())
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
        session_id: first.session_id,
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
    headers: HeaderMap,
    Json(body): Json<DkgInitRequest>,
) -> impl IntoResponse {
    // §07: authenticate the caller (or allow in dev mode). The verified identity
    // becomes the share's owner at DKG-complete (§08.1).
    let caller = match crate::auth::verify_or_allow(&headers, &state.auth) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let owner_identity = caller.identity_key.clone();

    let config = match ThresholdConfig::new(body.config.threshold, body.config.parties) {
        Ok(c) => c,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, e),
    };

    let session_id_str = match generate_session_id("dkg") {
        Ok(id) => id,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    let session_id = SessionId::from_str_hash(&session_id_str);
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
        store.dkg.insert(
            session_id_str.clone(),
            DkgSession {
                coordinator,
                owner_identity,
            },
        );
    }

    (
        StatusCode::OK,
        Json(
            serde_json::to_value(DkgInitResponse {
                session_id: session_id_str,
                round_message,
                total_rounds: 4,
            })
            .unwrap_or_default(),
        ),
    )
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

        let session = match store.dkg.get_mut(&body.session_id) {
            Some(s) => s,
            None => {
                return err_response(
                    StatusCode::NOT_FOUND,
                    format!("DKG session not found: {}", body.session_id),
                )
            }
        };

        match session.coordinator.process_round(incoming) {
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
            (
                StatusCode::OK,
                Json(
                    serde_json::to_value(DkgRoundResponse {
                        session_id: body.session_id,
                        round_message: Some(round_message),
                        complete: false,
                        joint_pubkey: None,
                    })
                    .unwrap_or_default(),
                ),
            )
        }
        DkgRoundResult::Complete(dkg_result) => {
            // Store share_A keyed by the JOINT KEY (agent_id) — the stable
            // identifier that /presign/init and /sign/init look it up by
            // (matches the worker DO's keying). Keying by session_id.hex() would
            // make the share unfindable for the subsequent presign ceremony.
            let agent_id = hex::encode(&dkg_result.joint_key.compressed);
            // Recover the DKG-time owner identity captured at /dkg/init (§08.1)
            // and bind it to the share — empty in dev mode (no owner enforced).
            let owner_identity = COORDINATOR_STORE
                .lock()
                .ok()
                .and_then(|s| {
                    s.dkg
                        .get(&body.session_id)
                        .map(|d| d.owner_identity.clone())
                })
                .unwrap_or_default();
            if let Ok(mut storage) = state.storage.write() {
                let _ =
                    storage.store_share_with_owner(&agent_id, &dkg_result.share, &owner_identity);
            }
            // Clean up coordinator
            if let Ok(mut store) = COORDINATOR_STORE.lock() {
                store.dkg.remove(&body.session_id);
            }
            (
                StatusCode::OK,
                Json(
                    serde_json::to_value(DkgRoundResponse {
                        session_id: dkg_result.session_id.hex(),
                        round_message: None,
                        complete: true,
                        joint_pubkey: Some(dkg_result.joint_key),
                    })
                    .unwrap_or_default(),
                ),
            )
        }
    }
}

/// `POST /sign/init` — Start a threshold signing ceremony.
pub async fn handle_sign_init(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<SignInitRequest>,
) -> impl IntoResponse {
    // §07/§08.1: authenticate, then enforce that the caller owns the share —
    // BEFORE any share material is loaded or used.
    let caller = match crate::auth::verify_or_allow(&headers, &state.auth) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    if let Some(resp) = authz_owner(&state, &caller, &body.agent_id) {
        return resp;
    }

    let share = match state.storage.read() {
        Ok(storage) => match storage.get_share(&body.agent_id) {
            Ok(Some(s)) => s,
            Ok(None) => {
                return err_response(
                    StatusCode::NOT_FOUND,
                    format!("No share for agent: {}", body.agent_id),
                )
            }
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        },
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    let sighash_bytes = match hex::decode(&body.sighash) {
        Ok(b) => b,
        Err(e) => {
            return err_response(StatusCode::BAD_REQUEST, format!("invalid sighash hex: {e}"))
        }
    };
    if sighash_bytes.len() != 32 {
        return err_response(
            StatusCode::BAD_REQUEST,
            format!("sighash must be 32 bytes, got {}", sighash_bytes.len()),
        );
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
                Err(e) => {
                    return err_response(
                        StatusCode::BAD_REQUEST,
                        format!("invalid hmac_offset hex: {e}"),
                    )
                }
            };
            if bytes.len() != 32 {
                return err_response(
                    StatusCode::BAD_REQUEST,
                    format!("hmac_offset must be 32 bytes, got {}", bytes.len()),
                );
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(arr)
        }
        None => None,
    };

    let session_id = SessionId::from_str_hash(&body.session_id);
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
        store
            .signing
            .insert(signing_session_id.clone(), coordinator);
    }

    (
        StatusCode::OK,
        Json(
            serde_json::to_value(SignInitResponse {
                signing_session_id,
                round_message,
                using_presignature: false,
                total_rounds: 4,
            })
            .unwrap_or_default(),
        ),
    )
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
            None => {
                return err_response(
                    StatusCode::NOT_FOUND,
                    format!("Signing session not found: {}", body.signing_session_id),
                )
            }
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
            (
                StatusCode::OK,
                Json(
                    serde_json::to_value(SignRoundResponse {
                        signing_session_id: body.signing_session_id,
                        round_message,
                        complete: false,
                        signature: None,
                    })
                    .unwrap_or_default(),
                ),
            )
        }
        SigningRoundResult::Complete(signing_result) => {
            if let Ok(mut store) = COORDINATOR_STORE.lock() {
                store.signing.remove(&body.signing_session_id);
            }
            (
                StatusCode::OK,
                Json(
                    serde_json::to_value(SignRoundResponse {
                        signing_session_id: body.signing_session_id,
                        round_message: None,
                        complete: true,
                        signature: Some(signing_result),
                    })
                    .unwrap_or_default(),
                ),
            )
        }
    }
}

/// `POST /presign/init` — Start a presigning batch.
pub async fn handle_presign_init(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<PresignInitRequest>,
) -> impl IntoResponse {
    // §07/§08.1: authenticate + owner-gate before loading the share.
    let caller = match crate::auth::verify_or_allow(&headers, &state.auth) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    if let Some(resp) = authz_owner(&state, &caller, &body.agent_id) {
        return resp;
    }

    if body.count == 0 || body.count > 100 {
        return err_response(StatusCode::BAD_REQUEST, "count must be between 1 and 100");
    }

    let share = match state.storage.read() {
        Ok(storage) => match storage.get_share(&body.agent_id) {
            Ok(Some(s)) => s,
            Ok(None) => {
                return err_response(
                    StatusCode::NOT_FOUND,
                    format!("No share for agent: {}", body.agent_id),
                )
            }
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        },
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    let presign_session_id = match generate_session_id("presign") {
        Ok(id) => id,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    // The proxy sends the canonical session_id as hex; reconstruct the SAME
    // SessionId (NOT from_str_hash, which would re-hash the hex and yield a
    // different cggmp24 ExecutionId → presig fails to complete). Fall back to
    // from_str_hash for any non-hex caller.
    let session_id = SessionId::from_hex(&body.session_id)
        .unwrap_or_else(|_| SessionId::from_str_hash(&body.session_id));
    let participants: Vec<u16> = (0..share.config.parties).collect();
    let mut manager = PresigningManager::new(session_id, share, participants, body.count as usize);

    let messages = match manager.init_generate() {
        Ok(msgs) => msgs,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    if let Ok(mut store) = COORDINATOR_STORE.lock() {
        store.presigning.insert(presign_session_id.clone(), manager);
        // Remember the joint key so on completion we ship Presignature_A to the
        // DO pool keyed by it (#7 pool segregation).
        store
            .presign_agent
            .insert(presign_session_id.clone(), body.agent_id.clone());
    }

    (
        StatusCode::OK,
        Json(
            serde_json::to_value(PresignInitResponse {
                presign_session_id,
                round_messages: messages,
                total_rounds: 3,
            })
            .unwrap_or_default(),
        ),
    )
}

/// `POST /presign/round` — Process a presigning round.
///
/// On completion, if provisioning is configured (#4), this party's freshly
/// generated `Presignature_A` is shipped to the cosigner DO pool **before** the
/// `complete: true` response is returned — so the proxy never adds its
/// correlated `box_B` without the DO already holding `Presignature_A` (FIFO
/// lockstep, fail-closed).
pub async fn handle_presign_round(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PresignRoundRequest>,
) -> impl IntoResponse {
    let result = {
        let mut store = match COORDINATOR_STORE.lock() {
            Ok(s) => s,
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        };

        let manager = match store.presigning.get_mut(&body.presign_session_id) {
            Some(m) => m,
            None => {
                return err_response(
                    StatusCode::NOT_FOUND,
                    format!("Presigning session not found: {}", body.presign_session_id),
                )
            }
        };

        match manager.process_generate_round(body.round_messages) {
            Ok(r) => r,
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        }
    };

    match result {
        PresigningRoundResult::NextRound(messages) => (
            StatusCode::OK,
            Json(
                serde_json::to_value(PresignRoundResponse {
                    presign_session_id: body.presign_session_id,
                    round_messages: Some(messages),
                    complete: false,
                    presignatures_generated: None,
                })
                .unwrap_or_default(),
            ),
        ),
        PresigningRoundResult::Complete => {
            // Extract this party's Presignature_A + the joint key it belongs to
            // (drop the std lock before any await), then remove the spent session.
            let (extracted, agent_id) = {
                let mut store = match COORDINATOR_STORE.lock() {
                    Ok(s) => s,
                    Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
                };
                let taken = store
                    .presigning
                    .get_mut(&body.presign_session_id)
                    .and_then(|m| m.take_raw());
                store.presigning.remove(&body.presign_session_id);
                let agent = store.presign_agent.remove(&body.presign_session_id);
                (taken, agent)
            };

            // Provision to the cosigner DO (only when configured).
            if let Some(prov) = &state.provision {
                let agent_id = match agent_id {
                    Some(a) => a,
                    None => {
                        return err_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "presign session has no recorded joint key (agent_id)".to_string(),
                        )
                    }
                };
                let (meta, raw) = match extracted {
                    Some(pair) => pair,
                    None => {
                        return err_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "presigning completed but no presignature to provision".to_string(),
                        )
                    }
                };
                let presig_json = match bsv_mpc_core::presigning::serialize_party_presignature(raw)
                {
                    Ok(j) => j,
                    Err(e) => {
                        return err_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("serialize Presignature_A: {e}"),
                        )
                    }
                };
                if let Err(e) = prov
                    .ship_presignature(&agent_id, &presig_json, &meta.session_id.hex(), &meta.id)
                    .await
                {
                    return err_response(
                        StatusCode::BAD_GATEWAY,
                        format!("provision Presignature_A to DO failed: {e}"),
                    );
                }
                tracing::info!(presig_id = %meta.id, "provisioned Presignature_A to cosigner DO");
            }

            (
                StatusCode::OK,
                Json(
                    serde_json::to_value(PresignRoundResponse {
                        presign_session_id: body.presign_session_id,
                        round_messages: None,
                        complete: true,
                        presignatures_generated: Some(1),
                    })
                    .unwrap_or_default(),
                ),
            )
        }
    }
}

/// `POST /ecdh` — Compute partial ECDH for BRC-42 key derivation.
///
/// Returns `counterparty_pub * share_scalar` for the specified agent's share.
pub async fn handle_ecdh(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<EcdhRequest>,
) -> impl IntoResponse {
    // §07/§08.1: authenticate + owner-gate before the share's scalar is used to
    // compute a partial ECDH point (which would otherwise leak share_A material
    // to any caller).
    let caller = match crate::auth::verify_or_allow(&headers, &state.auth) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    if let Some(resp) = authz_owner(&state, &caller, &body.agent_id) {
        return resp;
    }

    // Parse counterparty public key
    let cp_bytes = match hex::decode(&body.counterparty_pub) {
        Ok(b) => b,
        Err(e) => {
            return err_response(
                StatusCode::BAD_REQUEST,
                format!("invalid counterparty_pub hex: {e}"),
            )
        }
    };
    let counterparty_pub = match bsv::primitives::ec::PublicKey::from_bytes(&cp_bytes) {
        Ok(pk) => pk,
        Err(e) => {
            return err_response(
                StatusCode::BAD_REQUEST,
                format!("invalid counterparty_pub: {e}"),
            )
        }
    };

    // Load the agent's share
    let share = match state.storage.read() {
        Ok(storage) => match storage.get_share(&body.agent_id) {
            Ok(Some(s)) => s,
            Ok(None) => {
                return err_response(
                    StatusCode::NOT_FOUND,
                    format!("No share for agent: {}", body.agent_id),
                )
            }
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        },
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    // Extract scalar and compute partial ECDH
    let scalar = match bsv_mpc_core::ecdh::parse_share_scalar(&share.ciphertext) {
        Ok(s) => s,
        Err(e) => {
            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to parse share scalar: {e}"),
            )
        }
    };

    let partial = match bsv_mpc_core::ecdh::compute_partial_ecdh_point(&counterparty_pub, &scalar) {
        Ok(p) => p,
        Err(e) => {
            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("partial ECDH failed: {e}"),
            )
        }
    };

    (
        StatusCode::OK,
        Json(
            serde_json::to_value(EcdhResponse {
                partial: hex::encode(partial.to_compressed()),
            })
            .unwrap_or_default(),
        ),
    )
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
            storage
                .list_agents()
                .unwrap_or_default()
                .iter()
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
            Ok(Some(metadata)) => (
                StatusCode::OK,
                Json(serde_json::to_value(metadata).unwrap_or_default()),
            ),
            Ok(None) => err_response(
                StatusCode::NOT_FOUND,
                format!("No share for agent: {agent_id}"),
            ),
            Err(e) => err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        },
        Err(e) => err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// `POST /.well-known/auth` — BRC-31 Authrite handshake (§07).
///
/// In enforced mode (server key configured) this issues a signed InitialResponse
/// and stores the session for subsequent request verification. In dev mode it
/// returns a benign stub (auth is not enforced), preserving prior behavior.
pub async fn handle_authrite(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> axum::response::Response {
    match crate::auth::handshake(&headers, &state.auth) {
        Ok((resp_headers, body)) => {
            let mut hm = HeaderMap::new();
            for (name, value) in resp_headers {
                if let (Ok(n), Ok(v)) = (
                    axum::http::HeaderName::from_bytes(name.as_bytes()),
                    axum::http::HeaderValue::from_str(&value),
                ) {
                    hm.insert(n, v);
                }
            }
            (StatusCode::OK, hm, Json(body)).into_response()
        }
        Err(rejection) => rejection.into_response(),
    }
}
