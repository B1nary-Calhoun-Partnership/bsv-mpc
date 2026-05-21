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
    body::Bytes,
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

/// Deserialize the raw request body into the typed request `T`. The handlers now
/// take the body as `Bytes` (not `Json<T>`) so the SAME exact bytes that were
/// canonical-BRC-104-signed by the client are both auth-verified and parsed —
/// `Json` would have consumed/re-buffered the body before auth could see it.
fn parse_body<T: serde::de::DeserializeOwned>(
    body: &Bytes,
) -> Result<T, (StatusCode, Json<serde_json::Value>)> {
    serde_json::from_slice(body).map_err(|e| {
        err_response(
            StatusCode::BAD_REQUEST,
            format!("invalid request body: {e}"),
        )
    })
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

/// Load the agent's share, recovering it from durable custody (#9) on a local
/// cache miss (e.g. after an ephemeral-container restart). Recovery restores
/// BOTH the share and its owner binding (§08.1) into local storage, so a
/// subsequent [`authz_owner`] check enforces the SAME identity as before the
/// restart (call this BEFORE the owner check on a cold cache). Hot path is a
/// pure in-memory read; the custody round-trip only happens on a miss.
async fn load_share_or_recover(
    state: &AppState,
    agent_id: &str,
) -> Result<bsv_mpc_core::types::EncryptedShare, (StatusCode, Json<serde_json::Value>)> {
    // 1. Local cache (hot path).
    match state.storage.read() {
        Ok(s) => match s.get_share(agent_id) {
            Ok(Some(share)) => return Ok(share),
            Ok(None) => {}
            Err(e) => return Err(err_response(StatusCode::INTERNAL_SERVER_ERROR, e)),
        },
        Err(e) => return Err(err_response(StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
    // 2. Durable custody recover (cold path: post-restart) — re-binds the owner.
    if let Some(custody) = &state.custody {
        match custody.get_share(agent_id).await {
            Ok(Some((share, owner))) => {
                if let Ok(mut s) = state.storage.write() {
                    let _ = s.store_share_with_owner(agent_id, &share, &owner);
                }
                return Ok(share);
            }
            Ok(None) => {}
            Err(e) => {
                return Err(err_response(
                    StatusCode::BAD_GATEWAY,
                    format!("custody recover failed: {e}"),
                ))
            }
        }
    }
    Err(err_response(
        StatusCode::NOT_FOUND,
        format!("No share for agent: {agent_id}"),
    ))
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
    raw: Bytes,
) -> impl IntoResponse {
    // §07: authenticate the caller (or allow in dev mode) over the RAW body. The
    // verified identity becomes the share's owner at DKG-complete (§08.1).
    let caller =
        match crate::auth::verify_or_allow("POST", "/dkg/init", &headers, &raw, &state.auth) {
            Ok(id) => id,
            Err(resp) => return resp,
        };
    let body: DkgInitRequest = match parse_body(&raw) {
        Ok(b) => b,
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
    headers: HeaderMap,
    raw: Bytes,
) -> impl IntoResponse {
    // §07.6 defense-in-depth: require a valid BRC-31 session to advance a
    // ceremony (the session id is server-generated + unguessable, but we don't
    // trust that alone). Headers-only — no per-share owner-authz here (the
    // ceremony was owner-bound at /dkg/init). Dev mode allows.
    if let Err(resp) =
        crate::auth::verify_or_allow("POST", "/dkg/round", &headers, &raw, &state.auth)
    {
        return resp;
    }
    let body: DkgRoundRequest = match parse_body(&raw) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    // Pass the bundled message directly — the SM thread handles unbundling
    // JSON array payloads internally (same pattern as signing).
    let incoming = vec![body.round_message];

    let result = {
        let mut store = match COORDINATOR_STORE.lock() {
            Ok(s) => s,
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        };

        let outcome = match store.dkg.get_mut(&body.session_id) {
            Some(s) => s.coordinator.process_round(incoming),
            None => {
                return err_response(
                    StatusCode::NOT_FOUND,
                    format!("DKG session not found: {}", body.session_id),
                )
            }
        };

        match outcome {
            Ok(r) => r,
            Err(e) => {
                // Remove the orphaned coordinator: a ceremony that errors
                // mid-round must not leave stale state that blocks a retry of
                // the same session id or grows unbounded (#7 finding #3).
                store.dkg.remove(&body.session_id);
                return err_response(StatusCode::INTERNAL_SERVER_ERROR, e);
            }
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
            // #9: persist the KEK-wrapped share_A (+ its owner) to durable
            // custody FIRST, fail-closed — a restart must never lose share_A →
            // permanent fund-lock. If custody is configured but the put fails,
            // do NOT finalize the DKG (drop the coordinator; report it) so the
            // operator fixes durability before funding.
            if let Some(custody) = &state.custody {
                if let Err(e) = custody
                    .put_share(&agent_id, &dkg_result.share, &owner_identity)
                    .await
                {
                    if let Ok(mut store) = COORDINATOR_STORE.lock() {
                        store.dkg.remove(&body.session_id);
                    }
                    return err_response(
                        StatusCode::BAD_GATEWAY,
                        format!("durable custody put failed; DKG not finalized: {e}"),
                    );
                }
            }
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
    raw: Bytes,
) -> impl IntoResponse {
    // §07: authenticate over the RAW body. Then recover the share (+owner) from
    // durable custody on a cold-cache miss (#9) BEFORE the §08.1 owner check, so
    // post-restart the authz sees the restored owner binding — never a wide-open
    // share.
    let caller =
        match crate::auth::verify_or_allow("POST", "/sign/init", &headers, &raw, &state.auth) {
            Ok(id) => id,
            Err(resp) => return resp,
        };
    let body: SignInitRequest = match parse_body(&raw) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let share = match load_share_or_recover(&state, &body.agent_id).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if let Some(resp) = authz_owner(&state, &caller, &body.agent_id) {
        return resp;
    }

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
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    raw: Bytes,
) -> impl IntoResponse {
    // §07.6 defense-in-depth: require a valid BRC-31 session (dev mode allows).
    if let Err(resp) =
        crate::auth::verify_or_allow("POST", "/sign/round", &headers, &raw, &state.auth)
    {
        return resp;
    }
    let body: SignRoundRequest = match parse_body(&raw) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    // Pass the bundled message directly to the coordinator — the SM thread
    // handles unbundling JSON array payloads internally via VecDeque buffer.
    let incoming = vec![body.round_message];

    let result = {
        let mut store = match COORDINATOR_STORE.lock() {
            Ok(s) => s,
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        };

        let outcome = match store.signing.get_mut(&body.signing_session_id) {
            Some(c) => c.process_round(incoming),
            None => {
                return err_response(
                    StatusCode::NOT_FOUND,
                    format!("Signing session not found: {}", body.signing_session_id),
                )
            }
        };

        match outcome {
            Ok(r) => r,
            Err(e) => {
                // Remove the orphaned coordinator on a mid-ceremony error so a
                // failed sign doesn't block retry / leak (#7 finding #3).
                store.signing.remove(&body.signing_session_id);
                return err_response(StatusCode::INTERNAL_SERVER_ERROR, e);
            }
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
    raw: Bytes,
) -> impl IntoResponse {
    // §07: authenticate over the RAW body. Recover share (+owner) from durable
    // custody on a cold-cache miss (#9) BEFORE the §08.1 owner check.
    let caller =
        match crate::auth::verify_or_allow("POST", "/presign/init", &headers, &raw, &state.auth) {
            Ok(id) => id,
            Err(resp) => return resp,
        };
    let body: PresignInitRequest = match parse_body(&raw) {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    if body.count == 0 || body.count > 100 {
        return err_response(StatusCode::BAD_REQUEST, "count must be between 1 and 100");
    }

    let share = match load_share_or_recover(&state, &body.agent_id).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if let Some(resp) = authz_owner(&state, &caller, &body.agent_id) {
        return resp;
    }

    let presign_session_id = match generate_session_id("presign") {
        Ok(id) => id,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    // The proxy sends the canonical session_id as 64-char hex; reconstruct the
    // SAME SessionId via from_hex. HARD-ERROR on malformed hex (#7 finding #4):
    // the previous `from_str_hash` fallback silently RE-HASHED a corrupt hex
    // into a *different* SessionId → a divergent cggmp24 ExecutionId → the presig
    // would fail to complete with a confusing "malformed/cheating party" error
    // far from the real cause. A non-hex session_id here is a caller bug; fail
    // loudly at the boundary.
    let session_id = match SessionId::from_hex(&body.session_id) {
        Ok(id) => id,
        Err(e) => {
            return err_response(
                StatusCode::BAD_REQUEST,
                format!(
                    "session_id must be the canonical 64-char hex SessionId (got malformed: {e})"
                ),
            )
        }
    };
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
    headers: HeaderMap,
    raw: Bytes,
) -> impl IntoResponse {
    // §07.6 defense-in-depth: require a valid BRC-31 session (dev mode allows).
    if let Err(resp) =
        crate::auth::verify_or_allow("POST", "/presign/round", &headers, &raw, &state.auth)
    {
        return resp;
    }
    let body: PresignRoundRequest = match parse_body(&raw) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let result = {
        let mut store = match COORDINATOR_STORE.lock() {
            Ok(s) => s,
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e),
        };

        let outcome = match store.presigning.get_mut(&body.presign_session_id) {
            Some(m) => m.process_generate_round(body.round_messages),
            None => {
                return err_response(
                    StatusCode::NOT_FOUND,
                    format!("Presigning session not found: {}", body.presign_session_id),
                )
            }
        };

        match outcome {
            Ok(r) => r,
            Err(e) => {
                // Remove the orphaned manager + its agent mapping on a
                // mid-ceremony error (#7 finding #3).
                store.presigning.remove(&body.presign_session_id);
                store.presign_agent.remove(&body.presign_session_id);
                return err_response(StatusCode::INTERNAL_SERVER_ERROR, e);
            }
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
    raw: Bytes,
) -> impl IntoResponse {
    // §07/§08.1: authenticate (over the RAW body) + owner-gate before the share's
    // scalar is used to compute a partial ECDH point (which would otherwise leak
    // share_A material to any caller).
    let caller = match crate::auth::verify_or_allow("POST", "/ecdh", &headers, &raw, &state.auth) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let body: EcdhRequest = match parse_body(&raw) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    // Recover share (+owner) from durable custody on a cold-cache miss (#9)
    // BEFORE the §08.1 owner check.
    let share = match load_share_or_recover(&state, &body.agent_id).await {
        Ok(s) => s,
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

    // Extract scalar and compute partial ECDH (share recovered/loaded above)
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
    raw: Bytes,
) -> axum::response::Response {
    match crate::auth::handshake(&raw, &state.auth) {
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
