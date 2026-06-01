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
    presigning: HashMap<String, PresigningManager>,
    /// presign_session_id → joint-key `agent_id`, so on completion we ship
    /// `Presignature_A` to the DO pool keyed by the right joint key (#7).
    presign_agent: HashMap<String, String>,
}

static COORDINATOR_STORE: std::sync::LazyLock<Mutex<CoordinatorStore>> =
    std::sync::LazyLock::new(|| {
        Mutex::new(CoordinatorStore {
            dkg: HashMap::new(),
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
    // #102: hot cache → durable custody recover (post-restart, re-binds owner) →
    // 404, all through the single `DurableShares` seam.
    match state.shares().load_or_recover(agent_id).await {
        Ok(Some(share)) => Ok(share),
        Ok(None) => Err(err_response(
            StatusCode::NOT_FOUND,
            format!("No share for agent: {agent_id}"),
        )),
        Err(e) => Err(err_response(
            StatusCode::BAD_GATEWAY,
            format!("share load/recover failed: {e}"),
        )),
    }
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

// ── Re-exports for the relay handlers (§06.17.1 CONTAINER target, #30) ──────
//
// `crate::relay_handlers` reuses these internal helpers (same auth/share/parse
// semantics as the HTTP routes). Thin `pub` wrappers keep the helpers private to
// this module while letting the relay routes share the exact decision logic.

/// `pub` wrapper over [`parse_body`] for `crate::relay_handlers`.
pub fn parse_body_pub<T: serde::de::DeserializeOwned>(
    body: &Bytes,
) -> Result<T, (StatusCode, Json<serde_json::Value>)> {
    parse_body(body)
}

/// `pub` wrapper over [`authz_owner`] for `crate::relay_handlers`.
pub fn authz_owner_pub(
    state: &AppState,
    caller: &crate::auth::CallerIdentity,
    agent_id: &str,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    authz_owner(state, caller, agent_id)
}

/// §08.1 owner-authz for a SPECIFIC held index — the n-party device-holds presign
/// (#69/#86), where the share + its owner live at the composite key
/// `{agent_id}#{index}`.
///
/// Checks the composite share's owner first; falls back to the bare-`agent_id`
/// owner (the 2-party deployment). A composite wallet records its owner per held
/// index and leaves the bare key unowned — so checking only the bare key (as the
/// plain [`authz_owner_pub`] does) would let ANY authenticated caller arm a presign
/// on someone else's multi-index wallet (a §08.1 bypass). This closes that.
pub fn authz_owner_at_index_pub(
    state: &AppState,
    caller: &crate::auth::CallerIdentity,
    agent_id: &str,
    index: u16,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let owner = match state.storage.read() {
        Ok(s) => s
            .get_share_owner_at_index(agent_id, index)
            .ok()
            .flatten()
            .or_else(|| s.get_share_owner(agent_id).ok().flatten()),
        Err(e) => {
            return Some(err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("owner lookup failed: {e}"),
            ))
        }
    };
    crate::auth::authz_owner_or_reject(caller.as_opt(), owner.as_deref())
}

/// `pub` wrapper over [`load_share_or_recover`] for `crate::relay_handlers`.
pub async fn load_share_or_recover_pub(
    state: &AppState,
    agent_id: &str,
) -> Result<bsv_mpc_core::types::EncryptedShare, (StatusCode, Json<serde_json::Value>)> {
    load_share_or_recover(state, agent_id).await
}

/// Load the cosigner's share for a SPECIFIC keygen index — the n-party
/// device-holds presign (#69/#86), where one container holds several composite
/// shares `{agent_id}#{index}`.
///
/// Tries the composite key `{agent_id}#{index}` first (the multi-index wallet),
/// then falls back to [`load_share_or_recover`] on the bare `agent_id` (the
/// mainnet-proven 2-party deployment + custody recover). A composite wallet only
/// ever persists composite keys, so the bare fallback never returns a wrong-index
/// share for it; a 2-party wallet has only the bare share, which the fallback finds.
pub async fn load_share_or_recover_at_index_pub(
    state: &AppState,
    agent_id: &str,
    index: u16,
) -> Result<bsv_mpc_core::types::EncryptedShare, (StatusCode, Json<serde_json::Value>)> {
    // FAST PATH (no retry): composite hit (n-party), else bare hit (2-party). The
    // bare read here keeps the 2-party deployed arm BYTE-IDENTICAL — it returns
    // immediately and never spins the retry below (a 2-party wallet has no composite
    // key, so without this it would wait the full retry budget before the fallback).
    if let Ok(s) = state.storage.read() {
        if let Ok(Some(share)) = s.get_share_at_index(agent_id, index) {
            return Ok(share);
        }
        if let Ok(Some(share)) = s.get_share(agent_id) {
            return Ok(share);
        }
    }
    // Neither present yet. An n-party presign armed immediately after provisioning
    // can race the cosigner's DKG persist: `coordinate_dkg_over_relay` returns on the
    // device's own quorum agreement, while the container finishes its DKG SM +
    // persists its composite shares a beat later. Retry ONLY the composite read so the
    // n-party arm doesn't 404 on that window; a genuine miss still falls through to
    // the custody/404 path after the budget. Budget (~15s) comfortably covers the
    // SM-completion lag; the arm's HTTP timeout is far larger.
    const ATTEMPTS: usize = 75;
    for _ in 0..ATTEMPTS {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        if let Ok(s) = state.storage.read() {
            if let Ok(Some(share)) = s.get_share_at_index(agent_id, index) {
                return Ok(share);
            }
        }
    }
    // #102: COMPOSITE durable-custody recovery (post-restart) — the n-party share
    // is custodied keyed by `{agent_id}#{index}`, so recover IT (not the bare key,
    // which for an n-party wallet is absent / a wrong-index share). This closes the
    // 4-of-6 fund-lock-across-redeploy gap.
    match state
        .shares()
        .load_or_recover_at_index(agent_id, index)
        .await
    {
        Ok(Some(share)) => return Ok(share),
        Ok(None) => {}
        Err(e) => {
            return Err(err_response(
                StatusCode::BAD_GATEWAY,
                format!("composite custody recover failed: {e}"),
            ))
        }
    }
    // Bare fallback (the mainnet-proven 2-party deployment + its custody recover).
    load_share_or_recover(state, agent_id).await
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
            // identifier that /presign/init and /sign-relay look it up by
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
            // #9/#102: persist through the durable seam — custody-PUT FIRST
            // (fail-closed), then the hot cache. A restart must never lose share_A →
            // permanent fund-lock. If custody is configured but the put fails, do NOT
            // finalize the DKG (drop the coordinator; report it) so the operator fixes
            // durability before funding. (Same custody-first ordering as before, now
            // through the single `DurableShares` seam shared by every persist path.)
            if let Err(e) = state
                .shares()
                .persist_durable(&agent_id, &dkg_result.share, &owner_identity)
                .await
            {
                if let Ok(mut store) = COORDINATOR_STORE.lock() {
                    store.dkg.remove(&body.session_id);
                }
                return err_response(
                    StatusCode::BAD_GATEWAY,
                    format!("durable persist failed; DKG not finalized: {e}"),
                );
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
        // Live presign runs over the relay (`presign_handler`); this 2-party HTTP
        // `/presign/round` flow is ordered request/response, so the completing drive
        // carries no undelivered final-round messages (the `Complete` payload is empty
        // here) — see the #98 fix in `presigning::PresigningRoundResult`.
        PresigningRoundResult::Complete(_final_msgs) => {
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
    headers: HeaderMap,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    // §07: authenticate the caller (dev mode allows). A GET has no body, so the
    // canonical signed payload is over ("GET", path, b""); the path-param agent_id
    // is part of that signed request path. §08.1: share metadata is owner-only —
    // reject any caller that is not the share's recorded owner (403) BEFORE we
    // reveal whether/what metadata exists. (`handle_dkg_init` + `handle_ecdh` were
    // already gated; this closes the last #81 TODO.)
    let path = format!("/shares/{agent_id}");
    let caller = match crate::auth::verify_or_allow("GET", &path, &headers, b"", &state.auth) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    if let Some(resp) = authz_owner(&state, &caller, &agent_id) {
        return resp;
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthState, CallerIdentity};
    use crate::{AppState, SqliteShareStorage};
    use bsv_mpc_core::types::{EncryptedShare, SessionId, ShareIndex, ThresholdConfig};
    use std::sync::{Arc, RwLock};

    fn caller(id: &str) -> CallerIdentity {
        CallerIdentity {
            identity_key: id.to_string(),
        }
    }

    fn dummy_share(index: u16) -> EncryptedShare {
        EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: vec![1u8; 16],
            session_id: SessionId([0u8; 32]),
            share_index: ShareIndex(index),
            config: ThresholdConfig::new(4, 6).unwrap(),
            joint_pubkey_compressed: vec![2u8; 33],
        }
    }

    fn state_with(storage: SqliteShareStorage) -> Arc<AppState> {
        Arc::new(AppState {
            data_dir: String::new(),
            storage: Arc::new(RwLock::new(storage)),
            started_at: chrono::Utc::now(),
            provision: None,
            auth: AuthState::dev(),
            custody: None,
        })
    }

    /// §08.1 composite owner-authz (#69/#86): the n-party presign arm MUST authorize
    /// against the COMPOSITE share's owner, so a bare-key owner cannot bypass it.
    #[test]
    fn composite_authz_prefers_composite_owner_over_bare() {
        let agent = "02".to_string() + &"aa".repeat(32);
        let mut storage = SqliteShareStorage::open("authz-test-composite").unwrap();
        // n-party wallet: composite share at #3 owned by ALICE. A stray bare owner BOB.
        storage
            .store_share_at_index(&agent, 3, &dummy_share(3), "alice")
            .unwrap();
        storage
            .store_share_with_owner(&agent, &dummy_share(9), "bob")
            .unwrap();
        let state = state_with(storage);

        // ALICE (the composite owner) is authorized for index 3.
        assert!(authz_owner_at_index_pub(&state, &caller("alice"), &agent, 3).is_none());
        // BOB (only the bare owner) is REJECTED for index 3 — the composite owner
        // wins, so the bare key cannot be used to bypass §08.1.
        let rej = authz_owner_at_index_pub(&state, &caller("bob"), &agent, 3)
            .expect("bare owner must NOT authorize a composite index");
        assert_eq!(rej.0, StatusCode::FORBIDDEN);
    }

    /// 2-party back-compat: with no composite key, authz falls back to the bare owner.
    #[test]
    fn composite_authz_falls_back_to_bare_for_2party() {
        let agent = "02".to_string() + &"bb".repeat(32);
        let mut storage = SqliteShareStorage::open("authz-test-2party").unwrap();
        // 2-party wallet: only a bare share, owned by BOB. No composite key.
        storage
            .store_share_with_owner(&agent, &dummy_share(1), "bob")
            .unwrap();
        let state = state_with(storage);

        // BOB (the bare owner) is authorized (composite miss → bare fallback).
        assert!(authz_owner_at_index_pub(&state, &caller("bob"), &agent, 1).is_none());
        // EVE is rejected.
        assert!(authz_owner_at_index_pub(&state, &caller("eve"), &agent, 1).is_some());
    }

    /// REGRESSION: a 2-party wallet (bare share, no composite) MUST load on the fast
    /// path — NOT spin the n-party composite-retry budget (~3s). We bound it well
    /// under that budget to catch the retry leaking into the 2-party deployed arm.
    #[tokio::test]
    async fn load_at_index_2party_bare_is_immediate_no_retry() {
        let agent = "02".to_string() + &"cc".repeat(32);
        let mut storage = SqliteShareStorage::open("load-2party").unwrap();
        storage
            .store_share_with_owner(&agent, &dummy_share(1), "owner")
            .unwrap();
        let state = state_with(storage);

        let got = tokio::time::timeout(
            std::time::Duration::from_millis(800),
            load_share_or_recover_at_index_pub(&state, &agent, 1),
        )
        .await
        .expect("2-party bare load must NOT wait the composite-retry budget");
        assert_eq!(got.expect("bare share loads").share_index.0, 1);
    }

    /// An n-party wallet's composite share loads on the fast path.
    #[tokio::test]
    async fn load_at_index_composite_hits_fast() {
        let agent = "02".to_string() + &"dd".repeat(32);
        let mut storage = SqliteShareStorage::open("load-nparty").unwrap();
        storage
            .store_share_at_index(&agent, 3, &dummy_share(3), "owner")
            .unwrap();
        let state = state_with(storage);
        let got = tokio::time::timeout(
            std::time::Duration::from_millis(800),
            load_share_or_recover_at_index_pub(&state, &agent, 3),
        )
        .await
        .expect("composite load is immediate");
        assert_eq!(got.expect("composite share loads").share_index.0, 3);
    }
}
