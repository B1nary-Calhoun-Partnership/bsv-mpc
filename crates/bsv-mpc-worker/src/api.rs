//! HTTP handlers for the MPC protocol endpoints.
//!
//! Each handler extracts the JSON request body, delegates to the appropriate
//! `bsv-mpc-core` protocol coordinator, and returns a JSON response.
//!
//! ## Protocol Flow: DKG
//!
//! ```text
//! Proxy (share_B)                  Worker (share_A)
//!     │                                │
//!     │── POST /dkg/init ──────────────►│  Create DKG coordinator
//!     │◄── { round_1_msg } ────────────│  Return round 1 message
//!     │                                │
//!     │── POST /dkg/round { r1 } ──────►│  Process round 1
//!     │◄── { round_2_msg } ────────────│  Return round 2 message
//!     │                                │
//!     │── POST /dkg/round { r2 } ──────►│  Process round 2
//!     │◄── { round_3_msg } ────────────│  Return round 3 message
//!     │                                │
//!     │── POST /dkg/round { r3 } ──────►│  Finalize, store share
//!     │◄── { joint_pubkey } ───────────│  Return joint public key
//! ```
//!
//! ## Protocol Flow: Signing (without presignature, 4 rounds)
//!
//! ```text
//! Proxy (share_B)                  Worker (share_A)
//!     │                                │
//!     │── POST /sign/init { hash } ────►│  Load share, start full signing
//!     │◄── { round_1_msg } ────────────│  Return round 1
//!     │                                │
//!     │── POST /sign/round { r1 } ─────►│  Process round 1
//!     │◄── { round_2_msg } ────────────│  Return round 2
//!     │                                │
//!     │── ... (up to 4 rounds) ... ────►│
//!     │◄── { signature } ──────────────│  Return complete signature
//! ```
//!
//! ## Message Bundling
//!
//! Each protocol round may produce multiple wire messages (broadcast + p2p).
//! For transport between proxy and KSS, all outgoing messages for a round are
//! bundled into a single `RoundMessage` where the payload is a JSON array of
//! individual wire message payloads. The receiving side unbundles before feeding
//! to its coordinator.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use bsv_mpc_core::dkg::{DkgCoordinator, DkgRoundResult};
use bsv_mpc_core::presigning::{PresigningManager, PresigningRoundResult};
use bsv_mpc_core::signing::{SigningCoordinator, SigningRoundResult};
use bsv_mpc_core::types::{RoundMessage, SessionId, ShareIndex, ThresholdConfig};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use worker::*;

use crate::storage::MpcStore;

// ── Live Coordinator State ────────────────────────────────────────────────
//
// Protocol coordinators (DKG, signing, presigning) contain threads and channels
// that cannot be serialized. They are kept alive in these statics between
// requests. On the deployed worker the KSS routes are forwarded to a single
// per-cosigner Durable Object isolate (see `crate::poc::forward_to_cosigner_do`),
// so these statics live in that one DO's isolate and persist across the short
// ceremony (per-session DO pinning) — durable share storage is on DO SQLite.

/// A live DKG ceremony: the coordinator plus the `agent_id` that owns the
/// resulting share (retained from `/dkg/init` so completion stores the share
/// under the correct agent — not the session id).
struct DkgSession {
    coordinator: DkgCoordinator,
    agent_id: String,
    /// BRC-31 identity that ran this DKG — recorded as the share's
    /// `owner_identity` on completion (§08.1 / #5). Empty in unauthenticated
    /// dev mode.
    owner_identity: String,
}

/// Live DKG ceremonies, keyed by DKG session ID.
static DKG_SESSIONS: LazyLock<Mutex<HashMap<String, DkgSession>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Live signing coordinators, keyed by signing session ID.
static SIGNING_SESSIONS: LazyLock<Mutex<HashMap<String, SigningCoordinator>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Live presigning managers, keyed by presigning session ID.
static PRESIGNING_SESSIONS: LazyLock<Mutex<HashMap<String, PresigningManager>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

// ── Request / Response Types ──────────────────────────────────────────────

/// Request body for `POST /dkg/init`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // fields used by serde deserialization + future auth wiring
pub struct DkgInitRequest {
    /// BRC-31 identity key of the requesting agent (33-byte hex).
    pub agent_id: String,
    /// Desired threshold configuration (e.g., 2-of-2).
    pub config: ThresholdConfig,
    /// Optional session label for debugging.
    pub label: Option<String>,
}

/// Response from `POST /dkg/init`.
#[derive(Debug, Serialize)]
pub struct DkgInitResponse {
    /// Temporary session ID for this DKG ceremony (finalized after completion).
    pub session_id: String,
    /// This party's round 1 message (commitments + ZK proofs).
    pub round_message: RoundMessage,
    /// Total number of rounds expected for this DKG protocol.
    pub total_rounds: u8,
}

/// Request body for `POST /dkg/round`.
#[derive(Debug, Deserialize)]
pub struct DkgRoundRequest {
    /// The DKG session ID returned from `/dkg/init`.
    pub session_id: String,
    /// The incoming round message from the other party.
    pub round_message: RoundMessage,
}

/// Response from `POST /dkg/round`.
#[derive(Debug, Serialize)]
pub struct DkgRoundResponse {
    /// The session ID (may be finalized on last round).
    pub session_id: String,
    /// This party's response message, if more rounds remain.
    pub round_message: Option<RoundMessage>,
    /// Whether the DKG ceremony is now complete.
    pub complete: bool,
    /// The joint public key (only present when `complete` is true).
    pub joint_pubkey: Option<bsv_mpc_core::types::JointPublicKey>,
}

/// Request body for `POST /sign/init`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // fields used by serde + future presignature support
pub struct SignInitRequest {
    /// The agent requesting signing (must own the share).
    pub agent_id: String,
    /// The MPC session ID (from DKG completion).
    pub session_id: String,
    /// SHA-256 double hash of the BSV sighash to sign (32 bytes, hex).
    pub sighash: String,
    /// Whether to use a presignature for single-round signing.
    /// If true and no presignature is available, falls back to full protocol.
    pub use_presignature: bool,
}

/// Response from `POST /sign/init`.
#[derive(Debug, Serialize)]
pub struct SignInitResponse {
    /// Signing session identifier (ephemeral, distinct from the DKG session).
    pub signing_session_id: String,
    /// This party's round 1 message for the signing protocol.
    pub round_message: RoundMessage,
    /// Whether a presignature was consumed (single-round path).
    pub using_presignature: bool,
    /// Total rounds expected (1 if using presignature, up to 4 otherwise).
    pub total_rounds: u8,
}

/// Request body for `POST /sign/round`.
#[derive(Debug, Deserialize)]
pub struct SignRoundRequest {
    /// The signing session ID from `/sign/init`.
    pub signing_session_id: String,
    /// The incoming round message from the other party.
    pub round_message: RoundMessage,
}

/// Response from `POST /sign/round`.
#[derive(Debug, Serialize)]
pub struct SignRoundResponse {
    /// The signing session ID.
    pub signing_session_id: String,
    /// This party's response message, if more rounds remain.
    pub round_message: Option<RoundMessage>,
    /// Whether signing is now complete.
    pub complete: bool,
    /// The resulting signature (only present when `complete` is true).
    pub signature: Option<bsv_mpc_core::types::SigningResult>,
}

/// Request body for `POST /presign/init`.
#[derive(Debug, Deserialize)]
pub struct PresignInitRequest {
    /// The agent requesting presigning (must own the share).
    pub agent_id: String,
    /// The MPC session ID (from DKG completion).
    pub session_id: String,
    /// Number of presignatures to generate in this batch.
    pub count: u16,
}

/// Response from `POST /presign/init`.
#[derive(Debug, Serialize)]
pub struct PresignInitResponse {
    /// Presigning session identifier.
    pub presign_session_id: String,
    /// This party's round 1 messages (one per presignature being generated).
    pub round_messages: Vec<RoundMessage>,
    /// Total rounds for the presigning protocol (always 3).
    pub total_rounds: u8,
}

/// Request body for `POST /presign/round`.
#[derive(Debug, Deserialize)]
pub struct PresignRoundRequest {
    /// The presigning session ID from `/presign/init`.
    pub presign_session_id: String,
    /// The incoming round messages from the other party.
    pub round_messages: Vec<RoundMessage>,
}

/// Response from `POST /presign/round`.
#[derive(Debug, Serialize)]
pub struct PresignRoundResponse {
    /// The presigning session ID.
    pub presign_session_id: String,
    /// This party's response messages, if more rounds remain.
    pub round_messages: Option<Vec<RoundMessage>>,
    /// Whether presigning is complete.
    pub complete: bool,
    /// Number of presignatures generated (only present when `complete` is true).
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
    /// The partial ECDH result: counterparty_pub * share_A (33-byte hex).
    pub partial: String,
}

/// Response from `GET /health`.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Service status ("ok" or "degraded").
    pub status: String,
    /// Crate version.
    pub version: String,
    /// Total number of agent shares stored.
    pub share_count: usize,
    /// Total unconsumed presignatures across all agents.
    pub total_presignatures: u64,
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Generate a unique session ID with the given prefix.
///
/// Uses `getrandom` for entropy + SHA-256 for uniform distribution.
/// Format: `{prefix}-{32 hex chars}` (e.g., `dkg-a1b2c3...`).
fn generate_session_id(prefix: &str) -> std::result::Result<String, String> {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).map_err(|e| format!("entropy error: {e}"))?;
    let hash = sha2::Sha256::digest(buf);
    Ok(format!("{}-{}", prefix, hex::encode(&hash[..16])))
}

/// Bundle multiple outgoing `RoundMessage`s into a single `RoundMessage` for transport.
///
/// The payload of the bundled message is a JSON array of the individual wire message
/// payloads. The receiving side calls `unbundle_incoming_message` to recover them.
///
/// This is needed because each coordinator round may produce multiple wire messages
/// (broadcast + p2p), but the HTTP API sends a single `RoundMessage` per round.
fn bundle_outgoing_messages(
    messages: &[RoundMessage],
) -> std::result::Result<RoundMessage, String> {
    if messages.is_empty() {
        return Err("no outgoing messages to bundle".to_string());
    }

    // Parse each payload as JSON Value, then serialize as a JSON array
    let values: Vec<serde_json::Value> = messages
        .iter()
        .map(|m| {
            serde_json::from_slice(&m.payload)
                .map_err(|e| format!("failed to parse wire message for bundling: {e}"))
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

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

/// Unbundle an incoming transport `RoundMessage` back into individual `RoundMessage`s.
///
/// Handles both bundled format (JSON array of wire messages) and single-message
/// format (for backward compatibility).
fn unbundle_incoming_message(msg: &RoundMessage) -> std::result::Result<Vec<RoundMessage>, String> {
    // Check if payload is a JSON array (bundled format)
    if msg.payload.first() == Some(&b'[') {
        if let Ok(values) = serde_json::from_slice::<Vec<serde_json::Value>>(&msg.payload) {
            return values
                .into_iter()
                .map(|v| {
                    let payload = serde_json::to_vec(&v)
                        .map_err(|e| format!("failed to re-serialize wire message: {e}"))?;
                    Ok(RoundMessage {
                        session_id: msg.session_id,
                        round: msg.round,
                        from: msg.from,
                        to: msg.to,
                        payload,
                    })
                })
                .collect();
        }
    }

    // Single wire message (non-bundled): return as-is
    Ok(vec![msg.clone()])
}

// ── Authorization helpers (#5 / §08.1) ─────────────────────────────────────

/// BRC-31 identity-key header (MUST match `auth.rs` `headers::IDENTITY_KEY`).
/// Verified at the Worker entrypoint by `verify_or_allow` before the request is
/// forwarded to this DO, so by the time a handler reads it the value is the
/// authenticated caller (the DO is only reachable via the entrypoint binding).
const AUTH_IDENTITY_HEADER: &str = "x-bsv-auth-identity-key";

/// The authenticated caller's BRC-31 identity (hex), or `None` when absent
/// (unauthenticated dev mode).
fn caller_identity(req: &Request) -> Option<String> {
    req.headers()
        .get(AUTH_IDENTITY_HEADER)
        .ok()
        .flatten()
        .filter(|s| !s.is_empty())
}

/// Enforce that the authenticated caller owns the share it is operating on
/// (§08.1: only the DKG-time identity may sign/ECDH/presign). Returns
/// `Ok(None)` when authorized (or when no owner is bound — a dev/legacy share,
/// where the entrypoint BRC-31 gate still applies), or `Ok(Some(403))` to
/// return when the caller is not the owner — checked BEFORE any share material
/// is used.
fn authz_owner_or_reject(
    caller: Option<&str>,
    store: &dyn MpcStore,
    agent_id: &str,
) -> Result<Option<Response>> {
    let owner = store.get_share_owner(agent_id).map_err(Error::from)?;
    if is_owner_authorized(caller, owner.as_deref()) {
        return Ok(None);
    }
    let who = caller.unwrap_or("<unauthenticated>");
    Ok(Some(Response::error(
        format!("Forbidden: identity {who} is not authorized for this share"),
        403,
    )?))
}

/// Pure authorization decision (§08.1 / #5): a caller is authorized iff there is
/// no bound owner (dev/legacy share — the entrypoint BRC-31 gate still applied)
/// or the caller's identity exactly equals the bound owner.
fn is_owner_authorized(caller: Option<&str>, owner: Option<&str>) -> bool {
    match owner {
        None => true,
        Some(o) => caller == Some(o),
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────

/// Handle `POST /dkg/init` — start a Distributed Key Generation ceremony.
///
/// 1. Parse the DKG init request (agent_id, threshold config).
/// 2. Validate the threshold configuration.
/// 3. Create a DKG coordinator for party 0 (KSS is always share index 0).
/// 4. Call `coordinator.init()` to generate round 1 messages.
/// 5. Store the live coordinator in the global session map.
/// 6. Return the bundled round 1 message.
pub async fn handle_dkg_init(mut req: Request) -> Result<Response> {
    // Capture the authenticated caller (verified at the entrypoint) BEFORE the
    // body consumes `req` — it becomes the share's owner_identity (§08.1 / #5).
    let owner_identity = caller_identity(&req).unwrap_or_default();
    let body: DkgInitRequest = req.json().await?;

    // Validate threshold config
    let config = ThresholdConfig::new(body.config.threshold, body.config.parties)
        .map_err(|e| Error::from(e.to_string()))?;

    // Generate a unique session ID
    let session_id_str = generate_session_id("dkg").map_err(Error::from)?;
    let session_id = SessionId::from_str_hash(&session_id_str);

    // Create DKG coordinator for party 0 (KSS is always party 0)
    let mut coordinator = DkgCoordinator::new(session_id, config, ShareIndex(0));

    // Initialize — produces round 1 messages (Feldman VSS commitments + ZK proofs)
    let messages = coordinator.init().map_err(|e| Error::from(e.to_string()))?;

    // Bundle all round messages into a single transport message
    let round_message = bundle_outgoing_messages(&messages).map_err(Error::from)?;

    // Store the live ceremony (coordinator + owning agent_id) for later rounds.
    DKG_SESSIONS
        .lock()
        .map_err(|e| Error::from(e.to_string()))?
        .insert(
            session_id_str.clone(),
            DkgSession {
                coordinator,
                agent_id: body.agent_id,
                owner_identity,
            },
        );

    let response = DkgInitResponse {
        session_id: session_id_str,
        round_message,
        total_rounds: 4, // CGGMP'24 DKG: keygen (multiple rounds) + aux info (multiple rounds)
    };

    Response::from_json(&response)
}

/// Handle `POST /dkg/round` — process a DKG round message and return the next.
///
/// 1. Parse the DKG round request (session_id, round_message).
/// 2. Look up the live coordinator by session_id.
/// 3. Unbundle incoming messages and feed to the coordinator.
/// 4. If more rounds remain: bundle outgoing messages and return.
/// 5. If DKG is complete: store the encrypted share, clean up, return joint public key.
pub async fn handle_dkg_round(mut req: Request, store: &dyn MpcStore) -> Result<Response> {
    // TODO: Verify BRC-31 auth
    let body: DkgRoundRequest = req.json().await?;

    // Unbundle the incoming message
    let incoming = unbundle_incoming_message(&body.round_message).map_err(Error::from)?;

    // Look up and process with the live coordinator; capture the owning
    // agent_id + owner_identity (§08.1 / #5).
    let (result, agent_id, owner_identity) = {
        let mut sessions = DKG_SESSIONS
            .lock()
            .map_err(|e| Error::from(e.to_string()))?;

        let session = sessions
            .get_mut(&body.session_id)
            .ok_or_else(|| Error::from(format!("DKG session not found: {}", body.session_id)))?;

        let result = session
            .coordinator
            .process_round(incoming)
            .map_err(|e| Error::from(e.to_string()))?;
        (
            result,
            session.agent_id.clone(),
            session.owner_identity.clone(),
        )
    };

    match result {
        DkgRoundResult::NextRound(messages) => {
            let round_message = bundle_outgoing_messages(&messages).map_err(Error::from)?;
            let response = DkgRoundResponse {
                session_id: body.session_id,
                round_message: Some(round_message),
                complete: false,
                joint_pubkey: None,
            };
            Response::from_json(&response)
        }
        DkgRoundResult::Complete(dkg_result) => {
            // Persist the encrypted share under the OWNING agent_id (retained
            // from /dkg/init), recording owner_identity (§08.1 / #5) — to DO
            // SQLite on the deployed worker.
            store
                .store_share_with_owner(&agent_id, &dkg_result.share, &owner_identity)
                .map_err(Error::from)?;

            // Clean up the live coordinator
            DKG_SESSIONS
                .lock()
                .map_err(|e| Error::from(e.to_string()))?
                .remove(&body.session_id);

            let response = DkgRoundResponse {
                session_id: dkg_result.session_id.hex(),
                round_message: None,
                complete: true,
                joint_pubkey: Some(dkg_result.joint_key),
            };
            Response::from_json(&response)
        }
    }
}

/// Handle `POST /sign/init` — start a threshold signing ceremony.
///
/// 1. Parse the signing init request (agent_id, session_id, sighash).
/// 2. Load the agent's encrypted share from storage.
/// 3. Parse and validate the sighash (must be exactly 32 bytes hex).
/// 4. Create a SigningCoordinator for party 0 with participants [0, 1].
/// 5. Call `coordinator.sign()` to generate round 1 messages.
/// 6. Store the live coordinator for subsequent rounds.
/// 7. Return the bundled round 1 message.
pub async fn handle_sign_init(mut req: Request, store: &dyn MpcStore) -> Result<Response> {
    let caller = caller_identity(&req);
    let body: SignInitRequest = req.json().await?;

    // §08.1 / #5: only the share's owner may sign with it — checked BEFORE the
    // share is loaded/used.
    if let Some(resp) = authz_owner_or_reject(caller.as_deref(), store, &body.agent_id)? {
        return Ok(resp);
    }

    // Load the agent's share
    let share = store
        .get_share(&body.agent_id)
        .map_err(Error::from)?
        .ok_or_else(|| Error::from(format!("No share found for agent: {}", body.agent_id)))?;

    // Parse and validate the sighash (32 bytes, hex-encoded)
    let sighash_bytes =
        hex::decode(&body.sighash).map_err(|e| Error::from(format!("invalid sighash hex: {e}")))?;
    if sighash_bytes.len() != 32 {
        return Response::error(
            format!("sighash must be 32 bytes, got {}", sighash_bytes.len()),
            400,
        );
    }
    let mut sighash = [0u8; 32];
    sighash.copy_from_slice(&sighash_bytes);

    // Generate a signing session ID (distinct from the DKG session)
    let signing_session_id = generate_session_id("sign").map_err(Error::from)?;

    // Create signing coordinator for party 0
    // KSS is party 0, proxy is party 1 — standard 2-of-2 participants
    let session_id = SessionId::from_str_hash(&body.session_id);
    let config = share.config;
    let participants: Vec<u16> = (0..config.parties).collect();

    let mut coordinator = SigningCoordinator::new(session_id, share, config, participants);

    // Start signing — produces round 1 messages
    // Note: presignature support is future work (requires cggmp24 feature flag)
    let messages = coordinator
        .sign(&sighash, None, None)
        .map_err(|e| Error::from(e.to_string()))?;

    let round_message = bundle_outgoing_messages(&messages).map_err(Error::from)?;

    // Store the live coordinator
    SIGNING_SESSIONS
        .lock()
        .map_err(|e| Error::from(e.to_string()))?
        .insert(signing_session_id.clone(), coordinator);

    let response = SignInitResponse {
        signing_session_id,
        round_message,
        using_presignature: false, // presigned path not yet implemented
        total_rounds: 4,
    };

    Response::from_json(&response)
}

/// Handle `POST /sign/round` — process a signing round and return the next.
///
/// 1. Parse the signing round request (signing_session_id, round_message).
/// 2. Look up the live signing coordinator.
/// 3. Unbundle incoming messages and feed to the coordinator.
/// 4. If more rounds remain: return the next round's messages.
/// 5. If signing is complete: clean up, return the ECDSA signature.
pub async fn handle_sign_round(mut req: Request) -> Result<Response> {
    // TODO: Verify BRC-31 auth
    let body: SignRoundRequest = req.json().await?;

    let incoming = unbundle_incoming_message(&body.round_message).map_err(Error::from)?;

    let result = {
        let mut sessions = SIGNING_SESSIONS
            .lock()
            .map_err(|e| Error::from(e.to_string()))?;

        let coordinator = sessions.get_mut(&body.signing_session_id).ok_or_else(|| {
            Error::from(format!(
                "Signing session not found: {}",
                body.signing_session_id
            ))
        })?;

        coordinator
            .process_round(incoming)
            .map_err(|e| Error::from(e.to_string()))?
    };

    match result {
        SigningRoundResult::NextRound(messages) => {
            let round_message = bundle_outgoing_messages(&messages).map_err(Error::from)?;
            let response = SignRoundResponse {
                signing_session_id: body.signing_session_id,
                round_message: Some(round_message),
                complete: false,
                signature: None,
            };
            Response::from_json(&response)
        }
        SigningRoundResult::Complete(signing_result) => {
            // Clean up the live coordinator
            SIGNING_SESSIONS
                .lock()
                .map_err(|e| Error::from(e.to_string()))?
                .remove(&body.signing_session_id);

            let response = SignRoundResponse {
                signing_session_id: body.signing_session_id,
                round_message: None,
                complete: true,
                signature: Some(signing_result),
            };
            Response::from_json(&response)
        }
    }
}

/// Handle `POST /presign/init` — start a presigning batch.
///
/// Presignatures are generated during idle time so that online signing can
/// complete in a single round. Currently supports count=1 per batch.
///
/// 1. Parse the presigning init request.
/// 2. Validate count (max 100, currently only count=1 supported).
/// 3. Load the agent's share from storage.
/// 4. Create a PresigningManager and call `init_generate()`.
/// 5. Store the live manager for subsequent rounds.
/// 6. Return the round 1 messages.
pub async fn handle_presign_init(mut req: Request, store: &dyn MpcStore) -> Result<Response> {
    let caller = caller_identity(&req);
    let body: PresignInitRequest = req.json().await?;

    // §08.1 / #5: only the share's owner may presign with it.
    if let Some(resp) = authz_owner_or_reject(caller.as_deref(), store, &body.agent_id)? {
        return Ok(resp);
    }

    if body.count == 0 || body.count > 100 {
        return Response::error("count must be between 1 and 100", 400);
    }

    // Load the agent's share
    let share = store
        .get_share(&body.agent_id)
        .map_err(Error::from)?
        .ok_or_else(|| Error::from(format!("No share found for agent: {}", body.agent_id)))?;

    let presign_session_id = generate_session_id("presign").map_err(Error::from)?;

    // Create presigning manager for party 0
    let session_id = SessionId::from_str_hash(&body.session_id);
    let participants: Vec<u16> = (0..share.config.parties).collect();

    let mut manager = PresigningManager::new(session_id, share, participants, body.count as usize);

    // Start presigning — produces round 1 messages
    let messages = manager
        .init_generate()
        .map_err(|e| Error::from(e.to_string()))?;

    // Store the live manager
    PRESIGNING_SESSIONS
        .lock()
        .map_err(|e| Error::from(e.to_string()))?
        .insert(presign_session_id.clone(), manager);

    let response = PresignInitResponse {
        presign_session_id,
        round_messages: messages,
        total_rounds: 3,
    };

    Response::from_json(&response)
}

/// Handle `POST /presign/round` — process a presigning round.
///
/// 1. Parse the presigning round request.
/// 2. Look up the live presigning manager.
/// 3. Feed incoming messages to the manager.
/// 4. If more rounds remain: return the next round's messages.
/// 5. If complete: the presignature is added to the manager's pool. Clean up.
pub async fn handle_presign_round(mut req: Request) -> Result<Response> {
    // TODO: Verify BRC-31 auth
    let body: PresignRoundRequest = req.json().await?;

    let result = {
        let mut sessions = PRESIGNING_SESSIONS
            .lock()
            .map_err(|e| Error::from(e.to_string()))?;

        let manager = sessions.get_mut(&body.presign_session_id).ok_or_else(|| {
            Error::from(format!(
                "Presigning session not found: {}",
                body.presign_session_id
            ))
        })?;

        manager
            .process_generate_round(body.round_messages)
            .map_err(|e| Error::from(e.to_string()))?
    };

    match result {
        PresigningRoundResult::NextRound(messages) => {
            let response = PresignRoundResponse {
                presign_session_id: body.presign_session_id,
                round_messages: Some(messages),
                complete: false,
                presignatures_generated: None,
            };
            Response::from_json(&response)
        }
        PresigningRoundResult::Complete => {
            // Presignature has been added to the manager's internal pool.
            // Clean up the session (the presignature lives in the manager's pool).
            PRESIGNING_SESSIONS
                .lock()
                .map_err(|e| Error::from(e.to_string()))?
                .remove(&body.presign_session_id);

            let response = PresignRoundResponse {
                presign_session_id: body.presign_session_id,
                round_messages: None,
                complete: true,
                presignatures_generated: Some(1),
            };
            Response::from_json(&response)
        }
    }
}

/// Handle `POST /ecdh` — compute partial ECDH for BRC-42 key derivation.
///
/// The proxy sends a counterparty public key, and the KSS returns the
/// partial ECDH result: `counterparty_pub * share_A`.
///
/// This enables distributed BRC-42 key derivation without reconstructing
/// the private key. Used by encrypt/decrypt/HMAC/getPublicKey for
/// "self" and "other" counterparty types.
///
/// Proven in POC 3 (key derivation) and POC 9 (encrypt/decrypt).
pub async fn handle_ecdh(mut req: Request, store: &dyn MpcStore) -> Result<Response> {
    let caller = caller_identity(&req);
    let body: EcdhRequest = req.json().await?;

    // §08.1 / #5: only the share's owner may run partial ECDH with it.
    if let Some(resp) = authz_owner_or_reject(caller.as_deref(), store, &body.agent_id)? {
        return Ok(resp);
    }

    // Parse the counterparty public key
    let cp_bytes = hex::decode(&body.counterparty_pub)
        .map_err(|e| Error::from(format!("invalid counterparty_pub hex: {e}")))?;
    let counterparty_pub = bsv::primitives::ec::PublicKey::from_bytes(&cp_bytes)
        .map_err(|e| Error::from(format!("invalid counterparty_pub: {e}")))?;

    // Load the agent's share
    let share = store
        .get_share(&body.agent_id)
        .map_err(Error::from)?
        .ok_or_else(|| Error::from(format!("No share found for agent: {}", body.agent_id)))?;

    // Extract the share scalar
    let scalar = bsv_mpc_core::ecdh::parse_share_scalar(&share.ciphertext)
        .map_err(|e| Error::from(e.to_string()))?;

    // Compute partial ECDH: counterparty_pub * share_scalar
    let partial = bsv_mpc_core::ecdh::compute_partial_ecdh_point(&counterparty_pub, &scalar)
        .map_err(|e| Error::from(e.to_string()))?;

    let response = EcdhResponse {
        partial: hex::encode(partial.to_compressed()),
    };

    Response::from_json(&response)
}

/// Handle `GET /health` — liveness check with operational metrics.
///
/// No authentication required. Returns service status, version, share count,
/// and total presignature inventory.
pub async fn handle_health(store: &dyn MpcStore) -> Result<Response> {
    let share_count = store.share_count().unwrap_or(0);
    let total_presignatures = store.total_presignature_count().unwrap_or(0);

    let response = HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        share_count,
        total_presignatures,
    };

    Response::from_json(&response)
}

/// Handle `GET /shares/:agent_id` — get share metadata (no secrets).
///
/// Returns session ID, share index, threshold config, timestamps, and
/// presignature count. Never exposes the encrypted share data itself.
pub async fn handle_get_share_metadata(agent_id: &str, store: &dyn MpcStore) -> Result<Response> {
    // TODO: Verify BRC-31 auth and check requester == agent_id
    match store.get_share_metadata(agent_id).map_err(Error::from)? {
        Some(metadata) => Response::from_json(&metadata),
        None => Response::error(format!("No share found for agent: {agent_id}"), 404),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authz_owner_match_is_authorized() {
        // §08.1 / #5: the bound owner is authorized.
        assert!(is_owner_authorized(Some("02abc"), Some("02abc")));
    }

    #[test]
    fn authz_stranger_is_rejected() {
        // A different authenticated identity must NOT sign with someone else's share.
        assert!(!is_owner_authorized(Some("02deadbeef"), Some("02abc")));
    }

    #[test]
    fn authz_unauthenticated_rejected_when_owner_bound() {
        // No caller identity but a bound owner → reject.
        assert!(!is_owner_authorized(None, Some("02abc")));
    }

    #[test]
    fn authz_no_owner_bound_is_allowed() {
        // Dev/legacy share with no bound owner — entrypoint BRC-31 gate still
        // applies; handler authz is a no-op.
        assert!(is_owner_authorized(Some("02abc"), None));
        assert!(is_owner_authorized(None, None));
    }

    #[test]
    fn test_generate_session_id() {
        let id1 = generate_session_id("dkg").unwrap();
        let id2 = generate_session_id("dkg").unwrap();
        assert!(id1.starts_with("dkg-"));
        assert!(id2.starts_with("dkg-"));
        assert_ne!(id1, id2); // should be unique
        assert_eq!(id1.len(), 4 + 32); // "dkg-" + 32 hex chars
    }

    #[test]
    fn test_generate_session_id_prefixes() {
        let dkg_id = generate_session_id("dkg").unwrap();
        let sign_id = generate_session_id("sign").unwrap();
        let presign_id = generate_session_id("presign").unwrap();
        assert!(dkg_id.starts_with("dkg-"));
        assert!(sign_id.starts_with("sign-"));
        assert!(presign_id.starts_with("presign-"));
    }

    #[test]
    fn test_bundle_single_message() {
        let msg = RoundMessage {
            session_id: SessionId::from_str_hash("test"),
            round: 1,
            from: ShareIndex(0),
            to: None,
            payload: serde_json::to_vec(&serde_json::json!({
                "sender": 0,
                "is_broadcast": true,
                "msg": {"data": "test"}
            }))
            .unwrap(),
        };

        let bundled = bundle_outgoing_messages(&[msg]).unwrap();
        assert_eq!(bundled.session_id, SessionId::from_str_hash("test"));
        assert_eq!(bundled.round, 1);
        assert_eq!(bundled.from, ShareIndex(0));

        // Payload should be a JSON array with one element
        let values: Vec<serde_json::Value> = serde_json::from_slice(&bundled.payload).unwrap();
        assert_eq!(values.len(), 1);
    }

    #[test]
    fn test_bundle_multiple_messages() {
        let make_msg = |sender: u16, is_broadcast: bool| RoundMessage {
            session_id: SessionId::from_str_hash("test"),
            round: 2,
            from: ShareIndex(sender),
            to: None,
            payload: serde_json::to_vec(&serde_json::json!({
                "sender": sender,
                "is_broadcast": is_broadcast,
                "msg": {"round": 2}
            }))
            .unwrap(),
        };

        let msgs = vec![make_msg(0, true), make_msg(0, false)];
        let bundled = bundle_outgoing_messages(&msgs).unwrap();

        let values: Vec<serde_json::Value> = serde_json::from_slice(&bundled.payload).unwrap();
        assert_eq!(values.len(), 2);
    }

    #[test]
    fn test_unbundle_bundled_message() {
        let wire1 = serde_json::json!({"sender": 0, "is_broadcast": true, "msg": "hello"});
        let wire2 = serde_json::json!({"sender": 0, "is_broadcast": false, "msg": "world"});
        let bundled_payload = serde_json::to_vec(&vec![wire1, wire2]).unwrap();

        let msg = RoundMessage {
            session_id: SessionId::from_str_hash("test"),
            round: 1,
            from: ShareIndex(0),
            to: None,
            payload: bundled_payload,
        };

        let unbundled = unbundle_incoming_message(&msg).unwrap();
        assert_eq!(unbundled.len(), 2);
        assert_eq!(unbundled[0].session_id, SessionId::from_str_hash("test"));
        assert_eq!(unbundled[1].round, 1);
    }

    #[test]
    fn test_unbundle_single_wire_message() {
        let wire = serde_json::json!({"sender": 1, "is_broadcast": true, "msg": "data"});
        let payload = serde_json::to_vec(&wire).unwrap();

        let msg = RoundMessage {
            session_id: SessionId::from_str_hash("test"),
            round: 3,
            from: ShareIndex(1),
            to: None,
            payload,
        };

        let unbundled = unbundle_incoming_message(&msg).unwrap();
        assert_eq!(unbundled.len(), 1); // treated as single message
    }

    #[test]
    fn test_bundle_unbundle_roundtrip() {
        let make_msg = |data: &str| RoundMessage {
            session_id: SessionId::from_str_hash("roundtrip"),
            round: 1,
            from: ShareIndex(0),
            to: None,
            payload: serde_json::to_vec(&serde_json::json!({
                "sender": 0,
                "is_broadcast": true,
                "msg": data
            }))
            .unwrap(),
        };

        let original = vec![make_msg("alpha"), make_msg("beta")];
        let bundled = bundle_outgoing_messages(&original).unwrap();
        let unbundled = unbundle_incoming_message(&bundled).unwrap();

        assert_eq!(unbundled.len(), 2);

        // Verify payloads are identical
        for (orig, recovered) in original.iter().zip(unbundled.iter()) {
            let orig_val: serde_json::Value = serde_json::from_slice(&orig.payload).unwrap();
            let recovered_val: serde_json::Value =
                serde_json::from_slice(&recovered.payload).unwrap();
            assert_eq!(orig_val, recovered_val);
        }
    }

    #[test]
    fn test_bundle_empty_returns_error() {
        let result = bundle_outgoing_messages(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_health_response_shape() {
        let response = HealthResponse {
            status: "ok".to_string(),
            version: "0.1.0".to_string(),
            share_count: 5,
            total_presignatures: 42,
        };

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["version"], "0.1.0");
        assert_eq!(json["share_count"], 5);
        assert_eq!(json["total_presignatures"], 42);
    }
}
