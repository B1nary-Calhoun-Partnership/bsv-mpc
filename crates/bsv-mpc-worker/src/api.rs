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

use crate::storage::ShareStorage;

// ── Live Coordinator State ────────────────────────────────────────────────
//
// Protocol coordinators (DKG, signing, presigning) contain threads and channels
// that cannot be serialized. We keep them alive in memory between HTTP requests.
// In production CF Worker, these would use DO WebSocket or deterministic replay
// (see POC 10 in CLAUDE.md).

/// Live DKG coordinators, keyed by DKG session ID.
static DKG_SESSIONS: LazyLock<Mutex<HashMap<String, DkgCoordinator>>> =
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
        session_id: first.session_id.clone(),
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
fn unbundle_incoming_message(
    msg: &RoundMessage,
) -> std::result::Result<Vec<RoundMessage>, String> {
    // Check if payload is a JSON array (bundled format)
    if msg.payload.first() == Some(&b'[') {
        if let Ok(values) = serde_json::from_slice::<Vec<serde_json::Value>>(&msg.payload) {
            return values
                .into_iter()
                .map(|v| {
                    let payload = serde_json::to_vec(&v)
                        .map_err(|e| format!("failed to re-serialize wire message: {e}"))?;
                    Ok(RoundMessage {
                        session_id: msg.session_id.clone(),
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

// ── Handlers ──────────────────────────────────────────────────────────────

/// Handle `POST /dkg/init` — start a Distributed Key Generation ceremony.
///
/// 1. Parse the DKG init request (agent_id, threshold config).
/// 2. Validate the threshold configuration.
/// 3. Create a DKG coordinator for party 0 (KSS is always share index 0).
/// 4. Call `coordinator.init()` to generate round 1 messages.
/// 5. Store the live coordinator in the global session map.
/// 6. Return the bundled round 1 message.
pub async fn handle_dkg_init(mut req: Request, _ctx: &RouteContext<()>) -> Result<Response> {
    // TODO: Verify BRC-31 auth: auth::verify_request(&req)?
    let body: DkgInitRequest = req.json().await?;

    // Validate threshold config
    let config = ThresholdConfig::new(body.config.threshold, body.config.parties)
        .map_err(|e| Error::from(e.to_string()))?;

    // Generate a unique session ID
    let session_id_str = generate_session_id("dkg").map_err(Error::from)?;
    let session_id = SessionId(session_id_str.clone());

    // Create DKG coordinator for party 0 (KSS is always party 0)
    let mut coordinator = DkgCoordinator::new(session_id, config, ShareIndex(0));

    // Initialize — produces round 1 messages (Feldman VSS commitments + ZK proofs)
    let messages = coordinator
        .init()
        .map_err(|e| Error::from(e.to_string()))?;

    // Bundle all round messages into a single transport message
    let round_message = bundle_outgoing_messages(&messages).map_err(Error::from)?;

    // Store the live coordinator for subsequent rounds
    DKG_SESSIONS
        .lock()
        .map_err(|e| Error::from(e.to_string()))?
        .insert(session_id_str.clone(), coordinator);

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
pub async fn handle_dkg_round(mut req: Request, _ctx: &RouteContext<()>) -> Result<Response> {
    // TODO: Verify BRC-31 auth
    let body: DkgRoundRequest = req.json().await?;

    // Unbundle the incoming message
    let incoming = unbundle_incoming_message(&body.round_message).map_err(Error::from)?;

    // Look up and process with the live coordinator
    let result = {
        let mut sessions = DKG_SESSIONS
            .lock()
            .map_err(|e| Error::from(e.to_string()))?;

        let coordinator = sessions
            .get_mut(&body.session_id)
            .ok_or_else(|| Error::from(format!("DKG session not found: {}", body.session_id)))?;

        coordinator
            .process_round(incoming)
            .map_err(|e| Error::from(e.to_string()))?
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
            // Store the encrypted share
            let storage = ShareStorage::new();
            // The agent_id comes from the DKG init request — we need to retrieve it.
            // For now, use the session_id prefix as a workaround.
            // TODO: Store agent_id during DKG init and retrieve it here.
            // For development, we extract it from the share's session_id.
            storage
                .store_share(&dkg_result.session_id.0, &dkg_result.share)
                .map_err(Error::from)?;

            // Clean up the live coordinator
            DKG_SESSIONS
                .lock()
                .map_err(|e| Error::from(e.to_string()))?
                .remove(&body.session_id);

            let response = DkgRoundResponse {
                session_id: dkg_result.session_id.0.clone(),
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
pub async fn handle_sign_init(mut req: Request, _ctx: &RouteContext<()>) -> Result<Response> {
    // TODO: Verify BRC-31 auth and agent authorization
    let body: SignInitRequest = req.json().await?;

    // Load the agent's share
    let storage = ShareStorage::new();
    let share = storage
        .get_share(&body.agent_id)
        .map_err(Error::from)?
        .ok_or_else(|| Error::from(format!("No share found for agent: {}", body.agent_id)))?;

    // Parse and validate the sighash (32 bytes, hex-encoded)
    let sighash_bytes =
        hex::decode(&body.sighash).map_err(|e| Error::from(format!("invalid sighash hex: {e}")))?;
    if sighash_bytes.len() != 32 {
        return Response::error(
            format!(
                "sighash must be 32 bytes, got {}",
                sighash_bytes.len()
            ),
            400,
        );
    }
    let mut sighash = [0u8; 32];
    sighash.copy_from_slice(&sighash_bytes);

    // Generate a signing session ID (distinct from the DKG session)
    let signing_session_id = generate_session_id("sign").map_err(Error::from)?;

    // Create signing coordinator for party 0
    // KSS is party 0, proxy is party 1 — standard 2-of-2 participants
    let session_id = SessionId(body.session_id);
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
pub async fn handle_sign_round(mut req: Request, _ctx: &RouteContext<()>) -> Result<Response> {
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
pub async fn handle_presign_init(mut req: Request, _ctx: &RouteContext<()>) -> Result<Response> {
    // TODO: Verify BRC-31 auth and agent authorization
    let body: PresignInitRequest = req.json().await?;

    if body.count == 0 || body.count > 100 {
        return Response::error("count must be between 1 and 100", 400);
    }

    // Load the agent's share
    let storage = ShareStorage::new();
    let share = storage
        .get_share(&body.agent_id)
        .map_err(Error::from)?
        .ok_or_else(|| Error::from(format!("No share found for agent: {}", body.agent_id)))?;

    let presign_session_id = generate_session_id("presign").map_err(Error::from)?;

    // Create presigning manager for party 0
    let session_id = SessionId(body.session_id);
    let participants: Vec<u16> = (0..share.config.parties).collect();

    let mut manager = PresigningManager::new(
        session_id,
        share,
        participants,
        body.count as usize,
    );

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
pub async fn handle_presign_round(mut req: Request, _ctx: &RouteContext<()>) -> Result<Response> {
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
pub async fn handle_ecdh(mut req: Request, _ctx: &RouteContext<()>) -> Result<Response> {
    // TODO: Verify BRC-31 auth and agent authorization
    let body: EcdhRequest = req.json().await?;

    // Parse the counterparty public key
    let cp_bytes = hex::decode(&body.counterparty_pub)
        .map_err(|e| Error::from(format!("invalid counterparty_pub hex: {e}")))?;
    let counterparty_pub = bsv::primitives::ec::PublicKey::from_bytes(&cp_bytes)
        .map_err(|e| Error::from(format!("invalid counterparty_pub: {e}")))?;

    // Load the agent's share
    let storage = ShareStorage::new();
    let share = storage
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
pub async fn handle_health(_ctx: &RouteContext<()>) -> Result<Response> {
    let storage = ShareStorage::new();

    let share_count = storage.share_count().unwrap_or(0);
    let total_presignatures = storage.total_presignature_count().unwrap_or(0);

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
pub async fn handle_get_share_metadata(
    agent_id: &str,
    _ctx: &RouteContext<()>,
) -> Result<Response> {
    // TODO: Verify BRC-31 auth and check requester == agent_id
    let storage = ShareStorage::new();

    match storage
        .get_share_metadata(agent_id)
        .map_err(Error::from)?
    {
        Some(metadata) => Response::from_json(&metadata),
        None => Response::error(format!("No share found for agent: {agent_id}"), 404),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
            session_id: SessionId("test".to_string()),
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
        assert_eq!(bundled.session_id.0, "test");
        assert_eq!(bundled.round, 1);
        assert_eq!(bundled.from, ShareIndex(0));

        // Payload should be a JSON array with one element
        let values: Vec<serde_json::Value> =
            serde_json::from_slice(&bundled.payload).unwrap();
        assert_eq!(values.len(), 1);
    }

    #[test]
    fn test_bundle_multiple_messages() {
        let make_msg = |sender: u16, is_broadcast: bool| RoundMessage {
            session_id: SessionId("test".to_string()),
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

        let values: Vec<serde_json::Value> =
            serde_json::from_slice(&bundled.payload).unwrap();
        assert_eq!(values.len(), 2);
    }

    #[test]
    fn test_unbundle_bundled_message() {
        let wire1 = serde_json::json!({"sender": 0, "is_broadcast": true, "msg": "hello"});
        let wire2 = serde_json::json!({"sender": 0, "is_broadcast": false, "msg": "world"});
        let bundled_payload = serde_json::to_vec(&vec![wire1, wire2]).unwrap();

        let msg = RoundMessage {
            session_id: SessionId("test".to_string()),
            round: 1,
            from: ShareIndex(0),
            to: None,
            payload: bundled_payload,
        };

        let unbundled = unbundle_incoming_message(&msg).unwrap();
        assert_eq!(unbundled.len(), 2);
        assert_eq!(unbundled[0].session_id.0, "test");
        assert_eq!(unbundled[1].round, 1);
    }

    #[test]
    fn test_unbundle_single_wire_message() {
        let wire = serde_json::json!({"sender": 1, "is_broadcast": true, "msg": "data"});
        let payload = serde_json::to_vec(&wire).unwrap();

        let msg = RoundMessage {
            session_id: SessionId("test".to_string()),
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
            session_id: SessionId("roundtrip".to_string()),
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
