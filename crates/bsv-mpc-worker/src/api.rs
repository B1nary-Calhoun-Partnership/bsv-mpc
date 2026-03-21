//! HTTP handlers for the MPC protocol endpoints.
//!
//! Each handler extracts the JSON request body, validates BRC-31 authentication,
//! delegates to the appropriate `bsv-mpc-core` protocol function, and returns
//! a JSON response.
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
//! ## Protocol Flow: Signing (with presignature)
//!
//! ```text
//! Proxy (share_B)                  Worker (share_A)
//!     │                                │
//!     │── POST /sign/init { hash } ────►│  Load share + presig
//!     │◄── { round_1_msg } ────────────│  Return online round
//!     │                                │
//!     │── POST /sign/round { r1 } ─────►│  Combine partial sigs
//!     │◄── { signature } ──────────────│  Return complete signature
//! ```
//!
//! ## Protocol Flow: Signing (without presignature)
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

use crate::auth;
use crate::storage::ShareStorage;
use bsv_mpc_core::types::{RoundMessage, SessionId, ThresholdConfig};
use serde::{Deserialize, Serialize};
use worker::*;

// ── Request / Response Types ──────────────────────────────────────────────

/// Request body for `POST /dkg/init`.
#[derive(Debug, Deserialize)]
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

// ── Handlers ──────────────────────────────────────────────────────────────

/// Handle `POST /dkg/init` — start a Distributed Key Generation ceremony.
///
/// 1. Verify BRC-31 auth (only the target agent can initiate DKG for its share).
/// 2. Validate the threshold configuration.
/// 3. Create a DKG coordinator via `bsv_mpc_core::dkg`.
/// 4. Generate this party's round 1 message (Feldman VSS commitments + ZK proof
///    of secret share knowledge).
/// 5. Store intermediate DKG state in the Durable Object.
/// 6. Return the round 1 message to the caller (MPC Proxy).
pub async fn handle_dkg_init(mut req: Request, ctx: &RouteContext<()>) -> Result<Response> {
    todo!(
        "1. auth::verify_request(&req)?\n\
         2. let body: DkgInitRequest = req.json().await?\n\
         3. Validate config: body.config.threshold == 2, body.config.parties == 2\n\
         4. Create DKG coordinator: bsv_mpc_core::dkg::Coordinator::new(body.config)\n\
         5. Generate round 1 message: coordinator.round1()\n\
         6. Serialize coordinator state and store in DO SQLite\n\
         7. Return DkgInitResponse with round_message"
    )
}

/// Handle `POST /dkg/round` — process a DKG round message and return the next.
///
/// 1. Verify BRC-31 auth.
/// 2. Load the DKG coordinator state from the Durable Object.
/// 3. Feed the incoming round message to the coordinator.
/// 4. If more rounds remain, generate the next outgoing message and persist state.
/// 5. If this was the final round, finalize DKG:
///    a. Extract the encrypted key share.
///    b. Compute the session ID (SHA-256 of the DKG transcript).
///    c. Store the encrypted share in the Durable Object.
///    d. Clean up intermediate DKG state.
///    e. Return the joint public key.
pub async fn handle_dkg_round(mut req: Request, ctx: &RouteContext<()>) -> Result<Response> {
    todo!(
        "1. auth::verify_request(&req)?\n\
         2. let body: DkgRoundRequest = req.json().await?\n\
         3. let storage = ShareStorage::new(ctx).await?\n\
         4. Load coordinator state from DO for body.session_id\n\
         5. coordinator.process_round(body.round_message)?\n\
         6. if coordinator.is_complete():\n\
              a. let result = coordinator.finalize()?\n\
              b. storage.store_share(agent_id, &result.share).await?\n\
              c. Return DkgRoundResponse { complete: true, joint_pubkey: Some(result.joint_key) }\n\
         7. else:\n\
              a. let next_msg = coordinator.next_round()?\n\
              b. Persist updated coordinator state\n\
              c. Return DkgRoundResponse { round_message: Some(next_msg), complete: false }"
    )
}

/// Handle `POST /sign/init` — start a threshold signing ceremony.
///
/// 1. Verify BRC-31 auth (only the share owner can request signing).
/// 2. Load the encrypted share from storage.
/// 3. Parse the sighash (must be exactly 32 bytes).
/// 4. If `use_presignature` is true, attempt to consume a presignature.
///    - If available: start single-round online signing.
///    - If not available: fall back to full 4-round protocol.
/// 5. Generate this party's round 1 message.
/// 6. Store the signing coordinator state.
/// 7. Return the round 1 message.
pub async fn handle_sign_init(mut req: Request, ctx: &RouteContext<()>) -> Result<Response> {
    todo!(
        "1. auth::verify_request(&req)?\n\
         2. let body: SignInitRequest = req.json().await?\n\
         3. let storage = ShareStorage::new(ctx).await?\n\
         4. let share = storage.get_share(&body.agent_id).await?\n\
              .ok_or_else(|| Error::from('No share found for agent'))?\n\
         5. let sighash = hex::decode(&body.sighash)?\n\
         6. let presig = if body.use_presignature {\n\
              storage.consume_presignature(&body.agent_id).await?\n\
            } else { None };\n\
         7. Create signing coordinator with share + sighash + optional presig\n\
         8. Generate round 1 message\n\
         9. Store coordinator state\n\
         10. Return SignInitResponse"
    )
}

/// Handle `POST /sign/round` — process a signing round and return the next.
///
/// 1. Verify BRC-31 auth.
/// 2. Load the signing coordinator state.
/// 3. Process the incoming round message.
/// 4. If signing is complete:
///    a. Extract the ECDSA signature (DER, r, s, recovery_id).
///    b. Generate the participation proof.
///    c. Clean up intermediate signing state.
///    d. Return the complete signature.
/// 5. If more rounds remain:
///    a. Generate the next outgoing message.
///    b. Persist updated coordinator state.
///    c. Return the next round message.
pub async fn handle_sign_round(mut req: Request, ctx: &RouteContext<()>) -> Result<Response> {
    todo!(
        "1. auth::verify_request(&req)?\n\
         2. let body: SignRoundRequest = req.json().await?\n\
         3. Load signing coordinator from DO\n\
         4. coordinator.process_round(body.round_message)?\n\
         5. if coordinator.is_complete():\n\
              a. let result = coordinator.finalize()?\n\
              b. Clean up signing state\n\
              c. Return SignRoundResponse { complete: true, signature: Some(result) }\n\
         6. else:\n\
              a. let next_msg = coordinator.next_round()?\n\
              b. Persist updated state\n\
              c. Return SignRoundResponse { round_message: Some(next_msg), complete: false }"
    )
}

/// Handle `POST /presign/init` — start a presigning batch.
///
/// Presignatures are generated during idle time so that online signing can
/// complete in a single round. The 3-round offline presigning protocol
/// generates nonce shares and range proofs.
///
/// 1. Verify BRC-31 auth.
/// 2. Load the encrypted share.
/// 3. Create presigning coordinators (one per requested presignature).
/// 4. Generate round 1 messages for each.
/// 5. Store coordinator state.
/// 6. Return the batch of round 1 messages.
pub async fn handle_presign_init(mut req: Request, ctx: &RouteContext<()>) -> Result<Response> {
    todo!(
        "1. auth::verify_request(&req)?\n\
         2. let body: PresignInitRequest = req.json().await?\n\
         3. Validate body.count <= 100 (prevent abuse)\n\
         4. let storage = ShareStorage::new(ctx).await?\n\
         5. let share = storage.get_share(&body.agent_id).await?\n\
         6. For each presignature in 0..body.count:\n\
              a. Create presigning coordinator\n\
              b. Generate round 1 message\n\
         7. Store all coordinator states\n\
         8. Return PresignInitResponse with round_messages"
    )
}

/// Handle `POST /presign/round` — process a presigning round.
///
/// 1. Verify BRC-31 auth.
/// 2. Load the presigning coordinator states.
/// 3. Process incoming round messages.
/// 4. If the presigning protocol is complete:
///    a. Store the completed presignatures.
///    b. Clean up intermediate state.
///    c. Return the count of presignatures generated.
/// 5. If more rounds remain:
///    a. Generate the next outgoing messages.
///    b. Persist updated coordinator states.
///    c. Return the next round messages.
pub async fn handle_presign_round(mut req: Request, ctx: &RouteContext<()>) -> Result<Response> {
    todo!(
        "1. auth::verify_request(&req)?\n\
         2. let body: PresignRoundRequest = req.json().await?\n\
         3. Load presigning coordinators from DO\n\
         4. For each coordinator:\n\
              a. Process the corresponding round message\n\
         5. if all coordinators complete:\n\
              a. For each completed presignature:\n\
                   store in storage.store_presignature()\n\
              b. Clean up intermediate state\n\
              c. Return PresignRoundResponse { complete: true, presignatures_generated: Some(count) }\n\
         6. else:\n\
              a. Generate next round messages\n\
              b. Persist updated states\n\
              c. Return PresignRoundResponse { round_messages: Some(msgs), complete: false }"
    )
}

/// Handle `GET /health` — liveness check with operational metrics.
///
/// No authentication required. Returns service status, version, share count,
/// and total presignature inventory.
pub async fn handle_health(ctx: &RouteContext<()>) -> Result<Response> {
    todo!(
        "1. let storage = ShareStorage::new(ctx).await?\n\
         2. let share_count = storage.share_count().await?\n\
         3. Return HealthResponse { status: 'ok', version: env!('CARGO_PKG_VERSION'), share_count }"
    )
}

/// Handle `GET /shares/:agent_id` — get share metadata (no secrets).
///
/// Requires BRC-31 auth — only the share owner can query their own metadata.
/// Returns session ID, share index, threshold config, timestamps, and
/// presignature count. Never exposes the encrypted share data itself.
pub async fn handle_get_share_metadata(
    agent_id: &str,
    ctx: &RouteContext<()>,
) -> Result<Response> {
    todo!(
        "1. auth::verify_request (from context)?\n\
         2. Verify authenticated identity matches agent_id\n\
         3. let storage = ShareStorage::new(ctx).await?\n\
         4. let meta = storage.get_share_metadata(agent_id).await?\n\
         5. Return JSON response with ShareMetadata or 404"
    )
}
