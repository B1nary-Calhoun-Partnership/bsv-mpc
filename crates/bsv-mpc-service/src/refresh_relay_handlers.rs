//! §18.2 **container key-refresh over the relay** routes (issue #10, CONTAINER
//! target).
//!
//! The deployed CF Container runs the full native `bsv-mpc-service`, so it can
//! run the distributed PSS refresh ceremony (the worker isolate cannot). These
//! routes arm the container as a refresh peer:
//!
//!   - `GET  /refresh-relay/identity` — the container's relay / BRC-31 identity
//!     hex (so the proxy can register its slot + ship round-1 before arming the
//!     container — the §06.17 ordering invariant, identical to presign).
//!   - `POST /refresh-relay/init` — arm the container as a refresh peer: load its
//!     share, build a [`RefreshHandler`], start a `MessageBoxListener` on
//!     `mpc-refresh`, run `init()`, ship round-1 to the proxy, and spawn a
//!     completion task that **rotates the container's stored share AND purges its
//!     presignatures (§18.9)** the instant the ceremony commits — atomically with
//!     the refresh, so no presig generated against the old share survives the
//!     boundary (this is the container half of #22's ShareRefresh trigger).
//!
//! Owner-authz gated (§08.1); requires an enforced server identity
//! (`MPC_SERVER_PRIVATE_KEY`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use bsv_mpc_core::types::SessionId;
use bsv_mpc_messagebox::types::BOX_REFRESH;
use bsv_mpc_messagebox::MessageBoxClient;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::messagebox::MessageBoxListener;
use crate::refresh_handler::RefreshHandler;
use crate::AppState;

/// Live refresh ceremonies, keyed by `session_id` hex — holds the listener so the
/// background pump (rounds + completion) survives between requests.
struct RefreshCeremonyStore {
    listeners: HashMap<String, MessageBoxListener>,
}

static REFRESH_CEREMONIES: std::sync::LazyLock<Mutex<RefreshCeremonyStore>> =
    std::sync::LazyLock::new(|| {
        Mutex::new(RefreshCeremonyStore {
            listeners: HashMap::new(),
        })
    });

fn err_response(
    status: StatusCode,
    msg: impl std::fmt::Display,
) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({"error": msg.to_string()})))
}

// ── /refresh-relay/identity ───────────────────────────────────────────────────

/// `GET /refresh-relay/identity` — the container's relay / BRC-31 identity hex.
/// Read-only; also the deployed-image staleness smoke test (404 ⇒ stale image).
pub async fn handle_refresh_relay_identity(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    match crate::auth::server_identity_priv_from_env() {
        Ok(k) => (
            StatusCode::OK,
            Json(serde_json::json!({ "peer_pub_hex": k.public_key().to_hex() })),
        ),
        Err(e) => err_response(
            StatusCode::PRECONDITION_FAILED,
            format!("no server identity: {e}"),
        ),
    }
}

// ── /refresh-relay/init ────────────────────────────────────────────────────────

/// Request body for `POST /refresh-relay/init`.
#[derive(Debug, Deserialize)]
pub struct RefreshRelayInitRequest {
    /// Joint pubkey hex — the share key (also the 33-byte joint pubkey, unchanged).
    pub agent_id: String,
    /// Canonical refresh session_id (64-char hex).
    pub session_id: String,
    /// The proxy peer's BRC-31 / relay identity hex — recipient of round-1.
    pub peer_pub_hex: String,
    /// The proxy peer's party index.
    pub peer_party: u16,
    /// This container's party index.
    pub my_party_index: u16,
    /// Full party set in canonical ascending order. Defaults to `[0, 1]` (2-of-2).
    #[serde(default)]
    pub parties_at_keygen: Option<Vec<u16>>,
}

/// Response from `POST /refresh-relay/init`.
#[derive(Debug, Serialize)]
pub struct RefreshRelayInitResponse {
    /// This container's relay identity hex — the proxy addresses round messages here.
    pub peer_pub_hex: String,
    /// The refresh protocol mailbox.
    pub message_box: String,
}

/// `POST /refresh-relay/init` — arm the container as a refresh peer over the relay.
pub async fn handle_refresh_relay_init(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    raw: Bytes,
) -> impl IntoResponse {
    // §07 auth over the RAW body, then §08.1 owner-authz on the share.
    let caller = match crate::auth::verify_or_allow(
        "POST",
        "/refresh-relay/init",
        &headers,
        &raw,
        &state.auth,
    ) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let body: RefreshRelayInitRequest = match crate::handlers::parse_body_pub(&raw) {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    let identity_priv = match crate::auth::server_identity_priv_from_env() {
        Ok(k) => k,
        Err(e) => {
            return err_response(
                StatusCode::PRECONDITION_FAILED,
                format!("relay refresh requires an enforced server identity: {e}"),
            )
        }
    };

    // Load share (+ custody recover on cold miss) BEFORE the owner check.
    let mut share = match crate::handlers::load_share_or_recover_pub(&state, &body.agent_id).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if let Some(resp) = crate::handlers::authz_owner_pub(&state, &caller, &body.agent_id) {
        return resp;
    }

    // The RefreshCoordinator requires the share carry its 33-byte joint pubkey
    // (the share is keyed by the joint pubkey hex = agent_id).
    if share.joint_pubkey_compressed.len() != 33 {
        match hex::decode(&body.agent_id) {
            Ok(jpk) if jpk.len() == 33 => share.joint_pubkey_compressed = jpk,
            _ => {
                return err_response(
                    StatusCode::BAD_REQUEST,
                    "agent_id must be a 33-byte compressed joint pubkey hex",
                )
            }
        }
    }

    let session_id = match SessionId::from_hex(&body.session_id) {
        Ok(id) => id,
        Err(e) => {
            return err_response(
                StatusCode::BAD_REQUEST,
                format!("session_id must be canonical 64-char hex: {e}"),
            )
        }
    };
    let sid_hex = session_id.hex();
    let parties_at_keygen = body.parties_at_keygen.clone().unwrap_or_else(|| vec![0, 1]);

    let handler = RefreshHandler::new(body.my_party_index, parties_at_keygen);

    let relay_url = relay_url();
    let client = match MessageBoxClient::new(&relay_url, identity_priv.clone()) {
        Ok(c) => c,
        Err(e) => return err_response(StatusCode::BAD_GATEWAY, format!("relay client: {e}")),
    };
    let peer_pub_hex = match client.identity_hex().await {
        Ok(h) => h,
        Err(e) => return err_response(StatusCode::BAD_GATEWAY, format!("relay identity: {e}")),
    };

    // Initiate FIRST (registers the ceremony slot) — BEFORE subscribing — so the
    // proxy's round-1, backfilled by the relay the instant we subscribe, finds the
    // slot already present (the §06.17 ordering invariant).
    let peers = vec![(body.peer_party, body.peer_pub_hex.clone())];
    let (rx, round1_out) = match handler.initiate(session_id, share, peers).await {
        Ok(v) => v,
        Err(e) => {
            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("refresh initiate: {e}"),
            )
        }
    };

    let listener =
        match MessageBoxListener::start(client.clone(), BOX_REFRESH, handler.handler_fn()).await {
            Ok(l) => l,
            Err(e) => return err_response(StatusCode::BAD_GATEWAY, format!("listener start: {e}")),
        };

    // Ship our round-1 to the proxy (its only peer).
    for out in &round1_out {
        if let Err(e) = client
            .send_round_message(
                &out.recipient_pub_hex,
                &out.message_box,
                &out.round_msg,
                out.params.clone(),
            )
            .await
        {
            return err_response(StatusCode::BAD_GATEWAY, format!("ship refresh round-1: {e}"));
        }
    }

    // Spawn the completion task: on commit, ROTATE the container's stored share
    // AND purge its presignatures (§18.9), atomically with the refresh boundary.
    let agent_id = body.agent_id.clone();
    let state_for_commit = state.clone();
    tokio::spawn(async move {
        match rx.await {
            Ok(commit) => {
                rotate_on_commit(&state_for_commit, &agent_id, &commit);
            }
            Err(_) => {
                warn!(
                    session_id = %sid_hex,
                    "refresh-relay: completion channel dropped before commit; share NOT rotated"
                );
            }
        }
    });

    // Keep the listener alive between requests (rounds run on its background pump).
    if let Ok(mut store) = REFRESH_CEREMONIES.lock() {
        store.listeners.insert(session_id.hex(), listener);
    }

    info!(
        session_id = %session_id.hex(),
        my_party_index = body.my_party_index,
        "refresh-relay: peer armed + round-1 shipped to proxy"
    );

    (
        StatusCode::OK,
        Json(
            serde_json::to_value(RefreshRelayInitResponse {
                peer_pub_hex,
                message_box: BOX_REFRESH.to_string(),
            })
            .unwrap_or_default(),
        ),
    )
}

/// Rotation-on-commit (§18.9): overwrite the stored share with the rotated one
/// (empty owner preserves the §08.1 owner binding) and purge all presignatures
/// for the agent — they were generated against the now-dead share and MUST NOT be
/// consumable across the refresh boundary.
fn rotate_on_commit(state: &Arc<AppState>, agent_id: &str, commit: &bsv_mpc_core::RefreshCommit) {
    match state.storage.write() {
        Ok(mut storage) => {
            if let Err(e) =
                storage.store_share_with_owner(agent_id, &commit.rotated_share, "")
            {
                warn!("refresh-relay: failed to rotate share for {agent_id}: {e}");
                return;
            }
            let purged = storage
                .delete_presignatures_for_agent(agent_id)
                .unwrap_or(0);
            info!(
                agent_id = %agent_id,
                purged_presigs = purged,
                "refresh-relay: share ROTATED + {purged} stale presigs purged (§18.9)"
            );
        }
        Err(_) => warn!("refresh-relay: storage lock poisoned; share NOT rotated for {agent_id}"),
    }
}

/// MessageBox relay URL — parity with `relay_handlers::relay_url`.
fn relay_url() -> String {
    std::env::var("RELAY_URL")
        .or_else(|_| std::env::var("MESSAGEBOX_RELAY_URL"))
        .unwrap_or_else(|_| "https://rust-message-box.dev-a3e.workers.dev".to_string())
}
