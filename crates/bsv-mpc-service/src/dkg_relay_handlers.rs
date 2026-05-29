//! §06.22 / ADR-0052 — **genuine n-party DKG over the relay** (#69 PR-2,
//! CONTAINER target).
//!
//! The device-holds-(t−1) model needs all `n` shares of a `(t, n)` joint key
//! created by a GENUINE n-party DKG (each party independent entropy) — not the
//! 2-of-2-then-reshare path. These routes arm the deployed container as ONE
//! keygen party (`my_index`) of a fresh ceremony over the `mpc-dkg` relay box;
//! the device drives its own `w = t−1` parties (one identity each, ADR-0052
//! Model B). DKG-only — no old share, no PSS, no combine. The resulting share is
//! composite-keyed `"{joint_pubkey}#{my_index}"` (ADR-0052) so a container that
//! holds more than one index never overwrites.
//!
//!   - `GET  /dkg-relay/identity` — the container's relay / BRC-31 identity hex
//!     (so the device can register peers + ship round-1 before arming it — the
//!     §06.17 ordering invariant). Also the deployed-image staleness smoke test.
//!   - `POST /dkg-relay/init` — arm the container as keygen party `my_index`.
//!
//! Owner-authz gated (§08.1, the authed caller becomes the share owner); requires
//! an enforced server identity (`MPC_SERVER_PRIVATE_KEY`). Heavy MPC — container
//! only, NOT the worker isolate.

use std::sync::{Arc, LazyLock, Mutex};

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use bsv_mpc_core::types::{SessionId, ThresholdConfig};
use bsv_mpc_messagebox::types::BOX_DKG;
use bsv_mpc_messagebox::MessageBoxClient;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::dkg_handler::DkgHandler;
use crate::messagebox::MessageBoxListener;
use crate::AppState;

fn err_response(
    status: StatusCode,
    msg: impl std::fmt::Display,
) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({"error": msg.to_string()})))
}

/// The canonical relay URL (mirrors the reshare/presign/refresh relay routes).
fn relay_url() -> String {
    std::env::var("RELAY_URL")
        .or_else(|_| std::env::var("MESSAGEBOX_RELAY_URL"))
        .unwrap_or_else(|_| "https://rust-message-box.dev-a3e.workers.dev".to_string())
}

// ── #58-style checkpoint trail (mirrors /reshare-relay/debug) ────────────────────
//
// `/dkg-relay/init` does real work SYNCHRONOUSLY before returning 200 (subscribe,
// initiate, ship round-1) then spawns a completion task. `wrangler tail` does not
// surface the container's `tracing`, so a hang inside a deployed 6-party arm is
// otherwise invisible. This records timestamped checkpoints into an in-memory
// trail exposed at `/dkg-relay/debug`: the LAST checkpoint pinpoints the stuck
// step (the exact technique that debugged the reshare #58 hang). Relay→container
// connectivity is already probed by the existing `/reshare-relay/egress-test`
// (same container, same relay), so no separate dkg egress route is needed.
static DKG_RELAY_CHECKPOINTS: LazyLock<Mutex<Vec<(u64, String)>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Record a dkg-relay-arm checkpoint. `reset` clears the trail (call at arm start).
fn checkpoint(label: &str, reset: bool) {
    if let Ok(mut cps) = DKG_RELAY_CHECKPOINTS.lock() {
        if reset {
            cps.clear();
        }
        cps.push((now_millis(), label.to_string()));
        if cps.len() > 256 {
            let drop_n = cps.len() - 256;
            cps.drain(0..drop_n);
        }
    }
    info!(checkpoint = label, "dkg-relay: checkpoint");
}

/// `GET /dkg-relay/debug` — the in-memory checkpoint trail of the LAST dkg-relay
/// arm, so a hang inside the (synchronous) init path or the completion task is
/// observable over HTTP even when container stdout is not surfaced.
pub async fn handle_dkg_relay_debug(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    let cps = DKG_RELAY_CHECKPOINTS
        .lock()
        .map(|c| c.clone())
        .unwrap_or_default();
    let first = cps.first().map(|(t, _)| *t).unwrap_or(0);
    let steps: Vec<serde_json::Value> = cps
        .iter()
        .map(|(t, label)| {
            serde_json::json!({
                "t_ms": t,
                "since_start_ms": t.saturating_sub(first),
                "label": label,
            })
        })
        .collect();
    let now = now_millis();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "now_ms": now,
            "last_checkpoint_age_ms": cps.last().map(|(t, _)| now.saturating_sub(*t)),
            "count": cps.len(),
            "steps": steps,
        })),
    )
}

// ── /dkg-relay/identity ────────────────────────────────────────────────────────

/// `GET /dkg-relay/identity` — the container's relay / BRC-31 identity hex.
/// Read-only; also the deployed-image staleness smoke test (404 ⇒ stale image).
pub async fn handle_dkg_relay_identity(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
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

// ── /dkg-relay/peer-identity ─────────────────────────────────────────────────

/// Query for `GET /dkg-relay/peer-identity` — the (session, index) whose
/// per-index relay identity public key the caller wants.
#[derive(Debug, Deserialize)]
pub struct PeerIdentityQuery {
    /// The DKG session id — canonical 64-char hex.
    pub session: String,
    /// The absolute keygen index this container will drive in that ceremony.
    pub index: u16,
}

/// `GET /dkg-relay/peer-identity?session=<hex>&index=<u16>` — the **per-index**
/// relay identity *public* key this container will use as keygen party `index`
/// of the ceremony `session` (ADR-0052 Model B / §06.22).
///
/// The relay identity is a ONE-WAY HMAC of the master server identity (see
/// `bsv_mpc_core::hd::derive_relay_index_privkey`), so the **device cannot**
/// recompute it — it fetches each container index's relay pub here (read-only)
/// to register the cosigner parties as relay peers before arming them. The
/// value returned here MUST equal the `peer_pub_hex` that `POST /dkg-relay/init`
/// reports for the same (session, index) — the device asserts that equality to
/// catch any index-derivation drift (5b invariant).
///
/// Read-only and unauthenticated TODAY — the same MITM exposure as the other
/// `/*-relay/identity` reads, tracked by `#85`: pin the master identity
/// out-of-band + sign this fetch before god-tier-production funding.
pub async fn handle_dkg_relay_peer_identity(
    State(_state): State<Arc<AppState>>,
    Query(q): Query<PeerIdentityQuery>,
) -> impl IntoResponse {
    let server_priv = match crate::auth::server_identity_priv_from_env() {
        Ok(k) => k,
        Err(e) => {
            return err_response(
                StatusCode::PRECONDITION_FAILED,
                format!("no server identity: {e}"),
            )
        }
    };
    let session = match SessionId::from_hex(&q.session) {
        Ok(s) => s,
        Err(e) => {
            return err_response(
                StatusCode::BAD_REQUEST,
                format!("session must be canonical 64-char hex: {e}"),
            )
        }
    };
    let relay_priv =
        match bsv_mpc_core::hd::derive_relay_index_privkey(&server_priv, &session, q.index) {
            Ok(k) => k,
            Err(e) => {
                return err_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("dkg-relay identity derivation: {e}"),
                )
            }
        };
    let relay_pub = relay_priv.public_key();
    // #85 MITM gate: ATTEST this per-index relay pub with the MASTER identity so a
    // device that PINNED our master out-of-band can verify the value over an
    // otherwise-unauthenticated GET (a MITM cannot forge the master's signature).
    let attestation = match bsv_mpc_core::hd::sign_relay_identity_attestation(
        &server_priv,
        &session,
        q.index,
        &relay_pub,
    ) {
        Ok(sig) => hex::encode(sig),
        Err(e) => {
            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("attest relay identity: {e}"),
            )
        }
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "index": q.index,
            "session": q.session,
            "relay_pub_hex": relay_pub.to_hex(),
            // The MASTER identity pub (what the device pins) + its attestation over
            // (master, session, index, relay_pub).
            "master_pub_hex": server_priv.public_key().to_hex(),
            "attestation_hex": attestation,
        })),
    )
}

// ── /dkg-relay/init ──────────────────────────────────────────────────────────

/// A ceremony peer's relay identity (absolute keygen index → identity hex).
#[derive(Debug, Clone, Deserialize)]
pub struct DkgRelayPeer {
    /// The peer's ABSOLUTE keygen party index (entry of `parties_at_keygen`).
    pub index: u16,
    /// The peer's relay / BRC-31 identity hex.
    pub pub_hex: String,
}

/// Request body for `POST /dkg-relay/init`. `deny_unknown_fields` rejects
/// reshare-only fields (no `reshare_session`, `new_eval_points_hex`, contributor
/// lists) — this is a FRESH DKG, not a reshare.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DkgRelayInitRequest {
    /// Provisional ceremony id (owner-authz §08.1). For a FRESH DKG the joint
    /// pubkey is not known until completion, so the durable share is RE-KEYED to
    /// `{joint_pubkey}#{my_index}` at completion (ADR-0052 user-decision a); this
    /// field is the caller's declared ceremony handle, not the final storage key.
    pub agent_id: String,
    /// The DKG session id — canonical 64-char hex, SHARED across all `n` parties.
    pub dkg_session: String,
    /// This container's ABSOLUTE keygen index in `0..parties`.
    pub my_index: u16,
    /// The threshold `t`.
    pub threshold: u16,
    /// The party count `n`.
    pub parties: u16,
    /// ALL OTHER parties (absolute index, relay identity hex), canonical ascending
    /// — both the device's held indices and any other container indices.
    pub peers: Vec<DkgRelayPeer>,
}

/// Response from `POST /dkg-relay/init`.
#[derive(Debug, Serialize)]
pub struct DkgRelayInitResponse {
    /// This container's relay identity hex — the device addresses round messages here.
    pub peer_pub_hex: String,
}

/// `POST /dkg-relay/init` — arm the container as keygen party `my_index` of a
/// fresh genuine n-party DKG over the relay (§06.22 / ADR-0052). Subscribes the
/// `mpc-dkg` box, ships round-1, then (off the hot path) generates safe primes and
/// late-seeds them (§06.17 ordering). The share persists composite-keyed under
/// `{joint_pubkey}#{my_index}` with the authed caller as owner.
pub async fn handle_dkg_relay_init(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    raw: Bytes,
) -> impl IntoResponse {
    checkpoint("init:start", true);
    // §07 auth over the RAW body; the authed caller becomes the share owner (§08.1).
    let caller = match crate::auth::verify_or_allow(
        "POST",
        "/dkg-relay/init",
        &headers,
        &raw,
        &state.auth,
    ) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let body: DkgRelayInitRequest = match crate::handlers::parse_body_pub(&raw) {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    let identity_priv = match crate::auth::server_identity_priv_from_env() {
        Ok(k) => k,
        Err(e) => {
            return err_response(
                StatusCode::PRECONDITION_FAILED,
                format!("dkg-relay requires an enforced server identity: {e}"),
            )
        }
    };

    let config = match ThresholdConfig::new(body.threshold, body.parties) {
        Ok(c) => c,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, e),
    };
    if body.my_index >= body.parties {
        return err_response(
            StatusCode::BAD_REQUEST,
            format!("my_index {} >= parties {}", body.my_index, body.parties),
        );
    }
    let dkg_session = match SessionId::from_hex(&body.dkg_session) {
        Ok(id) => id,
        Err(e) => {
            return err_response(
                StatusCode::BAD_REQUEST,
                format!("dkg_session must be canonical 64-char hex: {e}"),
            )
        }
    };

    // Per-index relay identity (ADR-0052 Model B): a DISTINCT relay/BRC-31
    // identity per held keygen index, so each party lands in its OWN relay room
    // (`{identity}-{box}`) and round messages route cleanly even when one
    // container drives several indices (the "two Notaries, one holds two"
    // topology). ONE-WAY HMAC of the master server identity (server_priv is the
    // HMAC key) — a leaked relay key cannot recover server_priv, which is also
    // the BRC-31 auth + BRC-2 share-sealing key. See `bsv_mpc_core::hd`.
    let relay_identity_priv = match bsv_mpc_core::hd::derive_relay_index_privkey(
        &identity_priv,
        &dkg_session,
        body.my_index,
    ) {
        Ok(k) => k,
        Err(e) => {
            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("dkg-relay identity derivation: {e}"),
            )
        }
    };

    // Relay client + this container's per-index relay identity.
    let relay_url = relay_url();
    let client = match MessageBoxClient::new(&relay_url, relay_identity_priv) {
        Ok(c) => c,
        Err(e) => return err_response(StatusCode::BAD_GATEWAY, format!("relay client: {e}")),
    };
    let peer_pub_hex = match client.identity_hex().await {
        Ok(h) => h,
        Err(e) => return err_response(StatusCode::BAD_GATEWAY, format!("relay identity: {e}")),
    };

    let peers: Vec<(u16, String)> = body
        .peers
        .iter()
        .map(|p| (p.index, p.pub_hex.clone()))
        .collect();

    // DkgHandler bound to the REAL durable storage; composite-persist the genuine
    // share under `{joint_pubkey}#{my_index}` with owner = the authed caller (§08.1).
    let dkg_handler = DkgHandler::new(config, body.my_index, Arc::clone(&state.storage));
    dkg_handler.use_composite_persist(caller.identity_key.clone());

    let dkg_listener =
        match MessageBoxListener::start(client.clone(), BOX_DKG, dkg_handler.handler_fn()).await {
            Ok(l) => l,
            Err(e) => {
                return err_response(StatusCode::BAD_GATEWAY, format!("dkg listener start: {e}"))
            }
        };
    let (dkg_rx, dkg_round1) = match dkg_handler.initiate(dkg_session, peers).await {
        Ok(v) => v,
        Err(e) => {
            dkg_listener.shutdown().await;
            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("dkg initiate: {e}"),
            );
        }
    };
    for out in &dkg_round1 {
        if let Err(e) = client
            .send_round_message(
                &out.recipient_pub_hex,
                &out.message_box,
                &out.round_msg,
                out.params.clone(),
            )
            .await
        {
            dkg_listener.shutdown().await;
            return err_response(StatusCode::BAD_GATEWAY, format!("ship dkg round-1: {e}"));
        }
    }
    checkpoint("init:round1_shipped", false);

    // §06.17 ordering: round-1 is shipped (we are NOT late on the relay); now
    // generate the slow safe primes off the hot path and late-seed them before the
    // keygen→auxinfo transition consumes them. If keygen outruns prime gen, auxinfo
    // falls back to inline generation (correct, slower).
    {
        let seed_handler = dkg_handler.clone();
        tokio::spawn(async move {
            match tokio::task::spawn_blocking(|| {
                bsv_mpc_core::paillier_pool::generate_serialized(&mut rand::rngs::OsRng)
            })
            .await
            {
                Ok(primes) => seed_handler.seed_primes_late(dkg_session, primes),
                Err(e) => warn!("dkg-relay: prime gen task panicked: {e}; auxinfo will inline-gen"),
            }
        });
    }

    // Completion task: the share is persisted by the DkgHandler's `finish_complete`
    // (composite key, real storage) the moment this party's ceremony completes. We
    // await completion to VERIFY persistence-before-funding (the lost-funds class)
    // and release the listener.
    let state_for_verify = state.clone();
    let my_index = body.my_index;
    tokio::spawn(async move {
        let dkg_result = match dkg_rx.await {
            Ok(r) => r,
            Err(_) => {
                warn!("dkg-relay: DKG channel dropped before completion; share NOT persisted");
                dkg_listener.shutdown().await;
                return;
            }
        };
        checkpoint("task:dkg_complete", false);
        dkg_listener.shutdown().await;
        // Persistence-before-funding: the composite share for our held index MUST be
        // durably present (finish_complete already wrote it). The device gates a
        // fundable address on the same check across ALL its held indices.
        let agent_id = hex::encode(&dkg_result.joint_key.compressed);
        let present = state_for_verify
            .storage
            .read()
            .ok()
            .and_then(|s| s.get_share_at_index(&agent_id, my_index).ok().flatten())
            .is_some();
        if present {
            checkpoint("task:share_persisted", false);
            info!(agent_id = %agent_id, my_index, "dkg-relay: ceremony complete — share durably persisted");
        } else {
            checkpoint("task:share_MISSING", false);
            warn!(agent_id = %agent_id, my_index, "dkg-relay: ceremony complete but share NOT durably persisted — investigate");
        }
    });

    checkpoint("init:returning_200", false);
    info!(
        my_index = body.my_index,
        threshold = body.threshold,
        parties = body.parties,
        "dkg-relay: peer armed (genuine n-party DKG initiated), round-1 shipped"
    );
    (
        StatusCode::OK,
        Json(serde_json::to_value(DkgRelayInitResponse { peer_pub_hex }).unwrap_or_default()),
    )
}
