//! §18.2 **container cross-(t,n) reshare over the relay** routes (issue #35c pt2,
//! CONTAINER target).
//!
//! The deployed CF Container runs the full native `bsv-mpc-service`, so it can run
//! both phases of the proven cross-(t,n) reshare ceremony (the proven mechanism is
//! `tests/reshar_full_2of2_to_2of3_via_messagebox_e2e.rs`). These routes move
//! **party 0** of that ceremony onto the container; the proxy plays the remaining
//! new-set parties.
//!
//!   - `GET  /reshare-relay/identity` — the container's relay / BRC-31 identity hex
//!     (so the proxy can register its own slots + ship round-1 before arming the
//!     container — the §06.17 ordering invariant).
//!   - `POST /reshare-relay/init` — arm the container as a reshare peer for THIS
//!     container's new-set party. Runs the SAME two sequential phases as the proven
//!     test (phase A: throwaway new-set DKG over `mpc-dkg` for aux; phase B:
//!     cross-(t,n) PSS reshare over `mpc-refresh`), then combines via
//!     [`combine_reshared_with_aux`] and **stores the new share** (rotated to the
//!     new `(t', n')` set, SAME joint pubkey) + purges presignatures.
//!
//! Owner-authz gated (§08.1); requires an enforced server identity
//! (`MPC_SERVER_PRIVATE_KEY`).

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use bsv_mpc_core::reshar_coordinator::{
    combine_reshared_with_aux, ContributorInputs, ResharConfig,
};
use bsv_mpc_core::types::{EncryptedShare, SessionId, ShareIndex, ThresholdConfig};
use bsv_mpc_messagebox::types::{BOX_DKG, BOX_REFRESH};
use bsv_mpc_messagebox::MessageBoxClient;
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::{KeyShare, PregeneratedPrimes};
use generic_ec::{NonZero, Scalar, SecretScalar};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::dkg_handler::DkgHandler;
use crate::messagebox::MessageBoxListener;
use crate::reshar_handler::ResharHandler;
use crate::AppState;

fn err_response(
    status: StatusCode,
    msg: impl std::fmt::Display,
) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({"error": msg.to_string()})))
}

// ── /reshare-relay/identity ────────────────────────────────────────────────────

/// `GET /reshare-relay/identity` — the container's relay / BRC-31 identity hex.
/// Read-only; also the deployed-image staleness smoke test (404 ⇒ stale image).
pub async fn handle_reshare_relay_identity(
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
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

// ── /reshare-relay/init ──────────────────────────────────────────────────────────

/// A new-set peer's relay identity.
#[derive(Debug, Clone, Deserialize)]
pub struct ReshareRelayPeer {
    /// The peer's index in the NEW party set.
    pub index: u16,
    /// The peer's relay / BRC-31 identity hex.
    pub pub_hex: String,
}

/// Request body for `POST /reshare-relay/init`.
#[derive(Debug, Deserialize)]
pub struct ReshareRelayInitRequest {
    /// Joint pubkey hex — the OLD share key K (also the 33-byte joint pubkey,
    /// UNCHANGED by the reshare).
    pub agent_id: String,
    /// The throwaway-DKG session_id (64-char hex).
    pub dkg_session: String,
    /// The cross-(t,n) PSS reshare session_id (64-char hex).
    pub reshare_session: String,
    /// This container's index in the NEW party set.
    pub my_new_index: u16,
    /// The NEW threshold `t'`.
    pub new_threshold: u16,
    /// The NEW party count `n'`.
    pub new_parties: u16,
    /// The NEW set's VSS eval points (party order), 32-byte BE scalar hex each.
    pub new_eval_points_hex: Vec<String>,
    /// The NEW-set indices of the contributors (who send PSS round-1 evals).
    pub contributor_new_indices: Vec<u16>,
    /// The OLD-set indices of the same contributors (canonical ascending), used to
    /// build this container's λ over the contributor subset's OLD eval points.
    pub contributor_old_indices: Vec<u16>,
    /// All OTHER new-set parties' relay identities.
    pub peers: Vec<ReshareRelayPeer>,
}

/// Response from `POST /reshare-relay/init`.
#[derive(Debug, Serialize)]
pub struct ReshareRelayInitResponse {
    /// This container's relay identity hex — the proxy addresses round messages here.
    pub peer_pub_hex: String,
}

/// `POST /reshare-relay/init` — arm the container as a reshare peer over the relay.
///
/// Mirrors the proven `reshar_full_2of2_to_2of3_via_messagebox_e2e` ceremony for
/// THIS container's new-set party (`my_new_index`): phase A throwaway DKG over
/// `mpc-dkg` (aux), phase B cross-(t,n) PSS over `mpc-refresh`, then
/// [`combine_reshared_with_aux`] → store the rotated share + purge presigs.
pub async fn handle_reshare_relay_init(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    raw: Bytes,
) -> impl IntoResponse {
    // §07 auth over the RAW body, then §08.1 owner-authz on the share.
    let caller = match crate::auth::verify_or_allow(
        "POST",
        "/reshare-relay/init",
        &headers,
        &raw,
        &state.auth,
    ) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let body: ReshareRelayInitRequest = match crate::handlers::parse_body_pub(&raw) {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    let identity_priv = match crate::auth::server_identity_priv_from_env() {
        Ok(k) => k,
        Err(e) => {
            return err_response(
                StatusCode::PRECONDITION_FAILED,
                format!("relay reshare requires an enforced server identity: {e}"),
            )
        }
    };

    // Load the container's OLD share (+ custody recover on cold miss) BEFORE the
    // owner check (same as refresh).
    let mut old_share = match crate::handlers::load_share_or_recover_pub(&state, &body.agent_id).await
    {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if let Some(resp) = crate::handlers::authz_owner_pub(&state, &caller, &body.agent_id) {
        return resp;
    }

    // The OLD share is keyed by the joint pubkey hex = agent_id; ensure it carries
    // the 33-byte joint pubkey (the reshare invariant K).
    if old_share.joint_pubkey_compressed.len() != 33 {
        match hex::decode(&body.agent_id) {
            Ok(jpk) if jpk.len() == 33 => old_share.joint_pubkey_compressed = jpk,
            _ => {
                return err_response(
                    StatusCode::BAD_REQUEST,
                    "agent_id must be a 33-byte compressed joint pubkey hex",
                )
            }
        }
    }
    let jpk_bytes = old_share.joint_pubkey_compressed.clone();
    let mut jpk_arr = [0u8; 33];
    jpk_arr.copy_from_slice(&jpk_bytes);

    // Deserialize the OLD share's cggmp24 KeyShare → OLD index, OLD eval points,
    // OLD secret (per the proven test's secret extraction).
    let old_keyshare: KeyShare<Secp256k1, SecurityLevel128> =
        match serde_json::from_slice(&old_share.ciphertext) {
            Ok(k) => k,
            Err(e) => {
                return err_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("reshare: bad old key share: {e}"),
                )
            }
        };
    let old_index: u16 = old_keyshare.core.i;
    let old_eval: Vec<NonZero<Scalar<Secp256k1>>> = match old_keyshare
        .core
        .key_info
        .vss_setup
        .as_ref()
    {
        Some(v) => v.I.clone(),
        None => {
            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "reshare: old key share has no VSS setup",
            )
        }
    };
    let old_secret: Scalar<Secp256k1> =
        *<SecretScalar<Secp256k1> as AsRef<Scalar<Secp256k1>>>::as_ref(&old_keyshare.core.x);

    // Decode the NEW eval points.
    let new_eval_points: Vec<NonZero<Scalar<Secp256k1>>> = {
        let mut v = Vec::with_capacity(body.new_eval_points_hex.len());
        for h in &body.new_eval_points_hex {
            let bytes = match hex::decode(h) {
                Ok(b) if b.len() == 32 => b,
                _ => {
                    return err_response(
                        StatusCode::BAD_REQUEST,
                        "new_eval_points_hex entries must be 32-byte BE scalar hex",
                    )
                }
            };
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let s = match Scalar::<Secp256k1>::from_be_bytes(arr) {
                Ok(s) => s,
                Err(_) => {
                    return err_response(StatusCode::BAD_REQUEST, "invalid new eval scalar")
                }
            };
            match NonZero::from_scalar(s) {
                Some(nz) => v.push(nz),
                None => {
                    return err_response(StatusCode::BAD_REQUEST, "new eval point is zero")
                }
            }
        }
        v
    };

    // Build this container's ContributorInputs iff its OLD index is a contributor.
    let contributor = if body.contributor_old_indices.contains(&old_index) {
        let subset_eval_points: Vec<NonZero<Scalar<Secp256k1>>> = body
            .contributor_old_indices
            .iter()
            .map(|k| old_eval[*k as usize])
            .collect();
        let my_subset_pos = body
            .contributor_old_indices
            .iter()
            .position(|k| *k == old_index)
            .expect("old_index is in contributor_old_indices");
        Some(ContributorInputs {
            my_subset_pos,
            subset_eval_points,
            my_old_secret: old_secret,
        })
    } else {
        None
    };

    let dkg_session = match SessionId::from_hex(&body.dkg_session) {
        Ok(id) => id,
        Err(e) => {
            return err_response(
                StatusCode::BAD_REQUEST,
                format!("dkg_session must be canonical 64-char hex: {e}"),
            )
        }
    };
    let reshare_session = match SessionId::from_hex(&body.reshare_session) {
        Ok(id) => id,
        Err(e) => {
            return err_response(
                StatusCode::BAD_REQUEST,
                format!("reshare_session must be canonical 64-char hex: {e}"),
            )
        }
    };
    let reshare_session_hex = reshare_session.hex();

    let new_cfg = match ThresholdConfig::new(body.new_threshold, body.new_parties) {
        Ok(c) => c,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, e),
    };

    // Relay client + this container's relay identity.
    let relay_url = relay_url();
    let client = match MessageBoxClient::new(&relay_url, identity_priv.clone()) {
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

    // ════ PHASE A — throwaway new-set DKG over the relay (this party's aux) ══════
    let dkg_handler = DkgHandler::new(new_cfg, body.my_new_index, fresh_storage());
    let primes = match tokio::task::spawn_blocking(|| {
        PregeneratedPrimes::<SecurityLevel128>::generate(&mut rand::rngs::OsRng)
    })
    .await
    {
        Ok(p) => p,
        Err(e) => {
            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("prime gen task panicked: {e}"),
            )
        }
    };
    dkg_handler.seed_primes_for(dkg_session, primes);

    let dkg_listener =
        match MessageBoxListener::start(client.clone(), BOX_DKG, dkg_handler.handler_fn()).await {
            Ok(l) => l,
            Err(e) => {
                return err_response(StatusCode::BAD_GATEWAY, format!("dkg listener start: {e}"))
            }
        };
    let (dkg_rx, dkg_round1) = match dkg_handler.initiate(dkg_session, peers.clone()).await {
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

    // Phase B (PSS) is armed INSIDE the completion task AFTER phase A completes —
    // SEQUENTIAL phases, one relay subscription per identity at a time. Two
    // concurrent subscriptions on one identity (one per box) can split the relay
    // queue non-deterministically (the §06.17 race `relay_presign` documents); the
    // proven `reshar_full_2of2_to_2of3_via_messagebox_e2e` is sequential, and this
    // mirrors it. Phase A (the throwaway DKG) is a JOINT protocol whose completion
    // is a natural cross-party sync point: when `dkg_rx` fires, ALL new-set parties
    // have finished aux, so all start phase B together.
    let reshar_config = ResharConfig {
        session_id: reshare_session,
        my_new_index: body.my_new_index,
        new_eval_points,
        new_t: body.new_threshold,
        contributor_new_indices: body.contributor_new_indices.clone(),
        original_joint_pubkey: jpk_bytes.clone(),
        contributor,
    };

    // Spawn the completion task: own phase A's listener, await aux, shut it down,
    // THEN arm + run phase B, combine, store the rotated share + purge presigs.
    let agent_id = body.agent_id.clone();
    let state_for_commit = state.clone();
    let old_session = old_share.session_id;
    let my_new_index = body.my_new_index;
    let new_threshold = body.new_threshold;
    let new_parties = body.new_parties;
    let task_session = reshare_session_hex.clone();
    let task_client = client.clone();
    tokio::spawn(async move {
        // ── Phase A: await this party's aux, then release the DKG subscription ──
        let dkg_result = match dkg_rx.await {
            Ok(r) => r,
            Err(_) => {
                warn!(session = %task_session, "reshare-relay: DKG channel dropped; NOT rotated");
                dkg_listener.shutdown().await;
                return;
            }
        };
        dkg_listener.shutdown().await;

        // ── Phase B: now (and only now) subscribe + run the PSS reshare ──
        let reshar_handler = ResharHandler::new();
        let pss_listener = match MessageBoxListener::start(
            task_client.clone(),
            BOX_REFRESH,
            reshar_handler.handler_fn(),
        )
        .await
        {
            Ok(l) => l,
            Err(e) => {
                warn!(session = %task_session, "reshare-relay: pss listener start: {e}");
                return;
            }
        };
        let (pss_rx, pss_round1) = match reshar_handler.initiate(reshar_config, peers).await {
            Ok(v) => v,
            Err(e) => {
                warn!(session = %task_session, "reshare-relay: pss initiate: {e}");
                pss_listener.shutdown().await;
                return;
            }
        };
        for out in &pss_round1 {
            if let Err(e) = task_client
                .send_round_message(&out.recipient_pub_hex, &out.message_box, &out.round_msg, out.params.clone())
                .await
            {
                warn!(session = %task_session, "reshare-relay: ship pss round-1: {e}");
                pss_listener.shutdown().await;
                return;
            }
        }
        let commit = match pss_rx.await {
            Ok(c) => c,
            Err(_) => {
                warn!(session = %task_session, "reshare-relay: PSS channel dropped; NOT rotated");
                pss_listener.shutdown().await;
                return;
            }
        };
        pss_listener.shutdown().await;

        // ── Combine (PSS reshare of K + throwaway aux) + store the rotated share ──
        match combine_reshared_with_aux(&commit.incomplete_share_json, &dkg_result.share.ciphertext)
        {
            Ok(combined) => {
                let rotated = EncryptedShare {
                    nonce: vec![0u8; 12],
                    ciphertext: combined,
                    session_id: old_session,
                    share_index: ShareIndex(my_new_index),
                    config: ThresholdConfig::new(new_threshold, new_parties)
                        .expect("new threshold config validated above"),
                    joint_pubkey_compressed: jpk_bytes.clone(),
                };
                rotate_on_commit(&state_for_commit, &agent_id, &rotated);
            }
            Err(e) => warn!(session = %task_session, "reshare-relay: combine failed: {e}; NOT rotated"),
        }
    });

    info!(
        session = %reshare_session_hex,
        my_new_index,
        old_index,
        "reshare-relay: peer armed (phase A initiated), round-1 shipped; phase B follows on aux completion"
    );

    (
        StatusCode::OK,
        Json(
            serde_json::to_value(ReshareRelayInitResponse { peer_pub_hex })
                .unwrap_or_default(),
        ),
    )
}

/// Rotation-on-commit: overwrite the stored share with the new-set rotated one
/// (empty owner preserves the §08.1 owner binding) and purge all presignatures for
/// the agent — they were generated against the OLD `(t, n)` share and MUST NOT be
/// consumable across the reshare boundary.
fn rotate_on_commit(state: &Arc<AppState>, agent_id: &str, rotated: &EncryptedShare) {
    match state.storage.write() {
        Ok(mut storage) => {
            if let Err(e) = storage.store_share_with_owner(agent_id, rotated, "") {
                warn!("reshare-relay: failed to rotate share for {agent_id}: {e}");
                return;
            }
            let purged = storage.delete_presignatures_for_agent(agent_id).unwrap_or(0);
            info!(
                agent_id = %agent_id,
                purged_presigs = purged,
                "reshare-relay: share ROTATED to new (t,n) + {purged} stale presigs purged"
            );
        }
        Err(_) => warn!("reshare-relay: storage lock poisoned; share NOT rotated for {agent_id}"),
    }
}

/// Fresh isolated (HashMap-backed) storage for the throwaway DKG handler — its
/// share is DISCARDED (only the aux is used via `combine_reshared_with_aux`), so
/// the data_dir path is never written. Keyed under a unique temp path so a
/// concurrent ceremony cannot collide.
fn fresh_storage() -> Arc<std::sync::RwLock<crate::storage::SqliteShareStorage>> {
    use rand::RngCore;
    let mut tag = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut tag);
    let dir = std::env::temp_dir().join(format!("mpc-reshare-throwaway-{}", hex::encode(tag)));
    let path = dir.to_string_lossy().to_string();
    let s = crate::storage::SqliteShareStorage::open(&path).expect("open throwaway storage");
    Arc::new(std::sync::RwLock::new(s))
}

/// MessageBox relay URL — parity with `refresh_relay_handlers::relay_url`.
fn relay_url() -> String {
    std::env::var("RELAY_URL")
        .or_else(|_| std::env::var("MESSAGEBOX_RELAY_URL"))
        .unwrap_or_else(|_| "https://rust-message-box.dev-a3e.workers.dev".to_string())
}
