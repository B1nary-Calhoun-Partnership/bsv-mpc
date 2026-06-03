//! #104 aux-reuse — the Notary (container) side of the STANDALONE group
//! aux-setup ceremony + KEK-sealed aux custody + the per-wallet load helper.
//!
//! Aux-info is independent of any wallet key, so a fixed (device, Notary-set)
//! group runs the (~180-300s) aux ceremony ONCE, and every later per-wallet
//! provision reuses it (keygen + `from_parts` only). These routes arm the
//! container as ONE party of that one-time ceremony, capture its index's aux,
//! and KEK-seal it into durable custody keyed `auxblob-{group_id}#{index}`. The
//! per-wallet `/dkg-relay/init` path then loads + validates + reuses it (see
//! [`try_load_validated_aux`]).
//!
//!   - `GET  /aux-setup/identity`      — staleness smoke (404 ⇒ old image).
//!   - `GET  /aux-setup/peer-identity` — per-index relay pub + #85 attestation
//!     (reuses the dkg-relay handler — identical derivation).
//!   - `POST /aux-setup/init`          — arm as aux-setup party `my_index`,
//!     capture + KEK-seal this index's aux. Owner-authz (§08.1).
//!
//! Heavy MPC — CONTAINER only, never the worker isolate.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use bsv_mpc_core::aux_binding::{
    aux_binding_mac, aux_index_moduli_msf, build_aux_binding_record_parts, derive_binding_mac_key,
    validate_aux_for_load, AuxBindingRecord, AuxLoadExpectation,
};
use bsv_mpc_core::canonical::canonical_aux_setup_execution_id;
use bsv_mpc_core::types::{EncryptedShare, SessionId, ShareIndex, ThresholdConfig};
use bsv_mpc_messagebox::types::BOX_DKG;
use bsv_mpc_messagebox::MessageBoxClient;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::dkg_handler::DkgHandler;
use crate::messagebox::MessageBoxListener;
use crate::AppState;

const SECURITY_LEVEL_BITS: u16 = 128;

fn err_response(
    status: StatusCode,
    msg: impl std::fmt::Display,
) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({"error": msg.to_string()})))
}

fn relay_url() -> String {
    std::env::var("RELAY_URL")
        .or_else(|_| std::env::var("MESSAGEBOX_RELAY_URL"))
        .unwrap_or_else(|_| "https://rust-message-box.dev-a3e.workers.dev".to_string())
}

/// `auxblob-{group_id_hex}` — the custody `agent_id` for a group's aux blobs.
/// The container's existing composite-key custody then stores each index under
/// `auxblob-{group_id}#{index}`, disjoint from real share keys (`{jpk}#{index}`).
fn aux_blob_agent_id(group_id_hex: &str) -> String {
    format!("auxblob-{group_id_hex}")
}

/// The KEK-sealed-at-custody payload for one index's aux blob: the serialized
/// `AuxInfo`, its binding record, and the record MAC. Stored as the `ciphertext`
/// of an `EncryptedShare` so it rides the existing `/custody/{put,get}-share`
/// durable path (KEK-sealed on the DO) — no worker change.
#[derive(Debug, Serialize, Deserialize)]
struct AuxCustodyBlob {
    aux_json: String,
    record: AuxBindingRecord,
    mac: [u8; 32],
}

/// Wrap an `AuxCustodyBlob` as an `EncryptedShare` for the composite-key custody
/// path. The blob bytes live in `ciphertext` (custody KEK-seals the whole thing).
fn blob_to_share(blob: &AuxCustodyBlob, group_id: [u8; 32], index: u16) -> EncryptedShare {
    EncryptedShare {
        nonce: vec![0u8; 12],
        ciphertext: serde_json::to_vec(blob).unwrap_or_default(),
        session_id: SessionId(group_id),
        share_index: ShareIndex(index),
        config: ThresholdConfig::new(2, 2).unwrap(),
        joint_pubkey_compressed: group_id.to_vec(),
    }
}

// ── GET /aux-setup/identity — staleness smoke (distinct route ⇒ 404 on old image) ─
pub async fn handle_aux_setup_identity(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    match crate::auth::server_identity_priv_from_env() {
        Ok(k) => (
            StatusCode::OK,
            Json(serde_json::json!({ "peer_pub_hex": k.public_key().to_hex(), "aux_setup": true })),
        ),
        Err(e) => err_response(
            StatusCode::PRECONDITION_FAILED,
            format!("no server identity: {e}"),
        ),
    }
}

// ── POST /aux-setup/init ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct AuxSetupPeer {
    pub index: u16,
    pub pub_hex: String,
}

/// Request body for `POST /aux-setup/init`. A standalone aux-setup ceremony runs
/// across the FULL `parties` (n-of-n participation — every index generates aux);
/// `threshold` is recorded into the binding so the per-wallet `(t,n)` is pinned.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuxSetupInitRequest {
    pub agent_id: String,
    pub dkg_session: String,
    pub my_index: u16,
    pub threshold: u16,
    pub parties: u16,
    /// The 32-byte group-id (hex) the device computed from the frozen tuple
    /// (`bsv_mpc_core::canonical::aux_group_id`). Binds this aux to the group.
    pub group_id: String,
    /// The pinned-Notary epoch (must-do #10).
    pub aux_epoch: u64,
    pub peers: Vec<AuxSetupPeer>,
}

#[derive(Debug, Serialize)]
pub struct AuxSetupInitResponse {
    pub peer_pub_hex: String,
}

/// `POST /aux-setup/init` — arm the container as aux-setup party `my_index` of
/// the one-time group ceremony. Subscribes `mpc-dkg`, ships round-1, generates +
/// late-seeds primes (the aux SM runs here), and on completion captures this
/// index's aux and KEK-seals it into custody under `auxblob-{group_id}#{index}`.
pub async fn handle_aux_setup_init(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    raw: Bytes,
) -> impl IntoResponse {
    let caller = match crate::auth::verify_or_allow(
        "POST",
        "/aux-setup/init",
        &headers,
        &raw,
        &state.auth,
    ) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let body: AuxSetupInitRequest = match crate::handlers::parse_body_pub(&raw) {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    let identity_priv = match crate::auth::server_identity_priv_from_env() {
        Ok(k) => k,
        Err(e) => {
            return err_response(
                StatusCode::PRECONDITION_FAILED,
                format!("aux-setup requires an enforced server identity: {e}"),
            )
        }
    };
    // Aux blobs are key-grade — custody (durable KEK-seal) is MANDATORY here.
    let custody_kek = match state.custody.as_ref() {
        Some(c) => c.kek,
        None => {
            return err_response(
                StatusCode::PRECONDITION_FAILED,
                "aux-setup requires durable custody (no in-memory aux blobs)",
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
    let group_id = match hex_to_32(&body.group_id) {
        Ok(g) => g,
        Err(e) => {
            return err_response(
                StatusCode::BAD_REQUEST,
                format!("group_id must be 64-char hex: {e}"),
            )
        }
    };

    let relay_identity_priv = match bsv_mpc_core::hd::derive_relay_index_privkey(
        &identity_priv,
        &dkg_session,
        body.my_index,
    ) {
        Ok(k) => k,
        Err(e) => {
            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("aux-setup identity derivation: {e}"),
            )
        }
    };

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

    // CAPTURE mode: group-scoped aux sid + capture this index's aux. No share is
    // persisted (the fused keygen is a throwaway — finish_complete skips it).
    let dkg_handler = DkgHandler::new(config, body.my_index, Arc::clone(&state.storage));
    dkg_handler.set_aux_setup_capture(group_id);

    let dkg_listener =
        match MessageBoxListener::start(client.clone(), BOX_DKG, dkg_handler.handler_fn()).await {
            Ok(l) => l,
            Err(e) => {
                return err_response(StatusCode::BAD_GATEWAY, format!("aux listener start: {e}"))
            }
        };
    let (dkg_rx, dkg_round1) = match dkg_handler.initiate(dkg_session, peers).await {
        Ok(v) => v,
        Err(e) => {
            dkg_listener.shutdown().await;
            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("aux initiate: {e}"),
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
            return err_response(StatusCode::BAD_GATEWAY, format!("ship aux round-1: {e}"));
        }
    }

    // The aux SM runs in capture mode — generate + late-seed primes (§06.17).
    {
        let seed_handler = dkg_handler.clone();
        tokio::spawn(async move {
            match tokio::task::spawn_blocking(|| {
                bsv_mpc_core::paillier_pool::generate_serialized(&mut rand::rngs::OsRng)
            })
            .await
            {
                Ok(primes) => seed_handler.seed_primes_late(dkg_session, primes),
                Err(e) => warn!("aux-setup: prime gen task panicked: {e}; auxinfo will inline-gen"),
            }
        });
    }

    // Completion task: drain the captured aux, build + MAC the binding record,
    // KEK-seal into custody. Fail-closed (the wallet stays inline-aux until it
    // succeeds — the aux blob simply will not exist, and the load branch falls
    // back to fresh aux gen).
    let my_index = body.my_index;
    let n = body.parties;
    let threshold = body.threshold;
    let aux_epoch = body.aux_epoch;
    let owner = caller.identity_key.clone();
    let group_id_hex = body.group_id.clone();
    let handler_for_task = dkg_handler.clone();
    let state_for_task = state.clone();
    tokio::spawn(async move {
        // Await ceremony completion (throwaway DkgResult — we only want the aux).
        if dkg_rx.await.is_err() {
            warn!("aux-setup: ceremony channel dropped before completion; no aux captured");
            dkg_listener.shutdown().await;
            return;
        }
        dkg_listener.shutdown().await;
        let aux_json = match handler_for_task.take_captured_aux() {
            Some(j) => j,
            None => {
                error!("aux-setup: ceremony completed but no aux captured (capture flag lost?)");
                return;
            }
        };
        // Build the binding record from the captured aux + group params.
        let aux: cggmp24::key_share::AuxInfo<cggmp24::security_level::SecurityLevel128> =
            match serde_json::from_str(&aux_json) {
                Ok(a) => a,
                Err(e) => {
                    error!("aux-setup: captured aux failed to deserialize: {e}");
                    return;
                }
            };
        let record = match build_aux_binding_record_parts(
            &group_id,
            n as usize,
            threshold,
            SECURITY_LEVEL_BITS,
            &aux,
            aux_epoch,
        ) {
            Ok(r) => r,
            Err(e) => {
                error!("aux-setup: build binding record failed: {e}");
                return;
            }
        };
        let mac = aux_binding_mac(&record, &derive_binding_mac_key(&custody_kek));
        let blob = AuxCustodyBlob {
            aux_json,
            record,
            mac,
        };
        let share = blob_to_share(&blob, group_id, my_index);
        let agent_id = aux_blob_agent_id(&group_id_hex);
        match state_for_task
            .shares()
            .persist_durable_at_index(&agent_id, my_index, &share, &owner)
            .await
        {
            Ok(()) => info!(
                group_id = %group_id_hex,
                my_index, "aux-setup: index aux KEK-sealed into durable custody (reusable)"
            ),
            Err(e) => error!(
                group_id = %group_id_hex,
                my_index, "aux-setup: aux custody PUT FAILED ({e}); wallet stays inline-aux"
            ),
        }
    });

    info!(
        my_index = body.my_index,
        parties = body.parties,
        group_id = %body.group_id,
        "aux-setup: peer armed (group aux ceremony), round-1 shipped"
    );
    (
        StatusCode::OK,
        Json(serde_json::to_value(AuxSetupInitResponse { peer_pub_hex }).unwrap_or_default()),
    )
}

// ── POST /aux-setup/challenge — the #104 must-do #2 aux-bound liveness gate ──────

/// Request body for `POST /aux-setup/challenge`. The device sends a fresh nonce +
/// the `(group_id, index)` whose moduli it wants the live Notary to endorse.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuxChallengeRequest {
    /// The 32-byte group-id (hex) — selects which sealed aux to prove ownership of.
    pub group_id_hex: String,
    /// The absolute index whose moduli the Notary must sign over.
    pub index: u16,
    /// A fresh 32-byte device nonce (hex) — anti-replay.
    pub nonce_hex: String,
}

/// `POST /aux-setup/challenge` — the Notary proves it is LIVE and OWNS the exact
/// Paillier/Pedersen moduli it contributed at `index` for this group (#104 must-do
/// #2). It loads its sealed aux for `(group_id, index)`, extracts that index's
/// moduli, and signs `(master, group_id, aux_setup_sid, index, moduli, nonce)` with
/// its MASTER key. The device verifies the signature against the master it PINNED —
/// a setup-time modulus swap (attacker-known factorization) makes this fail, so the
/// device refuses to seal/reuse that aux. Read-only (no share access beyond its own
/// aux) and self-authenticating (the master signature), so no BRC-31 auth required.
///
/// Returns `409 CONFLICT` while the aux is not yet sealed (the `/aux-setup/init`
/// completion task seals async right after the ceremony), so the device retries.
pub async fn handle_aux_setup_challenge(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuxChallengeRequest>,
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
    let group_id = match hex_to_32(&req.group_id_hex) {
        Ok(g) => g,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, format!("group_id_hex: {e}")),
    };
    let nonce = match hex_to_32(&req.nonce_hex) {
        Ok(n) => n,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, format!("nonce_hex: {e}")),
    };

    // Load THIS index's sealed aux (custody KEK-decrypts at the storage layer).
    let agent_id = aux_blob_agent_id(&req.group_id_hex);
    let share = match state
        .shares()
        .load_or_recover_at_index(&agent_id, req.index)
        .await
    {
        Ok(Some(s)) => s,
        // Not yet sealed → the device should retry shortly.
        Ok(None) => {
            return err_response(
                StatusCode::CONFLICT,
                format!("aux for {}#{} not yet sealed", req.group_id_hex, req.index),
            )
        }
        Err(e) => {
            return err_response(
                StatusCode::BAD_GATEWAY,
                format!(
                    "aux custody GET failed for {}#{}: {e}",
                    req.group_id_hex, req.index
                ),
            )
        }
    };
    let blob: AuxCustodyBlob = match serde_json::from_slice(&share.ciphertext) {
        Ok(b) => b,
        Err(e) => {
            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("sealed aux blob deserialize: {e}"),
            )
        }
    };
    let aux: cggmp24::key_share::AuxInfo<cggmp24::security_level::SecurityLevel128> =
        match serde_json::from_str(&blob.aux_json) {
            Ok(a) => a,
            Err(e) => {
                return err_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("sealed aux deserialize: {e}"),
                )
            }
        };
    let (n_i, hat_n_i, s_i, t_i) = match aux_index_moduli_msf(&aux, req.index as usize) {
        Some(m) => m,
        None => {
            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("sealed aux has no moduli at index {}", req.index),
            )
        }
    };

    // The aux-setup execution id is deterministic from the group-id (no joint key
    // at setup — the all-zero-jpk carve-out), so both sides derive it identically.
    let aux_session = canonical_aux_setup_execution_id(&group_id);
    let sig = match bsv_mpc_core::hd::sign_aux_liveness_challenge(
        &server_priv,
        &group_id,
        &aux_session,
        req.index,
        &n_i,
        &hat_n_i,
        &s_i,
        &t_i,
        &nonce,
    ) {
        Ok(s) => hex::encode(s),
        Err(e) => {
            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("sign aux liveness challenge: {e}"),
            )
        }
    };
    info!(
        group_id = %req.group_id_hex,
        index = req.index,
        "aux-setup: liveness challenge answered (live master endorsed sealed moduli)"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "master_pub_hex": server_priv.public_key().to_hex(),
            "challenge_sig_hex": sig,
        })),
    )
}

/// Per-wallet LOAD helper (called from `/dkg-relay/init`): retrieve this index's
/// sealed aux for `group_id`, run the full binding gate
/// ([`validate_aux_for_load`]), and return the validated aux JSON to REUSE. Any
/// miss / validation failure returns `None` ⇒ the caller falls back to a fresh
/// aux ceremony (strictly Pareto — still correct, just slower).
pub async fn try_load_validated_aux(
    state: &Arc<AppState>,
    group_id_hex: &str,
    n: u16,
    threshold: u16,
    my_index: u16,
    aux_epoch: u64,
) -> Option<String> {
    let group_id = hex_to_32(group_id_hex).ok()?;
    let custody_kek = state.custody.as_ref()?.kek;
    let agent_id = aux_blob_agent_id(group_id_hex);

    let share = match state
        .shares()
        .load_or_recover_at_index(&agent_id, my_index)
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => return None, // never sealed for this group/index
        Err(e) => {
            warn!("aux-load: custody GET failed for {group_id_hex}#{my_index}: {e}");
            return None;
        }
    };
    let blob: AuxCustodyBlob = serde_json::from_slice(&share.ciphertext).ok()?;
    let aux: cggmp24::key_share::AuxInfo<cggmp24::security_level::SecurityLevel128> =
        serde_json::from_str(&blob.aux_json).ok()?;

    let expect = AuxLoadExpectation {
        group_id,
        n: n as usize,
        threshold,
        security_level_bits: SECURITY_LEVEL_BITS,
        aux_epoch,
    };
    match validate_aux_for_load(
        &expect,
        my_index,
        &aux,
        &blob.record,
        &blob.mac,
        &derive_binding_mac_key(&custody_kek),
    ) {
        Ok(()) => {
            info!(group_id = %group_id_hex, my_index, "aux-load: sealed aux validated — REUSING (skip aux SM)");
            Some(blob.aux_json)
        }
        Err(e) => {
            // Fail-closed on REUSE: do NOT reuse a rejected aux. Fall back to a
            // fresh aux ceremony (correct, slower) rather than risk a tampered one.
            error!(group_id = %group_id_hex, my_index, "aux-load: sealed aux REJECTED ({e}); falling back to fresh aux gen");
            None
        }
    }
}

fn hex_to_32(s: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s).map_err(|e| e.to_string())?;
    if v.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", v.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}
