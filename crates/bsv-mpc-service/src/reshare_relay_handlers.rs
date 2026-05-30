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
use cggmp24::KeyShare;
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

// ── #58 diagnostic: reshare-arm checkpoint trail ───────────────────────────────
//
// The reshare arm (`/reshare-relay/init`) does real work SYNCHRONOUSLY before it
// returns 200 (subscribe to the relay, initiate the throwaway DKG, ship round-1),
// then spawns a completion task for phase B. When the deployed gate failed we saw
// the proxy's POST to this route end in `Canceled` — i.e. it never returned — but
// `wrangler tail` does not surface the container's internal `tracing`, so we
// couldn't see WHERE it stalled. This records a timestamped checkpoint at every
// step into an in-memory trail, exposed over HTTP at `/reshare-relay/debug`: query
// it during a hang and the LAST checkpoint pinpoints the stuck step.
static RESHARE_CHECKPOINTS: std::sync::LazyLock<std::sync::Mutex<Vec<(u64, String)>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Record a reshare-arm checkpoint. `reset` clears the trail (call at arm start).
fn checkpoint(label: &str, reset: bool) {
    if let Ok(mut cps) = RESHARE_CHECKPOINTS.lock() {
        if reset {
            cps.clear();
        }
        cps.push((now_millis(), label.to_string()));
        // Bound the trail so a long-lived container can't grow it unboundedly.
        if cps.len() > 256 {
            let drop_n = cps.len() - 256;
            cps.drain(0..drop_n);
        }
    }
    info!(checkpoint = label, "reshare-relay: checkpoint");
}

/// `GET /reshare-relay/egress-test` — #58 diagnostic: directly measure whether
/// THIS container can reach the relay over the network (HTTP Engine.IO handshake +
/// DNS resolution + per-address-family TCP connect timing). Pinpoints whether the
/// reshare-arm hang is container→relay connectivity (and which address family),
/// without burning a real-sats reshare.
pub async fn handle_reshare_relay_egress_test(
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    use std::time::{Duration, Instant};
    let relay = relay_url();
    let base = relay.trim_end_matches('/');
    let mut out = serde_json::Map::new();
    out.insert("relay".into(), serde_json::json!(base));

    // 1. HTTP Engine.IO polling handshake (what `polling_handshake` does).
    let url = format!("{base}/socket.io/?EIO=4&transport=polling&t=egress");
    let t = Instant::now();
    let http = match tokio::time::timeout(Duration::from_secs(15), reqwest::get(&url)).await {
        Ok(Ok(r)) => {
            serde_json::json!({"status": r.status().as_u16(), "ms": t.elapsed().as_millis() as u64})
        }
        Ok(Err(e)) => {
            serde_json::json!({"error": e.to_string(), "ms": t.elapsed().as_millis() as u64})
        }
        Err(_) => serde_json::json!({"error": "timeout>15s"}),
    };
    out.insert("http_handshake".into(), http);

    // 2. DNS resolve + per-address TCP connect to :443 (IPv4 + IPv6).
    let host = base
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();
    match tokio::net::lookup_host((host.as_str(), 443u16)).await {
        Ok(addrs) => {
            let mut probes = Vec::new();
            for addr in addrs {
                let family = if addr.is_ipv4() { "v4" } else { "v6" };
                let t = Instant::now();
                let res = match tokio::time::timeout(
                    Duration::from_secs(8),
                    tokio::net::TcpStream::connect(addr),
                )
                .await
                {
                    Ok(Ok(_)) => {
                        serde_json::json!({"addr": addr.to_string(), "family": family, "ok": true, "ms": t.elapsed().as_millis() as u64})
                    }
                    Ok(Err(e)) => {
                        serde_json::json!({"addr": addr.to_string(), "family": family, "error": e.to_string(), "ms": t.elapsed().as_millis() as u64})
                    }
                    Err(_) => {
                        serde_json::json!({"addr": addr.to_string(), "family": family, "error": "timeout>8s"})
                    }
                };
                probes.push(res);
            }
            out.insert("tcp_probes".into(), serde_json::json!(probes));
        }
        Err(e) => {
            out.insert("dns_error".into(), serde_json::json!(e.to_string()));
        }
    }

    // 2b. Direct POST /.well-known/auth (the BRC-104 handshake endpoint) — bare
    //     reqwest, no Peer. Isolates whether the AUTH ENDPOINT itself responds from
    //     the container (fast non-2xx is fine — proves reachable) vs the hang being
    //     in the Peer's handshake *logic* (crypto/session await), not the HTTP.
    {
        let auth_url = format!("{base}/.well-known/auth");
        let t = Instant::now();
        let body = serde_json::json!({"version":"0.1","messageType":"initialRequest","identityKey":"02deadbeef","nonce":"AAAA"});
        let probe = tokio::time::timeout(
            Duration::from_secs(12),
            reqwest::Client::new().post(&auth_url).json(&body).send(),
        )
        .await;
        out.insert(
            "auth_endpoint_post".into(),
            match probe {
                Ok(Ok(r)) => serde_json::json!({"status": r.status().as_u16(), "ms": t.elapsed().as_millis() as u64}),
                Ok(Err(e)) => serde_json::json!({"error": e.to_string(), "ms": t.elapsed().as_millis() as u64}),
                Err(_) => serde_json::json!({"error": "timeout>12s"}),
            },
        );
    }

    // 3. The REAL authed relay-subscribe path the reshare arm uses (the same one
    //    the proven §06.17.1 presign / §18.2 refresh flows use): BRC-31 identity →
    //    `MessageBoxClient::new` → `subscribe_round_messages(mpc-dkg)` (auth
    //    handshake + /listMessages backfill + WS upgrade). Each step timed + the
    //    whole subscribe bounded by a timeout so a hang is observable, not fatal.
    match crate::auth::server_identity_priv_from_env() {
        Ok(id) => {
            let t = Instant::now();
            match MessageBoxClient::new(&relay, id) {
                Ok(client) => {
                    out.insert(
                        "client_new_ms".into(),
                        serde_json::json!(t.elapsed().as_millis() as u64),
                    );
                    let t = Instant::now();
                    let idh =
                        tokio::time::timeout(Duration::from_secs(10), client.identity_hex()).await;
                    out.insert(
                        "identity_hex".into(),
                        match idh {
                            Ok(Ok(_)) => serde_json::json!({"ok": true, "ms": t.elapsed().as_millis() as u64}),
                            Ok(Err(e)) => serde_json::json!({"error": e.to_string(), "ms": t.elapsed().as_millis() as u64}),
                            Err(_) => serde_json::json!({"error": "timeout>10s"}),
                        },
                    );
                    let t = Instant::now();
                    let sub = tokio::time::timeout(
                        Duration::from_secs(25),
                        client.subscribe_round_messages(BOX_DKG),
                    )
                    .await;
                    out.insert(
                        "subscribe_round_messages".into(),
                        match sub {
                            Ok(Ok(_s)) => serde_json::json!({"ok": true, "ms": t.elapsed().as_millis() as u64}),
                            Ok(Err(e)) => serde_json::json!({"error": e.to_string(), "ms": t.elapsed().as_millis() as u64}),
                            Err(_) => serde_json::json!({"error": "TIMEOUT>25s — this is the reshare-arm hang reproduced"}),
                        },
                    );
                }
                Err(e) => {
                    out.insert("client_new_error".into(), serde_json::json!(e.to_string()));
                }
            }
        }
        Err(e) => {
            out.insert(
                "server_identity".into(),
                serde_json::json!(format!("none: {e}")),
            );
        }
    }

    (StatusCode::OK, Json(serde_json::Value::Object(out)))
}

/// `GET /reshare-relay/debug` — the in-memory checkpoint trail of the most recent
/// reshare arm (+ per-step deltas), so a synchronous hang is observable over HTTP.
pub async fn handle_reshare_relay_debug(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    let cps = RESHARE_CHECKPOINTS
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
    checkpoint("init:start", true);
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
    checkpoint("init:authed", false);
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
    checkpoint("init:body_parsed", false);
    let mut old_share =
        match crate::handlers::load_share_or_recover_pub(&state, &body.agent_id).await {
            Ok(s) => s,
            Err(resp) => return resp,
        };
    if let Some(resp) = crate::handlers::authz_owner_pub(&state, &caller, &body.agent_id) {
        return resp;
    }
    checkpoint("init:share_loaded", false);

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
    let old_eval: Vec<NonZero<Scalar<Secp256k1>>> =
        match old_keyshare.core.key_info.vss_setup.as_ref() {
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
                Err(_) => return err_response(StatusCode::BAD_REQUEST, "invalid new eval scalar"),
            };
            match NonZero::from_scalar(s) {
                Some(nz) => v.push(nz),
                None => return err_response(StatusCode::BAD_REQUEST, "new eval point is zero"),
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
    checkpoint("init:eval_decoded", false);
    let relay_url = relay_url();
    let client = match MessageBoxClient::new(&relay_url, identity_priv.clone()) {
        Ok(c) => c,
        Err(e) => return err_response(StatusCode::BAD_GATEWAY, format!("relay client: {e}")),
    };
    checkpoint("init:relay_client", false);
    let peer_pub_hex = match client.identity_hex().await {
        Ok(h) => h,
        Err(e) => return err_response(StatusCode::BAD_GATEWAY, format!("relay identity: {e}")),
    };
    checkpoint("init:relay_identity", false);

    let peers: Vec<(u16, String)> = body
        .peers
        .iter()
        .map(|p| (p.index, p.pub_hex.clone()))
        .collect();

    // ════ PHASE A — throwaway new-set DKG over the relay (this party's aux) ══════
    //
    // §06.17 ORDERING FIX (issue: deployed reshare timed out — `party N timed
    // out awaiting throwaway DKG aux`). Safe-prime generation takes ~30-90s and
    // is the slowest step. If we generated primes BEFORE subscribing + shipping
    // round-1 (the previous ordering), this container joined the `mpc-dkg` relay
    // box ~60-90s after the proxy parties had already shipped their round-1 — so
    // this party joined LATE and the joint DKG never converged (relay backfill
    // did NOT recover the late join; reproduced hermetically in
    // `tests/reshar_phaseA_delayed_party0_e2e.rs`).
    //
    // Primes are only consumed at the keygen→auxinfo transition (not at init),
    // so we now: SUBSCRIBE + initiate + ship keygen round-1 IMMEDIATELY (no late
    // relay join), then generate primes off the hot path and `seed_primes_late`.
    // If keygen outruns prime gen, the auxinfo phase falls back to inline
    // generation (correct, just slower).
    let dkg_handler = DkgHandler::new(new_cfg, body.my_new_index, fresh_storage());

    checkpoint("init:dkg_listener_starting", false);
    let dkg_listener =
        match MessageBoxListener::start(client.clone(), BOX_DKG, dkg_handler.handler_fn()).await {
            Ok(l) => l,
            Err(e) => {
                return err_response(StatusCode::BAD_GATEWAY, format!("dkg listener start: {e}"))
            }
        };
    checkpoint("init:dkg_listener_started", false);
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
    checkpoint("init:dkg_initiated", false);
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

    // Now (round-1 already shipped — we are NOT late on the relay) generate the
    // slow safe primes off the hot path and late-seed them into the live
    // coordinator before the keygen→auxinfo transition consumes them.
    {
        let seed_handler = dkg_handler.clone();
        tokio::spawn(async move {
            match tokio::task::spawn_blocking(|| {
                // Process-global gate: one safe-prime gen's RSS peak live at a
                // time so back-to-back DKG + reshares can't OOM the container.
                bsv_mpc_core::paillier_pool::generate_serialized(&mut rand::rngs::OsRng)
            })
            .await
            {
                Ok(primes) => seed_handler.seed_primes_late(dkg_session, primes),
                Err(e) => warn!(
                    "reshare-relay: prime gen task panicked: {e}; auxinfo will generate inline"
                ),
            }
        });
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
        checkpoint("taskA:aux_received", false);
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
        checkpoint("taskB:pss_listener_started", false);
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
                .send_round_message(
                    &out.recipient_pub_hex,
                    &out.message_box,
                    &out.round_msg,
                    out.params.clone(),
                )
                .await
            {
                warn!(session = %task_session, "reshare-relay: ship pss round-1: {e}");
                pss_listener.shutdown().await;
                return;
            }
        }
        checkpoint("taskB:pss_round1_shipped", false);
        let commit = match pss_rx.await {
            Ok(c) => c,
            Err(_) => {
                warn!(session = %task_session, "reshare-relay: PSS channel dropped; NOT rotated");
                pss_listener.shutdown().await;
                return;
            }
        };
        checkpoint("taskB:pss_commit", false);
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
                rotate_on_commit(&state_for_commit, &agent_id, &rotated).await;
                checkpoint("taskB:rotated", false);
            }
            Err(e) => {
                warn!(session = %task_session, "reshare-relay: combine failed: {e}; NOT rotated")
            }
        }
    });

    checkpoint("init:returning_200", false);
    info!(
        session = %reshare_session_hex,
        my_new_index,
        old_index,
        "reshare-relay: peer armed (phase A initiated), round-1 shipped; phase B follows on aux completion"
    );

    (
        StatusCode::OK,
        Json(serde_json::to_value(ReshareRelayInitResponse { peer_pub_hex }).unwrap_or_default()),
    )
}

/// Rotation-on-commit: overwrite the stored share with the new-set rotated one
/// (empty owner preserves the §08.1 owner binding) and purge all presignatures for
/// the agent — they were generated against the OLD `(t, n)` share and MUST NOT be
/// consumable across the reshare boundary.
async fn rotate_on_commit(state: &Arc<AppState>, agent_id: &str, rotated: &EncryptedShare) {
    // Preserve the §08.1 owner across rotation: read it so the DURABLE custody record
    // seals the REAL owner (custody has no cache-style "empty = preserve" semantics).
    let owner = state
        .storage
        .read()
        .ok()
        .and_then(|s| s.get_share_owner(agent_id).ok().flatten())
        .unwrap_or_default();
    // #102: rotate through the durable seam — custody-PUT the rotated share FIRST so a
    // container restart can't strand the NEW (t,n) share while the OLD one is already
    // cryptographically invalidated (the reshare fund-lock gap), then the hot cache.
    if let Err(e) = state
        .shares()
        .persist_durable(agent_id, rotated, &owner)
        .await
    {
        warn!("reshare-relay: failed to durably rotate share for {agent_id}: {e}");
        return;
    }
    if let Ok(mut storage) = state.storage.write() {
        let purged = storage
            .delete_presignatures_for_agent(agent_id)
            .unwrap_or(0);
        info!(
            agent_id = %agent_id,
            purged_presigs = purged,
            "reshare-relay: share ROTATED to new (t,n) (durable) + {purged} stale presigs purged"
        );
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
