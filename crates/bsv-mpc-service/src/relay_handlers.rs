//! §06.17.1 **container-as-cosigner over the relay** routes (issue #30 / #25c
//! Stage 2, CONTAINER target).
//!
//! The deployed CF **Container** runs the full native `bsv-mpc-service`. Unlike
//! the CF Worker isolate (which can't run presign math), the container does DKG
//! and presign natively. These two additive routes give it the §06.17.1
//! coordinator-holds-ciphertext role over the live MessageBox relay, reusing the
//! relay-proven `PresignHandler` and `cosign_over_relay`.
//!
//!   - `POST /presign-relay/init` — arm the container as a presign **cosigner**:
//!     it loads its share, builds a `PresignHandler` (cosigner role), starts a
//!     `MessageBoxListener` on the protocol box, runs `init_generate`, ships its
//!     round-1 to the coordinator (proxy), and returns its relay identity. The
//!     listener drives the 3-round presign in the background; on round-3 the
//!     cosigner BRC-2 self-encrypts its OWN share and ships the ciphertext to the
//!     coordinator on `presig_return_{sid}` (the coordinator persists the
//!     bundle). The container NEVER reveals its plaintext presig share.
//!
//!   - `POST /sign-relay` — at sign-time, the coordinator ships back the
//!     container's own `cosigner_encrypted_share` (opaque to it); the container
//!     decrypts it under ITS OWN identity + the canonical presig_id, issues its
//!     partial, and ships it to the combiner over the relay. See
//!     [`crate::sign_relay_handler`].
//!
//! Both routes are owner-authz gated (§08.1) and require an enforced server
//! identity (`MPC_SERVER_PRIVATE_KEY`) — the relay/BRC-2 identity the container
//! self-encrypts + decrypts under.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use bsv_mpc_core::types::{PolicyId, SessionId};
use bsv_mpc_messagebox::types::presign_protocol_box;
use bsv_mpc_messagebox::MessageBoxClient;
use serde::{Deserialize, Serialize};

use crate::messagebox::MessageBoxListener;
use crate::presign_handler::{InMemoryBundleStore, PresignHandler, PresignHandlerConfig};
use crate::sign_relay_handler::{cosign_over_relay, SignRelayParams};
use crate::AppState;

/// Live presign-relay cosigner ceremonies, keyed by presign `session_id` hex.
/// Holds the `MessageBoxListener` so the background pump survives between
/// requests (the 3-round presign + return-ship happen on it), mirroring
/// `handlers::COORDINATOR_STORE`.
struct RelayCeremonyStore {
    listeners: HashMap<String, MessageBoxListener>,
}

static RELAY_CEREMONIES: std::sync::LazyLock<Mutex<RelayCeremonyStore>> =
    std::sync::LazyLock::new(|| {
        Mutex::new(RelayCeremonyStore {
            listeners: HashMap::new(),
        })
    });

fn err_response(
    status: StatusCode,
    msg: impl std::fmt::Display,
) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({"error": msg.to_string()})))
}

// ── presign-arm checkpoint trail (mirrors reshare_relay_handlers) ──────────────
// Captures WHAT SHARE the container actually loads for a presign + the arm params,
// so a deployed presign stall can be diagnosed without container stdout access
// (`wrangler tail` only surfaces the Worker's HTTP events, not the container's
// `tracing`). Query `GET /presign-relay/debug` after a presign arm.
static PRESIGN_CHECKPOINTS: std::sync::LazyLock<Mutex<Vec<(u64, String)>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::new()));

fn presign_now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn presign_checkpoint(label: impl Into<String>, reset: bool) {
    if let Ok(mut cps) = PRESIGN_CHECKPOINTS.lock() {
        if reset {
            cps.clear();
        }
        cps.push((presign_now_millis(), label.into()));
        if cps.len() > 256 {
            let n = cps.len() - 256;
            cps.drain(0..n);
        }
    }
}

/// `GET /presign-relay/debug` — diagnostic trail of the last presign-cosigner arm.
pub async fn handle_presign_relay_debug() -> impl IntoResponse {
    let cps = PRESIGN_CHECKPOINTS
        .lock()
        .map(|c| c.clone())
        .unwrap_or_default();
    let now = presign_now_millis();
    let start = cps.first().map(|(t, _)| *t).unwrap_or(now);
    let steps: Vec<serde_json::Value> = cps
        .iter()
        .map(|(t, l)| {
            serde_json::json!({"t_ms": t, "since_start_ms": t.saturating_sub(start), "label": l})
        })
        .collect();
    Json(serde_json::json!({
        "now_ms": now,
        "count": cps.len(),
        "last_age_ms": cps.last().map(|(t, _)| now.saturating_sub(*t)),
        "steps": steps,
        // Cosigner-side send/drop routing (armed in `handle_presign_relay_init`):
        // reveals which rounds THIS party produced + posted to its peers, so a
        // deterministic n-party stall is mapped from BOTH ends at once.
        "timing": bsv_mpc_core::presig_timing::summary(),
    }))
}

// ── /presign-relay/identity ─────────────────────────────────────────────────

/// `GET /presign-relay/identity` — the container's relay / BRC-2 identity-key
/// hex (the pubkey of `MPC_SERVER_PRIVATE_KEY`). The coordinator fetches this so
/// it can register its own presign ceremony slot + ship its round-1 BEFORE
/// arming the cosigner — otherwise the cosigner's round-1 races ahead of the
/// coordinator's slot and is dropped (the §06.17 ordering invariant). Read-only,
/// no secrets exposed.
pub async fn handle_presign_relay_identity(
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    match crate::auth::server_identity_priv_from_env() {
        Ok(k) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "cosigner_pub_hex": k.public_key().to_hex(),
            })),
        ),
        Err(e) => err_response(
            StatusCode::PRECONDITION_FAILED,
            format!("no server identity: {e}"),
        ),
    }
}

// ── /presign-relay/init ─────────────────────────────────────────────────────

/// Request body for `POST /presign-relay/init`.
#[derive(Debug, Deserialize)]
pub struct PresignRelayInitRequest {
    /// Joint pubkey hex — the share key (also the 33-byte joint pubkey the
    /// PresignHandler binds to).
    pub agent_id: String,
    /// Canonical presign session_id (64-char hex).
    pub session_id: String,
    /// The coordinator's (proxy) BRC-31 / relay identity-key hex — the recipient
    /// of this cosigner's round-1 + return ciphertext.
    pub coordinator_pub_hex: String,
    /// The coordinator's party index (collects + persists the bundle).
    pub coordinator_party: u16,
    /// This cosigner's party index in the keygen subset.
    pub my_party_index: u16,
    /// Cosigner subset in canonical ascending order (binding triple). Defaults to
    /// `[0, 1]` when omitted (the 2-of-2 deployment).
    #[serde(default)]
    pub parties_at_keygen: Option<Vec<u16>>,
    /// 32-byte policy id hex (§09 binding). Defaults to all-zero when omitted.
    #[serde(default)]
    pub policy_id_hex: Option<String>,
    /// **N-party device-holds presign (#69 / #86).** Every OTHER party as
    /// `(index, relay/BRC-2 identity-key hex)`. When present, this cosigner
    /// addresses its broadcasts + p2p MtA traffic + return ciphertext across ALL
    /// of these (the `w` co-located device parties + any other cosigner). When
    /// omitted, falls back to the single `[(coordinator_party, coordinator_pub_hex)]`
    /// peer — byte-identical to the mainnet-proven 2-of-2 deployment. The
    /// coordinator (where the return ciphertext goes) MUST appear in this list.
    #[serde(default)]
    pub peers: Option<Vec<PresignRelayPeer>>,
}

/// One peer entry for the n-party `/presign-relay/init` `peers` list (mirrors the
/// `/dkg-relay/init` peer shape: `{ index, pub_hex }`).
#[derive(Debug, Deserialize)]
pub struct PresignRelayPeer {
    pub index: u16,
    pub pub_hex: String,
}

/// Response from `POST /presign-relay/init`.
#[derive(Debug, Serialize)]
pub struct PresignRelayInitResponse {
    /// This cosigner's relay identity-key hex — the coordinator addresses its
    /// protocol-box round messages here, and the return ciphertext comes from it.
    pub cosigner_pub_hex: String,
    /// The presign protocol mailbox both parties drive the 3 rounds over.
    pub protocol_box: String,
}

/// `POST /presign-relay/init` — arm the container as a presign cosigner over the
/// relay.
pub async fn handle_presign_relay_init(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    raw: Bytes,
) -> impl IntoResponse {
    // §07: authenticate over the RAW body, then §08.1 owner-authz on the share.
    let caller = match crate::auth::verify_or_allow(
        "POST",
        "/presign-relay/init",
        &headers,
        &raw,
        &state.auth,
    ) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let body: PresignRelayInitRequest = match crate::handlers::parse_body_pub(&raw) {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    // Resolve the relay / BRC-2 identity (same key the share self-encrypts under).
    let identity_priv = match crate::auth::server_identity_priv_from_env() {
        Ok(k) => k,
        Err(e) => {
            return err_response(
                StatusCode::PRECONDITION_FAILED,
                format!("relay presign requires an enforced server identity: {e}"),
            )
        }
    };

    // Load THIS party's share (+ recover from custody on a cold miss) BEFORE the
    // owner check. N-party device-holds (#69/#86): the container holds several
    // composite shares `{agent_id}#{index}`, so load the one for THIS cosigner's
    // `my_party_index` (the helper falls back to the bare 2-party share).
    let mut share = match crate::handlers::load_share_or_recover_at_index_pub(
        &state,
        &body.agent_id,
        body.my_party_index,
    )
    .await
    {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    // §08.1 owner-authz against THIS held index's composite owner (n-party);
    // falls back to the bare-agent_id owner for the 2-party deployment.
    if let Some(resp) = crate::handlers::authz_owner_at_index_pub(
        &state,
        &caller,
        &body.agent_id,
        body.my_party_index,
    ) {
        return resp;
    }

    // The PresignHandler requires the share carry the 33-byte joint pubkey; the
    // share is keyed by the joint pubkey hex (agent_id), so populate it when the
    // stored share left it empty (storage default).
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

    // DIAGNOSTIC: record EXACTLY what share the container loaded for this presign +
    // the arm's binding params, so a deployed stall reveals whether the container
    // holds a stale/wrong share or a mismatched index (queryable at
    // `GET /presign-relay/debug`).
    {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&share.ciphertext);
        let ct_fp = hex::encode(&h.finalize()[..8]);
        let mut hj = Sha256::new();
        hj.update(&share.joint_pubkey_compressed);
        let jpk_fp = hex::encode(&hj.finalize()[..6]);
        presign_checkpoint(
            format!(
                "arm:share_loaded stored_share_index={} cfg={}of{} jpk={} jpk_fp={} ct_fp={} \
                 | arm my_party_index={} coordinator_party={} parties_at_keygen={:?}",
                share.share_index.0,
                share.config.threshold,
                share.config.parties,
                hex::encode(share.joint_pubkey_compressed.get(..6).unwrap_or(&[])),
                jpk_fp,
                ct_fp,
                body.my_party_index,
                body.coordinator_party,
                parties_at_keygen,
            ),
            true,
        );
    }

    // #98 cosigner-side routing visibility: arm the send/drop log for THIS presign so
    // `GET /presign-relay/debug` shows which rounds the cosigner produced + posted
    // (maps the deterministic n-party stall from the cosigner end too). The shared
    // `record_send`/`record_dropped` hooks are no-ops until armed.
    bsv_mpc_core::presig_timing::arm();

    let policy_id = match &body.policy_id_hex {
        Some(h) => match hex::decode(h) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                PolicyId(a)
            }
            _ => return err_response(StatusCode::BAD_REQUEST, "policy_id_hex must be 32 bytes"),
        },
        None => PolicyId([0u8; 32]),
    };

    // Build the cosigner handler. The cosigner seals nothing (the coordinator
    // holds the bundle), so `at_rest_root` is irrelevant; `bundle_store` is unused
    // on the cosigner path.
    let handler = PresignHandler::new(PresignHandlerConfig {
        my_party_index: body.my_party_index,
        coordinator_party: body.coordinator_party,
        parties_at_keygen,
        policy_id,
        identity_priv: identity_priv.clone(),
        at_rest_root: [0u8; 32],
        bundle_store: Arc::new(InMemoryBundleStore::new()),
    });

    // Relay client (own identity) + listener on the protocol box.
    let relay_url = relay_url();
    let client = match MessageBoxClient::new(&relay_url, identity_priv.clone()) {
        Ok(c) => c,
        Err(e) => return err_response(StatusCode::BAD_GATEWAY, format!("relay client: {e}")),
    };
    let cosigner_pub_hex = match client.identity_hex().await {
        Ok(h) => h,
        Err(e) => return err_response(StatusCode::BAD_GATEWAY, format!("relay identity: {e}")),
    };
    let protocol_box = presign_protocol_box(&sid_hex);

    // Resolve the cosigner's peer set (n-party list or 2-party fallback; fail fast
    // if it omits the coordinator — see [`resolve_presign_peers`]).
    let peers = match resolve_presign_peers(
        &body.peers,
        body.coordinator_party,
        &body.coordinator_pub_hex,
    ) {
        Ok(p) => p,
        Err(msg) => return err_response(StatusCode::BAD_REQUEST, msg),
    };

    // Initiate FIRST (registers the ceremony slot via init_generate) — BEFORE the
    // listener subscribes — so the coordinator's round-1, backfilled by the relay
    // the instant we subscribe, finds the slot already present (an inbound for an
    // unregistered session is dropped, deadlocking the presign).
    let (_rx, round1_out) = match handler.initiate(session_id, share, peers).await {
        Ok(v) => v,
        Err(e) => {
            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("presign initiate: {e}"),
            )
        }
    };

    let listener = match MessageBoxListener::start(
        client.clone(),
        &protocol_box,
        handler.handler_fn(),
    )
    .await
    {
        Ok(l) => l,
        Err(e) => return err_response(StatusCode::BAD_GATEWAY, format!("listener start: {e}")),
    };

    // Ship our round-1 to every peer (`wrap_protocol` already addressed each
    // outbound to its recipient: broadcasts fan out to all peers, p2p to one).
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
            return err_response(
                StatusCode::BAD_GATEWAY,
                format!("ship presign round-1: {e}"),
            );
        }
    }

    // Keep the listener alive between requests (the 3-round presign + return-ship
    // run on its background pump). Replacing a stale entry for the same session
    // drops + shuts down the prior listener.
    if let Ok(mut store) = RELAY_CEREMONIES.lock() {
        store.listeners.insert(sid_hex.clone(), listener);
    }

    presign_checkpoint(
        format!(
            "arm:round1_shipped count={} returning_200",
            round1_out.len()
        ),
        false,
    );
    tracing::info!(
        session_id = %sid_hex,
        my_party_index = body.my_party_index,
        "presign-relay: cosigner armed + round-1 shipped to coordinator"
    );

    (
        StatusCode::OK,
        Json(
            serde_json::to_value(PresignRelayInitResponse {
                cosigner_pub_hex,
                protocol_box,
            })
            .unwrap_or_default(),
        ),
    )
}

// ── /sign-relay ─────────────────────────────────────────────────────────────

/// Request body for `POST /sign-relay` (mirrors the worker's prod sign-relay,
/// §06.17.1 ciphertext branch).
#[derive(Debug, Deserialize)]
pub struct SignRelayRequest {
    /// Joint pubkey hex (share key) — owner-authz subject.
    pub agent_id: String,
    /// The combiner's (proxy) relay identity-key hex.
    pub recipient_pub_hex: String,
    /// 32-byte sighash hex.
    pub sighash_hex: String,
    /// This cosigner's BRC-2 ciphertext (coordinator-held, opaque), hex.
    pub cosigner_encrypted_share: String,
    /// The canonical `presig_id` (= the PRESIGN session_id hex) the cosigner
    /// sealed its share under at presign-time — the key_id `decrypt_and_issue_partial`
    /// MUST re-derive. This is the bundle's `presig_id`, DISTINCT from
    /// `session_id_hex` (the per-sign relay-correlation id). Falls back to
    /// `session_id_hex` when omitted (legacy callers where they coincide).
    #[serde(default)]
    pub presig_id: Option<String>,
    /// 33-byte joint pubkey hex (the §05 sign envelope carries the real key).
    #[serde(default)]
    pub joint_pubkey_hex: Option<String>,
    /// 32-byte per-sign correlation session_id hex.
    #[serde(default)]
    pub session_id_hex: Option<String>,
    /// This cosigner's signing-time index.
    #[serde(default)]
    pub from_index: Option<u16>,
    /// The combiner's signing-time index.
    #[serde(default)]
    pub to_index: Option<u16>,
    /// **BRC-42 HD-derived child-key signing (MPC-Spec §06.20, issue #26).** Hex
    /// of the 32-byte BRC-42 additive offset the combiner applied to its own
    /// presig + public data; this cosigner applies the SAME offset in
    /// `decrypt_and_issue_partial`. Omitted/`None` = base-key signing.
    #[serde(default)]
    pub brc42_offset: Option<String>,
}

/// `POST /sign-relay` — the container co-signs over the relay from its own
/// §06.17.1 ciphertext.
pub async fn handle_sign_relay(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    raw: Bytes,
) -> impl IntoResponse {
    // §07 auth + §08.1 owner-authz (before any share/presig material is touched).
    let caller =
        match crate::auth::verify_or_allow("POST", "/sign-relay", &headers, &raw, &state.auth) {
            Ok(id) => id,
            Err(resp) => return resp,
        };
    let body: SignRelayRequest = match crate::handlers::parse_body_pub(&raw) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    if let Some(resp) = crate::handlers::authz_owner_pub(&state, &caller, &body.agent_id) {
        return resp;
    }

    let identity_priv = match crate::auth::server_identity_priv_from_env() {
        Ok(k) => k,
        Err(e) => {
            return err_response(
                StatusCode::PRECONDITION_FAILED,
                format!("relay sign requires an enforced server identity: {e}"),
            )
        }
    };

    // Decode inputs.
    let sighash = match decode_32(&body.sighash_hex) {
        Ok(a) => a,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, format!("sighash_hex: {e}")),
    };
    let cosigner_encrypted_share = match hex::decode(&body.cosigner_encrypted_share) {
        Ok(b) if !b.is_empty() => b,
        Ok(_) => return err_response(StatusCode::BAD_REQUEST, "cosigner_encrypted_share is empty"),
        Err(e) => {
            return err_response(
                StatusCode::BAD_REQUEST,
                format!("cosigner_encrypted_share hex: {e}"),
            )
        }
    };
    let joint_pubkey = match &body.joint_pubkey_hex {
        Some(h) => match hex::decode(h) {
            Ok(b) if b.len() == 33 => {
                let mut a = [0u8; 33];
                a.copy_from_slice(&b);
                a
            }
            _ => return err_response(StatusCode::BAD_REQUEST, "joint_pubkey_hex must be 33 bytes"),
        },
        None => [0u8; 33],
    };
    let session_id = match &body.session_id_hex {
        Some(h) => match SessionId::from_hex(h) {
            Ok(id) => id,
            Err(e) => return err_response(StatusCode::BAD_REQUEST, format!("session_id_hex: {e}")),
        },
        None => SessionId::from_str_hash("mpc-sign-relay"),
    };
    // §06.17.1 binds the BRC-2 key to the canonical presig_id = the PRESIGN
    // session_id hex (the key_id the presign handler sealed under), which is the
    // bundle's `presig_id` — DISTINCT from the per-sign relay-correlation
    // `session_id`. Fall back to `session_id` hex when the caller omits it.
    let presig_id = body.presig_id.clone().unwrap_or_else(|| session_id.hex());

    // §06.20 / issue #26: optional BRC-42 offset (hex of 32 bytes). Reuse the
    // 32-byte decode helper; reject malformed hex/length with 400.
    let brc42_offset = match &body.brc42_offset {
        Some(h) => match decode_32(h) {
            Ok(a) => Some(a),
            Err(e) => return err_response(StatusCode::BAD_REQUEST, format!("brc42_offset: {e}")),
        },
        None => None,
    };

    let outcome = match cosign_over_relay(SignRelayParams {
        identity_priv,
        recipient_pub_hex: body.recipient_pub_hex.clone(),
        sighash,
        cosigner_encrypted_share,
        presig_id,
        joint_pubkey,
        session_id,
        from_index: body.from_index.unwrap_or(0),
        to_index: body.to_index.unwrap_or(1),
        relay_url: relay_url(),
        brc42_offset,
    })
    .await
    {
        Ok(o) => o,
        Err(e) => return err_response(StatusCode::BAD_GATEWAY, format!("sign-relay: {e}")),
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "route": "sign-relay",
            "client_identity": outcome.client_identity,
            "recipient": body.recipient_pub_hex,
            "owner": caller.identity_key,
            "partial_hex": outcome.partial_hex,
            "sent": outcome.sent,
        })),
    )
}

// ── /ecdh-relay (#90 distributed-ECDH partial round) ─────────────────────────

/// Request body for `POST /ecdh-relay` (#90).
#[derive(Debug, Deserialize)]
pub struct EcdhRelayRequest {
    /// The wallet's joint pubkey hex — the §08.1 owner-authz key + composite-share
    /// id `{agent_id}#{index}`.
    pub agent_id: String,
    /// 33-byte compressed counterparty pubkey hex (the `Self_`/`Other` ECDH peer;
    /// for `Self_` the device passes the joint pubkey itself).
    pub counterparty_pub_hex: String,
    /// The cosigner's held keygen indices to return partials for — one
    /// `(partial, vss_point)` pair per index. MUST be non-empty.
    pub indices: Vec<u16>,
    /// A fresh 32-byte device nonce hex, bound into the #85 attestation (anti-replay).
    pub nonce_hex: String,
}

/// `POST /ecdh-relay` — the container returns `counterparty_pub * its_share(idx)`
/// for each requested held index, plus a #85 master attestation binding the exact
/// partial set. The device Lagrange-combines these with its own `w` local partials
/// to recover the BRC-42 ECDH shared secret WITHOUT reconstructing the key (#90).
///
/// §08.1 owner-authz is enforced PER held index (composite owner, bare fallback)
/// before that index's share scalar is used — mirrors `/sign-relay`.
pub async fn handle_ecdh_relay(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    raw: Bytes,
) -> impl IntoResponse {
    // §07 auth over the RAW body, before any share material is touched.
    let caller =
        match crate::auth::verify_or_allow("POST", "/ecdh-relay", &headers, &raw, &state.auth) {
            Ok(id) => id,
            Err(resp) => return resp,
        };
    let body: EcdhRelayRequest = match crate::handlers::parse_body_pub(&raw) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    if body.indices.is_empty() {
        return err_response(StatusCode::BAD_REQUEST, "indices must be non-empty");
    }
    // De-dup/normalize (a repeated index is a client bug; one partial each).
    let mut indices = body.indices.clone();
    indices.sort_unstable();
    indices.dedup();

    let counterparty_pub = match hex::decode(&body.counterparty_pub_hex)
        .ok()
        .and_then(|b| bsv::primitives::ec::PublicKey::from_bytes(&b).ok())
    {
        Some(pk) => pk,
        None => {
            return err_response(
                StatusCode::BAD_REQUEST,
                "counterparty_pub_hex must be a 33-byte compressed pubkey",
            )
        }
    };
    let nonce = match decode_32(&body.nonce_hex) {
        Ok(n) => n,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, format!("nonce_hex: {e}")),
    };
    let identity_priv = match crate::auth::server_identity_priv_from_env() {
        Ok(k) => k,
        Err(e) => {
            return err_response(
                StatusCode::PRECONDITION_FAILED,
                format!("relay ECDH requires an enforced server identity: {e}"),
            )
        }
    };

    // §08.1 owner-authz + durable share-load per held index (composite owner first,
    // bare fallback for the 2-party deployment).
    let mut shares: Vec<(u16, Vec<u8>)> = Vec::with_capacity(indices.len());
    for &index in &indices {
        if let Some(resp) =
            crate::handlers::authz_owner_at_index_pub(&state, &caller, &body.agent_id, index)
        {
            return resp;
        }
        let share = match crate::handlers::load_share_or_recover_at_index_pub(
            &state,
            &body.agent_id,
            index,
        )
        .await
        {
            Ok(s) => s,
            Err(resp) => return resp,
        };
        shares.push((index, share.ciphertext));
    }

    let outcome = match crate::ecdh_relay_handler::issue_ecdh_partials(
        &identity_priv,
        &body.agent_id,
        &counterparty_pub,
        &nonce,
        &shares,
    ) {
        Ok(o) => o,
        Err(e) => return err_response(StatusCode::BAD_GATEWAY, format!("ecdh-relay: {e}")),
    };

    let partials_json: Vec<serde_json::Value> = outcome
        .partials
        .iter()
        .map(|p| {
            serde_json::json!({
                "index": p.index,
                "partial_hex": hex::encode(p.partial.to_compressed()),
                "vss_point_hex": hex::encode(p.vss_point),
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "route": "ecdh-relay",
            "owner": caller.identity_key,
            "partials": partials_json,
            "master_pub_hex": outcome.master_pub_hex,
            "attestation_sig_hex": outcome.attestation_sig_hex,
        })),
    )
}

// ── /identity-challenge ──────────────────────────────────────────────────────

/// Request body for `POST /identity-challenge` (#85 funding gate).
#[derive(Debug, Deserialize)]
pub struct IdentityChallengeRequest {
    /// The wallet's 33-byte joint pubkey hex (binds the proof to THIS wallet).
    pub joint_pubkey_hex: String,
    /// A fresh 32-byte device nonce hex (anti-replay).
    pub nonce_hex: String,
}

/// `POST /identity-challenge` — the cosigner proves it is LIVE and controls its
/// MASTER identity for a SPECIFIC wallet (#85). The device sends a fresh nonce +
/// the joint pubkey; the cosigner signs `(master, joint, nonce)` with its master
/// key; the device verifies the signature against the master it PINNED out-of-band,
/// gating funding on this independent confirmation. Read-only (no share access) and
/// self-authenticating (the master signature), so no BRC-31 auth is required.
pub async fn handle_identity_challenge(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<IdentityChallengeRequest>,
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
    let joint = match hex::decode(&req.joint_pubkey_hex) {
        Ok(b) if b.len() == 33 => b,
        _ => return err_response(StatusCode::BAD_REQUEST, "joint_pubkey_hex must be 33 bytes"),
    };
    let nonce = match decode_32(&req.nonce_hex) {
        Ok(n) => n,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, format!("nonce_hex: {e}")),
    };
    let sig = match bsv_mpc_core::hd::sign_cosigner_challenge(&server_priv, &joint, &nonce) {
        Ok(s) => hex::encode(s),
        Err(e) => {
            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("sign challenge: {e}"),
            )
        }
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "master_pub_hex": server_priv.public_key().to_hex(),
            "challenge_sig_hex": sig,
        })),
    )
}

fn decode_32(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let b = hex::decode(hex_str)?;
    if b.len() != 32 {
        anyhow::bail!("must be 32 bytes, got {}", b.len());
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Ok(a)
}

/// MessageBox relay URL — `RELAY_URL`/`MESSAGEBOX_RELAY_URL` env, else the live
/// Calhoun relay (parity with the worker's `DEFAULT_RELAY_URL`).
fn relay_url() -> String {
    std::env::var("RELAY_URL")
        .or_else(|_| std::env::var("MESSAGEBOX_RELAY_URL"))
        .unwrap_or_else(|_| "https://rust-message-box.dev-a3e.workers.dev".to_string())
}

/// Resolve the cosigner's peer set for `/presign-relay/init`.
///
/// - **N-party (#69/#86):** the explicit `peers` list (every OTHER party — the
///   `w` co-located device parties + any other cosigner) when present + non-empty.
/// - **2-party fallback:** the single `[(coordinator_party, coordinator_pub_hex)]`
///   — byte-identical to the mainnet-proven 2-of-2 deployment.
///
/// Errors (with the reason) if the resolved set omits `coordinator_party`: the
/// cosigner's return ciphertext is addressed there, so its absence would deadlock
/// the presign. Surfacing it here turns a silent late stall into a fast 400.
pub(crate) fn resolve_presign_peers(
    peers: &Option<Vec<PresignRelayPeer>>,
    coordinator_party: u16,
    coordinator_pub_hex: &str,
) -> std::result::Result<Vec<(u16, String)>, String> {
    let resolved: Vec<(u16, String)> = match peers {
        Some(list) if !list.is_empty() => {
            list.iter().map(|p| (p.index, p.pub_hex.clone())).collect()
        }
        _ => vec![(coordinator_party, coordinator_pub_hex.to_string())],
    };
    if !resolved.iter().any(|(i, _)| *i == coordinator_party) {
        return Err(format!(
            "peers must include coordinator_party {} (the return-ciphertext recipient); got {:?}",
            coordinator_party,
            resolved.iter().map(|(i, _)| *i).collect::<Vec<_>>()
        ));
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(index: u16) -> PresignRelayPeer {
        PresignRelayPeer {
            index,
            pub_hex: format!("02{:064x}", index),
        }
    }

    #[test]
    fn resolve_peers_2party_fallback_when_omitted() {
        // No `peers` field → the single coordinator peer (byte-identical 2-of-2).
        let got = resolve_presign_peers(&None, 0, "02abc").expect("fallback resolves");
        assert_eq!(got, vec![(0u16, "02abc".to_string())]);
        // An empty list is treated the same as omitted.
        let got_empty = resolve_presign_peers(&Some(vec![]), 0, "02abc").expect("empty → fallback");
        assert_eq!(got_empty, vec![(0u16, "02abc".to_string())]);
    }

    #[test]
    fn resolve_peers_nparty_uses_explicit_list() {
        // Device holds {0,1,2}; this cosigner (party 3) sees all three as peers.
        let peers = Some(vec![peer(0), peer(1), peer(2)]);
        let got = resolve_presign_peers(&peers, 0, "02ignored-fallback").expect("n-party resolves");
        assert_eq!(got.len(), 3);
        assert_eq!(
            got.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        // The explicit list wins — the fallback pub is NOT used.
        assert_eq!(got[0].1, format!("02{:064x}", 0));
    }

    #[test]
    fn resolve_peers_rejects_missing_coordinator() {
        // Coordinator is party 0 but it is absent from the peer list → fail fast.
        let peers = Some(vec![peer(1), peer(2)]);
        let err = resolve_presign_peers(&peers, 0, "02fallback")
            .expect_err("must reject peers omitting the coordinator");
        assert!(
            err.contains("must include coordinator_party 0"),
            "error must name the missing coordinator: {err}"
        );
    }

    #[test]
    fn presign_relay_init_request_parses_with_and_without_peers() {
        // N-party body (with peers) parses + populates the list.
        let with_peers = serde_json::json!({
            "agent_id": "02aa",
            "session_id": "ab".repeat(32),
            "coordinator_pub_hex": "02cc",
            "coordinator_party": 0,
            "my_party_index": 3,
            "parties_at_keygen": [0, 1, 2, 3],
            "peers": [
                {"index": 0, "pub_hex": "02d0"},
                {"index": 1, "pub_hex": "02d1"},
                {"index": 2, "pub_hex": "02d2"}
            ]
        });
        let req: PresignRelayInitRequest =
            serde_json::from_value(with_peers).expect("parse n-party");
        assert_eq!(req.peers.as_ref().map(|p| p.len()), Some(3));

        // 2-party body (no peers) parses, leaving `peers` = None (back-compat).
        let no_peers = serde_json::json!({
            "agent_id": "02aa",
            "session_id": "ab".repeat(32),
            "coordinator_pub_hex": "02cc",
            "coordinator_party": 0,
            "my_party_index": 1
        });
        let req2: PresignRelayInitRequest =
            serde_json::from_value(no_peers).expect("parse 2-party");
        assert!(req2.peers.is_none());
    }
}
