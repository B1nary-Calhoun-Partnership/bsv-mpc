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

fn presign_checkpoint(label: impl Into<String>, reset: bool) {
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

    // Load share (+ recover from custody on a cold miss) BEFORE the owner check.
    let mut share = match crate::handlers::load_share_or_recover_pub(&state, &body.agent_id).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if let Some(resp) = crate::handlers::authz_owner_pub(&state, &caller, &body.agent_id) {
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

    // Initiate FIRST (registers the ceremony slot via init_generate) — BEFORE the
    // listener subscribes — so the coordinator's round-1, backfilled by the relay
    // the instant we subscribe, finds the slot already present (an inbound for an
    // unregistered session is dropped, deadlocking the presign).
    let peers = vec![(body.coordinator_party, body.coordinator_pub_hex.clone())];
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

    // Ship our round-1 to the coordinator (its only peer).
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
