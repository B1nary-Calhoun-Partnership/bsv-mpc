//! 2-party CGGMP'24 **DKG over HTTP** against a remote heavy-compute cosigner
//! (party 0 — `bsv-mpc-service` / the CF Container), driven as **party 1**.
//! Factored out of the proxy `bridge.rs` (issue #63, path a-extended) so the
//! BRC-100 proxy AND the native client run the EXACT same authed distributed DKG.
//!
//! Real distributed DKG (no trusted dealer): neither party ever holds the other's
//! share. The cosigner stores `share_A` keyed by the joint pubkey on completion;
//! the returned [`DkgResult`] is this side's `share_B`. Paillier primes are
//! generated inline natively on both sides (DKG is the heavy off-hot-path
//! ceremony — ADR-018).

use std::sync::{Arc, Mutex};

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::dkg::{DkgCoordinator, DkgRoundResult};
use bsv_mpc_core::error::{MpcError, Result};
use bsv_mpc_core::types::{
    DkgResult, JointPublicKey, RoundMessage, SessionId, ShareIndex, ThresholdConfig,
};
use serde::{Deserialize, Serialize};

use crate::session::RelaySession;

/// Request body for `POST /dkg/init` (matches `bsv-mpc-service`).
#[derive(Serialize, Deserialize, Debug)]
struct DkgInitRequest {
    agent_id: String,
    config: ThresholdConfig,
    label: Option<String>,
}

/// Response from `POST /dkg/init`.
#[derive(Serialize, Deserialize, Debug)]
struct DkgInitResponse {
    session_id: String,
    round_message: RoundMessage,
    #[allow(dead_code)]
    total_rounds: u8,
}

/// Request body for `POST /dkg/round`.
#[derive(Serialize, Deserialize, Debug)]
struct DkgRoundRequest {
    session_id: String,
    round_message: RoundMessage,
}

/// Response from `POST /dkg/round`.
#[derive(Serialize, Deserialize, Debug)]
struct DkgRoundResponse {
    #[allow(dead_code)]
    session_id: String,
    round_message: Option<RoundMessage>,
    complete: bool,
    #[allow(dead_code)]
    joint_pubkey: Option<JointPublicKey>,
}

/// Bundle multiple outgoing `RoundMessage`s into a single transport `RoundMessage`
/// (payload = a JSON array of the per-message wire payloads).
fn bundle_messages(messages: &[RoundMessage]) -> Result<RoundMessage> {
    if messages.is_empty() {
        return Err(MpcError::Signing("no messages to bundle".into()));
    }
    let values: Vec<serde_json::Value> = messages
        .iter()
        .map(|m| {
            serde_json::from_slice(&m.payload).map_err(|e| {
                MpcError::Serialization(format!("failed to parse wire message for bundling: {e}"))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let bundled_payload = serde_json::to_vec(&values).map_err(|e| {
        MpcError::Serialization(format!("failed to serialize bundled messages: {e}"))
    })?;
    let first = &messages[0];
    Ok(RoundMessage {
        session_id: first.session_id,
        round: first.round,
        from: first.from,
        to: None,
        payload: bundled_payload,
    })
}

/// POST a JSON body to a KSS endpoint **without** BRC-31 auth (dev / non-enforced
/// cosigners). Called from within `spawn_blocking` via `handle.block_on`.
fn http_post_json<Req: Serialize, Resp: serde::de::DeserializeOwned>(
    handle: &tokio::runtime::Handle,
    client: &reqwest::Client,
    url: &str,
    body: &Req,
) -> Result<Resp> {
    handle.block_on(async {
        let resp = client
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(|e| MpcError::Protocol(format!("DKG request to {url} failed: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(MpcError::Dkg(format!(
                "KSS returned {status} from {url}: {body_text}"
            )));
        }
        resp.json::<Resp>()
            .await
            .map_err(|e| MpcError::Protocol(format!("DKG response parse error from {url}: {e}")))
    })
}

/// POST a JSON request to the KSS **with** canonical BRC-31 auth, serializing the
/// body ONCE so the signature covers the EXACT bytes sent (via `.body(..)`, NOT
/// `.json()`). `path` MUST be the URL path the server sees (e.g. `/dkg/init`).
fn kss_post_authed<Req: Serialize, Resp: serde::de::DeserializeOwned>(
    handle: &tokio::runtime::Handle,
    client: &reqwest::Client,
    url: &str,
    path: &str,
    body: &Req,
    auth: &Mutex<RelaySession>,
) -> Result<Resp> {
    handle.block_on(async {
        let body_bytes = serde_json::to_vec(body)
            .map_err(|e| MpcError::Serialization(format!("serialize request to {url}: {e}")))?;
        let mut builder = client
            .post(url)
            .header("content-type", "application/json")
            .body(body_bytes.clone());
        {
            let auth_guard = auth
                .lock()
                .map_err(|e| MpcError::Protocol(format!("auth lock poisoned: {e}")))?;
            if auth_guard.is_authenticated() {
                for (name, value) in auth_guard.auth_header_pairs("POST", path, &body_bytes)? {
                    builder = builder.header(name, value);
                }
            }
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| MpcError::Protocol(format!("KSS request to {url} failed: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(MpcError::Protocol(format!(
                "KSS returned {status} from {url}: {body_text}"
            )));
        }
        resp.json::<Resp>()
            .await
            .map_err(|e| MpcError::Protocol(format!("KSS response parse error from {url}: {e}")))
    })
}

/// Run a 2-party CGGMP'24 DKG against a remote heavy-compute cosigner (party 0)
/// over HTTP, as **party 1** — producing this side's `share_B` + the joint key.
/// Unauthenticated variant (dev / non-enforced cosigners); use
/// [`run_dkg_over_http_authed`] against an auth-ENFORCED cosigner (§07.6).
pub async fn run_dkg_over_http(kss_url: &str, config: ThresholdConfig) -> Result<DkgResult> {
    run_dkg_over_http_inner(kss_url, config, None).await
}

/// Authenticated variant of [`run_dkg_over_http`]: performs the BRC-31 handshake
/// with the cosigner using `auth_key` (§07.4 long-lived identity) and signs every
/// `/dkg/*` request, so a cosigner running with auth ENFORCED (§07.6) accepts the
/// ceremony and records this identity as the share's `owner_identity` (§08.1).
/// Subsequent `/sign`, `/presign`, `/ecdh` must then authenticate as the SAME
/// identity.
pub async fn run_dkg_over_http_authed(
    kss_url: &str,
    config: ThresholdConfig,
    auth_key: PrivateKey,
) -> Result<DkgResult> {
    // Handshake up front (async) so the in-loop authed POSTs have a session.
    let handshake_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| MpcError::Protocol(format!("failed to create HTTP client: {e}")))?;
    let mut auth = RelaySession::new(auth_key);
    auth.handshake(&handshake_client, kss_url).await?;
    run_dkg_over_http_inner(kss_url, config, Some(Arc::new(Mutex::new(auth)))).await
}

/// Shared DKG-over-HTTP driver. When `auth` is `Some`, every `/dkg/*` request is
/// BRC-31-signed; when `None`, requests are unauthenticated.
async fn run_dkg_over_http_inner(
    kss_url: &str,
    config: ThresholdConfig,
    auth: Option<Arc<Mutex<RelaySession>>>,
) -> Result<DkgResult> {
    let kss_url = kss_url.to_string();
    // DKG is a one-time, off-hot-path ceremony; a remote cosigner on a constrained
    // instance generates Paillier primes inline (tens of seconds to minutes), so
    // allow a generous per-round budget. Overridable via `MPC_DKG_TIMEOUT_SECS`.
    let dkg_timeout = std::env::var("MPC_DKG_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(600);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(dkg_timeout))
        .build()
        .map_err(|e| MpcError::Protocol(format!("failed to create HTTP client: {e}")))?;
    let handle = tokio::runtime::Handle::current();

    tokio::task::spawn_blocking(move || {
        let init_url = format!("{kss_url}/dkg/init");
        let init_req = DkgInitRequest {
            agent_id: String::new(),
            config,
            label: Some("relay-dkg-over-http".into()),
        };
        // Start the cosigner's DKG session FIRST (party 0). The cosigner picks the
        // session id; party 1 MUST adopt it so both derive the SAME canonical
        // cggmp24 ExecutionId (eid = f(session_id)) — a mismatch makes keygen fail.
        let init_resp: DkgInitResponse = match &auth {
            Some(a) => kss_post_authed(&handle, &client, &init_url, "/dkg/init", &init_req, a)?,
            None => http_post_json(&handle, &client, &init_url, &init_req)?,
        };
        let session_id = SessionId::from_str_hash(&init_resp.session_id);

        let mut dkg = DkgCoordinator::new(session_id, config, ShareIndex(1));
        let proxy_r1 = dkg.init()?;

        let round_url = format!("{kss_url}/dkg/round");
        let mut kss_msg = init_resp.round_message;
        let mut proxy_bundle = bundle_messages(&proxy_r1)?;

        loop {
            let round_req = DkgRoundRequest {
                session_id: init_resp.session_id.clone(),
                round_message: proxy_bundle,
            };
            let round_resp: DkgRoundResponse = match &auth {
                Some(a) => {
                    kss_post_authed(&handle, &client, &round_url, "/dkg/round", &round_req, a)?
                }
                None => http_post_json(&handle, &client, &round_url, &round_req)?,
            };

            match dkg.process_round(vec![kss_msg])? {
                DkgRoundResult::NextRound(next) => {
                    if round_resp.complete {
                        return Err(MpcError::Dkg(
                            "cosigner completed DKG but party 1 has more rounds".into(),
                        ));
                    }
                    kss_msg = round_resp.round_message.ok_or_else(|| {
                        MpcError::Dkg("cosigner returned no message but DKG not complete".into())
                    })?;
                    proxy_bundle = bundle_messages(&next)?;
                }
                DkgRoundResult::Complete(result) => return Ok(result),
            }
        }
    })
    .await
    .map_err(|e| MpcError::Dkg(format!("DKG task panicked: {e}")))?
}
