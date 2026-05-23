//! MPC bridge — translates BRC-100 wallet operations to CGGMP'24 protocol rounds.
//!
//! The bridge is the core translation layer between the BRC-100 wallet API
//! surface and the underlying MPC threshold signing protocol. It holds this
//! party's decrypted key share, maintains a session with the Key Share Service
//! (KSS), and orchestrates the multi-round signing ceremonies.
//!
//! ## Protocol rounds
//!
//! ### Presigning (offline, 3 rounds)
//!
//! ```text
//! Proxy                          KSS
//!   │── presign/init ────────────►│
//!   │◄── round_messages ─────────│
//!   │── presign/round { r1 } ───►│
//!   │◄── round_messages ─────────│
//!   │── presign/round { r2 } ───►│
//!   │◄── { complete } ───────────│
//!   │                             │
//!   │  Presignature stored locally│
//! ```
//!
//! ### Online signing (4 rounds without presignature)
//!
//! ```text
//! Proxy                          KSS
//!   │── sign/init ──────────────►│
//!   │◄── { round_message: R1 } ─│
//!   │── sign/round { R1 } ──────►│  (proxy sends its R1)
//!   │◄── { round_message: R2 } ─│
//!   │── sign/round { R2 } ──────►│
//!   │◄── { round_message: R3 } ─│
//!   │── sign/round { R3 } ──────►│
//!   │◄── { round_message: R4 } ─│
//!   │── sign/round { R4 } ──────►│
//!   │◄── { complete, signature } │
//!   │  Combine → DER signature   │
//! ```
//!
//! ## Security properties
//!
//! - The full private key **never exists** on either party. Each party holds
//!   only their share, which is useless without the other party's cooperation.
//! - Identifiable abort: if the KSS misbehaves (sends invalid data), the
//!   protocol identifies it and the proxy can report the violation.
//! - Presignatures are one-time-use. Each presignature is consumed during
//!   signing and cannot be reused.

use crate::config::ProxyConfig;
use bsv::primitives::ec::{PrivateKey, PublicKey};
use bsv_mpc_core::brc31_client::{self, Brc31Client};
use bsv_mpc_core::ecdh;
use bsv_mpc_core::error::MpcError;
use bsv_mpc_core::hd::{compute_invoice, derive_child_pubkey};
use bsv_mpc_core::presigning::{PresigningManager, PresigningRoundResult};
use bsv_mpc_core::signing::{SigningCoordinator, SigningRoundResult};
use bsv_mpc_core::types::*;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, RwLock};

// ============================================================================
// KSS HTTP API types (compatible with bsv-mpc-worker::api)
// ============================================================================

/// Request body for `POST /sign/init`.
#[derive(Serialize, Deserialize, Debug)]
struct SignInitRequest {
    /// BRC-31 identity key of the requesting agent (33-byte hex).
    agent_id: String,
    /// The MPC session ID (from DKG completion).
    session_id: String,
    /// SHA-256d sighash to sign (32 bytes, hex-encoded).
    sighash: String,
    /// Whether to use a presignature for single-round signing.
    use_presignature: bool,
    /// Optional BRC-42 HMAC offset for derived key signing (32 bytes, hex).
    #[serde(skip_serializing_if = "Option::is_none")]
    hmac_offset: Option<String>,
}

/// Response from `POST /sign/init`.
#[derive(Serialize, Deserialize, Debug)]
struct SignInitResponse {
    /// Ephemeral signing session identifier.
    signing_session_id: String,
    /// KSS's round 1 message.
    round_message: RoundMessage,
    /// Whether a presignature was consumed.
    using_presignature: bool,
    /// Total rounds expected.
    total_rounds: u8,
}

/// Request body for `POST /sign/round`.
#[derive(Serialize, Deserialize, Debug)]
struct SignRoundRequest {
    /// The signing session ID from `/sign/init`.
    signing_session_id: String,
    /// The proxy's round message.
    round_message: RoundMessage,
}

/// Response from `POST /sign/round`.
#[derive(Serialize, Deserialize, Debug)]
struct SignRoundResponse {
    /// The signing session ID.
    signing_session_id: String,
    /// KSS's response message (None when complete).
    round_message: Option<RoundMessage>,
    /// Whether signing is now complete.
    complete: bool,
}

/// Request body for `POST /presign/init`.
#[derive(Serialize, Deserialize, Debug)]
struct PresignInitRequest {
    /// BRC-31 identity key of the requesting agent.
    agent_id: String,
    /// The MPC session ID (from DKG completion).
    session_id: String,
    /// Number of presignatures to generate (always 1 for bridge).
    count: u16,
}

/// Response from `POST /presign/init`.
#[derive(Serialize, Deserialize, Debug)]
struct PresignInitResponse {
    /// Presigning session identifier.
    presign_session_id: String,
    /// KSS's round 1 messages.
    round_messages: Vec<RoundMessage>,
    /// Total rounds for presigning (always 3).
    total_rounds: u8,
}

/// Request body for `POST /presign/round`.
#[derive(Serialize, Deserialize, Debug)]
struct PresignRoundRequest {
    /// The presigning session ID from `/presign/init`.
    presign_session_id: String,
    /// The proxy's round messages.
    round_messages: Vec<RoundMessage>,
}

/// Response from `POST /presign/round`.
#[derive(Serialize, Deserialize, Debug)]
struct PresignRoundResponse {
    /// The presigning session ID.
    presign_session_id: String,
    /// KSS's response messages (None when complete).
    round_messages: Option<Vec<RoundMessage>>,
    /// Whether presigning is complete.
    complete: bool,
}

/// Request body for `POST /ecdh`.
#[derive(Serialize, Deserialize, Debug)]
struct EcdhRequest {
    /// BRC-31 identity key of the requesting agent (33-byte hex).
    agent_id: String,
    /// The counterparty public key to compute partial ECDH with (33-byte hex).
    counterparty_pub: String,
}

/// Response from `POST /ecdh`.
#[derive(Serialize, Deserialize, Debug)]
struct EcdhResponse {
    /// The partial ECDH result: counterparty_pub * share_A (33-byte hex).
    partial: String,
}

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

// ============================================================================
// Hex utilities
// ============================================================================

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(hex: &str) -> std::result::Result<Vec<u8>, MpcError> {
    if hex.len() % 2 != 0 {
        return Err(MpcError::Protocol("hex string has odd length".into()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| MpcError::Protocol(format!("invalid hex at position {i}: {e}")))
        })
        .collect()
}

// ============================================================================
// BRC-31 Auth Client (proxy → KSS)
// ============================================================================
//
// The proxy authenticates to the KSS using BRC-31 Authrite.
// Uses a local auth key (not the MPC share) for signing auth messages.
// Session is established via handshake on first KSS request.

/// Deterministically derive the proxy's 32-byte BRC-31 identity-key material
/// from secret share material (§07.4 / OQ-A2 — stable, zero-config). Bumps a
/// counter on the negligible chance of an out-of-range scalar (~2^-128/try).
fn derive_proxy_identity_bytes(share_secret: &[u8]) -> std::result::Result<[u8; 32], MpcError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    const DOMAIN: &[u8] = b"bsv-mpc proxy auth identity v1";
    for counter in 0u8..=u8::MAX {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(DOMAIN)
            .map_err(|e| MpcError::Protocol(format!("hmac init: {e}")))?;
        mac.update(share_secret);
        mac.update(&[counter]);
        let bytes: [u8; 32] = mac.finalize().into_bytes().into();
        // Validate the scalar is in range by attempting a key parse.
        if PrivateKey::from_bytes(&bytes).is_ok() {
            return Ok(bytes);
        }
    }
    Err(MpcError::Protocol(
        "could not derive a valid proxy auth key from share seed".into(),
    ))
}

/// Resolve the proxy's long-lived BRC-31 identity-key bytes (§07.4): an
/// operator-provided `MPC_PROXY_IDENTITY_KEY` (hex) takes precedence — required
/// when the cosigner records the owner at DKG time (the share-derived identity
/// does not exist until DKG completes, so a pre-DKG stable identity must be
/// supplied to make owner-authz against an enforced container match). Falls back
/// to the share-derived identity (stable across restarts, zero-config).
fn resolve_proxy_identity_bytes(share_secret: &[u8]) -> std::result::Result<[u8; 32], MpcError> {
    if let Ok(hex_key) = std::env::var("MPC_PROXY_IDENTITY_KEY") {
        let trimmed = hex_key.trim();
        if !trimmed.is_empty() {
            let raw = hex_decode(trimmed)
                .map_err(|e| MpcError::Protocol(format!("MPC_PROXY_IDENTITY_KEY hex: {e}")))?;
            let bytes: [u8; 32] = raw.try_into().map_err(|_| {
                MpcError::Protocol("MPC_PROXY_IDENTITY_KEY must be 32 bytes".into())
            })?;
            // Validate it's a usable scalar.
            PrivateKey::from_bytes(&bytes)
                .map_err(|e| MpcError::Protocol(format!("MPC_PROXY_IDENTITY_KEY invalid: {e}")))?;
            return Ok(bytes);
        }
    }
    derive_proxy_identity_bytes(share_secret)
}

/// Client-side BRC-31 session for proxy → KSS authentication.
///
/// Thin proxy-side wrapper over the reusable, transport-agnostic
/// [`bsv_mpc_core::brc31_client::Brc31Client`] (shared with the native
/// cosigner/container). This wrapper owns the `reqwest` handshake round-trip and
/// the proxy's stable-identity derivation; the crypto + header construction live
/// in core.
struct BridgeAuth {
    client: Brc31Client,
}

impl BridgeAuth {
    /// Create a new auth client with a random identity key (tests only).
    ///
    /// Production resolves a stable identity via [`resolve_proxy_identity_bytes`]
    /// (operator-provided `MPC_PROXY_IDENTITY_KEY`, else share-derived) so the
    /// proxy keeps the same owner identity across restarts.
    #[cfg(test)]
    fn new() -> std::result::Result<Self, MpcError> {
        use rand::RngCore;
        let mut key_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key_bytes);
        // Ensure the key is valid (non-zero, less than curve order)
        key_bytes[0] |= 0x01;
        let auth_key = PrivateKey::from_bytes(&key_bytes)
            .map_err(|e| MpcError::Protocol(format!("invalid auth key bytes: {e}")))?;
        Ok(Self {
            client: Brc31Client::new(auth_key),
        })
    }

    /// Derive the proxy's **stable** BRC-31 / relay identity key
    /// deterministically from secret share material.
    ///
    /// §07.4 mandates a *long-lived* identity key: the same key signs BRC-31
    /// auth to the KSS, the §05 envelope outer-signatures over the relay, and
    /// is recorded as the share's `owner_identity` at DKG time. A random
    /// per-process key would orphan the share's ownership after a restart, so
    /// the key is derived from the secret share material — binding owner
    /// identity to control of `share_B` (AUTHZ-DESIGN §3c / OQ-A2: derive from
    /// the share file, zero new config). Production goes through
    /// [`resolve_proxy_identity_bytes`] + [`BridgeAuth::from_key_bytes`]; this
    /// thin wrapper exercises the share-derived path directly in tests.
    #[cfg(test)]
    fn from_share_seed(share_secret: &[u8]) -> std::result::Result<Self, MpcError> {
        let bytes = derive_proxy_identity_bytes(share_secret)?;
        Self::from_key_bytes(&bytes)
    }

    /// Build a `BridgeAuth` from explicit 32-byte identity-key material. Used to
    /// (a) honor an operator-provided stable identity (`MPC_PROXY_IDENTITY_KEY`)
    /// and (b) construct a SECOND session (against `presign_url`) with the SAME
    /// long-lived identity (§07.4 — one identity, per-server sessions).
    fn from_key_bytes(bytes: &[u8; 32]) -> std::result::Result<Self, MpcError> {
        let auth_key = PrivateKey::from_bytes(bytes)
            .map_err(|e| MpcError::Protocol(format!("invalid auth key bytes: {e}")))?;
        Ok(Self {
            client: Brc31Client::new(auth_key),
        })
    }

    /// Whether the handshake has been completed.
    fn is_authenticated(&self) -> bool {
        self.client.is_authenticated()
    }

    /// The auth/relay identity key (§07.4 — one key for BRC-31 + envelope sigs).
    fn auth_key(&self) -> &PrivateKey {
        self.client.auth_key()
    }

    /// Our identity key as compressed hex (the BRC-104 identity / owner id).
    #[cfg(test)]
    fn identity_hex(&self) -> String {
        self.client.identity_hex()
    }

    /// Perform the canonical BRC-31 handshake with the KSS (the `reqwest`
    /// round-trip; the header/body crypto is the core [`Brc31Client`]). Sends a
    /// canonical `AuthMessage` InitialRequest body and parses the InitialResponse
    /// identity + session nonce from the response headers.
    async fn handshake(
        &mut self,
        client: &reqwest::Client,
        kss_url: &str,
    ) -> std::result::Result<(), MpcError> {
        let handshake_url = format!("{kss_url}/.well-known/auth");
        let init_body = self.client.initial_request_body()?;
        let mut req = client
            .post(&handshake_url)
            .header("content-type", "application/json")
            .body(init_body);
        for (name, value) in self.client.initial_request_headers() {
            req = req.header(name, value);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| MpcError::Protocol(format!("BRC-31 handshake failed: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(MpcError::Protocol(format!(
                "BRC-31 handshake returned {status}: {body}"
            )));
        }

        let header = |name: &str| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        };
        let server_identity = header(brc31_client::headers::IDENTITY_KEY).ok_or_else(|| {
            MpcError::Protocol("BRC-31: missing server identity in handshake response".into())
        })?;
        let server_nonce = header(brc31_client::headers::NONCE).ok_or_else(|| {
            MpcError::Protocol("BRC-31: missing server nonce in handshake response".into())
        })?;

        tracing::info!(server_identity = %server_identity, "BRC-31: handshake complete with KSS");
        if !self
            .client
            .complete_handshake(server_identity, server_nonce)
        {
            return Err(MpcError::Protocol(
                "BRC-31: handshake response carried an invalid server identity key".into(),
            ));
        }
        Ok(())
    }

    /// Canonical BRC-104 auth headers (name, value) for a fresh request over
    /// `(method, path, body)` — owned pairs, usable for a `reqwest` builder and
    /// for the relay trigger.
    fn auth_header_pairs(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> std::result::Result<Vec<(&'static str, String)>, MpcError> {
        self.client.request_headers(method, path, body)
    }
}

// ============================================================================
// HTTP helper
// ============================================================================

/// POST a JSON request to the KSS and deserialize the response.
///
/// Called from within `spawn_blocking` via `handle.block_on`. The request body
/// is serialized to bytes ONCE; the canonical BRC-104 signature is computed over
/// those exact bytes + `path`; and the SAME bytes are sent via `.body(..)` (NOT
/// `.json()`) so the server reconstructs a byte-identical payload. `path` MUST be
/// the URL path the server sees (e.g. `/sign/init`).
fn kss_post<Req: Serialize, Resp: serde::de::DeserializeOwned>(
    handle: &tokio::runtime::Handle,
    client: &reqwest::Client,
    url: &str,
    path: &str,
    body: &Req,
    auth: &Mutex<BridgeAuth>,
) -> std::result::Result<Resp, MpcError> {
    handle.block_on(async {
        let body_bytes = serde_json::to_vec(body)
            .map_err(|e| MpcError::Serialization(format!("serialize request to {url}: {e}")))?;
        let mut builder = client
            .post(url)
            .header("content-type", "application/json")
            .body(body_bytes.clone());

        // Add canonical BRC-31 auth headers if authenticated.
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

// ============================================================================
// Wire format: bundle / unbundle
// ============================================================================

/// Bundle multiple outgoing `RoundMessage`s into a single transport `RoundMessage`.
/// Payload becomes a JSON array of WireMessages.
fn bundle_messages(messages: &[RoundMessage]) -> std::result::Result<RoundMessage, MpcError> {
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
        .collect::<std::result::Result<Vec<_>, _>>()?;
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

// ============================================================================
// DKG over HTTP (proxy = party 1, holds share_B)
// ============================================================================

/// POST a JSON body to a KSS endpoint **without** BRC-31 auth and deserialize
/// the response. Used by [`run_dkg_over_http`] (the unauthenticated variant —
/// dev / non-enforced cosigners). When the cosigner runs with auth ENFORCED
/// (§07.6), use [`run_dkg_over_http_authed`], which signs each request so the
/// cosigner records the caller as the share's `owner_identity` (§08.1).
fn http_post_json<Req: Serialize, Resp: serde::de::DeserializeOwned>(
    handle: &tokio::runtime::Handle,
    client: &reqwest::Client,
    url: &str,
    body: &Req,
) -> std::result::Result<Resp, MpcError> {
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

/// Run a 2-party CGGMP'24 DKG against a remote heavy-compute cosigner (party 0,
/// `bsv-mpc-service` / CF Container) over HTTP, as **party 1** — producing this
/// proxy's `share_B` + the joint key. This is real distributed DKG (no trusted
/// dealer): neither party ever holds the other's share.
///
/// The cosigner stores `share_A` keyed by the joint pubkey on completion; the
/// returned [`DkgResult`] is the proxy's `share_B`, which the caller persists to
/// the proxy's share file. Paillier primes are generated inline natively on both
/// sides (DKG is the heavy off-hot-path ceremony — ADR-018).
pub async fn run_dkg_over_http(
    kss_url: &str,
    config: ThresholdConfig,
) -> bsv_mpc_core::error::Result<DkgResult> {
    run_dkg_over_http_inner(kss_url, config, None).await
}

/// Authenticated variant of [`run_dkg_over_http`]: performs the BRC-31 handshake
/// with the cosigner using `auth_key` (§07.4 long-lived identity) and signs
/// every `/dkg/*` request, so a cosigner running with auth ENFORCED (§07.6)
/// accepts the ceremony and records this identity as the share's
/// `owner_identity` (§08.1). Subsequent `/sign`, `/presign`, `/ecdh` must then
/// authenticate as the SAME identity.
pub async fn run_dkg_over_http_authed(
    kss_url: &str,
    config: ThresholdConfig,
    auth_key: PrivateKey,
) -> bsv_mpc_core::error::Result<DkgResult> {
    // Handshake up front (async) so the in-loop authed POSTs have a session.
    let handshake_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| MpcError::Protocol(format!("failed to create HTTP client: {e}")))?;
    let mut auth = BridgeAuth {
        client: Brc31Client::new(auth_key),
    };
    auth.handshake(&handshake_client, kss_url).await?;
    run_dkg_over_http_inner(kss_url, config, Some(Arc::new(Mutex::new(auth)))).await
}

/// Shared DKG-over-HTTP driver. When `auth` is `Some`, every `/dkg/*` request is
/// BRC-31-signed (the cosigner records the owner); when `None`, requests are
/// unauthenticated (dev / non-enforced cosigners).
async fn run_dkg_over_http_inner(
    kss_url: &str,
    config: ThresholdConfig,
    auth: Option<Arc<Mutex<BridgeAuth>>>,
) -> bsv_mpc_core::error::Result<DkgResult> {
    use bsv_mpc_core::dkg::{DkgCoordinator, DkgRoundResult};

    let kss_url = kss_url.to_string();
    // DKG is a one-time, off-hot-path ceremony; a remote cosigner on a
    // constrained instance generates Paillier primes inline (tens of seconds to
    // minutes), so allow a generous per-round budget. Overridable via
    // `MPC_DKG_TIMEOUT_SECS`.
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
            label: Some("proxy-dkg-over-http".into()),
        };
        // Start the cosigner's DKG session FIRST (party 0). The cosigner picks
        // the session id; the proxy MUST adopt it so both derive the SAME
        // canonical cggmp24 ExecutionId (eid = f(session_id)) — a mismatch makes
        // keygen fail to complete.
        let init_resp: DkgInitResponse = match &auth {
            Some(a) => kss_post(&handle, &client, &init_url, "/dkg/init", &init_req, a)?,
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
                Some(a) => kss_post(&handle, &client, &round_url, "/dkg/round", &round_req, a)?,
                None => http_post_json(&handle, &client, &round_url, &round_req)?,
            };

            match dkg.process_round(vec![kss_msg])? {
                DkgRoundResult::NextRound(next) => {
                    if round_resp.complete {
                        return Err(MpcError::Dkg(
                            "cosigner completed DKG but proxy has more rounds".into(),
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

// ============================================================================
// MpcBridge
// ============================================================================

/// Bridges BRC-100 wallet calls to MPC threshold signing operations.
///
/// Created once at startup from the proxy configuration. Holds the decrypted
/// share in memory for the lifetime of the process. Signing and presigning
/// operations create ephemeral coordinators that drive the multi-round
/// protocols via HTTP to the KSS.
pub struct MpcBridge {
    /// URL of the Key Share Service (the other MPC party).
    kss_url: String,

    /// This party's key share (ciphertext contains raw key share JSON).
    ///
    /// Note: Despite the name, the `ciphertext` field in `EncryptedShare`
    /// holds raw serialized cggmp24 key share JSON — it is NOT AES-encrypted.
    /// File-level encryption (if enabled) wraps the entire `DkgResult`.
    ///
    /// Behind an `RwLock` so a §18 key-refresh can **hot-swap** the rotated share
    /// at runtime (see [`MpcBridge::apply_refreshed_share`]) without a restart;
    /// readers take a short read-lock and clone out (the existing call sites
    /// already cloned the share). The joint pubkey / share index / config are
    /// invariant across refresh — only the `ciphertext` (rotated KeyShare) changes.
    share: Arc<RwLock<EncryptedShare>>,

    /// Joint public key computed during the DKG ceremony.
    joint_key: JointPublicKey,

    /// Root BSV PublicKey parsed from joint_key.compressed.
    root_pub: PublicKey,

    /// This party's share scalar (32 bytes big-endian), extracted from the
    /// cggmp24 IncompleteKeyShare. Used for local partial ECDH computation.
    ///
    /// Behind an `RwLock`: rotated atomically with `share` on a §18 refresh (the
    /// secret share changes, so this derived scalar must too).
    share_scalar: Arc<RwLock<[u8; 32]>>,

    /// VSS evaluation points for all parties (one 32-byte scalar per party).
    /// Needed for Lagrange interpolation when combining partial ECDH results.
    vss_points: Vec<[u8; 32]>,

    /// HTTP client for communicating with the KSS.
    client: reqwest::Client,

    /// Session identifier linking this proxy to a specific KSS session.
    session_id: SessionId,

    /// Party indices participating in signing ceremonies.
    /// For 2-of-2: `[0, 1]`. Derived from threshold config at init.
    participants: Vec<u16>,

    /// Agent identity (hex-encoded compressed joint public key).
    /// Used for BRC-31 auth with the KSS.
    agent_id: String,

    /// BRC-31 Authrite client for authenticated KSS (DO `kss_url`) communication.
    /// Arc<Mutex> for sharing across spawn_blocking closures.
    auth: Arc<Mutex<BridgeAuth>>,

    /// BRC-31 session for the heavy-compute cosigner (`presign_url`). When
    /// `presign_url == kss_url` this is the same `Arc` as `auth`; otherwise it is
    /// a SEPARATE session with the SAME long-lived identity (§07.4) — required
    /// because a BRC-31 session is per-server (signature is derived against the
    /// server's identity; the session nonce is server-issued), so presig against
    /// an enforced container needs its own handshake.
    presign_auth: Arc<Mutex<BridgeAuth>>,

    /// MessageBox relay URL for the ADR-018 relay sign path (#12).
    relay_url: String,

    /// Heavy-compute cosigner URL for DKG + presig ceremonies (ADR-018). Defaults
    /// to `kss_url` when `MPC_PRESIGN_URL` is unset.
    presign_url: String,
}

impl MpcBridge {
    /// Initialize the MPC bridge.
    ///
    /// 1. Reads the share file from `config.share_path` (JSON `DkgResult`).
    /// 2. If `config.encryption_key` is set, decrypts the file first.
    /// 3. Validates the share structure.
    /// 4. Extracts the joint public key and session ID.
    /// 5. Determines signing participants from the threshold config.
    /// 6. Creates an HTTP client for KSS communication.
    pub async fn new(config: &ProxyConfig) -> anyhow::Result<Self> {
        // 1. Read share file
        let file_bytes = tokio::fs::read(&config.share_path).await.map_err(|e| {
            anyhow::anyhow!("failed to read share file '{}': {e}", config.share_path)
        })?;

        // 2. Parse DkgResult (optionally decrypt first)
        let dkg_result: DkgResult = if let Some(ref enc_key_hex) = config.encryption_key {
            let key_bytes = hex_decode(enc_key_hex)
                .map_err(|e| anyhow::anyhow!("invalid encryption key hex: {e}"))?;
            if key_bytes.len() != 32 {
                anyhow::bail!(
                    "encryption key must be 32 bytes (64 hex chars), got {} bytes",
                    key_bytes.len()
                );
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);

            // File is a JSON EncryptedShare envelope wrapping encrypted DkgResult
            let encrypted: EncryptedShare = serde_json::from_slice(&file_bytes)
                .map_err(|e| anyhow::anyhow!("failed to parse encrypted share file: {e}"))?;
            let plaintext = bsv_mpc_core::share::decrypt_share(&encrypted, &key)
                .map_err(|e| anyhow::anyhow!("failed to decrypt share: {e}"))?;
            serde_json::from_slice(&plaintext)
                .map_err(|e| anyhow::anyhow!("failed to parse decrypted DkgResult: {e}"))?
        } else {
            // Plaintext DkgResult JSON
            serde_json::from_slice(&file_bytes)
                .map_err(|e| anyhow::anyhow!("failed to parse share file as DkgResult: {e}"))?
        };

        // 3. Validate share structure
        bsv_mpc_core::share::validate_encrypted_share(&dkg_result.share)
            .map_err(|e| anyhow::anyhow!("share validation failed: {e}"))?;

        // 4. Determine participants
        let tc = dkg_result.share.config;
        let my_index = dkg_result.share.share_index.0;
        let participants: Vec<u16> = if tc.threshold == tc.parties {
            // All parties must participate (e.g., 2-of-2)
            (0..tc.parties).collect()
        } else {
            // Need `threshold` parties: ourselves + first (threshold-1) others
            // TODO: For multi-KSS setups, allow configuring which parties to sign with
            let mut parts: Vec<u16> = (0..tc.parties)
                .filter(|&i| i != my_index)
                .take((tc.threshold - 1) as usize)
                .collect();
            parts.push(my_index);
            parts.sort();
            parts
        };

        let agent_id = hex_encode(&dkg_result.joint_key.compressed);

        // Parse root public key
        let root_pub = PublicKey::from_bytes(&dkg_result.joint_key.compressed)
            .map_err(|e| anyhow::anyhow!("invalid joint public key: {e}"))?;

        // Extract share scalar and VSS evaluation points for partial ECDH.
        // The ciphertext field holds raw cggmp24 key share JSON.
        // If parsing fails (e.g., stub shares), partial_ecdh will fail at call time.
        let (share_scalar, vss_points) =
            match ecdh::parse_share_scalar(&dkg_result.share.ciphertext).and_then(|scalar| {
                ecdh::parse_share_vss_points(&dkg_result.share.ciphertext).map(|pts| (scalar, pts))
            }) {
                Ok((scalar, pts)) => (scalar, pts),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "failed to parse share for partial ECDH — \
                         encrypt/decrypt with 'self'/'other' counterparty will fail"
                    );
                    ([0u8; 32], vec![])
                }
            };

        tracing::info!(
            session_id = %dkg_result.session_id,
            share_index = my_index,
            threshold = tc.threshold,
            parties = tc.parties,
            participants = ?participants,
            address = %dkg_result.joint_key.address,
            kss_url = %config.kss_url,
            "MPC bridge initialized"
        );

        // 5. Create HTTP client
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| anyhow::anyhow!("failed to create HTTP client: {e}"))?;

        // 6. Resolve the proxy's STABLE long-lived BRC-31 identity (§07.4):
        //    MPC_PROXY_IDENTITY_KEY if provided (needed to match a container's
        //    DKG-time owner binding), else derived from the share material
        //    (zero-config, stable across restarts).
        let identity_bytes = resolve_proxy_identity_bytes(&dkg_result.share.ciphertext)
            .map_err(|e| anyhow::anyhow!("failed to resolve proxy auth identity: {e}"))?;
        let mut bridge_auth = BridgeAuth::from_key_bytes(&identity_bytes)
            .map_err(|e| anyhow::anyhow!("failed to build proxy auth identity: {e}"))?;

        let presign_url = config
            .presign_url
            .clone()
            .unwrap_or_else(|| config.kss_url.clone());

        // 7. Check KSS health + perform BRC-31 handshake
        let health_url = format!("{}/health", config.kss_url);
        match client.get(&health_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!("KSS health check passed");

                // Perform BRC-31 handshake now that we know KSS is reachable
                match bridge_auth.handshake(&client, &config.kss_url).await {
                    Ok(()) => {
                        tracing::info!("BRC-31 handshake with KSS succeeded");
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "BRC-31 handshake failed — requests will be unauthenticated"
                        );
                    }
                }
            }
            Ok(resp) => {
                tracing::warn!(
                    status = %resp.status(),
                    "KSS health check returned non-OK — signing will fail until KSS is available"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "KSS unreachable — signing will fail until KSS is available"
                );
            }
        }

        // 8. Establish the presig-cosigner (`presign_url`) BRC-31 session. Same
        //    identity, separate session when it's a different server than the DO.
        let presign_auth = if presign_url == config.kss_url {
            // Same server — reuse the DO session.
            Arc::new(Mutex::new(bridge_auth))
        } else {
            let do_auth = Arc::new(Mutex::new(bridge_auth));
            let mut cosigner_auth = BridgeAuth::from_key_bytes(&identity_bytes)
                .map_err(|e| anyhow::anyhow!("failed to build cosigner auth identity: {e}"))?;
            match cosigner_auth.handshake(&client, &presign_url).await {
                Ok(()) => {
                    tracing::info!(%presign_url, "BRC-31 handshake with presig cosigner succeeded")
                }
                Err(e) => tracing::warn!(
                    error = %e, %presign_url,
                    "BRC-31 handshake with presig cosigner failed — presig will be unauthenticated"
                ),
            }
            // `auth` (DO) and `presign_auth` (cosigner) are distinct sessions.
            return Ok(Self {
                kss_url: config.kss_url.clone(),
                share: Arc::new(RwLock::new(dkg_result.share)),
                joint_key: dkg_result.joint_key,
                root_pub,
                share_scalar: Arc::new(RwLock::new(share_scalar)),
                vss_points,
                client,
                session_id: dkg_result.session_id,
                participants,
                agent_id,
                auth: do_auth,
                presign_auth: Arc::new(Mutex::new(cosigner_auth)),
                relay_url: config.relay_url.clone(),
                presign_url,
            });
        };

        Ok(Self {
            kss_url: config.kss_url.clone(),
            share: Arc::new(RwLock::new(dkg_result.share)),
            joint_key: dkg_result.joint_key,
            root_pub,
            share_scalar: Arc::new(RwLock::new(share_scalar)),
            vss_points,
            client,
            session_id: dkg_result.session_id,
            participants,
            agent_id,
            auth: presign_auth.clone(),
            presign_auth,
            relay_url: config.relay_url.clone(),
            presign_url,
        })
    }

    /// Current key share (clone). Takes a short read-lock; the §18 hot-swap
    /// ([`apply_refreshed_share`](Self::apply_refreshed_share)) takes the matching
    /// write-lock, so a sign/presign always reads a consistent share.
    fn current_share(&self) -> EncryptedShare {
        self.share
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Current share scalar (Copy) for local partial ECDH.
    fn current_share_scalar(&self) -> [u8; 32] {
        *self.share_scalar.read().unwrap_or_else(|p| p.into_inner())
    }

    /// **§18 rotation-on-commit (hot-swap).** Atomically replace the in-memory
    /// share + derived scalar with the refreshed material so subsequent signs use
    /// the rotated share WITHOUT a restart. The joint pubkey is unchanged (§18
    /// invariant); the new `share_scalar` is re-extracted from the rotated cggmp24
    /// KeyShare. Returns an error (leaving the live share untouched) if the
    /// rotated share is malformed.
    pub fn apply_refreshed_share(&self, rotated: &EncryptedShare) -> bsv_mpc_core::error::Result<()> {
        // Re-derive the local share scalar from the rotated KeyShare JSON.
        let new_scalar = bsv_mpc_core::ecdh::parse_share_scalar(&rotated.ciphertext)
            .map_err(|e| MpcError::Protocol(format!("refresh hot-swap: bad rotated share: {e}")))?;
        // Carry the invariant joint pubkey forward if the rotated share omitted it.
        let mut next = rotated.clone();
        if next.joint_pubkey_compressed.is_empty() {
            next.joint_pubkey_compressed = self.joint_key.compressed.clone();
        }
        {
            let mut s = self.share.write().unwrap_or_else(|p| p.into_inner());
            *s = next;
        }
        {
            let mut sc = self.share_scalar.write().unwrap_or_else(|p| p.into_inner());
            *sc = new_scalar;
        }
        Ok(())
    }

    /// Sign a 32-byte message hash using 2-party threshold ECDSA.
    ///
    /// Creates an ephemeral `SigningCoordinator`, drives it through the 4-round
    /// interactive protocol by exchanging messages with the KSS over HTTP.
    ///
    /// The coordinator runs in `spawn_blocking` because its internal SM bridge
    /// uses synchronous `mpsc` channels. HTTP requests use `handle.block_on`
    /// to bridge back to async.
    ///
    /// # Arguments
    ///
    /// - `message_hash` — The 32-byte SHA-256d sighash to sign.
    /// - `presignature` — Currently unused (presigned path not yet in coordinator).
    /// # Arguments
    ///
    /// - `message_hash` — The 32-byte SHA-256d sighash to sign.
    /// - `presignature` — Currently unused (presigned path not yet in coordinator).
    /// - `hmac_offset` — Optional BRC-42 HMAC offset for derived key signing.
    ///   When set, the signing produces a signature for `root_pub + G * offset`
    ///   rather than the root key. Both proxy and KSS must use the same offset.
    pub async fn sign(
        &self,
        message_hash: &[u8; 32],
        presignature: Option<Presignature>,
        hmac_offset: Option<[u8; 32]>,
    ) -> bsv_mpc_core::error::Result<SigningResult> {
        let share = self.current_share();
        let session_id = self.session_id;
        let threshold_config = share.config;
        let participants = self.participants.clone();
        let kss_url = self.kss_url.clone();
        let client = self.client.clone();
        let agent_id = self.agent_id.clone();
        let auth = self.auth.clone();
        let hash = *message_hash;

        let handle = tokio::runtime::Handle::current();

        tokio::task::spawn_blocking(move || {
            // Create coordinator for this signing operation
            let mut coord =
                SigningCoordinator::new(session_id, share, threshold_config, participants);

            // Initialize signing → get proxy's Round 1 messages
            let proxy_msgs = coord.sign(&hash, presignature, hmac_offset)?;

            tracing::debug!(
                round = 1,
                outgoing = proxy_msgs.len(),
                "signing: initialized, starting KSS session"
            );

            // Start KSS signing session → get KSS's Round 1 message.
            // Send the HMAC offset to KSS so it applies the same additive shift.
            let sign_init_url = format!("{}/sign/init", kss_url);
            let init_resp: SignInitResponse = kss_post(
                &handle,
                &client,
                &sign_init_url,
                "/sign/init",
                &SignInitRequest {
                    agent_id,
                    session_id: session_id.hex(),
                    sighash: hex_encode(&hash),
                    use_presignature: false,
                    hmac_offset: hmac_offset.map(|o| hex_encode(&o)),
                },
                &auth,
            )?;

            tracing::debug!(
                signing_session = %init_resp.signing_session_id,
                total_rounds = init_resp.total_rounds,
                "signing: KSS session started"
            );

            let signing_session_id = init_resp.signing_session_id;
            let sign_round_url = format!("{}/sign/round", kss_url);

            // Bundle proxy's outgoing messages for KSS transport.
            // The KSS bundles its responses too — we pass them directly to
            // the coordinator as single RoundMessages with bundled payloads.
            // The SM thread handles unbundling internally (JSON array of WireMessages).
            let mut kss_msg = init_resp.round_message;
            let mut proxy_bundle = bundle_messages(&proxy_msgs)?;

            loop {
                // Exchange: send proxy's bundled message to KSS, get KSS's next bundled message
                let round_resp: SignRoundResponse = kss_post(
                    &handle,
                    &client,
                    &sign_round_url,
                    "/sign/round",
                    &SignRoundRequest {
                        signing_session_id: signing_session_id.clone(),
                        round_message: proxy_bundle,
                    },
                    &auth,
                )?;

                // Process: feed KSS's bundled message directly to coordinator.
                // The SM thread handles unbundling the JSON array payload internally.
                match coord.process_round(vec![kss_msg])? {
                    SigningRoundResult::NextRound(next_proxy_msgs) => {
                        tracing::debug!(
                            round = coord.current_round(),
                            outgoing = next_proxy_msgs.len(),
                            kss_complete = round_resp.complete,
                            "signing: round complete"
                        );

                        if round_resp.complete {
                            return Err(MpcError::Signing(
                                "KSS completed but coordinator has more rounds".into(),
                            ));
                        }

                        kss_msg = round_resp.round_message.ok_or_else(|| {
                            MpcError::Signing(
                                "KSS returned no round message but signing is not complete".into(),
                            )
                        })?;

                        proxy_bundle = bundle_messages(&next_proxy_msgs)?;
                    }
                    SigningRoundResult::Complete(result) => {
                        tracing::info!("signing: complete");
                        return Ok(result);
                    }
                }
            }
        })
        .await
        .map_err(|e| MpcError::Signing(format!("signing task panicked: {e}")))?
    }

    /// Run the presigning protocol, returning the **raw** presignature output
    /// `(Presignature, Box<dyn Any + Send>)` — the box carries the
    /// non-serializable `PresignaturePublicData` the relay combiner needs.
    ///
    /// Creates an ephemeral `PresigningManager` with pool_size=1 and drives
    /// the 3-round offline protocol by exchanging messages with the KSS.
    ///
    /// Called by the background replenishment task during idle time.
    pub async fn presign_raw(
        &self,
    ) -> bsv_mpc_core::error::Result<(Presignature, Box<dyn std::any::Any + Send>)> {
        let share = self.current_share();
        let session_id = self.session_id;
        let participants = self.participants.clone();
        // ADR-018: presig runs against the heavy-compute cosigner (container),
        // not the wasm DO. Falls back to kss_url when MPC_PRESIGN_URL is unset.
        let kss_url = self.presign_url.clone();
        let client = self.client.clone();
        let agent_id = self.agent_id.clone();
        // The cosigner session (== the DO session when presign_url == kss_url).
        let auth = self.presign_auth.clone();

        let handle = tokio::runtime::Handle::current();

        tokio::task::spawn_blocking(move || {
            // Create a manager with pool_size=1 — we want exactly one presignature
            let mut mgr = PresigningManager::new(session_id, share, participants, 1);

            // Initialize presigning → get proxy's initial messages
            let proxy_msgs = mgr.init_generate()?;

            tracing::debug!(
                outgoing = proxy_msgs.len(),
                "presigning: initialized, starting KSS session"
            );

            // Start KSS presigning session → get KSS's initial messages
            let presign_init_url = format!("{}/presign/init", kss_url);
            let init_resp: PresignInitResponse = kss_post(
                &handle,
                &client,
                &presign_init_url,
                "/presign/init",
                &PresignInitRequest {
                    agent_id,
                    session_id: session_id.hex(),
                    count: 1,
                },
                &auth,
            )?;

            tracing::debug!(
                presign_session = %init_resp.presign_session_id,
                total_rounds = init_resp.total_rounds,
                kss_messages = init_resp.round_messages.len(),
                "presigning: KSS session started"
            );

            let presign_session_id = init_resp.presign_session_id;
            let presign_round_url = format!("{}/presign/round", kss_url);

            // State: proxy has proxy_R1 messages, KSS returned KSS_R1 messages
            let mut kss_msgs = init_resp.round_messages;
            let mut proxy_wire_msgs = proxy_msgs;

            loop {
                // Exchange: send proxy messages to KSS, get next KSS messages
                let round_resp: PresignRoundResponse = kss_post(
                    &handle,
                    &client,
                    &presign_round_url,
                    "/presign/round",
                    &PresignRoundRequest {
                        presign_session_id: presign_session_id.clone(),
                        round_messages: proxy_wire_msgs,
                    },
                    &auth,
                )?;

                // Process: feed KSS's previous messages to manager
                match mgr.process_generate_round(kss_msgs)? {
                    PresigningRoundResult::NextRound(next_msgs) => {
                        tracing::debug!(
                            outgoing = next_msgs.len(),
                            kss_complete = round_resp.complete,
                            "presigning: round complete"
                        );

                        if round_resp.complete {
                            return Err(MpcError::Protocol(
                                "KSS completed presigning but manager has more rounds".into(),
                            ));
                        }

                        kss_msgs = round_resp.round_messages.ok_or_else(|| {
                            MpcError::Protocol(
                                "KSS returned no messages but presigning is not complete".into(),
                            )
                        })?;
                        proxy_wire_msgs = next_msgs;
                    }
                    PresigningRoundResult::Complete => {
                        // Presignature added to manager's internal pool — take
                        // the raw output (Presignature + PresignaturePublicData).
                        let (presig, raw) = mgr.take_raw().ok_or_else(|| {
                            MpcError::Protocol(
                                "presigning completed but no presignature in pool".into(),
                            )
                        })?;
                        tracing::info!(presig_id = %presig.id, "presigning: complete");
                        return Ok((presig, raw));
                    }
                }
            }
        })
        .await
        .map_err(|e| MpcError::Protocol(format!("presigning task panicked: {e}")))?
    }

    /// Compute ECDH(counterparty_pub, root_priv) without reconstructing root_priv.
    ///
    /// Uses threshold partial ECDH: each party computes `counterparty_pub * share_i`,
    /// then results are combined with Lagrange interpolation at x=0.
    ///
    /// Flow (for 2-of-2):
    /// 1. Proxy computes locally: `partial_B = counterparty_pub * share_B`
    /// 2. Proxy sends counterparty_pub to KSS: `POST /ecdh`
    /// 3. KSS computes: `partial_A = counterparty_pub * share_A`
    /// 4. KSS returns: `partial_A`
    /// 5. Proxy combines: `shared_secret = λ_0 * partial_A + λ_1 * partial_B`
    ///
    /// Proven in POC 3 (key derivation) and POC 8 (BRC-31 auth).
    pub async fn partial_ecdh(
        &self,
        counterparty_pub: &PublicKey,
    ) -> bsv_mpc_core::error::Result<PublicKey> {
        let my_index = self.current_share().share_index.0 as usize;

        // Build partials from all participating parties
        let mut partials: Vec<(PublicKey, [u8; 32])> = Vec::new();

        for &p in &self.participants {
            let p_idx = p as usize;
            if p_idx == my_index {
                // Local computation: counterparty_pub * our_share_scalar
                let partial =
                    ecdh::compute_partial_ecdh_point(counterparty_pub, &self.current_share_scalar())?;
                partials.push((partial, self.vss_points[p_idx]));
            } else {
                // Remote (KSS): POST /ecdh
                let partial = self.kss_ecdh(counterparty_pub).await?;
                partials.push((partial, self.vss_points[p_idx]));
            }
        }

        // Combine with Lagrange interpolation
        ecdh::combine_partials_lagrange(&partials)
    }

    /// Send a partial ECDH request to the KSS.
    async fn kss_ecdh(
        &self,
        counterparty_pub: &PublicKey,
    ) -> bsv_mpc_core::error::Result<PublicKey> {
        let url = format!("{}/ecdh", self.kss_url);
        let req = EcdhRequest {
            agent_id: self.agent_id.clone(),
            counterparty_pub: hex_encode(&counterparty_pub.to_compressed()),
        };
        // Serialize once; sign over + send the exact bytes (canonical BRC-104).
        let body_bytes = serde_json::to_vec(&req)
            .map_err(|e| MpcError::Serialization(format!("serialize /ecdh request: {e}")))?;
        let mut builder = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .body(body_bytes.clone());

        // Add canonical BRC-31 auth headers if authenticated.
        {
            let auth_guard = self
                .auth
                .lock()
                .map_err(|e| MpcError::Protocol(format!("auth lock poisoned: {e}")))?;
            if auth_guard.is_authenticated() {
                for (name, value) in auth_guard.auth_header_pairs("POST", "/ecdh", &body_bytes)? {
                    builder = builder.header(name, value);
                }
            }
        }

        let resp = builder
            .send()
            .await
            .map_err(|e| MpcError::Protocol(format!("KSS /ecdh request failed: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(MpcError::Protocol(format!(
                "KSS /ecdh returned {status}: {body_text}"
            )));
        }

        let ecdh_resp: EcdhResponse = resp
            .json()
            .await
            .map_err(|e| MpcError::Protocol(format!("KSS /ecdh response parse: {e}")))?;

        let partial_bytes = hex_decode(&ecdh_resp.partial)?;
        PublicKey::from_bytes(&partial_bytes)
            .map_err(|e| MpcError::Protocol(format!("KSS returned invalid partial point: {e}")))
    }

    /// Derive a BRC-42 symmetric key for any counterparty type.
    ///
    /// - `"anyone"`: Local computation only (0 KSS round-trips).
    /// - `"self"`: 2 partial ECDH rounds with KSS.
    /// - hex pubkey: 2 partial ECDH rounds with KSS.
    ///
    /// Returns a 32-byte symmetric key compatible with the BSV SDK's
    /// `KeyDeriver::derive_symmetric_key()`. Proven in POC 9.
    pub async fn derive_symmetric_key(
        &self,
        counterparty: &str,
        level: u8,
        protocol_name: &str,
        key_id: &str,
    ) -> bsv_mpc_core::error::Result<[u8; 32]> {
        match counterparty {
            "anyone" => {
                ecdh::derive_symmetric_key_anyone(&self.root_pub, level, protocol_name, key_id)
            }
            _ => {
                // For "self" and "other(hex_pubkey)": 2-round partial ECDH
                let counterparty_pub = if counterparty == "self" {
                    self.root_pub.clone()
                } else {
                    let bytes = hex_decode(counterparty)?;
                    PublicKey::from_bytes(&bytes).map_err(|e| {
                        MpcError::Protocol(format!("invalid counterparty pubkey: {e}"))
                    })?
                };

                let invoice = compute_invoice(level, protocol_name, key_id)?;

                // Round 1: base ECDH — counterparty_pub * root_priv
                let shared_secret = self.partial_ecdh(&counterparty_pub).await?;

                // Compute child_counter_pub = counterparty_pub + G * hmac
                let child_counter_pub =
                    derive_child_pubkey(&counterparty_pub, &shared_secret, &invoice)?;

                // Round 2: root_priv * child_counter_pub
                let root_times_child = self.partial_ecdh(&child_counter_pub).await?;

                // Final local computation: combine into symmetric key
                ecdh::derive_symmetric_key_from_partials(
                    &counterparty_pub,
                    &shared_secret,
                    &root_times_child,
                    &invoice,
                )
            }
        }
    }

    /// Derive a BRC-42 child public key for any counterparty type.
    ///
    /// - `"anyone"`: Local derivation (0 KSS round-trips).
    /// - `"self"` / hex pubkey: 1 partial ECDH round with KSS.
    ///
    /// Returns the derived public key. For `for_self=true`, derives from
    /// root_pub. For `for_self=false`, derives from counterparty_pub.
    pub async fn derive_child_key(
        &self,
        counterparty: &str,
        level: u8,
        protocol_name: &str,
        key_id: &str,
        for_self: bool,
    ) -> bsv_mpc_core::error::Result<PublicKey> {
        let invoice = compute_invoice(level, protocol_name, key_id)?;

        match counterparty {
            "anyone" => {
                // shared_secret = root_pub for "anyone"
                let base = if for_self {
                    &self.root_pub
                } else {
                    // anyone_pub = G (generator, private key = 1)
                    let mut one = [0u8; 32];
                    one[31] = 1;
                    &PublicKey::from_scalar_mul_generator(&one).map_err(|e| {
                        MpcError::Protocol(format!("generator computation failed: {e}"))
                    })?
                };
                derive_child_pubkey(base, &self.root_pub, &invoice)
            }
            _ => {
                let counterparty_pub = if counterparty == "self" {
                    self.root_pub.clone()
                } else {
                    let bytes = hex_decode(counterparty)?;
                    PublicKey::from_bytes(&bytes).map_err(|e| {
                        MpcError::Protocol(format!("invalid counterparty pubkey: {e}"))
                    })?
                };

                // 1 partial ECDH round to get shared_secret
                let shared_secret = self.partial_ecdh(&counterparty_pub).await?;

                let base = if for_self {
                    &self.root_pub
                } else {
                    &counterparty_pub
                };
                derive_child_pubkey(base, &shared_secret, &invoice)
            }
        }
    }

    /// **§06.17.1 coordinator-holds-ciphertext presign (issue #30, CONTAINER
    /// target)** — run the presign over the relay as the coordinator against the
    /// deployed CF Container cosigner (`presign_url`), assembling + persisting the
    /// `PresigBundle` to `bundle_store`. The container generates + BRC-2
    /// self-encrypts its OWN presig share and ships the opaque ciphertext back;
    /// the proxy never holds the container's plaintext share.
    pub async fn coordinate_presign_bundle(
        &self,
        bundle_store: std::sync::Arc<bsv_mpc_service::FileBundleStore>,
        at_rest_root: [u8; 32],
        policy_id: bsv_mpc_core::types::PolicyId,
        timeout: std::time::Duration,
    ) -> bsv_mpc_core::error::Result<bsv_mpc_core::types::PresigBundle> {
        let identity_priv = {
            let auth = self
                .auth
                .lock()
                .map_err(|_| MpcError::Protocol("auth mutex poisoned".into()))?;
            auth.auth_key().clone()
        };
        // The proxy is the coordinator; the container is the cosigner.
        let coordinator_party = self.current_share().share_index.0;
        let cosigner_party = self.cosigner_index();
        let parties_at_keygen: Vec<u16> = {
            let mut p = self.participants.clone();
            p.sort_unstable();
            p
        };
        // Ensure the proxy's share carries the 33-byte joint pubkey (presign needs it).
        let mut share = self.current_share();
        if share.joint_pubkey_compressed.len() != 33 {
            share.joint_pubkey_compressed = self.joint_key.compressed.clone();
        }
        // Fresh presign session id (canonical 32-byte hex), bound to the joint key.
        let presign_session = {
            use rand::RngCore;
            let mut seed = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            SessionId::from_str_hash(&format!("presig-{}-{}", self.agent_id, hex_encode(&seed)))
        };

        // BRC-31 sign the container's `/presign-relay/init` over the canonical
        // wire (the cosigner session — same identity, container-scoped session).
        let presign_auth = self.presign_auth.clone();
        let request_signer = move |method: &str,
                                   path: &str,
                                   body: &[u8]|
              -> bsv_mpc_core::error::Result<Vec<(String, String)>> {
            let guard = presign_auth
                .lock()
                .map_err(|_| MpcError::Protocol("presign auth mutex poisoned".into()))?;
            if !guard.is_authenticated() {
                return Ok(vec![]);
            }
            Ok(guard
                .auth_header_pairs(method, path, body)?
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect())
        };

        crate::relay_presign::coordinate_presign_over_relay(
            &self.relay_url,
            identity_priv,
            share,
            coordinator_party,
            cosigner_party,
            parties_at_keygen,
            policy_id,
            at_rest_root,
            presign_session,
            bundle_store,
            crate::relay_presign::CosignerArm {
                url: format!("{}/presign-relay/init", self.presign_url),
                agent_id: self.agent_id.clone(),
            },
            &request_signer,
            timeout,
        )
        .await
    }

    /// **§18.2 key-refresh over the relay + rotation-on-commit (issue #10d /
    /// #22 ShareRefresh trigger), CONTAINER target.**
    ///
    /// Runs the distributed PSS refresh against the deployed container peer, then,
    /// atomically on commit:
    /// 1. **Hot-swaps** the proxy's in-memory share with the rotated one
    ///    ([`apply_refreshed_share`](Self::apply_refreshed_share)) — no restart.
    /// 2. **Persists** the rotated `DkgResult` to `share_path` (re-encrypted with
    ///    `encryption_key` when set), so a later restart loads the rotated share.
    /// 3. Fires the §06.18 **ShareRefresh invalidation**: purges every presig
    ///    bundle for this joint pubkey (zeroized) + records the
    ///    `bundles_invalidated_total{reason=refresh}` metric — no presig generated
    ///    against the dead share survives the boundary.
    ///
    /// The joint pubkey is unchanged (the §18 invariant), so no funds move.
    /// Returns `(joint_pubkey_hex, purged_bundles)`.
    #[allow(clippy::too_many_arguments)]
    pub async fn refresh_over_relay(
        &self,
        share_path: &str,
        encryption_key: Option<&[u8; 32]>,
        bundle_store: std::sync::Arc<bsv_mpc_service::FileBundleStore>,
        presign_manager: std::sync::Arc<RwLock<crate::presign_manager::PresignManager>>,
        timeout: std::time::Duration,
    ) -> bsv_mpc_core::error::Result<(String, u64)> {
        use bsv_mpc_service::BundleStore;

        let identity_priv = {
            let auth = self
                .auth
                .lock()
                .map_err(|_| MpcError::Protocol("auth mutex poisoned".into()))?;
            auth.auth_key().clone()
        };
        let my_party = self.current_share().share_index.0;
        let peer_party = self.cosigner_index();
        let parties_at_keygen: Vec<u16> = {
            let mut p = self.participants.clone();
            p.sort_unstable();
            p
        };
        // Ensure the proxy's share carries the 33-byte joint pubkey for the refresh.
        let mut share = self.current_share();
        if share.joint_pubkey_compressed.len() != 33 {
            share.joint_pubkey_compressed = self.joint_key.compressed.clone();
        }
        let refresh_session = {
            use rand::RngCore;
            let mut seed = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            SessionId::from_str_hash(&format!("refresh-{}-{}", self.agent_id, hex_encode(&seed)))
        };

        let presign_auth = self.presign_auth.clone();
        let request_signer = move |method: &str,
                                   path: &str,
                                   body: &[u8]|
              -> bsv_mpc_core::error::Result<Vec<(String, String)>> {
            let guard = presign_auth
                .lock()
                .map_err(|_| MpcError::Protocol("presign auth mutex poisoned".into()))?;
            if !guard.is_authenticated() {
                return Ok(vec![]);
            }
            Ok(guard
                .auth_header_pairs(method, path, body)?
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect())
        };

        let commit = crate::relay_refresh::coordinate_refresh_over_relay(
            &self.relay_url,
            identity_priv,
            share,
            my_party,
            peer_party,
            parties_at_keygen,
            refresh_session,
            crate::relay_refresh::PeerArm {
                url: format!("{}/refresh-relay/init", self.presign_url),
                agent_id: self.agent_id.clone(),
            },
            &request_signer,
            timeout,
        )
        .await?;

        // 1. Hot-swap the in-memory share.
        self.apply_refreshed_share(&commit.rotated_share)?;

        // 2. Persist the rotated DkgResult to disk (so a restart loads it too).
        self.persist_rotated_share(share_path, encryption_key, &commit.rotated_share)?;

        // 3. §06.18 ShareRefresh invalidation: purge every bundle for this jpk.
        let purged = bundle_store
            .invalidate(&bsv_mpc_core::types::InvalidationTrigger::ShareRefresh {
                joint_pubkey: &commit.joint_pubkey_compressed,
            })
            .map_err(|e| MpcError::Protocol(format!("refresh: bundle invalidation failed: {e}")))?;
        if let Ok(mut mgr) = presign_manager.write() {
            mgr.record_invalidation(crate::burn_rate::InvalidationReason::Refresh, purged);
        }
        tracing::info!(
            agent_id = %self.agent_id,
            purged_bundles = purged,
            "refresh-over-relay: share hot-swapped + persisted, {purged} presig bundles invalidated (§06.18 refresh)"
        );

        Ok((hex_encode(&commit.joint_pubkey_compressed), purged))
    }

    /// Write the rotated `DkgResult` to `share_path` atomically (temp + rename),
    /// matching the on-disk format `MpcBridge::new` reads: a plaintext
    /// `DkgResult` JSON, or — when `encryption_key` is set — an `EncryptedShare`
    /// envelope wrapping the encrypted `DkgResult`.
    fn persist_rotated_share(
        &self,
        share_path: &str,
        encryption_key: Option<&[u8; 32]>,
        rotated: &EncryptedShare,
    ) -> bsv_mpc_core::error::Result<()> {
        let dkg = bsv_mpc_core::types::DkgResult {
            joint_key: self.joint_key.clone(),
            share: rotated.clone(),
            session_id: self.session_id,
        };
        let dkg_json = serde_json::to_vec(&dkg)
            .map_err(|e| MpcError::Serialization(format!("serialize rotated DkgResult: {e}")))?;
        let bytes = match encryption_key {
            Some(key) => {
                let mut envelope = bsv_mpc_core::share::encrypt_share(&dkg_json, key)?;
                // `encrypt_share` leaves the envelope's metadata as sentinels;
                // populate them from the rotated share so the on-disk envelope
                // passes `validate_encrypted_share` on reload (decrypt validates).
                envelope.session_id = rotated.session_id;
                envelope.share_index = rotated.share_index;
                envelope.config = rotated.config;
                envelope.joint_pubkey_compressed = self.joint_key.compressed.clone();
                serde_json::to_vec(&envelope).map_err(|e| {
                    MpcError::Serialization(format!("serialize encrypted share envelope: {e}"))
                })?
            }
            None => dkg_json,
        };
        let tmp = format!("{share_path}.tmp");
        std::fs::write(&tmp, &bytes)
            .map_err(|e| MpcError::Protocol(format!("write rotated share {tmp}: {e}")))?;
        std::fs::rename(&tmp, share_path)
            .map_err(|e| MpcError::Protocol(format!("rename rotated share into {share_path}: {e}")))?;
        Ok(())
    }

    /// The current §06.17.1 binding triple `(policy_id, joint_pubkey,
    /// parties_at_keygen)` a bundle must match to be consumable.
    pub fn current_binding(
        &self,
        policy_id: bsv_mpc_core::types::PolicyId,
    ) -> bsv_mpc_core::types::PresigBinding {
        let mut parties = self.participants.clone();
        parties.sort_unstable();
        bsv_mpc_core::types::PresigBinding {
            policy_id,
            joint_pubkey: self.joint_key.compressed.clone(),
            parties_at_keygen: parties,
        }
    }

    /// **§06.17.3 single-use consume + §06.18 consume-time guard.** Atomically
    /// remove the bundle for `presig_id` from `bundle_store` (so it can NEVER be
    /// consumed twice — the CVE-2025-66017 mitigation) and re-check its binding
    /// triple against the current ceremony (defense in depth: a stale bundle that
    /// somehow escaped a §06.18 deletion still cannot be signed). On a binding
    /// mismatch the bundle stays removed (it is dead either way) and signing is
    /// refused.
    pub fn consume_bundle_for_sign(
        &self,
        bundle_store: &bsv_mpc_service::FileBundleStore,
        presig_id: &str,
        current_policy: bsv_mpc_core::types::PolicyId,
    ) -> bsv_mpc_core::error::Result<bsv_mpc_core::types::PresigBundle> {
        use bsv_mpc_service::BundleStore;
        let bundle = bundle_store
            .consume(presig_id)
            .map_err(|e| MpcError::Protocol(format!("bundle consume failed: {e}")))?
            .ok_or_else(|| {
                MpcError::Protocol(format!(
                    "presig bundle {presig_id} already consumed or absent (single-use §06.17.3)"
                ))
            })?;
        let current = self.current_binding(current_policy);
        if !bundle.matches_binding(&current) {
            return Err(MpcError::Protocol(format!(
                "presig bundle {presig_id} failed the §06.18 consume-time binding check \
                 (stale policy/joint-pubkey/subset); refusing to sign (bundle now purged)"
            )));
        }
        Ok(bundle)
    }

    /// **§06.17.1 sign-from-bundle over the relay (issue #30, CONTAINER target)**
    /// — at sign-time, reconstruct the coordinator's own partial from the durable
    /// `bundle` + ship the container's OWN ciphertext to its `/sign-relay`; the
    /// container decrypts it under its own identity, issues + relays its partial,
    /// and the proxy combines into the final signature. Base key only.
    pub async fn sign_from_bundle_over_relay(
        &self,
        sighash: &[u8; 32],
        bundle: &bsv_mpc_core::types::PresigBundle,
        at_rest_root: [u8; 32],
        recv_timeout: std::time::Duration,
    ) -> bsv_mpc_core::error::Result<SigningResult> {
        let identity_priv = {
            let auth = self
                .auth
                .lock()
                .map_err(|_| MpcError::Protocol("auth mutex poisoned".into()))?;
            auth.auth_key().clone()
        };
        // Unseal the coordinator's own presig share from the durable bundle.
        let at_rest_key =
            bsv_mpc_core::presig_at_rest::derive_presig_at_rest_key(&at_rest_root, &bundle.presig_id);
        let own_presig_json =
            bsv_mpc_core::presig_at_rest::unseal_presig_bytes(&bundle.presig_bytes, &at_rest_key)
                .map_err(|e| MpcError::Protocol(format!("unseal own presig share: {e}")))?;

        // The container's positional ciphertext slot (= its keygen-subset index).
        let cosigner_party = self.cosigner_index();
        let pos = bundle
            .parties_at_keygen
            .iter()
            .position(|&p| p == cosigner_party)
            .ok_or_else(|| {
                MpcError::Protocol(format!(
                    "cosigner party {cosigner_party} not in bundle parties {:?}",
                    bundle.parties_at_keygen
                ))
            })?;
        let cosigner_ct = bundle.cosigner_encrypted_shares[pos].clone().into_vec();
        if cosigner_ct.is_empty() {
            return Err(MpcError::Protocol(
                "bundle has no cosigner ciphertext at the container's positional slot".into(),
            ));
        }

        // Per-sign correlation session id (relay routing label).
        let sign_session = {
            use rand::RngCore;
            let mut seed = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            SessionId::from_str_hash(&format!("relay-sign-{}", hex_encode(&seed)))
        };

        let auth_for_sign = self.presign_auth.clone();
        let request_signer = move |method: &str,
                                   path: &str,
                                   body: &[u8]|
              -> bsv_mpc_core::error::Result<Vec<(String, String)>> {
            let guard = auth_for_sign
                .lock()
                .map_err(|_| MpcError::Protocol("presign auth mutex poisoned".into()))?;
            if !guard.is_authenticated() {
                return Ok(vec![]);
            }
            Ok(guard
                .auth_header_pairs(method, path, body)?
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect())
        };

        let trigger = crate::relay_sign::DoTrigger {
            url: format!("{}/sign-relay", self.presign_url),
            presig_a_json: vec![],
            do_index: cosigner_party,
            agent_id: Some(self.agent_id.clone()),
            auth_headers: vec![],
            cosigner_encrypted_share: None,
        };

        crate::relay_sign::combine_sign_from_bundle_over_relay(
            &self.relay_url,
            identity_priv,
            self.current_share(),
            self.participants.clone(),
            self.current_share().config,
            sign_session,
            sighash,
            &own_presig_json,
            &bundle.commitments,
            cosigner_ct,
            &bundle.presig_id,
            &self.joint_key,
            trigger,
            Some(&request_signer),
            recv_timeout,
        )
        .await
    }

    /// **ADR-018 relay sign (#12)** — combine the deployed DO's partial over
    /// the MessageBox relay into a final signature, with this proxy as the
    /// combiner.
    ///
    /// The proxy holds `share_B` + `my_presig_box` (its own `(Presignature,
    /// PresignaturePublicData)` from the presign pool, correlated with the DO's
    /// `Presignature_A` at generation). It dials the relay with its local auth
    /// identity, triggers the DO to issue + relay party-`trigger.do_index`'s
    /// partial, and combines. Delegates to the deployed-proven
    /// [`crate::relay_sign::combine_sign_over_relay`].
    pub async fn sign_over_relay(
        &self,
        sighash: &[u8; 32],
        my_presig_box: Box<dyn std::any::Any + Send>,
        trigger: crate::relay_sign::DoTrigger,
        recv_timeout: std::time::Duration,
    ) -> bsv_mpc_core::error::Result<SigningResult> {
        let identity_priv = {
            let auth = self
                .auth
                .lock()
                .map_err(|_| MpcError::Protocol("auth mutex poisoned".into()))?;
            auth.auth_key().clone()
        };
        // Canonical `/sign-relay` auth: the trigger body is serialized inside
        // `combine_sign_over_relay`, so we pass a signer closure (capturing our
        // worker BRC-31 session) that signs the EXACT serialized body there. The
        // deployed worker verifies the canonical wire (§07).
        let auth_for_sign = self.auth.clone();
        let request_signer = move |method: &str,
                                   path: &str,
                                   body: &[u8]|
              -> bsv_mpc_core::error::Result<Vec<(String, String)>> {
            let guard = auth_for_sign
                .lock()
                .map_err(|_| MpcError::Protocol("auth mutex poisoned".into()))?;
            Ok(guard
                .auth_header_pairs(method, path, body)?
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect())
        };
        // Fresh, unique session id PER SIGN — it correlates this sign's §05
        // relay envelope so the combiner can filter out stale/other partials on
        // the shared `mpc-sign` box (the crypto is presig-based + session-
        // agnostic, so a per-sign id is purely a routing/correlation label).
        let sign_session = {
            use rand::RngCore;
            let mut seed = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            SessionId::from_str_hash(&format!("relay-sign-{}", hex_encode(&seed)))
        };
        crate::relay_sign::combine_sign_over_relay(
            &self.relay_url,
            identity_priv,
            self.current_share(),
            self.participants.clone(),
            self.current_share().config,
            sign_session,
            sighash,
            my_presig_box,
            &self.joint_key,
            trigger,
            Some(&request_signer),
            recv_timeout,
        )
        .await
    }

    /// **#14/#6 provisioning** — POST a serialized `Presignature_A` into the
    /// deployed DO's presignature pool via the authed `/ceremony/ingest-presig`
    /// route, so a subsequent authed `/sign-relay` can consume it (the DO never
    /// receives `PresignaturePublicData`; only the serializable `Presignature`).
    ///
    /// The proxy must hold a live BRC-31 session with the KSS (established in
    /// [`MpcBridge::new`]); the request is signed with the proxy's stable owner
    /// identity. The correlated `Presignature_B` stays in the proxy's own pool.
    pub async fn provision_presig_to_do(
        &self,
        agent_id: &str,
        presig_a_json: &[u8],
        session_id: &str,
        presig_id: &str,
    ) -> bsv_mpc_core::error::Result<()> {
        let path = "/ceremony/ingest-presig";
        let url = format!("{}{path}", self.kss_url);
        // `agent_id` (joint key) keys the DO pool — it must match the joint key
        // the subsequent `/sign-relay` consumes from (#7 finding 5 segregation).
        let body = serde_json::json!({
            "agent_id": agent_id,
            "session_id": session_id,
            "presig_id": presig_id,
            "presignature_hex": hex_encode(presig_a_json),
        });
        // Serialize once; sign over + send the exact bytes (canonical BRC-104).
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| MpcError::Serialization(format!("serialize ingest-presig: {e}")))?;
        let mut builder = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .body(body_bytes.clone());
        {
            let auth = self
                .auth
                .lock()
                .map_err(|_| MpcError::Protocol("auth mutex poisoned".into()))?;
            if !auth.is_authenticated() {
                return Err(MpcError::Protocol(
                    "proxy not authenticated with KSS — cannot provision presig".into(),
                ));
            }
            for (name, value) in auth.auth_header_pairs("POST", path, &body_bytes)? {
                builder = builder.header(name, value);
            }
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| MpcError::Protocol(format!("ingest-presig request: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let txt = resp.text().await.unwrap_or_default();
            return Err(MpcError::Protocol(format!(
                "ingest-presig returned {status}: {txt}"
            )));
        }
        Ok(())
    }

    /// Get the root BSV PublicKey.
    pub fn root_pub(&self) -> &PublicKey {
        &self.root_pub
    }

    /// Get the joint public key.
    ///
    /// This is the secp256k1 compressed public key that can receive BSV
    /// at a standard P2PKH address. It was computed during the DKG ceremony.
    pub fn joint_public_key(&self) -> &JointPublicKey {
        &self.joint_key
    }

    /// Get the current MPC session ID.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Get the KSS URL.
    pub fn kss_url(&self) -> &str {
        &self.kss_url
    }

    /// Get the agent identity (hex-encoded compressed joint public key).
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// The cosigner (KSS / deployed DO) party's signing-time index — the `from`
    /// index its relay partial carries. For the 2-party setup this is the
    /// participant that is not this proxy's own share index.
    pub fn cosigner_index(&self) -> u16 {
        let me = self.current_share().share_index.0;
        self.participants
            .iter()
            .copied()
            .find(|&p| p != me)
            .unwrap_or(0)
    }

    /// Whether relay-mode signing is enabled (config `MPC_RELAY_SIGN`).
    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    /// Create a bridge with a known joint key for testing.
    /// No KSS connection is established — only `joint_public_key()` and local
    /// derivation methods are usable. Partial ECDH (requiring KSS) will fail.
    #[cfg(test)]
    pub fn new_for_test(joint_key: JointPublicKey) -> Self {
        let agent_id = hex_encode(&joint_key.compressed);
        let root_pub =
            PublicKey::from_bytes(&joint_key.compressed).expect("test joint key must be valid");
        Self {
            kss_url: "http://localhost:9999".into(),
            share: Arc::new(RwLock::new(EncryptedShare {
                nonce: vec![0u8; 12],
                ciphertext: vec![0u8; 1],
                session_id: SessionId::from_str_hash("test"),
                share_index: ShareIndex(0),
                config: ThresholdConfig {
                    threshold: 2,
                    parties: 2,
                },
                joint_pubkey_compressed: Vec::new(),
            })),
            joint_key,
            root_pub,
            share_scalar: Arc::new(RwLock::new([0u8; 32])),
            vss_points: vec![[0u8; 32]; 2],
            client: reqwest::Client::new(),
            session_id: SessionId::from_str_hash("test"),
            participants: vec![0, 1],
            agent_id,
            auth: Arc::new(Mutex::new(BridgeAuth::new().expect("test auth key"))),
            presign_auth: Arc::new(Mutex::new(BridgeAuth::new().expect("test auth key"))),
            relay_url: "https://rust-message-box.dev-a3e.workers.dev".into(),
            presign_url: "http://localhost:9999".into(),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn hex_encode_known_values() {
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0xff]), "ff");
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(
            hex_encode(&[0u8; 32]),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn hex_decode_known_values() {
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(hex_decode("00").unwrap(), vec![0x00]);
        assert_eq!(hex_decode("ff").unwrap(), vec![0xff]);
        assert_eq!(
            hex_decode("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(hex_decode("FF").unwrap(), vec![0xff]);
    }

    #[test]
    fn hex_decode_odd_length() {
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn hex_decode_invalid_chars() {
        assert!(hex_decode("zz").is_err());
    }

    #[test]
    fn hex_roundtrip() {
        let original = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe];
        let encoded = hex_encode(&original);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn sign_init_request_serializes() {
        let req = SignInitRequest {
            agent_id: "02abc123".into(),
            session_id: "sess-1".into(),
            sighash: "ff".repeat(32),
            use_presignature: false,
            hmac_offset: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["agent_id"], "02abc123");
        assert_eq!(json["session_id"], "sess-1");
        assert_eq!(json["use_presignature"], false);
    }

    #[test]
    fn sign_round_response_deserializes_with_message() {
        let json = serde_json::json!({
            "signing_session_id": "sign-1",
            "round_message": {
                "session_id": "0000000000000000000000000000000000000000000000000000000000000001",
                "round": 1,
                "from": 0,
                "to": null,
                "payload": [1, 2, 3]
            },
            "complete": false
        });
        let resp: SignRoundResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.signing_session_id, "sign-1");
        assert!(!resp.complete);
        assert!(resp.round_message.is_some());
    }

    #[test]
    fn sign_round_response_deserializes_complete() {
        let json = serde_json::json!({
            "signing_session_id": "sign-1",
            "round_message": null,
            "complete": true
        });
        let resp: SignRoundResponse = serde_json::from_value(json).unwrap();
        assert!(resp.complete);
        assert!(resp.round_message.is_none());
    }

    #[test]
    fn presign_round_response_deserializes() {
        let json = serde_json::json!({
            "presign_session_id": "ps-1",
            "round_messages": [{
                "session_id": "0000000000000000000000000000000000000000000000000000000000000001",
                "round": 1,
                "from": 0,
                "to": null,
                "payload": [10, 20]
            }],
            "complete": false
        });
        let resp: PresignRoundResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.presign_session_id, "ps-1");
        assert!(!resp.complete);
        assert!(resp.round_messages.is_some());
        assert_eq!(resp.round_messages.unwrap().len(), 1);
    }

    /// Test MpcBridge::new() with a plaintext DkgResult share file.
    #[tokio::test]
    async fn new_loads_plaintext_share() {
        // Use a valid secp256k1 compressed pubkey (G * 1 = generator point)
        let valid_pub = bsv::primitives::ec::PublicKey::from_scalar_mul_generator(&{
            let mut one = [0u8; 32];
            one[31] = 1;
            one
        })
        .unwrap();
        let dkg_result = DkgResult {
            joint_key: JointPublicKey {
                compressed: valid_pub.to_compressed().to_vec(),
                address: "1TestAddress".into(),
            },
            share: EncryptedShare {
                nonce: vec![0u8; 12],
                ciphertext: vec![1, 2, 3, 4, 5],
                session_id: SessionId::from_str_hash("test-session-123"),
                share_index: ShareIndex(1),
                config: ThresholdConfig {
                    threshold: 2,
                    parties: 2,
                },
                joint_pubkey_compressed: Vec::new(),
            },
            session_id: SessionId::from_str_hash("test-session-123"),
        };

        let dir = std::env::temp_dir();
        let share_path = dir.join("bridge_test_share.json");
        let json = serde_json::to_vec_pretty(&dkg_result).unwrap();
        tokio::fs::write(&share_path, &json).await.unwrap();

        let config = ProxyConfig {
            port: 3322,
            kss_url: "http://localhost:9999".into(), // won't actually connect
            share_path: share_path.to_string_lossy().to_string(),
            fee_per_signing: 0,
            fee_addresses: vec![],
            fee_threshold: None,
            max_presignatures: 5,
            encryption_key: None,
            arc_api_key: "test_key".into(),
            threshold_configs: vec!["2-of-2".to_string()],
            min_balance_sats: None,
            relay_url: "https://rust-message-box.dev-a3e.workers.dev".into(),
            relay_sign: false,
            presign_url: None,
        };

        let bridge = MpcBridge::new(&config).await.unwrap();
        assert_eq!(bridge.joint_public_key().address, "1TestAddress");
        assert_eq!(
            bridge.session_id(),
            &SessionId::from_str_hash("test-session-123")
        );
        assert_eq!(bridge.kss_url(), "http://localhost:9999");
        assert_eq!(bridge.participants, vec![0, 1]);

        // Cleanup
        let _ = tokio::fs::remove_file(&share_path).await;
    }

    /// Test MpcBridge::new() with a missing share file.
    #[tokio::test]
    async fn new_fails_on_missing_file() {
        let config = ProxyConfig {
            port: 3322,
            kss_url: "http://localhost:9999".into(),
            share_path: "/tmp/nonexistent_share_abc123.json".into(),
            fee_per_signing: 0,
            fee_addresses: vec![],
            fee_threshold: None,
            max_presignatures: 5,
            encryption_key: None,
            arc_api_key: "test_key".into(),
            threshold_configs: vec!["2-of-2".to_string()],
            min_balance_sats: None,
            relay_url: "https://rust-message-box.dev-a3e.workers.dev".into(),
            relay_sign: false,
            presign_url: None,
        };

        let result = MpcBridge::new(&config).await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.err().unwrap());
        assert!(err_msg.contains("failed to read share file"));
    }

    /// Test that participants are derived correctly for different configs.
    #[tokio::test]
    async fn new_derives_participants_for_threshold() {
        // 2-of-3 with share_index=2 → participants should be [0, 2]
        let dkg_result = DkgResult {
            joint_key: JointPublicKey {
                compressed: vec![0x02; 33],
                address: "1Test".into(),
            },
            share: EncryptedShare {
                nonce: vec![0u8; 12],
                ciphertext: vec![1, 2, 3],
                session_id: SessionId::from_str_hash("test"),
                share_index: ShareIndex(2),
                config: ThresholdConfig {
                    threshold: 2,
                    parties: 3,
                },
                joint_pubkey_compressed: Vec::new(),
            },
            session_id: SessionId::from_str_hash("test"),
        };

        let dir = std::env::temp_dir();
        let share_path = dir.join("bridge_test_2of3.json");
        let json = serde_json::to_vec(&dkg_result).unwrap();
        tokio::fs::write(&share_path, &json).await.unwrap();

        let config = ProxyConfig {
            port: 3322,
            kss_url: "http://localhost:9999".into(),
            share_path: share_path.to_string_lossy().to_string(),
            fee_per_signing: 0,
            fee_addresses: vec![],
            fee_threshold: None,
            max_presignatures: 5,
            encryption_key: None,
            arc_api_key: "test_key".into(),
            threshold_configs: vec!["2-of-2".to_string()],
            min_balance_sats: None,
            relay_url: "https://rust-message-box.dev-a3e.workers.dev".into(),
            relay_sign: false,
            presign_url: None,
        };

        let bridge = MpcBridge::new(&config).await.unwrap();
        // For 2-of-3 with index 2: first non-self index is 0, so [0, 2]
        assert_eq!(bridge.participants, vec![0, 2]);

        let _ = tokio::fs::remove_file(&share_path).await;
    }

    #[test]
    fn proxy_identity_is_deterministic_for_same_share() {
        // Stable proxy identity (OQ-A2): the same secret share material must
        // always derive the same long-lived BRC-31 / relay identity key, so a
        // proxy restart keeps the share's `owner_identity`.
        let secret = b"share_B raw cggmp24 key share json bytes".to_vec();
        let a = BridgeAuth::from_share_seed(&secret).unwrap();
        let b = BridgeAuth::from_share_seed(&secret).unwrap();
        assert_eq!(
            a.identity_hex(),
            b.identity_hex(),
            "same share must derive the same identity across restarts"
        );
        // Sanity: a valid 33-byte compressed pubkey (66 hex chars).
        assert_eq!(a.identity_hex().len(), 66);
    }

    #[test]
    fn proxy_identity_differs_per_share() {
        // Distinct share secrets (distinct owners) must derive distinct
        // identities — owner identity is bound to control of that share.
        let a = BridgeAuth::from_share_seed(b"share for agent one").unwrap();
        let b = BridgeAuth::from_share_seed(b"share for agent two").unwrap();
        assert_ne!(a.identity_hex(), b.identity_hex());
    }
}

/// #10d — proxy rotation-on-commit: hot-swap + durable persist of a refreshed
/// share. Uses REAL 2-of-2 cggmp24 key shares (round_based sim) so the hot-swap
/// re-derives a genuine share scalar and the persisted DkgResult reloads through
/// `MpcBridge::new`.
#[cfg(test)]
mod refresh_rotation_tests {
    use super::*;
    use std::collections::VecDeque;

    use bsv_mpc_core::types::DkgResult;
    use cggmp24::security_level::SecurityLevel128;
    use cggmp24::supported_curves::Secp256k1;
    use cggmp24::ExecutionId;

    #[pin_project::pin_project]
    struct BufferedSink<M, Inner> {
        #[pin]
        messages: VecDeque<M>,
        #[pin]
        inner: Inner,
    }
    type BufferedDelivery<M, D> = (
        <D as round_based::Delivery<M>>::Receive,
        BufferedSink<round_based::Outgoing<M>, <D as round_based::Delivery<M>>::Send>,
    );
    impl<M: Unpin, Inner: futures::Sink<M>> futures::Sink<M> for BufferedSink<M, Inner> {
        type Error = Inner::Error;
        fn poll_ready(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn start_send(
            self: std::pin::Pin<&mut Self>,
            item: M,
        ) -> std::result::Result<(), Self::Error> {
            self.project().messages.get_mut().push_back(item);
            Ok(())
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
            while !self.messages.is_empty() {
                let mut projection = self.as_mut().project();
                let mut inner = projection.inner;
                std::task::ready!(inner.as_mut().poll_ready(cx))?;
                if let Some(item) = projection.messages.pop_front() {
                    inner.as_mut().start_send(item)?;
                }
            }
            self.project().inner.poll_flush(cx)
        }
        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
            self.project().inner.poll_close(cx)
        }
    }
    fn buffer_outgoing<M, D, R>(
        party: round_based::MpcParty<M, D, R>,
    ) -> round_based::MpcParty<M, BufferedDelivery<M, D>, R>
    where
        M: Unpin,
        D: round_based::Delivery<M>,
        R: round_based::runtime::AsyncRuntime,
    {
        party.map_delivery(|delivery| {
            let (incoming, outgoing) = delivery.split();
            (
                incoming,
                BufferedSink {
                    messages: VecDeque::new(),
                    inner: outgoing,
                },
            )
        })
    }
    fn blum_prime(rng: &mut impl rand::RngCore, bits: u32) -> cggmp24::backend::Integer {
        use cggmp24::backend::Integer;
        loop {
            let n = Integer::generate_prime(rng, bits);
            if n.mod_u(4) == 3 {
                break n;
            }
        }
    }
    fn primes(rng: &mut impl rand::RngCore) -> cggmp24::PregeneratedPrimes<SecurityLevel128> {
        use cggmp24::security_level::SecurityLevel;
        let b = SecurityLevel128::RSA_PRIME_BITLEN;
        cggmp24::PregeneratedPrimes::try_from([
            blum_prime(rng, b),
            blum_prime(rng, b),
            blum_prime(rng, b),
            blum_prime(rng, b),
        ])
        .expect("primes")
    }
    async fn dkg_2of2() -> Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> {
        use rand::Rng;
        let mut rng = rand::rngs::OsRng;
        let (n, t) = (2u16, 2u16);
        let eid_bytes: [u8; 32] = rng.gen();
        let eid = ExecutionId::new(&eid_bytes);
        let inc = round_based::sim::run(n, |i, p| {
            let p = buffer_outgoing(p);
            let mut r = rand::rngs::OsRng;
            async move {
                cggmp24::keygen::<Secp256k1>(eid, i, n)
                    .set_threshold(t)
                    .start(&mut r, p)
                    .await
            }
        })
        .unwrap()
        .expect_ok()
        .into_vec();
        let eid_aux_bytes: [u8; 32] = rng.gen();
        let eid_aux = ExecutionId::new(&eid_aux_bytes);
        let pr: Vec<_> = (0..n).map(|_| primes(&mut rng)).collect();
        let aux = round_based::sim::run(n, |i, p| {
            let p = buffer_outgoing(p);
            let mut r = rand::rngs::OsRng;
            let pre = pr[usize::from(i)].clone();
            async move { cggmp24::aux_info_gen(eid_aux, i, n, pre).start(&mut r, p).await }
        })
        .unwrap()
        .expect_ok()
        .into_vec();
        inc.into_iter()
            .zip(aux)
            .map(|(s, a)| cggmp24::KeyShare::from_parts((s, a)).expect("key share"))
            .collect()
    }
    fn enc_share(
        ks: &cggmp24::KeyShare<Secp256k1, SecurityLevel128>,
        idx: u16,
    ) -> EncryptedShare {
        EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: serde_json::to_vec(ks).unwrap(),
            session_id: SessionId::from_str_hash("refresh-rot-test"),
            share_index: ShareIndex(idx),
            config: ThresholdConfig { threshold: 2, parties: 2 },
            joint_pubkey_compressed: ks.core.shared_public_key.to_bytes(true).to_vec(),
        }
    }
    fn config_for(share_path: &str, encryption_key: Option<String>) -> ProxyConfig {
        ProxyConfig {
            port: 3322,
            kss_url: "http://localhost:9999".into(),
            share_path: share_path.into(),
            fee_per_signing: 0,
            fee_addresses: vec![],
            fee_threshold: None,
            max_presignatures: 5,
            encryption_key,
            arc_api_key: "test".into(),
            threshold_configs: vec!["2-of-2".into()],
            min_balance_sats: None,
            relay_url: "https://rust-message-box.dev-a3e.workers.dev".into(),
            relay_sign: false,
            presign_url: None,
        }
    }

    #[tokio::test]
    async fn hot_swap_and_persist_rotated_share_roundtrips() {
        let shares = dkg_2of2().await;
        let jpk = shares[0].core.shared_public_key.to_bytes(true).to_vec();
        let scalar0 = bsv_mpc_core::ecdh::parse_share_scalar(
            &serde_json::to_vec(&shares[0]).unwrap(),
        )
        .unwrap();
        let scalar1 = bsv_mpc_core::ecdh::parse_share_scalar(
            &serde_json::to_vec(&shares[1]).unwrap(),
        )
        .unwrap();
        assert_ne!(scalar0, scalar1);

        // Bridge starts on party 1's share (written as a plaintext DkgResult file).
        let dir = tempfile::tempdir().unwrap();
        let share_path = dir.path().join("share.json");
        let orig = DkgResult {
            joint_key: JointPublicKey {
                compressed: jpk.clone(),
                address: "1Rot".into(),
            },
            share: enc_share(&shares[1], 1),
            session_id: SessionId::from_str_hash("refresh-rot-test"),
        };
        std::fs::write(&share_path, serde_json::to_vec(&orig).unwrap()).unwrap();
        let bridge = MpcBridge::new(&config_for(share_path.to_str().unwrap(), None))
            .await
            .unwrap();
        assert_eq!(bridge.current_share_scalar(), scalar1, "starts on party-1 scalar");

        // Hot-swap to a "rotated" share (party 0, same joint key).
        let rotated = enc_share(&shares[0], 0);
        bridge.apply_refreshed_share(&rotated).unwrap();
        assert_eq!(
            bridge.current_share_scalar(),
            scalar0,
            "scalar re-derived from the rotated share"
        );
        assert_eq!(
            bridge.current_share().ciphertext,
            rotated.ciphertext,
            "in-memory share hot-swapped"
        );

        // Persist (plaintext) + reload through MpcBridge::new → rotated share loads.
        bridge
            .persist_rotated_share(share_path.to_str().unwrap(), None, &rotated)
            .unwrap();
        let reloaded = MpcBridge::new(&config_for(share_path.to_str().unwrap(), None))
            .await
            .unwrap();
        assert_eq!(
            reloaded.current_share_scalar(),
            scalar0,
            "reloaded-from-disk share is the rotated one (plaintext)"
        );

        // Persist (encrypted envelope) + reload with the key → still the rotated share.
        let key = [0x5au8; 32];
        let key_hex = hex_encode(&key);
        bridge
            .persist_rotated_share(share_path.to_str().unwrap(), Some(&key), &rotated)
            .unwrap();
        let reloaded_enc = MpcBridge::new(&config_for(
            share_path.to_str().unwrap(),
            Some(key_hex),
        ))
        .await
        .unwrap();
        assert_eq!(
            reloaded_enc.current_share_scalar(),
            scalar0,
            "reloaded encrypted-at-rest rotated share matches"
        );
    }

    #[tokio::test]
    async fn consume_for_sign_is_single_use_and_binding_gated() {
        use bsv_mpc_core::types::{PolicyId, PresigBundle};
        use bsv_mpc_service::FileBundleStore;

        // A bridge whose joint key the bundle must match.
        let jpk = vec![0x02u8; 33];
        let bridge = MpcBridge::new_for_test(JointPublicKey {
            compressed: jpk.clone(),
            address: "1Guard".into(),
        });
        let policy = PolicyId([0x09; 32]);

        let dir = tempfile::tempdir().unwrap();
        let store = FileBundleStore::new(dir.path()).unwrap();

        let mk = |id: &str, pol: [u8; 32], jp: Vec<u8>| PresigBundle {
            presig_id: id.into(),
            presig_bytes: vec![1],
            cosigner_encrypted_shares: vec![
                serde_bytes::ByteBuf::from(vec![]),
                serde_bytes::ByteBuf::from(vec![2]),
            ],
            gamma_hex: "ab".into(),
            commitments: vec![1],
            policy_id: PolicyId(pol),
            joint_pubkey: jp,
            parties_at_keygen: vec![0, 1],
            generated_at: 1,
        };

        // Matching bundle: consume once OK, second time Err (single-use).
        use bsv_mpc_service::BundleStore;
        let good_id = "aa".repeat(32);
        store.persist(&mk(&good_id, [0x09; 32], jpk.clone())).unwrap();
        let got = bridge
            .consume_bundle_for_sign(&store, &good_id, policy)
            .expect("matching bundle consumes");
        assert_eq!(got.presig_id, good_id);
        assert!(
            bridge
                .consume_bundle_for_sign(&store, &good_id, policy)
                .is_err(),
            "second consume MUST fail (single-use §06.17.3)"
        );

        // Stale-binding bundle (wrong joint pubkey): guard refuses + purges it.
        let stale_id = "bb".repeat(32);
        store
            .persist(&mk(&stale_id, [0x09; 32], vec![0x03; 33]))
            .unwrap();
        let err = bridge.consume_bundle_for_sign(&store, &stale_id, policy);
        assert!(err.is_err(), "binding mismatch MUST refuse signing (§06.18 guard)");
        assert!(
            store.consume(&stale_id).unwrap().is_none(),
            "the stale bundle is purged by the consume, not left for reuse"
        );

        // Wrong policy id also fails the binding check.
        let pol_id = "cc".repeat(32);
        store.persist(&mk(&pol_id, [0xFF; 32], jpk.clone())).unwrap();
        assert!(
            bridge
                .consume_bundle_for_sign(&store, &pol_id, policy)
                .is_err(),
            "wrong policy_id MUST fail the consume-time binding check"
        );
    }

    #[tokio::test]
    async fn malformed_rotated_share_aborts_without_corrupting_live_share() {
        // Safety: a bad refresh MUST NOT clobber the live share (no asterisks).
        let shares = dkg_2of2().await;
        let scalar1 = bsv_mpc_core::ecdh::parse_share_scalar(
            &serde_json::to_vec(&shares[1]).unwrap(),
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let share_path = dir.path().join("share.json");
        let orig = DkgResult {
            joint_key: JointPublicKey {
                compressed: shares[1].core.shared_public_key.to_bytes(true).to_vec(),
                address: "1Rot".into(),
            },
            share: enc_share(&shares[1], 1),
            session_id: SessionId::from_str_hash("refresh-rot-test"),
        };
        std::fs::write(&share_path, serde_json::to_vec(&orig).unwrap()).unwrap();
        let bridge = MpcBridge::new(&config_for(share_path.to_str().unwrap(), None))
            .await
            .unwrap();

        let mut garbage = enc_share(&shares[0], 0);
        garbage.ciphertext = b"not a key share".to_vec();
        let err = bridge.apply_refreshed_share(&garbage);
        assert!(err.is_err(), "malformed rotated share must error");
        assert_eq!(
            bridge.current_share_scalar(),
            scalar1,
            "live share scalar UNCHANGED after a failed hot-swap"
        );
    }
}
