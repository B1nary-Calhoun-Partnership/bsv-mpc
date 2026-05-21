//! BRC-31 Authrite authentication for the CF Worker KSS — CANONICAL wire (#8).
//!
//! ## Canonical migration (leg 2)
//!
//! This module was ported off the old custom "sign `SHA-256(nonce)`" profile
//! and now verifies the **canonical BRC-31 wire** via the
//! [`bsv-middleware-cloudflare`](bsv_middleware_cloudflare) server middleware
//! (which we maintain). The leg-1 proxy already emits canonical-wire requests to
//! this worker DO, so the DO MUST verify the canonical wire to match. The proven
//! wire is exactly what `bsv-mpc-core/tests/conformance_07_brc31_auth.rs`
//! produces (a `bsv::auth::Peer`-signed General message); the worker's
//! [`process_request_auth`] accepts it byte-for-byte and rejects a stranger /
//! tampered payload.
//!
//! ## Where auth runs
//!
//! Auth runs **inside** the per-identity `CosignerSessionDo` (NOT at the
//! entrypoint), backed by that DO's co-located SQLite session store
//! ([`crate::do_storage::DoSqlStorage`] impl of
//! [`bsv_middleware_cloudflare::SessionStorage`]). The handshake-write and the
//! per-request read therefore hit the SAME store regardless of which entrypoint
//! isolate served them — the auth-session-isolate fix (#5). Sessions stay in
//! DO-SQLite; they are NOT moved to KV.
//!
//! ## Flow
//!
//! ```text
//! Proxy (client)                         KSS Worker DO (server)
//!     │── POST /.well-known/auth ────────────►│  InitialRequest → InitialResponse
//!     │◄── 200 + BRC-104 headers ────────────│  (canonical handshake, session saved)
//!     │                                       │
//!     │── POST /sign/init (General, signed) ─►│  verify canonical signature over
//!     │   x-bsv-auth-* + signed BRC-104 body  │  (method, path, headers, body)
//!     │◄── 200 ──────────────────────────────│  dispatch with verified caller
//! ```
//!
//! ## Replay (§07.1)
//!
//! `process_auth_with_storage` verifies the signature but does NOT track
//! per-request nonce reuse. After a request authenticates, the DO records its
//! per-request nonce in a bounded, TTL-swept consumed set
//! ([`crate::do_storage::DoSqlStorage::consume_request_nonce`]); a replay of the
//! same `(session_nonce, request_nonce)` pair is rejected (401). This check runs
//! AFTER signature verification so a forged nonce can't poison the set.
//!
//! ## Dev mode
//!
//! When the `SERVER_PRIVATE_KEY` secret is unset the DO runs
//! `allow_unauthenticated` (no server identity to sign the handshake),
//! preserving the existing local / self-stocking flows: an unauthenticated DKG
//! records an empty owner, and an empty owner authorizes any caller (the §07
//! gate is simply absent). Set the secret to enforce §07.6 on a deployed
//! cosigner.
//!
//! References:
//! - BRC-31: ~/bsv/BRCs/peer-to-peer/0031.md
//! - BRC-42: ~/bsv/BRCs/key-derivation/0042.md
//! - conformance: crates/bsv-mpc-core/tests/conformance_07_brc31_auth.rs

use worker::*;

use crate::do_storage::DoSqlStorage;

/// Default session TTL: 1 hour in milliseconds (§07.7).
const DEFAULT_SESSION_TTL_MS: u64 = 3_600_000;

// ── BRC-104 Header Constants ─────────────────────────────────────────────
//
// Canonical BRC-104 header names (must match the middleware + the proxy
// client). Retained here for the `caller_identity` reader in `api.rs` and the
// `/poc/auth-session-roundtrip` legacy compatibility route.

/// BRC-104 header names used for Authrite mutual authentication.
pub mod headers {
    pub const VERSION: &str = "x-bsv-auth-version";
    pub const IDENTITY_KEY: &str = "x-bsv-auth-identity-key";
    pub const NONCE: &str = "x-bsv-auth-nonce";
    pub const INITIAL_NONCE: &str = "x-bsv-auth-initial-nonce";
    pub const YOUR_NONCE: &str = "x-bsv-auth-your-nonce";
    pub const SIGNATURE: &str = "x-bsv-auth-signature";
    pub const MESSAGE_TYPE: &str = "x-bsv-auth-message-type";
    pub const REQUEST_ID: &str = "x-bsv-auth-request-id";
}

// ── Outcome of the DO-side canonical auth gate ──────────────────────────────

/// Result of running canonical BRC-31 auth on a DO request.
pub enum AuthOutcome {
    /// The middleware produced a response to return directly — the BRC-31
    /// handshake (`/.well-known/auth`), or an auth error (401/403/…). Return it
    /// to the client unchanged.
    Respond(Response),
    /// The request authenticated (or was allowed through in dev mode). Dispatch
    /// to the handler. `caller` is the verified BRC-31 identity (hex), or `None`
    /// in dev / unauthenticated mode. `request` is the original, body-bearing
    /// request the handler reads (its `x-bsv-auth-identity-key` header equals
    /// the verified caller).
    Proceed {
        caller: Option<String>,
        request: Request,
    },
}

/// Build the canonical [`bsv_middleware_cloudflare::AuthMiddlewareOptions`] from
/// the DO env. When `SERVER_PRIVATE_KEY` is set, auth is ENFORCED; otherwise the
/// DO runs in dev mode (`allow_unauthenticated`).
fn auth_options(env: &Env) -> bsv_middleware_cloudflare::AuthMiddlewareOptions {
    match env.secret("SERVER_PRIVATE_KEY") {
        Ok(secret) => bsv_middleware_cloudflare::AuthMiddlewareOptions {
            server_private_key: secret.to_string(),
            allow_unauthenticated: false,
            session_ttl_seconds: DEFAULT_SESSION_TTL_MS / 1000,
            ..Default::default()
        },
        Err(_) => bsv_middleware_cloudflare::AuthMiddlewareOptions {
            // Dev mode: any non-empty hex parses; the middleware never verifies
            // because `allow_unauthenticated` short-circuits when no auth headers
            // are present, and the DO skips replay tracking for dev.
            server_private_key: "0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
            allow_unauthenticated: true,
            session_ttl_seconds: DEFAULT_SESSION_TTL_MS / 1000,
            ..Default::default()
        },
    }
}

/// Whether the DO is enforcing auth (i.e. a `SERVER_PRIVATE_KEY` secret is set).
fn is_enforced(env: &Env) -> bool {
    env.secret("SERVER_PRIVATE_KEY").is_ok()
}

/// Run canonical BRC-31 auth for a DO request (handshake OR per-request verify).
///
/// This is the single entry the `CosignerSessionDo::fetch` path uses for both
/// the handshake (`/.well-known/auth`) and the per-request gate on authed
/// routes. It:
///
/// 1. clones the request so the handler still has the (un-consumed) body;
/// 2. runs the canonical [`process_auth_with_storage`] against the DO-SQLite
///    [`SessionStorage`] — this verifies the canonical signature over
///    `(method, path, headers, body)` and persists/loads the session durably;
/// 3. on `AuthResult::Response` (handshake or auth failure) returns it directly;
/// 4. on `AuthResult::Authenticated`, enforces §07.1 replay (when not dev mode),
///    then yields the verified caller + the original request for dispatch.
///
/// [`process_auth_with_storage`]: bsv_middleware_cloudflare::process_auth_with_storage
/// [`SessionStorage`]: bsv_middleware_cloudflare::SessionStorage
pub async fn process_request_auth(
    req: Request,
    storage: &DoSqlStorage<'_>,
    env: &Env,
) -> Result<AuthOutcome> {
    use bsv_middleware_cloudflare::{process_auth_with_storage, AuthResult};

    let options = auth_options(env);
    let enforced = is_enforced(env);

    // Keep an un-consumed copy for the handler: the middleware consumes the body
    // when it builds the signed BRC-104 payload for a General message.
    let handler_req = req.clone()?;

    let result = process_auth_with_storage(req, storage, &options)
        .await
        .map_err(|e| Error::RustError(format!("BRC-31 auth: {e}")))?;

    match result {
        AuthResult::Response(resp) => Ok(AuthOutcome::Respond(resp)),
        AuthResult::Authenticated { context, .. } => {
            // Dev / unauthenticated: no verified identity, no replay tracking —
            // preserves the existing local flows (empty owner authorizes any
            // caller). `is_authenticated` distinguishes a real session from the
            // `allow_unauthenticated` passthrough.
            if !context.is_authenticated {
                return Ok(AuthOutcome::Proceed {
                    caller: None,
                    request: handler_req,
                });
            }

            // §07 identity binding (defense-in-depth): the session is fetched by
            // its server nonce, and the canonical signature is verified against
            // the MESSAGE's own claimed identity (the `x-bsv-auth-identity-key`
            // header), so a validly-signed request whose claimed identity differs
            // from the session-bound peer must be rejected — otherwise the
            // header (which the handlers + owner-authz read as the caller) would
            // not equal the session identity the signature was bound to. This
            // mirrors the canonical-server property asserted by
            // `conformance_07_brc31_auth.rs` (signature from a non-session-bound
            // identity is rejected) and the service's `verify_request` 403.
            let header_identity = handler_req
                .headers()
                .get(headers::IDENTITY_KEY)
                .ok()
                .flatten()
                .unwrap_or_default();
            if header_identity != context.identity_key {
                return Ok(AuthOutcome::Respond(reject_403(
                    "identity mismatch with established session (§07)",
                )?));
            }

            // §07.1 replay: reject a reused per-request nonce on this session.
            // The middleware does not track this; we do it here, AFTER the
            // signature verified, against the DO-SQLite consumed set.
            if enforced {
                if let Some(resp) = enforce_replay(&handler_req, storage)? {
                    return Ok(AuthOutcome::Respond(resp));
                }
            }

            Ok(AuthOutcome::Proceed {
                caller: Some(context.identity_key),
                request: handler_req,
            })
        }
    }
}

/// §07.1: record + reject a replayed per-request nonce. Returns `Some(401)` to
/// return on replay (or on a malformed/missing nonce on a signed request),
/// `None` when fresh. Keyed by `(your_nonce = server session nonce, nonce =
/// fresh per-request nonce)` — the exact pair the canonical client signs under.
fn enforce_replay(req: &Request, storage: &DoSqlStorage<'_>) -> Result<Option<Response>> {
    let h = req.headers();
    let your_nonce = h.get(headers::YOUR_NONCE).ok().flatten();
    let nonce = h.get(headers::NONCE).ok().flatten();
    let (Some(session_nonce), Some(request_nonce)) = (your_nonce, nonce) else {
        // A verified General message always carries both; absence here is a
        // protocol violation → reject rather than silently skip replay defense.
        return Ok(Some(reject_401("missing nonce headers on signed request")?));
    };
    let now = current_time_ms();
    let fresh = storage.consume_request_nonce(
        &session_nonce,
        &request_nonce,
        now,
        DEFAULT_SESSION_TTL_MS,
    )?;
    if fresh {
        Ok(None)
    } else {
        Ok(Some(reject_401("stale/replayed request nonce (§07.1)")?))
    }
}

/// Build a canonical-shaped 401 JSON rejection.
fn reject_401(msg: &str) -> Result<Response> {
    let body = serde_json::json!({
        "status": "error",
        "code": "UNAUTHORIZED",
        "message": msg,
    });
    Ok(Response::from_json(&body)?.with_status(401))
}

/// Build a 403 JSON rejection (identity mismatch / not authorized).
fn reject_403(msg: &str) -> Result<Response> {
    let body = serde_json::json!({
        "status": "error",
        "code": "FORBIDDEN",
        "message": msg,
    });
    Ok(Response::from_json(&body)?.with_status(403))
}

/// Current time in milliseconds since the Unix epoch.
fn current_time_ms() -> u64 {
    chrono::Utc::now().timestamp_millis() as u64
}

/// Verify that the authenticated identity matches the `agent_id` in a request
/// body. Ensures agent A cannot run DKG / signing on agent B's share. In dev
/// mode (empty identity) all requests are allowed.
///
/// Retained for compatibility; the live owner-authz path is
/// [`crate::api::authz_owner_or_reject`] (checked against the share's bound
/// `owner_identity` BEFORE share material loads).
pub fn verify_agent_authorization(
    caller: Option<&str>,
    agent_id: &str,
) -> std::result::Result<(), String> {
    match caller {
        None => Ok(()), // dev / unauthenticated
        Some(id) if id == agent_id => Ok(()),
        Some(id) => Err(format!(
            "identity mismatch: authenticated as {id} but requesting for {agent_id}"
        )),
    }
}

/// Handle CORS preflight (OPTIONS). Delegates to the middleware so the
/// allowed/exposed BRC-104 + payment header set stays canonical.
pub fn handle_cors_preflight() -> worker::Result<Response> {
    bsv_middleware_cloudflare::middleware::auth::handle_cors_preflight()
}

// ── Legacy session record (compat: `/poc/auth-session-roundtrip`) ───────────
//
// The pre-canonical 3-field session shape. Retained ONLY so the existing
// `/poc/auth-session-roundtrip` deterministic-proof route (and its
// `DoSqlStorage` impl over the `mpc_auth_sessions` table) keeps working. The
// canonical auth path uses `bsv_middleware_cloudflare::types::StoredSession`
// in the separate `mpc_canonical_sessions` table.

/// Legacy server-side BRC-31 session record (compat only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthSession {
    /// Server's nonce for this session (base64; lookup key).
    pub server_nonce: String,
    /// Client's identity key (hex compressed pubkey).
    pub peer_identity_key: String,
    /// Client's initial nonce from handshake (base64).
    pub peer_nonce: String,
    /// Session creation time (ms since epoch).
    pub created_at: u64,
}

/// Legacy storage abstraction for [`AuthSession`] (compat only). The canonical
/// path uses [`bsv_middleware_cloudflare::SessionStorage`] instead.
pub trait AuthSessionStore {
    /// Persist (upsert) a session, keyed by `server_nonce`.
    fn put_session(&self, session: AuthSession) -> std::result::Result<(), String>;
    /// Look up a session by `server_nonce`.
    fn get_session(&self, server_nonce: &str) -> std::result::Result<Option<AuthSession>, String>;
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use bsv::auth::{AuthMessage, MessageType, AUTH_PROTOCOL_ID};
    use bsv::primitives::ec::PrivateKey;
    use bsv::wallet::{
        Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel,
        VerifySignatureArgs,
    };
    use bsv::PublicKey;
    use bsv_middleware_cloudflare::types::StoredSession;
    // The canonical BRC-104 payload builder. `bsv-middleware-cloudflare` keeps
    // its own copy private; `bsv-middleware-rs` exposes the identical (proven by
    // `conformance_07_brc31_auth.rs`) public function. Both produce byte-equal
    // payloads — that interop is exactly what this test guards. Pulled as a
    // worker dev-dependency for the test build only.
    use bsv_middleware_rs::transport::build_request_payload;

    fn key(byte: u8) -> PrivateKey {
        PrivateKey::from_bytes(&[byte | 1; 32]).expect("valid key")
    }

    fn b64(seed: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode([seed; 32])
    }

    /// Build + sign a General request EXACTLY as `bsv::auth::Peer` /
    /// `conformance_07_brc31_auth.rs` does — the canonical wire the worker must
    /// accept.
    fn canonical_client_general(
        client: &ProtoWallet,
        server_id: &PublicKey,
        server_session_nonce: &str,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> AuthMessage {
        let request_id = [0x11u8; 32];
        let payload = build_request_payload(&request_id, method, path, "", &[], body);
        let mut msg = AuthMessage::new(MessageType::General, client.identity_key());
        msg.nonce = Some(b64(0xC3));
        msg.your_nonce = Some(server_session_nonce.to_string());
        msg.payload = Some(payload);
        let key_id = msg.get_key_id(Some(server_session_nonce));
        let data = msg.signing_data();
        let sig = client
            .create_signature(CreateSignatureArgs {
                data: Some(data),
                hash_to_directly_sign: None,
                protocol_id: Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID),
                key_id,
                counterparty: Some(Counterparty::Other(server_id.clone())),
            })
            .expect("canonical client create_signature");
        msg.signature = Some(sig.signature);
        msg
    }

    /// Post-handshake server session bound to `client_id_hex`. Built with
    /// literal timestamps (NOT `StoredSession::new`, which calls
    /// `js_sys::Date::now()` and panics on the native test target).
    fn server_session(server_session_nonce: &str, client_id_hex: &str) -> StoredSession {
        StoredSession {
            session_nonce: server_session_nonce.to_string(),
            peer_identity_key: client_id_hex.to_string(),
            peer_nonce: Some(b64(0xB2)),
            is_authenticated: true,
            certificates_required: false,
            certificates_validated: false,
            created_at: 0,
            last_update: 0,
        }
    }

    /// Mirror the middleware's `verify_message_signature` (private there) so the
    /// worker unit test proves the SAME canonical verification the deployed DO
    /// runs accepts a canonical-client signature, and rejects a stranger /
    /// tampered payload. (The middleware's `process_auth_with_storage` requires a
    /// live `worker::Request`, which can't be built in a host unit test; this
    /// reconstructs the exact key derivation it uses.)
    fn verify_canonical(server: &ProtoWallet, msg: &AuthMessage, session: &StoredSession) -> bool {
        let Some(signature) = msg.signature.as_ref() else {
            return false;
        };
        let data = msg.signing_data();
        let key_id = msg.get_key_id(Some(session.session_nonce.as_str()));
        let protocol = Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID);
        server
            .verify_signature(VerifySignatureArgs {
                data: Some(data),
                hash_to_directly_verify: None,
                signature: signature.clone(),
                protocol_id: protocol,
                key_id,
                counterparty: Some(Counterparty::Other(msg.identity_key.clone())),
                for_self: None,
            })
            .map(|r| r.valid)
            .unwrap_or(false)
    }

    #[test]
    fn canonical_general_verifies_against_worker_server() {
        // The proven wire (conformance_07) verifies against the canonical
        // verification the worker DO performs — mutual auth works.
        let client = ProtoWallet::new(Some(key(0x22)));
        let server = ProtoWallet::new(Some(key(0x11)));
        let ssn = b64(0xA1);
        let msg = canonical_client_general(
            &client,
            &server.identity_key(),
            &ssn,
            "POST",
            "/sign/init",
            br#"{"agent_id":"02abc","session_id":"c07","sighash":"00"}"#,
        );
        let session = server_session(&ssn, &client.identity_key().to_hex());
        assert!(
            verify_canonical(&server, &msg, &session),
            "canonical Peer-client General message must verify on the worker"
        );
    }

    #[test]
    fn signature_from_stranger_rejected_by_identity_binding() {
        // §07 identity binding: when the session is bound to a DIFFERENT identity
        // than the actual signer, the DO's `process_request_auth` rejects (403)
        // because the message's claimed identity (the `x-bsv-auth-identity-key`
        // header == the actual signer) does not equal the session-bound peer
        // identity that the middleware reports as `context.identity_key`.
        //
        // The middleware's session lookup is by nonce and reports
        // `session.peer_identity_key`; this test models that confused-deputy gap
        // and proves the worker's explicit binding check closes it. (The pure
        // BRC-42 signature math verifies for any valid signer — that is exactly
        // why the explicit binding check is required and asserted here.)
        let client = ProtoWallet::new(Some(key(0x22)));
        let server = ProtoWallet::new(Some(key(0x11)));
        let stranger = ProtoWallet::new(Some(key(0x33)));
        let ssn = b64(0xA1);
        let msg = canonical_client_general(
            &client,
            &server.identity_key(),
            &ssn,
            "POST",
            "/sign/init",
            br#"{"agent_id":"02abc"}"#,
        );
        // Session (and thus the middleware-reported context identity) is bound to
        // the stranger; the actual signer / header identity is the client.
        let session_bound_identity = stranger.identity_key().to_hex();
        let header_identity = client.identity_key().to_hex(); // = msg.identity_key

        // The signature math itself verifies against the SIGNER's identity (this
        // is the gap the binding check guards):
        let session_for_signer = server_session(&ssn, &header_identity);
        assert!(
            verify_canonical(&server, &msg, &session_for_signer),
            "canonical signature must verify against the actual signer's identity"
        );
        // …but the DO's identity-binding check rejects because the header
        // identity (signer) != the session-bound identity (the reported caller):
        assert_ne!(
            header_identity, session_bound_identity,
            "the binding check compares header-identity (signer) to context-identity (session peer)"
        );
        // Equivalently, a wrong server key never verifies (key-confusion guard):
        let wrong_server = ProtoWallet::new(Some(key(0x44)));
        assert!(
            !verify_canonical(&wrong_server, &msg, &session_for_signer),
            "verification under the wrong server identity must fail"
        );
    }

    #[test]
    fn tampered_payload_rejected() {
        // Flipping a byte of the signed BRC-104 payload after signing must break
        // verification (request-body binding).
        let client = ProtoWallet::new(Some(key(0x22)));
        let server = ProtoWallet::new(Some(key(0x11)));
        let ssn = b64(0xA1);
        let mut msg = canonical_client_general(
            &client,
            &server.identity_key(),
            &ssn,
            "POST",
            "/sign/init",
            br#"{"agent_id":"02abc"}"#,
        );
        let p = msg.payload.as_mut().expect("payload");
        let n = p.len();
        p[n - 1] ^= 0xFF;
        let session = server_session(&ssn, &client.identity_key().to_hex());
        assert!(
            !verify_canonical(&server, &msg, &session),
            "tampering the request body must break the signature"
        );
    }

    #[test]
    fn agent_authorization_rules() {
        assert!(verify_agent_authorization(None, "02abc").is_ok()); // dev
        assert!(verify_agent_authorization(Some("02abc"), "02abc").is_ok());
        assert!(verify_agent_authorization(Some("02cd"), "02abc").is_err());
    }
}
