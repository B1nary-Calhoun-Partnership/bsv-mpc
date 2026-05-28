//! RED tests proving the bsv-mpc 2026-05-28 audit findings #76 and #78.
//!
//! Today (main) — these tests FAIL:
//!   - #76: `create_signature_impl` has NO policy/approval gate. A Deny manifest
//!     does NOT prevent the function from attempting to relay-sign. The response
//!     contains a relay error, not the "policy denied" the gate would produce.
//!   - #78: under `dry_run: true` a Deny verdict silently returns Ok(()) and the
//!     function proceeds — the HTTP response carries no `would_have_denied`
//!     signal a client could monitor on.
//!
//! After the fix — all tests turn GREEN: the gate fires BEFORE any relay
//! attempt, and dry_run denials surface a structured `would_have_denied` body.
//!
//! These tests intentionally use `MpcBridge::new_for_test` so they never hit a
//! real KSS or relay. No mainnet TXs in CI — the assertions all stop signing at
//! the gate, by design.
//!
//! Audit refs: bsv-mpc#76, #78. PROGRESS-PERSON-B.md tracks gate status.

use std::sync::Arc;
use tokio::sync::RwLock;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::policy::{
    ApprovalSpec, DefaultAction, PolicyEngine, PolicyManifest, Rule,
};
use bsv_mpc_core::types::{JointPublicKey, PolicyId};
use bsv_mpc_proxy::config::ProxyConfig;
use bsv_mpc_proxy::fee_injector::FeeInjector;
use bsv_mpc_proxy::presign_manager::PresignManager;
use bsv_mpc_proxy::storage::InMemoryBackend;
use bsv_mpc_proxy::wallet_api::create_signature_impl;
use bsv_mpc_proxy::{AppState, MpcBridge};
use serde_json::json;

// ─── Fixtures ───────────────────────────────────────────────────────────────

/// Reusable 32-byte private-key seed for a deterministic joint pubkey.
const TEST_KEY_BYTES: [u8; 32] = [
    0x0b, 0x1e, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1, 0xe2,
    0xf3, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1,
    0xf2, 0x03,
];

fn test_joint_key() -> JointPublicKey {
    let privkey = PrivateKey::from_bytes(&TEST_KEY_BYTES).expect("valid key");
    let pubkey = privkey.public_key();
    JointPublicKey {
        compressed: pubkey.to_compressed().to_vec(),
        address: "1TestAddress".to_string(),
    }
}

fn key(b: u8) -> Vec<u8> {
    let mut k = vec![0x02; 33];
    k[1] = b;
    k
}

fn empty_rule(pattern: &str) -> Rule {
    Rule {
        protocol_pattern: pattern.to_string(),
        max_amount_sats: None,
        max_per_hour: None,
        cumulative_daily_cap_sats: None,
        allowed_window: None,
        counterparty_allowlist: None,
        counterparty_denylist: None,
        min_fee_sats: None,
        jurisdiction: None,
        approval_spec: None,
        attestation_spec: None,
    }
}

fn manifest(rules: Vec<Rule>, default_action: DefaultAction, dry_run: bool) -> PolicyManifest {
    let mut m = PolicyManifest {
        version: 7,
        policy_id: PolicyId::from_bytes([0u8; 32]),
        cosigner_identity: key(0x11),
        group_key: key(0x22),
        rules,
        default_action,
        effective_after_ms: 0,
        expires_after_ms: None,
        prev_policy_id: None,
        approver_keys: vec![key(0xaa)],
        approver_sigs: vec![],
        dry_run,
    };
    m.policy_id = m.compute_policy_id();
    m
}

/// Default-Deny manifest — every signing request falls to default_action: Deny.
fn deny_manifest() -> PolicyManifest {
    manifest(vec![], DefaultAction::Deny, /*dry_run=*/ false)
}

/// Deny manifest in shadow mode — verdict is Deny but enforcement is shadow-only.
fn dry_run_deny_manifest() -> PolicyManifest {
    manifest(vec![], DefaultAction::Deny, /*dry_run=*/ true)
}

/// `max_per_hour: 0` rule — the first request inside the hour is RateLimited.
fn rate_limited_manifest() -> PolicyManifest {
    let mut r = empty_rule("*");
    r.max_per_hour = Some(0);
    manifest(vec![r], DefaultAction::Deny, /*dry_run=*/ false)
}

/// `approval_spec: k=1` rule — verdict is RequireApproval, gate must drive the
/// approval flow before signing.
fn approval_required_manifest() -> PolicyManifest {
    let mut r = empty_rule("*");
    r.approval_spec = Some(ApprovalSpec {
        k: 1,
        eligible: vec![key(0xcc)],
    });
    manifest(vec![r], DefaultAction::Deny, /*dry_run=*/ false)
}

/// Build an AppState wired to a test bridge (no KSS, no relay) + the given policy.
fn state_with_policy(engine: Option<PolicyEngine>) -> Arc<AppState> {
    let config = ProxyConfig {
        port: 0,
        kss_url: "http://policy-gate-test.invalid".into(),
        share_path: "/tmp/policy-gate-test-share".into(),
        fee_per_signing: 0,
        fee_addresses: vec![],
        fee_threshold: None,
        max_presignatures: 1,
        encryption_key: None,
        arc_api_key: "unused".into(),
        threshold_configs: vec!["2-of-2".to_string()],
        min_balance_sats: None,
        relay_url: "http://policy-gate-test.invalid".into(),
        relay_sign: true,
        presign_url: None,
        // 1s instead of the 60s default: under RequireApproval we want the
        // gate to fail-fast since no responder is listening on the bogus URL.
        approval_recv_timeout_secs: 1,
        network: None,
        policy_manifest_path: None,
    };
    let bridge = MpcBridge::new_for_test(test_joint_key());
    let policy_engine = engine.map(|e| Arc::new(std::sync::Mutex::new(e)));
    Arc::new(AppState {
        config,
        bridge,
        presign_manager: Arc::new(RwLock::new(PresignManager::new(1))),
        device_presig_pool: None,
        policy_engine,
        fee_injector: FeeInjector::new(0, vec![], None),
        storage: Arc::new(InMemoryBackend::new()),
        http_client: reqwest::Client::new(),
    })
}

/// A `/createSignature` body that asks for a direct sign of 32 zero bytes — the
/// minimal valid input that exercises `create_signature_impl`'s sign path.
fn body() -> serde_json::Value {
    json!({
        "data": "00".repeat(32),
        "hashToDirectlySign": true,
    })
}

fn err_str(resp: &serde_json::Value) -> String {
    resp.get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

// ─── #76 — createSignature MUST be gated ─────────────────────────────────────

/// #76 RED: under Deny, the response MUST identify the gate as the rejector —
/// not the relay/signing layer.
///
/// Negative-case assertion (per the audit's "Validate, don't skip" rule):
/// we assert the RIGHT rejection reason (`"policy denied"`), so a future
/// regression that returns Ok(()) AND a relay error would not silently pass.
#[tokio::test]
async fn red_76_deny_manifest_rejects_create_signature_before_relay() {
    let engine = PolicyEngine::new(deny_manifest()).expect("valid manifest");
    let state = state_with_policy(Some(engine));

    let resp = create_signature_impl(&state, body()).await;
    let err = err_str(&resp);

    assert!(
        resp.get("signature").is_none(),
        "Deny policy MUST NOT yield a signature; got {resp}"
    );
    assert!(
        err.contains("policy denied"),
        "Deny verdict must surface as 'policy denied: <reason>'; \
         got error={err:?}, full response={resp}"
    );
}

/// #76 RED: RateLimited verdict must surface as the policy gate's reason —
/// NOT a relay/timeout error.
#[tokio::test]
async fn red_76_rate_limited_manifest_rejects_create_signature() {
    let engine = PolicyEngine::new(rate_limited_manifest()).expect("valid manifest");
    let state = state_with_policy(Some(engine));

    let resp = create_signature_impl(&state, body()).await;
    let err = err_str(&resp);

    assert!(
        resp.get("signature").is_none(),
        "RateLimited verdict MUST NOT yield a signature; got {resp}"
    );
    assert!(
        err.contains("rate-limited"),
        "RateLimited verdict must surface as 'policy rate-limited; \
         retry after Ns'; got error={err:?}, full response={resp}"
    );
}

/// #76 RED: RequireApproval verdict must drive the approval flow, not bypass
/// it. We don't stand up a relay responder, so the call MUST fail at approval
/// collection — but it MUST mention approval, NOT silently sign.
#[tokio::test]
async fn red_76_require_approval_blocks_create_signature() {
    let engine = PolicyEngine::new(approval_required_manifest()).expect("valid manifest");
    let state = state_with_policy(Some(engine));

    let resp = create_signature_impl(&state, body()).await;
    let err = err_str(&resp);

    assert!(
        resp.get("signature").is_none(),
        "RequireApproval verdict MUST NOT yield a signature without a quorum; \
         got {resp}"
    );
    assert!(
        err.contains("approval") || err.contains("Approval"),
        "RequireApproval must surface as an approval-flow error; \
         got error={err:?}, full response={resp}"
    );
}

/// #76 vector / shape: pin the JSON shape of a policy-denial response so a
/// future regression that returns `{ "signature": "...", "error": "policy denied" }`
/// (a silent contradiction) does not slip through.
#[tokio::test]
async fn red_76_deny_response_shape_is_pinned() {
    let engine = PolicyEngine::new(deny_manifest()).expect("valid manifest");
    let state = state_with_policy(Some(engine));

    let resp = create_signature_impl(&state, body()).await;
    let obj = resp.as_object().expect("response is a JSON object");

    assert!(
        obj.contains_key("error"),
        "Denied response MUST carry an 'error' field; got {resp}"
    );
    assert!(
        !obj.contains_key("signature"),
        "Denied response MUST NOT carry a 'signature' field; got {resp}"
    );
}

// ─── #78 — dry_run MUST NOT silently neutralize ──────────────────────────────

/// #78 RED: under dry_run=true with a Deny verdict, the response MUST surface
/// `would_have_denied: true` AND MUST NOT return a signature. Today the
/// function silently returns Ok(()) on dry_run and proceeds; this test pins
/// the post-fix observable contract so a regression that re-introduces silent
/// neutralization fails this assertion.
#[tokio::test]
async fn red_78_dry_run_deny_surfaces_would_have_denied() {
    let engine = PolicyEngine::new(dry_run_deny_manifest()).expect("valid manifest");
    let state = state_with_policy(Some(engine));

    let resp = create_signature_impl(&state, body()).await;
    let would_have_denied = resp
        .get("would_have_denied")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let enforced = resp.get("enforced").and_then(|v| v.as_bool()).unwrap_or(true);

    assert!(
        would_have_denied,
        "dry_run Deny MUST surface 'would_have_denied: true'; got {resp}"
    );
    assert!(
        !enforced,
        "dry_run Deny MUST surface 'enforced: false'; got {resp}"
    );
    // dry_run denial still SHORT-CIRCUITS signing in the audit's option-2
    // contract: the client receives the would-have-denial as an HTTP-visible
    // signal instead of a silent success. A future change that opts back into
    // "compute verdict, log, but still sign" reverts to the audit gap.
    assert!(
        resp.get("signature").is_none(),
        "dry_run Deny under the would_have_denied contract MUST NOT return a \
         signature; got {resp}"
    );
}

// ─── HTTP-status E2E (audit #78 option 2) ───────────────────────────────────

/// Bind the proxy router to a random localhost port and return `(addr, server_task)`.
/// Mirrors `server::run`'s `axum::serve` shape but on a 127.0.0.1:0 listener so
/// CI runs in parallel without port collisions.
async fn spawn_router(state: Arc<AppState>) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let app = bsv_mpc_proxy::server::build_router(state);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("axum::serve");
    });
    (addr, server)
}

/// #78 (option 2) E2E HTTP-status: drive a real POST /createSignature through
/// the axum router under a dry_run Deny manifest, assert the HTTP status is
/// 403 and the body carries the structured `would_have_denied`.
///
/// Closes the audit's "silently neutralizes" gap at the wire level: any
/// monitoring tool that gates on 2xx-vs-non-2xx will see the denial. The test
/// runs the same router `server::run` wires up, so what gets exercised is
/// exactly the production HTTP surface.
#[tokio::test]
async fn red_78_dry_run_deny_returns_http_403_through_router() {
    let engine = PolicyEngine::new(dry_run_deny_manifest()).expect("valid manifest");
    let state = state_with_policy(Some(engine));
    let (addr, server) = spawn_router(state).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/createSignature"))
        .header("content-type", "application/json")
        .body(body().to_string())
        .send()
        .await
        .expect("POST /createSignature");
    let status = resp.status();
    let json: serde_json::Value = resp.json().await.expect("response is JSON");

    server.abort();

    assert_eq!(
        status.as_u16(),
        403,
        "dry_run Deny MUST surface as HTTP 403 (audit #78 option 2); got status={status}, body={json}"
    );
    assert_eq!(
        json["would_have_denied"],
        serde_json::Value::Bool(true),
        "body must carry would_have_denied=true; got {json}"
    );
    assert_eq!(
        json["enforced"],
        serde_json::Value::Bool(false),
        "body must carry enforced=false under dry_run; got {json}"
    );
    // The internal sentinel MUST NOT leak to clients.
    assert!(
        json.get("__http_status").is_none(),
        "internal HTTP_STATUS_SENTINEL must be drained from the response body; got {json}"
    );
}

/// #76 (option 2) E2E HTTP-status: hard Deny MUST also surface as HTTP 403,
/// with `enforced: true` (distinguishes from the dry_run path).
#[tokio::test]
async fn red_76_hard_deny_returns_http_403_through_router() {
    let engine = PolicyEngine::new(deny_manifest()).expect("valid manifest");
    let state = state_with_policy(Some(engine));
    let (addr, server) = spawn_router(state).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/createSignature"))
        .header("content-type", "application/json")
        .body(body().to_string())
        .send()
        .await
        .expect("POST /createSignature");
    let status = resp.status();
    let json: serde_json::Value = resp.json().await.expect("response is JSON");

    server.abort();

    assert_eq!(
        status.as_u16(),
        403,
        "hard Deny MUST surface as HTTP 403; got status={status}, body={json}"
    );
    assert_eq!(
        json["enforced"],
        serde_json::Value::Bool(true),
        "hard Deny must carry enforced=true; got {json}"
    );
    assert_eq!(
        json["would_have_denied"],
        serde_json::Value::Bool(false),
        "hard Deny must carry would_have_denied=false; got {json}"
    );
}
