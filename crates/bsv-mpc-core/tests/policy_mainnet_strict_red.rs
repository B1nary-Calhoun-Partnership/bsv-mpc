//! RED → GREEN test for audit #78 (option 1 — compile-time interlock).
//!
//! Under the `mainnet-strict` cargo feature, `PolicyManifest::validate` (and by
//! extension `PolicyEngine::new`, which calls `validate`) MUST refuse to load a
//! manifest with `dry_run: true`. This closes the audit's RED #3 at the binary
//! level: mainnet builds are interlocked against accidentally shipping a
//! shadow-mode manifest.
//!
//! The whole file is gated on `cfg(feature = "mainnet-strict")` so it runs only
//! in the dedicated CI job: `cargo test --features mainnet-strict -p bsv-mpc-core`.

#![cfg(feature = "mainnet-strict")]

use bsv_mpc_core::policy::{DefaultAction, PolicyEngine, PolicyManifest, Rule};
use bsv_mpc_core::types::PolicyId;

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

fn manifest(dry_run: bool) -> PolicyManifest {
    let mut m = PolicyManifest {
        version: 7,
        policy_id: PolicyId::from_bytes([0u8; 32]),
        cosigner_identity: key(0x11),
        group_key: key(0x22),
        rules: vec![empty_rule("*")],
        default_action: DefaultAction::Deny,
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

/// #78 (option 1) RED→GREEN: under `mainnet-strict`, `dry_run: true` is a hard
/// reject at `validate()`. PolicyEngine::new must surface the error verbatim.
#[test]
fn red_78_dry_run_true_rejected_under_mainnet_strict() {
    let m = manifest(/*dry_run=*/ true);
    let err = PolicyEngine::new(m)
        .err()
        .expect("mainnet-strict MUST refuse dry_run=true manifest");
    let s = format!("{err}");
    assert!(
        s.contains("dry_run") && s.contains("mainnet-strict"),
        "rejection reason must name BOTH 'dry_run' and 'mainnet-strict' so \
         operators know which interlock fired; got: {s}"
    );
}

/// Positive case: `dry_run: false` under `mainnet-strict` builds successfully.
/// Required pair to the negative test above so a future regression that
/// rejects ALL manifests under `mainnet-strict` (overzealous fix) fails this.
#[test]
fn red_78_dry_run_false_loads_under_mainnet_strict() {
    let m = manifest(/*dry_run=*/ false);
    let engine = PolicyEngine::new(m).expect("dry_run=false must build engine");
    assert!(!engine.is_dry_run(), "engine must report not-dry-run");
}
