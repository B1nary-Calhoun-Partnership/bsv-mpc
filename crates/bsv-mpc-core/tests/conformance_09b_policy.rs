//! Conformance suite for MPC-Spec §09.14 (policy-engine verdict vectors).
//!
//! Distinct from `conformance_09_rendered_text` (which byte-locks the approval
//! `request_view_hash`). This suite byte-locks the **policy evaluator**: it
//! builds 6 manifest+request fixtures mirroring the §09.14 examples and asserts
//! the engine's [`Verdict`] for each:
//!
//! 1. permissive policy + signing request   → Allow
//! 2. rate-limited policy at cap             → RateLimited
//! 3. whitelist miss                         → Deny
//! 4. min-fee mismatch                       → Deny
//! 5. approval-required                      → RequireApproval
//! 6. dry-run mode (same request as #1)      → Allow, but engine flags dry-run
//!
//! It also asserts `compute_policy_id` is stable: a fixed manifest hashes to the
//! same `policy_id` across two independent constructions. The in-test fixtures
//! are the lockable artifact; a divergence here means bsv-mpc would authorize a
//! signing request differently than the canonical spec / rust-mpc.

use bsv_mpc_core::policy::{
    ApprovalSpec, DefaultAction, PolicyEngine, PolicyManifest, Rule, SigningCheck, Verdict,
};
use bsv_mpc_core::types::PolicyId;

/// 33-byte compressed pubkey filled with `b`, for fixtures.
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

/// Build a manifest with the given rules + default action, computing its
/// `policy_id`.
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

fn signing(protocol: &str, amount: u64, fee: u64, cp: Option<&str>) -> SigningCheck {
    SigningCheck {
        protocol_id: protocol.to_string(),
        amount_sats: amount,
        fee_sats: fee,
        counterparty: cp.map(|s| s.to_string()),
    }
}

#[test]
fn vector_1_permissive_allow() {
    let m = manifest(vec![empty_rule("*")], DefaultAction::Deny, false);
    let mut eng = PolicyEngine::new(m).expect("valid manifest");
    let v = eng.check_signing(&signing("agent/pay", 50_000, 100, None), 1_000);
    assert_eq!(v, Verdict::Allow);
}

#[test]
fn vector_2_rate_limited_at_cap() {
    let mut r = empty_rule("agent/*");
    r.max_per_hour = Some(2);
    let m = manifest(vec![r], DefaultAction::Deny, false);
    let mut eng = PolicyEngine::new(m).expect("valid manifest");

    assert_eq!(
        eng.check_signing(&signing("agent/pay", 1, 1, None), 0),
        Verdict::Allow
    );
    assert_eq!(
        eng.check_signing(&signing("agent/pay", 1, 1, None), 1_000),
        Verdict::Allow
    );
    // The third request inside the 1-hour window exceeds max_per_hour=2.
    let v = eng.check_signing(&signing("agent/pay", 1, 1, None), 2_000);
    assert!(
        matches!(v, Verdict::RateLimited { .. }),
        "expected RateLimited, got {v:?}"
    );
}

#[test]
fn vector_3_whitelist_miss_deny() {
    let mut r = empty_rule("*");
    r.counterparty_allowlist = Some(vec!["02good".to_string()]);
    let m = manifest(vec![r], DefaultAction::Deny, false);
    let mut eng = PolicyEngine::new(m).expect("valid manifest");
    let v = eng.check_signing(&signing("agent/pay", 1, 1, Some("02bad")), 0);
    assert!(matches!(v, Verdict::Deny(_)), "expected Deny, got {v:?}");
}

#[test]
fn vector_4_min_fee_mismatch_deny() {
    let mut r = empty_rule("*");
    r.min_fee_sats = Some(500);
    let m = manifest(vec![r], DefaultAction::Deny, false);
    let mut eng = PolicyEngine::new(m).expect("valid manifest");
    let v = eng.check_signing(&signing("notary/sign", 1, 499, None), 0);
    assert!(matches!(v, Verdict::Deny(_)), "expected Deny, got {v:?}");
}

#[test]
fn vector_5_approval_required() {
    let mut r = empty_rule("treasury/*");
    r.approval_spec = Some(ApprovalSpec {
        k: 1,
        eligible: vec![key(0xcc)],
    });
    let m = manifest(vec![r], DefaultAction::Deny, false);
    let mut eng = PolicyEngine::new(m).expect("valid manifest");
    let v = eng.check_signing(&signing("treasury/move", 100_000_000, 1_000, None), 0);
    match v {
        Verdict::RequireApproval(q) => {
            assert_eq!(q.k, 1);
            assert_eq!(q.eligible, vec![key(0xcc)]);
        }
        other => panic!("expected RequireApproval, got {other:?}"),
    }
}

#[test]
fn vector_6_dry_run_allow_but_flagged() {
    // Same shape as vector 1 but dry_run = true: verdict still computes (Allow),
    // and the engine surfaces the dry-run flag so the caller logs-not-enforces.
    let m = manifest(vec![empty_rule("*")], DefaultAction::Deny, true);
    let mut eng = PolicyEngine::new(m).expect("valid manifest");
    assert!(eng.is_dry_run(), "engine must surface dry-run mode");
    let v = eng.check_signing(&signing("agent/pay", 50_000, 100, None), 1_000);
    assert_eq!(v, Verdict::Allow);
}

#[test]
fn policy_id_is_stable_across_constructions() {
    // Two independent constructions of the same manifest content must produce
    // byte-identical policy_ids (cross-impl byte-equivalence requirement).
    let mut r = empty_rule("treasury/*");
    r.max_amount_sats = Some(100_000_000);
    r.min_fee_sats = Some(500);
    r.approval_spec = Some(ApprovalSpec {
        k: 1,
        eligible: vec![key(0xcc)],
    });

    let a = manifest(vec![empty_rule("agent/*"), r.clone()], DefaultAction::EscalateToHuman, false);
    let b = manifest(vec![empty_rule("agent/*"), r], DefaultAction::EscalateToHuman, false);

    assert_eq!(a.compute_policy_id(), b.compute_policy_id());
    // and the stored id equals the recomputed id
    assert_eq!(a.policy_id, a.compute_policy_id());
}
