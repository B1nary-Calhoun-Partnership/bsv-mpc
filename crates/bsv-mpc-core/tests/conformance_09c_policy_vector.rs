//! **§09 policy conformance vector (byte-lock).** Mirrors
//! `MPC-Spec/conformance/test-vectors/09-policy.json` — a fully-specified
//! `PolicyManifest` whose `compute_policy_id` is byte-locked, plus the six
//! §09.14 verdict cases. Locking these makes any future change to the canonical
//! CBOR encoding (the `policy_id` field-set or the integer-key convention,
//! settled in MPC-Spec#43) fail loudly here AND in the shared vector — the
//! §09.15 cross-impl byte-equivalence guarantee.

use bsv_mpc_core::policy::*;
use bsv_mpc_core::types::PolicyId;

/// 33-byte compressed pubkey filled with `b` (deterministic fixture key).
fn key(b: u8) -> Vec<u8> {
    let mut k = vec![0x02; 33];
    k[1] = b;
    k
}

/// THE canonical §09 fixture manifest (identical to 09-policy.json).
fn fixture() -> PolicyManifest {
    let mut m = PolicyManifest {
        version: 7,
        policy_id: PolicyId([0u8; 32]),
        cosigner_identity: key(0xAA),
        group_key: key(0xBB),
        rules: vec![
            Rule {
                protocol_pattern: "agent/*".to_string(),
                max_amount_sats: Some(50_000),
                max_per_hour: Some(20),
                cumulative_daily_cap_sats: None,
                allowed_window: None,
                counterparty_allowlist: None,
                counterparty_denylist: None,
                min_fee_sats: Some(100),
                jurisdiction: None,
                approval_spec: None,
                attestation_spec: None,
            },
            Rule {
                protocol_pattern: "treasury/*".to_string(),
                max_amount_sats: Some(100_000_000),
                max_per_hour: None,
                cumulative_daily_cap_sats: None,
                allowed_window: None,
                counterparty_allowlist: None,
                counterparty_denylist: None,
                min_fee_sats: None,
                jurisdiction: None,
                approval_spec: Some(ApprovalSpec {
                    k: 1,
                    eligible: vec![key(0xCC)],
                }),
                attestation_spec: None,
            },
        ],
        default_action: DefaultAction::Deny,
        effective_after_ms: 0,
        expires_after_ms: None,
        prev_policy_id: None,
        approver_keys: vec![key(0xCC)],
        approver_sigs: vec![],
        dry_run: false,
    };
    m.policy_id = m.compute_policy_id();
    m
}

/// Byte-lock: the canonical fixture's `policy_id` (locked in MPC-Spec#43).
const LOCKED_POLICY_ID: &str = "d901a996cdbf7af492a0397f45bbc9bc99ed03c573463e8e2412753732af8382";

#[test]
fn policy_id_is_byte_locked() {
    assert_eq!(
        fixture().policy_id.hex(),
        LOCKED_POLICY_ID,
        "canonical fixture policy_id changed — the §09.2 CBOR encoding diverged \
         from the locked vector (MPC-Spec#43). Update both or revert."
    );
}

#[test]
fn manifest_cbor_round_trips() {
    let m = fixture();
    let bytes = m.to_cbor().expect("to_cbor");
    let back = PolicyManifest::from_cbor(&bytes).expect("from_cbor");
    assert_eq!(m, back);
    // policy_id is stable across a round-trip recompute.
    assert_eq!(back.compute_policy_id().hex(), LOCKED_POLICY_ID);
}

#[test]
fn verdicts_match_the_locked_vector() {
    let mut eng = PolicyEngine::new(fixture()).expect("engine");
    let now = 1_700_000_000_000u64;
    let chk = |proto: &str, amount: u64, fee: u64| SigningCheck {
        protocol_id: proto.to_string(),
        amount_sats: amount,
        fee_sats: fee,
        counterparty: None,
    };

    // 1. permissive agent/* under cap → Allow
    assert_eq!(
        eng.check_signing(&chk("agent/api-x", 1000, 200), now),
        Verdict::Allow
    );
    // 2. agent/* over max_amount → Deny
    assert!(matches!(
        eng.check_signing(&chk("agent/api-x", 60_000, 200), now),
        Verdict::Deny(_)
    ));
    // 3. agent/* fee below min_fee → Deny
    assert!(matches!(
        eng.check_signing(&chk("agent/api-x", 1000, 50), now),
        Verdict::Deny(_)
    ));
    // 4. treasury/* → RequireApproval k=1
    match eng.check_signing(&chk("treasury/move", 1_000_000, 1000), now) {
        Verdict::RequireApproval(q) => {
            assert_eq!(q.k, 1);
            assert_eq!(q.eligible, vec![key(0xCC)]);
        }
        other => panic!("expected RequireApproval, got {other:?}"),
    }
    // 5. no rule match → default Deny
    assert!(matches!(
        eng.check_signing(&chk("other/thing", 1, 1), now),
        Verdict::Deny(_)
    ));
    // 6. rate limit: the 21st agent/* op within the hour (cap 20) → RateLimited
    let mut last = Verdict::Allow;
    for _ in 0..21 {
        last = eng.check_signing(&chk("agent/api-x", 1000, 200), now);
    }
    assert!(matches!(last, Verdict::RateLimited { .. }));
}
