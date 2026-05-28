//! RED → GREEN tests for audit #77 (env-driven proxy binary ran with
//! `policy_engine: None`).
//!
//! Before the fix, `server::run` hardcoded `policy_engine: None` at
//! `server.rs:284`, so any container/CF Worker deploying the proxy via the
//! env-driven entry point ran without an enforced PolicyManifest. The fix
//! introduces [`bsv_mpc_proxy::server::load_policy_engine_from_config`] which:
//!
//!  - **fails fast** on `MPC_NETWORK=mainnet` with no `MPC_POLICY_MANIFEST`,
//!  - **loads + builds the engine** when the manifest path is provided, and
//!  - **preserves prior behavior** (no policy → no gate) for testnet/dev.
//!
//! Drives the loader through `ProxyConfig` literals (not the global env-var
//! reader) so the tests are deterministic under parallel `cargo test`.

use bsv_mpc_core::policy::{DefaultAction, PolicyManifest, Rule};
use bsv_mpc_core::types::PolicyId;
use bsv_mpc_proxy::config::ProxyConfig;
use bsv_mpc_proxy::server::load_policy_engine_from_config;

// ─── Fixtures ───────────────────────────────────────────────────────────────

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

fn deny_manifest() -> PolicyManifest {
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
        dry_run: false,
    };
    m.policy_id = m.compute_policy_id();
    m
}

fn base_config() -> ProxyConfig {
    ProxyConfig {
        port: 0,
        kss_url: "http://policy-loader-test.invalid".into(),
        share_path: "/tmp/policy-loader-test-share".into(),
        fee_per_signing: 0,
        fee_addresses: vec![],
        fee_threshold: None,
        max_presignatures: 1,
        encryption_key: None,
        arc_api_key: "unused".into(),
        threshold_configs: vec!["2-of-2".to_string()],
        min_balance_sats: None,
        relay_url: "http://policy-loader-test.invalid".into(),
        relay_sign: true,
        presign_url: None,
        approval_recv_timeout_secs: 1,
        network: None,
        policy_manifest_path: None,
    }
}

// ─── #77 RED → GREEN ────────────────────────────────────────────────────────

/// #77 RED: mainnet + no manifest MUST refuse to start with a clear error.
/// Before the fix, `server::run` accepted this configuration silently and
/// served traffic with `policy_engine: None`.
#[test]
fn red_77_mainnet_without_manifest_is_refused() {
    let mut config = base_config();
    config.network = Some("mainnet".into());
    config.policy_manifest_path = None;

    let err = load_policy_engine_from_config(&config)
        .expect_err("mainnet + no manifest MUST be refused");
    let s = format!("{err}");
    assert!(
        s.contains("MPC_NETWORK=mainnet") && s.contains("MPC_POLICY_MANIFEST"),
        "rejection must name BOTH env vars so operators know what to fix; got: {s}"
    );
}

/// #77 (case-insensitive variant): `"MAINNET"` and `"MainNet"` must trigger the
/// same fail-closed branch — operators set the var inconsistently across shell
/// histories and a silently-accepted-typo would re-introduce the audit gap.
#[test]
fn red_77_mainnet_signal_is_case_insensitive() {
    for value in &["MAINNET", "MainNet", "mainnet"] {
        let mut config = base_config();
        config.network = Some((*value).into());
        let err = load_policy_engine_from_config(&config)
            .err()
            .unwrap_or_else(|| panic!("MPC_NETWORK={value:?} MUST be refused without manifest"));
        let s = format!("{err}");
        assert!(
            s.contains("mainnet"),
            "rejection reason must call out mainnet for {value:?}; got: {s}"
        );
    }
}

/// #77 positive: testnet without a manifest is allowed (prior behavior).
/// This is the "no asterisks" pair: we don't want the fix to over-correct and
/// break dev / testnet runs.
#[test]
fn red_77_testnet_without_manifest_is_allowed() {
    let mut config = base_config();
    config.network = Some("testnet".into());
    config.policy_manifest_path = None;

    let engine = load_policy_engine_from_config(&config)
        .expect("testnet + no manifest is permitted (no policy gate)");
    assert!(
        engine.is_none(),
        "no manifest configured → no engine; got {:?}",
        engine.is_some()
    );
}

/// #77 positive: `None` network (i.e. operator didn't set `MPC_NETWORK` at all)
/// also runs without a gate. Mainnet operators MUST opt in explicitly.
#[test]
fn red_77_no_network_without_manifest_is_allowed() {
    let config = base_config();
    assert!(config.network.is_none());
    assert!(config.policy_manifest_path.is_none());

    let engine = load_policy_engine_from_config(&config)
        .expect("unset network + no manifest is permitted");
    assert!(engine.is_none());
}

/// #77 positive: mainnet WITH a CBOR-encoded manifest on disk loads the engine
/// successfully. Round-trip proof that the loader actually parses + builds.
#[test]
fn red_77_mainnet_with_manifest_loads_engine() {
    let bytes = deny_manifest()
        .to_cbor()
        .expect("encode test manifest as CBOR");
    let tmp = tempfile::NamedTempFile::new().expect("temp file");
    std::fs::write(tmp.path(), &bytes).expect("write manifest bytes");

    let mut config = base_config();
    config.network = Some("mainnet".into());
    config.policy_manifest_path = Some(tmp.path().to_string_lossy().to_string());

    let engine = load_policy_engine_from_config(&config)
        .expect("mainnet + valid manifest must load")
        .expect("Some(engine) when manifest is present");
    assert!(!engine.is_dry_run());
}

/// #77 negative: a manifest path that doesn't exist surfaces a clear error
/// (not a silent fall-through to `Ok(None)`). Mirrors the same fail-fast bar.
#[test]
fn red_77_missing_manifest_file_is_a_hard_error() {
    let mut config = base_config();
    config.network = Some("testnet".into());
    config.policy_manifest_path = Some("/nonexistent/path/manifest.cbor".into());

    let err = load_policy_engine_from_config(&config)
        .expect_err("missing manifest file MUST fail loud, not silently no-op");
    let s = format!("{err}");
    assert!(
        s.contains("MPC_POLICY_MANIFEST") || s.contains("/nonexistent/path/manifest.cbor"),
        "error must identify the bad path; got: {s}"
    );
}

/// #77 negative: a manifest file with garbage bytes surfaces a parse error.
#[test]
fn red_77_invalid_manifest_bytes_is_a_hard_error() {
    let tmp = tempfile::NamedTempFile::new().expect("temp file");
    std::fs::write(tmp.path(), b"not valid cbor at all").expect("write garbage");

    let mut config = base_config();
    config.network = Some("mainnet".into());
    config.policy_manifest_path = Some(tmp.path().to_string_lossy().to_string());

    let err = load_policy_engine_from_config(&config)
        .expect_err("garbage manifest bytes MUST fail parse");
    let s = format!("{err}");
    assert!(
        s.contains("MPC_POLICY_MANIFEST") || s.contains("parse"),
        "error must indicate parse failure on the manifest; got: {s}"
    );
}
