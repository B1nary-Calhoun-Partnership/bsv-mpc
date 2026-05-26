//! Conformance suite for MPC-Spec §18.5 + ADR-0038 (recovery-KDF Argon2id
//! byte-lock).
//!
//! Drives the canonical locked vector at
//! `tests/fixtures/18-recovery-kdf.json`. For each pinned
//! `(passphrase, salt, m, t, p)` input, bsv-mpc-core's `recovery` module MUST
//! reproduce the locked 32-byte KEK byte-for-byte. A divergence here means
//! bsv-mpc derives a DIFFERENT key-encryption key than the canonical
//! @bsv / rust-mpc Argon2id for the same recovery passphrase, so no cross-impl
//! backup-blob decrypt would work.
//!
//! NOTE: the `profile-server` vectors run Argon2id at 256 MiB; each derivation
//! is CPU/memory-heavy and may take a few seconds. That is expected.

use bsv_mpc_core::recovery::{derive_recovery_kek, derive_recovery_kek_raw, RecoveryProfile};
use serde_json::Value;

const VECTORS: &str = include_str!("fixtures/18-recovery-kdf.json");

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing string field {key}"))
}

fn u32_field(v: &Value, key: &str) -> u32 {
    u32::try_from(
        v[key]
            .as_u64()
            .unwrap_or_else(|| panic!("missing/invalid u64 field {key}")),
    )
    .unwrap_or_else(|_| panic!("field {key} does not fit u32"))
}

fn profile_from_str(name: &str) -> RecoveryProfile {
    match name {
        "profile-server" => RecoveryProfile::Server,
        "profile-mobile" => RecoveryProfile::Mobile,
        other => panic!("unknown profile {other}"),
    }
}

/// Every locked vector's KEK reproduces byte-for-byte via the self-describing
/// raw path (using the vector's own pinned parameters).
#[test]
fn recovery_kek_vectors_reproduce_byte_for_byte() {
    let r: Value = serde_json::from_str(VECTORS).expect("vector json parses");
    assert_eq!(
        r["spec_section"], "18.5 + ADR-0038",
        "vector file is §18.5 + ADR-0038"
    );

    let vectors = r["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 3, "§18 has 3 recovery-KDF vectors");

    for v in vectors {
        let name = s(v, "name");
        let inp = &v["inputs"];

        assert_eq!(
            s(inp, "algorithm"),
            "Argon2id",
            "{name}: algorithm must be Argon2id"
        );
        assert_eq!(
            u32_field(inp, "hash_len"),
            32,
            "{name}: hash_len must be 32"
        );

        let passphrase = hex::decode(s(inp, "passphrase_utf8_bytes_hex"))
            .unwrap_or_else(|e| panic!("{name}: passphrase hex: {e}"));
        let salt =
            hex::decode(s(inp, "salt_hex")).unwrap_or_else(|e| panic!("{name}: salt hex: {e}"));
        let m = u32_field(inp, "memory_cost_kib");
        let t = u32_field(inp, "time_cost");
        let p = u32_field(inp, "parallelism");
        let expected = s(v, "expected_kek_hex");

        // Self-describing raw path: feed the vector's own pinned m/t/p.
        let kek = derive_recovery_kek_raw(&passphrase, &salt, m, t, p)
            .unwrap_or_else(|e| panic!("{name}: derive_recovery_kek_raw failed: {e}"));
        assert_eq!(
            hex::encode(kek),
            expected,
            "{name}: KEK diverges (raw path)"
        );

        // Cross-check: the named profile must select the same pinned params, so
        // the profile path MUST produce the identical KEK.
        let profile = profile_from_str(s(inp, "profile"));
        assert_eq!(
            profile.params(),
            (m, t, p),
            "{name}: profile params disagree with vector's pinned m/t/p"
        );
        let kek_profile = derive_recovery_kek(&passphrase, &salt, profile)
            .unwrap_or_else(|e| panic!("{name}: derive_recovery_kek failed: {e}"));
        assert_eq!(
            hex::encode(kek_profile),
            expected,
            "{name}: KEK diverges (profile path)"
        );
    }
}
