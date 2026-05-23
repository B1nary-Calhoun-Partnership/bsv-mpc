//! Conformance suite for MPC-Spec §09.5.1 / ADR-0044 + ADR-0032
//! (`request_view_hash` rendered-text byte-lock).
//!
//! Drives the vector at `tests/fixtures/09-rendered-text.json` (vendored from
//! the MPC-Spec repo so this crate compiles standalone).
//!
//! For each of the 5 vectors we read `binding_inputs`, rebuild the canonical
//! CBOR preimage and the SHA-256 `request_view_hash` through
//! `bsv_mpc_core::approval::request_view_hash`, and assert byte-equality with
//! BOTH locked fields:
//!   - `request_view_hash_preimage_cbor_hex` (the canonical CBOR map {1..8})
//!   - `request_view_hash` (SHA-256 of that preimage)
//!
//! A divergence here means bsv-mpc would bind a DIFFERENT approval prompt to a
//! signing request than the canonical spec / rust-mpc, breaking the §09 wallet
//! approval-binding gate.

use bsv_mpc_core::approval::{request_view_hash, Recipient};
use serde_json::Value;

const VECTORS: &str = include_str!("fixtures/09-rendered-text.json");

fn root() -> Value {
    let r: Value = serde_json::from_str(VECTORS).expect("vector json parses");
    assert_eq!(
        r["spec_section"], "09.5.1 + ADR-0044",
        "vector file is §09.5.1 + ADR-0044"
    );
    r
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing string field {key}"))
}

/// Parse key 2 (recipient): a JSON string → `Single`, a JSON array of strings
/// → `Multi`.
fn recipient(v: &Value) -> Recipient {
    if let Some(text) = v.as_str() {
        Recipient::Single(text.to_string())
    } else if let Some(arr) = v.as_array() {
        Recipient::Multi(
            arr.iter()
                .map(|item| item.as_str().expect("recipient array item is text").to_string())
                .collect(),
        )
    } else {
        panic!("recipient must be a string or array of strings");
    }
}

#[test]
fn request_view_hash_reproduces_locked_vectors_byte_for_byte() {
    let r = root();
    let vectors = r["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 5, "§09 has 5 rendered-text vectors");

    for v in vectors {
        let name = s(v, "name");
        let bi = &v["binding_inputs"];

        let amount = bi["amount"].as_u64().unwrap_or_else(|| {
            panic!("{name}: binding_inputs.amount must be an unsigned integer")
        });
        let recip = recipient(&bi["recipient"]);

        let result = request_view_hash(
            amount,
            &recip,
            s(bi, "sighash_hex"),
            s(bi, "execution_id_hex"),
            s(bi, "policy_id_hex"),
            s(bi, "manifest_ack_hex"),
            s(bi, "human_locale"),
            s(bi, "rendered_text"),
        );

        // (a) canonical CBOR preimage byte-equality.
        let expected_preimage = s(v, "request_view_hash_preimage_cbor_hex");
        assert_eq!(
            hex::encode(&result.preimage),
            expected_preimage,
            "{name}: CBOR preimage diverges from locked vector"
        );

        // (b) SHA-256(preimage) == request_view_hash.
        let expected_hash = s(v, "request_view_hash");
        assert_eq!(
            hex::encode(result.hash),
            expected_hash,
            "{name}: request_view_hash diverges from locked vector"
        );

        // (c) sanity: binding_inputs.rendered_text == locked expected_rendered_text.
        assert_eq!(
            s(bi, "rendered_text"),
            s(v, "expected_rendered_text"),
            "{name}: binding_inputs.rendered_text must equal expected_rendered_text"
        );

        println!("OK   {name}: preimage + request_view_hash reproduce byte-for-byte");
    }
}
