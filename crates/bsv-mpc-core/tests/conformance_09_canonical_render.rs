//! Conformance suite for MPC-Spec §09.5.1 / ADR-0044 §2 (canonical wallet
//! renderer) — `canonical_render(intent) -> rendered_text` byte-lock.
//!
//! Sibling to `conformance_09_rendered_text.rs` (which byte-locks the CBOR
//! preimage + SHA-256 `request_view_hash` upstream of the rendered string).
//! This file drives the SAME fixture but exercises the renderer step: for
//! each of the 5 vectors we deserialize `vector.intent` into the typed
//! [`bsv_mpc_core::approval::Intent`] enum, call `canonical_render`, and
//! assert the output equals `vector.expected_rendered_text` byte-for-byte.
//! It also asserts the intent round-trips through serde without losing
//! fields, guarding against accidental `#[serde(skip)]` regressions.
//!
//! A divergence here means bsv-mpc would DISPLAY a different string than
//! rust-mpc (or the Python conformance runner) for the same intent, breaking
//! the WYSIWYS handoff that 100cash#15 depends on.

use bsv_mpc_core::approval::{canonical_render, Intent};
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

#[test]
fn canonical_render_reproduces_locked_vectors_byte_for_byte() {
    let r = root();
    let vectors = r["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 5, "§09 has 5 rendered-text vectors");

    for v in vectors {
        let name = v["name"].as_str().expect("name");
        let expected = v["expected_rendered_text"]
            .as_str()
            .expect("expected_rendered_text");

        // (a) the fixture's `intent` block deserializes into the typed Intent
        // enum without loss (no extra fields, no missing required fields).
        let intent: Intent = serde_json::from_value(v["intent"].clone())
            .unwrap_or_else(|e| panic!("{name}: Intent deserialize failed: {e}"));

        // (b) canonical_render(intent) reproduces the locked expected_rendered_text
        // byte-for-byte — this IS the WYSIWYS gate.
        let got = canonical_render(&intent)
            .unwrap_or_else(|e| panic!("{name}: canonical_render errored: {e}"));
        assert_eq!(
            got, expected,
            "{name}: canonical_render diverges from locked expected_rendered_text"
        );

        // (c) round-trip the parsed intent back to JSON and re-parse — guards
        // against accidental `#[serde(skip)]` / field-rename regressions.
        let json = serde_json::to_string(&intent)
            .unwrap_or_else(|e| panic!("{name}: re-serialize failed: {e}"));
        let back: Intent = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("{name}: re-deserialize failed: {e}"));
        assert_eq!(intent, back, "{name}: serde round-trip diverges");

        // (d) cross-check: the SAME string also appears at
        // `binding_inputs.rendered_text` (upstream of `request_view_hash`).
        // If `canonical_render` matches `expected_rendered_text` AND
        // `binding_inputs.rendered_text == expected_rendered_text` (already
        // asserted in `conformance_09_rendered_text.rs`), then the renderer's
        // output is what gets bound into the view hash. Asserted here too so
        // the two test files independently catch a drift.
        let binding_rendered = v["binding_inputs"]["rendered_text"]
            .as_str()
            .expect("binding_inputs.rendered_text");
        assert_eq!(
            got, binding_rendered,
            "{name}: canonical_render output must equal binding_inputs.rendered_text"
        );

        println!("OK   {name}: canonical_render reproduces expected text");
    }
}
