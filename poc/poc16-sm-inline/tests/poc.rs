//! CI #[test] versions of the four runtime gates + a static grep
//! verifying no `std::thread::spawn` / `tokio::spawn` calls exist in
//! the POC's source. Gate G-3.5 (wasm32 build) is verified by a
//! `cargo build --target wasm32-unknown-unknown` invocation in CI, not
//! by a #[test].

use std::fs;
use std::path::PathBuf;

use poc16_sm_inline::scenarios::{
    gate_3_1_inline_keygen, gate_3_2_inline_auxinfo, gate_3_3_byte_identical_auxinfo,
    gate_3_4_at_rest_round_trip,
};

#[test]
fn gate_3_1_inline_keygen_no_thread_spawn_test() {
    gate_3_1_inline_keygen().expect("gate G-3.1");
}

#[test]
fn gate_3_2_inline_auxinfo_test() {
    gate_3_2_inline_auxinfo().expect("gate G-3.2");
}

#[test]
fn gate_3_3_byte_identical_auxinfo_test() {
    gate_3_3_byte_identical_auxinfo().expect("gate G-3.3");
}

#[test]
fn gate_3_4_at_rest_round_trip_test() {
    gate_3_4_at_rest_round_trip().expect("gate G-3.4");
}

/// Static check: this POC crate's `src/` must contain no actual
/// `std::thread::spawn` or `tokio::spawn` *call sites* (the whole point
/// of the inline rewrite is that we can drive
/// `round_based::StateMachine` without either). The check looks for the
/// `xxx(` form so that doc comments mentioning the API name (which is
/// the whole point of this module) do NOT trip the gate.
///
/// To suppress a false positive in this file's own doc comments, we
/// also skip lines whose pre-trim starts with a doc-comment marker.
#[test]
fn gate_3_1_no_thread_or_tokio_spawn_in_source() {
    let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    // Each needle is the exact call-site form, not the bare path.
    let forbidden_call_sites = [
        "thread::spawn(",
        "thread::Builder::",
        "tokio::spawn(",
        "tokio::task::spawn(",
        "tokio::task::spawn_local(",
        "spawn_local(",
    ];

    for entry in fs::read_dir(&src_dir).expect("read src dir") {
        let entry = entry.expect("entry");
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let body = fs::read_to_string(&path).expect("read source");
        for (lineno, raw_line) in body.lines().enumerate() {
            let trimmed = raw_line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }
            for needle in &forbidden_call_sites {
                assert!(
                    !raw_line.contains(needle),
                    "forbidden call site {needle:?} at {}:{}: {raw_line:?} — Phase G design \
                     is inline; no thread/tokio spawn calls are allowed in the POC's source",
                    path.display(),
                    lineno + 1
                );
            }
        }
    }
}
