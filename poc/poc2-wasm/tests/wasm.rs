//! POC 2: WASM tests — run cggmp24 DKG + signing in Node.js via wasm-bindgen-test
//!
//! Run with: wasm-pack test --node

use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn test_dkg_in_wasm() {
    let pubkey = poc2_wasm::run_dkg();
    assert_eq!(pubkey.len(), 66, "compressed pubkey should be 66 hex chars (33 bytes)");
    assert!(
        pubkey.starts_with("02") || pubkey.starts_with("03"),
        "compressed pubkey should start with 02 or 03"
    );
    web_sys::console::log_1(&format!("DKG pubkey: {pubkey}").into());
}

#[wasm_bindgen_test]
fn test_full_dkg_sign_verify_in_wasm() {
    let result = poc2_wasm::run_full_test();
    assert!(result.starts_with("PASS:"), "full test should pass, got: {result}");
    // Print timings to Node.js console
    web_sys::console::log_1(&format!("Full test result: {result}").into());
}
