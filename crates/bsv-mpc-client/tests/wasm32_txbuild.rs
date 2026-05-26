//! wasm32 byte-identity gate for the lifted tx helpers (#41 proof-plan Tier 3).
//!
//! Asserts the SAME golden vector as the native unit test
//! (`txbuild::tests::demo_vector_matches_golden`). When both the native test and
//! this wasm32 test pass, the BIP-143 sighash + tx serialization are
//! **byte-identical on native and `wasm32-unknown-unknown`** — the property the
//! native client depends on (sign on-device in wasm, verify/broadcast anywhere).
//!
//! Run: `wasm-pack test --node -p bsv-mpc-client --test wasm32_txbuild`
#![cfg(target_arch = "wasm32")]

use bsv_mpc_client::txbuild::{compute_txid, demo_serialized, demo_sighash};
use wasm_bindgen_test::wasm_bindgen_test;

// Same constants as the native test (txbuild.rs). Duplicated deliberately so the
// two targets are checked against one shared expected value.
const GOLDEN_SIGHASH_HEX: &str = "96168d5c91a6893797a4eda3354831340c51951a468e8ca32bad7c2ea8418934";
const GOLDEN_TXID_HEX: &str = "67f647fe4eabce169056d3533a51f6e27202d413e1896fab5f8a761b942bb634";

#[wasm_bindgen_test]
fn wasm_tx_helpers_are_byte_identical_to_native() {
    assert_eq!(hex::encode(demo_sighash()), GOLDEN_SIGHASH_HEX);
    assert_eq!(compute_txid(&demo_serialized()), GOLDEN_TXID_HEX);
}
