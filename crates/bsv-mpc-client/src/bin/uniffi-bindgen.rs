//! UniFFI binding generator entry point (native feature).
//!
//! Generates the Swift / Kotlin bindings from the built dylib, e.g.:
//! `cargo run --features native --bin uniffi-bindgen -- generate \
//!    --library target/debug/libbsv_mpc_client.dylib --language swift --out-dir <dir>`
fn main() {
    uniffi::uniffi_bindgen_main()
}
