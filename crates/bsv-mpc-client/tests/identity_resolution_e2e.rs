//! **#95 live overlay identity resolution** (env-gated; mainnet overlay; no sats, no
//! keys). Proves the read-only identity-resolution FFI completes a real `ls_identity`
//! lookup over the BSV overlay end-to-end via a keyless `ProtoWallet::anyone()`. The
//! mapping correctness (`DisplayableIdentity` → FFI, network preset, client build) is
//! covered by the pure in-module tests in `ffi.rs`; this asserts the live round-trip.
//!
//! ```bash
//! CLIENT_IDENTITY_LIVE=1 cargo test -p bsv-mpc-client --features native \
//!   --test identity_resolution_e2e -- --nocapture --test-threads=1
//! ```
#![cfg(all(not(target_arch = "wasm32"), feature = "native"))]

use bsv_mpc_client::ffi::{ffi_resolve_identity_by_key, FfiOverlayNetwork};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resolve_identity_by_key_completes_over_mainnet_overlay() {
    if std::env::var("CLIENT_IDENTITY_LIVE").ok().as_deref() != Some("1") {
        eprintln!("CLIENT_IDENTITY_LIVE=1 not set — skipping the live overlay resolution.");
        return;
    }
    // An arbitrary valid compressed key (the secp256k1 generator G). We assert the
    // overlay query + parse path COMPLETES (Ok) — Some or None both prove the live
    // round-trip works; the mapping correctness is covered by the pure unit tests.
    let key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    match ffi_resolve_identity_by_key(key.to_string(), FfiOverlayNetwork::Mainnet, false, vec![])
        .await
    {
        Ok(found) => eprintln!(
            "✔ live mainnet overlay resolution completed (found = {})",
            found.map(|d| d.name).unwrap_or_else(|| "<none>".into())
        ),
        Err(e) => panic!("live overlay resolution MUST complete without error: {e}"),
    }
}
