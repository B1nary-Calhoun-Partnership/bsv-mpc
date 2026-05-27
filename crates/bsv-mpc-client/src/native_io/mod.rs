//! Native-io: the native-default backings of the injected client seams (handoff
//! §4.5 Decision 2). All `Send + Sync`, native-only (`cfg(not(target_arch =
//! "wasm32"))`), reusing the EXACT mainnet-proven shared crates so the iOS/Android
//! shells get one audited Rust stack — no Swift crypto/auth.
//!
//! - [`ceremony`] + [`signer`] — the §06.17.1 deployed-cosigner SIGN seam (#63):
//!   biometric-gated `sign()` over a presig pool against the live container/relay.
//! - [`keystore`] — the `Send + Sync` Secure-Enclave callback for the deployed path.
//! - [`storage`] — the BRC-103/104 STORAGE seam (#64): `WorkerStorageClient` ported
//!   to portable HTTP, exposing `rpc(method, params) -> json`.

pub mod ceremony;
pub mod keystore;
pub mod signer;
pub mod storage;

pub use ceremony::DeployedCosigner;
pub use keystore::{MemNativeKeyStore, NativeKeyStore};
pub use signer::{DeployedSigner, DeployedSignerConfig, WalletMeta};
