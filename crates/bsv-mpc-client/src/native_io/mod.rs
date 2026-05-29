//! Native-io: the native-default backings of the injected client seams (handoff
//! §4.5 Decision 2). All `Send + Sync`, native-only (`cfg(not(target_arch =
//! "wasm32"))`), reusing the EXACT mainnet-proven shared crates so the iOS/Android
//! shells get one audited Rust stack — no Swift crypto/auth.
//!
//! - [`ceremony`] + [`signer`] — the §06.17.1 deployed-cosigner SIGN seam (#63):
//!   biometric-gated `sign()` over a presig pool against the live container/relay.
//! - [`provision`] — the PROVISION/create seam (#65): DKG-over-relay vs the deployed
//!   cosigner → device-seal the share → wallet metadata for the signer's `connect()`.
//! - [`recover`] — the RECOVERY seam (#66): address-preserving reshare of the EXISTING
//!   wallet onto a fresh device from the L1 backup share B → device-seal the rotated
//!   share → wallet metadata (same shape as `provision`, ready for `connect()`).
//! - [`keystore`] — the `Send + Sync` Secure-Enclave callback for the deployed path.
//! - [`storage`] — the BRC-103/104 STORAGE seam (#64): `WorkerStorageClient` ported
//!   to portable HTTP, exposing `rpc(method, params) -> json`.

pub mod ceremony;
pub mod keystore;
pub mod multipresig;
pub mod provision;
pub mod recover;
pub mod signer;
pub mod storage;

pub use ceremony::DeployedCosigner;
pub use keystore::{MemNativeKeyStore, NativeKeyStore};
pub use multipresig::{DeviceMultiPresig, MultiPresigStore};
pub use provision::{
    provision_wallet, provision_wallet_nparty, NpartyCosigner, ProvisionedWallet,
    ProvisionedWalletNparty,
};
pub use recover::recover_wallet;
pub use signer::{DeployedSigner, DeployedSignerConfig, WalletMeta};
