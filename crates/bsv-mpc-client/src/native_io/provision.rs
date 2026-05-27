//! Wallet provisioning over the deployed cosigner (#65) — the **create** side of
//! the native client, completing the FFI trio (#63 sign, #64 storage, this =
//! provision). Runs the real distributed authed DKG vs the deployed container (the
//! #63-proven path), device-seals the resulting share via the [`NativeKeyStore`],
//! and returns the wallet metadata the signer's `connect()` needs.
//!
//! Keygen-over-FFI is exposed ONLY as this high-level provisioning call — never as
//! raw DKG rounds (the server-side ceremony service remains the alternative path).

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::types::{JointPublicKey, SessionId, ThresholdConfig};

use super::ceremony::DeployedCosigner;
use super::keystore::NativeKeyStore;
use crate::error::ClientError;

/// Public metadata of a freshly provisioned 2-party wallet. The share itself is
/// device-sealed in the [`NativeKeyStore`]; this is what the host persists and
/// later feeds to [`DeployedSigner::connect`](super::signer::DeployedSigner::connect).
pub struct ProvisionedWallet {
    /// Joint pubkey hex — the wallet id + owner-authz key.
    pub agent_id: String,
    /// The 2-of-2 joint public key (compressed bytes + BSV address).
    pub joint_key: JointPublicKey,
    /// Threshold config.
    pub config: ThresholdConfig,
    /// Sorted signing participant indices (e.g. `[0, 1]`).
    pub participants: Vec<u16>,
    /// This device's signing index (the coordinator party — `1` in the proven flow).
    pub device_share_index: u16,
    /// The deployed cosigner's keygen index (`0` in the proven flow).
    pub cosigner_party: u16,
    /// The DKG session id (carried on the device's `EncryptedShare`).
    pub dkg_session_id: SessionId,
}

/// Provision a 2-party wallet with the deployed cosigner: run the real distributed
/// authed DKG (device = party 1; the cosigner holds `share_A`, owner-bound to
/// `identity` §08.1), **device-seal the complete signable `share_B`** via
/// `keystore`, and return the wallet metadata. The share plaintext never leaves
/// this call except into the sealing callback.
pub async fn provision_wallet(
    container_url: &str,
    identity: PrivateKey,
    config: ThresholdConfig,
    keystore: &dyn NativeKeyStore,
) -> Result<ProvisionedWallet, ClientError> {
    let dkg = DeployedCosigner::provision_via_dkg(container_url, config, identity).await?;
    let agent_id = hex::encode(&dkg.joint_key.compressed);

    // Device-seal the complete (post-aux, signable) cggmp24 KeyShare JSON. The
    // DkgResult share ciphertext is the plaintext KeyShare (no core AES layer —
    // the Secure Enclave is the at-rest protection).
    keystore
        .seal_share(&agent_id, &dkg.share.ciphertext)
        .await?;

    let device_share_index = dkg.share.share_index.0;
    let participants: Vec<u16> = (0..config.parties).collect();
    let cosigner_party = participants
        .iter()
        .copied()
        .find(|&p| p != device_share_index)
        .ok_or_else(|| {
            ClientError::Core("no cosigner party distinct from the device index".into())
        })?;

    Ok(ProvisionedWallet {
        agent_id,
        joint_key: dkg.joint_key,
        config,
        participants,
        device_share_index,
        cosigner_party,
        dkg_session_id: dkg.session_id,
    })
}
