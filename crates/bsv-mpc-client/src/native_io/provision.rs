//! Wallet provisioning over the deployed cosigner (#65) — the **create** side of
//! the native client, completing the FFI trio (#63 sign, #64 storage, this =
//! provision). Runs the real distributed authed DKG vs the deployed container (the
//! #63-proven path), device-seals the resulting share via the [`NativeKeyStore`],
//! and returns the wallet metadata the signer's `connect()` needs.
//!
//! Keygen-over-FFI is exposed ONLY as this high-level provisioning call — never as
//! raw DKG rounds (the server-side ceremony service remains the alternative path).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::error::MpcError;
use bsv_mpc_core::types::{JointPublicKey, SessionId, ThresholdConfig};
use bsv_mpc_relay::provision_dkg::{coordinate_dkg_over_relay, CosignerEndpoint, DkgOverRelay};
use bsv_mpc_relay::reshare::ArmRequestSigner;
use bsv_mpc_relay::RelaySession;

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

/// A network-side cosigner endpoint for an n-party provisioning, plus the absolute
/// keygen indices it drives. `indices.len() > 1` is the multi-index-on-one-cosigner
/// path (one Notary holding e.g. `{3, 4}`).
pub struct NpartyCosigner {
    /// The cosigner's base URL (the `/dkg-relay/init` + `/dkg-relay/peer-identity`
    /// paths are derived from it).
    pub container_url: String,
    /// The absolute keygen indices this cosigner drives.
    pub indices: Vec<u16>,
    /// **#85 MITM gate.** This Notary's MASTER identity pubkey hex, PINNED
    /// out-of-band. When `Some`, the n-party DKG verifies every fetched per-index
    /// relay pub's attestation against it AND runs a post-DKG liveness challenge
    /// before returning a fundable wallet. `None` = unpinned (dev/test only).
    pub expected_master_pub: Option<String>,
}

/// Public metadata of a freshly provisioned **n-party** (device-holds-(t−1)) wallet
/// — ADR-0052 Model B / #69 PR-2. The device's `w = t−1` shares are device-sealed
/// composite-keyed `"{agent_id}#{index}"` in the [`NativeKeyStore`]; this is the
/// metadata the multi-index signer needs.
pub struct ProvisionedWalletNparty {
    /// Joint pubkey hex — the wallet id + owner-authz key.
    pub agent_id: String,
    /// The `(t, n)` joint public key (compressed bytes + BSV address).
    pub joint_key: JointPublicKey,
    /// Threshold config.
    pub config: ThresholdConfig,
    /// All signing participant indices `0..n`.
    pub participants: Vec<u16>,
    /// This device's held keygen indices (`w = t−1` of them), ascending. Each share
    /// is sealed under `"{agent_id}#{index}"`.
    pub my_indices: Vec<u16>,
    /// The network-side (cosigner-held) indices, ascending.
    pub cosigner_indices: Vec<u16>,
    /// The DKG session id (carried on each share's metadata).
    pub dkg_session_id: SessionId,
}

/// Provision an **n-party** (device-holds-(t−1)) wallet via a genuine n-party DKG
/// over the relay (ADR-0052 Model B / §06.22): the device drives its `w = t−1`
/// in-process keygen parties while the `cosigners` drive the rest (armed via
/// `POST /dkg-relay/init`). On agreement the device's `w` signable shares are
/// device-sealed composite-keyed `"{agent_id}#{index}"`, and the wallet metadata
/// is returned.
///
/// `identity` is the device's §07.4 long-lived key — it handshakes EACH cosigner
/// (one BRC-31 session per cosigner) and is recorded as the share owner (§08.1).
///
/// Topology is validated at this boundary BEFORE any network or seal: the device
/// MUST hold exactly `w = t−1` indices and the device + cosigner indices MUST
/// partition `0..n` with no gaps or duplicates (validate-don't-skip — a malformed
/// topology rejects fast and fail-closed, nothing handshaked or sealed).
/// Optional device Paillier prime pool (Lever B / #99) threaded into the n-party
/// DKG. `storage` is the host-owned encrypted-blob persistence; `at_rest_root` +
/// `pool_id` BRC-42-derive the pool key. `None` ⇒ today's always-inline behavior.
pub struct ProvisionPrimePool {
    /// Host-owned encrypted-blob persistence (FIFO).
    pub storage: Arc<dyn bsv_mpc_core::paillier_pool::PrimePoolStorage>,
    /// 32-byte at-rest root deriving the pool encryption key.
    pub at_rest_root: [u8; 32],
    /// Domain-separation bytes (e.g. device identity pubkey).
    pub pool_id: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub async fn provision_wallet_nparty(
    relay_url: &str,
    identity: PrivateKey,
    config: ThresholdConfig,
    device_indices: Vec<u16>,
    cosigners: Vec<NpartyCosigner>,
    timeout: Duration,
    keystore: &dyn NativeKeyStore,
    prime_pool: Option<ProvisionPrimePool>,
) -> Result<ProvisionedWalletNparty, ClientError> {
    // ── Validate topology at the client boundary (fail-closed, pre-network). ──
    let w = config.threshold - 1;
    if device_indices.len() as u16 != w {
        return Err(ClientError::Core(format!(
            "provision_wallet_nparty: device must hold w = t−1 = {w} indices for a \
             {}-of-{} wallet, got {} ({device_indices:?})",
            config.threshold,
            config.parties,
            device_indices.len()
        )));
    }
    let mut all_indices: Vec<u16> = device_indices.clone();
    for c in &cosigners {
        all_indices.extend(c.indices.iter().copied());
    }
    all_indices.sort_unstable();
    let expected: Vec<u16> = (0..config.parties).collect();
    if all_indices != expected {
        return Err(ClientError::Core(format!(
            "provision_wallet_nparty: device {device_indices:?} + cosigner indices must \
             partition 0..{} with no gaps/dupes, got {all_indices:?}",
            config.parties
        )));
    }

    // ── BRC-31 handshake EACH cosigner (one session per cosigner identity), then
    //    build a per-cosigner canonical arm signer over that session. ──
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| ClientError::Core(format!("build HTTP client: {e}")))?;
    let mut endpoints: Vec<CosignerEndpoint> = Vec::with_capacity(cosigners.len());
    for c in &cosigners {
        let mut session = RelaySession::new(identity.clone());
        session.handshake(&http, &c.container_url).await?;
        let session = Arc::new(Mutex::new(session));
        let arm_signer: ArmRequestSigner = {
            let session = session.clone();
            Arc::new(
                move |method: &str,
                      path: &str,
                      body: &[u8]|
                      -> bsv_mpc_core::error::Result<Vec<(String, String)>> {
                    let guard = session
                        .lock()
                        .map_err(|_| MpcError::Protocol("cosigner auth mutex poisoned".into()))?;
                    if !guard.is_authenticated() {
                        return Ok(vec![]);
                    }
                    guard.auth_header_pairs(method, path, body)
                },
            )
        };
        let mut indices = c.indices.clone();
        indices.sort_unstable();
        endpoints.push(CosignerEndpoint {
            init_url: format!("{}/dkg-relay/init", c.container_url),
            indices,
            arm_signer,
            expected_master_pub: c.expected_master_pub.clone(),
        });
    }

    // ── Run the genuine n-party DKG over the relay. ──
    // Lever B (#99): split the optional pool into the relay struct's fields
    // (storage / at_rest_root / pool_id). Absent ⇒ inline-gen as before.
    let (pool_storage, pool_root, pool_pid) = match prime_pool {
        Some(p) => (Some(p.storage), p.at_rest_root, p.pool_id),
        None => (None, [0u8; 32], Vec::new()),
    };
    let out = coordinate_dkg_over_relay(
        DkgOverRelay {
            relay_url: relay_url.to_string(),
            threshold: config.threshold,
            parties: config.parties,
            local_indices: device_indices.clone(),
            cosigners: endpoints,
            provisional_agent_id: identity.public_key().to_hex(),
            prime_pool: pool_storage,
            at_rest_root: pool_root,
            pool_id: pool_pid,
        },
        timeout,
    )
    .await?;

    let agent_id = hex::encode(&out.joint_key.compressed);

    // ── Composite-seal each held share under "{agent_id}#{index}" (ADR-0052). ──
    for (idx, share_json) in &out.local_shares {
        keystore
            .seal_share(&format!("{agent_id}#{idx}"), share_json)
            .await?;
    }

    let mut my_indices: Vec<u16> = device_indices;
    my_indices.sort_unstable();
    let mut cosigner_indices: Vec<u16> = cosigners.iter().flat_map(|c| c.indices.clone()).collect();
    cosigner_indices.sort_unstable();

    Ok(ProvisionedWalletNparty {
        agent_id,
        joint_key: out.joint_key,
        config,
        participants: (0..config.parties).collect(),
        my_indices,
        cosigner_indices,
        dkg_session_id: out.session_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_io::keystore::MemNativeKeyStore;

    fn dummy_identity() -> PrivateKey {
        PrivateKey::from_bytes(&[0x31u8; 32]).expect("valid key")
    }

    /// Validate-don't-skip: a device holding the wrong number of indices (here 2,
    /// not w = t−1 = 3 for 4-of-6) MUST reject for the RIGHT reason, BEFORE any
    /// network or seal (fail-closed).
    #[tokio::test]
    async fn rejects_device_not_holding_t_minus_1() {
        let ks = MemNativeKeyStore::new();
        let res = provision_wallet_nparty(
            "https://relay.invalid",
            dummy_identity(),
            ThresholdConfig::new(4, 6).unwrap(),
            vec![0, 1], // wrong: should be 3 indices
            vec![NpartyCosigner {
                container_url: "https://cosigner.invalid".into(),
                indices: vec![2, 3, 4, 5],
                expected_master_pub: None,
            }],
            Duration::from_secs(1),
            &ks,
            None,
        )
        .await;
        let Err(err) = res else {
            panic!("a device not holding t−1 must reject, got Ok");
        };
        assert!(
            matches!(&err, ClientError::Core(m) if m.contains("w = t−1") && m.contains("got 2")),
            "expected a w=t−1 reject naming the bad count, got: {err:?}"
        );
        assert!(
            ks.unseal_share("any#0", "nothing sealed on reject")
                .await
                .is_err(),
            "no share must be sealed when topology rejects"
        );
    }

    /// Validate-don't-skip: device + cosigner indices that do NOT partition 0..n
    /// (here index 5 is missing, 4 duplicated) MUST reject for the RIGHT reason,
    /// fail-closed.
    #[tokio::test]
    async fn rejects_indices_not_partitioning_0_to_n() {
        let ks = MemNativeKeyStore::new();
        let res = provision_wallet_nparty(
            "https://relay.invalid",
            dummy_identity(),
            ThresholdConfig::new(4, 6).unwrap(),
            vec![0, 1, 2],
            vec![NpartyCosigner {
                container_url: "https://cosigner.invalid".into(),
                indices: vec![3, 4, 4], // gap at 5, dupe at 4
                expected_master_pub: None,
            }],
            Duration::from_secs(1),
            &ks,
            None,
        )
        .await;
        let Err(err) = res else {
            panic!("non-partitioning indices must reject, got Ok");
        };
        assert!(
            matches!(&err, ClientError::Core(m) if m.contains("partition 0..6")),
            "expected a partition reject, got: {err:?}"
        );
        assert!(
            ks.unseal_share("any#0", "nothing sealed on reject")
                .await
                .is_err(),
            "no share must be sealed when topology rejects"
        );
    }
}
