//! Wallet RECOVERY over the deployed cosigner (#66) — the **L1 backup-share**
//! recovery seam, completing the FFI quartet (create #65 / sign #63 / storage #64 /
//! recover this). Removes the last `notImplemented` mock on 100cash's native
//! ceremony path (`RealMpcCeremonyService.recoverOntoThisDevice()`).
//!
//! Runs the ADDRESS-PRESERVING reshare of the EXISTING wallet onto THIS fresh /
//! lost-phone device, using the host-supplied **backup share B** (the
//! passkey-PRF-unwrapped old device key share). This device contributes B as its OLD
//! secret into the reshare; the deployed container is the other contributor; the
//! joint pubkey is UNCHANGED (same address, no funds move). The rotated new device
//! share is device-sealed via the [`NativeKeyStore`] and the wallet metadata
//! returned (same shape as [`provision_wallet`](super::provision::provision_wallet),
//! ready for `DeployedSigner::connect`).
//!
//! Why a reshare and not a re-seal: the reshare ROTATES both shares (Proactive
//! Secret Sharing), so the lost phone's old copy of B is cryptographically DEAD
//! afterward — recovery doubles as a key-rotation. The joint key (and thus the
//! address + funds) is preserved.
//!
//! Contrast with #40 (L2 trustee / true-loss): there the device has NO prior share
//! and survivors reshare onto it (a 2-of-3 survivor quorum). L1 is the same-ecosystem
//! convenience path — the device kept its PRF-wrapped backup, so both old shares are
//! available and the reshare is a clean `2-of-2 → 2-of-2` rotation.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bsv::primitives::ec::{PrivateKey, PublicKey};
use bsv_mpc_core::error::MpcError;
use bsv_mpc_core::types::{JointPublicKey, SessionId, ThresholdConfig};
use bsv_mpc_relay::reshare::ArmRequestSigner;
use bsv_mpc_relay::{
    coordinate_reshare_over_relay, parse_old_share_topology, RelaySession, ReshareOverRelay,
};

use super::keystore::NativeKeyStore;
use super::provision::ProvisionedWallet;
use crate::error::ClientError;

/// Recover the EXISTING wallet onto THIS device via an address-preserving reshare
/// from the host-supplied backup share B (`backup_factor` = the PRF-unwrapped old
/// cggmp24 key share JSON). Drives the device's NEW-set party as the OLD-secret
/// contributor against the deployed container (the other contributor), device-seals
/// the rotated share, and returns the wallet metadata. The joint pubkey — and thus
/// the address — is UNCHANGED; the lost phone's old share is dead after the rotation.
///
/// `identity` MUST be the SAME §07.4 long-lived key recorded as owner at create time
/// (§08.1 owner-authz on `/reshare-relay/init`), so the host passes the persisted
/// identity key, not a fresh one.
pub async fn recover_wallet(
    relay_url: &str,
    container_url: &str,
    identity: PrivateKey,
    backup_factor: Vec<u8>,
    timeout: Duration,
    keystore: &dyn NativeKeyStore,
) -> Result<ProvisionedWallet, ClientError> {
    // 1. Derive the OLD topology + joint pubkey K from the backup share ALONE — the
    //    wallet id (agent_id) is the address the device is restoring, carried inside
    //    the share, so no separate joint-pubkey input is needed.
    let topo = parse_old_share_topology(&backup_factor)?;
    // L1 v1 supports the proven 2-of-2 device+cosigner wallet (the #65 create shape).
    // Other topologies (L2 trustee / true-loss) are the #40 survivor-quorum path.
    if topo.threshold != 2 || topo.parties != 2 {
        return Err(ClientError::Core(format!(
            "recover_wallet (L1 backup-share) supports a 2-of-2 wallet; backup share is {}-of-{}",
            topo.threshold, topo.parties
        )));
    }
    let device_index = topo.old_index;
    let all_old: Vec<u16> = (0..topo.parties).collect();
    let container_index = all_old
        .iter()
        .copied()
        .find(|&i| i != device_index)
        .ok_or_else(|| {
            ClientError::Core("no container party distinct from the device index".into())
        })?;
    let agent_id = hex::encode(&topo.joint_pubkey_compressed);

    // 2. BRC-31 handshake against the container (the SAME identity recorded as owner
    //    at create time), then the canonical request-signer over that session.
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| ClientError::Core(format!("build HTTP client: {e}")))?;
    let mut session = RelaySession::new(identity.clone());
    session.handshake(&http, container_url).await?;
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
                    .map_err(|_| MpcError::Protocol("container auth mutex poisoned".into()))?;
                if !guard.is_authenticated() {
                    return Ok(vec![]);
                }
                guard.auth_header_pairs(method, path, body)
            },
        )
    };

    // 3. Address-preserving reshare: NEW set == OLD set (2-of-2, same indices) — a
    //    clean rotation. The device plays its own index as the contributor (old
    //    secret = backup B); the container plays its index. Both rotate; K is
    //    UNCHANGED (the coordinator rejects any commit whose joint pubkey changed).
    let contributor_indices = all_old.clone(); // already ascending 0..n
    let out = coordinate_reshare_over_relay(
        ReshareOverRelay {
            relay_url: relay_url.to_string(),
            container_init_url: format!("{container_url}/reshare-relay/init"),
            agent_id: agent_id.clone(),
            joint_pubkey_compressed: topo.joint_pubkey_compressed.clone(),
            new_threshold: topo.threshold,
            new_parties: topo.parties,
            contributor_new_indices: contributor_indices.clone(),
            contributor_old_indices: contributor_indices,
            container_new_index: container_index,
            local_new_indices: vec![device_index],
            local_contributor_new_index: device_index,
            local_contributor_old_index: device_index,
            local_contributor_old_share_json: backup_factor,
        },
        arm_signer,
        timeout,
    )
    .await?;

    // 4. The recovered device share = the single in-process party's rotated KeyShare.
    let new_share_json = out
        .local_key_shares_json
        .into_iter()
        .find(|(idx, _)| *idx == device_index)
        .map(|(_, json)| json)
        .ok_or_else(|| ClientError::Core("reshare produced no device share".into()))?;

    // 5. Device-seal the rotated share (consumed here, not retained).
    keystore.seal_share(&agent_id, &new_share_json).await?;

    // 6. Wallet metadata — joint pubkey UNCHANGED ⇒ SAME address (the #35/#18
    //    invariant). The session id is share metadata only (no DKG was run).
    let address = PublicKey::from_bytes(&topo.joint_pubkey_compressed)
        .map(|pk| pk.to_address())
        .map_err(|e| ClientError::Core(format!("joint pubkey parse: {e}")))?;
    let mut participants = vec![device_index, container_index];
    participants.sort_unstable();
    let config = ThresholdConfig::new(out.new_threshold, out.new_parties)?;

    Ok(ProvisionedWallet {
        agent_id: agent_id.clone(),
        joint_key: JointPublicKey {
            compressed: topo.joint_pubkey_compressed,
            address,
        },
        config,
        participants,
        device_share_index: device_index,
        cosigner_party: container_index,
        dkg_session_id: SessionId::from_str_hash(&format!("recover-{agent_id}")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_io::keystore::MemNativeKeyStore;

    fn dummy_identity() -> PrivateKey {
        PrivateKey::from_bytes(&[0x11u8; 32]).expect("valid key")
    }

    /// Validate-don't-skip: a `backup_factor` that is NOT a cggmp24 key share is the
    /// "wrong factor" case — it must reject for the RIGHT reason (bad key share), and
    /// the reject must happen BEFORE any network/seal (nothing is sealed).
    #[tokio::test]
    async fn garbage_backup_factor_rejects_as_bad_key_share() {
        let ks = MemNativeKeyStore::new();
        let res = recover_wallet(
            "https://relay.invalid",
            "https://container.invalid",
            dummy_identity(),
            b"definitely-not-a-cggmp24-key-share".to_vec(),
            Duration::from_secs(1),
            &ks,
        )
        .await;
        let Err(err) = res else {
            panic!("garbage backup must reject, got Ok");
        };
        assert!(
            matches!(&err, ClientError::Core(m) if m.contains("bad old key share")),
            "expected a bad-key-share Core reject, got {err:?}"
        );
        // Fail-closed: no share was sealed (the parse rejected before the ceremony).
        assert!(
            ks.unseal_share(
                "any",
                "should be empty — recover rejected before sealing anything",
            )
            .await
            .is_err(),
            "no share must be sealed when recovery rejects the backup factor"
        );
    }

    /// An empty `backup_factor` is also the wrong-factor case (no share to contribute).
    #[tokio::test]
    async fn empty_backup_factor_rejects() {
        let ks = MemNativeKeyStore::new();
        let res = recover_wallet(
            "https://relay.invalid",
            "https://container.invalid",
            dummy_identity(),
            Vec::new(),
            Duration::from_secs(1),
            &ks,
        )
        .await;
        let Err(err) = res else {
            panic!("empty backup must reject, got Ok");
        };
        assert!(
            matches!(&err, ClientError::Core(m) if m.contains("bad old key share")),
            "expected a bad-key-share Core reject, got {err:?}"
        );
    }
}
