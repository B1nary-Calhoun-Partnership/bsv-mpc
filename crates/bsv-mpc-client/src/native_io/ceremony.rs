//! `DeployedCosigner` — the native client's transport + auth layer to the DEPLOYED
//! cosigner (the CF Container) for the §06.17.1 deployed-cosigner ceremony (#63).
//!
//! Pure transport/auth/orchestration: it reuses the EXACT mainnet-proven shared
//! crates (`bsv_mpc_relay::{run_dkg_over_http_authed, coordinate_presign_over_relay,
//! combine_sign_from_bundle_over_relay}`) and replicates the glue the proxy
//! `MpcBridge` provides (extract identity, build the BRC-31 request-signer, the
//! `DoTrigger`, unseal the bundle's own-presig, extract the cosigner ciphertext) —
//! but it holds NO key share or storage. The share is unsealed by the higher-level
//! [`DeployedSigner`](super::signer::DeployedSigner) and passed in per call, so the
//! plaintext window is per-op.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bsv::primitives::ec::{PrivateKey, PublicKey};
use bsv_mpc_core::error::{MpcError, Result};
use bsv_mpc_core::types::{
    DkgResult, EncryptedShare, JointPublicKey, PolicyId, PresigBundle, SessionId, SigningResult,
    ThresholdConfig,
};
use std::any::Any;

use bsv_mpc_relay::presign::CosignerArm;
use bsv_mpc_relay::reshare::ArmRequestSigner;
use bsv_mpc_relay::{
    combine_sign_from_bundle_over_relay, combine_sign_over_relay_nparty,
    coordinate_ecdh_over_relay, coordinate_presign_over_relay,
    coordinate_presign_over_relay_nparty, run_dkg_over_http_authed, DoTrigger, EcdhCosignerArm,
    EcdhPartial, PresignCosignerArm, PresignOverRelay, PresignOverRelayOutput, RelaySession,
};
use bsv_mpc_service::FileBundleStore;

/// Build the canonical BRC-31 request-signer closure over an `Arc<Mutex<RelaySession>>`
/// (the container session). Mirrors the proxy `MpcBridge` closures: returns the
/// signed `x-bsv-auth-*` header pairs over the EXACT body bytes, or `vec![]` if the
/// session hasn't handshaked (unauthed dev cosigner).
fn request_signer_over(
    session: Arc<Mutex<RelaySession>>,
) -> impl Fn(&str, &str, &[u8]) -> Result<Vec<(String, String)>> + Send + Sync {
    move |method: &str, path: &str, body: &[u8]| {
        let guard = session
            .lock()
            .map_err(|_| MpcError::Protocol("container auth mutex poisoned".into()))?;
        if !guard.is_authenticated() {
            return Ok(vec![]);
        }
        guard.auth_header_pairs(method, path, body)
    }
}

/// Build an OWNED (`'static`) canonical BRC-31 arm signer over the container
/// session — the `Arc` form [`coordinate_presign_over_relay_nparty`] needs (it arms
/// the cosigner in a spawned task). Mirrors [`request_signer_over`] but boxed.
fn arm_signer_over(session: Arc<Mutex<RelaySession>>) -> ArmRequestSigner {
    Arc::new(
        move |method: &str, path: &str, body: &[u8]| -> Result<Vec<(String, String)>> {
            let guard = session
                .lock()
                .map_err(|_| MpcError::Protocol("container auth mutex poisoned".into()))?;
            if !guard.is_authenticated() {
                return Ok(vec![]);
            }
            guard.auth_header_pairs(method, path, body)
        },
    )
}

/// A fresh canonical 32-byte session id, salted with random bytes + a label.
fn fresh_session(label: &str) -> SessionId {
    use rand::RngCore;
    let mut seed = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    SessionId::from_str_hash(&format!("{label}-{}", hex::encode(seed)))
}

/// Connection to the deployed cosigner: its base URL (presign/sign/arm + BRC-31
/// handshake), the MessageBox relay URL, the wallet `agent_id` (joint pubkey hex,
/// for owner-authz §08.1), the §07.4 long-lived identity key, and the established
/// BRC-31 session against the container.
pub struct DeployedCosigner {
    relay_url: String,
    container_url: String,
    agent_id: String,
    identity: PrivateKey,
    session: Arc<Mutex<RelaySession>>,
}

impl DeployedCosigner {
    /// Provision a 2-party share by running the REAL distributed authed DKG against
    /// the deployed cosigner as **party 1** (the cosigner holds `share_A`, owner-bound
    /// to `identity` §08.1; the returned [`DkgResult`] is this device's `share_B`).
    /// Keygen-over-FFI is intentionally NOT exposed to hosts (server-side ceremony);
    /// this drives the gate + the server-side provisioning flow.
    pub async fn provision_via_dkg(
        container_url: &str,
        config: ThresholdConfig,
        identity: PrivateKey,
    ) -> Result<DkgResult> {
        run_dkg_over_http_authed(container_url, config, identity).await
    }

    /// Connect to a provisioned wallet's deployed cosigner: BRC-31 handshake against
    /// `container_url` with the §07.4 `identity` (the SAME key recorded as owner at
    /// DKG time).
    pub async fn connect(
        container_url: String,
        relay_url: String,
        agent_id: String,
        identity: PrivateKey,
    ) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| MpcError::Protocol(format!("build HTTP client: {e}")))?;
        let mut session = RelaySession::new(identity.clone());
        session.handshake(&http, &container_url).await?;
        Ok(Self {
            relay_url,
            container_url,
            agent_id,
            identity,
            session: Arc::new(Mutex::new(session)),
        })
    }

    /// The wallet `agent_id` (joint pubkey hex) this cosigner is bound to.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Drive a §06.17.1 presign over the relay → a durable [`PresigBundle`] persisted
    /// to `bundle_store`. The container self-presigns + self-encrypts its OWN share;
    /// this coordinator keeps only the opaque ciphertext (the §06.17.1 threshold gain).
    #[allow(clippy::too_many_arguments)]
    pub async fn coordinate_presig(
        &self,
        share: EncryptedShare,
        coordinator_party: u16,
        cosigner_party: u16,
        participants: &[u16],
        policy_id: PolicyId,
        at_rest_root: [u8; 32],
        bundle_store: Arc<FileBundleStore>,
        timeout: Duration,
    ) -> Result<PresigBundle> {
        let mut parties = participants.to_vec();
        parties.sort_unstable();
        let request_signer = request_signer_over(self.session.clone());
        coordinate_presign_over_relay(
            &self.relay_url,
            self.identity.clone(),
            share,
            coordinator_party,
            cosigner_party,
            parties,
            policy_id,
            at_rest_root,
            fresh_session("presig"),
            bundle_store,
            CosignerArm {
                url: format!("{}/presign-relay/init", self.container_url),
                agent_id: self.agent_id.clone(),
            },
            &request_signer,
            timeout,
        )
        .await
    }

    /// §06.17.1 online sign from a durable bundle over the relay (ONE relay round-trip
    /// to the container, which decrypts its OWN ciphertext + co-signs). Replicates the
    /// proxy `MpcBridge::sign_from_bundle_over_relay` glue. The combined signature is
    /// NOT yet pre-flight-verified — the caller ([`DeployedSigner`]) fail-closes on
    /// low-s + joint-key verify before any broadcast.
    #[allow(clippy::too_many_arguments)]
    pub async fn sign_from_bundle(
        &self,
        share: EncryptedShare,
        participants: &[u16],
        config: ThresholdConfig,
        joint_key: &JointPublicKey,
        cosigner_party: u16,
        sighash: &[u8; 32],
        bundle: &PresigBundle,
        at_rest_root: [u8; 32],
        recv_timeout: Duration,
        brc42_offset: Option<[u8; 32]>,
    ) -> Result<SigningResult> {
        // Unseal this device's OWN presig share from the durable bundle.
        let at_rest_key = bsv_mpc_core::presig_at_rest::derive_presig_at_rest_key(
            &at_rest_root,
            &bundle.presig_id,
        );
        let own_presig_json =
            bsv_mpc_core::presig_at_rest::unseal_presig_bytes(&bundle.presig_bytes, &at_rest_key)
                .map_err(|e| MpcError::Protocol(format!("unseal own presig share: {e}")))?;

        // The container's positional ciphertext slot (= its keygen-subset index).
        let pos = bundle
            .parties_at_keygen
            .iter()
            .position(|&p| p == cosigner_party)
            .ok_or_else(|| {
                MpcError::Protocol(format!(
                    "cosigner party {cosigner_party} not in bundle parties {:?}",
                    bundle.parties_at_keygen
                ))
            })?;
        let cosigner_ct = bundle.cosigner_encrypted_shares[pos].clone().into_vec();
        if cosigner_ct.is_empty() {
            return Err(MpcError::Protocol(
                "bundle has no cosigner ciphertext at the container's positional slot".into(),
            ));
        }

        let request_signer = request_signer_over(self.session.clone());
        let trigger = DoTrigger {
            url: format!("{}/sign-relay", self.container_url),
            presig_a_json: vec![],
            do_index: cosigner_party,
            agent_id: Some(self.agent_id.clone()),
            auth_headers: vec![],
            cosigner_encrypted_share: None,
            // §06.20 HD path (issue #26): both the coordinator
            // (sign_from_bundle_with_offset) and the cosigner (decrypt_and_issue_partial)
            // apply this BRC-42 offset → the signature verifies under
            // child_pub = joint + offset·G. None = base key.
            brc42_offset: brc42_offset.map(hex::encode),
            presig_id: None,
        };

        combine_sign_from_bundle_over_relay(
            &self.relay_url,
            self.identity.clone(),
            share,
            participants.to_vec(),
            config,
            fresh_session("relay-sign"),
            sighash,
            &own_presig_json,
            &bundle.commitments,
            cosigner_ct,
            &bundle.presig_id,
            joint_key,
            trigger,
            Some(&request_signer),
            recv_timeout,
        )
        .await
    }

    /// **Distributed-ECDH partial round (#90/#91).** Fetch the cosigner's
    /// `counterparty_pub * its_share(idx)` partial(s) over one authed HTTP round-trip
    /// to `/ecdh-relay`, #85-verified against `expected_master_pub`. The caller
    /// ([`DeployedSigner`](super::signer::DeployedSigner)) Lagrange-combines these
    /// with its own `w` local partials to recover the BRC-42 ECDH shared secret.
    pub async fn coordinate_ecdh(
        &self,
        counterparty_pub: &PublicKey,
        nonce: &[u8; 32],
        cosigner_indices: Vec<u16>,
        expected_master_pub: Option<String>,
        timeout: Duration,
    ) -> Result<Vec<EcdhPartial>> {
        let request_signer = request_signer_over(self.session.clone());
        coordinate_ecdh_over_relay(
            counterparty_pub,
            nonce,
            &EcdhCosignerArm {
                url: format!("{}/ecdh-relay", self.container_url),
                agent_id: self.agent_id.clone(),
                indices: cosigner_indices,
                expected_master_pub,
            },
            Some(&request_signer),
            timeout,
        )
        .await
    }

    /// **Device-holds n-party presign over the relay (#69/#86).** Drive the device's
    /// `w = t−1` co-located parties + ONE external cosigner → a correlated presig set
    /// (raw boxes + the cosigner's sealed ct). The caller converts it into a durable
    /// [`DeviceMultiPresig`](super::multipresig::DeviceMultiPresig).
    #[allow(clippy::too_many_arguments)]
    pub async fn coordinate_presig_nparty(
        &self,
        config: ThresholdConfig,
        local_shares: Vec<(u16, EncryptedShare)>,
        cosigner_index: u16,
        policy_id: PolicyId,
        at_rest_root: [u8; 32],
        // #85: the cosigner's PINNED master pub (verify the fetched identity == pin).
        expected_master_pub: Option<String>,
        timeout: Duration,
    ) -> Result<PresignOverRelayOutput> {
        let arm_signer = arm_signer_over(self.session.clone());
        coordinate_presign_over_relay_nparty(
            PresignOverRelay {
                relay_url: self.relay_url.clone(),
                config,
                local_shares,
                cosigner: PresignCosignerArm {
                    init_url: format!("{}/presign-relay/init", self.container_url),
                    index: cosigner_index,
                    arm_signer,
                    expected_master_pub,
                },
                agent_id: self.agent_id.clone(),
                policy_id,
                at_rest_root,
            },
            timeout,
        )
        .await
    }

    /// **Device-holds n-party online sign over the relay (#69/#86).** Fold the
    /// device's `w` reconstructed presig boxes locally (the primary primed +
    /// extras added via `device_holds_combine`) and trigger the ONE external
    /// cosigner — shipping back its sealed ciphertext under the PRESIGN `presig_id`
    /// (§06.17.1). `device_presigs` is party-indexed; this re-keys the non-primary
    /// boxes to signing indices for the combine. Not yet pre-flight-verified — the
    /// caller ([`DeployedSigner`](super::signer::DeployedSigner)) fail-closes.
    #[allow(clippy::too_many_arguments)]
    pub async fn sign_nparty(
        &self,
        primary_share: EncryptedShare,
        device_presigs: Vec<(u16, Box<dyn Any + Send>)>,
        participants: &[u16],
        config: ThresholdConfig,
        joint_key: &JointPublicKey,
        primary_index: u16,
        cosigner_index: u16,
        sighash: &[u8; 32],
        presig_id: &str,
        cosigner_encrypted_share: Vec<u8>,
        recv_timeout: Duration,
        brc42_offset: Option<[u8; 32]>,
    ) -> Result<SigningResult> {
        // Split into the primary box + the extras (re-keyed party → signing index).
        let mut my_presig_box: Option<Box<dyn Any + Send>> = None;
        let mut extras: Vec<(u16, Box<dyn Any + Send>)> = Vec::new();
        for (party, raw) in device_presigs {
            if party == primary_index {
                my_presig_box = Some(raw);
            } else {
                let sig_idx = participants
                    .iter()
                    .position(|&p| p == party)
                    .ok_or_else(|| {
                        MpcError::Protocol(format!(
                            "device party {party} not in participants {participants:?}"
                        ))
                    })? as u16;
                extras.push((sig_idx, raw));
            }
        }
        let my_presig_box = my_presig_box.ok_or_else(|| {
            MpcError::Protocol(format!(
                "primary party {primary_index} not among the device presig set"
            ))
        })?;

        let do_index = participants
            .iter()
            .position(|&p| p == cosigner_index)
            .ok_or_else(|| {
                MpcError::Protocol(format!(
                    "cosigner {cosigner_index} not in participants {participants:?}"
                ))
            })? as u16;

        let request_signer = request_signer_over(self.session.clone());
        let trigger = DoTrigger {
            url: format!("{}/sign-relay", self.container_url),
            presig_a_json: vec![],
            do_index,
            agent_id: Some(self.agent_id.clone()),
            auth_headers: vec![],
            cosigner_encrypted_share: Some(cosigner_encrypted_share),
            brc42_offset: brc42_offset.map(hex::encode),
            // §06.17.1 key_id = the PRESIGN session hex (DISTINCT from the per-sign
            // relay-correlation session the combiner picks below).
            presig_id: Some(presig_id.to_string()),
        };

        combine_sign_over_relay_nparty(
            &self.relay_url,
            self.identity.clone(),
            primary_share,
            extras,
            participants.to_vec(),
            config,
            fresh_session("relay-sign-nparty"),
            sighash,
            my_presig_box,
            joint_key,
            brc42_offset,
            trigger,
            Some(&request_signer),
            recv_timeout,
        )
        .await
    }
}
