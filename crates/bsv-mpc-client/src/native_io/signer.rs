//! `DeployedSigner` — the high-level, biometric-gated native signer (#63 / #41-4d).
//!
//! Ties the Secure-Enclave [`NativeKeyStore`] + a durable presig pool + the wallet
//! metadata together behind the locked design:
//!
//! - **sign() = fast online path.** A fund-bearing spend re-prompts the biometric
//!   (per-spend), unseals the share as `Zeroizing` (per-op window), takes a READY
//!   §06.17.1 bundle from the pool, does ONE relay round-trip to the deployed
//!   container (its partial), combines, and **fail-closes** on a pre-flight low-s +
//!   joint-key verify before the signature ever leaves Rust. The heavy presign is
//!   OFF the tap path.
//! - **top_up_presigs() = opportunistic provisioning.** One biometric mints `n`
//!   durable bundles (the heavy §06.17.1 presign-over-relay) within an authed window.
//! - **on-demand fallback.** If the pool is empty at sign time, one presign is run
//!   inline (slower) so a spend never hard-fails for an empty pool.
//!
//! Single-use is enforced by [`BundleStore::consume`] (atomic remove + zeroize) —
//! the spec mitigation for the presignature-forgery class (CVE-2025-66017).

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bsv::primitives::ec::{PrivateKey, PublicKey, Signature};
use bsv_mpc_core::types::{
    EncryptedShare, JointPublicKey, PolicyId, PresigBundle, SessionId, ShareIndex, SigningResult,
    ThresholdConfig,
};
use bsv_mpc_service::{BundleStore, FileBundleStore};

use super::ceremony::DeployedCosigner;
use super::keystore::NativeKeyStore;
use crate::error::ClientError;

/// Static metadata for a provisioned 2-party wallet (no secrets). The share itself
/// lives device-sealed in the [`NativeKeyStore`]; this is the public binding info
/// the ceremony needs.
#[derive(Clone)]
pub struct WalletMeta {
    /// Joint pubkey hex — the wallet id + owner-authz key (§08.1).
    pub agent_id: String,
    /// The 2-of-2 joint public key (verify target + presig binding).
    pub joint_key: JointPublicKey,
    /// Threshold config (2-of-2 for the deployed device+cosigner wallet).
    pub config: ThresholdConfig,
    /// Signing participant set (sorted keygen indices, e.g. `[0, 1]`).
    pub participants: Vec<u16>,
    /// This device's PRIMARY signing index (`device_holds_combine`'s primary
    /// share). For a 2-of-2 wallet it is the lone device index; for an n-party
    /// device-holds-(t−1) wallet it is `my_indices[0]`.
    pub device_share_index: u16,
    /// ALL keygen indices this device holds (ADR-0052 device-holds-(t−1)). Length
    /// 1 for the proven 2-of-2 wallet (`= [device_share_index]`); length `w = t−1`
    /// for the multi-share wallet. Each share is sealed composite-keyed
    /// `"{agent_id}#{index}"` (multi-share) or under `agent_id` (legacy 2-of-2).
    pub my_indices: Vec<u16>,
    /// The cosigner keygen index that co-signs to complete the quorum (the relay
    /// trigger target). `0` in the proven 2-of-2 flow.
    pub cosigner_party: u16,
    /// The DKG session id (carried on the device's `EncryptedShare`).
    pub dkg_session_id: SessionId,
}

/// Connection + config for a provisioned wallet's deployed signer.
pub struct DeployedSignerConfig {
    pub relay_url: String,
    pub container_url: String,
    /// §07.4 long-lived BRC-31 / relay identity (the SAME key recorded as owner at
    /// DKG time). Distinct from the MPC share.
    pub identity: PrivateKey,
    /// Device secret rooting the at-rest seal of each bundle's own-presig bytes.
    pub at_rest_root: [u8; 32],
    /// Durable presig-pool directory (app storage).
    pub bundle_dir: PathBuf,
    /// §09 policy hash bound into every minted bundle.
    pub policy_id: PolicyId,
    pub meta: WalletMeta,
}

/// The high-level native signer. Construct with [`DeployedSigner::connect`].
pub struct DeployedSigner {
    cosigner: DeployedCosigner,
    keystore: Arc<dyn NativeKeyStore>,
    bundle_store: Arc<FileBundleStore>,
    /// In-memory FIFO of available (persisted) bundle ids — the pool. The durable
    /// JSON files are the source of truth; `consume` removes one single-use at sign
    /// time.
    pool: Mutex<VecDeque<String>>,
    at_rest_root: [u8; 32],
    policy_id: PolicyId,
    meta: WalletMeta,
}

impl DeployedSigner {
    /// Connect to a provisioned wallet's deployed cosigner (BRC-31 handshake) and
    /// open the durable presig pool.
    pub async fn connect(
        config: DeployedSignerConfig,
        keystore: Arc<dyn NativeKeyStore>,
    ) -> Result<Self, ClientError> {
        let cosigner = DeployedCosigner::connect(
            config.container_url,
            config.relay_url,
            config.meta.agent_id.clone(),
            config.identity,
        )
        .await?;
        let bundle_store =
            Arc::new(
                FileBundleStore::new(config.bundle_dir).map_err(|e| ClientError::Host {
                    seam: "bundle_store",
                    reason: format!("open bundle store: {e}"),
                })?,
            );
        Ok(Self {
            cosigner,
            keystore,
            bundle_store,
            pool: Mutex::new(VecDeque::new()),
            at_rest_root: config.at_rest_root,
            policy_id: config.policy_id,
            meta: config.meta,
        })
    }

    /// Number of ready bundles in the pool.
    pub fn pool_len(&self) -> usize {
        self.pool.lock().map(|p| p.len()).unwrap_or(0)
    }

    /// Biometric-gated unseal → build the transient `EncryptedShare` the ceremony
    /// consumes. The cggmp24 KeyShare JSON is the device-sealed plaintext (the
    /// KeyStore is the at-rest protection; no core AES layer → `nonce` unused).
    async fn unseal_device_share(&self, reason: &str) -> Result<EncryptedShare, ClientError> {
        let share_json = self
            .keystore
            .unseal_share(&self.meta.agent_id, reason)
            .await?;
        Ok(EncryptedShare {
            nonce: vec![0u8; 12],
            ciphertext: share_json.to_vec(),
            session_id: self.meta.dkg_session_id,
            share_index: ShareIndex(self.meta.device_share_index),
            config: self.meta.config,
            joint_pubkey_compressed: self.meta.joint_key.compressed.clone(),
        })
    }

    /// **Opportunistic top-up** (the locked policy): one biometric mints `n` durable
    /// §06.17.1 bundles. Heavy (relay 3-round + container self-presign); run within
    /// an already-authed window, NOT on the tap path. Returns how many were minted.
    pub async fn top_up_presigs(
        &self,
        n: usize,
        reason: &str,
        timeout: Duration,
    ) -> Result<usize, ClientError> {
        if n == 0 {
            return Ok(0);
        }
        let share = self.unseal_device_share(reason).await?;
        let mut minted = 0usize;
        for _ in 0..n {
            let bundle = self
                .cosigner
                .coordinate_presig(
                    share.clone(),
                    self.meta.device_share_index,
                    self.meta.cosigner_party,
                    &self.meta.participants,
                    self.policy_id,
                    self.at_rest_root,
                    self.bundle_store.clone(),
                    timeout,
                )
                .await?;
            self.push_pool(bundle.presig_id);
            minted += 1;
        }
        Ok(minted)
    }

    /// **The exported high-level sign.** Biometric-gated per spend: unseal (Zeroizing,
    /// per-op) → take a ready bundle (on-demand presign if the pool is empty) → ONE
    /// relay round-trip to the container → combine → **fail-closed pre-flight** →
    /// return the BSV-ready signature. `brc42_offset` applies a BRC-42 additive shift
    /// for derived-key signing (§06.20); the pre-flight then verifies under
    /// `child_pub = joint + offset·G`.
    pub async fn sign(
        &self,
        sighash: &[u8; 32],
        reason: &str,
        brc42_offset: Option<[u8; 32]>,
        recv_timeout: Duration,
        presign_timeout: Duration,
    ) -> Result<SigningResult, ClientError> {
        // Every fund-bearing spend re-prompts the biometric (locked policy).
        let share = self.unseal_device_share(reason).await?;

        // Take a READY bundle (single-use consume); on-demand presign if the pool is
        // exhausted so a spend never hard-fails for an empty pool.
        let bundle = match self.take_ready_bundle()? {
            Some(b) => b,
            None => {
                self.cosigner
                    .coordinate_presig(
                        share.clone(),
                        self.meta.device_share_index,
                        self.meta.cosigner_party,
                        &self.meta.participants,
                        self.policy_id,
                        self.at_rest_root,
                        self.bundle_store.clone(),
                        presign_timeout,
                    )
                    .await?;
                // Re-fetch through the atomic single-use path (defends against a
                // concurrent sign racing for the same fresh bundle).
                self.take_ready_bundle()?.ok_or_else(|| {
                    ClientError::Core("on-demand presign produced no consumable bundle".into())
                })?
            }
        };

        let sig = self
            .cosigner
            .sign_from_bundle(
                share,
                &self.meta.participants,
                self.meta.config,
                &self.meta.joint_key,
                self.meta.cosigner_party,
                sighash,
                &bundle,
                self.at_rest_root,
                recv_timeout,
                brc42_offset,
            )
            .await?;

        // Fail-closed: no malformed / non-verifying signature leaves Rust.
        self.preflight_verify(sighash, &sig, brc42_offset)?;
        Ok(sig)
    }

    /// Pop pool ids until one `consume`s to a present bundle (atomic single-use).
    /// Skips ids whose file was already consumed/invalidated.
    fn take_ready_bundle(&self) -> Result<Option<PresigBundle>, ClientError> {
        loop {
            let id = {
                let mut pool = self
                    .pool
                    .lock()
                    .map_err(|_| ClientError::Core("presig pool mutex poisoned".into()))?;
                match pool.pop_front() {
                    Some(id) => id,
                    None => return Ok(None),
                }
            };
            match self
                .bundle_store
                .consume(&id)
                .map_err(|e| ClientError::Core(format!("consume bundle {id}: {e}")))?
            {
                Some(b) => return Ok(Some(b)),
                None => continue, // already consumed/invalidated — try the next id
            }
        }
    }

    fn push_pool(&self, presig_id: String) {
        if let Ok(mut pool) = self.pool.lock() {
            pool.push_back(presig_id);
        }
    }

    /// Pre-flight: the combined signature MUST be low-s (BIP-62) and MUST verify under
    /// the (optionally BRC-42-shifted) joint pubkey. Delegates to the pure
    /// [`preflight_verify_sig`].
    fn preflight_verify(
        &self,
        sighash: &[u8; 32],
        sig: &SigningResult,
        brc42_offset: Option<[u8; 32]>,
    ) -> Result<(), ClientError> {
        preflight_verify_sig(
            &self.meta.joint_key.compressed,
            sighash,
            &sig.r,
            &sig.s,
            brc42_offset,
        )
    }
}

/// Fail-closed pre-flight on a combined signature, **pure** (no signer state) so it
/// is unit-testable and reused by the deployed sign path. The signature MUST be
/// low-s (BIP-62 — anti-malleability) and MUST verify under the joint pubkey (or
/// `child_pub = joint + offset·G` when a BRC-42 `brc42_offset` was applied). Mirrors
/// the mainnet-capstone gate: no malformed / non-verifying signature is ever
/// returned to the host (and thus never broadcast).
pub(crate) fn preflight_verify_sig(
    joint_compressed: &[u8],
    sighash: &[u8; 32],
    r: &[u8],
    s: &[u8],
    brc42_offset: Option<[u8; 32]>,
) -> Result<(), ClientError> {
    if r.len() != 32 || s.len() != 32 {
        return Err(ClientError::Core("MPC signature r/s not 32 bytes".into()));
    }
    let mut rb = [0u8; 32];
    let mut sb = [0u8; 32];
    rb.copy_from_slice(r);
    sb.copy_from_slice(s);
    let bsv_sig = Signature::new(rb, sb);
    if !bsv_sig.is_low_s() {
        return Err(ClientError::Core(
            "MPC signature is not low-s (BIP-62) — refusing".into(),
        ));
    }
    if joint_compressed.len() != 33 {
        return Err(ClientError::Core("joint pubkey is not 33 bytes".into()));
    }
    let mut jp = [0u8; 33];
    jp.copy_from_slice(joint_compressed);
    let joint_pub = PublicKey::from_bytes(&jp)
        .map_err(|e| ClientError::Core(format!("joint pubkey parse: {e}")))?;
    let verify_pub = match brc42_offset {
        None => joint_pub,
        Some(offset) => {
            // child_pub = joint + offset·G (the same shift both signers applied).
            let offset_pub = PrivateKey::from_bytes(&offset)
                .map_err(|e| ClientError::Core(format!("brc42 offset scalar: {e}")))?
                .public_key();
            bsv_mpc_core::ecdh::point_add(&joint_pub, &offset_pub)?
        }
    };
    if !verify_pub.verify(sighash, &bsv_sig) {
        return Err(ClientError::Core(
            "PRE-FLIGHT: signature does not verify under the joint pubkey".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::preflight_verify_sig;
    use crate::error::ClientError;
    use bsv::primitives::ec::PrivateKey;

    /// secp256k1 group order N (big-endian) — used to synthesize a high-s value.
    const SECP256K1_N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];

    fn signed(seed: u8, sighash: &[u8; 32]) -> (Vec<u8>, [u8; 32], [u8; 32]) {
        let k = PrivateKey::from_bytes(&[seed | 1; 32]).expect("key");
        let pub_compressed = k.public_key().to_compressed().to_vec();
        let sig = k.sign(sighash).expect("sign");
        (pub_compressed, *sig.r(), *sig.s())
    }

    #[test]
    fn valid_low_s_signature_passes_under_its_key() {
        let sighash = [0x11u8; 32];
        let (pubc, r, s) = signed(7, &sighash);
        // bsv-rs `sign` is low-s normalized → pre-flight accepts.
        assert!(preflight_verify_sig(&pubc, &sighash, &r, &s, None).is_ok());
    }

    #[test]
    fn high_s_signature_is_rejected_for_being_high_s() {
        let sighash = [0x22u8; 32];
        let (pubc, r, _s) = signed(7, &sighash);
        // N-1 is unambiguously > N/2 → high-s. The low-s gate must fire BEFORE verify.
        let mut high_s = SECP256K1_N;
        high_s[31] -= 1;
        let err = preflight_verify_sig(&pubc, &sighash, &r, &high_s, None).unwrap_err();
        assert!(
            matches!(&err, ClientError::Core(m) if m.contains("low-s")),
            "expected low-s rejection, got {err:?}"
        );
    }

    #[test]
    fn signature_under_wrong_key_is_rejected() {
        let sighash = [0x33u8; 32];
        let (_pubc, r, s) = signed(7, &sighash);
        // A DIFFERENT key's pubkey — a valid low-s sig that does not verify here.
        let (other_pubc, _r2, _s2) = signed(9, &sighash);
        let err = preflight_verify_sig(&other_pubc, &sighash, &r, &s, None).unwrap_err();
        assert!(
            matches!(&err, ClientError::Core(m) if m.contains("does not verify")),
            "expected verify rejection, got {err:?}"
        );
    }

    #[test]
    fn wrong_length_rs_is_rejected() {
        let sighash = [0x44u8; 32];
        let (pubc, _r, s) = signed(7, &sighash);
        let short_r = vec![0u8; 31];
        let err = preflight_verify_sig(&pubc, &sighash, &short_r, &s, None).unwrap_err();
        assert!(
            matches!(&err, ClientError::Core(m) if m.contains("32 bytes")),
            "expected length rejection, got {err:?}"
        );
    }

    #[test]
    fn brc42_offset_verifies_under_the_shifted_child_key() {
        // child_priv = base + offset (mod N); the sig under child_priv must verify
        // under child_pub = base_pub + offset·G — the §06.20 derived-key path.
        let sighash = [0x55u8; 32];
        // base scalar = [3;32]; offset = last byte 5 → child = base + offset has only
        // the last byte changed (3 + 5 = 8, no carry across limbs).
        let base = [3u8; 32];
        let offset = {
            let mut o = [0u8; 32];
            o[31] = 5;
            o
        };
        let child = {
            let mut c = base;
            c[31] += offset[31];
            c
        };
        let child_key = PrivateKey::from_bytes(&child).expect("child key");
        let base_pub = PrivateKey::from_bytes(&base)
            .expect("base key")
            .public_key();
        let sig = child_key.sign(&sighash).expect("sign");
        // Verifies under base_pub + offset·G (offset applied), not under base alone.
        assert!(
            preflight_verify_sig(
                &base_pub.to_compressed(),
                &sighash,
                sig.r(),
                sig.s(),
                Some(offset)
            )
            .is_ok(),
            "offset child sig must verify under joint+offset·G"
        );
        assert!(
            preflight_verify_sig(&base_pub.to_compressed(), &sighash, sig.r(), sig.s(), None)
                .is_err(),
            "without the offset it must NOT verify under the base key"
        );
    }
}
