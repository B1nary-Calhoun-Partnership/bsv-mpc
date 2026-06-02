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
use super::multipresig::{DeviceMultiPresig, MultiPresigStore};
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
    /// **#85 MITM gate.** The completing cosigner's MASTER identity pubkey hex,
    /// PINNED out-of-band. When `Some`, the n-party presign verifies the cosigner's
    /// fetched identity equals this pin (a MITM substitution → reject). `None` =
    /// unpinned (2-of-2 / dev). Set from the chosen Notary's identity at provisioning.
    pub cosigner_master_pub: Option<String>,
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

/// The BRC-42 counterparty a derivation is computed against (#91).
///
/// - `SelfWallet` and `Other` need the distributed-ECDH round (the shared secret
///   `counterparty_pub * root_priv` can't be computed locally — `root_priv` is split).
/// - `Anyone` is local (0 MPC): the shared secret IS the joint pubkey.
pub enum DerivationCounterparty {
    /// `Self_` — derive against the wallet's own joint pubkey.
    SelfWallet,
    /// `Anyone` — the publicly-derivable counterparty (counterparty key = 1).
    Anyone,
    /// `Other(pubkey)` — a specific external counterparty.
    Other(PublicKey),
}

/// A fully-derived BRC-42 child key (#91), produced ATOMICALLY from one ECDH shared
/// secret so the four fields can never disagree (the loss-of-funds invariant): the
/// signing `brc42_offset`, the `derived_pubkey` that goes in the spend's scriptSig,
/// the `derived_p2pkh_locking_script` (the sighash subscript), and the
/// `derived_address` (the receive address) ALL come from the same derivation.
pub struct DerivedKey {
    /// The 32-byte BRC-42 additive offset to sign the derived input
    /// (`FfiDeployedSigner::sign`'s `brc42_offset`).
    pub brc42_offset: [u8; 32],
    /// The derived child compressed pubkey — `joint + offset·G`.
    pub derived_pubkey: PublicKey,
    /// The P2PKH locking script of the derived key (the sighash subscript + the
    /// script funds land in).
    pub derived_p2pkh_locking_script: Vec<u8>,
    /// The Base58Check P2PKH receive address of the derived key.
    pub derived_address: String,
}

/// The high-level native signer. Construct with [`DeployedSigner::connect`].
pub struct DeployedSigner {
    cosigner: DeployedCosigner,
    keystore: Arc<dyn NativeKeyStore>,
    bundle_store: Arc<FileBundleStore>,
    /// **N-party device-holds pool (#69/#86).** Durable [`DeviceMultiPresig`] sets
    /// for a multi-index (`my_indices.len() > 1`) wallet — the 2-party analog of
    /// `bundle_store`. Unused for a 2-of-2 wallet.
    multi_store: Arc<MultiPresigStore>,
    /// In-memory FIFO of available (persisted) presig ids — the pool. The durable
    /// JSON files (bundle_store for 2-party, multi_store for n-party) are the source
    /// of truth; `consume` removes one single-use at sign time.
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
        let bundle_dir = config.bundle_dir.clone();
        let bundle_store =
            Arc::new(
                FileBundleStore::new(bundle_dir.clone()).map_err(|e| ClientError::Host {
                    seam: "bundle_store",
                    reason: format!("open bundle store: {e}"),
                })?,
            );
        // The n-party pool lives in a sibling subdir so its `.mpresig.json` files
        // never collide with the 2-party bundle JSONs.
        let multi_store = Arc::new(MultiPresigStore::new(bundle_dir.join("multi"))?);
        // Re-hydrate the in-memory id queue from whichever durable store backs this
        // wallet (so a restart resumes its pool).
        let pool: VecDeque<String> = if config.meta.my_indices.len() > 1 {
            multi_store.list_ids().into_iter().collect()
        } else {
            VecDeque::new()
        };
        Ok(Self {
            cosigner,
            keystore,
            bundle_store,
            multi_store,
            pool: Mutex::new(pool),
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

    /// Whether this is a device-holds-(t−1) multi-index wallet (vs a 2-of-2 wallet).
    fn is_multi(&self) -> bool {
        self.meta.my_indices.len() > 1
    }

    /// Biometric-gated unseal of ALL `w` held composite shares `{agent_id}#{index}`
    /// (#69/#86), each rebuilt into the transient `EncryptedShare` the n-party
    /// ceremony consumes. (A production Enclave prompts once per `unseal_share`; a
    /// future batched callback could fold the `w` prompts into one — UX, not crypto.)
    async fn unseal_device_shares_multi(
        &self,
        reason: &str,
    ) -> Result<Vec<(u16, EncryptedShare)>, ClientError> {
        let mut shares = Vec::with_capacity(self.meta.my_indices.len());
        for &idx in &self.meta.my_indices {
            let composite = format!("{}#{}", self.meta.agent_id, idx);
            let share_json = self.keystore.unseal_share(&composite, reason).await?;
            shares.push((
                idx,
                EncryptedShare {
                    nonce: vec![0u8; 12],
                    ciphertext: share_json.to_vec(),
                    session_id: self.meta.dkg_session_id,
                    share_index: ShareIndex(idx),
                    config: self.meta.config,
                    joint_pubkey_compressed: self.meta.joint_key.compressed.clone(),
                },
            ));
        }
        // GUARD (#98): the keystore MUST honor the per-`{agent_id}#index` contract —
        // a DISTINCT sealed share per held index. A SINGLE-SLOT keystore (one stored
        // share, overwritten on each seal and returned for every key) hands back the
        // same share `w` times; the n-party presig then derives its aux-info from the
        // wrong shares and aborts far downstream as a cryptic `EncProofOfK` /
        // "signing protocol failed" (the slot-count bug that blocked 100cash#31 for 12
        // drives). Fail fast HERE with the real reason. (w==1 can't collide.)
        if shares.len() > 1 {
            let mut seen = std::collections::HashSet::with_capacity(shares.len());
            for (idx, s) in &shares {
                if !seen.insert(s.ciphertext.as_slice()) {
                    return Err(ClientError::Host {
                        seam: "keystore",
                        reason: format!(
                            "keystore returned a DUPLICATE share for device index {idx}: it must \
                             store one distinct share per '{{agent_id}}#index' ({} held), but \
                             appears SINGLE-SLOT (sealing {} shares overwrote down to one). The \
                             reconstructed aux-info would diverge from the cosigner's and fail the \
                             presign enc-proofs. Make the keystore multi-slot (account-per-index).",
                            self.meta.my_indices.len(),
                            self.meta.my_indices.len()
                        ),
                    });
                }
            }
        }
        Ok(shares)
    }

    /// Pop pool ids until one `consume`s to a present [`DeviceMultiPresig`] (atomic
    /// single-use); skips ids whose file was already consumed/invalidated.
    fn take_ready_multipresig(&self) -> Result<Option<DeviceMultiPresig>, ClientError> {
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
            match self.multi_store.consume(&id)? {
                Some(set) => return Ok(Some(set)),
                None => continue,
            }
        }
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
        // N-party device-holds top-up (#69/#86): mint correlated multi-index sets.
        if self.is_multi() {
            let local_shares = self.unseal_device_shares_multi(reason).await?;
            let mut minted = 0usize;
            for _ in 0..n {
                let out = self
                    .cosigner
                    .coordinate_presig_nparty(
                        self.meta.config,
                        local_shares.clone(),
                        self.meta.cosigner_party,
                        self.policy_id,
                        self.at_rest_root,
                        self.meta.cosigner_master_pub.clone(),
                        timeout,
                    )
                    .await?;
                let set = DeviceMultiPresig::from_output(out)?;
                self.multi_store.persist(&set)?;
                self.push_pool(set.presig_id);
                minted += 1;
            }
            return Ok(minted);
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
        // N-party device-holds sign (#69/#86): unseal the `w` held shares, fold
        // their correlated presigs locally, and trigger the ONE external cosigner.
        if self.is_multi() {
            let local_shares = self.unseal_device_shares_multi(reason).await?;
            let primary_share = local_shares
                .iter()
                .find(|(i, _)| *i == self.meta.device_share_index)
                .map(|(_, s)| s.clone())
                .ok_or_else(|| {
                    ClientError::Core("primary device share not among the unsealed set".into())
                })?;
            // Take a READY set (single-use); on-demand presign if the pool is empty.
            let set = match self.take_ready_multipresig()? {
                Some(s) => s,
                None => {
                    let out = self
                        .cosigner
                        .coordinate_presig_nparty(
                            self.meta.config,
                            local_shares.clone(),
                            self.meta.cosigner_party,
                            self.policy_id,
                            self.at_rest_root,
                            self.meta.cosigner_master_pub.clone(),
                            presign_timeout,
                        )
                        .await?;
                    DeviceMultiPresig::from_output(out)?
                }
            };
            let device_boxes = set.reconstruct_boxes()?;
            let participants = set.participants.clone();
            let primary_index = set.primary_index;
            let cosigner_index = set.cosigner_index;
            let presig_id = set.presig_id.clone();
            let cosigner_ct = set.cosigner_encrypted_share;
            let sig = self
                .cosigner
                .sign_nparty(
                    primary_share,
                    device_boxes,
                    &participants,
                    self.meta.config,
                    &self.meta.joint_key,
                    primary_index,
                    cosigner_index,
                    sighash,
                    &presig_id,
                    cosigner_ct,
                    recv_timeout,
                    brc42_offset,
                )
                .await?;
            // Fail-closed: no malformed / non-verifying signature leaves Rust.
            self.preflight_verify(sighash, &sig, brc42_offset)?;
            return Ok(sig);
        }

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

    /// **#91 — derive the BRC-42 offset + child key for a counterparty, atomically.**
    ///
    /// For `Anyone` this is local (0 MPC): the shared secret is the joint pubkey. For
    /// `SelfWallet`/`Other` it runs the distributed ECDH — the device computes its `w`
    /// local partials (`compute_partial_ecdh_point` over each unsealed held share) and
    /// fetches ONE cosigner partial over the #90 relay round (#85-pinned), then
    /// `combine_partials_lagrange` recovers the shared secret WITHOUT reconstructing
    /// the key. The offset, derived pubkey, locking script, and address are all
    /// derived from that ONE shared secret (the loss-of-funds invariant). `reason` is
    /// the biometric prompt for the share unseal (unused on the local `Anyone` path).
    pub async fn derive_offset_for_counterparty(
        &self,
        counterparty: DerivationCounterparty,
        protocol_name: &str,
        key_id: &str,
        security_level: u8,
        reason: &str,
        timeout: Duration,
    ) -> Result<DerivedKey, ClientError> {
        let invoice = bsv_mpc_core::hd::compute_invoice(security_level, protocol_name, key_id)?;
        let joint_pub = {
            let arr: [u8; 33] = self
                .meta
                .joint_key
                .compressed
                .as_slice()
                .try_into()
                .map_err(|_| ClientError::Core("joint pubkey is not 33 bytes".into()))?;
            PublicKey::from_bytes(&arr)
                .map_err(|e| ClientError::Core(format!("joint pubkey parse: {e}")))?
        };

        // The ECDH shared secret. `Anyone` ⇒ the joint pubkey (local). `Self_`/`Other`
        // ⇒ the distributed round: device `w` local partials + ONE cosigner partial.
        let shared_secret = match &counterparty {
            DerivationCounterparty::Anyone => joint_pub.clone(),
            DerivationCounterparty::SelfWallet | DerivationCounterparty::Other(_) => {
                let counterparty_pub = match &counterparty {
                    DerivationCounterparty::Other(x) => x.clone(),
                    // `Self_` derives against the wallet's own joint pubkey.
                    _ => joint_pub.clone(),
                };

                // Device-local partials: `counterparty_pub * share(idx)` paired with
                // the party's VSS eval point `I[idx]`, over each unsealed held share.
                let local = if self.is_multi() {
                    self.unseal_device_shares_multi(reason).await?
                } else {
                    vec![(
                        self.meta.device_share_index,
                        self.unseal_device_share(reason).await?,
                    )]
                };
                let mut partials: Vec<(PublicKey, [u8; 32])> = Vec::with_capacity(local.len() + 1);
                for (idx, share) in &local {
                    let scalar = bsv_mpc_core::ecdh::parse_share_scalar(&share.ciphertext)?;
                    let vss = bsv_mpc_core::ecdh::parse_share_vss_points(&share.ciphertext)?;
                    let eval_point = *vss.get(*idx as usize).ok_or_else(|| {
                        ClientError::Core(format!("VSS eval point for index {idx} out of range"))
                    })?;
                    let partial =
                        bsv_mpc_core::ecdh::compute_partial_ecdh_point(&counterparty_pub, &scalar)?;
                    partials.push((partial, eval_point));
                }

                // ONE cosigner partial reaches the t-quorum (device holds w = t−1).
                let nonce = {
                    use rand::RngCore;
                    let mut n = [0u8; 32];
                    rand::rngs::OsRng.fill_bytes(&mut n);
                    n
                };
                let cosigner_partials = self
                    .cosigner
                    .coordinate_ecdh(
                        &counterparty_pub,
                        &nonce,
                        vec![self.meta.cosigner_party],
                        self.meta.cosigner_master_pub.clone(),
                        timeout,
                    )
                    .await?;
                for cp in cosigner_partials {
                    partials.push((cp.partial, cp.vss_point));
                }
                bsv_mpc_core::ecdh::combine_partials_lagrange(&partials)?
            }
        };

        // All outputs from the ONE shared secret (loss-of-funds invariant).
        derived_key_from_shared_secret(&joint_pub, &shared_secret, &invoice)
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

/// Build the full [`DerivedKey`] from a BRC-42 ECDH shared secret + invoice (#91),
/// **pure** (no signer state) so the high-level
/// [`DeployedSigner::derive_offset_for_counterparty`] AND the host-driven low-level
/// FFI combine produce byte-identical outputs — the loss-of-funds invariant lives in
/// ONE place. `offset = HMAC(shared_secret, invoice)`; `derived_pubkey = joint +
/// offset·G`; the script + address are the child's P2PKH.
pub fn derived_key_from_shared_secret(
    joint_pub: &PublicKey,
    shared_secret: &PublicKey,
    invoice: &str,
) -> Result<DerivedKey, ClientError> {
    let brc42_offset = bsv_mpc_core::hd::compute_brc42_hmac(shared_secret, invoice);
    let derived_pubkey = bsv_mpc_core::hd::derive_child_pubkey(joint_pub, shared_secret, invoice)?;
    let addr = bsv::Address::new_from_public_key(&derived_pubkey, true)
        .map_err(|e| ClientError::Core(format!("derive address: {e}")))?;
    let derived_address = addr.to_string();
    let hash = addr.public_key_hash();
    let hash20: [u8; 20] = hash
        .try_into()
        .map_err(|_| ClientError::Core("address pubkey-hash is not 20 bytes".into()))?;
    let derived_p2pkh_locking_script = crate::txbuild::p2pkh_locking_script_from_hash(&hash20);
    Ok(DerivedKey {
        brc42_offset,
        derived_pubkey,
        derived_p2pkh_locking_script,
        derived_address,
    })
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
