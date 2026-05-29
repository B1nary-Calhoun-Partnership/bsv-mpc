//! `DeviceMultiPresig` — the durable, serializable multi-index presignature set
//! (#69 PR-2 step 7b / #86): the n-party device-holds analog of a `PresigBundle`.
//!
//! Where the 2-party path persists a [`PresigBundle`](bsv_mpc_core::types::PresigBundle)
//! (coordinator holds ONE own presig + cosigner ciphertexts), a device-holds-(t−1)
//! wallet holds `w` correlated presigs — one per held index — plus the ONE external
//! cosigner's sealed ciphertext. We store each device presig as its DECRYPTED JSON
//! (the ephemeral relay identities that the generation ceremony minted to seal them
//! are gone by sign-time, so the encrypted bundle form is NOT durable for the
//! device's own shares), paired with the shared `commitments` public data. At
//! sign-time each is reconstructed into a raw `(Presignature, PublicData)` box via
//! the proven core inverse [`deserialize_party_presig_with_public_data`], folded
//! locally, and the external cosigner's ciphertext is shipped back over the relay.
//!
//! Single-use is enforced by [`MultiPresigStore::consume`] (atomic rename + remove)
//! — the same CVE-2025-66017 mitigation the 2-party `FileBundleStore` uses.

use std::any::Any;
use std::path::{Path, PathBuf};

use bsv_mpc_core::presigning::{
    deserialize_party_presig_with_public_data, serialize_party_presig_with_public_data,
};
use bsv_mpc_relay::PresignOverRelayOutput;

use crate::error::ClientError;

/// One device-held raw presig, party-indexed: `(party_index, (Presignature,
/// PublicData) type-erased)` — the input shape the device-holds combine folds.
pub type DevicePresigBox = (u16, Box<dyn Any + Send>);

/// A durable multi-index presignature set, ready to re-hydrate into raw boxes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceMultiPresig {
    /// Canonical `presig_id` = the PRESIGN session_id hex (the §06.17.1 BRC-2 key_id
    /// the external cosigner sealed its ciphertext under).
    pub presig_id: String,
    /// The signing subset (ascending) this presig was generated over.
    pub participants: Vec<u16>,
    /// The device's primary (combine-coordinator) party index.
    pub primary_index: u16,
    /// The external cosigner's signing-subset index (the sign-time `do_index`).
    pub cosigner_index: u16,
    /// `(party_index, decrypted presignature JSON)` for each of the device's `w`
    /// held parties — paired with `commitments` (the shared public data) to rebuild
    /// the raw box.
    pub device_presigs: Vec<(u16, Vec<u8>)>,
    /// Shared `PresignaturePublicData` CBOR — ONE for all device parties (the agreed
    /// presign transcript).
    pub commitments: Vec<u8>,
    /// The external cosigner's BRC-2 ciphertext (opaque to the device; shipped back
    /// via `trigger.cosigner_encrypted_share` at sign-time).
    pub cosigner_encrypted_share: Vec<u8>,
}

impl DeviceMultiPresig {
    /// Consume a generation output, re-serializing its raw boxes into the durable
    /// form (the proven byte-stable round-trip — see the core inverse's gate).
    pub fn from_output(out: PresignOverRelayOutput) -> Result<Self, ClientError> {
        let presig_id = out.session_id.hex();
        let mut device_presigs = Vec::with_capacity(out.device_presigs.len());
        let mut commitments: Option<Vec<u8>> = None;
        for (idx, raw) in out.device_presigs {
            let (presig_json, public_data_cbor, _gamma) =
                serialize_party_presig_with_public_data(raw).map_err(|e| {
                    ClientError::Core(format!("serialize device presig {idx}: {e}"))
                })?;
            // All device parties share ONE public-data transcript; keep the first.
            if commitments.is_none() {
                commitments = Some(public_data_cbor);
            }
            device_presigs.push((idx, presig_json));
        }
        let commitments = commitments.ok_or_else(|| {
            ClientError::Core("multi-index presig set has no device presigs".into())
        })?;
        Ok(Self {
            presig_id,
            participants: out.participants,
            primary_index: out.primary_index,
            cosigner_index: out.cosigner_index,
            device_presigs,
            commitments,
            cosigner_encrypted_share: out.cosigner_encrypted_share,
        })
    }

    /// Rehydrate the device's `w` raw `(Presignature, PublicData)` boxes
    /// (party-indexed) for the device-holds combine.
    pub fn reconstruct_boxes(&self) -> Result<Vec<DevicePresigBox>, ClientError> {
        self.device_presigs
            .iter()
            .map(|(idx, json)| {
                let raw = deserialize_party_presig_with_public_data(json, &self.commitments)
                    .map_err(|e| {
                        ClientError::Core(format!("reconstruct device presig {idx}: {e}"))
                    })?;
                Ok((*idx, raw))
            })
            .collect()
    }
}

/// Durable file-backed pool of [`DeviceMultiPresig`] sets — one JSON file per
/// `presig_id`, with atomic single-use [`consume`](Self::consume) (rename + zeroize
/// + remove). Mirrors the 2-party `FileBundleStore` for the multi-index path.
#[derive(Clone)]
pub struct MultiPresigStore {
    root: PathBuf,
}

impl MultiPresigStore {
    /// Open (creating if needed) a multi-presig pool rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, ClientError> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|e| ClientError::Host {
            seam: "multipresig_store",
            reason: format!("create dir {}: {e}", root.display()),
        })?;
        Ok(Self { root })
    }

    fn path_for(&self, presig_id: &str) -> PathBuf {
        let safe: String = presig_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.root.join(format!("{safe}.mpresig.json"))
    }

    /// Persist a set atomically (temp + rename).
    pub fn persist(&self, set: &DeviceMultiPresig) -> Result<(), ClientError> {
        let path = self.path_for(&set.presig_id);
        let bytes =
            serde_json::to_vec(set).map_err(|e| ClientError::Core(format!("serialize: {e}")))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes).map_err(|e| ClientError::Host {
            seam: "multipresig_store",
            reason: format!("write {}: {e}", tmp.display()),
        })?;
        std::fs::rename(&tmp, &path).map_err(|e| ClientError::Host {
            seam: "multipresig_store",
            reason: format!("rename {}: {e}", path.display()),
        })?;
        Ok(())
    }

    /// Atomic single-use consume: rename the file to a unique sibling (one winner),
    /// read it, zeroize + remove. Returns `None` if absent / already consumed.
    pub fn consume(&self, presig_id: &str) -> Result<Option<DeviceMultiPresig>, ClientError> {
        let path = self.path_for(presig_id);
        let claim = path.with_extension(format!("consuming.{}", std::process::id()));
        match std::fs::rename(&path, &claim) {
            Ok(()) => {
                let bytes = std::fs::read(&claim).map_err(|e| ClientError::Host {
                    seam: "multipresig_store",
                    reason: format!("read claimed {}: {e}", claim.display()),
                })?;
                let set: DeviceMultiPresig = serde_json::from_slice(&bytes)
                    .map_err(|e| ClientError::Core(format!("parse claimed set: {e}")))?;
                zeroize_and_remove(&claim);
                Ok(Some(set))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ClientError::Host {
                seam: "multipresig_store",
                reason: format!("claim {}: {e}", path.display()),
            }),
        }
    }

    /// All persisted set ids (file stems), for pool re-hydration on connect.
    pub fn list_ids(&self) -> Vec<String> {
        let Ok(rd) = std::fs::read_dir(&self.root) else {
            return Vec::new();
        };
        rd.flatten()
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                name.strip_suffix(".mpresig.json").map(|s| s.to_string())
            })
            .collect()
    }
}

/// Best-effort zeroizing delete (overwrite-then-remove) — the secret-bearing JSON
/// is not merely unlinked.
fn zeroize_and_remove(path: &Path) {
    use std::io::Write;
    if let Ok(meta) = std::fs::metadata(path) {
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
            let zeros = vec![0u8; meta.len() as usize];
            let _ = f.write_all(&zeros);
            let _ = f.flush();
        }
    }
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_set(id: &str) -> DeviceMultiPresig {
        DeviceMultiPresig {
            presig_id: id.to_string(),
            participants: vec![0, 1, 2, 3],
            primary_index: 0,
            cosigner_index: 3,
            device_presigs: vec![(0, vec![0xa0]), (1, vec![0xa1]), (2, vec![0xa2])],
            commitments: vec![0xcc; 8],
            cosigner_encrypted_share: vec![0xee; 16],
        }
    }

    /// Durable round-trip + ATOMIC SINGLE-USE: a set persists, re-hydrates by id,
    /// consumes ONCE (the CVE-2025-66017 mitigation), and the second consume returns
    /// `None` (the file is gone). The fields survive the JSON round-trip byte-for-byte.
    #[test]
    fn store_persists_rehydrates_and_consumes_single_use() {
        let mut tag = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut tag);
        let dir = std::env::temp_dir().join(format!("mpresig-store-test-{}", hex::encode(tag)));
        let store = MultiPresigStore::new(&dir).expect("open store");

        store.persist(&dummy_set("sess-A")).unwrap();
        store.persist(&dummy_set("sess-B")).unwrap();

        // Re-hydration sees both ids.
        let mut ids = store.list_ids();
        ids.sort();
        assert_eq!(ids, vec!["sess-A".to_string(), "sess-B".to_string()]);

        // First consume returns the set with all fields intact.
        let got = store.consume("sess-A").unwrap().expect("present");
        assert_eq!(got.presig_id, "sess-A");
        assert_eq!(got.participants, vec![0, 1, 2, 3]);
        assert_eq!(got.cosigner_index, 3);
        assert_eq!(got.device_presigs.len(), 3);
        assert_eq!(got.cosigner_encrypted_share, vec![0xee; 16]);

        // Second consume of the SAME id is `None` — single-use enforced.
        assert!(store.consume("sess-A").unwrap().is_none());
        // The other set is untouched.
        assert!(store.consume("sess-B").unwrap().is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A missing id consumes to `None` (never an error / never a junk set).
    #[test]
    fn consume_absent_is_none() {
        let mut tag = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut tag);
        let dir = std::env::temp_dir().join(format!("mpresig-absent-{}", hex::encode(tag)));
        let store = MultiPresigStore::new(&dir).expect("open store");
        assert!(store.consume("never-persisted").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
