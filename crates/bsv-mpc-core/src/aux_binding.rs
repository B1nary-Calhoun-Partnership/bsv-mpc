//! #104 aux-reuse — tamper-evident binding envelope + load-time validation.
//!
//! THE load-bearing security gate for aux-info reuse. The cggmp24 crate's ZK
//! proofs prove a modulus *well-formed* but NOT that its contributor doesn't know
//! its factorization, and [`from_parts`] checks only `N[i] == p*q` for THIS
//! party's slot — it never inspects a peer slot `N[j]`, binds no identity, no
//! `(t,n)`, no epoch. Because one aux vector backs MANY wallets, a one-time
//! relay-MITM at aux-setup that substitutes attacker-factored (yet well-formed)
//! moduli would *permanently, invisibly* backdoor every future wallet.
//!
//! This module is the out-of-band scoping the crate leaves to us:
//!
//! * [`AuxBindingRecord`] — a canonical, MAC'd record persisted alongside the
//!   sealed aux: the group-id (binds masters + index→master map + n + t + sec),
//!   the aux-epoch, and a digest of EVERY modulus (`N_j`, `hat_N_j`) in index
//!   order plus a full-vector hash.
//! * [`build_aux_binding_record`] — built ONCE at setup from a freshly-validated
//!   aux (any party's aux carries the full moduli vectors, so it is group-level).
//! * [`validate_aux_for_load`] — re-verified at EVERY per-wallet load BEFORE
//!   [`from_parts`]; rejects a swapped / stale / coherently-tampered / duplicate /
//!   wrong-group / wrong-epoch / wrong-index aux with a SPECIFIC reason
//!   ([`MpcError::AuxBindingRejected`]) — never a late, opaque sign-time abort.
//!
//! Security must-dos #5 (binding envelope), #6 (distinctness + bit-length floor),
//! #7 (explicit `from_parts` pre-assertions). The aux-setup identity pin (#1) and
//! the aux-bound liveness challenge (#2) live in [`crate::hd`].
//!
//! [`from_parts`]: cggmp24::key_share::KeyShare::from_parts

use cggmp24::backend::Integer;
use cggmp24::key_share::AuxInfo;
use cggmp24::security_level::{SecurityLevel, SecurityLevel128};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonical::{aux_group_id, AuxGroupDescriptor};
use crate::error::{MpcError, Result};

/// Domain for a single canonical per-modulus digest.
const MODULUS_DIGEST_DOMAIN: &[u8] = b"bsv-mpc aux modulus digest v1";
/// Domain for the full-vector moduli hash.
const FULL_N_HASH_DOMAIN: &[u8] = b"bsv-mpc aux full-N hash v1";
/// Domain mixed into the device/notary HMAC over the binding record.
const AUX_BINDING_MAC_DOMAIN: &[u8] = b"bsv-mpc aux-binding mac v1";

/// Canonical 32-byte digest of one Paillier/Pedersen modulus.
///
/// `SHA-256(domain || to_bytes_msf(modulus))`. `to_bytes_msf` is the big-endian
/// magnitude (leading zeros stripped) and is deterministic per value, so two
/// equal moduli digest identically and any substitution flips the digest.
fn modulus_digest(m: &Integer) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(MODULUS_DIGEST_DOMAIN);
    h.update(m.to_bytes_msf());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Canonical hash over the ENTIRE moduli vector (`N_j` + `hat_N_j`, index order),
/// each length-prefixed so the preimage is unambiguous. Belt-and-suspenders over
/// the per-index digests — binds the vector AS A WHOLE.
fn full_n_hash(aux: &AuxInfo<SecurityLevel128>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(FULL_N_HASH_DOMAIN);
    h.update((aux.N.len() as u16).to_be_bytes());
    for j in 0..aux.N.len() {
        let n = aux.N[j].to_bytes_msf();
        let hat = aux.pedersen_params[j].hat_N.to_bytes_msf();
        h.update((n.len() as u32).to_be_bytes());
        h.update(&n);
        h.update((hat.len() as u32).to_be_bytes());
        h.update(&hat);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Big-endian magnitude bytes of the four moduli a Notary attests at one index:
/// `(N_i, hat_N_i, s_i, t_i)`.
pub type IndexModuliMsf = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Big-endian magnitude bytes of the four moduli a Notary attests at `index`
/// (`N_i`, `hat_N_i`, `s_i`, `t_i`) — fed to [`crate::hd::aux_liveness_challenge_msg`]
/// (#104 must-do #2). Returns `None` if `index` is out of range.
pub fn aux_index_moduli_msf(
    aux: &AuxInfo<SecurityLevel128>,
    index: usize,
) -> Option<IndexModuliMsf> {
    if index >= aux.N.len() || index >= aux.pedersen_params.len() {
        return None;
    }
    let p = &aux.pedersen_params[index];
    Some((
        aux.N[index].to_bytes_msf(),
        p.hat_N.to_bytes_msf(),
        p.s.to_bytes_msf(),
        p.t.to_bytes_msf(),
    ))
}

/// The tamper-evident record persisted alongside a sealed aux blob (must-do #5).
///
/// One record per GROUP (any party's aux carries the full moduli vectors). Stored
/// with its [`aux_binding_mac`]; re-verified at every load by
/// [`validate_aux_for_load`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuxBindingRecord {
    /// 32-byte group-id = [`aux_group_id`] of the frozen group descriptor. Binds
    /// the masters, the index→master map, `n`, `t`, and the security level.
    pub group_id: [u8; 32],
    /// Number of parties / moduli (`n`).
    pub n: u16,
    /// Threshold (`t`).
    pub t: u16,
    /// Security level in bits.
    pub security_level_bits: u16,
    /// The pinned-Notary epoch this aux is valid for (must-do #10). A per-wallet
    /// provision whose current epoch differs MUST refuse to reuse.
    pub aux_epoch: u64,
    /// `SHA-256` digest of each Paillier modulus `N_j` (index order).
    pub n_digests: Vec<[u8; 32]>,
    /// `SHA-256` digest of each Pedersen modulus `hat_N_j` (index order).
    pub hat_n_digests: Vec<[u8; 32]>,
    /// Hash over the entire moduli vector (binds it as a whole).
    pub full_n_hash: [u8; 32],
}

/// Canonical, deterministic byte encoding of the record for MAC/sign input.
fn encode_record(r: &AuxBindingRecord) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + 2 + 2 + 2 + 8 + 32 + 64 * r.n_digests.len());
    v.extend_from_slice(&r.group_id);
    v.extend_from_slice(&r.n.to_be_bytes());
    v.extend_from_slice(&r.t.to_be_bytes());
    v.extend_from_slice(&r.security_level_bits.to_be_bytes());
    v.extend_from_slice(&r.aux_epoch.to_be_bytes());
    v.extend_from_slice(&r.full_n_hash);
    v.extend_from_slice(&(r.n_digests.len() as u16).to_be_bytes());
    for d in &r.n_digests {
        v.extend_from_slice(d);
    }
    v.extend_from_slice(&(r.hat_n_digests.len() as u16).to_be_bytes());
    for d in &r.hat_n_digests {
        v.extend_from_slice(d);
    }
    v
}

/// HMAC-SHA256 over the canonical record under a device/notary at-rest MAC key —
/// the storage tamper-evidence seal (must-do #5). Store this alongside the record.
pub fn aux_binding_mac(record: &AuxBindingRecord, mac_key: &[u8; 32]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mac_key)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(AUX_BINDING_MAC_DOMAIN);
    mac.update(&encode_record(record));
    let out = mac.finalize().into_bytes();
    let mut b = [0u8; 32];
    b.copy_from_slice(&out);
    b
}

/// Domain for deriving a dedicated binding-MAC subkey from an at-rest secret.
const AUX_BINDING_MAC_KEY_DOMAIN: &[u8] = b"bsv-mpc aux-binding mac key v1";

/// Derive a dedicated 32-byte binding-MAC key from an at-rest secret (e.g. a
/// custody KEK or the device's at-rest root), so the MAC key is cryptographically
/// separated from any sealing key derived from the same secret. Deterministic —
/// the same secret yields the same key at setup and at load.
pub fn derive_binding_mac_key(secret: &[u8; 32]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(AUX_BINDING_MAC_KEY_DOMAIN);
    let out = mac.finalize().into_bytes();
    let mut k = [0u8; 32];
    k.copy_from_slice(&out);
    k
}

/// Constant-time verification of an [`aux_binding_mac`].
pub fn verify_aux_binding_mac(
    record: &AuxBindingRecord,
    mac_key: &[u8; 32],
    tag: &[u8; 32],
) -> bool {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mac_key)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(AUX_BINDING_MAC_DOMAIN);
    mac.update(&encode_record(record));
    mac.verify_slice(tag).is_ok()
}

/// Build the binding record from a freshly-generated, in-ceremony-validated aux
/// at SETUP time (must-do #5). The aux's moduli vectors are recorded; the group
/// descriptor pins identity/topology. Errors if the aux vector length disagrees
/// with the descriptor `n`.
pub fn build_aux_binding_record(
    descriptor: &AuxGroupDescriptor,
    aux: &AuxInfo<SecurityLevel128>,
    aux_epoch: u64,
) -> Result<AuxBindingRecord> {
    build_aux_binding_record_parts(
        &aux_group_id(descriptor),
        descriptor.index_masters.len(),
        descriptor.threshold,
        descriptor.security_level_bits,
        aux,
        aux_epoch,
    )
}

/// Like [`build_aux_binding_record`] but from the precomputed `group_id` +
/// `(n, t, sec)` — for a Notary that holds the group-id but not the master
/// pubkeys (the device pins the masters and ships the group-id).
pub fn build_aux_binding_record_parts(
    group_id: &[u8; 32],
    n: usize,
    threshold: u16,
    security_level_bits: u16,
    aux: &AuxInfo<SecurityLevel128>,
    aux_epoch: u64,
) -> Result<AuxBindingRecord> {
    if aux.N.len() != n || aux.pedersen_params.len() != n {
        return Err(MpcError::AuxBindingRejected(format!(
            "aux vector length (N={}, pedersen={}) != n={n}",
            aux.N.len(),
            aux.pedersen_params.len()
        )));
    }
    let n_digests = aux.N.iter().map(modulus_digest).collect();
    let hat_n_digests = aux
        .pedersen_params
        .iter()
        .map(|p| modulus_digest(&p.hat_N))
        .collect();
    Ok(AuxBindingRecord {
        group_id: *group_id,
        n: n as u16,
        t: threshold,
        security_level_bits,
        aux_epoch,
        n_digests,
        hat_n_digests,
        full_n_hash: full_n_hash(aux),
    })
}

fn reject(msg: impl Into<String>) -> MpcError {
    MpcError::AuxBindingRejected(msg.into())
}

/// What a per-wallet load EXPECTS the persisted aux to be bound to (#104). Built
/// from the full group descriptor on the device (which pins the masters), or
/// from the precomputed `group_id` + `(n, t, sec)` on a Notary (which only knows
/// the group-id) — both sides then call the identical [`validate_aux_for_load`].
#[derive(Debug, Clone)]
pub struct AuxLoadExpectation {
    /// The 32-byte group-id the aux MUST be bound to.
    pub group_id: [u8; 32],
    /// Party count `n`.
    pub n: usize,
    /// Threshold `t`.
    pub threshold: u16,
    /// Security level in bits.
    pub security_level_bits: u16,
    /// The current pinned-Notary epoch (must-do #10).
    pub aux_epoch: u64,
}

impl AuxLoadExpectation {
    /// Build from the full group descriptor (device side — pins the masters).
    pub fn from_descriptor(d: &AuxGroupDescriptor, aux_epoch: u64) -> Self {
        Self {
            group_id: aux_group_id(d),
            n: d.index_masters.len(),
            threshold: d.threshold,
            security_level_bits: d.security_level_bits,
            aux_epoch,
        }
    }
}

/// THE #104 load-time security gate (must-dos #5/#6/#7). Verifies a sealed aux is
/// safe to REUSE for `my_index` in `descriptor` at `expected_epoch`, given the
/// stored binding `record` and its device `mac`. Call this BEFORE
/// [`crate::dkg::DkgCoordinator::set_loaded_aux_info`]; on `Ok(())` the aux is
/// safe to fuse, on `Err(AuxBindingRejected(reason))` NOTHING funded may reuse it.
///
/// Checks, in order (fail-closed, validate-don't-skip):
/// 0. MAC verifies (storage tamper-evidence) — first, so downstream comparisons
///    aren't against attacker-chosen record fields.
/// 1. record group-id / `(n,t,sec)` / epoch == the CURRENT pinned group (#10).
/// 2. structural shape — `aux.N.len()==n`, `pedersen.len()==n`, digests length,
///    `my_index < n` (#7; never trust `from_parts` to catch this).
/// 3. every modulus matches its recorded digest + the full-vector hash (#5) —
///    catches a COHERENTLY-tampered own modulus (`N==p*q` still holds, so
///    `from_parts` passes it) AND a swapped/stale PEER `N[j]` (`from_parts` never
///    inspects peer slots).
/// 4. per-index distinctness + `RSA_PUBKEY_BITLEN` floor (#6) — a Notary cannot
///    reuse one Paillier key across two of its indices.
/// 5. the `from_parts` identity for THIS party: `aux.N[my_index] == p*q` (#7).
pub fn validate_aux_for_load(
    expect: &AuxLoadExpectation,
    my_index: u16,
    aux: &AuxInfo<SecurityLevel128>,
    record: &AuxBindingRecord,
    mac: &[u8; 32],
    mac_key: &[u8; 32],
) -> Result<()> {
    let n = expect.n;

    // (0) Storage tamper-evidence FIRST.
    if !verify_aux_binding_mac(record, mac_key, mac) {
        return Err(reject(
            "binding record MAC mismatch (storage tampered or wrong at-rest key)",
        ));
    }

    // (1) The record must describe THIS pinned group + epoch.
    if record.group_id != expect.group_id {
        return Err(reject(
            "binding record group-id != current pinned group (swapped/stale aux for a different group)",
        ));
    }
    if record.n as usize != n {
        return Err(reject(format!(
            "binding record n={} != expected n={n} (n-mismatch)",
            record.n
        )));
    }
    if record.t != expect.threshold {
        return Err(reject(format!(
            "binding record t={} != expected t={}",
            record.t, expect.threshold
        )));
    }
    if record.security_level_bits != expect.security_level_bits {
        return Err(reject("binding record security level != expected"));
    }
    if record.aux_epoch != expect.aux_epoch {
        return Err(reject(format!(
            "aux-epoch {} != current pinned epoch {} (stale aux — Notary rotated/reshared)",
            record.aux_epoch, expect.aux_epoch
        )));
    }

    // (2) Structural shape (#7) — don't treat from_parts success as proof.
    if aux.N.len() != n || aux.pedersen_params.len() != n {
        return Err(reject(format!(
            "aux vector length (N={}, pedersen={}) != n={n}",
            aux.N.len(),
            aux.pedersen_params.len()
        )));
    }
    if record.n_digests.len() != n || record.hat_n_digests.len() != n {
        return Err(reject("binding record digest vectors length != n"));
    }
    if usize::from(my_index) >= n {
        return Err(reject(format!("my_index {my_index} out of range for n={n}")));
    }

    // (3) Every modulus matches its recorded digest + full-vector hash (#5).
    for j in 0..n {
        if modulus_digest(&aux.N[j]) != record.n_digests[j] {
            return Err(reject(format!(
                "Paillier modulus N[{j}] != recorded digest (tampered/swapped/stale)"
            )));
        }
        if modulus_digest(&aux.pedersen_params[j].hat_N) != record.hat_n_digests[j] {
            return Err(reject(format!(
                "Pedersen modulus hat_N[{j}] != recorded digest (tampered/swapped/stale)"
            )));
        }
    }
    if full_n_hash(aux) != record.full_n_hash {
        return Err(reject("full-N vector hash != recorded (aux vector tampered)"));
    }

    // (4) Per-index distinctness + bit-length floor (#6). The crate verifies the
    // floor + per-party proofs in-ceremony, but NOT cross-index distinctness over
    // the persisted vector.
    let floor = u64::from(SecurityLevel128::RSA_PUBKEY_BITLEN);
    let mut n_seen: Vec<Vec<u8>> = Vec::with_capacity(n);
    let mut hat_seen: Vec<Vec<u8>> = Vec::with_capacity(n);
    for j in 0..n {
        if aux.N[j].significant_bits() < floor {
            return Err(reject(format!(
                "Paillier modulus N[{j}] is {} bits, below the {floor}-bit floor",
                aux.N[j].significant_bits()
            )));
        }
        if aux.pedersen_params[j].hat_N.significant_bits() < floor {
            return Err(reject(format!(
                "Pedersen modulus hat_N[{j}] is {} bits, below the {floor}-bit floor",
                aux.pedersen_params[j].hat_N.significant_bits()
            )));
        }
        let nb = aux.N[j].to_bytes_msf();
        let hb = aux.pedersen_params[j].hat_N.to_bytes_msf();
        if n_seen.contains(&nb) {
            return Err(reject(format!(
                "duplicate Paillier modulus at index {j} (a Notary reused one key across two indices)"
            )));
        }
        if hat_seen.contains(&hb) {
            return Err(reject(format!("duplicate Pedersen modulus at index {j}")));
        }
        n_seen.push(nb);
        hat_seen.push(hb);
    }

    // (5) The from_parts identity for THIS party (#7 "i==expected"): a wrong-index
    // aux is rejected HERE with a clear reason, not as a from_parts error later.
    if aux.N[usize::from(my_index)] != &aux.p * &aux.q {
        return Err(reject(format!(
            "aux primes (p,q) do not satisfy N[{my_index}] == p*q (wrong-index aux for this party)"
        )));
    }

    Ok(())
}

/// [`validate_aux_for_load`] from a serialized-`AuxInfo` JSON string — for callers
/// (e.g. the device FFI seal boundary) that hold the aux only as JSON and don't
/// depend on cggmp24's types directly. Deserializes, then runs the identical gate.
pub fn validate_aux_json_for_load(
    expect: &AuxLoadExpectation,
    my_index: u16,
    aux_json: &str,
    record: &AuxBindingRecord,
    mac: &[u8; 32],
    mac_key: &[u8; 32],
) -> Result<()> {
    let aux: AuxInfo<SecurityLevel128> = serde_json::from_str(aux_json)
        .map_err(|e| MpcError::AuxBindingRejected(format!("aux JSON deserialize: {e}")))?;
    validate_aux_for_load(expect, my_index, &aux, record, mac, mac_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_encoding_is_deterministic_and_mac_round_trips() {
        let r = AuxBindingRecord {
            group_id: [0x11; 32],
            n: 6,
            t: 4,
            security_level_bits: 128,
            aux_epoch: 7,
            n_digests: (0..6).map(|i| [i as u8; 32]).collect(),
            hat_n_digests: (0..6).map(|i| [0x80 | i as u8; 32]).collect(),
            full_n_hash: [0xCD; 32],
        };
        assert_eq!(encode_record(&r), encode_record(&r.clone()));
        let key = [0x42u8; 32];
        let mac = aux_binding_mac(&r, &key);
        assert!(verify_aux_binding_mac(&r, &key, &mac));
        // Wrong key fails closed.
        assert!(!verify_aux_binding_mac(&r, &[0x43u8; 32], &mac));
        // Any field flip fails closed.
        let mut r2 = r.clone();
        r2.aux_epoch = 8;
        assert!(!verify_aux_binding_mac(&r2, &key, &mac));
        let mut r3 = r.clone();
        r3.n_digests[2][0] ^= 1;
        assert!(!verify_aux_binding_mac(&r3, &key, &mac));
    }

    #[test]
    fn mac_binds_n_vs_hat_split() {
        // The length prefixes prevent n_digests/hat_n_digests from being
        // re-partitioned without changing the MAC.
        let key = [0x09u8; 32];
        let base = AuxBindingRecord {
            group_id: [0; 32],
            n: 2,
            t: 2,
            security_level_bits: 128,
            aux_epoch: 0,
            n_digests: vec![[1; 32], [2; 32]],
            hat_n_digests: vec![[3; 32]],
            full_n_hash: [0; 32],
        };
        let shifted = AuxBindingRecord {
            n_digests: vec![[1; 32]],
            hat_n_digests: vec![[2; 32], [3; 32]],
            ..base.clone()
        };
        assert_ne!(aux_binding_mac(&base, &key), aux_binding_mac(&shifted, &key));
    }
}
