//! HD key derivation from MPC shares (SLIP-10/BIP-32 compatible).
//!
//! Standard BSV wallets use BIP-32 hierarchical deterministic key derivation
//! to generate child keys from a master key. This module provides the same
//! capability for MPC-generated joint keys, enabling standard derivation paths
//! like `m/44'/236'/0'/0/0` without ever reconstructing the private key.
//!
//! ## How It Works
//!
//! BIP-32 child key derivation is defined as:
//!
//! ```text
//! // Non-hardened (public) derivation:
//! child_key = parent_key + HMAC-SHA512(chain_code, parent_pubkey || index)[0..32] * G
//!
//! // Hardened derivation:
//! child_key = parent_key + HMAC-SHA512(chain_code, 0x00 || parent_privkey || index)[0..32] * G
//! ```
//!
//! For **non-hardened derivation**, only the public key is needed. Each MPC party
//! can independently derive the child public key from the joint public key without
//! any communication. The child's corresponding private key share is derived by
//! each party adding the same scalar tweak to their existing share.
//!
//! For **hardened derivation**, the private key is needed. In MPC, this requires
//! a protocol round where parties jointly compute the HMAC without revealing
//! their shares. This is more expensive but provides stronger security (child
//! keys cannot be linked to the parent by an observer).
//!
//! ## SLIP-10 Compatibility
//!
//! [SLIP-10](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) is
//! a variant of BIP-32 that works with any elliptic curve (not just secp256k1).
//! For secp256k1, SLIP-10 and BIP-32 produce identical results for non-hardened
//! derivation. We use SLIP-10 as the reference because it has a cleaner spec.
//!
//! ## BSV Derivation Paths
//!
//! Standard BSV paths (BIP-44):
//! - `m/44'/236'/0'/0/0` — First receiving address (236 = BSV coin type)
//! - `m/44'/236'/0'/1/0` — First change address
//!
//! The account level (`m/44'/236'/0'`) uses hardened derivation for security.
//! The address level (`/0/0`) uses non-hardened derivation for efficiency.
//!
//! ## Chain Code Bootstrapping
//!
//! BIP-32 requires a 32-byte chain code at each level of the derivation tree.
//! In a standard wallet, the root chain code comes from the master seed. In MPC,
//! there is no single master seed, so the chain code must be established during
//! DKG or derived deterministically from the joint public key.
//!
//! If `JointPublicKey::chain_code` is `None`, this module derives a chain code
//! from `SHA-256(compressed_pubkey)`. This is safe because:
//! 1. Non-hardened derivation does not require chain code secrecy.
//! 2. The compressed public key is already public information.
//! 3. The derivation is deterministic — all parties compute the same chain code.
//!
//! For production DKG, the chain code SHOULD be set from the DKG transcript hash
//! or another shared randomness source, stored in `JointPublicKey::chain_code`.

use crate::error::{MpcError, Result};
use crate::types::JointPublicKey;

use bsv::primitives::ec::PublicKey;
use bsv::primitives::hash::{sha256, sha512_hmac};
use bsv::Address;

/// The secp256k1 curve order n, encoded as 32 big-endian bytes.
///
/// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
///
/// Any HMAC-SHA512 left-half that, interpreted as a big-endian unsigned integer,
/// is >= n makes the derivation index invalid (per BIP-32 spec). This is
/// astronomically unlikely (~1 in 2^128) but must be checked for correctness.
const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Maximum valid non-hardened child index (2^31 - 1).
const MAX_CHILD_INDEX: u32 = 0x7FFF_FFFF;

/// Derive a child public key from a joint MPC public key using a BIP-32/SLIP-10 path.
///
/// For non-hardened path components, this is a pure public-key operation that
/// does not require any MPC communication — each party can compute the child
/// public key independently.
///
/// For hardened path components (those with `'` suffix), this function currently
/// only supports public key derivation and will return an error. Hardened
/// derivation from MPC shares requires a separate protocol.
///
/// # Arguments
///
/// * `joint_key` — The parent joint public key (from DKG or a previous derivation).
/// * `path` — A BIP-32 derivation path string, e.g., `"m/44'/236'/0'/0/0"`.
///
/// # Returns
///
/// A new [`JointPublicKey`] for the derived child key, with the BSV address
/// updated to reflect the child's public key.
///
/// # Path Format
///
/// - `m` — Root (the joint key from DKG)
/// - `/N` — Non-hardened child at index N (0 <= N < 2^31)
/// - `/N'` or `/Nh` — Hardened child at index N (0 <= N < 2^31)
///
/// # Errors
///
/// - [`MpcError::Protocol`] if a hardened derivation step is requested (not yet supported
///   without MPC communication).
/// - [`MpcError::InvalidShare`] if the path is malformed or the compressed public key
///   is not a valid 33-byte secp256k1 point.
///
/// # Example
///
/// ```ignore
/// let child = derive_child_key(&joint_key, "m/0/1")?;
/// println!("Child address: {}", child.address);
/// ```
pub fn derive_child_key(joint_key: &JointPublicKey, path: &str) -> Result<JointPublicKey> {
    let components = parse_derivation_path(path)?;

    // Empty path means return the original key unchanged.
    if components.is_empty() {
        return Ok(joint_key.clone());
    }

    // Validate compressed public key length.
    if joint_key.compressed.len() != 33 {
        return Err(MpcError::InvalidShare(format!(
            "joint public key must be 33 bytes (compressed secp256k1), got {} bytes",
            joint_key.compressed.len()
        )));
    }

    // Validate compressed public key prefix (must be 0x02 or 0x03).
    let prefix = joint_key.compressed[0];
    if prefix != 0x02 && prefix != 0x03 {
        return Err(MpcError::InvalidShare(format!(
            "invalid compressed public key prefix: 0x{:02x} (expected 0x02 or 0x03)",
            prefix
        )));
    }

    // Bootstrap the chain code if not present.
    // Use SHA-256 of the compressed public key as a deterministic fallback.
    let initial_chain_code: [u8; 32] = match &joint_key.chain_code {
        Some(cc) if cc.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(cc);
            arr
        }
        Some(cc) => {
            return Err(MpcError::InvalidShare(format!(
                "chain code must be exactly 32 bytes, got {} bytes",
                cc.len()
            )));
        }
        None => sha256(&joint_key.compressed),
    };

    // Iteratively derive each path component.
    let mut current_key_bytes: [u8; 33] = joint_key.compressed.as_slice().try_into().map_err(
        |_| MpcError::InvalidShare("compressed key is not 33 bytes".to_string()),
    )?;
    let mut current_chain_code = initial_chain_code;

    for (index, hardened) in &components {
        if *hardened {
            return Err(MpcError::Protocol(
                "hardened derivation requires the private key, which is split across MPC shares; \
                 use a 2-party HMAC protocol or restrict to non-hardened paths"
                    .to_string(),
            ));
        }

        // BIP-32 non-hardened derivation:
        //   data = compressed_parent_pubkey (33 bytes) || index (4 bytes big-endian)
        //   I = HMAC-SHA512(chain_code, data)
        //   I_L = I[0..32] (tweak scalar)
        //   I_R = I[32..64] (child chain code)
        //   child_pubkey = parent_pubkey + I_L * G
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&current_key_bytes);
        data.extend_from_slice(&index.to_be_bytes());

        let hmac_output = sha512_hmac(&current_chain_code, &data);
        let (il, ir) = hmac_output.split_at(32);

        // Check that I_L < curve order (astronomically unlikely to fail, but
        // BIP-32 spec requires the check).
        if !scalar_less_than_order(il) {
            return Err(MpcError::InvalidShare(format!(
                "derived scalar >= secp256k1 order at index {}; \
                 try the next index (astronomically unlikely event)",
                index
            )));
        }

        // Check that I_L is not zero (would produce the same key as parent).
        if il.iter().all(|&b| b == 0) {
            return Err(MpcError::InvalidShare(format!(
                "derived scalar is zero at index {}; \
                 try the next index (astronomically unlikely event)",
                index
            )));
        }

        // Compute I_L * G (the offset point on secp256k1).
        let il_array: [u8; 32] = il.try_into().expect("il is exactly 32 bytes");
        let offset_point = PublicKey::from_scalar_mul_generator(&il_array).map_err(|e| {
            MpcError::InvalidShare(format!(
                "failed to compute offset point G * I_L: {}",
                e
            ))
        })?;

        // Compute child_pubkey = parent_pubkey + offset_point (point addition).
        let parent_point = PublicKey::from_bytes(&current_key_bytes).map_err(|e| {
            MpcError::InvalidShare(format!("invalid parent public key: {}", e))
        })?;
        let child_point = parent_point.add(&offset_point).map_err(|e| {
            MpcError::InvalidShare(format!("point addition failed: {}", e))
        })?;

        // Update for next iteration.
        current_key_bytes = child_point.to_compressed();
        current_chain_code = ir.try_into().expect("ir is exactly 32 bytes");
    }

    // Derive BSV mainnet P2PKH address from the final child public key.
    let child_pubkey = PublicKey::from_bytes(&current_key_bytes).map_err(|e| {
        MpcError::InvalidShare(format!("derived child key is invalid: {}", e))
    })?;
    let address = Address::new_from_public_key(&child_pubkey, true).map_err(|e| {
        MpcError::InvalidShare(format!("failed to derive BSV address: {}", e))
    })?;

    Ok(JointPublicKey {
        compressed: current_key_bytes.to_vec(),
        address: address.to_string(),
        chain_code: Some(current_chain_code.to_vec()),
    })
}

/// Compute the scalar tweak from a BIP-32 non-hardened derivation step.
///
/// This returns the left 32 bytes of `HMAC-SHA512(chain_code, pubkey || index)`,
/// which is the scalar that each MPC party should add to their private key share
/// to derive the child share. This is useful for the proxy and KSS to independently
/// update their shares without communication (for non-hardened derivation).
///
/// # Arguments
///
/// * `parent_compressed` — 33-byte compressed parent public key.
/// * `chain_code` — 32-byte BIP-32 chain code for this derivation level.
/// * `index` — Non-hardened child index (must be < 2^31).
///
/// # Returns
///
/// A tuple of `(tweak_scalar, child_chain_code)` where:
/// - `tweak_scalar` is a 32-byte big-endian scalar to add to each party's share.
/// - `child_chain_code` is the 32-byte chain code for the next derivation level.
///
/// # Errors
///
/// - [`MpcError::InvalidShare`] if the tweak scalar is >= the curve order or zero.
/// - [`MpcError::Protocol`] if the index is >= 2^31 (hardened range).
pub fn derive_tweak(
    parent_compressed: &[u8; 33],
    chain_code: &[u8; 32],
    index: u32,
) -> Result<([u8; 32], [u8; 32])> {
    if index > MAX_CHILD_INDEX {
        return Err(MpcError::Protocol(
            "index >= 2^31 is hardened derivation, which requires MPC protocol".to_string(),
        ));
    }

    let mut data = Vec::with_capacity(37);
    data.extend_from_slice(parent_compressed);
    data.extend_from_slice(&index.to_be_bytes());

    let hmac_output = sha512_hmac(chain_code, &data);
    let il: [u8; 32] = hmac_output[..32]
        .try_into()
        .expect("first 32 bytes of 64-byte HMAC");
    let ir: [u8; 32] = hmac_output[32..]
        .try_into()
        .expect("last 32 bytes of 64-byte HMAC");

    if !scalar_less_than_order(&il) {
        return Err(MpcError::InvalidShare(
            "derived tweak scalar >= secp256k1 order".to_string(),
        ));
    }

    if il.iter().all(|&b| b == 0) {
        return Err(MpcError::InvalidShare(
            "derived tweak scalar is zero".to_string(),
        ));
    }

    Ok((il, ir))
}

/// Parse a BIP-32 derivation path string into a sequence of child indices.
///
/// Returns a vector of `(index, hardened)` tuples.
///
/// # Path Format
///
/// - Must start with `m` or `M` (case-insensitive root marker).
/// - Components are separated by `/`.
/// - A trailing `'`, `h`, or `H` on a component marks it as hardened.
/// - Indices must be valid `u32` values in `[0, 2^31 - 1]`.
/// - `"m"` alone is a valid path that returns an empty vector (identity derivation).
///
/// # Examples
///
/// - `"m/44'/236'/0'/0/0"` -> `[(44, true), (236, true), (0, true), (0, false), (0, false)]`
/// - `"m/0/1/2"` -> `[(0, false), (1, false), (2, false)]`
/// - `"m"` -> `[]`
///
/// # Errors
///
/// - [`MpcError::InvalidShare`] if the path is malformed, contains non-numeric
///   components, has double slashes, or has indices out of range.
pub fn parse_derivation_path(path: &str) -> Result<Vec<(u32, bool)>> {
    let trimmed = path.trim();

    if trimmed.is_empty() {
        return Err(MpcError::InvalidShare(
            "derivation path is empty".to_string(),
        ));
    }

    // Must start with 'm' or 'M'.
    if !trimmed.starts_with('m') && !trimmed.starts_with('M') {
        return Err(MpcError::InvalidShare(format!(
            "derivation path must start with 'm' or 'M', got '{}'",
            trimmed.chars().next().unwrap_or('?')
        )));
    }

    // "m" or "M" alone is a valid empty derivation (identity).
    if trimmed == "m" || trimmed == "M" {
        return Ok(Vec::new());
    }

    // After "m", the next character must be '/'.
    let rest = &trimmed[1..];
    if !rest.starts_with('/') {
        return Err(MpcError::InvalidShare(format!(
            "expected '/' after 'm' in derivation path, got '{}'",
            rest.chars().next().unwrap_or('?')
        )));
    }

    // Strip the leading '/'.
    let components_str = &rest[1..];

    // Reject trailing slash.
    if components_str.ends_with('/') {
        return Err(MpcError::InvalidShare(
            "derivation path has trailing '/'".to_string(),
        ));
    }

    let mut result = Vec::new();

    for component in components_str.split('/') {
        if component.is_empty() {
            return Err(MpcError::InvalidShare(
                "derivation path contains empty component (double slash)".to_string(),
            ));
        }

        // Check for hardened suffix.
        let (index_str, hardened) =
            if component.ends_with('\'') || component.ends_with('h') || component.ends_with('H') {
                (&component[..component.len() - 1], true)
            } else {
                (component, false)
            };

        if index_str.is_empty() {
            return Err(MpcError::InvalidShare(format!(
                "derivation path component '{}' has no numeric index",
                component
            )));
        }

        // Parse as u32. This naturally rejects negative numbers and overflow.
        let index: u32 = index_str.parse().map_err(|e| {
            MpcError::InvalidShare(format!(
                "invalid index '{}' in derivation path: {}",
                index_str, e
            ))
        })?;

        // BIP-32: non-hardened indices are [0, 2^31 - 1].
        // Hardened indices are [0, 2^31 - 1] with the hardened flag.
        // The on-wire index for hardened is index + 0x80000000, but the path
        // notation uses just the base index with a ' suffix.
        if index > MAX_CHILD_INDEX {
            return Err(MpcError::InvalidShare(format!(
                "index {} exceeds maximum (2^31 - 1 = {})",
                index, MAX_CHILD_INDEX
            )));
        }

        result.push((index, hardened));
    }

    Ok(result)
}

/// Compare a 32-byte big-endian value against the secp256k1 curve order.
///
/// Returns `true` if the value is strictly less than the curve order.
fn scalar_less_than_order(bytes: &[u8]) -> bool {
    assert!(
        bytes.len() == 32,
        "scalar comparison requires exactly 32 bytes"
    );
    // Compare byte-by-byte in big-endian order (most significant first).
    for i in 0..32 {
        if bytes[i] < SECP256K1_ORDER[i] {
            return true;
        }
        if bytes[i] > SECP256K1_ORDER[i] {
            return false;
        }
        // bytes[i] == SECP256K1_ORDER[i]: continue to next byte.
    }
    // All bytes equal means bytes == order, which is NOT less than.
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // parse_derivation_path tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_standard_bip44_path() {
        let result = parse_derivation_path("m/44'/236'/0'/0/0").unwrap();
        assert_eq!(
            result,
            vec![
                (44, true),
                (236, true),
                (0, true),
                (0, false),
                (0, false),
            ]
        );
    }

    #[test]
    fn test_parse_all_hardened() {
        let result = parse_derivation_path("m/44'/1'/2'/3'").unwrap();
        assert_eq!(result, vec![(44, true), (1, true), (2, true), (3, true)]);
    }

    #[test]
    fn test_parse_all_non_hardened() {
        let result = parse_derivation_path("m/0/1/2/3").unwrap();
        assert_eq!(
            result,
            vec![(0, false), (1, false), (2, false), (3, false)]
        );
    }

    #[test]
    fn test_parse_empty_path_m() {
        let result = parse_derivation_path("m").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_uppercase_m() {
        let result = parse_derivation_path("M").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_single_component() {
        let result = parse_derivation_path("m/0").unwrap();
        assert_eq!(result, vec![(0, false)]);
    }

    #[test]
    fn test_parse_hardened_h_suffix() {
        let result = parse_derivation_path("m/44h/0h").unwrap();
        assert_eq!(result, vec![(44, true), (0, true)]);
    }

    #[test]
    fn test_parse_hardened_uppercase_h_suffix() {
        let result = parse_derivation_path("m/44H/0H").unwrap();
        assert_eq!(result, vec![(44, true), (0, true)]);
    }

    #[test]
    fn test_parse_no_m_prefix_error() {
        let err = parse_derivation_path("44'/0'/0").unwrap_err();
        assert!(
            err.to_string().contains("must start with 'm'"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_parse_empty_string_error() {
        let err = parse_derivation_path("").unwrap_err();
        assert!(err.to_string().contains("empty"), "got: {}", err);
    }

    #[test]
    fn test_parse_non_numeric_component_error() {
        let err = parse_derivation_path("m/abc/0").unwrap_err();
        assert!(
            err.to_string().contains("invalid index"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_parse_double_slash_error() {
        let err = parse_derivation_path("m//0").unwrap_err();
        assert!(
            err.to_string().contains("empty component"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_parse_trailing_slash_error() {
        let err = parse_derivation_path("m/0/").unwrap_err();
        assert!(
            err.to_string().contains("trailing"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_parse_negative_number_error() {
        // "-1" is not a valid u32, so it should fail to parse.
        let err = parse_derivation_path("m/-1").unwrap_err();
        assert!(
            err.to_string().contains("invalid index"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_parse_max_valid_index() {
        let result = parse_derivation_path("m/2147483647").unwrap();
        assert_eq!(result, vec![(2_147_483_647, false)]);
    }

    #[test]
    fn test_parse_overflow_u32_error() {
        let err = parse_derivation_path("m/4294967296").unwrap_err();
        assert!(
            err.to_string().contains("invalid index"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_parse_index_exceeds_max_child_error() {
        // 2^31 = 2147483648, which is > MAX_CHILD_INDEX (2^31 - 1).
        let err = parse_derivation_path("m/2147483648").unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_parse_mixed_hardened() {
        let result = parse_derivation_path("m/44'/0/1'/2").unwrap();
        assert_eq!(
            result,
            vec![(44, true), (0, false), (1, true), (2, false)]
        );
    }

    #[test]
    fn test_parse_m_without_slash_error() {
        let err = parse_derivation_path("m44").unwrap_err();
        assert!(
            err.to_string().contains("expected '/'"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_parse_whitespace_trimmed() {
        let result = parse_derivation_path("  m/0  ").unwrap();
        assert_eq!(result, vec![(0, false)]);
    }

    // -----------------------------------------------------------------------
    // scalar_less_than_order tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_scalar_zero_is_less_than_order() {
        assert!(scalar_less_than_order(&[0u8; 32]));
    }

    #[test]
    fn test_scalar_one_is_less_than_order() {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        assert!(scalar_less_than_order(&bytes));
    }

    #[test]
    fn test_scalar_order_is_not_less_than_order() {
        assert!(!scalar_less_than_order(&SECP256K1_ORDER));
    }

    #[test]
    fn test_scalar_order_minus_one_is_less_than_order() {
        let mut bytes = SECP256K1_ORDER;
        bytes[31] -= 1; // n - 1
        assert!(scalar_less_than_order(&bytes));
    }

    #[test]
    fn test_scalar_all_ff_is_not_less_than_order() {
        assert!(!scalar_less_than_order(&[0xFF; 32]));
    }

    // -----------------------------------------------------------------------
    // derive_child_key tests
    // -----------------------------------------------------------------------

    /// Helper: create a JointPublicKey from a known compressed public key.
    /// Uses a deterministic private key to produce the public key.
    fn make_test_joint_key() -> JointPublicKey {
        // Deterministic key bytes (same as POC 3 for consistency).
        let privkey = bsv::PrivateKey::from_bytes(&[
            0x0b, 0x1e, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1,
            0xe2, 0xf3, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf,
            0xd0, 0xe1, 0xf2, 0x03,
        ])
        .expect("valid test private key");
        let pubkey = privkey.public_key();
        let compressed = pubkey.to_compressed().to_vec();
        let address = Address::new_from_public_key(&pubkey, true)
            .expect("valid address")
            .to_string();

        JointPublicKey {
            compressed,
            address,
            chain_code: None, // Will use SHA-256 fallback.
        }
    }

    /// Helper: create a JointPublicKey with an explicit chain code.
    fn make_test_joint_key_with_chain_code(chain_code: [u8; 32]) -> JointPublicKey {
        let mut key = make_test_joint_key();
        key.chain_code = Some(chain_code.to_vec());
        key
    }

    #[test]
    fn test_derive_non_hardened_produces_different_key() {
        let parent = make_test_joint_key();
        let child = derive_child_key(&parent, "m/0").unwrap();

        assert_ne!(
            parent.compressed, child.compressed,
            "child key must differ from parent"
        );
        assert_ne!(
            parent.address, child.address,
            "child address must differ from parent"
        );
    }

    #[test]
    fn test_derive_same_path_is_deterministic() {
        let parent = make_test_joint_key();
        let child1 = derive_child_key(&parent, "m/0/1/2").unwrap();
        let child2 = derive_child_key(&parent, "m/0/1/2").unwrap();

        assert_eq!(
            child1.compressed, child2.compressed,
            "same path must produce same key"
        );
        assert_eq!(
            child1.address, child2.address,
            "same path must produce same address"
        );
    }

    #[test]
    fn test_derive_different_paths_produce_different_keys() {
        let parent = make_test_joint_key();
        let child_a = derive_child_key(&parent, "m/0").unwrap();
        let child_b = derive_child_key(&parent, "m/1").unwrap();

        assert_ne!(
            child_a.compressed, child_b.compressed,
            "different indices must produce different keys"
        );
    }

    #[test]
    fn test_derive_hardened_returns_error() {
        let parent = make_test_joint_key();
        let err = derive_child_key(&parent, "m/44'").unwrap_err();

        assert!(
            err.to_string().contains("hardened"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_derive_empty_path_returns_original() {
        let parent = make_test_joint_key();
        let child = derive_child_key(&parent, "m").unwrap();

        assert_eq!(
            parent.compressed, child.compressed,
            "empty path must return same key"
        );
    }

    #[test]
    fn test_derive_deep_path() {
        let parent = make_test_joint_key();
        let child = derive_child_key(&parent, "m/0/1/2/3/4/5").unwrap();

        // Simply verify it completes without error and produces a different key.
        assert_ne!(parent.compressed, child.compressed);
        assert_eq!(child.compressed.len(), 33);
    }

    #[test]
    fn test_derived_key_is_valid_secp256k1_point() {
        let parent = make_test_joint_key();
        let child = derive_child_key(&parent, "m/0").unwrap();

        // Verify it's a valid compressed secp256k1 point by parsing it.
        let child_pubkey = PublicKey::from_bytes(&child.compressed);
        assert!(
            child_pubkey.is_ok(),
            "derived key must be a valid secp256k1 point: {:?}",
            child_pubkey.err()
        );

        // Verify prefix is 0x02 or 0x03.
        let prefix = child.compressed[0];
        assert!(
            prefix == 0x02 || prefix == 0x03,
            "compressed key prefix must be 02 or 03, got {:02x}",
            prefix
        );
    }

    #[test]
    fn test_derive_with_explicit_chain_code() {
        // Use a known chain code and verify derivation works.
        let chain_code = [0x42u8; 32];
        let parent = make_test_joint_key_with_chain_code(chain_code);
        let child = derive_child_key(&parent, "m/0").unwrap();

        assert_ne!(parent.compressed, child.compressed);
        // Child should have a chain code set.
        assert!(child.chain_code.is_some());
        // Child chain code should differ from parent chain code (it's the right
        // half of the HMAC output).
        assert_ne!(
            child.chain_code.as_ref().unwrap(),
            &chain_code.to_vec(),
            "child chain code should differ from parent"
        );
    }

    #[test]
    fn test_derive_without_chain_code_uses_sha256_fallback() {
        let parent_no_cc = make_test_joint_key();
        assert!(parent_no_cc.chain_code.is_none());

        // Derive with no chain code (should use SHA-256 fallback).
        let child = derive_child_key(&parent_no_cc, "m/0").unwrap();
        assert_ne!(parent_no_cc.compressed, child.compressed);

        // Derive with explicit SHA-256 chain code — should produce same result.
        let expected_cc = sha256(&parent_no_cc.compressed);
        let parent_explicit = make_test_joint_key_with_chain_code(expected_cc);
        let child_explicit = derive_child_key(&parent_explicit, "m/0").unwrap();

        assert_eq!(
            child.compressed, child_explicit.compressed,
            "SHA-256 fallback must match explicit SHA-256 chain code"
        );
    }

    #[test]
    fn test_derive_invalid_pubkey_length() {
        let bad_key = JointPublicKey {
            compressed: vec![0x02; 20], // Wrong length.
            address: "bad".to_string(),
            chain_code: None,
        };
        let err = derive_child_key(&bad_key, "m/0").unwrap_err();
        assert!(
            err.to_string().contains("33 bytes"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_derive_invalid_pubkey_prefix() {
        let bad_key = JointPublicKey {
            compressed: vec![0x04; 33], // Uncompressed prefix.
            address: "bad".to_string(),
            chain_code: None,
        };
        let err = derive_child_key(&bad_key, "m/0").unwrap_err();
        assert!(
            err.to_string().contains("prefix"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_derive_invalid_chain_code_length() {
        let bad_key = JointPublicKey {
            compressed: make_test_joint_key().compressed,
            address: "test".to_string(),
            chain_code: Some(vec![0x00; 16]), // Wrong length.
        };
        let err = derive_child_key(&bad_key, "m/0").unwrap_err();
        assert!(
            err.to_string().contains("32 bytes"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_derive_child_address_is_valid() {
        let parent = make_test_joint_key();
        let child = derive_child_key(&parent, "m/0/1").unwrap();

        // Verify the address is a valid BSV mainnet address (starts with '1').
        assert!(
            child.address.starts_with('1'),
            "BSV mainnet P2PKH address must start with '1', got: {}",
            child.address
        );

        // Verify the address can be parsed back.
        let parsed = Address::new_from_string(&child.address);
        assert!(
            parsed.is_ok(),
            "derived address must be parseable: {:?}",
            parsed.err()
        );
    }

    #[test]
    fn test_derive_child_chain_code_propagation() {
        // Derive m/0 then m/0/1 and verify it equals deriving m/0/1 in one call.
        let parent = make_test_joint_key();

        let child_0 = derive_child_key(&parent, "m/0").unwrap();
        let child_0_1 = derive_child_key(&child_0, "m/1").unwrap();

        let direct_0_1 = derive_child_key(&parent, "m/0/1").unwrap();

        assert_eq!(
            child_0_1.compressed, direct_0_1.compressed,
            "incremental derivation must match single-call derivation"
        );
        assert_eq!(child_0_1.address, direct_0_1.address);
    }

    #[test]
    fn test_derive_matches_manual_bip32() {
        // Cross-validate our implementation against a manual BIP-32 computation
        // using the same HMAC-SHA512 + point arithmetic, step by step.
        //
        // We manually compute one level of non-hardened derivation and verify
        // our derive_child_key produces the identical result.
        let parent = make_test_joint_key();
        let chain_code = [0x55u8; 32]; // Known chain code.
        let parent_with_cc = make_test_joint_key_with_chain_code(chain_code);

        // Manually compute child at index 7.
        let index: u32 = 7;
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&parent.compressed);
        data.extend_from_slice(&index.to_be_bytes());

        let hmac_out = sha512_hmac(&chain_code, &data);
        let il: [u8; 32] = hmac_out[..32].try_into().unwrap();
        let ir: [u8; 32] = hmac_out[32..].try_into().unwrap();

        // offset = G * il
        let offset = PublicKey::from_scalar_mul_generator(&il).expect("valid offset");
        // child = parent + offset
        let parent_pub = PublicKey::from_bytes(&parent.compressed).expect("valid parent");
        let manual_child = parent_pub.add(&offset).expect("point addition");

        // Now derive using our function.
        let derived = derive_child_key(&parent_with_cc, "m/7").expect("derivation");

        assert_eq!(
            derived.compressed,
            manual_child.to_compressed().to_vec(),
            "derive_child_key must match manual BIP-32 computation"
        );

        // Verify the child chain code is the right half of the HMAC.
        assert_eq!(
            derived.chain_code.as_ref().unwrap().as_slice(),
            &ir,
            "child chain code must be HMAC right half"
        );
    }

    // -----------------------------------------------------------------------
    // derive_tweak tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_derive_tweak_basic() {
        let parent = make_test_joint_key();
        let parent_compressed: [u8; 33] =
            parent.compressed.as_slice().try_into().unwrap();
        let chain_code = sha256(&parent.compressed);

        let (tweak, child_cc) = derive_tweak(&parent_compressed, &chain_code, 0).unwrap();

        // Tweak should be non-zero.
        assert!(tweak.iter().any(|&b| b != 0), "tweak must be non-zero");
        // Child chain code should differ from parent.
        assert_ne!(child_cc, chain_code, "child chain code must differ");
        // Tweak should be less than the curve order.
        assert!(scalar_less_than_order(&tweak));
    }

    #[test]
    fn test_derive_tweak_hardened_index_rejected() {
        let parent = make_test_joint_key();
        let parent_compressed: [u8; 33] =
            parent.compressed.as_slice().try_into().unwrap();
        let chain_code = [0u8; 32];

        let err = derive_tweak(&parent_compressed, &chain_code, 0x8000_0000).unwrap_err();
        assert!(
            err.to_string().contains("hardened"),
            "got: {}",
            err
        );
    }

    #[test]
    fn test_derive_tweak_matches_derive_child_key() {
        // The tweak from derive_tweak, when applied as G * tweak + parent,
        // should produce the same child key as derive_child_key.
        let chain_code = [0x42u8; 32];
        let parent = make_test_joint_key_with_chain_code(chain_code);
        let parent_compressed: [u8; 33] =
            parent.compressed.as_slice().try_into().unwrap();

        let (tweak, _child_cc) = derive_tweak(&parent_compressed, &chain_code, 0).unwrap();

        // Compute child via point arithmetic.
        let offset = PublicKey::from_scalar_mul_generator(&tweak).unwrap();
        let parent_pub = PublicKey::from_bytes(&parent_compressed).unwrap();
        let manual_child = parent_pub.add(&offset).unwrap();

        // Compute child via derive_child_key.
        let derived_child = derive_child_key(&parent, "m/0").unwrap();

        assert_eq!(
            manual_child.to_compressed().to_vec(),
            derived_child.compressed,
            "derive_tweak + point add must match derive_child_key"
        );
    }
}
