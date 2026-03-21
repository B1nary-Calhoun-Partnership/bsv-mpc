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

use crate::error::Result;
use crate::types::JointPublicKey;

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
/// - [`MpcError::InvalidShare`] if the path is malformed.
///
/// # Example
///
/// ```ignore
/// let child = derive_child_key(&joint_key, "m/44'/236'/0'/0/0")?;
/// println!("Child address: {}", child.address);
/// ```
pub fn derive_child_key(joint_key: &JointPublicKey, path: &str) -> Result<JointPublicKey> {
    todo!(
        "BIP-32/SLIP-10 HD derivation: \
         1. Parse the derivation path string into a sequence of ChildNumber values \
            - Split on '/' \
            - 'm' is the root (joint_key) \
            - 'N' -> ChildNumber::Normal(N) \
            - \"N'\" or 'Nh' -> ChildNumber::Hardened(N) \
         2. Validate: all indices < 2^31 \
         3. For each path component, derive the child key: \
            a. Non-hardened (public derivation): \
               - data = parent_compressed_pubkey || index.to_be_bytes() \
               - I = HMAC-SHA512(chain_code, data) \
               - I_L = I[0..32] (scalar tweak) \
               - I_R = I[32..64] (child chain code) \
               - child_pubkey = parent_pubkey + I_L * G (secp256k1 point addition) \
               - If I_L >= secp256k1 order n, this index is invalid (astronomically unlikely) \
            b. Hardened derivation: \
               - Requires the private key, which we don't have in MPC \
               - Return MpcError::Protocol('hardened derivation requires MPC protocol') \
               - Future: implement 2-party HMAC protocol where parties jointly compute \
                 HMAC-SHA512(chain_code, 0x00 || private_key || index) without revealing shares \
         4. Derive BSV address from the final child public key: \
            - SHA-256 of compressed pubkey \
            - RIPEMD-160 of the SHA-256 hash \
            - Prepend version byte 0x00 (BSV mainnet) \
            - Append 4-byte checksum (first 4 bytes of double-SHA256) \
            - Base58 encode \
         5. Return JointPublicKey {{ compressed: child_pubkey, address: bsv_address }} \
         \
         Parent key: {} bytes, path: {}",
        joint_key.compressed.len(),
        path
    )
}

/// Parse a BIP-32 derivation path string into a sequence of child indices.
///
/// Returns a vector of `(index, hardened)` tuples.
///
/// # Examples
///
/// - `"m/44'/236'/0'/0/0"` -> `[(44, true), (236, true), (0, true), (0, false), (0, false)]`
/// - `"m/0/1/2"` -> `[(0, false), (1, false), (2, false)]`
pub fn parse_derivation_path(path: &str) -> Result<Vec<(u32, bool)>> {
    todo!(
        "Parse BIP-32 path: \
         1. Verify path starts with 'm' or 'M' \
         2. Split remaining string on '/' \
         3. For each component: \
            - If ends with ' or h or H: hardened, parse the numeric prefix \
            - Otherwise: non-hardened, parse as u32 \
            - Validate index < 2^31 \
         4. Return Vec<(index, is_hardened)> \
         \
         Path: {}",
        path
    )
}
