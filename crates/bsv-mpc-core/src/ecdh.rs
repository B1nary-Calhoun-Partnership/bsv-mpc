//! Partial ECDH and Lagrange interpolation for MPC threshold key derivation.
//!
//! This module implements the distributed ECDH protocol used by BRC-42 key
//! derivation when the private key is split across MPC shares. Each party
//! computes a "partial ECDH" (point * share_scalar), and the results are
//! combined via Lagrange interpolation to recover the full ECDH shared secret
//! without ever reconstructing the private key.
//!
//! ## Algorithm (from POC 3)
//!
//! For VSS (threshold) shares: `share_i = f(I_i)` where `f(0) = secret_key`.
//!
//! Reconstruction: `secret = Σ λ_i * share_i`
//!
//! So: `point * secret = Σ λ_i * (point * share_i)`
//!
//! Where `λ_i` are Lagrange coefficients evaluated at x=0.
//!
//! ## Symmetric Key Derivation
//!
//! BRC-42 symmetric key derivation (for encrypt/decrypt/HMAC) requires computing:
//!
//! ```text
//! sym_point = child_priv * child_counter_pub
//!           = (root_priv + hmac) * (counterparty_pub + G * hmac)
//!           = root_priv * child_counter_pub + hmac * child_counter_pub
//! ```
//!
//! This needs 2 rounds of partial ECDH for "self"/"other" counterparties,
//! but can be computed locally for "anyone" (where counterparty_priv = 1).
//!
//! Proven in POC 3 (key derivation), POC 8 (BRC-31 auth), POC 9 (encrypt/decrypt).

use crate::error::{MpcError, Result};
use crate::hd::{compute_brc42_hmac, compute_invoice, derive_child_pubkey};

use bsv::primitives::ec::PublicKey;
use cggmp24::supported_curves::Secp256k1;
use generic_ec::{Scalar, SecretScalar};

// ── Share parsing ────────────────────────────────────────────────────────────

/// Parse the IncompleteKeyShare from raw JSON.
///
/// Handles both formats:
/// - Full `KeyShare` (has `.core` containing the IncompleteKeyShare + `.aux` with Paillier data)
/// - Raw `IncompleteKeyShare` (legacy/POC format)
fn parse_incomplete_key_share(
    raw_share_json: &[u8],
) -> Result<cggmp24::IncompleteKeyShare<Secp256k1>> {
    // Try full KeyShare first (production format from complete DKG).
    // Extract the core's JSON and re-deserialize as IncompleteKeyShare.
    if let Ok(full) = serde_json::from_slice::<serde_json::Value>(raw_share_json) {
        if let Some(core_val) = full.get("core") {
            let core_bytes = serde_json::to_vec(core_val)
                .map_err(|e| MpcError::InvalidShare(format!("failed to re-serialize core: {e}")))?;
            if let Ok(share) =
                serde_json::from_slice::<cggmp24::IncompleteKeyShare<Secp256k1>>(&core_bytes)
            {
                return Ok(share);
            }
        }
    }

    // Fall back to raw IncompleteKeyShare (legacy/POC format)
    serde_json::from_slice(raw_share_json)
        .map_err(|e| MpcError::InvalidShare(format!("failed to deserialize key share: {e}")))
}

/// Extract the secret scalar bytes from a serialized cggmp24 key share.
///
/// The raw_share_json is the key share data (the `ciphertext` field from
/// `EncryptedShare`, which despite its name holds raw JSON).
///
/// Handles both full `KeyShare` and raw `IncompleteKeyShare` formats.
///
/// Returns the 32-byte big-endian scalar.
pub fn parse_share_scalar(raw_share_json: &[u8]) -> Result<[u8; 32]> {
    let share = parse_incomplete_key_share(raw_share_json)?;
    let scalar: &Scalar<Secp256k1> =
        <SecretScalar<Secp256k1> as AsRef<Scalar<Secp256k1>>>::as_ref(&share.x);
    let encoded = scalar.to_be_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(encoded.as_bytes());
    Ok(arr)
}

/// Extract VSS evaluation points from a serialized cggmp24 key share.
///
/// Returns one 32-byte big-endian scalar per party, in party order.
/// These are the polynomial evaluation points `I[0], I[1], ...` from the
/// Feldman VSS setup. Needed for Lagrange coefficient computation.
///
/// Handles both full `KeyShare` and raw `IncompleteKeyShare` formats.
pub fn parse_share_vss_points(raw_share_json: &[u8]) -> Result<Vec<[u8; 32]>> {
    let share = parse_incomplete_key_share(raw_share_json)?;
    let vss = share.vss_setup.as_ref().ok_or_else(|| {
        MpcError::InvalidShare("share missing VSS setup (not a threshold share?)".into())
    })?;
    let mut points = Vec::with_capacity(vss.I.len());
    for eval_point in &vss.I {
        let scalar = Scalar::<Secp256k1>::from(*eval_point);
        let encoded = scalar.to_be_bytes();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(encoded.as_bytes());
        points.push(arr);
    }
    Ok(points)
}

// ── Partial ECDH ─────────────────────────────────────────────────────────────

/// Compute a single partial ECDH: `counterparty_pub * scalar`.
///
/// This is a simple EC scalar multiplication. Each MPC party calls this
/// with their share scalar to produce their partial ECDH contribution.
///
/// Used by both the proxy (locally) and the KSS (via `/ecdh` endpoint).
pub fn compute_partial_ecdh_point(
    counterparty_pub: &PublicKey,
    scalar: &[u8; 32],
) -> Result<PublicKey> {
    counterparty_pub
        .mul_scalar(scalar)
        .map_err(|e| MpcError::Protocol(format!("partial ECDH scalar mult failed: {e}")))
}

/// EC point addition: `a + b`.
pub fn point_add(a: &PublicKey, b: &PublicKey) -> Result<PublicKey> {
    a.add(b)
        .map_err(|e| MpcError::Protocol(format!("EC point addition failed: {e}")))
}

// ── Lagrange interpolation ───────────────────────────────────────────────────

/// Compute Lagrange coefficient λ_j(0) for a set of evaluation points.
///
/// ```text
/// λ_j(0) = Π_{m≠j} (0 - I_m) / (I_j - I_m)
///        = Π_{m≠j} (-I_m) / (I_j - I_m)
/// ```
///
/// Returns the coefficient as a 32-byte big-endian scalar.
/// Ported from POC 3 (`mpc_partial_ecdh` lines 70-87).
fn lagrange_coefficient(j: usize, evaluation_points: &[[u8; 32]]) -> Result<[u8; 32]> {
    let i_j = Scalar::<Secp256k1>::from_be_bytes(evaluation_points[j]).map_err(|_| {
        MpcError::Protocol(format!(
            "invalid evaluation point at index {j}: not a valid scalar"
        ))
    })?;

    let mut lambda = Scalar::<Secp256k1>::one();

    for (m, ep_m) in evaluation_points.iter().enumerate() {
        if m == j {
            continue;
        }
        let i_m = Scalar::<Secp256k1>::from_be_bytes(*ep_m).map_err(|_| {
            MpcError::Protocol(format!(
                "invalid evaluation point at index {m}: not a valid scalar"
            ))
        })?;

        // numerator: -I_m
        let neg_i_m = -i_m;
        // denominator: I_j - I_m
        let diff = i_j - i_m;
        let diff_inv = diff.invert().ok_or_else(|| {
            MpcError::Protocol(format!(
                "evaluation points at {j} and {m} are not distinct (inversion failed)"
            ))
        })?;
        lambda = lambda * neg_i_m * diff_inv;
    }

    let encoded = lambda.to_be_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(encoded.as_bytes());
    Ok(arr)
}

/// Combine partial ECDH results using Lagrange interpolation at x=0.
///
/// Each entry is `(partial_ecdh_point, evaluation_point_bytes)` where:
/// - `partial_ecdh_point` = `counterparty_pub * share_i` (computed by party i)
/// - `evaluation_point_bytes` = the VSS evaluation point `I_i` (32 bytes BE)
///
/// Returns `Σ λ_i * partial_i` which equals `counterparty_pub * secret_key`.
///
/// Ported from POC 3 (`mpc_partial_ecdh` lines 68-117).
pub fn combine_partials_lagrange(partials: &[(PublicKey, [u8; 32])]) -> Result<PublicKey> {
    let n = partials.len();
    if n == 0 {
        return Err(MpcError::Protocol("no partials to combine".into()));
    }

    let eval_points: Vec<[u8; 32]> = partials.iter().map(|(_, ep)| *ep).collect();

    // Compute first weighted partial: λ_0 * partial_0
    let lambda_0 = lagrange_coefficient(0, &eval_points)?;
    let mut result = partials[0]
        .0
        .mul_scalar(&lambda_0)
        .map_err(|e| MpcError::Protocol(format!("Lagrange scalar mult failed: {e}")))?;

    // Add subsequent weighted partials: result += λ_j * partial_j
    for (j, (partial_j, _)) in partials.iter().enumerate().skip(1) {
        let lambda_j = lagrange_coefficient(j, &eval_points)?;
        let weighted = partial_j
            .mul_scalar(&lambda_j)
            .map_err(|e| MpcError::Protocol(format!("Lagrange scalar mult failed: {e}")))?;
        result = result
            .add(&weighted)
            .map_err(|e| MpcError::Protocol(format!("Lagrange point addition failed: {e}")))?;
    }

    Ok(result)
}

// ── Symmetric key derivation ─────────────────────────────────────────────────

/// Derive the full BRC-42 symmetric key for "anyone" counterparty (0 MPC rounds).
///
/// For "anyone", the counterparty private key is 1, so:
/// - `shared_secret = ECDH(anyone_pub, root_priv) = root_pub` (known locally)
/// - `child_anyone_priv = 1 + hmac` (known locally)
/// - `child_our_pub = root_pub + G * hmac` (known locally)
/// - `sym_point = child_anyone_priv * child_our_pub` (local scalar mult)
/// - `sym_key = sym_point.x()`
///
/// Proven in POC 9 (test_bidirectional_all_protocols uses "anyone" variant).
pub fn derive_symmetric_key_anyone(
    root_pub: &PublicKey,
    level: u8,
    protocol_name: &str,
    key_id: &str,
) -> Result<[u8; 32]> {
    let invoice = compute_invoice(level, protocol_name, key_id)?;

    // For "anyone": shared_secret = root_pub
    let hmac_bytes = compute_brc42_hmac(root_pub, &invoice);

    // child_our_pub = root_pub + G * hmac
    let child_our_pub = derive_child_pubkey(root_pub, root_pub, &invoice)?;

    // child_anyone_priv = 1 + hmac (scalar addition mod curve order)
    let one = Scalar::<Secp256k1>::one();
    let hmac_scalar = Scalar::<Secp256k1>::from_be_bytes(hmac_bytes)
        .map_err(|_| MpcError::Protocol("HMAC bytes not a valid secp256k1 scalar".into()))?;
    let child_anyone_priv = one + hmac_scalar;
    let encoded = child_anyone_priv.to_be_bytes();
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(encoded.as_bytes());

    // sym_point = child_our_pub * child_anyone_priv
    let sym_point = child_our_pub
        .mul_scalar(&scalar_bytes)
        .map_err(|e| MpcError::Protocol(format!("anyone symmetric key scalar mult failed: {e}")))?;

    // sym_key = x-coordinate of sym_point
    Ok(sym_point.x())
}

/// Derive the full BRC-42 symmetric key from two partial ECDH results.
///
/// This is the second half of the 2-round symmetric key derivation for
/// "self" and "other" counterparties. The caller must have already:
///
/// 1. Computed `shared_secret = partial_ecdh(counterparty_pub)` (round 1)
/// 2. Computed `hmac = HMAC-SHA256(compressed(shared_secret), invoice)`
/// 3. Computed `child_counter_pub = counterparty_pub + G * hmac`
/// 4. Computed `root_times_child = partial_ecdh(child_counter_pub)` (round 2)
///
/// This function performs the final local computation:
/// ```text
/// hmac_times_child = child_counter_pub * hmac
/// sym_point = root_times_child + hmac_times_child
/// sym_key = sym_point.x()
/// ```
///
/// Algorithm from POC 9 (`mpc_derive_symmetric_key`).
pub fn derive_symmetric_key_from_partials(
    counterparty_pub: &PublicKey,
    shared_secret: &PublicKey,
    root_times_child: &PublicKey,
    invoice: &str,
) -> Result<[u8; 32]> {
    // Compute HMAC from the shared secret
    let hmac_bytes = compute_brc42_hmac(shared_secret, invoice);

    // child_counter_pub = counterparty_pub + G * hmac
    let child_counter_pub = derive_child_pubkey(counterparty_pub, shared_secret, invoice)?;

    // hmac * child_counter_pub (local scalar multiplication)
    let hmac_times_child = child_counter_pub
        .mul_scalar(&hmac_bytes)
        .map_err(|e| MpcError::Protocol(format!("symmetric key hmac*child mult failed: {e}")))?;

    // sym_point = root_times_child + hmac_times_child
    let sym_point = point_add(root_times_child, &hmac_times_child)?;

    // sym_key = x-coordinate of sym_point
    Ok(sym_point.x())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bsv::primitives::ec::PrivateKey;
    use bsv::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};
    use cggmp24::security_level::SecurityLevel128;
    use generic_ec::NonZero;

    /// Same test key as POC 3 / POC 9 / hd.rs tests.
    const TEST_KEY_BYTES: [u8; 32] = [
        0x0b, 0x1e, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1, 0xe2,
        0xf3, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1,
        0xf2, 0x03,
    ];

    fn bsv_privkey_to_scalar(privkey: &PrivateKey) -> NonZero<SecretScalar<Secp256k1>> {
        let bytes = privkey.to_bytes();
        let mut scalar =
            Scalar::<Secp256k1>::from_be_bytes(bytes).expect("valid scalar from private key bytes");
        let secret = SecretScalar::new(&mut scalar);
        NonZero::from_secret_scalar(secret).expect("non-zero scalar")
    }

    fn generate_2of2_shares(root_key: &PrivateKey) -> Vec<cggmp24::IncompleteKeyShare<Secp256k1>> {
        let sk = bsv_privkey_to_scalar(root_key);
        cggmp24::trusted_dealer::builder::<Secp256k1, SecurityLevel128>(2)
            .set_threshold(Some(2))
            .set_shared_secret_key(sk)
            .generate_core_shares(&mut rand::rngs::OsRng)
            .expect("trusted dealer should work")
    }

    fn share_to_bytes(share: &cggmp24::IncompleteKeyShare<Secp256k1>) -> [u8; 32] {
        let scalar: &Scalar<Secp256k1> =
            <SecretScalar<Secp256k1> as AsRef<Scalar<Secp256k1>>>::as_ref(&share.x);
        let encoded = scalar.to_be_bytes();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(encoded.as_bytes());
        arr
    }

    #[test]
    fn test_parse_share_scalar_roundtrip() {
        let root_key = PrivateKey::from_bytes(&TEST_KEY_BYTES).unwrap();
        let shares = generate_2of2_shares(&root_key);
        let share_json = serde_json::to_vec(&shares[0]).unwrap();

        let parsed_scalar = parse_share_scalar(&share_json).unwrap();
        let expected_scalar = share_to_bytes(&shares[0]);

        assert_eq!(parsed_scalar, expected_scalar);
    }

    #[test]
    fn test_parse_share_vss_points() {
        let root_key = PrivateKey::from_bytes(&TEST_KEY_BYTES).unwrap();
        let shares = generate_2of2_shares(&root_key);
        let share_json = serde_json::to_vec(&shares[0]).unwrap();

        let points = parse_share_vss_points(&share_json).unwrap();
        assert_eq!(points.len(), 2); // 2-of-2 has 2 evaluation points

        // Points should be non-zero and distinct
        assert_ne!(points[0], [0u8; 32]);
        assert_ne!(points[1], [0u8; 32]);
        assert_ne!(points[0], points[1]);
    }

    #[test]
    fn test_partial_ecdh_matches_full_ecdh() {
        // Generate key pair and split into MPC shares
        let root_key = PrivateKey::from_bytes(&TEST_KEY_BYTES).unwrap();
        let root_pub = root_key.public_key();
        let shares = generate_2of2_shares(&root_key);

        // Normal ECDH: root_pub * root_priv (self counterparty)
        let full_ecdh = root_key.derive_shared_secret(&root_pub).expect("ECDH self");

        // MPC partial ECDH: compute partials and combine with Lagrange
        let share0_json = serde_json::to_vec(&shares[0]).unwrap();
        let share1_json = serde_json::to_vec(&shares[1]).unwrap();

        let scalar0 = parse_share_scalar(&share0_json).unwrap();
        let scalar1 = parse_share_scalar(&share1_json).unwrap();
        let vss_points = parse_share_vss_points(&share0_json).unwrap();

        let partial0 = compute_partial_ecdh_point(&root_pub, &scalar0).unwrap();
        let partial1 = compute_partial_ecdh_point(&root_pub, &scalar1).unwrap();

        let partials = vec![(partial0, vss_points[0]), (partial1, vss_points[1])];
        let mpc_ecdh = combine_partials_lagrange(&partials).unwrap();

        assert_eq!(
            full_ecdh.to_compressed(),
            mpc_ecdh.to_compressed(),
            "MPC partial ECDH must match full ECDH"
        );
    }

    #[test]
    fn test_partial_ecdh_with_other_counterparty() {
        let root_key = PrivateKey::from_bytes(&TEST_KEY_BYTES).unwrap();
        let shares = generate_2of2_shares(&root_key);

        // Server public key
        let server_key = PrivateKey::from_bytes(&[
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0x00, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x13,
            0x57, 0x9b, 0xdf, 0x02,
        ])
        .unwrap();
        let server_pub = server_key.public_key();

        // Full ECDH
        let full_ecdh = root_key
            .derive_shared_secret(&server_pub)
            .expect("ECDH other");

        // MPC partial ECDH
        let share0_json = serde_json::to_vec(&shares[0]).unwrap();
        let share1_json = serde_json::to_vec(&shares[1]).unwrap();
        let scalar0 = parse_share_scalar(&share0_json).unwrap();
        let scalar1 = parse_share_scalar(&share1_json).unwrap();
        let vss_points = parse_share_vss_points(&share0_json).unwrap();

        let partial0 = compute_partial_ecdh_point(&server_pub, &scalar0).unwrap();
        let partial1 = compute_partial_ecdh_point(&server_pub, &scalar1).unwrap();

        let mpc_ecdh =
            combine_partials_lagrange(&[(partial0, vss_points[0]), (partial1, vss_points[1])])
                .unwrap();

        assert_eq!(
            full_ecdh.to_compressed(),
            mpc_ecdh.to_compressed(),
            "MPC partial ECDH must match full ECDH for Other counterparty"
        );
    }

    #[test]
    fn test_derive_symmetric_key_anyone_matches_sdk() {
        let root_key = PrivateKey::from_bytes(&TEST_KEY_BYTES).unwrap();
        let root_pub = root_key.public_key();

        let protocol = Protocol::new(SecurityLevel::Counterparty, "worm memory");
        let key_id = "knowledge";

        // BSV SDK symmetric key
        let deriver = KeyDeriver::new(Some(root_key));
        let wallet_sym = deriver
            .derive_symmetric_key(&protocol, key_id, &Counterparty::Anyone)
            .expect("wallet derivation");

        // Our MPC-compatible derivation
        let mpc_sym = derive_symmetric_key_anyone(&root_pub, 2, "worm memory", key_id).unwrap();

        assert_eq!(
            wallet_sym.as_bytes(),
            &mpc_sym,
            "MPC 'anyone' symmetric key must match BSV SDK"
        );
    }

    #[test]
    fn test_derive_symmetric_key_self_matches_sdk() {
        let root_key = PrivateKey::from_bytes(&TEST_KEY_BYTES).unwrap();
        let root_pub = root_key.public_key();
        let shares = generate_2of2_shares(&root_key);

        let protocol = Protocol::new(SecurityLevel::Counterparty, "worm memory");
        let key_id = "knowledge";

        // BSV SDK symmetric key
        let deriver = KeyDeriver::new(Some(root_key.clone()));
        let wallet_sym = deriver
            .derive_symmetric_key(&protocol, key_id, &Counterparty::Self_)
            .expect("wallet derivation");

        // MPC: simulate 2-round partial ECDH
        let share0_json = serde_json::to_vec(&shares[0]).unwrap();
        let share1_json = serde_json::to_vec(&shares[1]).unwrap();
        let scalar0 = parse_share_scalar(&share0_json).unwrap();
        let scalar1 = parse_share_scalar(&share1_json).unwrap();
        let vss_points = parse_share_vss_points(&share0_json).unwrap();

        // Round 1: base ECDH — counterparty_pub * root_priv
        // For "self": counterparty_pub = root_pub
        let p0_r1 = compute_partial_ecdh_point(&root_pub, &scalar0).unwrap();
        let p1_r1 = compute_partial_ecdh_point(&root_pub, &scalar1).unwrap();
        let shared_secret =
            combine_partials_lagrange(&[(p0_r1, vss_points[0]), (p1_r1, vss_points[1])]).unwrap();

        // Compute invoice and child_counter_pub
        let invoice = compute_invoice(2, "worm memory", key_id).unwrap();
        let child_counter_pub = derive_child_pubkey(&root_pub, &shared_secret, &invoice).unwrap();

        // Round 2: root_priv * child_counter_pub
        let p0_r2 = compute_partial_ecdh_point(&child_counter_pub, &scalar0).unwrap();
        let p1_r2 = compute_partial_ecdh_point(&child_counter_pub, &scalar1).unwrap();
        let root_times_child =
            combine_partials_lagrange(&[(p0_r2, vss_points[0]), (p1_r2, vss_points[1])]).unwrap();

        // Final: derive_symmetric_key_from_partials
        let mpc_sym = derive_symmetric_key_from_partials(
            &root_pub, // counterparty_pub = root_pub for "self"
            &shared_secret,
            &root_times_child,
            &invoice,
        )
        .unwrap();

        assert_eq!(
            wallet_sym.as_bytes(),
            &mpc_sym,
            "MPC 'self' symmetric key must match BSV SDK"
        );
    }

    #[test]
    fn test_lagrange_single_partial_errors() {
        // Can't combine zero partials
        let result = combine_partials_lagrange(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_anyone_symmetric_key_all_worm_protocols() {
        let root_key = PrivateKey::from_bytes(&TEST_KEY_BYTES).unwrap();
        let root_pub = root_key.public_key();

        let protocols = [
            ("worm memory", "knowledge"),
            ("worm state", "session-token"),
            ("worm conversation", "conv-id-1"),
        ];

        for (proto_name, key_id) in &protocols {
            let protocol = Protocol::new(SecurityLevel::Counterparty, *proto_name);
            let deriver = KeyDeriver::new(Some(root_key.clone()));
            let wallet_sym = deriver
                .derive_symmetric_key(&protocol, key_id, &Counterparty::Anyone)
                .unwrap();

            let mpc_sym = derive_symmetric_key_anyone(&root_pub, 2, proto_name, key_id).unwrap();

            assert_eq!(
                wallet_sym.as_bytes(),
                &mpc_sym,
                "key mismatch for anyone/{}/{}",
                proto_name,
                key_id
            );
        }
    }
}
