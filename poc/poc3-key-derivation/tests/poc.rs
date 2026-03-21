//! POC 3: BRC-42 Key Derivation Compatibility
//!
//! GO/NO-GO for wallet replacement.
//!
//! Validates that the MPC proxy can derive the SAME public keys as a normal
//! wallet for BRC-42 key derivation with various counterparty types.
//!
//! BRC-42 derivation formula:
//!   shared_secret = ECDH(counterparty_pub, root_priv)
//!   hmac = HMAC-SHA256(key=compressed(shared_secret), data=invoice_bytes)
//!   child_pubkey = root_pubkey + G * hmac
//!
//! For MPC: the proxy has the joint public key but NOT the private key.
//! - counterparty "anyone": shared_secret = root_pubkey → can derive locally
//! - counterparty "self"/Other: needs ECDH → needs MPC cooperation (partial ECDH)

use bsv::primitives::ec::{PrivateKey, PublicKey};
use bsv::primitives::hash::sha256_hmac;
use bsv::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};

use cggmp24::key_share::reconstruct_secret_key;
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use generic_ec::{NonZero, Point, SecretScalar};

/// Helper: convert a BSV SDK PrivateKey to a generic-ec NonZero<SecretScalar> for cggmp24
fn bsv_privkey_to_scalar(
    privkey: &PrivateKey,
) -> NonZero<SecretScalar<Secp256k1>> {
    let bytes = privkey.to_bytes();
    let mut scalar = generic_ec::Scalar::<Secp256k1>::from_be_bytes(&bytes)
        .expect("valid scalar from private key bytes");
    let secret = SecretScalar::new(&mut scalar);
    NonZero::from_secret_scalar(secret).expect("non-zero scalar")
}

/// Helper: extract share scalar bytes from an IncompleteKeyShare
fn share_to_bytes(share: &cggmp24::IncompleteKeyShare<Secp256k1>) -> [u8; 32] {
    let scalar: &generic_ec::Scalar<Secp256k1> =
        <SecretScalar<Secp256k1> as AsRef<generic_ec::Scalar<Secp256k1>>>::as_ref(&share.x);
    let encoded = scalar.to_be_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(encoded.as_bytes());
    arr
}

/// Helper: compute partial ECDH from MPC shares and combine with Lagrange interpolation.
///
/// For VSS (threshold) shares, shares are polynomial evaluations:
///   share_i = f(I_i), where f(0) = secret_key
/// Reconstruction: secret = Σ λ_i * share_i, where λ_i = Lagrange coeff at x=0
/// So: counterparty_pub * secret = Σ λ_i * (counterparty_pub * share_i)
fn mpc_partial_ecdh(
    counterparty_pub: &PublicKey,
    shares: &[cggmp24::IncompleteKeyShare<Secp256k1>],
) -> PublicKey {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::elliptic_curve::PrimeField;
    use k256::ProjectivePoint;

    // Get the VSS evaluation points from the shares
    let vss = shares[0]
        .vss_setup
        .as_ref()
        .expect("threshold shares should have VSS setup");

    let n = shares.len();
    let mut result = ProjectivePoint::IDENTITY;

    for j in 0..n {
        // Compute Lagrange coefficient λ_j(0) = Π_{m≠j} (0 - I_m) / (I_j - I_m)
        //                                     = Π_{m≠j} (-I_m) / (I_j - I_m)
        let i_j = &vss.I[j];
        let mut lambda = generic_ec::Scalar::<Secp256k1>::one();
        for m in 0..n {
            if m == j {
                continue;
            }
            let i_m = &vss.I[m];
            // numerator: -I_m
            let neg_i_m = -generic_ec::Scalar::<Secp256k1>::from(*i_m);
            // denominator: I_j - I_m
            let diff = generic_ec::Scalar::<Secp256k1>::from(*i_j)
                - generic_ec::Scalar::<Secp256k1>::from(*i_m);
            let diff_inv = diff.invert().expect("evaluation points must be distinct");
            lambda = lambda * neg_i_m * diff_inv;
        }

        // Compute partial_j = counterparty_pub * share_j
        let share_bytes = share_to_bytes(&shares[j]);
        let partial = counterparty_pub
            .mul_scalar(&share_bytes)
            .expect("partial ECDH");

        // Convert to k256 ProjectivePoint
        let partial_point = {
            let enc = k256::EncodedPoint::from_bytes(&partial.to_compressed()).unwrap();
            ProjectivePoint::from(k256::AffinePoint::from_encoded_point(&enc).unwrap())
        };

        // Multiply by Lagrange coefficient: λ_j * partial_j
        let lambda_bytes = lambda.to_be_bytes();
        let mut lambda_arr = [0u8; 32];
        lambda_arr.copy_from_slice(lambda_bytes.as_bytes());
        let lambda_scalar =
            Option::from(k256::Scalar::from_repr(lambda_arr.into()))
                .expect("valid scalar for Lagrange coefficient");
        let weighted = partial_point * lambda_scalar;

        result = result + weighted;
    }

    // Convert result to BSV PublicKey
    let affine = result.to_affine();
    let encoded = k256::EncodedPoint::from(affine);
    PublicKey::from_bytes(encoded.as_bytes()).expect("valid combined ECDH point")
}

/// Helper: convert a generic-ec Point (compressed) to a BSV SDK PublicKey
fn point_to_bsv_pubkey(point: &Point<Secp256k1>) -> PublicKey {
    let bytes = point.to_bytes(true); // compressed
    PublicKey::from_bytes(&bytes).expect("valid pubkey from point bytes")
}

/// Manually compute BRC-42 child public key derivation.
///
/// This is what the MPC proxy must compute:
///   child_pubkey = root_pubkey + G * HMAC-SHA256(compressed(shared_secret), invoice)
///
/// The caller provides the ECDH shared_secret (which for MPC would be computed
/// via partial scalar multiplication with KSS cooperation).
fn derive_child_pubkey_manual(
    root_pubkey: &PublicKey,
    shared_secret: &PublicKey,
    invoice_number: &str,
) -> PublicKey {
    // HMAC-SHA256(key=compressed_shared_secret, data=invoice_bytes)
    let hmac = sha256_hmac(&shared_secret.to_compressed(), invoice_number.as_bytes());

    // child_pubkey = root_pubkey + G * hmac
    // Use BSV SDK's PublicKey::derive_child which does exactly this
    // But we need to do it from first principles to prove MPC can do it.
    //
    // We need: root_pubkey_point + G * hmac_scalar
    // The BSV SDK PublicKey::derive_child takes (other_privkey, invoice) and computes
    // the ECDH internally. We already have the shared secret, so we compute the
    // offset point manually.

    // Convert HMAC to a scalar and compute G * scalar
    // Then add to root_pubkey
    // We can use BSV SDK's PrivateKey to do G * scalar (public_key() does this)
    let hmac_as_privkey = PrivateKey::from_bytes(&hmac).expect("HMAC should be valid scalar");
    let offset_pubkey = hmac_as_privkey.public_key(); // G * hmac

    // Add root_pubkey + offset_pubkey using point addition
    // BSV SDK doesn't expose raw point addition, so we use derive_child trick:
    // Actually, we need to do this at the byte level.
    // Use k256 directly for the point addition.
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::ProjectivePoint;

    let root_point = {
        let encoded = k256::EncodedPoint::from_bytes(&root_pubkey.to_compressed())
            .expect("valid encoding");
        let affine = k256::AffinePoint::from_encoded_point(&encoded).unwrap();
        ProjectivePoint::from(affine)
    };

    let offset_point = {
        let encoded = k256::EncodedPoint::from_bytes(&offset_pubkey.to_compressed())
            .expect("valid encoding");
        let affine = k256::AffinePoint::from_encoded_point(&encoded).unwrap();
        ProjectivePoint::from(affine)
    };

    let child_point = root_point + offset_point;
    let child_affine = child_point.to_affine();
    let child_encoded = k256::EncodedPoint::from(child_affine);
    PublicKey::from_bytes(child_encoded.as_bytes()).expect("valid child pubkey")
}

// ---- The Tests ----

/// Test 1: Counterparty "anyone" — MPC proxy can derive locally
///
/// For "anyone", the counterparty private key is scalar 1, so:
///   counterparty_pub = G * 1 = G (generator)
///   shared_secret = counterparty_pub * root_priv = G * root_priv = root_pubkey
///
/// The shared secret IS the root public key — no private key needed!
#[test]
fn test_anyone_counterparty_local_derivation() {
    println!("=== Test 1: Counterparty 'anyone' — local derivation ===");

    // Known root key
    let root_key = PrivateKey::from_bytes(&[
        0x0b, 0x1e, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b,
        0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1, 0xe2, 0xf3,
        0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b,
        0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03,
    ]).expect("valid private key");

    let root_pubkey = root_key.public_key();
    println!("  Root pubkey: {}", root_pubkey.to_hex());

    // Normal wallet derivation
    let deriver = KeyDeriver::new(Some(root_key.clone()));
    let protocol = Protocol::new(SecurityLevel::Counterparty, "3241645161d8");
    let key_id = "test-prefix test-suffix";

    let wallet_pubkey = deriver
        .derive_public_key(&protocol, key_id, &Counterparty::Anyone, true)
        .expect("wallet derivation should work");
    println!("  Wallet-derived pubkey: {}", wallet_pubkey.to_hex());

    // MPC derivation: using only the root PUBLIC key (no private key!)
    // For "anyone": shared_secret = root_pubkey (because anyone_priv = 1, so ECDH = G * root_priv = root_pub)
    //
    // But wait — the actual ECDH is: anyone_pub * root_priv
    // anyone_pub = G * 1 = G
    // shared_secret = G * root_priv = root_pubkey
    //
    // Verify this:
    let (anyone_priv, _anyone_pub) = KeyDeriver::anyone_key();
    let actual_shared_secret = root_key
        .derive_shared_secret(&anyone_priv.public_key())
        .expect("ECDH should work");
    assert_eq!(
        actual_shared_secret.to_compressed(),
        root_pubkey.to_compressed(),
        "For 'anyone', ECDH shared secret should equal root_pubkey"
    );
    println!("  Confirmed: ECDH(anyone_pub, root_priv) == root_pubkey");

    // Now derive using only the root public key (what MPC proxy would do)
    let invoice_number = format!("2-3241645161d8-{}", key_id);
    let mpc_derived = derive_child_pubkey_manual(&root_pubkey, &root_pubkey, &invoice_number);
    println!("  MPC-derived pubkey:    {}", mpc_derived.to_hex());

    assert_eq!(
        wallet_pubkey.to_compressed(),
        mpc_derived.to_compressed(),
        "MPC-derived pubkey must match wallet-derived pubkey for 'anyone'"
    );
    println!("  MATCH: MPC proxy can derive 'anyone' keys locally (no KSS needed)");
}

/// Test 2: Counterparty "self" — needs ECDH (MPC cooperation required)
///
/// For "self", the counterparty IS the wallet's own public key:
///   shared_secret = root_pubkey * root_priv (NOT equal to root_pubkey!)
///
/// The MPC proxy needs the private key for ECDH. In 2-of-2 MPC:
///   partial_A = root_pubkey * share_A
///   partial_B = root_pubkey * share_B
///   shared_secret = partial_A + partial_B
#[test]
fn test_self_counterparty_mpc_ecdh() {
    println!("\n=== Test 2: Counterparty 'self' — MPC ECDH ===");

    let root_key = PrivateKey::from_bytes(&[
        0x0b, 0x1e, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b,
        0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1, 0xe2, 0xf3,
        0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b,
        0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03,
    ]).expect("valid private key");

    let root_pubkey = root_key.public_key();

    // Normal wallet derivation
    let deriver = KeyDeriver::new(Some(root_key.clone()));
    let protocol = Protocol::new(SecurityLevel::Counterparty, "3241645161d8");
    let key_id = "test-prefix test-suffix";

    let wallet_pubkey = deriver
        .derive_public_key(&protocol, key_id, &Counterparty::Self_, true)
        .expect("wallet derivation should work");
    println!("  Wallet-derived pubkey: {}", wallet_pubkey.to_hex());

    // Verify that shared_secret != root_pubkey for "self"
    let self_shared_secret = root_key
        .derive_shared_secret(&root_pubkey)
        .expect("ECDH with self should work");
    assert_ne!(
        self_shared_secret.to_compressed(),
        root_pubkey.to_compressed(),
        "For 'self', shared secret must NOT equal root_pubkey"
    );
    println!("  Confirmed: ECDH(root_pub, root_priv) != root_pubkey");

    // Split the root key into 2-of-2 MPC shares using trusted_dealer
    let sk = bsv_privkey_to_scalar(&root_key);

    let shares = cggmp24::trusted_dealer::builder::<Secp256k1, SecurityLevel128>(2)
        .set_threshold(Some(2))
        .set_shared_secret_key(sk.clone())
        .generate_core_shares(&mut rand::rngs::OsRng)
        .expect("trusted dealer should work");

    // Verify the joint public key matches
    let joint_pubkey = point_to_bsv_pubkey(&shares[0].shared_public_key);
    assert_eq!(
        joint_pubkey.to_compressed(),
        root_pubkey.to_compressed(),
        "MPC joint pubkey must match root pubkey"
    );
    println!("  MPC joint pubkey matches root pubkey");

    // Verify secret key reconstruction
    let reconstructed = reconstruct_secret_key(&shares).expect("reconstruction should work");
    let reconstructed_scalar: &generic_ec::Scalar<Secp256k1> = reconstructed.as_ref();
    let reconstructed_bytes = reconstructed_scalar.to_be_bytes();
    assert_eq!(
        &root_key.to_bytes()[..],
        reconstructed_bytes.as_bytes(),
        "Reconstructed key must match original"
    );
    println!("  Secret key round-trip verified");

    // Simulate MPC ECDH: each party computes partial ECDH, combine with Lagrange
    let mpc_shared_secret = mpc_partial_ecdh(&root_pubkey, &shares);

    // Verify MPC ECDH matches normal ECDH
    assert_eq!(
        mpc_shared_secret.to_compressed(),
        self_shared_secret.to_compressed(),
        "MPC partial ECDH must produce same shared secret"
    );
    println!("  MPC partial ECDH matches normal ECDH");

    // Now derive child pubkey using the MPC-computed shared secret
    let invoice_number = format!("2-3241645161d8-{}", key_id);
    let mpc_derived =
        derive_child_pubkey_manual(&root_pubkey, &mpc_shared_secret, &invoice_number);
    println!("  MPC-derived pubkey:    {}", mpc_derived.to_hex());

    assert_eq!(
        wallet_pubkey.to_compressed(),
        mpc_derived.to_compressed(),
        "MPC-derived pubkey must match wallet-derived pubkey for 'self'"
    );
    println!("  MATCH: MPC proxy can derive 'self' keys via partial ECDH with KSS");
}

/// Test 3: Counterparty = specific server public key
#[test]
fn test_other_counterparty_mpc_ecdh() {
    println!("\n=== Test 3: Counterparty = specific server pubkey ===");

    let root_key = PrivateKey::from_bytes(&[
        0x0b, 0x1e, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b,
        0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1, 0xe2, 0xf3,
        0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b,
        0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03,
    ]).expect("valid private key");

    let root_pubkey = root_key.public_key();

    // A known server public key (random but deterministic)
    let server_key = PrivateKey::from_bytes(&[
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
        0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a,
        0xbc, 0xde, 0xf0, 0x13, 0x57, 0x9b, 0xdf, 0x02,
    ]).expect("valid server key");
    let server_pubkey = server_key.public_key();
    println!("  Server pubkey: {}", server_pubkey.to_hex());

    // Normal wallet derivation
    let deriver = KeyDeriver::new(Some(root_key.clone()));
    let protocol = Protocol::new(SecurityLevel::Counterparty, "3241645161d8");
    let key_id = "test-prefix test-suffix";

    let wallet_pubkey = deriver
        .derive_public_key(
            &protocol,
            key_id,
            &Counterparty::Other(server_pubkey.clone()),
            true,
        )
        .expect("wallet derivation should work");
    println!("  Wallet-derived pubkey: {}", wallet_pubkey.to_hex());

    // Split root key into MPC shares
    let sk = bsv_privkey_to_scalar(&root_key);
    let shares = cggmp24::trusted_dealer::builder::<Secp256k1, SecurityLevel128>(2)
        .set_threshold(Some(2))
        .set_shared_secret_key(sk)
        .generate_core_shares(&mut rand::rngs::OsRng)
        .expect("trusted dealer should work");

    // MPC partial ECDH with Lagrange interpolation
    let mpc_shared_secret = mpc_partial_ecdh(&server_pubkey, &shares);

    // Derive child pubkey
    let invoice_number = format!("2-3241645161d8-{}", key_id);
    let mpc_derived =
        derive_child_pubkey_manual(&root_pubkey, &mpc_shared_secret, &invoice_number);
    println!("  MPC-derived pubkey:    {}", mpc_derived.to_hex());

    assert_eq!(
        wallet_pubkey.to_compressed(),
        mpc_derived.to_compressed(),
        "MPC-derived pubkey must match wallet-derived for Other counterparty"
    );
    println!("  MATCH: MPC proxy can derive Other(server_pub) keys via partial ECDH");
}

/// Test 4: Memory encryption protocol [2, "worm memory"]
#[test]
fn test_worm_memory_protocol() {
    println!("\n=== Test 4: worm memory protocol ===");

    let root_key = PrivateKey::from_bytes(&[
        0x0b, 0x1e, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b,
        0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1, 0xe2, 0xf3,
        0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b,
        0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03,
    ]).expect("valid private key");

    let root_pubkey = root_key.public_key();

    let deriver = KeyDeriver::new(Some(root_key.clone()));
    let protocol = Protocol::new(SecurityLevel::Counterparty, "worm memory");
    let key_id = "memory-block-42";

    // Wallet derivation with counterparty "self" (memory encryption is self-encrypted)
    let wallet_pubkey = deriver
        .derive_public_key(&protocol, key_id, &Counterparty::Self_, true)
        .expect("wallet derivation should work");
    println!("  Wallet-derived pubkey: {}", wallet_pubkey.to_hex());

    // MPC derivation via partial ECDH
    let sk = bsv_privkey_to_scalar(&root_key);
    let shares = cggmp24::trusted_dealer::builder::<Secp256k1, SecurityLevel128>(2)
        .set_threshold(Some(2))
        .set_shared_secret_key(sk)
        .generate_core_shares(&mut rand::rngs::OsRng)
        .expect("trusted dealer should work");

    // MPC partial ECDH with Lagrange interpolation
    let mpc_shared_secret = mpc_partial_ecdh(&root_pubkey, &shares);

    let invoice_number = format!("2-worm memory-{}", key_id);
    let mpc_derived = derive_child_pubkey_manual(&root_pubkey, &mpc_shared_secret, &invoice_number);
    println!("  MPC-derived pubkey:    {}", mpc_derived.to_hex());

    assert_eq!(
        wallet_pubkey.to_compressed(),
        mpc_derived.to_compressed(),
    );
    println!("  MATCH: worm memory protocol derivation matches");
}

/// Test 5: Auth message signature protocol [2, "auth message signature"]
#[test]
fn test_auth_message_signature_protocol() {
    println!("\n=== Test 5: auth message signature protocol ===");

    let root_key = PrivateKey::from_bytes(&[
        0x0b, 0x1e, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b,
        0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1, 0xe2, 0xf3,
        0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b,
        0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03,
    ]).expect("valid private key");

    let root_pubkey = root_key.public_key();

    // Auth uses a specific server counterparty
    let server_key = PrivateKey::from_bytes(&[
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
        0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a,
        0xbc, 0xde, 0xf0, 0x13, 0x57, 0x9b, 0xdf, 0x02,
    ]).expect("valid server key");
    let server_pubkey = server_key.public_key();

    let deriver = KeyDeriver::new(Some(root_key.clone()));
    let protocol = Protocol::new(SecurityLevel::Counterparty, "auth message signature");
    let key_id = "request-nonce-abc123";

    let wallet_pubkey = deriver
        .derive_public_key(
            &protocol,
            key_id,
            &Counterparty::Other(server_pubkey.clone()),
            true,
        )
        .expect("wallet derivation should work");
    println!("  Wallet-derived pubkey: {}", wallet_pubkey.to_hex());

    // MPC partial ECDH
    let sk = bsv_privkey_to_scalar(&root_key);
    let shares = cggmp24::trusted_dealer::builder::<Secp256k1, SecurityLevel128>(2)
        .set_threshold(Some(2))
        .set_shared_secret_key(sk)
        .generate_core_shares(&mut rand::rngs::OsRng)
        .expect("trusted dealer should work");

    // MPC partial ECDH with Lagrange interpolation
    let mpc_shared_secret = mpc_partial_ecdh(&server_pubkey, &shares);

    let invoice_number = format!("2-auth message signature-{}", key_id);
    let mpc_derived = derive_child_pubkey_manual(&root_pubkey, &mpc_shared_secret, &invoice_number);
    println!("  MPC-derived pubkey:    {}", mpc_derived.to_hex());

    assert_eq!(
        wallet_pubkey.to_compressed(),
        mpc_derived.to_compressed(),
    );
    println!("  MATCH: auth message signature protocol derivation matches");
}

/// Test 6: BRC-42 spec test vectors — verify our manual derivation against spec
#[test]
fn test_brc42_spec_vectors() {
    println!("\n=== Test 6: BRC-42 spec test vectors ===");

    // Public key derivation test vector 1 from BRC-42 spec
    let sender_privkey = PrivateKey::from_hex(
        "583755110a8c059de5cd81b8a04e1be884c46083ade3f779c1e022f6f89da94c",
    ).expect("valid sender key");
    let recipient_pubkey = PublicKey::from_hex(
        "02c0c1e1a1f7d247827d1bcf399f0ef2deef7695c322fd91a01a91378f101b6ffc",
    ).expect("valid recipient pubkey");
    let invoice_number = "IBioA4D/OaE=";
    let expected_pubkey = PublicKey::from_hex(
        "03c1bf5baadee39721ae8c9882b3cf324f0bf3b9eb3fc1b8af8089ca7a7c2e669f",
    ).expect("valid expected pubkey");

    // Normal derivation (sender derives recipient's child pubkey)
    let derived = recipient_pubkey
        .derive_child(&sender_privkey, invoice_number)
        .expect("derivation should work");

    assert_eq!(
        derived.to_compressed(),
        expected_pubkey.to_compressed(),
        "BSV SDK derivation must match spec test vector"
    );
    println!("  BSV SDK matches spec vector 1");

    // Manual derivation using our formula
    let shared_secret = sender_privkey
        .derive_shared_secret(&recipient_pubkey)
        .expect("ECDH should work");
    let manual_derived =
        derive_child_pubkey_manual(&recipient_pubkey, &shared_secret, invoice_number);

    assert_eq!(
        manual_derived.to_compressed(),
        expected_pubkey.to_compressed(),
        "Manual derivation must match spec test vector"
    );
    println!("  Manual derivation matches spec vector 1");
    println!("  BRC-42 spec compliance verified");
}

/// Summary test — print the architecture implications
#[test]
fn test_summary() {
    println!("\n========================================");
    println!("  POC 3 ARCHITECTURE SUMMARY");
    println!("========================================");
    println!();
    println!("  For MPC proxy getPublicKey implementation:");
    println!();
    println!("  | Counterparty | ECDH secret      | Proxy action          |");
    println!("  |--------------|------------------|-----------------------|");
    println!("  | Anyone       | = root_pubkey    | Derive locally (0 RT) |");
    println!("  | Self_        | needs priv key   | Partial ECDH (1 RT)   |");
    println!("  | Other(key)   | needs priv key   | Partial ECDH (1 RT)   |");
    println!();
    println!("  RT = round-trip to KSS");
    println!();
    println!("  Partial ECDH protocol:");
    println!("    1. Proxy computes: partial_B = counterparty_pub * share_B");
    println!("    2. Proxy asks KSS: partial_A = counterparty_pub * share_A");
    println!("    3. Proxy adds: shared_secret = partial_A + partial_B");
    println!("    4. Proxy derives: child_pub = root_pub + G * HMAC(shared_secret, invoice)");
    println!();
    println!("  Security: partial ECDH reveals nothing about shares (ECDL is hard)");
    println!("========================================");
}
