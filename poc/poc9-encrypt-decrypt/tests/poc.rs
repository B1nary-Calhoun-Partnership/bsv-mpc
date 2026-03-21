//! POC 9: Encrypt/Decrypt Compatibility
//!
//! GO/NO-GO for wallet migration.
//!
//! Validates that MPC shares can derive the SAME symmetric encryption keys
//! as a normal ProtoWallet, enabling:
//! - Wallet encrypts → MPC decrypts (migration: read existing encrypted data)
//! - MPC encrypts → Wallet decrypts (interop: both can read MPC-encrypted data)
//!
//! Algorithm for MPC symmetric key derivation (2 partial ECDH rounds):
//!
//! 1. Base ECDH: counterparty_key * root_priv (via MPC partial ECDH)
//! 2. Compute HMAC from base shared secret → derive child_pub locally
//! 3. Final ECDH: root_priv * child_pub (via MPC partial ECDH)
//! 4. Add local term: hmac * child_pub
//! 5. symmetric_point = (root_priv * child_pub) + (hmac * child_pub)
//! 6. symmetric_key = symmetric_point.x()
//!
//! This works because derive_symmetric_key does:
//!   child_priv = root_priv + hmac
//!   child_pub  = counterparty_key + G * hmac
//!   sym_point  = child_priv * child_pub = (root_priv + hmac) * child_pub
//!             = root_priv * child_pub + hmac * child_pub

use bsv::primitives::ec::{PrivateKey, PublicKey};
use bsv::primitives::hash::sha256_hmac;
use bsv::primitives::symmetric::SymmetricKey;
use bsv::wallet::{
    Counterparty, DecryptArgs, EncryptArgs, KeyDeriver, ProtoWallet, Protocol, SecurityLevel,
};

use cggmp24::key_share::reconstruct_secret_key;
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use generic_ec::{NonZero, SecretScalar};

/// Known root key used across all tests (deterministic).
const ROOT_KEY_BYTES: [u8; 32] = [
    0x0b, 0x1e, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1, 0xe2,
    0xf3, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1,
    0xf2, 0x03,
];

// ---- Helpers (reused from POC 3) ----

/// Convert a BSV SDK PrivateKey to a generic-ec NonZero<SecretScalar> for cggmp24.
fn bsv_privkey_to_scalar(privkey: &PrivateKey) -> NonZero<SecretScalar<Secp256k1>> {
    let bytes = privkey.to_bytes();
    let mut scalar =
        generic_ec::Scalar::<Secp256k1>::from_be_bytes(&bytes).expect("valid scalar");
    let secret = SecretScalar::new(&mut scalar);
    NonZero::from_secret_scalar(secret).expect("non-zero scalar")
}

/// Extract share scalar bytes from an IncompleteKeyShare.
fn share_to_bytes(share: &cggmp24::IncompleteKeyShare<Secp256k1>) -> [u8; 32] {
    let scalar: &generic_ec::Scalar<Secp256k1> =
        <SecretScalar<Secp256k1> as AsRef<generic_ec::Scalar<Secp256k1>>>::as_ref(&share.x);
    let encoded = scalar.to_be_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(encoded.as_bytes());
    arr
}

/// Compute partial ECDH from MPC shares and combine with Lagrange interpolation.
///
/// For VSS (threshold) shares: share_i = f(I_i) where f(0) = secret_key
/// Reconstruction: secret = Σ λ_i * share_i
/// So: point * secret = Σ λ_i * (point * share_i)
fn mpc_partial_ecdh(
    point: &PublicKey,
    shares: &[cggmp24::IncompleteKeyShare<Secp256k1>],
) -> PublicKey {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::elliptic_curve::PrimeField;
    use k256::ProjectivePoint;

    let vss = shares[0]
        .vss_setup
        .as_ref()
        .expect("threshold shares should have VSS setup");

    let n = shares.len();
    let mut result = ProjectivePoint::IDENTITY;

    for j in 0..n {
        // Lagrange coefficient λ_j(0) = Π_{m≠j} (-I_m) / (I_j - I_m)
        let i_j = &vss.I[j];
        let mut lambda = generic_ec::Scalar::<Secp256k1>::one();
        for m in 0..n {
            if m == j {
                continue;
            }
            let i_m = &vss.I[m];
            let neg_i_m = -generic_ec::Scalar::<Secp256k1>::from(*i_m);
            let diff = generic_ec::Scalar::<Secp256k1>::from(*i_j)
                - generic_ec::Scalar::<Secp256k1>::from(*i_m);
            let diff_inv = diff.invert().expect("distinct evaluation points");
            lambda = lambda * neg_i_m * diff_inv;
        }

        // partial_j = point * share_j
        let share_bytes = share_to_bytes(&shares[j]);
        let partial = point.mul_scalar(&share_bytes).expect("partial ECDH");

        // Convert to k256 ProjectivePoint
        let partial_point = {
            let enc = k256::EncodedPoint::from_bytes(&partial.to_compressed()).unwrap();
            ProjectivePoint::from(k256::AffinePoint::from_encoded_point(&enc).unwrap())
        };

        // Multiply by Lagrange coefficient
        let lambda_bytes = lambda.to_be_bytes();
        let mut lambda_arr = [0u8; 32];
        lambda_arr.copy_from_slice(lambda_bytes.as_bytes());
        let lambda_k256 = k256::Scalar::from_repr(lambda_arr.into())
            .expect("Lagrange coefficient must be valid scalar");
        let weighted = partial_point * lambda_k256;

        result = result + weighted;
    }

    let affine = result.to_affine();
    let encoded = k256::EncodedPoint::from(affine);
    PublicKey::from_bytes(encoded.as_bytes()).expect("valid combined ECDH point")
}

/// Add two PublicKey points using k256.
fn point_add(a: &PublicKey, b: &PublicKey) -> PublicKey {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::ProjectivePoint;

    let pa = {
        let enc = k256::EncodedPoint::from_bytes(&a.to_compressed()).unwrap();
        ProjectivePoint::from(k256::AffinePoint::from_encoded_point(&enc).unwrap())
    };
    let pb = {
        let enc = k256::EncodedPoint::from_bytes(&b.to_compressed()).unwrap();
        ProjectivePoint::from(k256::AffinePoint::from_encoded_point(&enc).unwrap())
    };

    let sum = pa + pb;
    let affine = sum.to_affine();
    let encoded = k256::EncodedPoint::from(affine);
    PublicKey::from_bytes(encoded.as_bytes()).expect("valid sum point")
}

// ---- Core MPC symmetric key derivation ----

/// Derive the same symmetric key as KeyDeriver::derive_symmetric_key, but using
/// only MPC shares (no access to the root private key).
///
/// Algorithm (2 partial ECDH rounds):
/// 1. base_ecdh = counterparty_key * root_priv  (MPC partial ECDH round 1)
/// 2. hmac = HMAC-SHA256(compressed(base_ecdh), invoice_bytes)
/// 3. child_pub = counterparty_key + G * hmac
/// 4. root_times_child = root_priv * child_pub  (MPC partial ECDH round 2)
/// 5. hmac_times_child = child_pub * hmac        (local scalar mult)
/// 6. symmetric_point = root_times_child + hmac_times_child
/// 7. symmetric_key = SymmetricKey::from_bytes(symmetric_point.x())
fn mpc_derive_symmetric_key(
    counterparty: &Counterparty,
    root_pubkey: &PublicKey,
    shares: &[cggmp24::IncompleteKeyShare<Secp256k1>],
    protocol: &Protocol,
    key_id: &str,
) -> SymmetricKey {
    // Normalize counterparty (mirrors KeyDeriver::derive_symmetric_key)
    let counterparty_key = match counterparty {
        Counterparty::Self_ => root_pubkey.clone(),
        Counterparty::Anyone => KeyDeriver::anyone_key().1,
        Counterparty::Other(pk) => pk.clone(),
    };

    // For Anyone, the SDK maps it to Other(anyone_pub) before deriving
    // The actual counterparty used in derivation:
    let actual_cp_key = match counterparty {
        Counterparty::Anyone => KeyDeriver::anyone_key().1,
        _ => counterparty_key.clone(),
    };

    // Build invoice number: "{security_level}-{protocol_name}-{key_id}"
    let invoice = format!(
        "{}-{}-{}",
        protocol.security_level as u8, protocol.protocol_name, key_id
    );

    // Round 1: Base ECDH — counterparty_key * root_priv
    let base_ecdh = mpc_partial_ecdh(&actual_cp_key, shares);

    // Compute HMAC
    let hmac_bytes = sha256_hmac(&base_ecdh.to_compressed(), invoice.as_bytes());

    // child_pub = counterparty_key + G * hmac (what derive_public_key(for_self=false) computes)
    let hmac_as_privkey =
        PrivateKey::from_bytes(&hmac_bytes).expect("HMAC should be valid scalar");
    let g_times_hmac = hmac_as_privkey.public_key();
    let child_pub = point_add(&actual_cp_key, &g_times_hmac);

    // Round 2: root_priv * child_pub (MPC partial ECDH)
    let root_times_child = mpc_partial_ecdh(&child_pub, shares);

    // Local: hmac * child_pub
    let hmac_times_child = child_pub
        .mul_scalar(&hmac_bytes)
        .expect("scalar mult should work");

    // symmetric_point = root_times_child + hmac_times_child
    let symmetric_point = point_add(&root_times_child, &hmac_times_child);

    // Extract X coordinate as symmetric key
    let x_bytes = symmetric_point.x();
    SymmetricKey::from_bytes(&x_bytes).expect("valid symmetric key")
}

/// Generate 2-of-2 MPC shares from a known root key using trusted dealer.
fn generate_shares(
    root_key: &PrivateKey,
) -> Vec<cggmp24::IncompleteKeyShare<Secp256k1>> {
    let sk = bsv_privkey_to_scalar(root_key);
    cggmp24::trusted_dealer::builder::<Secp256k1, SecurityLevel128>(2)
        .set_threshold(Some(2))
        .set_shared_secret_key(sk)
        .generate_core_shares(&mut rand::rngs::OsRng)
        .expect("trusted dealer should work")
}

// ---- Tests ----

/// Test 1: Verify MPC-derived symmetric key bytes match wallet-derived key bytes.
/// This is the foundation — if keys match, encrypt/decrypt will work.
#[test]
fn test_symmetric_key_equality() {
    println!("=== Test 1: Symmetric key byte equality ===");

    let root_key = PrivateKey::from_bytes(&ROOT_KEY_BYTES).unwrap();
    let root_pubkey = root_key.public_key();
    let shares = generate_shares(&root_key);

    // Verify joint pubkey matches
    let joint_pubkey = {
        let bytes = shares[0].shared_public_key.to_bytes(true);
        PublicKey::from_bytes(&bytes).unwrap()
    };
    assert_eq!(
        joint_pubkey.to_compressed(),
        root_pubkey.to_compressed(),
        "Joint pubkey must match root pubkey"
    );

    // Verify secret reconstruction
    let reconstructed = reconstruct_secret_key(&shares).unwrap();
    let reconstructed_scalar: &generic_ec::Scalar<Secp256k1> = reconstructed.as_ref();
    assert_eq!(
        &root_key.to_bytes()[..],
        reconstructed_scalar.to_be_bytes().as_bytes(),
        "Reconstructed key must match"
    );

    let protocol = Protocol::new(SecurityLevel::Counterparty, "worm memory");
    let key_id = "knowledge";

    // Wallet symmetric key
    let deriver = KeyDeriver::new(Some(root_key));
    let wallet_sym = deriver
        .derive_symmetric_key(&protocol, key_id, &Counterparty::Self_)
        .unwrap();

    // MPC symmetric key
    let mpc_sym =
        mpc_derive_symmetric_key(&Counterparty::Self_, &root_pubkey, &shares, &protocol, key_id);

    assert_eq!(
        wallet_sym.as_bytes(),
        mpc_sym.as_bytes(),
        "MPC-derived symmetric key must be byte-identical to wallet-derived key"
    );
    println!("  PASS: Symmetric key bytes match exactly");
}

/// Test 2: Wallet encrypts → MPC decrypts (the migration case).
/// Existing bsv-worm agents have encrypted memory. After switching to MPC proxy,
/// the MPC shares must be able to decrypt that existing data.
#[test]
fn test_wallet_encrypt_mpc_decrypt() {
    println!("\n=== Test 2: Wallet encrypt → MPC decrypt ===");

    let root_key = PrivateKey::from_bytes(&ROOT_KEY_BYTES).unwrap();
    let root_pubkey = root_key.public_key();
    let shares = generate_shares(&root_key);
    let wallet = ProtoWallet::new(Some(root_key));

    let protocol = Protocol::new(SecurityLevel::Counterparty, "worm memory");
    let plaintext = b"The agent remembers everything about its mission parameters.";

    // Wallet encrypts
    let encrypted = wallet
        .encrypt(EncryptArgs {
            plaintext: plaintext.to_vec(),
            protocol_id: protocol.clone(),
            key_id: "knowledge".to_string(),
            counterparty: Some(Counterparty::Self_),
        })
        .unwrap();

    println!(
        "  Encrypted: {} bytes (plaintext was {} bytes)",
        encrypted.ciphertext.len(),
        plaintext.len()
    );

    // MPC decrypts using shares
    let mpc_sym = mpc_derive_symmetric_key(
        &Counterparty::Self_,
        &root_pubkey,
        &shares,
        &protocol,
        "knowledge",
    );
    let decrypted = mpc_sym
        .decrypt(&encrypted.ciphertext)
        .expect("MPC-derived key must decrypt wallet-encrypted data");

    assert_eq!(
        &decrypted[..],
        &plaintext[..],
        "Decrypted plaintext must match original"
    );
    println!("  PASS: MPC successfully decrypted wallet-encrypted data");
}

/// Test 3: MPC encrypts → Wallet decrypts (the interop case).
#[test]
fn test_mpc_encrypt_wallet_decrypt() {
    println!("\n=== Test 3: MPC encrypt → Wallet decrypt ===");

    let root_key = PrivateKey::from_bytes(&ROOT_KEY_BYTES).unwrap();
    let root_pubkey = root_key.public_key();
    let shares = generate_shares(&root_key);
    let wallet = ProtoWallet::new(Some(root_key));

    let protocol = Protocol::new(SecurityLevel::Counterparty, "worm memory");
    let plaintext = b"New knowledge created by MPC-backed agent.";

    // MPC encrypts
    let mpc_sym = mpc_derive_symmetric_key(
        &Counterparty::Self_,
        &root_pubkey,
        &shares,
        &protocol,
        "knowledge",
    );
    let ciphertext = mpc_sym
        .encrypt(plaintext)
        .expect("MPC encryption should work");

    println!(
        "  Encrypted: {} bytes (plaintext was {} bytes)",
        ciphertext.len(),
        plaintext.len()
    );

    // Wallet decrypts
    let decrypted = wallet
        .decrypt(DecryptArgs {
            ciphertext,
            protocol_id: protocol,
            key_id: "knowledge".to_string(),
            counterparty: Some(Counterparty::Self_),
        })
        .unwrap();

    assert_eq!(
        &decrypted.plaintext[..],
        &plaintext[..],
        "Wallet-decrypted plaintext must match MPC-encrypted original"
    );
    println!("  PASS: Wallet successfully decrypted MPC-encrypted data");
}

/// Test 4: Protocol [2, "worm memory"] — agent memory encryption.
/// This is the most critical protocol for bsv-worm migration.
#[test]
fn test_protocol_worm_memory() {
    println!("\n=== Test 4: Protocol [2, \"worm memory\"] ===");

    let root_key = PrivateKey::from_bytes(&ROOT_KEY_BYTES).unwrap();
    let root_pubkey = root_key.public_key();
    let shares = generate_shares(&root_key);
    let wallet = ProtoWallet::new(Some(root_key));

    let protocol = Protocol::new(SecurityLevel::Counterparty, "worm memory");

    // Test multiple key_ids representing different memory blocks
    let memory_blocks = vec![
        ("block-0", "Initial system prompt and identity."),
        ("block-42", "Learned that user prefers concise responses."),
        ("block-999", "Critical: API key rotation schedule every 30 days."),
    ];

    for (key_id, content) in &memory_blocks {
        let encrypted = wallet
            .encrypt(EncryptArgs {
                plaintext: content.as_bytes().to_vec(),
                protocol_id: protocol.clone(),
                key_id: key_id.to_string(),
                counterparty: Some(Counterparty::Self_),
            })
            .unwrap();

        let mpc_sym = mpc_derive_symmetric_key(
            &Counterparty::Self_,
            &root_pubkey,
            &shares,
            &protocol,
            key_id,
        );
        let decrypted = mpc_sym.decrypt(&encrypted.ciphertext).unwrap();

        assert_eq!(
            std::str::from_utf8(&decrypted).unwrap(),
            *content,
            "Memory block '{}' round-trip failed",
            key_id
        );
        println!("  PASS: key_id='{}' — wallet→MPC round-trip OK", key_id);
    }
}

/// Test 5: Protocol [2, "worm state"] — agent state token encryption.
#[test]
fn test_protocol_worm_state() {
    println!("\n=== Test 5: Protocol [2, \"worm state\"] ===");

    let root_key = PrivateKey::from_bytes(&ROOT_KEY_BYTES).unwrap();
    let root_pubkey = root_key.public_key();
    let shares = generate_shares(&root_key);
    let wallet = ProtoWallet::new(Some(root_key));

    let protocol = Protocol::new(SecurityLevel::Counterparty, "worm state");
    let state_data = r#"{"task":"research","progress":0.73,"context_hash":"a1b2c3"}"#;

    // Wallet encrypt → MPC decrypt
    let encrypted = wallet
        .encrypt(EncryptArgs {
            plaintext: state_data.as_bytes().to_vec(),
            protocol_id: protocol.clone(),
            key_id: "session-token".to_string(),
            counterparty: Some(Counterparty::Self_),
        })
        .unwrap();

    let mpc_sym = mpc_derive_symmetric_key(
        &Counterparty::Self_,
        &root_pubkey,
        &shares,
        &protocol,
        "session-token",
    );
    let decrypted = mpc_sym.decrypt(&encrypted.ciphertext).unwrap();
    assert_eq!(std::str::from_utf8(&decrypted).unwrap(), state_data);
    println!("  PASS: wallet→MPC decrypt OK");

    // MPC encrypt → Wallet decrypt
    let mpc_ciphertext = mpc_sym
        .encrypt(state_data.as_bytes())
        .unwrap();
    let wallet_decrypted = wallet
        .decrypt(DecryptArgs {
            ciphertext: mpc_ciphertext,
            protocol_id: protocol,
            key_id: "session-token".to_string(),
            counterparty: Some(Counterparty::Self_),
        })
        .unwrap();
    assert_eq!(
        std::str::from_utf8(&wallet_decrypted.plaintext).unwrap(),
        state_data
    );
    println!("  PASS: MPC→wallet decrypt OK");
}

/// Test 6: Protocol [2, "worm conversation"] — conversation log encryption.
#[test]
fn test_protocol_worm_conversation() {
    println!("\n=== Test 6: Protocol [2, \"worm conversation\"] ===");

    let root_key = PrivateKey::from_bytes(&ROOT_KEY_BYTES).unwrap();
    let root_pubkey = root_key.public_key();
    let shares = generate_shares(&root_key);
    let wallet = ProtoWallet::new(Some(root_key));

    let protocol = Protocol::new(SecurityLevel::Counterparty, "worm conversation");
    let conversation = "User: What is BSV?\nAgent: BSV is Bitcoin Satoshi Vision...";

    // Wallet encrypt → MPC decrypt
    let encrypted = wallet
        .encrypt(EncryptArgs {
            plaintext: conversation.as_bytes().to_vec(),
            protocol_id: protocol.clone(),
            key_id: "conv-2024-03-21-001".to_string(),
            counterparty: Some(Counterparty::Self_),
        })
        .unwrap();

    let mpc_sym = mpc_derive_symmetric_key(
        &Counterparty::Self_,
        &root_pubkey,
        &shares,
        &protocol,
        "conv-2024-03-21-001",
    );
    let decrypted = mpc_sym.decrypt(&encrypted.ciphertext).unwrap();
    assert_eq!(std::str::from_utf8(&decrypted).unwrap(), conversation);
    println!("  PASS: wallet→MPC decrypt OK");

    // MPC encrypt → Wallet decrypt
    let mpc_ciphertext = mpc_sym
        .encrypt(conversation.as_bytes())
        .unwrap();
    let wallet_decrypted = wallet
        .decrypt(DecryptArgs {
            ciphertext: mpc_ciphertext,
            protocol_id: protocol,
            key_id: "conv-2024-03-21-001".to_string(),
            counterparty: Some(Counterparty::Self_),
        })
        .unwrap();
    assert_eq!(
        std::str::from_utf8(&wallet_decrypted.plaintext).unwrap(),
        conversation
    );
    println!("  PASS: MPC→wallet decrypt OK");
}

/// Test 7: Counterparty "self" — the common case for agent self-encryption.
/// Verifies that Self_ counterparty works across all three protocols.
#[test]
fn test_counterparty_self_all_protocols() {
    println!("\n=== Test 7: Counterparty Self_ across all protocols ===");

    let root_key = PrivateKey::from_bytes(&ROOT_KEY_BYTES).unwrap();
    let root_pubkey = root_key.public_key();
    let shares = generate_shares(&root_key);
    let deriver = KeyDeriver::new(Some(root_key));

    let protocols = vec![
        ("worm memory", "knowledge"),
        ("worm state", "session-token"),
        ("worm conversation", "conv-id-1"),
    ];

    for (proto_name, key_id) in &protocols {
        let protocol = Protocol::new(SecurityLevel::Counterparty, *proto_name);

        let wallet_sym = deriver
            .derive_symmetric_key(&protocol, key_id, &Counterparty::Self_)
            .unwrap();
        let mpc_sym = mpc_derive_symmetric_key(
            &Counterparty::Self_,
            &root_pubkey,
            &shares,
            &protocol,
            key_id,
        );

        assert_eq!(
            wallet_sym.as_bytes(),
            mpc_sym.as_bytes(),
            "Key mismatch for protocol '{}', key_id '{}'",
            proto_name,
            key_id
        );
        println!(
            "  PASS: [2, \"{}\"] key_id='{}' — keys match",
            proto_name, key_id
        );
    }
}

/// Test 8: Large payload — verify encryption works with non-trivial data sizes.
#[test]
fn test_large_payload() {
    println!("\n=== Test 8: Large payload (10KB) ===");

    let root_key = PrivateKey::from_bytes(&ROOT_KEY_BYTES).unwrap();
    let root_pubkey = root_key.public_key();
    let shares = generate_shares(&root_key);
    let wallet = ProtoWallet::new(Some(root_key));

    let protocol = Protocol::new(SecurityLevel::Counterparty, "worm memory");

    // 10KB payload simulating a large memory block
    let large_data: Vec<u8> = (0..10240).map(|i| (i % 256) as u8).collect();

    let encrypted = wallet
        .encrypt(EncryptArgs {
            plaintext: large_data.clone(),
            protocol_id: protocol.clone(),
            key_id: "large-block".to_string(),
            counterparty: Some(Counterparty::Self_),
        })
        .unwrap();

    println!(
        "  Payload: {} bytes → ciphertext: {} bytes",
        large_data.len(),
        encrypted.ciphertext.len()
    );

    let mpc_sym = mpc_derive_symmetric_key(
        &Counterparty::Self_,
        &root_pubkey,
        &shares,
        &protocol,
        "large-block",
    );
    let decrypted = mpc_sym.decrypt(&encrypted.ciphertext).unwrap();

    assert_eq!(decrypted, large_data, "Large payload round-trip failed");
    println!("  PASS: 10KB payload — wallet→MPC round-trip OK");
}

/// Test 9: Empty plaintext edge case.
#[test]
fn test_empty_plaintext() {
    println!("\n=== Test 9: Empty plaintext ===");

    let root_key = PrivateKey::from_bytes(&ROOT_KEY_BYTES).unwrap();
    let root_pubkey = root_key.public_key();
    let shares = generate_shares(&root_key);
    let wallet = ProtoWallet::new(Some(root_key));

    let protocol = Protocol::new(SecurityLevel::Counterparty, "worm memory");

    let encrypted = wallet
        .encrypt(EncryptArgs {
            plaintext: vec![],
            protocol_id: protocol.clone(),
            key_id: "empty".to_string(),
            counterparty: Some(Counterparty::Self_),
        })
        .unwrap();

    let mpc_sym = mpc_derive_symmetric_key(
        &Counterparty::Self_,
        &root_pubkey,
        &shares,
        &protocol,
        "empty",
    );
    let decrypted = mpc_sym.decrypt(&encrypted.ciphertext).unwrap();

    assert!(decrypted.is_empty(), "Empty plaintext should decrypt to empty");
    println!("  PASS: Empty plaintext round-trip OK");
}

/// Test 10: Bidirectional — encrypt with one, decrypt with other, for every
/// combination of (wallet, MPC) x (encrypt, decrypt) x (3 protocols).
#[test]
fn test_bidirectional_all_protocols() {
    println!("\n=== Test 10: Bidirectional matrix (2 x 2 x 3) ===");

    let root_key = PrivateKey::from_bytes(&ROOT_KEY_BYTES).unwrap();
    let root_pubkey = root_key.public_key();
    let shares = generate_shares(&root_key);
    let wallet = ProtoWallet::new(Some(root_key));

    let protocols = vec![
        ("worm memory", "test-key"),
        ("worm state", "test-key"),
        ("worm conversation", "test-key"),
    ];

    let plaintext = b"Cross-compatibility test payload";

    for (proto_name, key_id) in &protocols {
        let protocol = Protocol::new(SecurityLevel::Counterparty, *proto_name);
        let mpc_sym = mpc_derive_symmetric_key(
            &Counterparty::Self_,
            &root_pubkey,
            &shares,
            &protocol,
            key_id,
        );

        // Direction 1: Wallet → MPC
        let wallet_ct = wallet
            .encrypt(EncryptArgs {
                plaintext: plaintext.to_vec(),
                protocol_id: protocol.clone(),
                key_id: key_id.to_string(),
                counterparty: Some(Counterparty::Self_),
            })
            .unwrap();
        let mpc_pt = mpc_sym.decrypt(&wallet_ct.ciphertext).unwrap();
        assert_eq!(&mpc_pt[..], &plaintext[..]);

        // Direction 2: MPC → Wallet
        let mpc_ct = mpc_sym.encrypt(plaintext).unwrap();
        let wallet_pt = wallet
            .decrypt(DecryptArgs {
                ciphertext: mpc_ct,
                protocol_id: protocol,
                key_id: key_id.to_string(),
                counterparty: Some(Counterparty::Self_),
            })
            .unwrap();
        assert_eq!(&wallet_pt.plaintext[..], &plaintext[..]);

        println!("  PASS: [2, \"{}\"] — both directions OK", proto_name);
    }
}

/// Summary — print architecture implications for MPC proxy encrypt/decrypt.
#[test]
fn test_summary() {
    println!("\n========================================");
    println!("  POC 9 ARCHITECTURE SUMMARY");
    println!("========================================");
    println!();
    println!("  MPC symmetric key derivation algorithm:");
    println!("    Round 1: base_ecdh = counterparty_key * root_priv  (partial ECDH)");
    println!("    Local:   hmac = HMAC-SHA256(compressed(base_ecdh), invoice)");
    println!("    Local:   child_pub = counterparty_key + G * hmac");
    println!("    Round 2: root_times_child = root_priv * child_pub  (partial ECDH)");
    println!("    Local:   hmac_times_child = child_pub * hmac");
    println!("    Local:   sym_point = root_times_child + hmac_times_child");
    println!("    Local:   sym_key = SymmetricKey::from_bytes(sym_point.x())");
    println!();
    println!("  KSS round-trips per encrypt/decrypt: 2");
    println!("    (Can be parallelized if KSS supports batch partial ECDH)");
    println!();
    println!("  Protocol compatibility verified:");
    println!("    [2, \"worm memory\"]       — agent memory encryption");
    println!("    [2, \"worm state\"]        — state token encryption");
    println!("    [2, \"worm conversation\"] — conversation log encryption");
    println!();
    println!("  Migration path: CONFIRMED");
    println!("    Existing wallet-encrypted data is readable by MPC shares");
    println!("    MPC-encrypted data is readable by normal wallet");
    println!("    Zero data loss during wallet → MPC proxy transition");
    println!("========================================");
}
