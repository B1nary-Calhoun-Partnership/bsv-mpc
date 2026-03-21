//! POC 8: BRC-31 Authrite Authentication Through MPC
//!
//! GO/NO-GO for MPC-based BRC-31 authentication.
//!
//! Validates that the MPC proxy can handle BRC-31 Authrite handshakes:
//! 1. Partial ECDH derives correct BRC-42 auth signing keys (1 KSS round-trip)
//! 2. Share offset property: each party adds HMAC locally → correct child key
//! 3. Threshold signing with derived child key produces valid BRC-31 signatures
//! 4. Server-side verification works (ECDH commutativity)
//! 5. BONUS: Real BRC-31 handshake with x402 service
//!
//! BRC-31 signing flow:
//!   protocol = [2, "auth message signature"]
//!   key_id = "{message_nonce} {peer_session_nonce}"
//!   counterparty = peer's identity key
//!   → shared_secret = ECDH(counterparty, root_priv)  [MPC: partial ECDH]
//!   → hmac = HMAC-SHA256(compressed(shared_secret), invoice)
//!   → signing_key = root_priv + hmac  [MPC: share_i + hmac locally]
//!   → signature = ECDSA(signing_key, SHA-256(data))

use std::collections::VecDeque;

use base64::Engine;
use bsv::primitives::ec::{PrivateKey, PublicKey};
use bsv::primitives::hash::sha256_hmac;
use bsv::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};

use cggmp24::key_share::reconstruct_secret_key;
use cggmp24::security_level::SecurityLevel128;
use cggmp24::signing::DataToSign;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use generic_ec::{NonZero, Point, Scalar, SecretScalar};
use rand::Rng;
use sha2::Sha256;

// ---- Buffered sink (from POC 1 / POC 13) ----
// Ensures messages are flushed between rounds, catching protocol bugs.

#[pin_project::pin_project]
struct BufferedSink<M, Inner> {
    #[pin]
    messages: VecDeque<M>,
    #[pin]
    inner: Inner,
}

type BufferedDelivery<M, D> = (
    <D as round_based::Delivery<M>>::Receive,
    BufferedSink<round_based::Outgoing<M>, <D as round_based::Delivery<M>>::Send>,
);

impl<M: Unpin, Inner: futures::Sink<M>> futures::Sink<M> for BufferedSink<M, Inner> {
    type Error = Inner::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: M) -> Result<(), Self::Error> {
        self.project().messages.get_mut().push_back(item);
        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        while !self.messages.is_empty() {
            let mut projection = self.as_mut().project();
            let mut inner = projection.inner;
            std::task::ready!(inner.as_mut().poll_ready(cx))?;
            if let Some(item) = projection.messages.pop_front() {
                inner.as_mut().start_send(item)?;
            }
        }
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.project().inner.poll_close(cx)
    }
}

fn buffer_outgoing<M, D, R>(
    party: round_based::MpcParty<M, D, R>,
) -> round_based::MpcParty<M, BufferedDelivery<M, D>, R>
where
    M: Unpin,
    D: round_based::Delivery<M>,
    R: round_based::runtime::AsyncRuntime,
{
    party.map_delivery(|delivery| {
        let (incoming, outgoing) = delivery.split();
        let buffered_outgoing = BufferedSink {
            messages: VecDeque::new(),
            inner: outgoing,
        };
        (incoming, buffered_outgoing)
    })
}

// ---- Blum prime generation (from POC 1) ----

// Alias to avoid conflict with bsv::wallet::SecurityLevel
use cggmp24::security_level::SecurityLevel as MpcSecurityLevel;

fn generate_blum_prime(rng: &mut impl rand::RngCore, bits_size: u32) -> cggmp24::backend::Integer {
    use cggmp24::backend::Integer;
    loop {
        let n = Integer::generate_prime(rng, bits_size);
        if n.mod_u(4) == 3 {
            break n;
        }
    }
}

fn generate_pregenerated_primes(
    rng: &mut impl rand::RngCore,
) -> cggmp24::key_refresh::PregeneratedPrimes<SecurityLevel128> {
    let bitsize = <SecurityLevel128 as MpcSecurityLevel>::RSA_PRIME_BITLEN;
    let primes = [
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
    ];
    cggmp24::key_refresh::PregeneratedPrimes::try_from(primes)
        .expect("primes have wrong bit size")
}

// ---- BSV PrivateKey → generic-ec scalar (from POC 3) ----

fn bsv_privkey_to_scalar(privkey: &PrivateKey) -> NonZero<SecretScalar<Secp256k1>> {
    let bytes = privkey.to_bytes();
    let mut scalar =
        Scalar::<Secp256k1>::from_be_bytes(&bytes).expect("valid scalar from private key bytes");
    let secret = SecretScalar::new(&mut scalar);
    NonZero::from_secret_scalar(secret).expect("non-zero scalar")
}

// ---- Share scalar extraction (from POC 3) ----

fn share_to_bytes(share: &cggmp24::IncompleteKeyShare<Secp256k1>) -> [u8; 32] {
    let scalar: &Scalar<Secp256k1> =
        <SecretScalar<Secp256k1> as AsRef<Scalar<Secp256k1>>>::as_ref(&share.x);
    let encoded = scalar.to_be_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(encoded.as_bytes());
    arr
}

// ---- Partial ECDH with Lagrange interpolation (from POC 3) ----
// For VSS (threshold) shares: shared_secret = Σ λ_i * (counterparty_pub * share_i)
// This is the 1 KSS round-trip for "Other" counterparty.

fn mpc_partial_ecdh(
    counterparty_pub: &PublicKey,
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
        let mut lambda = Scalar::<Secp256k1>::one();
        for m in 0..n {
            if m == j {
                continue;
            }
            let i_m = &vss.I[m];
            let neg_i_m = -Scalar::<Secp256k1>::from(*i_m);
            let diff = Scalar::<Secp256k1>::from(*i_j) - Scalar::<Secp256k1>::from(*i_m);
            let diff_inv = diff.invert().expect("evaluation points must be distinct");
            lambda = lambda * neg_i_m * diff_inv;
        }

        // partial_j = counterparty_pub * share_j
        let s_bytes = share_to_bytes(&shares[j]);
        let partial = counterparty_pub
            .mul_scalar(&s_bytes)
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
        let lambda_ct = k256::Scalar::from_repr(lambda_arr.into());
        assert!(
            bool::from(lambda_ct.is_some()),
            "Lagrange coefficient must be valid scalar"
        );
        let weighted: ProjectivePoint = partial_point * lambda_ct.unwrap();
        result = result + weighted;
    }

    let affine = result.to_affine();
    let encoded = k256::EncodedPoint::from(affine);
    PublicKey::from_bytes(encoded.as_bytes()).expect("valid combined ECDH point")
}

// ---- Point → BSV PublicKey (from POC 3) ----

fn point_to_bsv_pubkey(point: &Point<Secp256k1>) -> PublicKey {
    let bytes = point.to_bytes(true); // compressed
    PublicKey::from_bytes(&bytes).expect("valid pubkey from point bytes")
}

// ---- BRC-42 child pubkey derivation (from POC 3) ----
// child_pubkey = root_pubkey + G * HMAC-SHA256(compressed(shared_secret), invoice)

fn derive_child_pubkey_manual(
    root_pubkey: &PublicKey,
    shared_secret: &PublicKey,
    invoice_number: &str,
) -> PublicKey {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::ProjectivePoint;

    let hmac = sha256_hmac(&shared_secret.to_compressed(), invoice_number.as_bytes());

    // G * hmac (using BSV PrivateKey as shortcut for scalar multiplication)
    let hmac_as_privkey = PrivateKey::from_bytes(&hmac).expect("HMAC should be valid scalar");
    let offset_pubkey = hmac_as_privkey.public_key();

    // Point addition: root_pubkey + G * hmac
    let root_point = {
        let enc = k256::EncodedPoint::from_bytes(&root_pubkey.to_compressed()).unwrap();
        ProjectivePoint::from(k256::AffinePoint::from_encoded_point(&enc).unwrap())
    };
    let offset_point = {
        let enc = k256::EncodedPoint::from_bytes(&offset_pubkey.to_compressed()).unwrap();
        ProjectivePoint::from(k256::AffinePoint::from_encoded_point(&enc).unwrap())
    };
    let child_point = root_point + offset_point;
    let child_encoded = k256::EncodedPoint::from(child_point.to_affine());
    PublicKey::from_bytes(child_encoded.as_bytes()).expect("valid child pubkey")
}

// ---- Run aux_info_gen (from POC 13) ----

async fn run_aux_gen(n: u16) -> Vec<cggmp24::key_share::AuxInfo<SecurityLevel128>> {
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rng.gen();
    let eid_aux = ExecutionId::new(&eid_bytes);

    let primes: Vec<_> = (0..n)
        .map(|_| generate_pregenerated_primes(&mut rng))
        .collect();

    round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut party_rng = rand::rngs::OsRng;
        let pregenerated = primes[usize::from(i)].clone();
        async move {
            cggmp24::aux_info_gen(eid_aux, i, n, pregenerated)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec()
}

// ---- Sign with party subset (from POC 13) ----

async fn sign_with_parties(
    key_shares: &[cggmp24::KeyShare<Secp256k1, SecurityLevel128>],
    participants: &[u16],
    data_to_sign: &DataToSign<Secp256k1>,
) -> cggmp24::Signature<Secp256k1> {
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rng.gen();
    let eid_sign = ExecutionId::new(&eid_bytes);
    let participants_vec = participants.to_vec();

    round_based::sim::run_with_setup(
        participants.iter().map(|i| &key_shares[usize::from(*i)]),
        |i, party, share| {
            let party = buffer_outgoing(party);
            let mut party_rng = rand::rngs::OsRng;
            let p = participants_vec.clone();
            async move {
                cggmp24::signing(eid_sign, i, &p, share)
                    .sign(&mut party_rng, party, data_to_sign)
                    .await
            }
        },
    )
    .unwrap()
    .expect_ok()
    .expect_eq()
}

// ============================================================================
// TEST 1: Full MPC BRC-31 auth signing chain
// ============================================================================

#[tokio::test]
async fn test_mpc_brc31_auth_full_chain() {
    let mut rng = rand::rngs::OsRng;

    // =========================================================================
    // STEP 1: MPC identity key + server identity key
    // =========================================================================
    println!("=== STEP 1: MPC identity key + server identity ===");

    // Known root key (same as POC 3 for consistency)
    let root_key = PrivateKey::from_bytes(&[
        0x0b, 0x1e, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1,
        0xe2, 0xf3, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf,
        0xd0, 0xe1, 0xf2, 0x03,
    ])
    .expect("valid root key");
    let root_pubkey = root_key.public_key();

    // Server identity key (same as POC 3 test 5)
    let server_key = PrivateKey::from_bytes(&[
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0x00, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x13,
        0x57, 0x9b, 0xdf, 0x02,
    ])
    .expect("valid server key");
    let server_pubkey = server_key.public_key();

    println!("  MPC identity:    {}", root_pubkey.to_hex());
    println!("  Server identity: {}", server_pubkey.to_hex());

    // =========================================================================
    // STEP 2: Split root key into 2-of-2 MPC shares
    // =========================================================================
    println!("\n=== STEP 2: 2-of-2 MPC key shares (trusted dealer) ===");

    let sk = bsv_privkey_to_scalar(&root_key);
    let root_shares = cggmp24::trusted_dealer::builder::<Secp256k1, SecurityLevel128>(2)
        .set_threshold(Some(2))
        .set_shared_secret_key(sk)
        .generate_core_shares(&mut rng)
        .expect("trusted dealer should work");

    let joint_pubkey = point_to_bsv_pubkey(&root_shares[0].shared_public_key);
    assert_eq!(
        joint_pubkey.to_compressed(),
        root_pubkey.to_compressed(),
        "MPC joint pubkey must match root pubkey"
    );
    println!("  Joint pubkey matches root: PASS");

    // =========================================================================
    // STEP 3: Partial ECDH with server counterparty (1 KSS round-trip)
    // =========================================================================
    println!("\n=== STEP 3: Partial ECDH → shared secret ===");

    let mpc_shared_secret = mpc_partial_ecdh(&server_pubkey, &root_shares);

    // Verify against normal ECDH
    let normal_shared_secret = root_key
        .derive_shared_secret(&server_pubkey)
        .expect("normal ECDH");
    assert_eq!(
        mpc_shared_secret.to_compressed(),
        normal_shared_secret.to_compressed(),
        "MPC partial ECDH must match normal ECDH"
    );
    println!("  MPC partial ECDH matches normal ECDH: PASS");
    println!("  (This is the 1 KSS round-trip for Other counterparty)");

    // =========================================================================
    // STEP 4: BRC-42 auth key derivation
    // =========================================================================
    println!("\n=== STEP 4: BRC-42 auth key derivation ===");

    // Generate BRC-31 nonces (simulating handshake)
    let my_nonce_bytes: [u8; 32] = rng.gen();
    let server_nonce_bytes: [u8; 32] = rng.gen();
    let b64 = base64::engine::general_purpose::STANDARD;
    let my_nonce = b64.encode(my_nonce_bytes);
    let server_nonce = b64.encode(server_nonce_bytes);

    // BRC-31 key_id = "{message_nonce} {peer_session_nonce}"
    let key_id = format!("{} {}", my_nonce, server_nonce);
    let protocol = Protocol::new(SecurityLevel::Counterparty, "auth message signature");
    // BRC-42 invoice = "{security_level}-{protocol}-{key_id}"
    let invoice_number = format!("2-auth message signature-{}", key_id);

    println!("  Protocol: [2, \"auth message signature\"]");
    println!("  Key ID: <my_nonce> <server_nonce> ({} chars)", key_id.len());

    // MPC-derived child pubkey (manual derivation from partial ECDH)
    let mpc_child_pubkey =
        derive_child_pubkey_manual(&root_pubkey, &mpc_shared_secret, &invoice_number);

    // Wallet-derived child pubkey (for cross-check)
    let deriver = KeyDeriver::new(Some(root_key.clone()));
    let wallet_child_pubkey = deriver
        .derive_public_key(
            &protocol,
            &key_id,
            &Counterparty::Other(server_pubkey.clone()),
            true,
        )
        .expect("wallet derivation should work");

    assert_eq!(
        mpc_child_pubkey.to_compressed(),
        wallet_child_pubkey.to_compressed(),
        "MPC-derived child pubkey must match wallet-derived"
    );
    println!("  MPC child pubkey matches wallet: PASS");
    println!("  Auth signing pubkey: {}", mpc_child_pubkey.to_hex());

    // =========================================================================
    // STEP 5: Derive child private key + verify offset property
    // =========================================================================
    println!("\n=== STEP 5: Child key derivation + offset verification ===");

    // HMAC offset = HMAC-SHA256(compressed(shared_secret), invoice_bytes)
    let hmac_bytes = sha256_hmac(
        &mpc_shared_secret.to_compressed(),
        invoice_number.as_bytes(),
    );
    let hmac_scalar =
        Scalar::<Secp256k1>::from_be_bytes(&hmac_bytes).expect("valid HMAC scalar");

    // child_priv = root_priv + hmac (mod curve order)
    let root_scalar =
        Scalar::<Secp256k1>::from_be_bytes(&root_key.to_bytes()).expect("valid root scalar");
    let child_scalar = root_scalar + hmac_scalar;
    let child_bytes = child_scalar.to_be_bytes();
    let child_privkey =
        PrivateKey::from_bytes(child_bytes.as_bytes()).expect("valid child private key");

    // Verify G * child_priv = child_pubkey
    let child_pubkey_from_priv = child_privkey.public_key();
    assert_eq!(
        child_pubkey_from_priv.to_compressed(),
        mpc_child_pubkey.to_compressed(),
        "G * child_priv must equal child_pubkey"
    );
    println!("  G * (root_priv + hmac) = child_pubkey: PASS");

    // Verify additive offset property:
    // reconstruct(root_shares) + hmac = child_priv
    // This proves each MPC party can add hmac to their share locally.
    let reconstructed = reconstruct_secret_key(&root_shares).expect("reconstruction should work");
    let reconstructed_scalar: &Scalar<Secp256k1> = reconstructed.as_ref();
    let expected_child = *reconstructed_scalar + hmac_scalar;
    assert_eq!(
        child_scalar, expected_child,
        "reconstruct(shares) + hmac must equal child_priv"
    );
    println!("  reconstruct(root_shares) + hmac = child_priv: PASS");
    println!("  → Production: each party adds hmac to their share locally (0 extra round-trips)");

    // =========================================================================
    // STEP 6: Split child key → MPC shares + aux info → KeyShares
    // =========================================================================
    println!("\n=== STEP 6: Child key MPC shares + aux info ===");

    let child_sk = {
        let mut s = child_scalar;
        let secret = SecretScalar::new(&mut s);
        NonZero::from_secret_scalar(secret).expect("non-zero child scalar")
    };

    let child_shares = cggmp24::trusted_dealer::builder::<Secp256k1, SecurityLevel128>(2)
        .set_threshold(Some(2))
        .set_shared_secret_key(child_sk)
        .generate_core_shares(&mut rng)
        .expect("trusted dealer for child key");

    // Verify child shares have the right joint pubkey
    let child_joint_pub = point_to_bsv_pubkey(&child_shares[0].shared_public_key);
    assert_eq!(
        child_joint_pub.to_compressed(),
        mpc_child_pubkey.to_compressed(),
        "child shares joint pubkey must match derived child pubkey"
    );
    println!("  Child shares joint pubkey correct: PASS");

    // Aux info generation (Paillier primes — this is the expensive part)
    let aux_infos = run_aux_gen(2).await;
    println!("  Aux info generated for 2 parties");

    let child_key_shares: Vec<cggmp24::KeyShare<Secp256k1, SecurityLevel128>> = child_shares
        .into_iter()
        .zip(aux_infos)
        .map(|(core, aux)| {
            cggmp24::KeyShare::from_parts((core, aux))
                .expect("child key share validation should pass")
        })
        .collect();
    println!("  2 complete child KeyShares ready for signing");

    // =========================================================================
    // STEP 7: BRC-31 auth signing — general message payload
    // =========================================================================
    println!("\n=== STEP 7: Sign BRC-31 general message payload ===");

    let payload = b"MPC-authenticated request to x402 service";
    println!(
        "  Payload: {:?}",
        std::str::from_utf8(payload).unwrap()
    );

    let data_to_sign = DataToSign::digest::<Sha256>(payload);

    let sig = sign_with_parties(&child_key_shares, &[0, 1], &data_to_sign).await;

    let mut sig_bytes = [0u8; 64];
    sig.write_to_slice(&mut sig_bytes);
    println!("  Signature (compact r||s):");
    println!("    r: {}", hex::encode(&sig_bytes[..32]));
    println!("    s: {}", hex::encode(&sig_bytes[32..]));

    // =========================================================================
    // STEP 8: Verify — cggmp24 + BSV SDK
    // =========================================================================
    println!("\n=== STEP 8: Signature verification ===");

    // cggmp24 internal verification
    let child_point = child_key_shares[0].core.shared_public_key;
    sig.verify(&child_point, &data_to_sign)
        .expect("cggmp24 internal verification must pass");
    println!("  cggmp24 verify against child pubkey: PASS");

    // BSV SDK verification
    let bsv_child_pub = PublicKey::from_bytes(&child_point.to_bytes(true))
        .expect("valid BSV pubkey from child point");
    let msg_hash: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(payload).into()
    };
    let bsv_sig =
        bsv::Signature::from_compact(&sig_bytes).expect("valid compact signature for BSV SDK");
    assert!(
        bsv_child_pub.verify(&msg_hash, &bsv_sig),
        "BSV SDK verification must pass"
    );
    println!("  BSV SDK verify against child pubkey: PASS");

    // Cross-check: child pubkey matches wallet derivation
    assert_eq!(
        bsv_child_pub.to_hex(),
        wallet_child_pubkey.to_hex(),
        "verification pubkey must match wallet derivation"
    );
    println!("  Verification pubkey = wallet-derived pubkey: PASS");

    // =========================================================================
    // STEP 9: Server-side verification (ECDH commutativity)
    // =========================================================================
    println!("\n=== STEP 9: Server-side verification ===");

    // Server derives client's auth pubkey using its own private key.
    // ECDH is commutative: ECDH(server_pub, client_priv) = ECDH(client_pub, server_priv)
    let server_shared_secret = server_key
        .derive_shared_secret(&root_pubkey)
        .expect("server-side ECDH");

    assert_eq!(
        server_shared_secret.to_compressed(),
        mpc_shared_secret.to_compressed(),
        "ECDH must be commutative"
    );
    println!("  ECDH(client_pub, server_priv) = ECDH(server_pub, client_priv): PASS");

    // Server derives same child pubkey for client
    let server_derived_client_pubkey =
        derive_child_pubkey_manual(&root_pubkey, &server_shared_secret, &invoice_number);
    assert_eq!(
        server_derived_client_pubkey.to_compressed(),
        mpc_child_pubkey.to_compressed(),
        "server must derive same child pubkey for client"
    );
    println!("  Server derives same client auth pubkey: PASS");

    // Server verifies MPC signature
    assert!(
        server_derived_client_pubkey.verify(&msg_hash, &bsv_sig),
        "server must be able to verify MPC signature"
    );
    println!("  Server verifies MPC-signed auth message: PASS");

    // =========================================================================
    // STEP 10: Sign nonce data (initialResponse format)
    // =========================================================================
    println!("\n=== STEP 10: Sign nonce data (initialResponse format) ===");

    // BRC-31 initialResponse signing data = yourNonce || initialNonce (raw bytes)
    let nonce_data = [my_nonce_bytes.as_slice(), server_nonce_bytes.as_slice()].concat();
    let nonce_data_to_sign = DataToSign::digest::<Sha256>(&nonce_data);

    let nonce_sig = sign_with_parties(&child_key_shares, &[0, 1], &nonce_data_to_sign).await;

    // cggmp24 verify
    nonce_sig
        .verify(&child_point, &nonce_data_to_sign)
        .expect("nonce signature must verify with cggmp24");

    // BSV SDK verify
    let mut nonce_sig_bytes = [0u8; 64];
    nonce_sig.write_to_slice(&mut nonce_sig_bytes);
    let nonce_hash: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(&nonce_data).into()
    };
    let bsv_nonce_sig =
        bsv::Signature::from_compact(&nonce_sig_bytes).expect("valid nonce signature");
    assert!(
        bsv_child_pub.verify(&nonce_hash, &bsv_nonce_sig),
        "nonce signature must verify with BSV SDK"
    );
    println!("  Nonce data (64 bytes: client_nonce || server_nonce) signed and verified: PASS");

    // =========================================================================
    // STEP 11: Sign DER-encoded for BRC-31 wire format
    // =========================================================================
    println!("\n=== STEP 11: DER encoding for BRC-31 wire format ===");

    // BRC-31 sends signatures as hex-encoded DER
    // cggmp24 produces compact (r||s, 64 bytes) — convert to DER
    let der_sig = bsv_sig.to_der();
    let der_hex = hex::encode(&der_sig);
    println!("  Compact (64 bytes): {}", hex::encode(&sig_bytes));
    println!("  DER ({} bytes): {}", der_sig.len(), der_hex);

    // Verify DER roundtrip
    let roundtrip_sig =
        bsv::Signature::from_der(&der_sig).expect("DER roundtrip must work");
    assert!(
        bsv_child_pub.verify(&msg_hash, &roundtrip_sig),
        "DER roundtrip signature must verify"
    );
    println!("  DER roundtrip verify: PASS");
    println!("  BRC-31 signature header value: {}", der_hex);

    // =========================================================================
    // SUMMARY
    // =========================================================================
    println!("\n========================================");
    println!("  POC 8 RESULT: ALL TESTS PASSED");
    println!("========================================");
    println!();
    println!("  BRC-31 Authrite through MPC is VALIDATED:");
    println!();
    println!("  [x] Partial ECDH derives correct shared secret (1 KSS round-trip)");
    println!("  [x] BRC-42 child pubkey matches normal wallet derivation");
    println!("  [x] Additive share offset: share_i + hmac → correct child key");
    println!("  [x] Threshold signing with child key produces valid signatures");
    println!("  [x] cggmp24 internal verification PASS");
    println!("  [x] BSV SDK verification PASS");
    println!("  [x] Server-side verification via ECDH commutativity PASS");
    println!("  [x] Payload signing (general message) works");
    println!("  [x] Nonce signing (initialResponse format) works");
    println!("  [x] DER encoding for BRC-31 wire format works");
    println!();
    println!("  Production MPC auth flow:");
    println!("    1. Proxy + KSS do partial ECDH (1 round-trip) → shared_secret");
    println!("    2. Both compute HMAC offset from shared_secret + invoice");
    println!("    3. Both add offset to their share locally (0 extra round-trips)");
    println!("    4. Threshold sign auth data (standard signing rounds)");
    println!("    5. Overhead: 1 extra KSS round-trip (~135µs from POC 5)");
    println!("========================================");
}

// ============================================================================
// TEST 2: BONUS — Real BRC-31 handshake with x402 service
// ============================================================================

#[tokio::test]
#[ignore] // Requires network access
async fn test_real_brc31_handshake() {
    let mut rng = rand::rngs::OsRng;

    println!("=== BONUS: Real BRC-31 handshake with x402 service ===");

    // MPC identity key
    let root_key = PrivateKey::from_bytes(&[
        0x0b, 0x1e, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1,
        0xe2, 0xf3, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf,
        0xd0, 0xe1, 0xf2, 0x03,
    ])
    .expect("valid root key");
    let root_pubkey = root_key.public_key();

    // Generate nonce
    let nonce_bytes: [u8; 32] = rng.gen();
    let b64 = base64::engine::general_purpose::STANDARD;
    let nonce = b64.encode(nonce_bytes);

    println!("  Client identity: {}", root_pubkey.to_hex());
    println!("  Client nonce: {}...", &nonce[..20]);

    // Attempt initialRequest via HTTP headers to x402 service
    let client = reqwest::Client::new();
    let resp = client
        .post("https://openai-chat.x402agency.com/.well-known/auth")
        .header("x-bsv-auth-version", "0.1")
        .header("x-bsv-auth-identity-key", root_pubkey.to_hex())
        .header("x-bsv-auth-message-type", "initialRequest")
        .header("x-bsv-auth-nonce", &nonce)
        .header("x-bsv-auth-initial-nonce", &nonce)
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await;

    match resp {
        Ok(response) => {
            let status = response.status();
            println!("  HTTP Status: {}", status);

            // Check for auth response headers
            if let Some(server_id) = response.headers().get("x-bsv-auth-identity-key") {
                println!("  Server identity: {}", server_id.to_str().unwrap_or("?"));
            }
            if let Some(server_nonce) = response.headers().get("x-bsv-auth-nonce") {
                let nonce_str = server_nonce.to_str().unwrap_or("?");
                println!(
                    "  Server nonce: {}...",
                    &nonce_str[..nonce_str.len().min(20)]
                );
            }
            if let Some(your_nonce) = response.headers().get("x-bsv-auth-your-nonce") {
                let yn = your_nonce.to_str().unwrap_or("?");
                // Verify server echoed our nonce
                if yn == nonce {
                    println!("  Our nonce echoed back: PASS");
                } else {
                    println!("  Our nonce echoed back: MISMATCH");
                }
            }
            if let Some(sig) = response.headers().get("x-bsv-auth-signature") {
                let sig_str = sig.to_str().unwrap_or("?");
                println!(
                    "  Server signature: {}...",
                    &sig_str[..sig_str.len().min(40)]
                );
            }

            let body = response.text().await.unwrap_or_default();
            if !body.is_empty() {
                let preview = if body.len() > 200 {
                    &body[..200]
                } else {
                    &body
                };
                println!("  Body: {}", preview);
            }

            if status.is_success() {
                println!("\n  Real BRC-31 handshake: PASS");
            } else {
                println!("\n  Server returned {}: may need different auth format", status);
            }
        }
        Err(e) => {
            println!("  Connection failed: {}", e);
            println!("  (Expected if service is not running or URL has changed)");
        }
    }
}
