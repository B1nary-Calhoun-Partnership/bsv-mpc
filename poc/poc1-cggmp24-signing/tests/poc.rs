//! POC 1: cggmp24 2-party DKG + threshold signing on secp256k1
//!
//! GO/NO-GO for the entire bsv-mpc project.
//!
//! Validates:
//! 1. cggmp24 API works for 2-of-2 DKG on secp256k1
//! 2. Threshold signing produces valid ECDSA signatures
//! 3. bsv SDK's PublicKey::verify() accepts MPC-generated signatures
//! 4. Presigning + 1-round online signing works

use std::collections::VecDeque;

use cggmp24::security_level::SecurityLevel128;
use cggmp24::signing::DataToSign;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use generic_ec::Point;
use rand::Rng;
use sha2::Sha256;

// ---- Buffered sink (from cggmp24 test infra) ----
// Ensures messages are flushed between rounds, catching bugs where
// protocols forget to flush.

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

// ---- Generate blum primes (faster than safe primes, correct for testing) ----

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
    let bitsize = SecurityLevel128::RSA_PRIME_BITLEN;
    let primes = [
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
    ];
    cggmp24::key_refresh::PregeneratedPrimes::try_from(primes)
        .expect("primes have wrong bit size")
}

use cggmp24::security_level::SecurityLevel;

// ---- The test ----

#[tokio::test]
async fn test_two_party_dkg_and_sign() {
    let mut rng = rand::rngs::OsRng;
    let n: u16 = 2;
    let t: u16 = 2; // 2-of-2

    // =========================================================================
    // STEP 1: Two-party DKG
    // =========================================================================
    println!("=== STEP 1: Two-party DKG (threshold={t}, n={n}) ===");

    let eid_bytes: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid_bytes);

    let incomplete_shares = round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut party_rng = rand::rngs::OsRng;
        async move {
            cggmp24::keygen::<Secp256k1>(eid, i, n)
                .set_threshold(t)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    // Verify DKG output
    assert_eq!(incomplete_shares.len(), 2, "should have 2 shares");
    assert_eq!(
        incomplete_shares[0].shared_public_key, incomplete_shares[1].shared_public_key,
        "both parties must agree on joint public key"
    );

    let joint_pubkey = incomplete_shares[0].shared_public_key;
    println!(
        "  Joint public key: {}",
        hex::encode(joint_pubkey.to_bytes(true))
    );

    // Verify each party's public share matches G * x_i
    for (i, share) in incomplete_shares.iter().enumerate() {
        assert_eq!(share.i, i as u16);
        assert_eq!(
            Point::<Secp256k1>::generator() * &share.x,
            share.public_shares[i],
            "public share must equal G * secret_share for party {i}"
        );
    }
    println!("  DKG: PASS - both parties have valid shares, joint pubkey is valid secp256k1 point");

    // =========================================================================
    // STEP 2: Aux info generation (Paillier primes)
    // =========================================================================
    println!("\n=== STEP 2: Aux info generation ===");

    let eid_bytes: [u8; 32] = rng.gen();
    let eid_aux = ExecutionId::new(&eid_bytes);

    // Generate primes for each party (this is the expensive part)
    let primes: Vec<_> = (0..n)
        .map(|_| generate_pregenerated_primes(&mut rng))
        .collect();

    let aux_infos = round_based::sim::run(n, |i, party| {
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
    .into_vec();

    println!("  Aux info generated for {} parties", aux_infos.len());

    // =========================================================================
    // STEP 3: Combine into complete KeyShares
    // =========================================================================
    println!("\n=== STEP 3: Combining into complete KeyShares ===");

    let key_shares: Vec<_> = incomplete_shares
        .into_iter()
        .zip(aux_infos)
        .map(|(share, aux)| {
            cggmp24::KeyShare::from_parts((share, aux))
                .expect("key share validation should pass")
        })
        .collect();

    println!("  Complete KeyShares created and validated for {} parties", key_shares.len());

    // =========================================================================
    // STEP 4: Two-party threshold signing (4 rounds, no presig)
    // =========================================================================
    println!("\n=== STEP 4: Two-party threshold signing ===");

    let eid_bytes: [u8; 32] = rng.gen();
    let eid_sign = ExecutionId::new(&eid_bytes);

    let message = b"Hello from bsv-mpc POC 1!";
    let data_to_sign = DataToSign::digest::<Sha256>(message);

    let participants: Vec<u16> = vec![0, 1]; // both parties

    let sig = round_based::sim::run_with_setup(
        participants.iter().map(|i| &key_shares[usize::from(*i)]),
        |i, party, share| {
            let party = buffer_outgoing(party);
            let mut party_rng = rand::rngs::OsRng;
            let participants = participants.clone();
            async move {
                cggmp24::signing(eid_sign, i, &participants, share)
                    .sign(&mut party_rng, party, &data_to_sign)
                    .await
            }
        },
    )
    .unwrap()
    .expect_ok()
    .expect_eq();

    println!("  Signature produced:");
    let mut sig_bytes = [0u8; 64];
    sig.write_to_slice(&mut sig_bytes);
    println!("    r: {}", hex::encode(&sig_bytes[..32]));
    println!("    s: {}", hex::encode(&sig_bytes[32..]));

    // Verify with cggmp24's internal verifier
    sig.verify(&key_shares[0].core.shared_public_key, &data_to_sign)
        .expect("cggmp24 internal verification should pass");
    println!("  cggmp24 internal verify: PASS");

    // =========================================================================
    // STEP 5: Verify with BSV SDK
    // =========================================================================
    println!("\n=== STEP 5: BSV SDK verification ===");

    // Get the compressed public key bytes
    let pubkey_bytes = key_shares[0].core.shared_public_key.to_bytes(true);
    let bsv_pubkey =
        bsv::PublicKey::from_bytes(&pubkey_bytes).expect("BSV SDK should accept the public key");
    println!("  BSV PublicKey created: {}", bsv_pubkey.to_hex());

    // The message hash that was signed (SHA-256 of the original message)
    let msg_hash: [u8; 32] = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(message);
        hasher.finalize().into()
    };

    // Convert cggmp24 signature (compact r||s) to BSV SDK Signature
    let bsv_sig = bsv::Signature::from_compact(&sig_bytes)
        .expect("BSV SDK should accept the compact signature");

    let valid = bsv_pubkey.verify(&msg_hash, &bsv_sig);
    assert!(valid, "BSV SDK verification must pass!");
    println!("  BSV SDK verify: PASS");

    // =========================================================================
    // STEP 6: Presigning + 1-round online signing
    // =========================================================================
    println!("\n=== STEP 6: Presigning (3 offline rounds) + partial signature combine ===");

    let eid_bytes: [u8; 32] = rng.gen();
    let eid_presign = ExecutionId::new(&eid_bytes);

    let presigs = round_based::sim::run_with_setup(
        participants.iter().map(|i| &key_shares[usize::from(*i)]),
        |i, party, share| {
            let party = buffer_outgoing(party);
            let mut party_rng = rand::rngs::OsRng;
            let participants = participants.clone();
            async move {
                cggmp24::signing(eid_presign, i, &participants, share)
                    .generate_presignature(&mut party_rng, party)
                    .await
            }
        },
    )
    .unwrap()
    .expect_ok()
    .into_vec();

    println!("  Generated {} presignatures", presigs.len());

    // All commitments must match
    for (i, (_, commitment)) in presigs.iter().enumerate() {
        assert_eq!(presigs[0].1, *commitment, "commitment mismatch at party {i}");
    }
    let (_, commitments) = presigs[0].clone();

    // Sign a different message using presignatures
    let message2 = b"Second message signed with presignature";
    let data_to_sign2 = DataToSign::digest::<Sha256>(message2);

    let partial_signatures: Vec<_> = presigs
        .into_iter()
        .map(|(presig, _)| presig.issue_partial_signature(data_to_sign2))
        .collect();

    let sig2 =
        cggmp24::PartialSignature::combine(&partial_signatures, &commitments, data_to_sign2)
            .expect("partial signature combination should work");

    // Verify with cggmp24
    sig2.verify(&key_shares[0].core.shared_public_key, &data_to_sign2)
        .expect("presigned signature should verify");
    println!("  cggmp24 presig verify: PASS");

    // Verify with BSV SDK
    let mut sig2_bytes = [0u8; 64];
    sig2.write_to_slice(&mut sig2_bytes);

    let msg_hash2: [u8; 32] = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(message2);
        hasher.finalize().into()
    };

    let bsv_sig2 = bsv::Signature::from_compact(&sig2_bytes)
        .expect("BSV SDK should accept presigned signature");
    let valid2 = bsv_pubkey.verify(&msg_hash2, &bsv_sig2);
    assert!(valid2, "BSV SDK presigned verification must pass!");
    println!("  BSV SDK presig verify: PASS");

    // =========================================================================
    // SUMMARY
    // =========================================================================
    println!("\n========================================");
    println!("  POC 1 RESULT: ALL TESTS PASSED");
    println!("========================================");
    println!("  [x] 2-of-2 DKG on secp256k1");
    println!("  [x] Joint public key is valid");
    println!("  [x] Aux info generation (Paillier)");
    println!("  [x] 4-round threshold signing");
    println!("  [x] cggmp24 internal verification");
    println!("  [x] BSV SDK PublicKey::verify()");
    println!("  [x] Presigning (3 offline rounds)");
    println!("  [x] Partial signature combine");
    println!("  [x] Presigned signature verification");
    println!("========================================");
    println!("  VERDICT: GO - cggmp24 works for bsv-mpc");
    println!("========================================");
}
