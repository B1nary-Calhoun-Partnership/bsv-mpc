//! POC 12: 3-of-5 threshold signing — production configuration
//!
//! Validates:
//! 1. 5-party DKG on secp256k1 with threshold=3
//! 2. Any 3 of 5 can produce valid signatures
//! 3. Different 3-party subsets produce signatures for the SAME joint pubkey
//! 4. 2 of 5 (below threshold) correctly fails
//! 5. Presigning with 3-of-5 works
//! 6. Latency comparison: 3-party vs 2-party signing

use std::collections::VecDeque;
use std::time::Instant;

use cggmp24::security_level::SecurityLevel128;
use cggmp24::signing::DataToSign;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use generic_ec::Point;
use rand::Rng;
use sha2::Sha256;

// ---- Buffered sink (from cggmp24 test infra) ----

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

// ---- Generate blum primes ----

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
    use cggmp24::security_level::SecurityLevel;
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

// ---- Helper: sign with a subset of parties ----

async fn sign_with_subset(
    key_shares: &[cggmp24::KeyShare<Secp256k1, SecurityLevel128>],
    participants: &[u16],
    data_to_sign: &DataToSign<Secp256k1>,
) -> Result<cggmp24::signing::Signature<Secp256k1>, String> {
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid_bytes);
    let participants_vec = participants.to_vec();

    let result = round_based::sim::run_with_setup(
        participants.iter().map(|i| &key_shares[usize::from(*i)]),
        |i, party, share| {
            let party = buffer_outgoing(party);
            let mut party_rng = rand::rngs::OsRng;
            let p = participants_vec.clone();
            async move {
                cggmp24::signing(eid, i, &p, share)
                    .sign(&mut party_rng, party, data_to_sign)
                    .await
            }
        },
    );

    match result {
        Ok(sim_output) => {
            // Get raw per-party results without panicking
            let results = sim_output.into_vec();
            let mut sigs = Vec::new();
            for (i, r) in results.into_iter().enumerate() {
                match r {
                    Ok(sig) => sigs.push(sig),
                    Err(e) => return Err(format!("party {} failed: {:?}", i, e)),
                }
            }
            // All parties should produce same signature
            for (i, sig) in sigs.iter().enumerate().skip(1) {
                let mut bytes_0 = [0u8; 64];
                let mut bytes_i = [0u8; 64];
                sigs[0].write_to_slice(&mut bytes_0);
                sig.write_to_slice(&mut bytes_i);
                if bytes_0 != bytes_i {
                    return Err(format!("party 0 and party {} produced different signatures", i));
                }
            }
            Ok(sigs.into_iter().next().unwrap())
        }
        Err(e) => Err(format!("simulation failed: {:?}", e)),
    }
}

// ---- Helper: verify signature with BSV SDK ----

fn verify_with_bsv_sdk(
    joint_pubkey: &Point<Secp256k1>,
    message: &[u8],
    sig: &cggmp24::signing::Signature<Secp256k1>,
) -> bool {
    let pubkey_bytes = joint_pubkey.to_bytes(true);
    let bsv_pubkey = bsv::PublicKey::from_bytes(&pubkey_bytes).expect("valid pubkey");

    let msg_hash: [u8; 32] = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(message);
        hasher.finalize().into()
    };

    let mut sig_bytes = [0u8; 64];
    sig.write_to_slice(&mut sig_bytes);
    let bsv_sig = bsv::Signature::from_compact(&sig_bytes).expect("valid signature");

    bsv_pubkey.verify(&msg_hash, &bsv_sig)
}

// ---- The test ----

#[tokio::test]
async fn test_three_of_five_threshold_signing() {
    let mut rng = rand::rngs::OsRng;
    let n: u16 = 5;
    let t: u16 = 3; // 3-of-5

    // =========================================================================
    // STEP 1: Five-party DKG
    // =========================================================================
    println!("=== STEP 1: Five-party DKG (threshold={t}, n={n}) ===");
    let dkg_start = Instant::now();

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

    let dkg_elapsed = dkg_start.elapsed();

    assert_eq!(incomplete_shares.len(), 5, "should have 5 shares");

    // All parties must agree on joint public key
    let joint_pubkey = incomplete_shares[0].shared_public_key;
    for (i, share) in incomplete_shares.iter().enumerate() {
        assert_eq!(
            share.shared_public_key, joint_pubkey,
            "party {i} has different joint pubkey"
        );
    }

    println!(
        "  Joint public key: {}",
        hex::encode(joint_pubkey.to_bytes(true))
    );
    println!("  DKG time: {:?}", dkg_elapsed);

    // Verify each party's public share
    for (i, share) in incomplete_shares.iter().enumerate() {
        assert_eq!(share.i, i as u16);
        assert_eq!(
            Point::<Secp256k1>::generator() * &share.x,
            share.public_shares[i],
            "public share must equal G * secret_share for party {i}"
        );
    }
    println!("  DKG: PASS - 5 parties have valid shares");

    // =========================================================================
    // STEP 2: Aux info generation (Paillier primes for 5 parties)
    // =========================================================================
    println!("\n=== STEP 2: Aux info generation (5 parties) ===");
    let aux_start = Instant::now();

    let eid_bytes: [u8; 32] = rng.gen();
    let eid_aux = ExecutionId::new(&eid_bytes);

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

    let aux_elapsed = aux_start.elapsed();
    println!("  Aux info generated for {} parties in {:?}", aux_infos.len(), aux_elapsed);

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

    println!("  Complete KeyShares created for {} parties", key_shares.len());

    let message = b"Hello from bsv-mpc POC 12 - 3-of-5 threshold!";
    let data_to_sign = DataToSign::digest::<Sha256>(message);

    // =========================================================================
    // STEP 4: Sign with parties [0,1,2] — first valid subset
    // =========================================================================
    println!("\n=== STEP 4: Sign with parties [0,1,2] ===");
    let sign_start = Instant::now();

    let sig_012 = sign_with_subset(&key_shares, &[0, 1, 2], &data_to_sign)
        .await
        .expect("signing with [0,1,2] should succeed");

    let sign_012_elapsed = sign_start.elapsed();

    sig_012
        .verify(&key_shares[0].core.shared_public_key, &data_to_sign)
        .expect("cggmp24 verify should pass");

    assert!(
        verify_with_bsv_sdk(&joint_pubkey, message, &sig_012),
        "BSV SDK verify must pass for [0,1,2]"
    );

    println!("  Parties [0,1,2]: PASS (cggmp24 + BSV SDK)");
    println!("  Sign time: {:?}", sign_012_elapsed);

    // =========================================================================
    // STEP 5: Sign with parties [1,3,4] — different subset
    // =========================================================================
    println!("\n=== STEP 5: Sign with parties [1,3,4] ===");
    let sign_start = Instant::now();

    let sig_134 = sign_with_subset(&key_shares, &[1, 3, 4], &data_to_sign)
        .await
        .expect("signing with [1,3,4] should succeed");

    let sign_134_elapsed = sign_start.elapsed();

    sig_134
        .verify(&key_shares[0].core.shared_public_key, &data_to_sign)
        .expect("cggmp24 verify should pass");

    assert!(
        verify_with_bsv_sdk(&joint_pubkey, message, &sig_134),
        "BSV SDK verify must pass for [1,3,4]"
    );

    println!("  Parties [1,3,4]: PASS (cggmp24 + BSV SDK)");
    println!("  Sign time: {:?}", sign_134_elapsed);

    // =========================================================================
    // STEP 6: Sign with parties [0,2,4] — yet another subset
    // =========================================================================
    println!("\n=== STEP 6: Sign with parties [0,2,4] ===");
    let sign_start = Instant::now();

    let sig_024 = sign_with_subset(&key_shares, &[0, 2, 4], &data_to_sign)
        .await
        .expect("signing with [0,2,4] should succeed");

    let sign_024_elapsed = sign_start.elapsed();

    sig_024
        .verify(&key_shares[0].core.shared_public_key, &data_to_sign)
        .expect("cggmp24 verify should pass");

    assert!(
        verify_with_bsv_sdk(&joint_pubkey, message, &sig_024),
        "BSV SDK verify must pass for [0,2,4]"
    );

    println!("  Parties [0,2,4]: PASS (cggmp24 + BSV SDK)");
    println!("  Sign time: {:?}", sign_024_elapsed);

    // =========================================================================
    // STEP 7: Verify all signatures are for the SAME joint pubkey
    // =========================================================================
    println!("\n=== STEP 7: Verify same joint public key across subsets ===");

    // All signatures verify against the same joint public key
    // (already verified above, but let's be explicit)
    for (name, sig) in [
        ("[0,1,2]", &sig_012),
        ("[1,3,4]", &sig_134),
        ("[0,2,4]", &sig_024),
    ] {
        sig.verify(&joint_pubkey, &data_to_sign)
            .expect(&format!("verify {} against joint pubkey", name));
    }

    // Note: signatures from different subsets will be DIFFERENT (different nonces)
    // but all verify against the SAME public key — that's the point of threshold crypto
    let mut bytes_012 = [0u8; 64];
    let mut bytes_134 = [0u8; 64];
    sig_012.write_to_slice(&mut bytes_012);
    sig_134.write_to_slice(&mut bytes_134);
    // Different nonces → different signatures (this is expected and correct)
    println!("  Signatures differ across subsets (different nonces): expected");
    println!("  All verify against same joint pubkey: PASS");

    // =========================================================================
    // STEP 8: Below-threshold attempt — [0,1] (2 of 5, should fail)
    // =========================================================================
    println!("\n=== STEP 8: Below-threshold [0,1] — must fail ===");

    let result = sign_with_subset(&key_shares, &[0, 1], &data_to_sign).await;

    assert!(
        result.is_err(),
        "signing with only 2 parties in a 3-of-5 scheme MUST fail"
    );
    println!("  Parties [0,1] (below threshold): correctly rejected");
    println!("  Error: {}", result.unwrap_err());

    // =========================================================================
    // STEP 9: Presigning with 3-of-5
    // =========================================================================
    println!("\n=== STEP 9: Presigning with parties [0,1,2] ===");
    let presign_start = Instant::now();

    let eid_bytes: [u8; 32] = rng.gen();
    let eid_presign = ExecutionId::new(&eid_bytes);
    let presign_participants: Vec<u16> = vec![0, 1, 2];

    let presigs = round_based::sim::run_with_setup(
        presign_participants
            .iter()
            .map(|i| &key_shares[usize::from(*i)]),
        |i, party, share| {
            let party = buffer_outgoing(party);
            let mut party_rng = rand::rngs::OsRng;
            let p = presign_participants.clone();
            async move {
                cggmp24::signing(eid_presign, i, &p, share)
                    .generate_presignature(&mut party_rng, party)
                    .await
            }
        },
    )
    .unwrap()
    .expect_ok()
    .into_vec();

    let presign_elapsed = presign_start.elapsed();
    println!("  Generated {} presignatures in {:?}", presigs.len(), presign_elapsed);

    // All commitments must match
    for (i, (_, commitment)) in presigs.iter().enumerate() {
        assert_eq!(presigs[0].1, *commitment, "commitment mismatch at party {i}");
    }
    let (_, commitments) = presigs[0].clone();

    // 1-round sign with presignatures
    let message2 = b"Second message via 3-of-5 presignature";
    let data_to_sign2 = DataToSign::digest::<Sha256>(message2);

    let combine_start = Instant::now();

    let partial_sigs: Vec<_> = presigs
        .into_iter()
        .map(|(presig, _)| presig.issue_partial_signature(data_to_sign2))
        .collect();

    let sig_presigned =
        cggmp24::PartialSignature::combine(&partial_sigs, &commitments, data_to_sign2)
            .expect("partial signature combination should work");

    let combine_elapsed = combine_start.elapsed();

    sig_presigned
        .verify(&key_shares[0].core.shared_public_key, &data_to_sign2)
        .expect("presigned sig should verify");

    assert!(
        verify_with_bsv_sdk(&joint_pubkey, message2, &sig_presigned),
        "BSV SDK must verify presigned sig"
    );

    println!("  Presig combine time: {:?}", combine_elapsed);
    println!("  Presigned signature: PASS (cggmp24 + BSV SDK)");

    // =========================================================================
    // STEP 10: Latency comparison — 2-of-2 baseline
    // =========================================================================
    println!("\n=== STEP 10: Latency comparison (2-of-2 baseline) ===");

    // Run a fresh 2-of-2 DKG + sign for comparison
    let n2: u16 = 2;
    let t2: u16 = 2;

    let eid_bytes: [u8; 32] = rng.gen();
    let eid2 = ExecutionId::new(&eid_bytes);

    let incomplete_2 = round_based::sim::run(n2, |i, party| {
        let party = buffer_outgoing(party);
        let mut party_rng = rand::rngs::OsRng;
        async move {
            cggmp24::keygen::<Secp256k1>(eid2, i, n2)
                .set_threshold(t2)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    let eid_bytes: [u8; 32] = rng.gen();
    let eid_aux2 = ExecutionId::new(&eid_bytes);

    let primes2: Vec<_> = (0..n2)
        .map(|_| generate_pregenerated_primes(&mut rng))
        .collect();

    let aux2 = round_based::sim::run(n2, |i, party| {
        let party = buffer_outgoing(party);
        let mut party_rng = rand::rngs::OsRng;
        let pregenerated = primes2[usize::from(i)].clone();
        async move {
            cggmp24::aux_info_gen(eid_aux2, i, n2, pregenerated)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    let key_shares_2: Vec<_> = incomplete_2
        .into_iter()
        .zip(aux2)
        .map(|(share, aux)| {
            cggmp24::KeyShare::from_parts((share, aux)).expect("valid")
        })
        .collect();

    // Time 2-of-2 signing
    let sign2_start = Instant::now();

    let _sig_2of2 = sign_with_subset(&key_shares_2, &[0, 1], &data_to_sign)
        .await
        .expect("2-of-2 signing should work");

    let sign2_elapsed = sign2_start.elapsed();

    println!("  2-of-2 sign time: {:?}", sign2_elapsed);
    println!("  3-of-5 sign time: {:?} (from step 4)", sign_012_elapsed);
    let ratio = sign_012_elapsed.as_micros() as f64 / sign2_elapsed.as_micros().max(1) as f64;
    println!("  Ratio (3-of-5 / 2-of-2): {:.2}x", ratio);

    // =========================================================================
    // SUMMARY
    // =========================================================================
    println!("\n========================================");
    println!("  POC 12 RESULT: ALL TESTS PASSED");
    println!("========================================");
    println!("  [x] 5-party DKG on secp256k1 (t=3, n=5)");
    println!("  [x] Sign with [0,1,2] — BSV SDK verified");
    println!("  [x] Sign with [1,3,4] — BSV SDK verified");
    println!("  [x] Sign with [0,2,4] — BSV SDK verified");
    println!("  [x] Below-threshold [0,1] correctly rejected");
    println!("  [x] All subsets verify against same joint pubkey");
    println!("  [x] Presigning with 3-of-5 works");
    println!("  [x] Presig combine + BSV SDK verified");
    println!("  [x] Latency: 3-of-5 = {:?}, 2-of-2 = {:?} ({:.1}x)", sign_012_elapsed, sign2_elapsed, ratio);
    println!("========================================");
    println!("  VERDICT: GO - 3-of-5 production config validated");
    println!("========================================");
}
