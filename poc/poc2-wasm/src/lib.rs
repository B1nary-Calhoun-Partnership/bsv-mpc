//! POC 2: cggmp24 compiled to WASM
//!
//! Validates that the MPC crypto stack compiles and runs in wasm32-unknown-unknown.
//! Uses the synchronous state machine API (no async runtime needed in WASM).

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::iter;

use cggmp24::security_level::SecurityLevel;
use cggmp24::security_level::SecurityLevel128;
use cggmp24::signing::DataToSign;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use rand::Rng;
use sha2::Sha256;
use wasm_bindgen::prelude::*;

use cggmp24::backend::Integer;

/// Get current time in milliseconds (works in WASM via js_sys)
fn now_ms() -> f64 {
    js_sys::Date::now()
}

// ---- Blum prime generation (same as POC 1) ----

fn generate_blum_prime(rng: &mut impl rand::RngCore, bits_size: u32) -> Integer {
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

// ---- Sync DKG using state machine API ----

/// Run 2-of-2 DKG and return the joint public key as hex.
/// This is the core validation: cggmp24 crypto works in WASM.
#[wasm_bindgen]
pub fn run_dkg() -> String {
    let mut rng = rand::rngs::OsRng;
    let n: u16 = 2;
    let t: u16 = 2;

    let eid_bytes: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid_bytes);

    let mut party_rngs: Vec<_> = iter::repeat_with(|| rand::rngs::OsRng)
        .take(n.into())
        .collect();

    let mut simulation = round_based::sim::Simulation::with_capacity(n);
    for (i, party_rng) in (0u16..).zip(&mut party_rngs) {
        simulation.add_party(
            cggmp24::keygen::<Secp256k1>(eid, i, n)
                .set_threshold(t)
                .into_state_machine(party_rng),
        );
    }

    let key_shares = simulation
        .run()
        .unwrap()
        .into_vec()
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("DKG should succeed");

    assert_eq!(key_shares.len(), 2);
    assert_eq!(
        key_shares[0].shared_public_key, key_shares[1].shared_public_key,
        "both parties must agree on joint public key"
    );

    hex::encode(key_shares[0].shared_public_key.to_bytes(true))
}

/// Run full DKG + aux info gen + signing + verification in WASM.
/// Returns a result string with detailed timings for each phase.
#[wasm_bindgen]
pub fn run_full_test() -> String {
    let mut rng = rand::rngs::OsRng;
    let n: u16 = 2;
    let t: u16 = 2;

    // === DKG ===
    let t0 = now_ms();

    let eid_bytes: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid_bytes);

    let mut party_rngs: Vec<_> = iter::repeat_with(|| rand::rngs::OsRng)
        .take(n.into())
        .collect();

    let mut simulation = round_based::sim::Simulation::with_capacity(n);
    for (i, party_rng) in (0u16..).zip(&mut party_rngs) {
        simulation.add_party(
            cggmp24::keygen::<Secp256k1>(eid, i, n)
                .set_threshold(t)
                .into_state_machine(party_rng),
        );
    }

    let incomplete_shares = simulation
        .run()
        .unwrap()
        .into_vec()
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("DKG should succeed");

    let dkg_ms = now_ms() - t0;
    let joint_pubkey_hex = hex::encode(incomplete_shares[0].shared_public_key.to_bytes(true));

    // === Prime generation ===
    let t1 = now_ms();

    let primes: Vec<_> = (0..n)
        .map(|_| generate_pregenerated_primes(&mut rng))
        .collect();

    let prime_gen_ms = now_ms() - t1;

    // === Aux info gen protocol ===
    let t2 = now_ms();

    let eid_bytes: [u8; 32] = rng.gen();
    let eid_aux = ExecutionId::new(&eid_bytes);

    let mut party_rngs: Vec<_> = iter::repeat_with(|| rand::rngs::OsRng)
        .take(n.into())
        .collect();

    let mut aux_sim = round_based::sim::Simulation::with_capacity(n);
    for (i, (party_rng, pregenerated)) in (0u16..).zip(party_rngs.iter_mut().zip(primes)) {
        aux_sim.add_party(
            cggmp24::aux_info_gen(eid_aux, i, n, pregenerated)
                .into_state_machine(party_rng),
        );
    }

    let aux_infos = aux_sim
        .run()
        .unwrap()
        .into_vec()
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("aux info gen should succeed");

    let aux_gen_ms = now_ms() - t2;

    // === Combine into complete KeyShares ===
    let key_shares: Vec<_> = incomplete_shares
        .into_iter()
        .zip(aux_infos)
        .map(|(share, aux)| {
            cggmp24::KeyShare::from_parts((share, aux))
                .expect("key share validation should pass")
        })
        .collect();

    // === Signing (4-round, no presig) ===
    let t3 = now_ms();

    let eid_bytes: [u8; 32] = rng.gen();
    let eid_sign = ExecutionId::new(&eid_bytes);

    let message = b"Hello from bsv-mpc WASM POC!";
    let data_to_sign = DataToSign::digest::<Sha256>(message);

    let participants: Vec<u16> = vec![0, 1];

    let mut signer_rngs: Vec<_> = iter::repeat_with(|| rand::rngs::OsRng)
        .take(t.into())
        .collect();

    let mut sign_sim = round_based::sim::Simulation::with_capacity(t);
    for ((i, share), signer_rng) in (0u16..)
        .zip(participants.iter().map(|i| &key_shares[usize::from(*i)]))
        .zip(&mut signer_rngs)
    {
        sign_sim.add_party(
            cggmp24::signing(eid_sign, i, &participants, share)
                .sign_sync(signer_rng, &data_to_sign),
        );
    }

    let sigs = sign_sim
        .run()
        .unwrap()
        .into_vec()
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("signing should succeed");

    let signing_ms = now_ms() - t3;
    let sig = &sigs[0];

    // Verify with cggmp24's internal verifier
    sig.verify(&key_shares[0].core.shared_public_key, &data_to_sign)
        .expect("signature verification should pass");

    let mut sig_bytes = [0u8; 64];
    sig.write_to_slice(&mut sig_bytes);
    let sig_hex = hex::encode(&sig_bytes);

    // === Presigning (3 offline rounds) ===
    let t4 = now_ms();

    let eid_bytes: [u8; 32] = rng.gen();
    let eid_presign = ExecutionId::new(&eid_bytes);

    let mut presign_rngs: Vec<_> = iter::repeat_with(|| rand::rngs::OsRng)
        .take(t.into())
        .collect();

    let mut presign_sim = round_based::sim::Simulation::with_capacity(t);
    for ((i, share), signer_rng) in (0u16..)
        .zip(participants.iter().map(|i| &key_shares[usize::from(*i)]))
        .zip(&mut presign_rngs)
    {
        presign_sim.add_party(
            cggmp24::signing(eid_presign, i, &participants, share)
                .generate_presignature_sync(signer_rng),
        );
    }

    let presigs = presign_sim
        .run()
        .unwrap()
        .into_vec()
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("presigning should succeed");

    let presigning_ms = now_ms() - t4;

    // === Partial signature combine (the "1 online round" with presig) ===
    let t5 = now_ms();

    let message2 = b"Presigned WASM message";
    let data_to_sign2 = DataToSign::digest::<Sha256>(message2);

    let (_, commitments) = presigs[0].clone();
    let partial_sigs: Vec<_> = presigs
        .into_iter()
        .map(|(presig, _)| presig.issue_partial_signature(data_to_sign2))
        .collect();

    let sig2 = cggmp24::PartialSignature::combine(&partial_sigs, &commitments, data_to_sign2)
        .expect("partial signature combination should work");

    let partial_combine_ms = now_ms() - t5;

    sig2.verify(&key_shares[0].core.shared_public_key, &data_to_sign2)
        .expect("presigned signature verification should pass");

    let mut sig2_bytes = [0u8; 64];
    sig2.write_to_slice(&mut sig2_bytes);

    alloc::format!(
        "PASS: pubkey={}, sig={}, presig={} | \
         timings: dkg={:.0}ms, prime_gen={:.0}ms, aux_gen={:.0}ms, \
         signing_4round={:.0}ms, presigning_3round={:.0}ms, \
         partial_combine={:.2}ms",
        joint_pubkey_hex,
        sig_hex,
        hex::encode(&sig2_bytes),
        dkg_ms,
        prime_gen_ms,
        aux_gen_ms,
        signing_ms,
        presigning_ms,
        partial_combine_ms,
    )
}
