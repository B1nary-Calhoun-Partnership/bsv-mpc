//! WASM runtime test for the inline DKG coordinator — Phase G Step 5b
//! merge gate, per `docs/PHASE-G-AUDIT.md` §7.4.
//!
//! ## What this proves
//!
//! G-5a verified `cargo build -p bsv-mpc-core --target wasm32-unknown-unknown`
//! succeeds — i.e. the rewritten inline coordinators (G-4b/c/d) *compile* on
//! wasm32. That's a necessary precondition but not sufficient: cargo build
//! emits an rlib without linking, so getrandom's wasm32 link error and any
//! latent `std::thread::spawn` reference would slip past. This test runs the
//! inline `DkgCoordinator::init` + `process_round` driver loop end-to-end on
//! `wasm32-unknown-unknown` to prove the coordinator *executes* there.
//!
//! Driving a real `DkgCoordinator` (vs. raw `round_based::sim` against
//! cggmp24, which POC 2 already proved) is the production-path check —
//! it exercises the same code that `bsv-mpc-service::handlers` will call
//! from the future `bsv-mpc-worker` deployment.
//!
//! ## Pattern parity with the native test
//!
//! Mirrors `dkg::tests::two_coordinators_keygen_message_exchange` at
//! `crates/bsv-mpc-core/src/dkg.rs:1267`. Same shape, same Blum-prime
//! shortcut, same 20-round bound — only the target and runner differ.
//! When the native test passes and this wasm32 test passes, both prove
//! the same inline-coordinator path works.
//!
//! ## Running
//!
//! ```bash
//! wasm-pack test --node -p bsv-mpc-core
//! ```

#![cfg(target_arch = "wasm32")]

use bsv_mpc_core::dkg::{DkgCoordinator, DkgRoundResult};
use bsv_mpc_core::{SessionId, ShareIndex, ThresholdConfig};
use wasm_bindgen_test::*;

// Default runner is Node (set by `wasm-pack test --node`). No
// `wasm_bindgen_test_configure!` macro call needed — that macro only
// accepts `run_in_browser`.

// Blum prime generation — ported from `poc2-wasm/src/lib.rs:31-52`
// and mirrors the test-only helper at `dkg.rs:870`. Blum primes (≡ 3 mod 4)
// take <100ms each on WASM; safe primes (which production code generates
// via `PregeneratedPrimes::generate` or the §06.10.1 pool) take 5-15s. For a
// state-machine runtime test on wasm32 the cryptographic distinction does
// not matter — the aux_info_gen flow runs and produces an `AuxInfo` either
// way. We use Blum primes here for the same reason the native test does:
// the test asserts the coordinator *runs to completion*, not safe-prime
// security properties.
use cggmp24::backend::Integer;
use cggmp24::key_refresh::PregeneratedPrimes;
use cggmp24::security_level::{SecurityLevel, SecurityLevel128};

fn generate_blum_prime(rng: &mut impl rand::RngCore, bits_size: u32) -> Integer {
    loop {
        let n = Integer::generate_prime(rng, bits_size);
        if n.mod_u(4) == 3 {
            break n;
        }
    }
}

fn generate_test_primes(rng: &mut impl rand::RngCore) -> PregeneratedPrimes<SecurityLevel128> {
    let bitsize = SecurityLevel128::RSA_PRIME_BITLEN;
    let primes = [
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
        generate_blum_prime(rng, bitsize),
    ];
    PregeneratedPrimes::try_from(primes).expect("primes have wrong bit size")
}

#[wasm_bindgen_test]
fn two_of_two_dkg_via_inline_coordinator() {
    let config = ThresholdConfig::new(2, 2).unwrap();
    let session = SessionId::from_str_hash("wasm32-dkg-runtime-test");

    let mut coord0 = DkgCoordinator::new(session, config, ShareIndex(0));
    let mut coord1 = DkgCoordinator::new(session, config, ShareIndex(1));

    let mut rng = rand::rngs::OsRng;
    coord0.set_pregenerated_primes(generate_test_primes(&mut rng));
    coord1.set_pregenerated_primes(generate_test_primes(&mut rng));

    let msgs0 = coord0.init().expect("coord0 init should succeed on wasm32");
    let msgs1 = coord1.init().expect("coord1 init should succeed on wasm32");

    assert!(!msgs0.is_empty(), "coord0 must emit initial outbound messages");
    assert!(!msgs1.is_empty(), "coord1 must emit initial outbound messages");
    assert_eq!(coord0.phase(), "keygen");
    assert_eq!(coord1.phase(), "keygen");

    let mut outgoing0 = msgs0;
    let mut outgoing1 = msgs1;

    for round in 0..20 {
        let result0 = coord0.process_round(outgoing1.clone());
        let result1 = coord1.process_round(outgoing0.clone());

        match (result0, result1) {
            (Ok(DkgRoundResult::NextRound(new0)), Ok(DkgRoundResult::NextRound(new1))) => {
                outgoing0 = new0;
                outgoing1 = new1;
            }
            (Ok(DkgRoundResult::Complete(r0)), Ok(DkgRoundResult::Complete(r1))) => {
                assert_eq!(
                    r0.joint_key.compressed, r1.joint_key.compressed,
                    "wasm32 inline coordinators must agree on the joint public key"
                );
                assert_eq!(r0.joint_key.address, r1.joint_key.address);
                assert_eq!(r0.joint_key.compressed.len(), 33);
                assert!(
                    r0.joint_key.compressed[0] == 0x02 || r0.joint_key.compressed[0] == 0x03,
                    "joint pubkey must be a valid compressed secp256k1 point"
                );
                assert!(r0.joint_key.address.starts_with('1'));
                assert_eq!(r0.share.share_index, ShareIndex(0));
                assert_eq!(r1.share.share_index, ShareIndex(1));
                return;
            }
            (Ok(DkgRoundResult::Complete(_)), Ok(DkgRoundResult::NextRound(_)))
            | (Ok(DkgRoundResult::NextRound(_)), Ok(DkgRoundResult::Complete(_))) => {
                panic!(
                    "wasm32 coordinators desynchronized at round {round}: \
                     one completed but the other did not"
                );
            }
            (Err(e), _) => panic!("coord0 error at round {round}: {e}"),
            (_, Err(e)) => panic!("coord1 error at round {round}: {e}"),
        }
    }

    panic!("DKG did not complete within 20 rounds on wasm32");
}
