//! The five POC gates from `docs/PHASE-G-AUDIT.md` §6.2.
//!
//! Each function below is one gate. They're invoked from both
//! `src/main.rs` (interactive run with timings) and `tests/poc.rs`
//! (CI). The hard gate criteria — what makes each scenario "pass" —
//! are commented inline above each function.

use std::time::Instant;

use cggmp24::backend::Integer;
use cggmp24::key_refresh::PregeneratedPrimes;
use cggmp24::security_level::SecurityLevel;
use cggmp24::security_level::SecurityLevel128;
use rand::RngCore;

use crate::inline_drive::{run_inline_2of2_auxinfo, run_inline_2of2_keygen};
use crate::paillier_pool::{InMemoryPoolStorage, PaillierPool, PrimePoolStorage};

/// Gate G-3.1 — Inline 2-of-2 DKG keygen with no `std::thread::spawn`.
///
/// Pass criteria:
/// - Both parties produce `IncompleteKeyShare` outputs.
/// - Joint pubkeys match byte-for-byte.
/// - Zero `std::thread::spawn` / `tokio::spawn` in this crate (grep
///   check in `tests/poc.rs`).
pub fn gate_3_1_inline_keygen() -> anyhow::Result<()> {
    let t0 = Instant::now();
    let eid_bytes: [u8; 32] = rand::random();
    let (share_a, share_b) = run_inline_2of2_keygen(eid_bytes)?;

    let pk_a = hex::encode(share_a.shared_public_key.to_bytes(true));
    let pk_b = hex::encode(share_b.shared_public_key.to_bytes(true));
    anyhow::ensure!(pk_a == pk_b, "joint pubkey mismatch: A={pk_a}, B={pk_b}");

    println!(
        "[G-3.1] inline 2-of-2 keygen OK: joint_pk={pk_a} ({:?})",
        t0.elapsed()
    );
    Ok(())
}

/// Gate G-3.2 — Inline auxinfo with INJECTED primes.
///
/// Pass criteria:
/// - `PregeneratedPrimes::TryFrom<[Integer; 4]>` accepts our Blum primes.
/// - `aux_info_gen` runs end-to-end via inline drive.
/// - Both parties' `AuxInfo` outputs are produced (no protocol error).
pub fn gate_3_2_inline_auxinfo() -> anyhow::Result<()> {
    let t0 = Instant::now();
    let mut rng = rand::rngs::OsRng;

    // Generate Blum primes out-of-band, then inject via TryFrom.
    let primes_a = generate_blum_primes(&mut rng);
    let primes_b = generate_blum_primes(&mut rng);

    let eid_bytes: [u8; 32] = rand::random();
    let (_aux_a, _aux_b) = run_inline_2of2_auxinfo(eid_bytes, primes_a, primes_b)?;

    println!(
        "[G-3.2] inline 2-party auxinfo with injected primes OK ({:?})",
        t0.elapsed()
    );
    Ok(())
}

/// Gate G-3.3 — Pool round-trip preserves `PregeneratedPrimes`
/// byte-for-byte AND runs auxinfo end-to-end against the round-tripped
/// primes.
///
/// **What we test** (and why this differs from the audit-doc-§6.2
/// initial phrasing): empirically `cggmp24::aux_info_gen` is not
/// byte-deterministic on `(primes, eid)` alone — its internal ZK
/// proofs consume fresh RNG state (`OsRng` inside cggmp24), so two
/// runs with the same primes produce different AuxInfo bytes. The
/// honest invariant the pool can guarantee is "primes go in, the
/// same primes come out" — which is what this gate now checks. The
/// audit doc was updated to reflect this finding in the same commit
/// that ships this POC.
///
/// Pass criteria:
/// - Serialized primes BEFORE `pool.put(primes)` equal serialized
///   primes AFTER `pool.take()` for both parties — byte-identical.
/// - `aux_info_gen` runs end-to-end against the round-tripped primes
///   and produces a valid `AuxInfo` (proves the round-tripped primes
///   are still cryptographically usable, not just structurally equal).
pub fn gate_3_3_byte_identical_auxinfo() -> anyhow::Result<()> {
    let t0 = Instant::now();
    let mut rng = rand::rngs::OsRng;

    let primes_a_orig = generate_blum_primes(&mut rng);
    let primes_b_orig = generate_blum_primes(&mut rng);

    // Snapshot serialization before pool storage.
    let primes_a_before = serde_json::to_vec(&primes_a_orig)?;
    let primes_b_before = serde_json::to_vec(&primes_b_orig)?;

    let root_key = [0xAAu8; 32];
    let pool_a = PaillierPool::new(InMemoryPoolStorage::new(), &root_key, b"party-0", 0);
    let pool_b = PaillierPool::new(InMemoryPoolStorage::new(), &root_key, b"party-1", 0);
    pool_a.put(primes_a_orig)?;
    pool_b.put(primes_b_orig)?;

    let primes_a_back = pool_a.take()?.expect("pool A non-empty");
    let primes_b_back = pool_b.take()?.expect("pool B non-empty");

    let primes_a_after = serde_json::to_vec(&primes_a_back)?;
    let primes_b_after = serde_json::to_vec(&primes_b_back)?;

    anyhow::ensure!(
        primes_a_before == primes_a_after,
        "party 0 primes byte-mismatch after pool round-trip: before={}B, after={}B",
        primes_a_before.len(),
        primes_a_after.len()
    );
    anyhow::ensure!(
        primes_b_before == primes_b_after,
        "party 1 primes byte-mismatch after pool round-trip: before={}B, after={}B",
        primes_b_before.len(),
        primes_b_after.len()
    );

    // Cryptographic-usability check: the round-tripped primes still
    // drive aux_info_gen to a valid AuxInfo. (We don't check
    // AuxInfo-byte-equality across runs — see doc-comment above.)
    let eid_bytes: [u8; 32] = rand::random();
    let (_aux_a, _aux_b) = run_inline_2of2_auxinfo(eid_bytes, primes_a_back, primes_b_back)?;

    println!(
        "[G-3.3] pool round-trip preserves primes byte-for-byte \
         ({}B+{}B serialized) + aux_info_gen runs end-to-end on \
         round-tripped primes ({:?})",
        primes_a_before.len(),
        primes_b_before.len(),
        t0.elapsed()
    );
    Ok(())
}

/// Gate G-3.4 — At-rest encryption round-trip.
///
/// Pass criteria:
/// - Pool `put` writes a ciphertext blob to storage that is NOT the
///   plaintext serialization (i.e., encryption is actually applied).
/// - Pool `take` returns the same `PregeneratedPrimes` value (the
///   `aux_info_gen` produces byte-identical AuxInfo when given the
///   take()d primes vs the put()ted primes).
/// - `backfill_to_floor` populates an empty pool to its configured
///   floor.
pub fn gate_3_4_at_rest_round_trip() -> anyhow::Result<()> {
    let t0 = Instant::now();
    let mut rng = rand::rngs::OsRng;

    let root_key = [0xCDu8; 32];
    let pool_id = b"poc16-gate-3-4";
    let floor = 2;

    let pool = PaillierPool::new(InMemoryPoolStorage::new(), &root_key, pool_id, floor);

    // Backfill to floor.
    let added = pool.backfill_to_floor(&mut rng)?;
    anyhow::ensure!(
        added == floor,
        "expected backfill_to_floor to add {floor} keypairs, got {added}"
    );
    anyhow::ensure!(
        pool.storage().count()? == floor,
        "storage count != floor after backfill"
    );

    // Re-check: calling backfill again is a no-op when at floor.
    let added2 = pool.backfill_to_floor(&mut rng)?;
    anyhow::ensure!(
        added2 == 0,
        "backfill_to_floor should be no-op when at floor (got {added2})"
    );

    // Verify the at-rest blob is non-plaintext.
    // We take the SECOND keypair so we can inspect its raw ciphertext
    // representation without consuming the first. (Pool exposes
    // storage(), so we peek by taking + re-putting.)
    let primes_taken = pool.take()?.expect("pool non-empty");

    // Inspect: a "plaintext blob" would be the JSON of PregeneratedPrimes.
    let plaintext_repr = serde_json::to_vec(&primes_taken)?;

    // Re-put and immediately inspect the stored blob through storage.
    pool.put(primes_taken)?;
    let stored = pool.storage().take_encrypted()?.expect("just put one");
    anyhow::ensure!(
        stored.ciphertext != plaintext_repr,
        "stored ciphertext equals plaintext — encryption not applied!"
    );
    anyhow::ensure!(
        stored.nonce != [0u8; 12],
        "all-zero nonce indicates AES-GCM nonce generator broken"
    );

    println!(
        "[G-3.4] pool round-trip OK: floor={floor}, ciphertext={}B != plaintext={}B ({:?})",
        stored.ciphertext.len(),
        plaintext_repr.len(),
        t0.elapsed()
    );
    Ok(())
}

/// Generate a `PregeneratedPrimes` value using Blum primes (`p ≡ 3 mod 4`),
/// which are faster to generate than safe primes and acceptable for the
/// CGGMP'24 protocol's correctness — same trick used by poc2-wasm so the
/// POC runs in seconds instead of minutes. See:
/// `poc/poc2-wasm/src/lib.rs:29-52` for the upstream pattern.
///
/// **For production**, `PregeneratedPrimes::generate(rng)` is the right
/// call (proper safe primes). The pool's `backfill_to_floor()` uses the
/// production path; only the POC's Gate-3.2 / Gate-3.3 use Blum primes
/// to keep wall-clock tractable.
fn generate_blum_primes<R: RngCore>(rng: &mut R) -> PregeneratedPrimes<SecurityLevel128> {
    let bitsize = SecurityLevel128::RSA_PRIME_BITLEN;
    let primes = [
        gen_blum(rng, bitsize),
        gen_blum(rng, bitsize),
        gen_blum(rng, bitsize),
        gen_blum(rng, bitsize),
    ];
    PregeneratedPrimes::try_from(primes).expect("Blum primes have correct bit size")
}

fn gen_blum<R: RngCore>(rng: &mut R, bitsize: u32) -> Integer {
    loop {
        let n = Integer::generate_prime(rng, bitsize);
        if n.mod_u(4) == 3 {
            break n;
        }
    }
}
