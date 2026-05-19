# POC 16 — Phase G inline state-machine drive + Paillier safe-prime pool

> Empirical validation of `docs/PHASE-G-AUDIT.md` § 2 (inline SM rewrite)
> and § 3 (Paillier safe-prime pool per MPC-Spec §06.10.1 / ADR-0041).
> First POC commit of Phase G; lands on `main` BEFORE the implementation
> commits (G-4) begin.

## What this POC proves

Five gates, mapped to audit doc §6.2:

| Gate | What it proves | Test |
|---|---|---|
| **G-3.1** | Inline 2-of-2 DKG keygen with **no `std::thread::spawn`** anywhere. Both parties' joint pubkeys match byte-for-byte. | `gate_3_1_inline_keygen_no_thread_spawn_test` |
| **G-3.1 grep** | The source tree contains no `thread::spawn` / `thread::Builder` / `tokio::spawn` / `spawn_local` tokens. | `gate_3_1_no_thread_or_tokio_spawn_in_source` |
| **G-3.2** | `aux_info_gen` runs end-to-end with `PregeneratedPrimes` constructed via `TryFrom<[Integer; 4]>` (the injection path), driven inline (no spawn). | `gate_3_2_inline_auxinfo_test` |
| **G-3.3** | **`PregeneratedPrimes` go in, the same primes come out** of the pool (byte-identical serialization). `aux_info_gen` runs end-to-end against the round-tripped primes (proves they're still cryptographically usable, not just structurally equal). Original phrasing ("byte-identical AuxInfo") was corrected after empirical POC run revealed `aux_info_gen` is non-deterministic on internal RNG state. | `gate_3_3_byte_identical_auxinfo_test` |
| **G-3.4** | At-rest pool encryption round-trip via `InMemoryPoolStorage` + AES-256-GCM + BRC-42 HMAC-derived key. Stored ciphertext is non-plaintext. `backfill_to_floor` populates an empty pool to its floor. | `gate_3_4_at_rest_round_trip_test` |
| **G-3.5** | `cargo build --target wasm32-unknown-unknown -p poc16-sm-inline` succeeds. The POC compiles to WASM by construction (no `thread::spawn`, no tokio runtime). | not a `#[test]` — checked via `cargo build` invocation. |

## Run

```bash
# All native gates (G-3.1 ... G-3.4)
cargo test  -p poc16-sm-inline -- --nocapture
cargo run   -p poc16-sm-inline

# WASM build (G-3.5)
rustup target add wasm32-unknown-unknown
cargo build -p poc16-sm-inline --target wasm32-unknown-unknown
```

Expected output (gate timings vary on machine):

```
==== POC 16 — Phase G inline SM + Paillier pool ====
[G-3.1] inline 2-of-2 keygen OK: joint_pk=03… (~4ms)
[G-3.2] inline 2-party auxinfo with injected primes OK (~28s)
[G-3.3] pool round-trip preserves primes byte-for-byte (1660B+1660B serialized)
       + aux_info_gen runs end-to-end on round-tripped primes (~29s)
[G-3.4] pool round-trip OK: floor=2, ciphertext=1676B != plaintext=1660B (~131s)
ALL GATES PASS — Phase G design empirically validated.
```

(`G-3.4` wall-clock is dominated by `PregeneratedPrimes::generate(rng)`
which uses real 2048-bit safe primes; the other gates use Blum primes
via `gen_blum` for tractable test time — same trick as `poc/poc2-wasm`.)

Empirical findings from this POC that informed the audit doc:

- **`cggmp24::aux_info_gen` is non-deterministic on internal RNG
  state.** Two runs with identical primes + identical `ExecutionId`
  produce different `AuxInfo` bytes (same size, different content) —
  ZK proof nonces consume fresh randomness from the SM's `&mut R`.
  G-3.3 was originally drafted to check byte-identical AuxInfo; we
  corrected to byte-identical *primes through pool* + e2e auxinfo
  usability, which is the actual pool invariant.
- **`PregeneratedPrimes` serialize losslessly through AES-256-GCM.**
  1660-byte plaintext → 1676-byte ciphertext (16 extra bytes = 12B
  nonce + 16B AES-GCM tag minus serde framing; standard AEAD overhead).
- **wasm32-unknown-unknown build succeeds in ~45s** from a clean
  target dir (incremental: ~1s) — no `getrandom/js` runtime missing.

## Module layout

- `src/lib.rs` — module declarations + public API
- `src/inline_drive.rs` — `run_inline_2of2_keygen` / `run_inline_2of2_auxinfo`. The kernel `drive_one_party()` is the inline-drive pattern that `bsv-mpc-core`'s coordinators will adopt in G-4.
- `src/paillier_pool.rs` — `PrimePoolStorage` trait, `InMemoryPoolStorage`, `PaillierPool` with BRC-42-HMAC-derived AES-256-GCM at-rest encryption. Mirrors the target shape of `crates/bsv-mpc-core/src/paillier_pool.rs` per ADR-0041 § Consequences.
- `src/scenarios.rs` — the five gate scenarios.
- `src/main.rs` — runs all four runtime gates with timings.
- `tests/poc.rs` — `#[test]` versions + the static grep check.

## Design decisions inherited from `docs/PHASE-G-AUDIT.md`

Per the audit doc's locked decisions (no re-litigation in this POC):

- **Inline, not LocalSet** — Coordinator owns the SM directly; no
  `tokio::task::spawn_local` or `LocalSet`. `proceed()` is non-blocking
  by construction, so this is strictly simpler. Audit §2.
- **Pool optional via `.with_pool(&pool)`** (OQ1 default) — POC's
  `PaillierPool` is consumed by injection into `aux_info_gen` via
  `PregeneratedPrimes`, not via implicit magic.
- **BRC-42 HMAC + `[2, "mpc paillier pool"]` domain separator** (OQ2
  default) — mirrors `share.rs::derive_share_encryption_key()`. Same
  crypto, one audit surface. Production module in G-4 may upgrade to
  full BRC-42 ECDH if the wallet primitive is available, but POC shows
  the simpler HMAC path works.
- **`Send + Sync` storage trait** (OQ3 default) — costs zero on CF
  Workers (DOs are single-threaded anyway) and benefits native consumers.
- **Eager backfill at startup** (OQ4 default) — POC's
  `backfill_to_floor()` is the synchronous primitive; scheduling is a
  consumer concern.
- **Path dep on cggmp24 fork** (OQ5 default) — POC uses the EXACT
  cggmp24 source (Calhooon fork, commit `6c6421ee…`) the production
  workspace uses, so the inline pattern is validated against the same
  state-machine impl that ships in production.

## What this POC does NOT do

- It does NOT produce on-chain artifacts. The merge-gate mainnet TXID
  comes from Phase G Step 5 (`G-5`), re-running the existing Phase E
  `sign_mainnet_via_messagebox_e2e` test with the new inline SM.
- It does NOT exercise the full `DkgCoordinator` API. The POC drives
  both parties' SMs in one function call (single-process simulation).
  The production rewrite (G-4) will host the SM on a coordinator
  struct that persists across `process_round()` calls — that's the
  next step.
- It does NOT benchmark WASM performance. Audit doc §6.3 explicitly
  excludes WASM cold-start / p99 benchmarking from POC scope — that's
  Phase I deployment work.

## References

- `docs/PHASE-G-AUDIT.md` — design doc this POC validates
- `docs/NEXT-STEPS.md` — phased v1.0 cosigner plan (5-step workflow)
- `MPC-Spec/06-transport.md` §06.10.1 — Paillier safe-prime pool spec
- `MPC-Spec/decisions/0041-network-profile-latency-budgets.md` — ADR
- `crates/bsv-mpc-core/src/dkg.rs:759-908` — the SM thread bridge being
  replaced
- `crates/bsv-mpc-core/src/share.rs:135-176` — the BRC-42 HMAC pattern
  this POC mirrors for at-rest pool encryption
- `poc/poc2-wasm/src/lib.rs:29-52` — the Blum prime generation trick
  reused here for tractable test wall-clock
