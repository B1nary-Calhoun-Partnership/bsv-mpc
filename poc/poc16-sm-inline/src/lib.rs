//! POC 16 — Inline state-machine drive + Paillier safe-prime pool
//!
//! Validates the two interlocking design decisions of `docs/PHASE-G-AUDIT.md`:
//!
//! 1. **Inline drive** — `round_based::StateMachine::proceed()` is
//!    non-blocking by construction. We can drive it directly via
//!    `proceed()` + `received_msg()` without any `std::thread::spawn` or
//!    `tokio::task::spawn_local`. This module's [`inline_drive`] proves
//!    the pattern on a 2-of-2 DKG keygen and a 2-party `aux_info_gen`.
//!
//! 2. **Paillier safe-prime pool** — Per MPC-Spec §06.10.1 / ADR-0041.
//!    [`paillier_pool`] implements an at-rest-encrypted pool (AES-256-GCM
//!    with a BRC-42-derived key, mirroring the §16.1 share-encryption
//!    pattern), with `take`/`put`/`backfill_to_floor` primitives.
//!
//! All five POC gates from `docs/PHASE-G-AUDIT.md` §6.2 are scenarios in
//! this module: `gate_3_1_inline_keygen`, `gate_3_2_inline_auxinfo`,
//! `gate_3_3_byte_identical_auxinfo`, `gate_3_4_at_rest_round_trip`,
//! `gate_3_5_wasm_build` (the last is a build-time concern — passing
//! the gate just means this crate compiles for `wasm32-unknown-unknown`).
//!
//! ## Run
//!
//! ```bash
//! # Native scenarios (gates 3.1 - 3.4):
//! cargo run -p poc16-sm-inline
//! cargo test  -p poc16-sm-inline
//!
//! # WASM build (gate 3.5):
//! cargo build -p poc16-sm-inline --target wasm32-unknown-unknown
//! ```

pub mod inline_drive;
pub mod paillier_pool;
pub mod scenarios;

pub use inline_drive::{run_inline_2of2_auxinfo, run_inline_2of2_keygen, InlineDriveError};
pub use paillier_pool::{InMemoryPoolStorage, PaillierPool, PoolError, PrimePoolStorage};
