# bsv-mpc — Project Status

> What's done, what's open, what's next.
> Updated: 2026-05-19

This file is the short / scannable view. The full, authoritative
trackers are:

- [**docs/NEXT-STEPS.md**](docs/NEXT-STEPS.md) — live phase plan (G/H/I/J/K)
- [**docs/PHASE-G-AUDIT.md**](docs/PHASE-G-AUDIT.md) — Phase G design + merge-gate check-off
- [**bsv-mpc#2**](https://github.com/B1nary-Calhoun-Partnership/bsv-mpc/issues/2) — v1.0 CF-native cosigner umbrella issue
- [**MPC-Spec#36**](https://github.com/B1nary-Calhoun-Partnership/MPC-Spec/issues/36) — joint cross-stack mainnet TX (Phase K closing)
- [**LESSONS.md**](LESSONS.md) — POC + implementation findings

---

## Phase tracker

| Phase | Scope | State | On-chain / CI artifact |
|---|---|---|---|
| A–F | canonical envelopes + MessageBox wire + DKG via MB + Sign via MB | **CLOSED** | Phase E mainnet TXID [`82ccb15c…`](https://whatsonchain.com/tx/82ccb15c49985a32b355a618f417bb7a09ec4ee5cf34e539e9baaebb74dadc29) |
| G | inline SM coordinator rewrite + Paillier safe-prime pool | **CLOSED 2026-05-19** | Mainnet TXID [`442bd391…`](https://whatsonchain.com/tx/442bd391cf8eda299f82dc1e4aeb1a9cb4f33610365d44c9c1c0e55d32f171b9) (G-5d) + wasm32 `tests/wasm32_dkg.rs` green (G-5b). Merge-gate commit `d9b1b27`. |
| H | `bsv-mpc-messagebox` Rust client crate (WASM-compatible, outbound WS DO) | **NEXT** | — |
| I | wire G + H into deployed `bsv-mpc-worker` CF cosigner | blocked on H | — |
| J | CHIP + `/capabilities` + `/health.json` (MPC-Spec §12 + §16) | blocked on I | — |
| K | cross-stack joint mainnet TX (closes MPC-Spec #36) | blocked on J + Quaakee's rust-mpc deploy | — |

---

## POC validation (historical)

All 16 POCs PASSED across the project's history. POCs 1-15 ran in M0
(Mar 2026) and de-risked the cryptographic + wire path. POC 16
(`poc16-sm-inline`) ran in Phase G Step 3 (2026-05-19) and proved the
inline-SM + Paillier-pool design empirically before the production
port. See [LESSONS.md](LESSONS.md) for the full technical writeup.

---

## What's running today

- 5-crate Cargo workspace (`bsv-mpc-core`, `bsv-mpc-proxy`,
  `bsv-mpc-service`, `bsv-mpc-worker`, `bsv-mpc-overlay`) plus
  `bsv-mpc-messagebox` (Phase A-F). ~22K LOC production code + ~13K
  LOC POC code.
- All protocol modules in `bsv-mpc-core` implemented inline (no thread
  bridge, no spawn) and wasm32-buildable + wasm32-runtime-verified.
- `bsv-mpc-service` runs locally with the canonical MessageBox wire,
  signs real mainnet transactions via the live Calhoun relay.
- CI on `B1nary-Calhoun-Partnership/bsv-mpc` `main` covers: fmt,
  clippy `-D warnings`, native build+test (all crates, all targets),
  wasm32 build (`bsv-mpc-core` + `bsv-mpc-worker`), and the wasm32 DKG
  runtime test.

---

## Known follow-ups deferred past Phase G

| Item | Source | Why deferred |
|---|---|---|
| Replace `unsafe impl Send` on inline coordinators with a `SendShield<T>` structural wrapper | audit §2.5 OQ6 | Sound today under documented invariant; right shape depends on Phase I DO concurrency patterns — revisit in Phase I deployment audit. |
| Eager startup backfill of `paillier_pool` in `bsv-mpc-service` | audit OQ4 | Spec-recommended; not on the G gate path. Phase I work. |
| SQLite persistence backend for `bsv-mpc-service` | CLAUDE.md | Currently in-memory; not load-bearing for cross-stack tests. Phase I or later. |
| Overlay proof publication (`publish_proof`, `query_proofs`, `count_proofs_by_node`) | CLAUDE.md | Phase J adjacent. |
