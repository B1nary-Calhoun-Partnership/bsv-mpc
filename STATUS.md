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
| H | Socket.IO + BRC-103 wasm32 client + native unification + `bsv-rs` upstream `SocketIoTransport` | **STEPS 1-2 DONE** (~5-7 wk total); H-3 POC next | audit doc `254ff0f` + `4a1f8bc` (§2.5b) + §11 god-tier expansion landed |
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

## Upstream contributions due in Phase H

Per audit §11.2 **revised** (pure Rust+WASM, leverage existing Calhoun-owned `engineio/codec.rs`; JS bundle is Plan B fallback only):

| Target repo | What | When |
|---|---|---|
| `bsv-rs` (`~/bsv/bsv-rs/src/auth/transports/`) | new `SocketIoTransport` Rust impl of `bsv_rs::auth::Transport` over Socket.IO `authMessage` event — Rust analog of TS `@bsv/authsocket-client::SocketClientTransport` | **Phase H gate** (PR open/merged before merge-gate commit) |

## Ecosystem follow-ups (NOT Phase H gates — tracked here for visibility)

| Target | What | Why |
|---|---|---|
| New crate `bsv-engineio-rs` (or co-located) | Extract `engineio/codec.rs` from `bsv-messagebox-cloudflare-public` + `rust-message-box` into a shared crate; refactor both servers + our new client to depend on it | Currently the codec is duplicated byte-for-byte across both Rust servers. Shared crate = DRY + canonical Rust impl of Engine.IO v4 + Socket.IO v5 wire for the BSV ecosystem. Coordination work; post-Phase-H. |
| `rust-socketio` upstream (`1c3t3a/rust-socketio`) | wasm32-unknown-unknown target support | Plan A1 (vendor codec) gives pure Rust+WASM without needing `rust-socketio` at all, so this is no longer Phase H gating. Still worth doing as a broader-ecosystem contribution — replaces `reqwest+blocking+native-tls`, `tokio-tungstenite`, `native-tls` with wasm32-compatible alternates inside the external crate. Post-Phase-H. |
| New crate `bsv-authsocket-rs` | Rust analog of TS `@bsv/authsocket-client` — wraps upstream `SocketIoTransport` + `Peer` for the broader BSV ecosystem | Post-Phase-H crate publication, depends on the bsv-rs upstream PR landing first. |
