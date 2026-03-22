# bsv-mpc — Project Status

> What's done, what's validated, what's next.
> Updated: 2026-03-21

---

## Overall Status: POC COMPLETE — Ready for Production Implementation

**15/15 POCs passed.** Every critical assumption validated. ~12,300 lines of POC code written. $0.05 total mainnet cost. The entire cryptographic path is de-risked. Production implementation starts now.

### Timeline

| Milestone | Issues | Due | Days |
|---|---|---|---|
| ~~M0: POC Validation~~ | 0 open, 15 closed | ~~Mar 21~~ | **DONE** |
| M1: Core MPC Library | 5 open | Mar 28 | ~7 days |
| M2: Signing Proxy | 6 open | Apr 4 | ~7 days |
| M3: CF Worker Deployment | 3 open | Apr 8 | ~4 days |
| M4: Fee System | 2 open | Apr 11 | ~3 days |
| M5: Integration & BRCs | 4 open | Apr 14 | ~3 days |
| Beta: Overlay & Hardening | 4 open | Apr 25 | ~10 days |

**Original estimate: 10 weeks. Revised: ~3.5 weeks to alpha (M1-M5), ~5 weeks to beta.** POCs went ~3x faster than predicted, and ~60% of POC code is directly portable.

---

## POC Validation Results: 15/15 PASSED

| POC | What it validated | Result | Key metric |
|---|---|---|---|
| 1: cggmp24 signing | DKG + signing on secp256k1 | **PASS** | Signatures verify with BSV SDK |
| 2: WASM compilation | cggmp24 → wasm32-unknown-unknown | **PASS** | 636KB module, 79.5MB RSS, 1ms presig combine |
| 3: Key derivation | BRC-42 compatible with MPC | **PASS** | All 3 counterparty types match wallet |
| 4: Real BSV transaction | MPC-signed tx accepted by mainnet | **PASS** | [TXID](https://whatsonchain.com/tx/2e4a3afa0ae5c9c92422f6c703e36590884165669775cf7c7705a2ae43046bb7), 100 sat fee |
| 5: HTTP latency | Signing over HTTP | **PASS** | 359µs presigned, 135µs RTT |
| 6: Wallet toolbox | rust-wallet-toolbox as dependency | **PASS** | Zero coupling in UTXO/fee/handlers, ~30-line fork |
| 7: Fee injection | Fee output in transaction | **PASS** | [TXID](https://whatsonchain.com/tx/6033e4fb4872d1d6a28acb6659f35641e63738bb8297bca56dc88b60276b2d42), 3 outputs |
| 8: BRC-31 auth | Authrite through MPC | **PASS** | 1 KSS round-trip (~135µs), DER encoding correct |
| 9: Encrypt/decrypt | Wallet encryption compatibility | **PASS** | Byte-identical symmetric keys, zero data loss |
| 10: CF Worker HTTPS | MPC signing to deployed Worker | **PASS** | 1069KB WASM, 16ms RTT, 52ms DKG |
| 11: Fee settlement | Nodes co-sign settlement tx | **PASS** | [TXID](https://whatsonchain.com/tx/afbb7ecd746bf75c346303e863e9e6a4bd17184d8149ac68f0bdcc1003e485d7), 2-of-3 |
| 12: 3-of-5 threshold | Production config | **PASS** | 138ms DKG, 4.4ms presig combine |
| 13: Key refresh | Threshold resharing | **PASS** | Same key, 0 on-chain cost, ~50 LOC |
| 14: Overlay discovery | SHIP/SLAP on mainnet | **PASS** | 4/4 trackers live, no fallback needed |
| 15: Capstone | bsv-worm through MPC proxy | **PASS** | [TXID](https://whatsonchain.com/tx/4653d09a9a0baca057d954237a5cbc0f6d95c385d1e4aa2e98fa1113283349b1), full x402 payment |

---

## POC Shortcuts to Fix in Production

The capstone (POC 15) validated the full flow but used shortcuts that must be replaced:

| Component | POC shortcut | Production requirement | POC reference |
|---|---|---|---|
| BRC-31 auth signing | Reconstructed derived key | Share offsets via partial ECDH (POC 8 pattern) | `poc8/tests/poc.rs` |
| Encrypt/decrypt | Reconstructed key via ProtoWallet | Partial ECDH — 2 KSS round-trips (POC 9 pattern) | `poc9/tests/poc.rs` |
| UTXO management | WhatsOnChain query per request | Local UTXO tracker (reuse StorageSqlx from toolbox) | `poc6/tests/poc.rs` |
| Key persistence | Ephemeral DKG on startup | Persistent DO/SQLite storage | `poc10/worker/src/lib.rs` |
| Fee injection | Not implemented in capstone | Fee output per POC 7 pattern | `poc7/src/lib.rs` |
| Presigning | Not used (full 4-round each time) | Background presig pool (sub-ms signing) | `poc1/tests/poc.rs` |

---

## What's Done

### POC Code (~12,300 LOC across 15 POCs)
- [x] 15 standalone POC crates in `poc/` directory
- [x] All validated on BSV mainnet where applicable
- [x] ~60% of code directly portable to production crates

### Project Structure (unchanged from scaffolding)
- [x] Cargo workspace with 5 crates (~6,200 LOC scaffolded)
- [x] All types, errors, configs, routing complete
- [x] Pool management working (presign_manager.rs)
- [x] All 28 BRC-100 routes wired (server.rs)

### Documentation
- [x] CLAUDE.md — full architecture context
- [x] SPECS.md — plain English specifications
- [x] INTEGRATION.md — bsv-worm integration guide
- [x] TESTING.md — test strategy
- [x] POCS.md — POC validation plan (all completed)
- [x] LESSONS.md — technical findings from all 15 POCs
- [x] 4 BRC drafts in `brc-drafts/`

### Research
- [x] MPC library landscape (selected cggmp24)
- [x] Platform cost analysis (CF Workers selected)
- [x] BSV overlay mapping (4 live trackers confirmed)
- [x] TSSHOCK vulnerability assessment (cggmp24 patched)

---

## Implementation Order (Revised Post-POC)

### M1: Core MPC Library (Mar 21-28)
1. **#8 DKG coordinator** — port POC 1 DKG patterns to `dkg.rs` (2-3 days)
2. **#9 Signing coordinator** — port POC 1 signing + POC 5 HTTP SM to `signing.rs` (2-3 days)
3. **#10 Presigning manager** — integrate cggmp24 presign with existing pool (1-2 days)
4. **#11 Share encryption** — AES-256-GCM, straightforward (1 day)
5. **#12 Participation proofs** — OP_RETURN format (1-2 days)

### M2: Signing Proxy (Mar 28 - Apr 4)
1. **#13 MPC bridge** — port POC 5 HTTP state machine (2-3 days)
2. **#15 getPublicKey + createSignature** — port POC 3 + POC 8 (2-3 days)
3. **#16 encrypt/decrypt** — port POC 9 partial ECDH (1-2 days)
4. **#17 fee injection** — port POC 7 `lib.rs` nearly verbatim (1 day)
5. **#14 createAction** — port POC 4 + POC 6 toolbox integration (3-5 days)
6. **#18 bsv-worm URL fix** — 1-line fix (0.5 day)

### M3: CF Worker Deployment (Apr 4-8)
1. **#19 WASM compilation** — workspace Cargo.toml config (1 day)
2. **#20 CF Worker KSS** — port POC 10 worker + DO storage (3-4 days)
3. **#21 BRC-31 auth** — use rust-middleware crate (2 days)

### M4: Fee System (Apr 8-11)
1. **#24 Participation proofs** — overlay publishing (2 days)
2. **#25 Fee settlement** — port POC 11 settlement (3-4 days)

### M5: Integration (Apr 11-14)
1. **#26 E2E test** — port POC 15 capstone (1 day)
2. **#28 Standalone KSS** — axum binary, same API (2 days)
3. **#27 BRC submissions** — finalize 4 drafts (1 day)
4. **#41 Level 3 covenant** — deferred to post-beta

---

## Unsolved Problems (Reduced from 14 to 4)

| # | Problem | Status | Solution |
|---|---|---|---|
| 1 | cggmp24 API integration | **SOLVED** — POC 1, 5, 12 | All patterns proven |
| 2 | WASM + getrandom | **SOLVED** — POC 2, 10 | `getrandom/js` works |
| 3 | Transaction construction | **SOLVED** — POC 4, 6, 15 | Toolbox reuse + MpcSigner |
| 4 | UTXO tracking | **SOLVED** — POC 6 | Reuse StorageSqlx from toolbox |
| 5 | Key refresh | **SOLVED** — POC 13 | ~50 LOC threshold resharing |
| 6 | cggmp24 alpha stability | **Mitigated** — pin version, API proven across 15 POCs |
| 7 | Overlay bootstrap | **SOLVED** — POC 14 | 4 live SLAP trackers, production-ready |
| 8 | BRC-31 auth in CF Worker | **SOLVED** — POC 8, 10 | Stateless per-request verification works |
| 9 | CF Worker memory limit | **SOLVED** — POC 2 | 79.5MB RSS (128MB limit) |
| 10 | sCrypt fee covenant | Deferred to post-beta | Level 2 multisig works |
| **11** | **Toolbox fork or no-fork?** | **OPEN** | Fork (~30 lines) recommended by POC 6; alternative: `sign_and_process: false` |
| **12** | **Paillier replay in CF Worker** | **OPEN** | Store KeyShare in DO, load per request (POC 10 validated) |
| **13** | **Multiple BRC-42 derivation paths per tx** | **OPEN** | Each input may need different derived key |
| **14** | **Production key persistence format** | **OPEN** | KeyShare is 10KB JSON; need encrypted storage schema |

---

## File Count Summary

| Category | Files | Lines (approx) |
|---|---|---|
| Rust source (.rs) in crates/ | ~32 | ~6,200 |
| POC source (.rs) in poc/ | ~20 | ~12,300 |
| Config (Cargo.toml, etc.) | 12 | ~400 |
| Documentation (.md) | 8 | ~3,500 |
| BRC drafts | 4 | ~2,000 |
| Tests (integration) | 0 | 0 |
| **Total** | **~76** | **~24,400** |
