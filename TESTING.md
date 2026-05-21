# bsv-mpc Testing Strategy

> Unit tests prove the pieces work. Integration tests prove they talk to each other.
> E2E tests prove the whole thing works. Each POC adds tests that become permanent.

---

## Philosophy

Every POC produces tests that become the permanent test suite. We don't throw away POC code — we promote it. By the time all 7 POCs pass, we have a comprehensive test suite covering crypto, WASM, key derivation, transactions, latency, wallet integration, and fee injection.

---

## Live gated E2E inventory (updated 2026-05-21)

> The tables below (Levels 1–3) are the original POC-era plan. This section is
> the **current, authoritative** list of env-var-gated end-to-end harnesses that
> exercise the deployed CF-native cosigner. Ungated unit + integration tests run
> on a plain `cargo test --workspace`. Each harness is gated so heavy/networked/
> real-sats runs are opt-in. Run with:
> `cargo test -p bsv-mpc-proxy --test <name> --release` plus the env gate.

Shared deployed-infra env vars: `DEPLOYED_WORKER_URL`, `DEPLOYED_CONTAINER_URL`,
`MESSAGEBOX_RELAY_URL`, `MPC_PROXY_IDENTITY_KEY` (owner identity for authed DKG).
Real-sats funding via the local wallet at `localhost:3321` (Origin
`http://admin.com`); minimize sats. Secrets live in `secrets.md` (gitignored).

| Test (`crates/bsv-mpc-proxy/tests/`) | Gate env var | What it proves |
|---|---|---|
| `createaction_relay_mainnet_e2e` | `E2E_MAINNET=1` | #6 gate — canonical `CreateActionArgs` → relay → **real-sats mainnet TX** |
| `i5_real_sats_deployed_e2e` | `E2E_MAINNET=1` | earlier real-sats deployed gate |
| `self_stocking_loop_e2e` | `SELF_STOCKING_E2E=1` | #4 self-stocking (DKG→presig→ship→relay-sign); authed deployed with `DEPLOYED_CONTAINER_URL` + `MPC_PROXY_IDENTITY_KEY` |
| `provision_via_service_deployed_e2e` | `PROVISION_SVC_E2E=1` | #4c container ships `Presignature_A` to DO pool |
| `dkg_over_http_local_e2e` | `DKG_HTTP_E2E=1` | #4d distributed DKG-over-HTTP driver |
| `sign_relay_authed_deployed_e2e` | `SIGN_RELAY_AUTHED_E2E=1` | authed `/sign-relay` against segregated pool |
| `relay_combine_deployed_e2e` | `RELAY_COMBINE_E2E=1` | relay combiner over deployed infra |
| `relay_sign_bench_e2e` | `RELAY_BENCH_E2E=1` (`BENCH_K=N`) | latency + N sequential relay co-signs (regression for relay backlog cross-contamination) |
| `service_owner_authz_e2e` | `SERVICE_AUTHZ_E2E=1` | #7 finding #1 — in-process ENFORCED service; unauthed→401 / stranger→403 / owner→200 |
| `proxy_enforced_cosigner_e2e` | `PROXY_ENFORCED_E2E=1` | #7 finding #1 proxy side — multi-server BRC-31 vs enforced container |
| `custody_restart_survival_e2e` | `CUSTODY_E2E=1` | #9 — drop cosigner A → fresh B recovers KEK-sealed `share_A` → valid partial |
| `concurrency_stress_e2e` | `CONCURRENCY_E2E=1` | #12 — K parallel ceremonies, distinct keys, owner-gated, no corruption |
| `deploy_smoke_e2e` | `DEPLOY_SMOKE=1` | post-deploy smoke — deployed health + unauthed→401 on funded-boundary/custody routes |

**After any deploy, run `deploy_smoke_e2e`.** Wire/crypto/on-chain/cross-impl
changes must be gated by a real-mainnet e2e (cite the TXID in the commit), not
just unit + mock tests.

---

## Test Levels

### Level 1: Unit Tests (per-module, fast, no network)

Run with `cargo test`. Each module gets its own tests.

| Crate | Module | What to test | When |
|-------|--------|-------------|------|
| **core** | `types.rs` | ThresholdConfig validation (t≤n, t≥2), serde roundtrip | POC 1 |
| **core** | `share.rs` | AES-256-GCM encrypt → decrypt roundtrip, key derivation determinism | POC 1 |
| **core** | `dkg.rs` | Two in-process parties: DKG rounds → both get valid shares → joint key is valid secp256k1 point | POC 1 |
| **core** | `signing.rs` | Sign with 2-of-2 → verify with bsv SDK `PublicKey::verify()` | POC 1 |
| **core** | `presigning.rs` | Presign → consume → 1-round sign → verify | POC 1 |
| **core** | `proof.rs` | Proof creation, OP_RETURN serialization, roundtrip | M1 |
| **core** | `hd.rs` | HD derivation produces valid child keys | M1 |
| **proxy** | `config.rs` | Env var parsing, defaults | Already has test |
| **proxy** | `fee_injector.rs` | Fee output injection, change adjustment, threshold parsing | Already has 7 tests |
| **proxy** | `presign_manager.rs` | Pool management, FIFO ordering, replenishment trigger | Already has 6 tests |
| **overlay** | `types.rs` | MpcNodeInfo serde roundtrip | M4 |
| **overlay** | `proofs.rs` | `calculate_settlement()` proportional math | Already implemented |

### Level 2: Integration Tests (cross-crate, HTTP, no chain)

Run with `cargo test --test <name>`. Use `mockito` for HTTP mocking, `tempfile` for filesystem.

| Test | What it validates | When |
|------|------------------|------|
| `tests/test_dkg_signing_e2e.rs` | Core: DKG → sign → verify, all in-process | POC 1 |
| `tests/test_wasm.rs` | Core compiled to WASM, same tests pass in wasm-pack | POC 2 |
| `tests/test_key_derivation.rs` | MPC-derived pubkey matches normal wallet for same protocol/key/counterparty | POC 3 |
| `tests/test_proxy_routes.rs` | Proxy HTTP routes respond with correct JSON format | POC 5 |
| `tests/test_proxy_to_kss.rs` | Proxy sends signing request → service responds → signature valid | POC 5 |
| `tests/test_fee_injection_tx.rs` | Fee output added to real transaction, script evaluation passes | POC 7 |
| `tests/test_toolbox_integration.rs` | rust-wallet-toolbox as dependency, signer swap works | POC 6 |
| `tests/test_create_action.rs` | Full createAction: UTXO select → build tx → inject fee → MPC sign → valid tx | M2 |
| `tests/test_encrypt_decrypt.rs` | Proxy encrypt/decrypt matches normal wallet encryption | M2 |
| `tests/test_brc31_auth.rs` | Proxy handles BRC-31 handshake, signatures verify | M2 |

### Level 3: E2E Tests (full stack, real BSV, slow)

Run manually or in CI with `cargo test --test e2e -- --ignored`. Requires funded wallet.

| Test | What it validates | When |
|------|------------------|------|
| `tests/e2e_real_tx.rs` | MPC-sign a P2PKH transaction, verify script evaluation | POC 4 |
| `tests/e2e_worm_status.rs` | bsv-worm connects to MPC proxy, `bsv-worm status` works | M2 |
| `tests/e2e_worm_think.rs` | bsv-worm calls LLM through MPC proxy, payment on-chain | M5 |
| `tests/e2e_cf_worker.rs` | Proxy talks to deployed CF Worker KSS, signing works | M3 |
| `tests/e2e_overlay.rs` | CHIP token published, discoverable, proof published | M4 |
| `tests/e2e_fee_settlement.rs` | Fee accumulates, nodes settle, proportional payout | M4 |

---

## How POCs Become Tests

Each POC is a standalone test that validates one assumption. When the POC passes, its code moves into the permanent test suite:

```
POC 1 (poc/poc1-cggmp24-signing/tests/poc.rs)
    ↓ passes
tests/test_dkg_signing_e2e.rs (permanent integration test)
    ↓ enriched during M1
tests/test_signing.rs (unit tests for signing module)
tests/test_dkg.rs (unit tests for DKG module)
```

### POC → Test Promotion Map

| POC | Becomes | Level |
|-----|---------|-------|
| POC 1: cggmp24 signs | `test_dkg_signing_e2e.rs` + per-module unit tests | Unit + Integration |
| POC 2: WASM | `test_wasm.rs` + CI wasm-pack job | Integration |
| POC 3: Key derivation | `test_key_derivation.rs` | Integration |
| POC 4: Real BSV tx | `e2e_real_tx.rs` (ignored by default) | E2E |
| POC 5: HTTP latency | `test_proxy_to_kss.rs` + latency assertions | Integration |
| POC 6: Toolbox dep | `test_toolbox_integration.rs` | Integration |
| POC 7: Fee injection | `test_fee_injection_tx.rs` | Integration |

---

## Test Conventions

- **One test file per module** in `tests/` directory (same as bsv-worm: 34 test files, ~1600 tests)
- **Use `tempfile`** for filesystem tests (shares, storage)
- **Use `mockito`** for HTTP mocking (KSS responses, overlay queries)
- **Valid secp256k1 pubkeys required** — never use fake pubkeys (same convention as bsv-worm)
- **`#[ignore]` for E2E tests** that need network/funded wallet — CI runs with `--ignored` flag separately
- **Assert on crypto correctness**, not just "no panic" — verify every signature, check every derived key

## CI Pipeline (when ready)

```yaml
# .github/workflows/test.yml
jobs:
  unit:
    - cargo test --workspace
    - cargo clippy --workspace -- -D warnings

  wasm:
    - cargo build -p bsv-mpc-core --target wasm32-unknown-unknown
    - wasm-pack test -p bsv-mpc-core --node

  integration:
    - cargo test --test '*' --workspace

  e2e:  # manual trigger only
    - cargo test --test 'e2e_*' -- --ignored
```

---

## Test Count Targets

| Milestone | Cumulative Tests | What's tested |
|-----------|-----------------|--------------|
| After POCs (M0) | ~30 | Crypto, WASM, key derivation, tx signing, HTTP, fee injection |
| After M1 | ~80 | All core modules: DKG, signing, presigning, shares, proofs, HD |
| After M2 | ~150 | Proxy routes, createAction, encrypt/decrypt, BRC-31, fee injection |
| After M3 | ~200 | WASM compilation, CF Worker handlers, DO SQLite storage |
| After M4 | ~250 | CHIP tokens, discovery, overlay proofs, fee settlement |
| After M5 | ~300 | E2E integration with bsv-worm, full signing flow |

For comparison: bsv-worm has ~1600 tests across 34 files. We're targeting ~300 for a simpler codebase.

---

## What Makes a Test "Good Enough"

A test is sufficient when it answers: **"Would this catch a regression that breaks signing?"**

- Crypto tests: verify the signature, not just that it returned bytes
- Key derivation tests: compare against a known-good wallet's output
- Transaction tests: run script evaluation, not just serialization
- HTTP tests: check response format matches what bsv-worm expects
- Fee tests: verify total inputs = total outputs + mining fee
- E2E tests: confirm on-chain acceptance (when possible)
