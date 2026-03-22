# Next Session Prompt

> Copy-paste this into a new Claude Code window at ~/bsv/bsv-mpc/

---

Read HANDOFF.md and CLAUDE.md. Then complete M2 with two parallel worktree agents + a verification agent.

## Task: Complete M2 — Derived Key Signing + Safe Stubs

### Agent 1 (worktree): Stub 10 todo!() endpoints as safe no-ops

In `crates/bsv-mpc-proxy/src/wallet_api.rs`, replace all 10 remaining `todo!()` calls with safe JSON responses. These are Tier 3 endpoints bsv-worm doesn't call — they must NOT panic, just return empty/error responses.

After stubbing, add an E2E test in `tests/e2e.rs` that:
1. Calls ALL 28 BRC-100 endpoints against the running proxy
2. Asserts every endpoint returns HTTP 200 with valid JSON (no panics, no 500s from todo!())
3. Verifies the response shape matches what bsv-worm's wallet.rs expects

Run `cargo test --test e2e -- --ignored --nocapture` to verify the full E2E suite still passes with the stubs.

### Agent 2 (worktree): Wire derived key signing in createAction

The critical missing piece: `createAction` currently signs all inputs with the root MPC key. Real BRC-100 operation requires per-input BRC-42 derived key signing.

1. Read the TODO comments at `wallet_api.rs:1363` and `wallet_api.rs:1560`
2. Read POC 3 (`poc/poc3-key-derivation/`) for the BRC-42 derivation pattern
3. Read `bridge.rs` — the `sign()` method already accepts an `hmac_offset` parameter
4. Wire the derivation: for each input, compute BRC-42 HMAC offset from the input's derivation path, pass it to `bridge.sign()`

**Tests (CRITICAL — this is where slop happens):**
1. Unit test in `wallet_api.rs`: Create a derived key via `getPublicKey(protocolID, keyID, counterparty)`, then `createSignature` with same params, then `verifySignature` with `forSelf: true` — full crypto round-trip
2. E2E test in `tests/e2e.rs`: Add a test scenario that does the sign-verify round-trip over HTTP through the proxy+KSS (like existing `test_signature_roundtrip` but with derived keys, not just root key)

Run `cargo test -p bsv-mpc-proxy` and `cargo test --test e2e -- --ignored --nocapture` to verify.

### After both merge: Verification

After merging both worktrees:
1. `cargo test --workspace` — all 270+ tests pass
2. `cargo test --test e2e -- --ignored --nocapture` — all E2E scenarios pass (including new ones)
3. `cargo clippy --workspace -- -D warnings` — zero warnings
4. Verify: no `todo!()` remains in `wallet_api.rs` (grep to confirm)
5. Verify: derived key signing works end-to-end (the new E2E test proves this)

## What "done" looks like

- Zero `todo!()` stubs in wallet_api.rs
- All 28 BRC-100 endpoints return valid JSON (no panics)
- Derived key signing works: getPublicKey → createSignature → verifySignature with same BRC-42 params produces valid crypto round-trip
- 280+ tests pass (existing 270 + new tests)
- E2E suite passes with all scenarios

## What NOT to do

- Do NOT implement certificates, discovery, or key linkage for real — just safe no-op returns
- Do NOT refactor working code — only add/modify what's needed for derived signing and stubs
- Do NOT skip tests — every change must have a test that proves it works end-to-end
- Do NOT create new files unless absolutely necessary — modify existing test files

## Key files

- `crates/bsv-mpc-proxy/src/wallet_api.rs` — the 10 todo!() stubs + derived key signing
- `crates/bsv-mpc-proxy/src/bridge.rs` — `sign(hash, presig, hmac_offset)` already supports offset
- `crates/bsv-mpc-core/src/hd.rs` — BRC-42 HMAC computation
- `crates/bsv-mpc-core/src/ecdh.rs` — partial ECDH for "self"/"other" counterparty
- `tests/e2e.rs` — add new test scenarios here
- `poc/poc3-key-derivation/` — the source of truth for derivation patterns
- `poc/poc8-brc31-auth/` — partial ECDH pattern for "self" counterparty
