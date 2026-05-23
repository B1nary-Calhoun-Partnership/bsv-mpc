# Handoff — #13: retire the legacy 4-round HTTP sign path (110%, no asterisks)

> **Mission:** delete the legacy interactive 4-round HTTP signing path (`bridge.rs::sign` ↔ KSS `/sign/{init,round}`) and route ALL MPC signing through the relay, with **zero capability loss** and **zero coverage loss** — proven by green gates + a fresh deployed mainnet TXID. Swarm/orchestrate as needed. **Re-run every gate yourself; never trust an agent's "passed."**
> Canonical repo: `/Users/johncalhoun/bsv/mpc/bsv-mpc` (NOT `-DEAD-do-not-use`). Spec: `~/bsv/mpc/MPC-Spec`. Issue: **#13**. Branch per logical change; squash-merge; warning-free clippy (native + wasm).

This doc was produced by a 4-agent audit (proxy, KSS, relay-coverage, tests). Where the agents disagreed, the reconciled truth is called out inline — **read §3 (the real prerequisites) and §6 (do-NOT-delete list) before deleting anything.**

---

## 0. The ONE thing

The relay sign path (`/sign-relay` + MessageBox §05 envelope) is the deployed-proven default and, since **#26 (merged, `49a4071`)**, supports BOTH base-key and BRC-42 HD-derived (offset) signing. The legacy 4-round HTTP path is now only reachable when `relay_sign=false`. Retire it: delete the proxy client method + KSS handlers + their wire types, re-route `createSignature`/`createAction` to relay-only, migrate the tests that still exercise it, and prove the retire with a **multi-input createAction-over-relay mainnet TXID** (the one capability not yet mainnet-proven).

`Cleanup; not fund-loss.` But it touches deployed KSS routes + the 6-scenario HTTP e2e suite, so a half-done job breaks `main` — do it completely.

---

## 1. What is already proven (do NOT rebuild)

- **Relay base-key signing** — mainnet-proven by FOUR independent TXIDs: `i5_real_sats_deployed_e2e`, `container_sec0617_deployed_mainnet_e2e`, `container_refresh_deployed_mainnet_e2e`, `createaction_relay_mainnet_e2e`.
- **Relay HD-derived (offset) signing** — mainnet-proven by **#26**: `container_hd_relay_deployed_mainnet_e2e` (child-key spend TXID `a7d463907876c6c6d123588c4b5705d2c54e63fda7af86a39394fe588f365728`; verifies under child, rejects under base). Offset applied both sides via `SigningCoordinator::sign_with_presignature_with_offset` / `sign_from_bundle_with_offset` (signing.rs) + cosigner `decrypt_and_issue_partial(Some(offset))`.
- **The relay sign path is fully independent** of the 4-round path: `relay_sign.rs::{combine_sign_over_relay, combine_sign_from_bundle_over_relay}`, service `sign_relay_handler.rs::cosign_over_relay`, worker `poc.rs::handle_prod_sign_relay`. None of these call `bridge.sign` / `/sign/{init,round}` / `init_round`.

## 2. The 4-round path anatomy (what gets deleted)

**Proxy (`crates/bsv-mpc-proxy/src`)**
- `bridge.rs::sign` (~L1046–1160) — orchestrates `/sign/init` then loops `/sign/round` ×3, driving `SigningCoordinator::sign`→`init_round`/`process_round` over HTTP. **DELETE.**
- `bridge.rs` wire types `SignInitRequest`/`SignInitResponse`/`SignRoundRequest`/`SignRoundResponse` (~L66–113). Used ONLY by `bridge.sign`. **DELETE.**
- Callers: `wallet_api.rs::create_signature_impl` (~L1193–1210, the `if relay_sign {…} else { bridge.sign }` branch) and `create_action_impl` (~L1512–1529, per-input `else { bridge.sign }`). **RE-ROUTE to relay-only** (see §4).

**KSS — service (`crates/bsv-mpc-service/src`)**
- `lib.rs:94-95` routes `/sign/init`,`/sign/round`. **DELETE routes.**
- `handlers.rs::handle_sign_init` (~L574–695) + `handle_sign_round` (~L698–785) + wire types `SignInitRequest`/`Response`/`SignRoundRequest`/`Response` (~L117–159). **DELETE.**
- `auth.rs:25` doc comment lists `/sign/init`; tests (~L630–739) use `/sign/init` as a mock path. **EDIT** doc comment; **re-point** mock tests to `/presign/init` (BRC-31 logic is path-agnostic) — do not delete the generic `verify_or_allow`.

**KSS — worker (`crates/bsv-mpc-worker/src`)**
- `lib.rs:121-126` routes `/sign/init`,`/sign/round` → `poc::forward_to_cosigner_do`. **DELETE routes.**
- `poc.rs::is_authed_path` lists `/sign/init`,`/sign/round` (~L55-56). **EDIT** (remove them).
- `api.rs::handle_sign_init` (~L533–598) + `handle_sign_round` (~L607–664) + their wire types. **DELETE.**

**Core (`crates/bsv-mpc-core/src/signing.rs`) — VERIFY, then likely delete**
- `SigningCoordinator::sign` (~L259) + `init_round` (~L502) are used by `bridge.sign` AND the KSS `/sign/{init,round}` handlers. Once BOTH proxy `bridge.sign` and the KSS handlers are deleted, **`sign`/`init_round` become dead code** (the relay path uses `sign_with_presignature*`/`sign_from_bundle*` + `process_round`, NOT `init_round`). **Verify with `cargo +nightly udeps` or grep, then delete `sign`+`init_round` if unused.** `process_round` STAYS (the relay combiner uses it). The 9 unit tests in signing.rs are local state-machine tests — keep the ones that don't drive `init_round`; delete/migrate any that do.

## 3. The REAL prerequisites (RECONCILED — agents disagreed here)

The "proxy" audit claimed "no blocking gaps"; the "relay-coverage" audit found these. Both can't be right — **these are real and must be closed BEFORE deletion, or the retire ships a regression:**

1. **Multi-input `createAction` over relay is NOT mainnet-proven.** Every deployed relay test signs a SINGLE input. `create_action_impl` loops `relay_sign` per input (each does `presign_manager.take_raw()`), so it *should* work, but "should" ≠ 110%. **PREREQUISITE: a deployed mainnet test that funds ≥2 UTXOs to the joint (or a child) address and spends them in one `createAction` over the relay → one TXID with ≥2 `vin`, WoC-confirmed.** This is the new headline gate.
2. **The 4-round path was the on-demand fallback when the presig pool is empty.** Relay requires pre-stocked presigs on BOTH the proxy and the deployed cosigner (DO/container) pools. After deletion, presig starvation = a hard `createSignature`/`createAction` error (no 4-round fallback). **DECISION REQUIRED (state it in the PR):** relay-only is the deployed reality already; the mitigation is presig provisioning (proxy `background_replenish` + container/DO provisioning), and relay-empty must return a CLEAR error (it does: "presignature pool empty — provisioning is not keeping up"). Confirm the proxy background replenish + the container presig provisioning keep the pool stocked under a multi-sign run (the multi-input gate above exercises this). Do NOT re-introduce a hidden 4-round fallback — that defeats the issue.
3. **`createAction` HD-derived inputs:** today `create_action_impl` signs every input with the root key (`offset=None`). That's unchanged by this issue and fine — note it, don't expand scope.

## 4. The re-route (createSignature + createAction → relay-only)

`create_signature_impl` (wallet_api.rs ~L1193):
```rust
// BEFORE: if state.config.relay_sign { relay_sign(state,&msg_hash,hmac_offset).await } else { bridge.sign(...) }
// AFTER:  relay_sign(state, &msg_hash, hmac_offset).await   // relay-only; no 4-round branch
```
`create_action_impl` (per-input loop, ~L1512):
```rust
// BEFORE: if state.config.relay_sign { relay_sign(state,&sighash,None).await } else { bridge.sign(...) }
// AFTER:  relay_sign(state, &sighash, None).await
```
- `ProxyConfig::relay_sign` (config.rs) becomes vestigial — either hard-pin it true (and assert at startup) or remove the field + all `relay_sign: false`/`true` literals in tests. Removing is cleaner but touches ~11 test sites (§5).

## 5. Test plan (RECONCILED — and a correction)

**`tests/e2e.rs` (root, 6 scenarios over local HTTP, `relay_sign:false`, `max_presignatures:0`):** scenarios 3 (`test_signature_roundtrip`), 6 (`test_all_endpoints_no_panic`→createSignature), 7 (`test_derived_key_signing`), 8 (`test_mainnet_transaction`→createAction) drive the 4-round path and **WILL break on deletion**. Scenarios 1,2,4,5 are local-only (health/derive/encrypt/hmac) — unaffected.
- **Migration reality check:** e2e.rs runs proxy ↔ a LOCAL service/worker over HTTP with NO MessageBox relay. The relay path needs a relay. So you cannot just flip `relay_sign:true` in-process unless you stand up a relay + presig provisioning in the harness. **Two options — pick one and state it:** (a) point e2e.rs signing scenarios at the live relay (`MESSAGEBOX_RELAY_URL`) + a presig-provisioned local cosigner, gated like the other relay e2e tests; or (b) REMOVE the 4-round HTTP signing scenarios from e2e.rs and rely on the deployed relay mainnet tests + the hermetic relay tests for signing coverage (keep 1,2,4,5). Option (b) is simpler and loses no real coverage (the 4-round path has ZERO mainnet proof; relay has five TXIDs). Recommend (b), but justify it in the PR.

**Proxy tests with `relay_sign:false` (~6 files):** AUDIT FINDING — **none of them call `bridge.sign`**; they all call relay combiners directly (`sign_over_relay`/`sign_from_bundle_over_relay`/`reshare_*`). They will NOT break on deletion. If you remove the `relay_sign` config field, you must update these literals, but their behavior is unaffected.

**⚠️ DO NOT DELETE `crates/bsv-mpc-core/tests/conformance_07_brc31_auth.rs`.** The tests-audit agent recommended deleting it as "redundant /sign/init auth coverage" — that is **WRONG**. conformance_07 (+ conformance_07b, added 2026-05-23) byte-lock the canonical §07 BRC-31 General-message *auth wire* (Peer ↔ bsv-middleware-rs), independent of `/sign/init`. Deleting it loses §07 cross-impl conformance. Leave it.

**Unit tests:** signing.rs has ~9 local unit tests; keep those that test `process_round`/state, remove only ones that drive the now-deleted `init_round`/`sign`. handlers.rs has no unit tests for the sign handlers.

## 6. KEEP list (shared infra — deleting these breaks DKG/presign/relay)

- `bridge.rs::kss_post`, `bundle_messages`, `hex_encode/decode` — used by DKG + presign. KEEP.
- service `handlers.rs::bundle_outgoing_messages`, `COORDINATOR_STORE`, `load_share_or_recover`, `authz_owner`; `auth.rs::verify_or_allow` — shared. KEEP.
- worker `api.rs::bundle_outgoing_messages`, `unbundle_incoming_message` (+ their 13 unit tests) — used by DKG/presign. KEEP.
- `SigningCoordinator::process_round` + presig/bundle methods — relay combiner uses them. KEEP.
- ALL relay sign code (service `sign_relay_handler.rs`/`relay_handlers.rs`, worker `poc.rs::handle_prod_sign_relay`) — KEEP.
- `bridge.rs` Presign/DKG/ECDH wire types — KEEP.
- DKG `/dkg/{init,round}` + presign `/presign/{init,round}` HTTP paths — OUT OF SCOPE (the issue's "converge framings" only converges the SIGNING framing to relay-only; DKG/presign HTTP framing stays — note this and don't expand scope).

## 7. THE PLAN (do this, in order)

1. **Close the multi-input gap FIRST (the new gate).** Write `crates/bsv-mpc-proxy/tests/createaction_multi_input_relay_mainnet_e2e.rs` (gate env e.g. `CONTAINER_MULTI_RELAY_MAINNET=1`): DKG vs container → joint addr; fund ≥2 UTXOs to it (one wallet `createAction` with 2 outputs, or two funding txs); provision ≥2 presigs to BOTH pools; drive the proxy `createAction` (or a per-input `sign_over_relay` loop) spending both UTXOs in ONE tx; pre-flight verify each input under the joint key; broadcast; **independently confirm on WhatsOnChain that the spend has ≥2 `vin` each spending a funding UTXO.** Mirror `createaction_relay_mainnet_e2e.rs` + the broadcaster from `container_reshare_deployed_mainnet_e2e.rs` (it has the TAAL bearer token — the bare sec0617 broadcaster 401s; see #26 handoff lesson). Deploy is already offset-aware (`e45315b6`+).
2. **Delete + re-route** per §2/§4/§6. Branch `feat/13-retire-4round-sign`.
3. **Migrate/trim e2e.rs** per §5 (recommend option b).
4. **Re-verify dead code:** after deletion, grep for `init_round`/`SigningCoordinator::sign(`; delete if unused. `cargo build` the whole workspace; fix every break (the deleted KSS routes/types, the e2e scenarios).
5. **Gates (ALL re-run by you):** `cargo test` workspace; every `conformance_*` green (esp. 07/07b — must NOT be deleted); `cargo clippy -p bsv-mpc-core -p bsv-mpc-proxy -p bsv-mpc-service -p bsv-mpc-worker --all-targets -- -D warnings`; `cargo clippy -p bsv-mpc-worker --target wasm32-unknown-unknown -- -D warnings`; `cargo build -p bsv-mpc-worker --target wasm32-unknown-unknown`. Then **deploy** the slimmed container (`cd poc/cf-container-p2 && eval "$(grep '^export CLOUDFLARE' ~/bsv/mpc/bsv-mpc/secrets.md)" && npx wrangler deploy`; confirm `/reshare-relay/identity` 200) and re-run at least ONE existing deployed base-key relay mainnet gate (e.g. `createaction_relay_mainnet_e2e`) + the NEW multi-input gate to prove the slimmed KSS still signs.
6. **Deploy-smoke:** `DEPLOY_SMOKE=1 cargo test -p bsv-mpc-proxy --test deploy_smoke_e2e --release` (asserts deployed health + auth) — and confirm it doesn't assert on `/sign/{init,round}` (update if it does).

## 8. Done = (the 110% bar)
- `bridge.sign` + `/sign/{init,round}` (proxy types + service + worker handlers/routes) deleted; `init_round`/`sign` removed if dead; createSignature + createAction relay-only; `relay_sign` config vestigial-pinned-or-removed.
- Workspace builds; all conformance harnesses green (07/07b intact); clippy `-D warnings` clean (native + wasm); e2e.rs migrated/trimmed and green.
- **NEW deployed mainnet TXID: a multi-input `createAction` over the relay**, ≥2 `vin` each spending a funding UTXO, WoC-confirmed by you. Plus a re-run of an existing base-key relay mainnet gate against the slimmed/redeployed container.
- PR states the presig-starvation decision (relay-only; provisioning is the mitigation; no hidden 4-round fallback).
- Comment the TXID(s) on #13, update STATUS.md, write a memory note.

## 9. Environment / gotchas
- Container: `https://bsv-mpc-service-container.dev-a3e.workers.dev`; Relay: `https://rust-message-box.dev-a3e.workers.dev`. Deploy token: `eval "$(grep '^export CLOUDFLARE' ~/bsv/mpc/bsv-mpc/secrets.md)"`. Wallet for sats: `localhost:3321`, Origin `http://admin.com` (funded).
- **Broadcaster:** use the `broadcast_via_arc` from `container_reshare_deployed_mainnet_e2e.rs` (carries the TAAL `Authorization: Bearer mainnet_9596de07e92300c6287e4393594ae39c`). The bare sec0617 broadcaster 401s on TAAL and may fail funding propagation (cost a real-sats run during #26 — don't repeat).
- bsv-rs is **0.3.12** (crates.io) since #26 (adds `SymmetricKey::encrypt_with_iv`). Don't downgrade.
- Re-run EVERY gate yourself. The 4-round path has ZERO mainnet proof and the relay path has five TXIDs — retirement is genuinely zero-coverage-loss, but the multi-input gate is the one new proof you MUST produce.
