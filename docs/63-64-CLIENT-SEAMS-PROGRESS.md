# #63 + #64 — native-client FFI seams (live progress)

> Two HIGH-LEVEL FFI seams 100cash binds to, in `crates/bsv-mpc-client`. Rust owns ALL
> crypto/auth; Swift = Secure Enclave + UI. Companion to `docs/HANDOFF-41-CLIENT-AND-63-RELAY.md`.
> Started 2026-05-27. Everything on `main`, no commit without showing diff + approval.

## Locked design (user, 2026-05-27)
- **Factor = path a-extended.** Move DKG-over-HTTP + presign-over-relay + a shared BRC-31
  `RelaySession` out of `bsv-mpc-proxy` into `crates/bsv-mpc-relay` (where the combiner already
  lives). Re-point the proxy. NO axum/server in the iOS staticlib. Proxy 157/157 must stay green.
- **sign() = presig pool (fast path).** `sign(sighash, protocol?, key_id?, reason) -> signature`
  = biometric unseal (KeyStore → Zeroizing) + take a ready §06.17.1 bundle + ONE relay round-trip
  to the deployed container (cosigner partial) + combine + fail-closed pre-flight. Heavy presign
  runs OFF the tap path (opportunistic top-up; on-demand fallback if pool empty).
- **Biometric per spend + opportunistic top-up.** Every fund-bearing sign re-taps the Secure
  Enclave; share held only as `Zeroizing` per-op (narrowest F2 exposure window).
- **God-tier gates, no asterisks:** real WoC TXID for #63 (vs LIVE deployed container; local
  verify first); real authed live-backend round-trip with server response-sig VERIFIED for #64.

## Proven end-to-end recipe (blueprint)
`crates/bsv-mpc-proxy/tests/container_sec0617_deployed_mainnet_e2e.rs` (mainnet TXID `8b5b954a…`):
`run_dkg_over_http_authed` → `coordinate_presign_bundle` → `sign_from_bundle_over_relay`. The two
`MpcBridge` methods are thin glue over already-free fns; `Brc31Client` is already in `bsv-mpc-core`.

## Task board
| # | Task | Status |
|---|------|--------|
| 1 | relay: add `RelaySession` (BRC-31) | ✅ done |
| 2 | relay: move DKG-over-HTTP + presign-over-relay in; re-point proxy | ✅ done |
| 3 | verify proxy stays green (157/157, clippy, fmt) | ✅ done — 157/157, clippy clean |
| 4 | client native-io: presig pool + ceremony + pre-flight | ✅ done — 20 tests (incl. 4 fail-closed pre-flight) |
| 5 | export high-level async `sign()` over UniFFI | ✅ done — Swift/Kotlin bindings generate |
| 6 | #63 T3: ceremony verify → mainnet TXID vs LIVE container | ✅ DONE — mainnet TXID `60cccb06…` |
| 7 | #64 storage seam: port WorkerStorageClient + `rpc()` UniFFI | ✅ done — LIVE round-trip, response-sig verified |

## What shipped (all on `main` tree, UNCOMMITTED — awaiting diff review)
**Factor (a-extended):** `crates/bsv-mpc-relay` now hosts `session.rs` (`RelaySession`),
`dkg.rs` (`run_dkg_over_http{,_authed}`), `presign.rs` (`coordinate_presign_over_relay`) +
the existing combiner. Proxy `bridge.rs` re-points to them (`BridgeAuth`→`RelaySession`,
deleted ~330 LOC of moved code); `relay_presign` module → `pub use bsv_mpc_relay::presign`.
**Proxy stayed 157/157 green.**

**Client native-io** (`crates/bsv-mpc-client/src/native_io/`, native-only, `Send+Sync`):
- `keystore.rs` — `NativeKeyStore` (Send+Sync async Enclave seam) + `MemNativeKeyStore`.
- `ceremony.rs` — `DeployedCosigner`: provision_via_dkg / connect / coordinate_presig /
  sign_from_bundle (reuses the shared crates; glue mirrors `MpcBridge`).
- `signer.rs` — `DeployedSigner`: biometric-per-spend `sign()` over a single-use presig
  pool (`BundleStore::consume`) + on-demand fallback + `top_up_presigs()`; pure
  `preflight_verify_sig` (low-s + joint-key, BRC-42 child path) with 4 unit tests.
- `storage.rs` — #64 `WorkerStorageClient` port (BRC-103/104 on reqwest) + response-sig verify.
- `ffi.rs` — `FfiDeployedSigner.sign()` (async) + `FfiKeyStore` callback interface +
  `WalletStorageConn.rpc()` (async). Swift+Kotlin bindings generate clean.

## Gates green
- proxy lib 157/157; clippy `-D warnings` on relay+proxy, client default+`--features native`+wasm32.
- client: 20 unit tests (8 orig + 12 native_io incl. 4 fail-closed pre-flight + BRC-42 child).
- #64 LIVE: handshake + `makeAvailable` + `listOutputs` vs `wallet-infra.x402agency.com`,
  **server response-sig verified**, tampered request rejected.
- #63 FREE ceremony verify: client signed vs the LIVE deployed cosigner over the LIVE relay,
  combined sig **verifies under joint key `03e3cf70…`** (addr `16NoPDh7…`) — protocol asterisk killed, 0 sats.
- **#63 T3 MAINNET GATE (god-tier, no asterisks):** the client's high-level `sign()` signed a
  REAL spend vs the deployed container over the live relay → **TXID
  `60cccb0650745aa8d08c88ad60f7cc4cd377a1c460c93ea3bce68fbaf10ed61b`** (SEEN_ON_NETWORK; joint
  `02e8a456…`, funded by `ee472a37…`, fail-closed pre-flight inside `sign()`).

## No-regression verification (2026-05-27)
- `cargo build --workspace` clean; `cargo test --workspace --no-run` — EVERY crate's tests
  (incl. all proxy integration tests referencing the re-exported `run_dkg_over_http_authed` /
  `relay_presign`, + root `tests/e2e.rs`, worker, service, overlay, poc16) compile.
- proxy lib **157/157** pass; clippy `-D warnings` green on relay + proxy + client
  (default native / `--features native` / wasm32). Nothing committed yet.

## Log
- 2026-05-27: design locked (3 AskUserQuestion decisions). Factor landed green (proxy 157/157).
  native_io ceremony+pool+pre-flight built (20 tests). FFI exported (bindings generate). #64
  integrated from worktree + LIVE-verified. #63 free ceremony verify PASSED. Mainnet T3 launched
  (real-money cleared). Nothing committed — diff pending review.
