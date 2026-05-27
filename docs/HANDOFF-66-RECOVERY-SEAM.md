# HANDOFF — #66 native-client RECOVERY seam (the 4th FFI seam)

> **Read this + GitHub issue #66 in full, then `gh issue view 66`.** This is the handoff for
> building the recovery seam in a fresh window. Written 2026-05-27 right after the
> create/sign/storage trio (#65/#63/#64) shipped + the #5 hardening closed. Canonical repo:
> `~/bsv/mpc/bsv-mpc`. Everything below is on `main`, pushed.

---

## 0. TL;DR — what #66 is

The **4th** high-level FFI seam 100cash binds to, completing the set: **#65 create · #63 sign ·
#64 storage · #66 recover**. Export, over UniFFI:

```
async recover_wallet(relay_url, container_url, identity_key_hex, at_rest_root_hex,
                     bundle_dir, policy_id_hex, backup_factor, keystore) -> FfiSignerConfig
```

It runs the **address-preserving reshare** of the EXISTING wallet onto a fresh/lost-phone device
(joint pubkey UNCHANGED — no funds move, same address), device-seals the new share via the host's
`FfiKeyStore.seal_share` callback, and returns the `FfiSignerConfig` the host persists + feeds
straight to `FfiDeployedSigner::connect` (same shape `create_wallet` #65 returns). This removes the
**last `notImplemented` mock** on 100cash's native ceremony path
(`RealMpcCeremonyService.recoverOntoThisDevice()`).

Contrast with #65 `create_wallet`: create mints a NEW wallet (new address via DKG); recover reshares
the SAME wallet (same address). That's the whole difference at the seam.

---

## 1. The ONE thing that makes #66 bigger than #65 (read this)

#65 was a thin wrap because `coordinate_presign_over_relay` was **already a free function**. For #66
the reshare orchestration is **NOT yet a free fn** — it lives inside `MpcBridge`:

- **`MpcBridge::reshare_change_threshold_over_relay`** — `crates/bsv-mpc-proxy/src/bridge.rs:1307`
  (~400 LOC). Drives the whole §18.2 reshare-over-relay: `ResharCoordinator` + a relay listener +
  the throwaway-DKG-for-aux + `combine_reshared_with_aux`, using the `relay_reshare` helpers. The
  **joint-pubkey-unchanged invariant** is `bridge.rs:158` (the `ReshareSummary` type).

Reusable AS-IS (no factoring needed):
- **`bsv_mpc_core::reshar_coordinator`** — `ResharCoordinator::{new,init,process_round}` +
  `combine_reshared_with_aux` + `ContributorInputs`/`ResharConfig`/`ResharCommit`. Inline, wasm-safe
  (core). `crates/bsv-mpc-core/src/reshar_coordinator.rs`.
- **`crate::relay_reshare`** helpers — `fetch_peer_identity`, `arm_container`, `ReshareRelayPeer`,
  `ContainerArm`, `RequestSigner` (free fns, `crates/bsv-mpc-proxy/src/relay_reshare.rs`).

**So the recipe is the a-extended factor again** (exactly what commit `24767b8` did for DKG+presign):
1. Factor `reshare_change_threshold_over_relay`'s orchestration out of `MpcBridge` into a shared free
   fn in `crates/bsv-mpc-relay` (e.g. `coordinate_reshare_over_relay(...)`), and move the
   `relay_reshare` helpers into the relay crate too (mirror how `relay_presign` → `bsv_mpc_relay::presign`).
   Re-point the proxy via `pub use` so `crate::relay_reshare::*` + the bridge method still resolve;
   **proxy lib tests must stay green** (currently 157/157).
2. Then the client `native_io/recover.rs` (mirror `native_io/provision.rs`) calls the shared fn,
   seals via `NativeKeyStore::seal_share`, returns a `ProvisionedWallet`-shaped result.
3. `ffi.rs`: `recover_wallet` export (mirror `create_wallet`), reusing `FfiKeyStore`/`FfiSignerConfig`.

If the factor's blast radius is too big at session-tail, the fallback is path (b): replicate the
orchestration in `native_io/recover.rs` (duplication, real-money divergence risk) — NOT recommended;
prefer the factor.

---

## 2. The build pattern to MIRROR (from #65, proven)

Everything #66 needs already has a working twin from this session:

| #66 piece | Mirror this (#65/#63) |
|---|---|
| `native_io/recover.rs` (DKG-reshare glue → seal → metadata) | `crates/bsv-mpc-client/src/native_io/provision.rs` (`provision_wallet`) |
| reshare transport/auth | `native_io/ceremony.rs` (`DeployedCosigner` — connect/BRC-31 `RelaySession`/`request_signer_over`) |
| `#[uniffi::export] async recover_wallet -> FfiSignerConfig` | `ffi.rs::create_wallet` (verbatim template; same args + `FfiKeyStore` + `FfiSignerConfig`) |
| seal the recovered share | `FfiKeyStore.seal_share` (ALREADY added in #65 — done) |
| metadata struct | `signer::WalletMeta` / `FfiSignerConfig` (reuse) |
| free E2E + mainnet gate | `crates/bsv-mpc-client/tests/deployed_sign_e2e.rs` (copy the structure) |
| proxy mainnet blueprint | `crates/bsv-mpc-proxy/tests/recovery_spend_deployed_mainnet_e2e.rs` (the #40 recovered-spend, mainnet-proven — the reshare→spend recipe) |

The shared BRC-31 client `bsv_mpc_relay::RelaySession` (handshake + `auth_header_pairs`) is what the
client uses for the container triggers — reuse it.

---

## 3. The OPEN design question — ASK THE USER FIRST

Before finalizing `recover_wallet`'s signature, confirm the **recovery-factor wire shape** (#66 honest
boundary). The factor is the input that lets THIS fresh device participate in the reshare:
- **L1 (same ecosystem):** the passkey-PRF-unwrapped **backup share B** (`Vec<u8>` / `Data`). Simplest;
  the device contributes the recovered share material into the reshare.
- **L2 (trustees):** trustee participation over the relay (links to #40's lost-phone ceremony). Different
  wire (the new device has NO prior share; survivors reshare onto it).
- **L3:** cold-device.

These have DIFFERENT `recover_wallet` signatures (a `backup_factor: Vec<u8>` vs a trustee-coordination
flow). Pick the v1 scope with the user (likely L1 first, typed hook for L2) before writing the export.
Identity ≠ custody: an OAuth subject is never a recovery factor.

---

## 4. Proof plan (110%, no asterisks — same bar as #63/#65)

- **T1 unit:** returned `FfiSignerConfig` round-trips into `FfiDeployedSigner::connect`; `seal_share`
  invoked with the resharded share; **joint pubkey == original** (the #35 invariant).
- **T2 E2E (free, no sats):** `create_wallet` → drop the sealed share (simulate device loss) →
  `recover_wallet` onto a FRESH `MemNativeKeyStore` → `connect` → `sign` → signature verifies under the
  **SAME** joint key. Reuse the `deployed_sign_e2e` harness + the #58 reshare path.
- **T3 (real sats):** a real mainnet spend from a wallet recovered ENTIRELY through `recover_wallet` →
  WoC-confirmed TXID, **same address as before loss**. Fund via wallet:3321 (Origin `http://admin.com`),
  broadcast via gorillapool ARC, fail-closed pre-flight. Per-run real-money clearance.
- Swift+Kotlin bindings generate (`cargo run -p bsv-mpc-client --features native --bin uniffi-bindgen
  -- generate --library target/debug/libbsv_mpc_client.dylib --language swift --out-dir /tmp/x`).

---

## 5. Discipline gates (non-negotiable)

- **NO commit/push/PR without showing the diff + approval.** Ask the user for any real decision.
- clippy `-D warnings`, `CARGO_INCREMENTAL=0`, on: `-p bsv-mpc-client` default native, `--features native`
  `--all-targets`, AND `--target wasm32-unknown-unknown --tests`. Same for any factored crate
  (`-p bsv-mpc-relay -p bsv-mpc-proxy --all-targets`).
- **wasm must stay clean:** native-only deps go under `[target.'cfg(not(target_arch="wasm32"))'.…]`;
  native_io is gated `#[cfg(not(target_arch="wasm32"))]`. (The reshare path is native-only — same as sign.)
- **Format only edited files** (`rustfmt --edition 2021 <file>`); NEVER rustfmt a crate root (`lib.rs`)
  — it cascades. Enforced gate is clippy, not fmt.
- **Validate, don't skip:** assert rejection paths reject for the right reason (wrong factor, wrong key,
  joint-pubkey-changed → reject).
- Real-money: local/free verify BEFORE any mainnet spend; per-run clearance.

---

## 6. Deployed infra + commands (confirmed live this session)

| Thing | Value |
|---|---|
| Container cosigner (heavy MPC; DKG/presign/reshare/§06.17.1) | `https://bsv-mpc-service-container.dev-a3e.workers.dev` — Version `2ef9d7fd` (rate-limited). `GET /presign-relay/identity` → 200 (404 = stale). |
| Worker isolate (light) | `https://bsv-mpc-kss.dev-a3e.workers.dev` — Version `2530f946` (primes sealed). |
| MessageBox relay | `https://rust-message-box.dev-a3e.workers.dev` (BRC-31-gated) |
| Funding wallet | `http://localhost:3321` — header `Origin: http://admin.com`; `getPublicKey {identityKey:true}`; broadcast self via ARC `https://arc.gorillapool.io/v1/tx` (keyless, works). |
| Deploy container | `cd poc/cf-container-p2 && eval "$(grep '^export CLOUDFLARE' ~/bsv/mpc/bsv-mpc/secrets.md)" && npx wrangler deploy` (CONTAINERS_TOKEN; injects `MPC_SERVER_PRIVATE_KEY` secret → enforced auth). |
| Deploy worker | `cd crates/bsv-mpc-worker && eval "$(grep '^export CLOUDFLARE' …secrets.md)" && npx wrangler deploy` (API_TOKEN). |

Deploys are OUTWARD + the container is what 100cash uses live — confirm before deploying; rate limit is
generous per-identity (60 burst / 1-per-sec) so distinct identities are unaffected.

---

## 7. Gotchas learned this session (don't rediscover)

- **wasm tokio dev-dep split:** the deployed E2E needs `tokio` `rt-multi-thread`/`time`/`net`, but `net`
  pulls `mio` which can't compile to wasm32. Keep the base `[dev-dependencies]` tokio `mio`-free
  (`default-features=false, features=["rt","macros"]`); put heavy features in
  `[target.'cfg(not(target_arch="wasm32"))'.dev-dependencies]`.
- **`wrangler.toml.example` pre-commit guard:** the `wrangler.toml` substring trips a secret-guard hook
  (even on a staged deletion). The template is now `wrangler.example.toml`. Don't reintroduce the old name.
- **Container cold-start resets the in-memory rate bucket:** the singleton container's `RateLimiter` is
  in-memory; right after a deploy the first burst can miss 429 (instance warming). Warm, it's deterministic.
- **`MemNativeKeyStore`** (`native_io/keystore.rs`) is the test Enclave stand-in (`seal_share`/`unseal_share`).
- **`SessionId(pub [u8;32])`** — `.hex()` ↔ `from_bytes`/`from_hex` (64-char). `FfiSignerConfig.dkg_session_id_hex`
  uses `.hex()`.
- **`PrivateKey::to_bytes() -> [u8;32]`**; pre-flight = low-s + `joint.verify` (or `joint+offset·G` for HD).
- **Container generates primes ephemerally in-memory** (no at-rest exposure); reshare-for-aux uses
  `seed_primes_late` / `generate_serialized` over the relay (§06.17 ordering) — relevant if recover triggers
  a throwaway-DKG-for-aux.

---

## 8. This session's ledger (all on `main`, pushed)

| Commit | What |
|---|---|
| `24767b8` | `refactor(#63)`: factor DKG+presign+BRC-31 session → `bsv-mpc-relay` (a-extended) — **the template for #66's reshare factor** |
| `f5b40b9` | `feat(#63,#64)`: client sign seam + storage seam over UniFFI |
| `891ee0f` | `feat(#65)`: provisioning seam — `create_wallet` (DKG→seal→`FfiSignerConfig`) — **the template for #66's `recover_wallet`** |
| `5b2e790`+`3e0f1d0` | `feat(#5)`: primes at-rest + deployed gate |
| `cc221fe`+`38fb83c` | `feat(#5)`: rate limiting + deployed gate |
| `f4ff7fe` | `docs(#5)`: hardening backlog closed |

Mainnet TXIDs: #63 `60cccb0650745aa8d08c88ad60f7cc4cd377a1c460c93ea3bce68fbaf10ed61b`,
#65 `a8909cffcb575967f3b8a8d3aebc627c74177b9f56ebd896d1e5b61ca450c00c`.
Closed this session: #63, #64, #65, #55, #5. Open: **#66 (this)**, #56 (multi-device design), #41
(on-device, 100cash), #37/#2 (umbrellas).

Companion docs: `docs/HANDOFF-41-CLIENT-AND-63-RELAY.md` (the locked §4.5 architecture),
`docs/63-64-CLIENT-SEAMS-PROGRESS.md`, `docs/HANDOFF-40-deployed-reshare-fixed.md` (the reshare internals).

## 9. First moves in the new window
1. `gh issue view 66`; read this doc + `docs/HANDOFF-41-CLIENT-AND-63-RELAY.md` §4.5.
2. **Ask the user the §3 recovery-factor design question** (L1 backup-share vs L2 trustee) before coding.
3. Read the blueprint: `bridge.rs:1307` (`reshare_change_threshold_over_relay`), `relay_reshare.rs`,
   `reshar_coordinator.rs`, and `tests/recovery_spend_deployed_mainnet_e2e.rs`.
4. Factor reshare orchestration → `bsv-mpc-relay` (mirror `24767b8`); keep proxy 157/157 green.
5. `native_io/recover.rs` + `ffi.rs::recover_wallet` (mirror `provision.rs` + `create_wallet`).
6. Gate: T1 unit → T2 free (create→lose→recover→sign→same key) → T3 mainnet recovered-spend (same address).
