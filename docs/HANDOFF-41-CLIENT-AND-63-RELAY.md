# HANDOFF (EXTENDED) — #41 native client (mainnet-proven) + #63 relay transport

> **Read this first, in full.** Definitive handoff for the bsv-mpc **native client** track (#41) and the
> **client↔deployed-cosigner relay sign** (#63). Written 2026-05-26 after a long build session that took
> #41 from audit → **mainnet-proven** and shipped #63 step 1. Canonical repo: `~/bsv/mpc/bsv-mpc`.
> Everything below is on `main`; every gate was green; nothing was committed without showing a diff first.

---

## 0. TL;DR / where we are

- **#41 native client = built Phases 1→5 and MAINNET-PROVEN.** A brand-new crate `crates/bsv-mpc-client`
  wraps `bsv-mpc-core` (zero `rust-mpc`/Binary dep). `WalletClient::sign` produced a **real, WoC-confirmed
  mainnet threshold-ECDSA tx**: **TXID `d238e447975fe54f562ea73fe30d20e27b3608cafe1729adcb09b88d4c0b7dd6`**
  (funded from `5ad14133…` via wallet:3321; both SEEN_ON_NETWORK via GorillaPool ARC).
- **#63 (client signs vs the DEPLOYED cosigner over the live relay) = step 1 shipped, T3 scoped.** The
  relay-sign combiner was factored into shared crate `crates/bsv-mpc-relay` (commit `8426621`). The
  deployed container is **confirmed live**. The remaining T3 work (the real client↔deployed-container
  mainnet TXID) needs the `MpcBridge` §06.17.1 orchestration — a focused, real-money next step, **not yet
  done** (deliberately not rushed at session tail).
- **The single honest asterisk on #41:** the biometric tap used `InMemoryKeyStore` (the audited Secure-
  Enclave stand-in), not a physical device. Closing it = wire `bsv-mpc-client`'s UniFFI into **100cash**
  (the **Calhoun** iOS app — `~/bsv/mpc/100cash`, `Sources/Crypto/EnclaveKeyStore.swift`) and run on real
  hardware. (100cash is Calhoun-side; only `rust-mpc` is the Binary boundary.)

---

## 1. The `bsv-mpc-client` crate (what exists, file by file)

`crates/bsv-mpc-client/` — target-agnostic core + two FFI skins. Builds **native, wasm32, and
`--features native`**; clippy `-D warnings` on all three; fmt-clean; secrets `Zeroizing` end-to-end.

| File | What it is |
|---|---|
| `src/lib.rs` | module wiring + re-exports; `pub use bsv_mpc_core::SigningResult`; `#[cfg(target_arch="wasm32")] pub mod wasm`; `#[cfg(feature="native")] pub mod ffi` + `uniffi::setup_scaffolding!()` |
| `src/error.rs` | `ClientError` (thiserror) + `From<MpcError>`/`From<serde_json::Error>`. **`NotImplemented(&'static str)`** for staged paths (no panic/`todo!`) |
| `src/keystore.rs` | **`KeyStore` trait** (`seal_share`/`unseal_share → Zeroizing<Vec<u8>>`, biometric `reason`) + functional **`InMemoryKeyStore`** (sim/CI; the enclave stand-in) |
| `src/storage.rs` | **`WalletStorage` trait** + `StoredShare` *metadata* (agent_id, share_index, threshold, parties, session_id:Vec<u8>(32), joint_pubkey:Vec<u8>). The share material lives device-sealed in the KeyStore, NOT here. |
| `src/chain.rs` | **`ChainServices` trait** + `Utxo` / `BroadcastResult` |
| `src/transport.rs` | **`RoundTransport` trait** (`exchange(outgoing)->incoming`). NOTE: this generic symmetric shuttle fits an *in-process* cosigner; the **deployed** cosigner is asymmetric (HTTP trigger + relay receive) — see §4. |
| `src/txbuild.rs` | **pure, wasm-safe tx helpers** lifted verbatim from proxy `wallet_api.rs:186-452` (sha2+hex only): `compute_bip143_sighash`/`SighashParams`, `serialize_signed_tx`, `parse_tx_outputs`, `compute_txid`, P2PKH script builders, varints, `estimate_mining_fee`. Plus `demo_sighash`/`demo_serialized` golden-vector fns. |
| `src/signer.rs` | **`unseal_signing_scalar(keystore, agent_id, reason) -> Zeroizing<[u8;32]>`** — biometric unseal → `bsv_mpc_core::ecdh::parse_share_scalar`. The secret hot path. |
| `src/client.rs` | **`WalletClient`** (the core). `new` / `agent_id` / `provision_share` / `list_agents` / `list_utxos` / **`derive_address`** (BRC-42 anyone, local) / **`sign`** (real 2-party threshold over an injected `RoundTransport`). All real, no stubs. |
| `src/wasm.rs` | `#[cfg(wasm32)]` **wasm-bindgen skin**: `txTxid`/`txOutputSats` (JS-callable). wasm-bindgen is a wasm32-target dep (native never pulls it). |
| `src/ffi.rs` | `#[cfg(feature="native")]` **UniFFI skin**: `FfiError`, `ffi_tx_txid`/`ffi_tx_output_sats`, and **`FfiSigningSession`** (uniffi::Object) + `FfiSignStep` (uniffi::Enum) — a **sync host-driven signing state machine** (the proven `rust-mpc/clients/native` sans-io pattern: host owns I/O + biometric, pumps round messages; Rust is a pure sync transform). |
| `src/bin/uniffi-bindgen.rs` | `uniffi::uniffi_bindgen_main()` (native feature) — generates Swift/Kotlin bindings from the dylib |
| `tests/wasm32_txbuild.rs` | `#[wasm_bindgen_test]` — wasm sighash/serialize **byte-identical to native** golden + the wasm-bindgen skin. Run: `wasm-pack test --node -p bsv-mpc-client --test wasm32_txbuild` |
| `tests/hermetic_sign.rs` | the heavy native E2Es (`#![cfg(not(wasm32))]`): real DKG+aux via round_based sim (`dkg_key_shares`), `InProcessCosigner` relay stand-in, **`wallet_client_signs_a_real_threshold_ecdsa_signature`** (Tier 4.1, BSV-SDK-verified), `ffi_signing_session_drives_a_real_threshold_signature` (`--features native`), and **`mainnet_capstone_client_signs_real_tx`** (gated `E2E_MAINNET=1`). |

### Cargo features / deps (client)
- default: core deps only (bsv-mpc-core, zeroize, async-trait, serde/serde_json/hex/sha2/thiserror).
- `native` = `["dep:uniffi"]` (UniFFI skin). `[lib] crate-type = ["lib","cdylib","staticlib"]`.
- wasm32-target dep: `wasm-bindgen`. wasm32-dev-deps: `wasm-bindgen-test`, `getrandom/js`.
- native-only dev-deps (for hermetic + mainnet tests): `cggmp24` (with **`spof`** feature = `trusted_dealer`),
  `generic-ec`, `rand`, `round-based` (sim), `futures`, `pin-project`, `bsv`, `reqwest`, `serde_json`, `tokio`.

---

## 2. Commit ledger (this session, all on `main`, pushed)

| Commit | What |
|---|---|
| `6109479` | `feat(#41)`: **zeroize** core accessors → `Zeroizing<T>` (ecdh::parse_share_scalar, share::decrypt_share, derive_share_encryption_key) |
| `11121ab` | `feat(#41)`: Phase 1 — scaffold the crate (3 traits + InMemoryKeyStore + WalletClient) |
| `bcaf011` | `feat(#41)`: Phase 2 — `txbuild.rs` lifted; wasm byte-identical; `derive_address` |
| `b413252` | `feat(#41)`: Phase 3 — `signer::unseal_signing_scalar` hot path (real cggmp24 share) |
| `3db42ca` | `feat(#41)`: Phase 4a-i — wasm-bindgen skin |
| `327db06` | `feat(#41)`: Phase 4a-ii — UniFFI skin (Swift+Kotlin bindings generate) |
| `e187e12` | `feat(#41)`: Phase 4b — `WalletClient::sign` real 2-party sign + hermetic Tier-4.1 test |
| `9e23a0e` | `feat(#41)`: Phase 4c — `FfiSigningSession` host-driven UniFFI signing state machine |
| `441fe22` | `test(#41)`: **Phase 5 mainnet capstone** — TXID `d238e447…` |
| `8426621` | `refactor(#63)`: factor `relay_sign` → shared `bsv-mpc-relay` crate (proxy 157/157 pass) |

Foundational (toolbox repo `~/bsv/rust-wallet-toolbox`): `65a59f1` — bump bsv-rs 0.3.4→0.3.13, pushed
branch `chore/bump-bsv-rs-0.3.13` (NOT merged).

---

## 3. The mainnet capstone (#41 Phase 5) — exactly how it worked

`tests/hermetic_sign.rs::mainnet_capstone_client_signs_real_tx` (gated `E2E_MAINNET=1`):
1. local 2-of-2 DKG (`dkg_key_shares(2,2)` — round_based sim + Blum-prime aux) → joint P2PKH.
2. **fund** the joint locking script via `POST http://localhost:3321/createAction` with header
   **`Origin: http://admin.com`** → response carries `txid` + `tx` (atomic-BEEF byte array). 3321's own
   broadcaster is unreliable, so **extract the raw funding tx from the BEEF and self-broadcast via ARC**
   (`raw_tx_hex_from_create_action` → `bsv::Transaction::from_atomic_beef`/`from_beef` → `.to_hex()`).
3. find the UTXO on WoC (`/v1/bsv/main/tx/hash/{txid}`, match `scriptPubKey.hex`).
4. build spend to a 3321 address (P2PKH of the identity key); BIP-143 sighash (txbuild; **version 1,
   sighash_type 0x41**, mirrors proxy `wallet_api.rs`).
5. **`WalletClient::sign`** — share device-sealed in `InMemoryKeyStore`; cosigner = `InProcessCosigner`
   (the in-process relay stand-in). Returns DER + r + s.
6. **PRE-FLIGHT, fail-closed:** `bsv::Signature::from_der`, `is_low_s()`, `joint_pub.verify(&sighash,&sig)`
   BEFORE broadcast (no malformed sig hits the network).
7. assemble (`<DER+0x41> <33-byte joint pubkey>` unlocking) + **broadcast via ARC** → WoC TXID.

**Run it:** `E2E_MAINNET=1 cargo test -p bsv-mpc-client --test hermetic_sign mainnet_capstone -- --nocapture --test-threads=1`

---

## 4. #63 — client signs vs the DEPLOYED cosigner (the next big build)

### What's done
**Step 1 (commit `8426621`):** `relay_sign` combiner factored into **`crates/bsv-mpc-relay`** (lib.rs).
Exposes `combine_sign_over_relay` / `combine_sign_over_relay_nparty` / `combine_sign_from_bundle_over_relay`
+ `DoTrigger` + `RelayRequestSigner`. Proxy re-points via `pub use bsv_mpc_relay as relay_sign;` (so all
`crate::relay_sign::…` paths still resolve). **Proxy 157/157 lib tests pass.** The client can now `use
bsv_mpc_relay::…` to reuse the EXACT mainnet-proven combiner.

### The crucial protocol fact (don't re-learn this the hard way)
The deployed cosigner does **NOT** do a generic symmetric round exchange. Relay signing is **presigned
1-round + an HTTP `/sign-relay` trigger** (the 4-round interactive path was retired in #13):
1. **combiner (client)** holds a presig → `SigningCoordinator::sign_with_presignature_with_offset` issues
   its partial locally.
2. combiner **HTTP-POSTs `/sign-relay`** to the cosigner DO (sighash + presig/ciphertext + session_id +
   recipient pub + indices).
3. cosigner issues + **relays its partial back over MessageBox** (`BOX_SIGN`); combiner filters by
   `from`+`session_id`, `process_round` → combine.

⇒ the client's generic `RoundTransport::exchange()` does **not** model the deployed cosigner. The #41
hermetic capstone passed only because both parties were in-process interactive coordinators.

### What T3 still needs (the orchestration, not just the combiner)
Driving the client↔container sign is orchestrated by **`MpcBridge`** (bsv-mpc-proxy `bridge.rs`, ~3.4K LOC):
- `run_dkg_over_http_authed(container_url, config, identity)` — 2-of-2 DKG over HTTP; container holds `share_A`.
- `MpcBridge::coordinate_presign_bundle(...)` — §06.17.1 presign over the relay; container self-presigns +
  self-encrypts → `PresigBundle`.
- `MpcBridge::sign_from_bundle_over_relay(&bundle, …)` — ships ciphertext to `/sign-relay`; container
  decrypts + co-signs; **then** the factored combiner folds it in.

The factored `bsv-mpc-relay` combiner is the *innermost* piece. **Blueprint:**
`crates/bsv-mpc-proxy/tests/container_sec0617_deployed_mainnet_e2e.rs` (mainnet-proven, TXID `8b5b954a…`).

### Two paths to T3 (decide first thing next session)
- **(a-extended) — recommended:** factor `MpcBridge`'s relay orchestration (`run_dkg_over_http_authed` +
  `coordinate_presign_bundle` + `sign_from_bundle_over_relay` + helpers) into shared code the client reuses.
  Zero duplication; bigger than the combiner factor. Watch the blast radius (bridge.rs is large + has many
  responsibilities; you only need the relay-sign orchestration path).
- **(c) — fastest:** `bsv-mpc-client` depends on `bsv-mpc-proxy` as a **library** (it's lib-usable) and calls
  `MpcBridge` directly. Heavy/architecturally-odd (client → server crate) but quickest to a TXID.
- **(b) — NOT recommended:** reimplement the orchestration in the client (large; real-money divergence risk).

### T3 gate (110%-no-asterisks) — the acceptance for #63
`bsv-mpc-client` signs a real mainnet tx where the second party is the **REAL deployed cosigner over the LIVE
MessageBox relay** → WoC-confirmed TXID. No in-process stand-in. **Verify locally first** (run the local
`bsv-mpc-service` as the cosigner) BEFORE the mainnet spend, so a refactor bug can't burn sats.

---

## 4.5 — 100cash integration seam: GOD-TIER ARCHITECTURE DECISIONS (locked 2026-05-27)

> 100cash (the **Calhoun** iOS app, `~/bsv/mpc/100cash`) has **already switched off `rust-mpc` onto our
> `bsv-mpc-client`** (its `HANDOFF.md`: "regenerated `MpcNative.xcframework` from `bsv-mpc-client`",
> `MpcSigner` drives the real `FfiSigningSession`; keygen server-side). So `research/20`'s `mpc-native`
> references now mean **`bsv-mpc-client`**. These two decisions are confirmed by **both** `100cash/research/20-real-backend-wiring.md`
> AND 100cash's current code state.

### THE PRINCIPLE (single source of truth)
**Rust (`bsv-mpc-client`) owns ALL crypto + auth + protocol orchestration. Swift owns ONLY the Secure
Enclave (the hardware biometric — the one thing Rust physically cannot do) + UI.** Every FFI seam is
**high-level** (`sign(sighash)->sig`, `rpc(method,params)->json`), never low-level crypto/auth in Swift.
No Swift secp256k1, no Swift BRC-31. This minimizes the Swift surface, prevents crypto duplication/divergence,
and the shipped XCFramework already carries the pure-Rust `k256` stack on `aarch64-apple-ios`.

### Decision 1 — the sign FFI shape (#41-4d + #63 converge here)
`RealMpcCeremonyService.sign()` binds to a **high-level async `sign(sighash, protocol?, key_id?, reason) ->
signature`** exported over UniFFI, which runs the **full deployed-cosigner ceremony INTERNALLY in Rust**
(unseal via KeyStore → presigned §06.17.1 relay sign-from-bundle → combine), with the relay/HTTP **transport
Rust-owned** (the #63 native `MessageBoxRoundTransport` / `MpcBridge` orchestration). This is `WalletClient::sign`
with a *real* transport, exported async via UniFFI.
- ❌ NOT the sans-io `FfiSigningSession` for this seam. That stays as the **lower-level primitive** (what
  `MpcSigner` drives today, host-pumps round messages) — kept for hosts that want full control, but
  `RealMpcCeremonyService` does NOT bind to it. (100cash HANDOFF §53: "full ceremony needs transport / §4 / #63".)
- The host injects **only** the `KeyStore` (Secure Enclave seal/unseal) as a UniFFI callback interface.

### Decision 2 — storage/chain ownership (research/20 option (a))
**Rust does BRC-31/103/104, not Swift.** Port `WorkerStorageClient` (`rust-middleware/bsv-auth-cloudflare/
src/client/storage.rs` — a complete, tested BRC-103/104 client: handshake + per-request BRC-104 signed
General messages + JSON-RPC, on bsv-rs `k256`) into `bsv-mpc-client`, swapping its transport from
`worker::Fetch` to portable HTTP (reqwest native / host-fetch wasm). Expose **`rpc(method, paramsJson) ->
json`** over UniFFI. `RealWalletStorageService` (Swift) binds to `rpc()`.
- ❌ Swift does NOT implement `ChainServices`/`WalletStorage` with secp256k1/BRC-31 — that would reimplement
  the proven Rust client (the "Swift has no secp256k1" blocker is *already solved* by the Rust client).
- The injected `ChainServices`/`WalletStorage`/`RoundTransport` traits in `bsv-mpc-client` remain the
  **generic/web/test** seam (host-injected JS on wasm); the **native/100cash default = the Rust-shipped
  clients** (a `native-io`-style feature). One trait surface, two backings.

### Net FFI surface 100cash binds to (the contract)
| Swift type | binds to (UniFFI) | runs where |
|---|---|---|
| `RealMpcCeremonyService.sign()` | `async sign(sighash,…) -> signature` (#41-4d/#63) | **Rust** (relay orchestration internal) |
| `RealWalletStorageService` | `rpc(method, paramsJson) -> json` (research/20) | **Rust** (`WorkerStorageClient`, BRC-31) |
| (Secure Enclave) | `KeyStore` callback interface `seal_share`/`unseal_share` | **Swift** (the ONLY native crypto-adjacent code) |
| address/tx utils | `derive_address`, `ffi_tx_txid`, … (already shipped) | Rust |

### Concrete work this implies (add to #41-4d / #63)
1. **#63 / #41-4d:** finish the Rust-owned relay orchestration (this doc §4), then export a **high-level async
   `sign()`** over UniFFI (relay transport constructed internally; KeyStore the only host callback). Keygen
   stays server-side (ceremony svc); `MpcSigner.generateKey()` currently `notImplemented` is correct.
2. **New (storage seam):** port `WorkerStorageClient` → `bsv-mpc-client` (portable HTTP) + `#[uniffi::export]
   rpc(method, paramsJson) -> json`. Likely its own focused issue under #41/#37; references research/20.
3. **DKG-over-FFI is intentionally NOT exposed** (keygen is server-side via the ceremony service).

---

## 5. Deployed infra (confirmed live 2026-05-26) + access

| Thing | URL / value |
|---|---|
| **Container cosigner** (heavy MPC: DKG/presign/§06.17.1) | `https://bsv-mpc-service-container.dev-a3e.workers.dev` — `/health`→ok, `/presign-relay/identity`→`cosigner_pub 0278138e618ebb69c8bc6af07d15e50c72d9628b2c0fd7042185ee5cf5712af0e8`, `share_count:0` (coordinator-holds-ciphertext) |
| Worker isolate (LIGHT online-sign only) | `https://bsv-mpc-kss.dev-a3e.workers.dev` |
| MessageBox relay | `https://rust-message-box.dev-a3e.workers.dev` (BRC-31-gated) |
| Funding wallet (BRC-100) | `http://localhost:3321` — **needs `Origin: http://admin.com` header**; `getPublicKey {identityKey:true}` → `03ef3231…`; funded (584 outputs) |
| Broadcast | ARC: `https://arc.gorillapool.io/v1/tx` (no auth, **works**) ; `https://arc.taal.com/v1/tx` (**401 without key — expected, gorillapool covers it**). Body `{"rawTx": hex}`; accept `SEEN_ON_NETWORK`/`STORED`/`MINED`. |
| Deploy the container | `cd poc/cf-container-p2 && eval "$(grep '^export CLOUDFLARE' ~/bsv/mpc/bsv-mpc/secrets.md)" && npx wrangler deploy` (token has Containers:Edit). Verify: `GET .../presign-relay/identity` → 200 (404 = stale image). |

---

## 6. Gotchas / hard-won facts (do not rediscover)

- **`bsv-mpc-messagebox` is NATIVE-ONLY** (tokio-tungstenite; no wasm32). So the **native** client RoundTransport
  wraps it; the **web** client injects a JS-WebSocket transport via the host seam (that's why `RoundTransport`
  is injected). Phase H was to make a wasm parallel.
- **secp256k1 ∉ Secure Enclave / StrongBox** (Apple `SecureEnclave.P256` only; Android StrongBox P-256 only) →
  the wrap-key (seal/unseal the share, biometric-gated) is the correct design; the in-memory exposure window
  is the disclosed asterisk. `docs/41-AUDIT-FINDINGS.md` F2.
- **WebAuthn-PRF is per-ecosystem** (no iOS↔Android passkey sync; loss → trustee reshare #40). It's an L1
  convenience unwrap, never sole custody.
- **cggmp24 `trusted_dealer` is behind the `spof` feature** (the client dev-dep enables it). Mirrors core's dev-dep.
- **`InProcessCosigner` lockstep:** the test transport keeps the cosigner one step ahead (returns its pending
  round, then advances by processing the client's msgs). Works because the protocol is symmetric.
- **Never rustfmt a crate root** (`lib.rs`) — it cascades + reflows pre-existing files. Format only edited
  files (`rustfmt --edition 2021 <file>`). The fmt CI gate is green since #62; keep edits fmt-clean.
- **bsv-rs version:** published `0.3.13` on crates.io (registry). bsv-mpc + toolbox both on it now.
- The **#55** issue ("export joint pubkey from keygen-only share / instant-signup seam") is OPEN — graphify
  surfaced it as a small high-UX product win (show address before aux-info completes).

---

## 7. Discipline gates (non-negotiable, every PR)

- **NO commit/push/PR without showing the diff + approval.**
- clippy: **native crates `--all-targets` + the wasm worker/client target**, `-D warnings`, `CARGO_INCREMENTAL=0`.
- **Validate, don't skip** — assert rejection paths reject *for the right reason* (e.g. wrong key → GCM auth fail;
  short BRC-42 protocol name → `Core`; missing share → `Host{storage}`).
- **Never rustfmt a crate root**; format only edited files.
- **Mainnet spends:** fail-closed pre-flight (low-s + joint-key verify) BEFORE broadcast; local verify before
  real-money runs; user clearance per run.
- Don't touch `~/bsv/mpc/MPC-Spec/` (separate spec lane). Don't depend on `rust-mpc` (Binary). 100cash is Calhoun (OK).

---

## 8. Open issues map (GitHub, B1nary-Calhoun-Partnership/bsv-mpc)

- **#41** — native client foundation (this) — **OPEN**, body has a ✅done/⬜remaining checklist + the capstone TXID.
  Remaining: real on-device enclave (100cash), WebAuthn-PRF backup, shells, async-WalletClient-over-FFI (4d).
- **#63** — client relay transport / signs vs deployed cosigner — **OPEN**; step 1 done; T3 scoped (this doc §4).
- **#37** — god-tier consumer wallet (umbrella). **#2** — v1.0 CF-native cosigner deployment (umbrella; #4 Phase I,
  #6 productionize cosigner). **#56** — multi-device sessions (design). **#55** — instant-signup keygen-only seam.
  **#5** — prod hardening backlog. **#58** — reshare-over-relay convergence hardening.

---

## 9. Recommended next steps (priority order)

1. **#63 T3** — pick path (a-extended) or (c) (§4), wire the client to sign vs the deployed container, verify
   locally, then the **mainnet TXID** gate. Highest leverage: it removes the last *protocol* asterisk and is the
   real product path (it's also what 100cash will use).
2. **On-device 100cash** (#41) — wire `bsv-mpc-client` UniFFI (`FfiSigningSession`) into 100cash; real biometric
   tap on hardware. Removes the last #41 asterisk.
3. **#55 instant-signup seam** — small, high-UX product win.
4. **WebAuthn-PRF backup** + **Phase 4d** (async client over FFI callbacks) — recovery UX + FFI polish.
5. Watch **M1 cross-impl demo** timing (partnership, with rust-mpc) — separate track; may pre-empt the above.

---

## 10. Quick commands

```bash
# build everything the client supports
cargo build -p bsv-mpc-client                                  # native default
cargo build -p bsv-mpc-client --features native                # + UniFFI
cargo build -p bsv-mpc-client --target wasm32-unknown-unknown  # web
# gates
CARGO_INCREMENTAL=0 cargo clippy -p bsv-mpc-client --all-targets -- -D warnings
CARGO_INCREMENTAL=0 cargo clippy -p bsv-mpc-client --features native --all-targets -- -D warnings
CARGO_INCREMENTAL=0 cargo clippy -p bsv-mpc-client --target wasm32-unknown-unknown --tests -- -D warnings
# tests
cargo test -p bsv-mpc-client --lib                             # 8 unit
cargo test -p bsv-mpc-client --features native --test hermetic_sign   # 2 real 2-party signs (~30s each)
wasm-pack test --node -p bsv-mpc-client --test wasm32_txbuild  # wasm byte-identity
# UniFFI bindings
cargo run -p bsv-mpc-client --features native --bin uniffi-bindgen -- \
  generate --library target/debug/libbsv_mpc_client.dylib --language swift --out-dir /tmp/swift
# mainnet (BURNS SATS, needs 3321 wallet running):
E2E_MAINNET=1 cargo test -p bsv-mpc-client --test hermetic_sign mainnet_capstone -- --nocapture --test-threads=1
```

## 11. Companion docs (in `docs/`)
- `41-AUDIT-FINDINGS.md` — the GREEN realizability audit (F1 wasm-split pivot, F2 enclave, F3 PRF, F4 zeroize, F5 proof plan).
- `41-CLIENT-PLAN.md` — the build plan + the "don't wasm-split the toolbox" pivot rationale.
- `41-CLIENT-PROGRESS.md` — live phase tracker (1→5 ✅ + the capstone TXID).
- knowledge graph: `graphify-out/` (gitignored, regenerate with `/graphify --update`).
