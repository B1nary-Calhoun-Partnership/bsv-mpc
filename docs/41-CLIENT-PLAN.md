# #41 native client — build plan (post design-swarm, 2026-05-26)

> Greenfield, **100% Calhoun-solo, zero-Binary-dependency** (user decision 2026-05-26). Synthesizes a
> 3-agent design swarm. **Headline pivot: don't wasm-split the external toolbox — bsv-mpc doesn't depend
> on it, and the proxy already owns the proven, wasm-portable tx logic.** Build a new `bsv-mpc-client`
> crate on `bsv-mpc-core` + lifted proxy helpers instead.

---

## The pivot (why the issue's "wasm-split toolbox" framing is the wrong path)

Issue #41 says "wasm-split toolbox + UniFFI + …". The swarm found that framing is **more work than needed**:

1. **bsv-mpc has ZERO production dependency on `rust-wallet-toolbox`.** The only reference anywhere is
   `poc/poc6-toolbox-dep/Cargo.toml:11`. All 6 production crates: none. *(Agent 2, grep-verified.)*
2. **The proxy already implements the entire `createAction` pipeline, self-contained and mainnet-proven**
   — UTXO select → fee inject → BIP-143 sighash → MPC sign-per-input → BEEF → broadcast
   (`crates/bsv-mpc-proxy/src/wallet_api.rs:1510`). Its **pure tx helpers are already wasm-portable**
   (`wallet_api.rs:186-452`: `compute_bip143_sighash`, `serialize_signed_tx`, `p2pkh_locking_script_from_hash`,
   `build_p2pkh_unlocking_script`, varint codecs — no async/IO/SQL).
3. **The toolbox is hostile to the split anyway.** Its wasm wall is `mio` (from an *unconditional*
   `tokio = { features=["full"] }` at `Cargo.toml:25`) plus `bsv-rs/http`; and its `WalletSigner` is a
   **concrete struct, not a trait** (`src/wallet/signer.rs:108`, field at `wallet.rs:314`), so injecting MPC
   signing needs a trait-extraction refactor of someone else's crate. *(Agent 1 + Agent 2.)*

⇒ **Decision: lift the proxy's pure tx helpers into a wasm-safe module and build the client on
`bsv-mpc-core`, NOT on a wasm-split of the external toolbox.** The toolbox split stays a *future option*
(only if we later want its action-history / SABPPP / monitor features), gated behind the trait extraction
Agent 1 scoped — out of scope for the #41 capstone.

---

## Empirical anchors (falsifiable, from the swarm)

**Toolbox wasm break surface** *(Agent 1; `cargo build --target wasm32` on toolbox, both default and
`--no-default-features`, fails identically):*
```
error: This wasm target is unsupported by mio. ... disable the net feature.
  --> mio-1.1.1/src/lib.rs:44   (pulled by tokio=["full"], unconditional, Cargo.toml:25)
```
Hostile deps → modules: `sqlx`+`libsqlite3-sys` → `src/storage/sqlx/*`; `reqwest`/`hyper` → `src/services/*`,
`src/storage/client/*`, `src/chaintracks/ingestors/*`; `native-tls`/`openssl` → `tokio-tungstenite` (websocket);
`ring` → `src/managers/cwi_style_wallet_manager.rs:17,367`. Root config blocker: `bsv-rs/http` pulls reqwest+tokio
into bsv-rs itself.

**bsv-mpc-core is already wasm32-built + runtime-tested in CI** *(Agent 2):* `.github/workflows/ci.yml:74`
(`cargo build -p bsv-mpc-core --target wasm32`) + `:90` (`wasm-pack test --node … wasm32_dkg`). The client's
wasm core = `bsv-mpc-core` (`ecdh`/`hd`/`signing`/`share`, all un-gated wasm) + `bsv-rs` (`wasm` feature) +
the lifted proxy tx helpers. `brc31_client` is the only core module gated off wasm (`lib.rs:53`).

**Reusable platform patterns to reimplement-fresh** *(prior Explore + Agent 3; studied, NOT depended on):*
Secure-Enclave seal/unseal at `~/bsv/mpc/100cash/Sources/Crypto/EnclaveKeyStore.swift` (P-256 + ECIES +
`.biometryCurrentSet` + `MockKeyStore`); UniFFI 0.28 no-`.udl` pattern at `~/bsv/mpc/rust-mpc/clients/native/`;
`bsv-rs` `wasm` feature usage at `~/bsv/zanaadu/middleware/Cargo.toml`. WebAuthn binding verify already in core:
`approval.rs:401 verify_webauthn_approval()`.

---

## The build: `bsv-mpc-client` crate (Agent 3 skeleton)

One target-agnostic `WalletClient` core + two thin FFI skins (UniFFI native, wasm-bindgen web). Three
**injected** traits (host owns I/O); zero forbidden deps.

```
crates/bsv-mpc-client/
  Cargo.toml          # features: native (uniffi) | native-io (sqlx+reqwest) | wasm (wasm-bindgen+getrandom/js)
  build.rs            # cfg(native): uniffi scaffolding; no-op on wasm
  src/
    lib.rs            # setup_scaffolding!() (native) / wasm_bindgen start (wasm)
    client.rs         # WalletClient: init / derive_address / sign  (target-agnostic core)
    keystore.rs       # KeyStore trait (enclave seam) + InMemoryKeyStore (sim/CI)
    storage.rs        # WalletStorage trait + StoredShare
    chain.rs          # ChainServices trait + Utxo / BroadcastResult
    signer.rs         # Zeroizing unseal -> bsv_mpc_core signing  (the secret hot path)
    txbuild.rs        # LIFTED pure tx helpers from proxy wallet_api.rs:186-452 (sighash/serialize/scripts)
    ffi/              # cfg(native): #[uniffi::export] + callback_interface traits
    wasm/             # cfg(wasm): #[wasm_bindgen] skin, JS-closure host adapters
    native_impls/     # cfg(native-io): SqliteStorage (sqlx) + ReqwestChain (reqwest/ARC/WoC)
```

Per-target bsv-rs split: native = `["transaction","wallet","auth"]` (no `http`/`overlay`); wasm =
`["transaction","wallet","wasm"]` + `getrandom/js`. Secret flow: `KeyStore::unseal_share → Zeroizing<Vec<u8>>`
→ `bsv_mpc_core::share::decrypt_share` (already `Zeroizing`-locked, this session's PR) → `SigningCoordinator`,
wiped on scope exit.

---

## Phased build order (each a reviewable diff; capstone = mainnet TXID)

1. **Scaffold `bsv-mpc-client`** — crate skeleton, the 3 traits, `InMemoryKeyStore`, `WalletClient` core
   compiling on **both** native and wasm32 (CI gate: `cargo build -p bsv-mpc-client --target wasm32`).
2. **Lift + wasm-prove the tx helpers** — move proxy `wallet_api.rs:186-452` pure fns into `txbuild.rs`
   (shared), wasm-bindgen-test that wasm sighash/serialize is **byte-identical to native** (proof-plan Tier 3).
3. **Signer hot path** — `signer.rs`: `InMemoryKeyStore` → core signing; full-software integration test
   (zeroize + share + sign, no device) as a CI gate (proof-plan Tier 4.1).
4. **UniFFI + wasm-bindgen skins** — generated Swift + Kotlin compile + round-trip byte match (Tier 3).
5. **Enclave wrap-key + WebAuthn-PRF + shells** — Swift `SecureEnclaveKeyStore` (reimplemented fresh)
   implements `KeyStore` via UniFFI callback; **capstone = first shell signs a mainnet tx with a
   biometric-gated, enclave-wrapped share → WoC-confirmed TXID** (proof-plan Tier 4.2).

## Discipline (carried): clippy `-D warnings` native + wasm worker, `CARGO_INCREMENTAL=0`, validate-don't-skip,
never rustfmt a crate root, no commit/push/PR without diff + approval, no rust-mpc/100cash dependency.
