# #41 native client — build progress

> Live tracker for the `bsv-mpc-client` build (plan: `docs/41-CLIENT-PLAN.md`). Updated as work lands.
> Legend: ✅ done · 🔄 in progress · ⬜ not started · ⏸ blocked.

_Last updated: 2026-05-26_

## Phase milestones (capstone = WoC-confirmed mainnet TXID)

| Phase | Status | Notes |
|------|--------|-------|
| 0. Audit + plan | ✅ | `41-AUDIT-FINDINGS.md` (GREEN), `41-CLIENT-PLAN.md` (pivot: build on core, not toolbox-split) |
| 0b. zeroize (Finding 4) | ✅ | committed+pushed `6109479` on bsv-mpc main |
| 0c. bsv-rs unify | ✅ | toolbox bumped 0.3.4→0.3.13, pushed `chore/bump-bsv-rs-0.3.13` |
| 1. Scaffold `bsv-mpc-client` | ✅ | 3 traits + InMemoryKeyStore + WalletClient core; builds native+wasm32, clippy -D warnings both, 1 test green |
| 2. Lift + wasm-prove tx helpers | ✅ | `txbuild.rs` (lifted, pure); wasm sighash/serialize **byte-identical to native** proven on node (`wasm-pack test`); `derive_address` wired via `bsv_mpc_core::hd` |
| 3. Signer hot path | ✅ | `signer::unseal_signing_scalar`: biometric unseal → `parse_share_scalar` → `Zeroizing<[u8;32]>`; proven on a REAL cggmp24 trusted-dealer share (recovers exact scalar) + garbage rejects. Live 2-party combine = Phase 4 (relay seam). |
| 4a. wasm-bindgen skin | ✅ | `src/wasm.rs` (wasm32-only): `txTxid`/`txOutputSats` over txbuild; node test passes (`wasm-pack test`). |
| 4a. UniFFI skin | ✅ | `src/ffi.rs` (feature `native`): `FfiError` + `ffi_tx_txid`/`ffi_tx_output_sats` + `setup_scaffolding!` + `uniffi-bindgen` bin. **Swift + Kotlin bindings generate** from the dylib (verified). |
| 4b. `WalletClient::sign` + hermetic 2-party sign | ✅ | `sign()` drives a real ceremony over the injected `RoundTransport`; hermetic test (real DKG+aux via sim) produces a **threshold ECDSA sig BSV-SDK-verified against the joint key** (Tier 4.1), `Zeroizing` throughout. |
| 4c. UniFFI signing session (sans-io) | ✅ | `FfiSigningSession` (sync, host-driven) over UniFFI — proven to drive a **real BSV-verified threshold sig** (native test) + exported in Swift/Kotlin bindings. The proven partner pattern (host owns I/O, Rust = sync state machine). |
| 4d. async WalletClient over FFI callbacks | ⬜ | deferred — expose the async seams over UniFFI `callback_interface` + wasm-bindgen JS callbacks |
| 5. Mainnet capstone (client signs real tx) | ✅ | **WoC-CONFIRMED mainnet TXID `d238e447975fe54f562ea73fe30d20e27b3608cafe1729adcb09b88d4c0b7dd6`** — `WalletClient::sign` produced a real threshold ECDSA sig that the network accepted. Physical biometric tap = 100cash-on-hardware follow-up (100cash is the **Calhoun** iOS app; Simulator uses MockKeyStore). |

### Phase 5 — mainnet capstone (in progress)
Gated `E2E_MAINNET=1`. Flow (`tests/hermetic_sign.rs::mainnet_capstone…`):
1. local 2-of-2 DKG → joint P2PKH; 2. fund joint addr via wallet:3321 `createAction` (Origin admin.com) → extract raw from BEEF → **self-broadcast via ARC** → find UTXO on WoC; 3. build spend to a 3321 address, BIP-143 sighash (txbuild, mirrors proxy: v1, 0x41); 4. **`WalletClient::sign`** (share device-sealed in InMemoryKeyStore, cosigner over InProcessCosigner relay) → DER sig; 5. pre-flight (low-s + joint-pubkey verify, fail-closed); 6. assemble + **broadcast via ARC** → **WoC-confirmed TXID**.
- **TXID:** ✅ `d238e447975fe54f562ea73fe30d20e27b3608cafe1729adcb09b88d4c0b7dd6` (funded from `5ad14133…`; both `SEEN_ON_NETWORK` via gorillapool ARC; WoC scriptSig shows the threshold sig `30440220…[ALL|FORKID]` + joint pubkey). https://whatsonchain.com/tx/d238e447975fe54f562ea73fe30d20e27b3608cafe1729adcb09b88d4c0b7dd6
- **On-device biometric (100cash, Calhoun):** follow-up — wire `bsv-mpc-client` UniFFI into 100cash, run on a physical Secure-Enclave device for the real tap.

## Phase 1 — scaffold ✅ COMPLETE (2026-05-26)

| Step | Status | Notes |
|------|--------|-------|
| Cargo.toml + workspace member | ✅ | lean (core deps only); FFI/bsv-rs-direct features deferred to Phases 2-4 |
| error.rs (ClientError) | ✅ | thiserror + From<MpcError> + From<serde_json> + NotImplemented (no panic/todo!) |
| keystore.rs (KeyStore + InMemoryKeyStore) | ✅ | seal/unseal → Zeroizing<Vec<u8>>; round-trip + reject-unknown test |
| storage.rs + chain.rs (traits) | ✅ | WalletStorage / ChainServices, async-trait(?Send), StoredShare/Utxo/BroadcastResult |
| client.rs + lib.rs (WalletClient core) | ✅ | new + provision_share/list_agents/list_utxos real (all 3 seams used); derive_address/sign staged |
| Gates | ✅ | native+wasm32 build, clippy -D warnings (both targets), 1 test green, all files fmt-clean |

**Phase 1 LANDED** — committed `11121ab` + pushed to origin/main (crate + workspace member + Cargo.lock). The three `41-*` docs left untracked (user's call).

## Phase 2 — LANDED (local, awaiting commit approval)
- `src/txbuild.rs`: lifted pure helpers (sha256d, varints, P2PKH scripts, `compute_bip143_sighash`, `serialize_signed_tx`, `parse_tx_outputs`, `compute_txid`) + shared `demo_sighash`/`demo_serialized` vector. Golden: sighash `96168d5c…`, txid `67f647fe…`.
- `tests/wasm32_txbuild.rs`: `#[wasm_bindgen_test]` asserts the same golden ⇒ **wasm == native byte-for-byte** (ran on node via wasm-pack ✅).
- `client.rs`: `derive_address` real (storage → JointPublicKey → `hd::derive_anyone_joint_key` level 2 → address); tests cover deterministic + key_id-sensitive + reject short protocol + reject missing share.
- Gates: native build+test (6 pass), wasm32 build+clippy, native clippy `-D warnings`, wasm-pack test (1 pass), all fmt-clean.

## Phase 3 — LANDED (local, awaiting commit approval)
- `src/signer.rs`: `pub async fn unseal_signing_scalar(keystore, agent_id, reason) -> Zeroizing<[u8;32]>` — biometric-gated unseal → `bsv_mpc_core::ecdh::parse_share_scalar`. Lib deps unchanged (bsv-mpc-core only) ⇒ wasm-clean.
- Tests (native, on a **real** cggmp24 2-of-2 trusted-dealer share — fast, no DKG): recovers the exact share scalar as Zeroizing; garbage share rejects → `Core`. cggmp24/generic-ec/rand are **native-only dev-deps**, test gated `cfg(not(wasm32))`.
- `WalletClient::sign` stays staged (`NotImplemented`) — the **live 2-party ceremony** that consumes the scalar rides the relay seam (Phase 4); the on-chain signature is the Phase 5 capstone. Boundary kept explicit (no-asterisks).
- Gates: 8 native tests, wasm32 lib build (no cggmp24), clippy `-D warnings` native + wasm32 `--tests`, fmt-clean.

## Next: Phase 4 — relay-wired sign + FFI skins
Wire `WalletClient::sign`: `unseal_signing_scalar` → `SigningCoordinator` partial → cosigner round over the `ChainServices`/relay seam → combine → DER sig. Then UniFFI (Swift/Kotlin) + wasm-bindgen skins (Tier 3 binding gates). Full-software 2-party hermetic integration test (Tier 4.1).

## Decisions / constraints
- 100% Calhoun-solo, **zero rust-mpc / 100cash dependency** (reimplement studied patterns fresh).
- I/O is **injected** (host owns storage/chain/keystore); secrets are `Zeroizing` end-to-end.
- Discipline: clippy `-D warnings` (native + wasm), never rustfmt a crate root, no commit/push without diff+approval.
