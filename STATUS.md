# bsv-mpc — Project Status

> What's done, what's scaffolded, what's not tested, what still needs to be solved.
> Updated: 2026-03-21

---

## Overall Status: SCAFFOLDED — Not Yet Functional

The project structure, type definitions, module stubs, specs, BRC drafts, and research are in place. **No functional MPC code exists yet.** Every function body is `todo!()`. This is the blueprint — implementation starts from here.

### Critical Architecture Shortcut Discovered

**bsv-wallet-cli has a clean ProtoWallet/Signer separation.** The MPC proxy can depend on `rust-wallet-toolbox` as a Cargo dependency and ONLY replace the signing layer. UTXO selection, fee calculation, transaction construction, HTTP handlers, and SQLite storage are all reusable. This cuts build time from ~10 weeks to ~4-6 weeks. See `INTEGRATION.md` for full analysis.

### Next Step: POC Validation (2 weeks)

Before writing production code, run 7 POCs to validate every assumption. See `POCS.md` for the full plan. The critical path: POC 1 (does cggmp24 actually work?) → POC 2 (does it compile to WASM?) → POC 3 (key derivation compatibility?).

---

## What's Done

### Project Structure
- [x] Cargo workspace with 5 crates
- [x] Root Cargo.toml with shared workspace dependencies
- [x] .gitignore, rust-toolchain.toml (includes wasm32 target), deny.toml
- [x] Git repo initialized

### bsv-mpc-core (8 source files)
- [x] `types.rs` — All shared types defined: SessionId, ShareIndex, ThresholdConfig, JointPublicKey, EncryptedShare, Presignature, ParticipationProof, RoundMessage, DkgResult, SigningResult
- [x] `error.rs` — MpcError enum with all variants (Dkg, Signing, ShareStorage, InvalidThreshold, PresigningExhausted, Encryption, etc.)
- [x] `dkg.rs` — DkgCoordinator struct, init/process_round signatures, DkgRoundResult enum. Bodies: `todo!()`
- [x] `signing.rs` — SigningCoordinator struct, sign/init_round/process_round signatures, SigningRoundResult enum. Bodies: `todo!()`
- [x] `presigning.rs` — PresigningManager struct with pool management, generate/take/should_replenish. Bodies: `todo!()`
- [x] `share.rs` — encrypt_share, decrypt_share, derive_share_encryption_key signatures. Bodies: `todo!()`
- [x] `hd.rs` — derive_child_key stub. Body: `todo!()`
- [x] `proof.rs` — create_participation_proof, proof_to_op_return, verify_participation_proof. Bodies: `todo!()`
- [x] `lib.rs` — Module declarations and re-exports

### bsv-mpc-proxy (7 source files)
- [x] `config.rs` — ProxyConfig with all fields (port, kss_url, share_path, fee config, encryption_key). `from_env()` implementation is **functional** (reads env vars)
- [x] `server.rs` — Axum router with all 28 BRC-100 routes defined. AppState struct. Background presig replenishment task spawn
- [x] `wallet_api.rs` — Handler stubs for all endpoints. Bodies: `todo!()`
- [x] `bridge.rs` — MpcBridge struct with sign/presign/joint_public_key. Bodies: `todo!()`
- [x] `fee_injector.rs` — FeeInjector struct with inject_fee. Body: `todo!()`
- [x] `presign_manager.rs` — PresignManager with pool management. `take()`/`add()`/`len()`/`should_replenish()` are **functional** (simple Vec operations). `background_replenish()` loop structure is functional (calls bridge.presign which is todo)
- [x] `main.rs` — Binary entry point (parses config, starts server)
- [x] `error.rs` — ProxyError enum

### bsv-mpc-worker (4 source files)
- [x] `lib.rs` — CF Worker entry point with route definitions
- [x] `storage.rs` — ShareStorage struct with DO SQLite schema. Methods: `todo!()`
- [x] `api.rs` — HTTP handlers for DKG/sign/presign/health. Bodies: `todo!()`
- [x] `auth.rs` — BRC-31 auth stub. Body: `todo!()`

### bsv-mpc-service (1-2 source files)
- [x] `main.rs` or `lib.rs` — Standalone binary skeleton with axum routes

### bsv-mpc-overlay (2+ source files)
- [x] `lib.rs` — Module declarations
- [x] `Cargo.toml` — Dependencies

### Documentation
- [x] SPECS.md — Plain English specifications for all 5 components + fee system + overlay
- [x] STATUS.md — This file
- [x] Research analysis at `~/bsv/rust-bsv-worm/research/MPC-SIGNING-NETWORK-ANALYSIS.md` (1,276 lines)

### Research Completed
- [x] MPC library landscape: evaluated 8 libraries, selected cggmp24
- [x] Platform cost analysis: CF Workers, Lambda, Fly.io, Modal, Cloud Run
- [x] Signature latency analysis: 7ms-640ms depending on topology
- [x] Node economics: revenue model, break-even analysis, margin projections
- [x] BSV overlay network mapping: SHIP/SLAP for MPC discovery
- [x] sCrypt covenant feasibility: confirmed hashOutputs introspection works for fee splits
- [x] TSSHOCK vulnerability assessment: cggmp24 is patched, ZenGo/tofn are not
- [x] Defense-in-depth analysis: same-cloud vs cross-cloud trade-offs

---

## What's Scaffolded But Not Implemented

Every function marked `todo!()` — these are the actual implementation tasks:

### bsv-mpc-core — The Crypto (HIGHEST PRIORITY)

| Function | File | What it needs to do | Difficulty | Depends on |
|----------|------|---------------------|-----------|------------|
| `DkgCoordinator::init()` | dkg.rs | Create cggmp24 DKG party, generate round 1 message | Hard | cggmp24 API understanding |
| `DkgCoordinator::process_round()` | dkg.rs | Feed incoming messages to cggmp24, get next round or final share | Hard | cggmp24 API |
| `SigningCoordinator::sign()` | signing.rs | Full signing flow with optional presignature | Hard | cggmp24 API |
| `SigningCoordinator::init_round()` | signing.rs | Start signing protocol round 1 | Hard | cggmp24 API |
| `SigningCoordinator::process_round()` | signing.rs | Process signing round messages | Hard | cggmp24 API |
| `PresigningManager::generate()` | presigning.rs | Run 3-round presigning protocol | Hard | cggmp24 API |
| `encrypt_share()` | share.rs | AES-256-GCM encryption | Easy | aes-gcm crate |
| `decrypt_share()` | share.rs | AES-256-GCM decryption | Easy | aes-gcm crate |
| `derive_share_encryption_key()` | share.rs | BRC-42 HMAC-SHA256 key derivation | Medium | bsv SDK |
| `derive_child_key()` | hd.rs | SLIP-10/BIP-32 from MPC shares | Medium | cggmp24 HD support |
| `create_participation_proof()` | proof.rs | Assemble proof struct | Easy | None |
| `proof_to_op_return()` | proof.rs | Serialize to BRC-18 OP_RETURN format | Medium | bsv SDK (Script) |
| `verify_participation_proof()` | proof.rs | Verify proof integrity | Easy | sha2 |

**The cggmp24 integration (dkg.rs, signing.rs, presigning.rs) is the critical path.** Everything else is plumbing.

### bsv-mpc-proxy — The Wallet Bridge

| Function | File | What it needs to do | Difficulty | Depends on |
|----------|------|---------------------|-----------|------------|
| `MpcBridge::new()` | bridge.rs | Load share, decrypt, initialize bridge | Medium | core::share |
| `MpcBridge::sign()` | bridge.rs | HTTP round-trips to KSS for MPC signing | Medium | core::signing, reqwest |
| `MpcBridge::presign()` | bridge.rs | HTTP round-trips to KSS for presigning | Medium | core::presigning |
| `get_public_key` handler | wallet_api.rs | Return joint MPC public key | Easy | bridge |
| `create_signature` handler | wallet_api.rs | Run MPC signing, return signature | Medium | bridge |
| `create_action` handler | wallet_api.rs | Build tx + inject fee + MPC sign + broadcast | **Hard** | bridge, fee_injector, bsv SDK |
| `encrypt`/`decrypt` handlers | wallet_api.rs | Local AES-256-GCM with derived key | Easy | aes-gcm |
| `FeeInjector::inject_fee()` | fee_injector.rs | Parse tx, add fee output, re-serialize | Medium | bsv SDK (Transaction) |
| All other BRC-100 handlers | wallet_api.rs | Various wallet operations | Medium | Depends on operation |

**`create_action` is the hardest handler** — it does UTXO selection, transaction construction, fee injection, and MPC signing. This is where most of the wallet logic lives.

### bsv-mpc-worker — The WASM Service

| Function | File | What it needs to do | Difficulty | Depends on |
|----------|------|---------------------|-----------|------------|
| All API handlers | api.rs | DKG/sign/presign protocol participation | Medium | core (via WASM) |
| Share storage | storage.rs | DO SQLite CRUD for encrypted shares | Easy | worker crate |
| BRC-31 auth | auth.rs | Verify Authrite headers | Medium | BRC-31 spec |
| WASM compilation | - | Get cggmp24 + core compiling to wasm32 | **Hard** | getrandom/js, num-bigint |

**WASM compilation is the biggest unknown.** cggmp24 says it supports wasm32, but integrating with CF Worker's V8 isolate, entropy source, and memory limits needs hands-on validation.

### bsv-mpc-overlay — The Discovery Layer

| Function | File | What it needs to do | Difficulty | Depends on |
|----------|------|---------------------|-----------|------------|
| `create_chip_token()` | chip.rs | Build BRC-48 PushDrop CHIP token | Medium | bsv SDK |
| `parse_chip_token()` | chip.rs | Parse CHIP token from script | Medium | bsv SDK |
| `publish_chip_token()` | chip.rs | Submit to overlay via BRC-22 | Easy | reqwest |
| `discover_nodes()` | discovery.rs | Query BRC-24 lookup | Easy | reqwest |
| `publish_proof()` | proofs.rs | Submit proof to overlay | Easy | reqwest |
| `query_proofs()` | proofs.rs | Query proofs from overlay | Easy | reqwest |

**The overlay crate is the simplest.** It's mostly HTTP requests to existing overlay infrastructure.

---

## What's NOT Built Yet (Missing Files/Components)

| Component | What's missing | Priority |
|-----------|---------------|----------|
| `bsv-mpc-overlay/src/chip.rs` | CHIP token creation/parsing | Medium |
| `bsv-mpc-overlay/src/discovery.rs` | Node discovery via SLAP | Medium |
| `bsv-mpc-overlay/src/proofs.rs` | Participation proof publishing | Medium |
| `bsv-mpc-overlay/src/types.rs` | Overlay types (MpcNodeInfo, etc.) | Medium |
| `bsv-mpc-overlay/src/error.rs` | OverlayError enum | Low |
| `bsv-mpc-proxy/src/bridge.rs` | MPC bridge (may exist, check) | High |
| `bsv-mpc-proxy/src/fee_injector.rs` | Fee output injection (may exist, check) | High |
| `contracts/mpc-fee-pool/` | sCrypt fee covenant contract | Low (Phase 2) |
| `brc-drafts/*.md` | 4 BRC draft documents | Medium |
| `CLAUDE.md` | Project context for Claude Code | High |
| `README.md` | Project README | Medium |
| Integration tests | `tests/` directory is empty | High (after impl) |

---

## What's NOT Tested

**Nothing is tested.** There are zero tests. The project is all stubs.

### Test plan (when implementation begins):

| Test Area | What to test | File |
|-----------|-------------|------|
| Share encryption roundtrip | encrypt → decrypt gives back original | `tests/test_share.rs` |
| DKG between two parties | Two DkgCoordinators exchange rounds, both get valid shares | `tests/test_dkg.rs` |
| Signing with 2-of-2 | DKG → sign → verify signature on secp256k1 | `tests/test_signing.rs` |
| Signing with presignature | DKG → presign → sign (1 round) → verify | `tests/test_presigning.rs` |
| Presign pool management | Pool replenishment, take, exhaustion | `tests/test_presign_pool.rs` |
| BRC-100 proxy routing | HTTP requests to correct handlers | `tests/test_proxy_routes.rs` |
| Fee injection | Transaction gains correct fee output | `tests/test_fee_injection.rs` |
| WASM compilation | cggmp24 + core compiles to wasm32 | CI job |
| End-to-end signing | proxy → worker → sign → verify | `tests/test_e2e.rs` |
| Participation proof format | Proof serializes to valid BRC-18 OP_RETURN | `tests/test_proofs.rs` |
| CHIP token roundtrip | Create → parse gives back original | `tests/test_chip.rs` |

---

## Unsolved Problems & Open Questions

### Critical (must solve before functional)

| # | Problem | Why it's hard | Potential solution |
|---|---------|--------------|-------------------|
| 1 | **cggmp24 API integration** | The crate's API is complex (round-based state machine with generic type params). No tutorial exists — only source code and a few examples. | Read cggmp24 examples in the repo. Start with 2-of-2 keygen test. |
| 2 | **WASM + getrandom** | cggmp24 in WASM needs a JS-backed entropy source. CF Worker's V8 isolate may have restrictions. | Use `getrandom` with `js` feature. Test early — this is a go/no-go for CF Workers. |
| 3 | **Transaction construction in proxy** | `create_action` needs full UTXO selection, script construction, fee calculation, and change output. This is ~500 lines in bsv-wallet-cli. | Start with a minimal subset: P2PKH only, single input, fixed fee. Expand later. |
| 4 | **UTXO tracking** | The proxy needs to know what UTXOs the agent owns. Without a full wallet database, it can't select inputs for transactions. | Options: (a) proxy maintains a simple UTXO cache synced from chain, (b) proxy delegates UTXO queries to a remote service, (c) use an existing wallet for everything except signing. |

### Important (must solve before production)

| # | Problem | Why it's hard | Potential solution |
|---|---------|--------------|-------------------|
| 5 | **Key refresh** | cggmp24 v0.7.0-alpha.3 lacks key refresh. If a node dies, you can't replace its share without full re-DKG + fund transfer. | Periodic proactive re-DKG. Or contribute key refresh to cggmp24 upstream. |
| 6 | **cggmp24 alpha stability** | v0.7.0-alpha.3 — API may change without notice. | Pin version. The crypto core is audited; API wrapper is the variable part. |
| 7 | **Overlay node bootstrap** | SHIP/SLAP needs running overlay nodes. We'd be the first `tm_mpc_signing` topic. | Run our own overlay node initially. Existing BSV overlay infra (if any) may already support custom topics. |
| 8 | **BRC-31 auth in CF Worker** | Authrite mutual auth requires session management. Workers are stateless (per-request). | Use Durable Objects for session state. Or stateless auth (verify signature per-request without session). |
| 9 | **CF Worker memory limit (128MB)** | cggmp24 WASM module + protocol state must fit in 128MB. | Benchmark: compile to WASM, measure module size + runtime memory. Almost certainly fine but needs validation. |

### Nice to Have (can defer)

| # | Problem | Notes |
|---|---------|-------|
| 10 | sCrypt fee covenant (Level 3) | Level 2 multisig works fine without it. Add when there are independent operators. |
| 11 | HD derivation from MPC shares | cggmp24 supports it but we don't need it for MVP. |
| 12 | Cross-cloud deployment (CF + GCP) | Same-cloud with different accounts is fine for alpha. |
| 13 | Reputation system | Simple proof count works initially. Sophisticated scoring later. |
| 14 | Dynamic fee pricing | Fixed 1,000 sats is fine for alpha. Market-driven pricing later. |

---

## Implementation Order (Recommended)

### Phase 1: Prove the crypto works (Week 1-2)
1. Get cggmp24 compiling in a test harness (not WASM yet, just native)
2. Write test: two-party DKG → both get shares → joint key is valid secp256k1 pubkey
3. Write test: two-party signing → produce valid ECDSA signature → verify with bsv SDK
4. Write test: presigning → consume presig → single-round signing works
5. Implement `share.rs` encryption (simplest module, validates the toolchain)

**Exit criteria:** A passing test that does DKG + sign + verify entirely in Rust. No network, no CF Worker, just two in-process parties.

### Phase 2: Prove WASM works (Week 3)
1. Compile bsv-mpc-core to `wasm32-unknown-unknown`
2. Fix any getrandom/entropy issues
3. Run the same DKG + sign test in WASM (via wasm-pack test or Node.js)
4. Measure: module size, memory usage, signing latency in WASM

**Exit criteria:** The same test passes in WASM. Module fits in 128MB. Signing takes <50ms.

### Phase 3: Build the proxy (Week 4-5)
1. Implement `MpcBridge::sign()` — HTTP round-trips to a local bsv-mpc-service
2. Implement `get_public_key` and `create_signature` handlers
3. Test: bsv-worm calls the proxy, gets a valid signature
4. Implement `create_action` (the hard one) — start with P2PKH-only transactions
5. Implement fee injection

**Exit criteria:** bsv-worm can run a task using the MPC proxy instead of bsv-wallet-cli.

### Phase 4: Deploy to CF (Week 6-7)
1. Build bsv-mpc-worker as a CF Worker
2. Deploy to Cloudflare
3. Point the proxy at the deployed worker
4. End-to-end test: agent → proxy → CF Worker → signed transaction

**Exit criteria:** An agent on CF Container signs via an MPC Worker. Real BSV transaction on mainnet.

### Phase 5: Overlay + fees (Week 8-10)
1. Implement CHIP token creation and publishing
2. Implement SLAP discovery
3. Implement participation proofs
4. Implement fee settlement (Level 2 multisig)
5. Deploy overlay node

**Exit criteria:** Independent node operator can register, participate in signing, and get paid.

---

## Dependencies & Blockers

| Dependency | Status | Blocker? |
|-----------|--------|----------|
| cggmp24 crate (git) | Available, alpha | No — but API may change |
| bsv Rust SDK (../rust-sdk) | Available, local | No |
| CF Worker Rust SDK (worker crate) | v0.4 stable | No |
| Overlay node infrastructure | Unclear if BSV overlay nodes exist in prod | **Maybe** — need to check if tm_mpc_signing topic requires deploying our own overlay node |
| sCrypt (for Level 3 covenant) | Production on BSV mainnet | No — Level 2 doesn't need it |
| bsv-worm `wallet_tools.rs:13` hardcoded URL | Known bug, 1-line fix | **Yes for Mode A** — fix before testing remote wallet |

---

## File Count Summary

| Category | Files | Lines (approx) |
|----------|-------|----------------|
| Rust source (.rs) | ~27 | ~3,000 |
| Config (Cargo.toml, etc.) | 8 | ~200 |
| Documentation (.md) | 3+ | ~1,500 |
| BRC drafts | 4 (pending) | ~1,200 |
| Tests | 0 | 0 |
| **Total** | **~42** | **~5,900** |

Compare to bsv-worm: 90 .rs files, ~1,600 tests. This project is at day 1.
