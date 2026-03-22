# bsv-mpc
> Decentralized MPC threshold signing network for autonomous AI agents on BSV.
>
> The agent's private key never exists. Two or more parties each hold one share.
> Valid ECDSA signatures require t+1 parties to cooperate. Neither party alone can sign.
> Nodes are discoverable via BSV overlay network. Fees distributed on-chain.

## CRITICAL: POCs are the source of truth — use BRC standards, not BIPs

**Every implementation must be ported from proven POC code.** We validated 15 POCs on mainnet. The POC code in `poc/` is the authoritative source for how things work. If a stub description contradicts a POC, **the POC is correct** — fix the stub.

**BSV uses BRC standards**, not Bitcoin BIPs. Key standards:
- **Key derivation: BRC-42** (`~/bsv/BRCs/key-derivation/0042.md`) — ECDH + HMAC-SHA256 with invoice strings (protocolID, keyID, counterparty). NOT BIP-32/SLIP-10.
- **Auth: BRC-31** (`~/bsv/BRCs/peer-to-peer/0031.md`) — Authrite mutual auth. NOT generic ECDSA.
- **Wallet API: BRC-100** (`~/bsv/BRCs/wallet/0100.md`)
- **Overlay: BRC-22/23/24/25** — SHIP/SLAP/CHIP
- **Proofs: BRC-18** — OP_RETURN data format

**Before implementing ANY function:**
1. Find the corresponding POC that proves the pattern
2. Read the POC code line-by-line
3. Read the relevant BRC spec from `~/bsv/BRCs/`
4. Port the POC pattern, don't invent alternatives

## IMPORTANT: This is a 100% Rust project

**Everything is Rust.** All 5 crates, all tests, the CF Worker (Rust -> WASM), the standalone service, the overlay integration — all Rust. No TypeScript, no Go, no Python, no JavaScript. The only exception is the sCrypt fee covenant (contracts/mpc-fee-pool/) which is deferred to Phase 2.

When writing code for this project, write Rust. When writing tests, write Rust. When building the CF Worker, compile Rust to WASM. Do not introduce other languages.

For BSV smart contracts (Level 3 fee covenant), use **Runar** (`https://github.com/icellan/runar`) — a Rust-native BSV Script compiler. This keeps even the covenant code in Rust instead of sCrypt TypeScript.

## Architecture

5 Rust crates in a Cargo workspace. The MPC Signing Proxy presents a BRC-100 wallet API on localhost:3322 — bsv-worm (or any BRC-100 client) calls it unchanged. Internally, every signing request becomes a 2-party CGGMP'24 threshold ECDSA ceremony with a remote Key Share Service (KSS).

```
bsv-worm                          bsv-mpc
+------------------+               +------------------+
| Agent loop       |               | MPC Signing Proxy|
| Calls wallet API | <-localhost:3322-> | (bsv-mpc-proxy)  |
| at localhost:3322|               |                  |
| (unchanged)      |               | <-- 2PC signing -->
+------------------+               +-----|------------+
                                         |
                                   +-----+-----------+
                                   | Key Share Service|
                                   | (bsv-mpc-worker |
                                   |  or bsv-mpc-    |
                                   |  service)        |
                                   +------------------+
```

bsv-worm requires ZERO code changes. The MPC Signing Proxy is a drop-in replacement for bsv-wallet-cli.

### Crates

#### bsv-mpc-core (~8K LOC, 11 files)
Core MPC protocol layer wrapping cggmp24 for threshold ECDSA on secp256k1. **All protocol modules fully implemented — zero todo!() stubs.**
- `dkg.rs` — **Implemented.** DKG coordinator (4-round CGGMP'24). Thread-based SM bridge. 12 tests incl 2-of-2 and 2-of-3 integration.
- `signing.rs` — **Implemented.** Threshold signing (1 round with presig, 4 without). `SigningCoordinator` with full state machine management via `std::thread` + `mpsc` channels.
- `presigning.rs` — **Implemented.** Background presignature generation (3-round protocol). FIFO pool management, exponential backoff on generation failures, utilization metrics.
- `ecdh.rs` — **Implemented.** Partial ECDH for threshold key derivation. Lagrange interpolation reconstruction for "self"/"other" counterparty BRC-42 paths.
- `refresh.rs` — **Implemented.** Key refresh via threshold resharing (ported from POC 13). Same joint key, 0 on-chain cost, old shares cryptographically invalidated.
- `share.rs` — **Implemented.** AES-256-GCM share encryption + HMAC-SHA256 BRC-42 key derivation. 22 tests.
- `hd.rs` — **Implemented.** BRC-42 key derivation (NOT BIP-32). `derive_child_pubkey`, `derive_anyone_pubkey`, `compute_invoice`, `compute_brc42_hmac`. 24 tests incl BRC-42 spec vectors.
- `proof.rs` — **Implemented.** BRC-18 participation proofs — create, OP_RETURN serialize, verify. 33 tests.
- `types.rs` — **Complete.** All 10 core types: SessionId, ShareIndex, ThresholdConfig, JointPublicKey, EncryptedShare, Presignature, ParticipationProof, RoundMessage, DkgResult, SigningResult.
- `error.rs` — **Complete.** MpcError enum with 9 variants + From impls.

#### bsv-mpc-proxy (~6.2K LOC, 9 files)
BRC-100 compatible signing proxy. Drop-in replacement for bsv-wallet-cli at localhost:3322.
- `server.rs` — **Complete.** Axum router with all 28 BRC-100 endpoints, AppState, background presig task.
- `wallet_api.rs` — 28 handlers. 18 working or partially implemented, **10 todo!() stubs** remaining (certificates, discovery, key linkage, some crypto ops).
- `bridge.rs` — **Implemented.** MPC protocol bridge to KSS. HTTP client, share loading/decryption, session management.
- `fee_injector.rs` — **Implemented.** Fee output injection into transactions. P2PKH split and bare multisig modes. 7 tests.
- `utxo_tracker.rs` — **Implemented.** In-memory UTXO tracking with FIFO management, spending status, basket/tag metadata.
- `presign_manager.rs` — **Implemented.** FIFO pool management, background replenishment loop with exponential backoff.
- `config.rs` — **Complete.** `ProxyConfig::from_env()` reads `MPC_*` env vars.
- `error.rs` — **Complete.** ProxyError enum with HTTP status mapping.
- `main.rs` — **Complete.** Binary entry point.

#### bsv-mpc-worker (~2.5K LOC, 4 files)
Cloudflare Worker Key Share Service (Rust -> WASM). Holds share_A.
- `lib.rs` — **Complete.** CF Worker router with all 8 endpoints.
- `api.rs` — All 12 request/response types defined. Handler bodies have detailed pseudocode.
- `storage.rs` — ShareStorage struct + ShareMetadata. 3-table DO SQLite schema. Methods have pseudocode.
- `auth.rs` — `verify_agent_authorization()` **implemented**. BRC-31 handshake and request verification have pseudocode.

#### bsv-mpc-service (~1.2K LOC, 4 files)
Standalone Key Share Service binary. Same API as bsv-mpc-worker but backed by local SQLite.
- `main.rs` — **Complete.** Axum server with all 9 routes, AppState with RwLock storage.
- `handlers.rs` — `handle_health` **implemented**. 8 protocol handlers have pseudocode.
- `storage.rs` — SqliteShareStorage with 5-table schema. 15+ methods have pseudocode.

#### bsv-mpc-overlay (~1.9K LOC, 6 files + tests)
BSV overlay network integration for MPC node discovery.
- `types.rs` — **Complete.** MpcNodeInfo, DiscoveryQuery, OverlayProof, FeeSettlement, constants.
- `error.rs` — **Complete.** OverlayError with 8 variants.
- `proofs.rs` — `calculate_settlement()` **implemented** for proportional fee distribution. 4 todo!() stubs for proof publication/querying.
- `chip.rs` — CHIP token creation/parsing for node advertisement (BRC-23). Pseudocode.
- `discovery.rs` — SLAP/CLAP lookup to find MPC nodes (BRC-24/25). Pseudocode.
- `tests/integration.rs` — Integration test for CHIP tokens + discovery (ported from POC 14).
- Topic: `tm_mpc_signing` on BRC-22 overlay.

## Project Layout

```
bsv-mpc/
  Cargo.toml                         # Workspace: 5 crates, shared deps + cggmp24 fork patches
  deny.toml                          # License/advisory policy (copyleft=deny)
  rust-toolchain.toml                # Stable + wasm32-unknown-unknown target
  CLAUDE.md                          # This file — full architecture context
  SPECS.md                           # Plain English specifications
  INTEGRATION.md                     # bsv-worm integration, wallet-cli architecture
  STATUS.md                          # Implementation status and timeline
  POCS.md                            # POC validation plan (all 15 completed)
  TESTING.md                         # Test strategy (unit / integration / E2E)
  LESSONS.md                         # Technical findings from all 15 POCs
  HANDOFF.md                         # Quick-start for new sessions
  src/lib.rs                         # Root crate (exists solely to host integration tests)
  crates/
    bsv-mpc-core/src/                # 11 files, ~8K LOC — all protocol modules implemented
    bsv-mpc-proxy/src/               # 9 files, ~6.2K LOC — bridge + fee injector implemented
    bsv-mpc-worker/src/              # 4 files, ~2.5K LOC — router complete, handlers pseudocode
    bsv-mpc-service/src/             # 4 files, ~1.2K LOC — router complete, handlers pseudocode
    bsv-mpc-overlay/src/             # 6 files + tests, ~1.9K LOC — settlement implemented
  poc/                               # 15 POCs, all VALIDATED (~12,300 LOC)
  tests/
    e2e.rs                           # E2E test suite: proxy + KSS over HTTP (6 scenarios)
  brc-drafts/                        # 4 BRC specification drafts (~2K lines total)
  regulatory/                        # MPC regulatory analysis (5 files)
    compute-service-position-paper.md  # MPC operators = compute providers, not MSBs
    fee-model-evaluation.md            # 4 fee model comparison (per-tx, subscription, hybrid, tiered)
    mpc-fee-network-analysis.md        # Business fundamentals analysis
    action-items.md                    # Regulatory work items before Beta/GA
  contracts/mpc-fee-pool/            # sCrypt fee covenant (deferred to Phase 2)
  research/                          # Strategic analysis docs
```

## POC Validation Results

All 15 POCs PASSED. See `LESSONS.md` for comprehensive technical findings.

| POC | Risk Validated | Result |
|-----|---------------|--------|
| POC 1: cggmp24 signing | DKG + signing on secp256k1 | **PASS** |
| POC 2: WASM compilation | cggmp24 compiles to wasm32-unknown-unknown | **PASS** — 636KB module |
| POC 3: Key derivation | MPC-derived keys match standard HD wallets | **PASS** — Self_ needs partial ECDH |
| POC 4: Real BSV transaction | MPC produces valid mainnet tx | **PASS** — mainnet tx confirmed |
| POC 5: HTTP latency | MPC signing fast enough over HTTP | **PASS** — 359µs presigned, 135µs HTTP RTT |
| POC 6: Wallet toolbox dep | Proxy can reuse rust-wallet-toolbox | **PASS** — ~30-line fork |
| POC 7: Fee injection | Fee output injected without breaking tx | **PASS** — 3-output mainnet tx |
| POC 8: BRC-31 auth | Authrite works through MPC | **PASS** — 1 KSS round-trip for partial ECDH |
| POC 9: encrypt/decrypt | MPC encryption compatible with normal wallet | **PASS** — byte-identical keys |
| POC 10: CF Worker HTTPS | MPC signing over real HTTPS to CF Worker | **PASS** — 16ms RTT, DO storage works |
| POC 11: Fee settlement | Nodes co-sign settlement tx | **PASS** — 2-of-3 mainnet settlement |
| POC 12: 3-of-5 threshold | Production config works | **PASS** — 5-party DKG, any 3-of-5 signs |
| POC 13: Key refresh | Shares refreshed without moving funds | **PASS** — same key, 0 on-chain cost |
| POC 14: Overlay discovery | SHIP/SLAP node registration | **PASS** — 4/4 mainnet SLAP trackers alive |
| POC 15: Capstone integration | bsv-worm works through MPC proxy | **PASS** — full x402 payment via MPC |

### Key POC Lessons (see LESSONS.md for full details)

- **Key derivation**: `Anyone` = local (0 round-trips), `Self_`/`Other` = partial ECDH with KSS (1 round-trip)
- **Transaction signing**: Use `PrehashedDataToSign::from_scalar()`, `TransactionSignature::to_checksig_format()` for DER + 0x41 sighash byte
- **BEEF**: Wallet's `internalizeAction` requires AtomicBEEF with full merkle proof ancestry. Use BSV SDK `Beef` struct.
- **DKG persistence**: ALWAYS persist DKG keys before funding — ephemeral keys = lost funds
- **BRC-31 auth**: 1 KSS round-trip for partial ECDH, then local HMAC offset. Additive share offset: `reconstruct(shares) + hmac = child_priv`
- **Key refresh**: Built from cggmp24 primitives (~50 LOC). Same joint key, 0 on-chain cost. cggmp24 lacks this natively.
- **CF Worker**: worker crate 0.7 required. DO storage for key shares (10KB JSON). 16ms HTTPS RTT.
- **Fee injection**: Must inject BEFORE sighash. Graceful failure when change < fee.
- **cggmp24 fork**: Local fork at `../cggmp21-fork` exposes `set_additive_shift()` for BRC-42 derived key signing.

## Implementation Status

~20K LOC production code + ~12,300 LOC POC code. Core protocol fully implemented. Remaining work: KSS handlers, remaining wallet API endpoints, overlay publication.

| Layer | Status | Notes |
|-------|--------|-------|
| Types + errors (all crates) | **Complete** | All types defined, all error enums done |
| Config + routing (proxy, service, worker) | **Complete** | Axum/CF Worker routers wired, env config working |
| MPC protocol (DKG) | **Implemented** | dkg.rs: 4-round CGGMP'24, thread-based SM, 12 tests |
| MPC protocol (signing) | **Implemented** | signing.rs: 1-round (presig) and 4-round (interactive) paths |
| MPC protocol (presigning) | **Implemented** | presigning.rs: 3-round offline generation, FIFO pool |
| Partial ECDH | **Implemented** | ecdh.rs: Lagrange interpolation for threshold key derivation |
| Key refresh | **Implemented** | refresh.rs: threshold resharing, ported from POC 13 |
| Share encryption (AES-256-GCM) | **Implemented** | share.rs: encrypt/decrypt/derive_key, 22 tests |
| BRC-42 key derivation | **Implemented** | hd.rs: all counterparty types, 24 tests |
| BRC-18 participation proofs | **Implemented** | proof.rs: create/serialize/verify, 33 tests |
| MPC bridge (proxy → KSS) | **Implemented** | bridge.rs: HTTP client, share loading, session mgmt |
| Fee injection | **Implemented** | fee_injector.rs: P2PKH + multisig modes, 7 tests |
| UTXO tracking | **Implemented** | utxo_tracker.rs: in-memory FIFO management |
| Presign pool management | **Implemented** | presign_manager.rs: FIFO + background replenishment |
| BRC-100 handlers (18 of 28) | **Partial** | 10 todo!() stubs (certificates, discovery, key linkage) |
| Fee settlement calculation | **Implemented** | proofs.rs: proportional distribution |
| E2E test suite | **Implemented** | tests/e2e.rs: 6 scenarios incl mainnet tx signing |
| KSS handlers (worker + service) | **Pseudocode** | All types defined, handler bodies need porting from POCs |
| Overlay publication (CHIP/SLAP) | **Pseudocode** | chip.rs, discovery.rs need porting from POC 14 |
| KSS storage (SQLite/DO) | **Pseudocode** | Schema documented, methods need implementation |

### Timeline

| Milestone | Due | Status |
|---|---|---|
| M0: POC Validation | Mar 21 | **DONE** (15/15) |
| M1: Core MPC Library | Mar 28 | **DONE** — all protocol modules implemented |
| M2: Signing Proxy | Apr 4 | In progress — bridge + fee injector done, wallet API 18/28 |
| M3: CF Worker Deployment | Apr 8 | |
| M4: Fee System | Apr 11 | |
| M5: Integration & BRCs | Apr 14 | |
| Beta: Overlay & Hardening | Apr 25 | |

## Key Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| cggmp24 | **local fork** (`../cggmp21-fork`) | CGGMP'24 threshold ECDSA + `set_additive_shift()` for BRC-42 |
| cggmp24-keygen | **local fork** (same) | DKG protocol |
| bsv | local path `../rust-sdk` | BSV primitives (features = ["transaction", "wallet"]) |
| axum | 0.8 | HTTP server (proxy + service), WebSocket support |
| reqwest | 0.12 | HTTP client (proxy to KSS), rustls-tls |
| worker | 0.7 | CF Worker Rust SDK (bsv-mpc-worker only) |
| aes-gcm | 0.10 | Share encryption |
| sha2 | 0.10 | Hashing, BRC-42 derivation |
| tokio | 1 | Async runtime (full features) |
| thiserror | 2 | Error derive macros |
| glass_pumpkin | =1.9.0 | Pinned to avoid rand_core 0.6/0.10 conflict with fast-paillier |

**CRITICAL**: cggmp24 MUST use `num-bigint` feature (not `rug`) for two reasons:
1. `rug` depends on GMP which is LGPL — copyleft contamination (deny.toml blocks this)
2. `rug` is a C library that does not compile to `wasm32-unknown-unknown`

**CRITICAL**: Dev profile optimizes all dependencies at opt-level 2 (see Cargo.toml). Without this, num-bigint/Paillier operations are 10-100x slower, making DKG take minutes in tests.

## Conventions

- **Error handling**: `MpcError` in core, `ProxyError` in proxy, `OverlayError` in overlay. All use thiserror.
- **Share encryption**: BRC-42 HMAC-SHA256 key derivation to AES-256-GCM. Protocol ID: `[2, "mpc share"]`, key_id: session_id, counterparty: `"self"`.
- **Protocol messages**: JSON over HTTP (proxy to KSS). Format: `{ session_id, round, from, to, payload }`.
- **WASM target**: bsv-mpc-worker targets `wasm32-unknown-unknown`. Must use `getrandom/js` for entropy.
- **BSV SDK**: Local path dependency at `../rust-sdk` with `features = ["transaction", "wallet"]`.
- **Config**: All via `MPC_*` environment variables (see proxy `config.rs`).
- **License**: MIT OR Apache-2.0 (workspace-level). deny.toml enforces copyleft=deny.
- **Rust edition**: 2021, minimum 1.85.
- **Mainnet only**: Never testnet. BSV mainnet is the target.

## BRC-100 Proxy Endpoint Map

All 28 BRC-100 endpoints are routed in `server.rs`:

**MPC-routed** (require KSS): `getPublicKey`, `createSignature`, `createAction`, `internalizeAction`.

**Local-only** (no MPC rounds): `encrypt`, `decrypt`, `createHmac`, `verifyHmac`, `verifySignature`, `listOutputs`, `listActions`, `relinquishOutput`, `getNetwork`, `getVersion`, `isAuthenticated`, certificate operations, discovery, key linkage, `health`.

## KSS API (Worker/Service)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/dkg/init` | BRC-31 | Start DKG ceremony |
| POST | `/dkg/round` | BRC-31 | Process DKG round |
| POST | `/sign/init` | BRC-31 | Start signing |
| POST | `/sign/round` | BRC-31 | Process signing round |
| POST | `/presign/init` | BRC-31 | Start presigning |
| POST | `/presign/round` | BRC-31 | Process presigning round |
| GET | `/health` | none | Liveness check |
| GET | `/shares/:agent_id` | BRC-31 | Share metadata |

## BRC Standards (Drafts)

Four BRC specification drafts exist in `brc-drafts/`:

| Draft | Lines | Content |
|-------|-------|---------|
| brc-mpc-signing.md | ~470 | Threshold ECDSA protocol specification |
| brc-mpc-discovery.md | ~490 | Node discovery via SHIP/SLAP + CHIP tokens |
| brc-mpc-fees.md | ~650 | Fee distribution and settlement (3 levels) |
| brc-mpc-proofs.md | ~450 | Participation proof format and verification |

## Relationship to bsv-worm

bsv-mpc is a separate project that bsv-worm uses transparently. The proxy at `localhost:3322` presents the exact same BRC-100 HTTP API as bsv-wallet-cli. bsv-worm's `wallet.rs` calls it unchanged.

- `createAction` is the critical path — UTXO selection, tx construction, fee injection, MPC signing per input, broadcasting.
- `encrypt`/`decrypt`/`createHmac`/`verifyHmac` derive keys locally from the MPC share — no KSS communication.
- Fee outputs are injected transparently. bsv-worm sees slightly higher tx costs but doesn't account for them specially.

## Transaction Infrastructure

### Key repos (all at ~/bsv/)
| Repo | Path | Purpose |
|------|------|---------|
| **rust-sdk** | `~/bsv/rust-sdk` | BSV SDK — Transaction, Script, PublicKey, BRC-42, sighash, BEEF |
| **cggmp21-fork** | `~/bsv/cggmp21-fork` | Local fork with `set_additive_shift()` for BRC-42 derived key signing |
| **bsv-wallet-cli** | `~/bsv/bsv-wallet-cli` | Reference BRC-100 wallet daemon. Use for funding MPC addresses. |
| **rust-wallet-toolbox** | `~/bsv/rust-wallet-toolbox` | Wallet engine — ProtoWallet, StorageSqlx, WalletSigner |
| **rust-middleware** | `~/bsv/rust-middleware` | `bsv-auth-cloudflare` — USE THIS for BRC-31 auth in bsv-mpc-worker |
| **agents** | `~/bsv/agents` | 11 production CF Workers — pattern reference for BRC-31 + BRC-29 in WASM |
| **BRCs** | `~/bsv/BRCs` | 114 BRC specifications (BRC-31, BRC-42, BRC-100, BRC-22/23/24/25) |

### Broadcasting
Use built-in broadcasters from rust-sdk (`WhatsOnChainBroadcaster`, `ArcBroadcaster`) or rust-wallet-toolbox (`services.post_beef()` with failover). Do NOT write raw HTTP calls.

### Mainnet only
Never testnet. BSV mainnet transactions cost fractions of a cent. Testnet has different behavior and hides real bugs.

## Development

```bash
cargo build                                                    # Build all crates
cargo test                                                     # Run unit tests
cargo test --test e2e                                          # Run E2E test suite
cargo test --test e2e -- --ignored --nocapture                 # Run mainnet E2E (needs E2E_MAINNET=1)
cargo clippy                                                   # Lint (must be warning-free)
cargo build -p bsv-mpc-worker --target wasm32-unknown-unknown  # WASM build for CF Worker
cargo run -p bsv-mpc-proxy                                     # Start signing proxy
cargo run -p bsv-mpc-service                                   # Start standalone KSS
```

Required: `rustup target add wasm32-unknown-unknown` for WASM builds.

## Key Decisions

- **cggmp24 over cb-mpc**: Pure Rust, WASM-compatible, MIT, Kudelski-audited. cb-mpc is C++ (no WASM, GG18/GG20).
- **cggmp24 local fork**: Adds `set_additive_shift()` for BRC-42 derived key signing. Patched in Cargo.toml.
- **`num-bigint` over `rug`**: Avoids LGPL contamination and enables WASM compilation.
- **Drop-in proxy pattern**: Any BRC-100 client gets MPC signing with zero code changes.
- **Presigning over on-demand**: Stockpile presigs in idle time (7ms effective) vs 4-round on-demand (180ms).
- **CF Workers for KSS**: $5/mo, 0ms cold start, global edge, WASM native, DO SQLite storage.
- **Separate CF accounts**: Agent container and KSS on different CF accounts for defense-in-depth.
- **Local symmetric crypto from share**: Only signing requires 2PC; encrypt/decrypt/HMAC are local.
- **Fee via multisig (Level 2)**: MPC nodes self-settle. Upgrade to sCrypt covenant (Level 3) for trustless enforcement.
- **Overlay topic `tm_mpc_signing`**: Uses existing SHIP/SLAP infrastructure.
- **Runar for covenants**: Rust-native BSV Script compiler instead of sCrypt TypeScript.

## Open Questions

- Should `fee_injector` use bare multisig P2MS or P2SH multisig for the fee output? (Both implemented, need to decide default.)
- How to handle `createAction` with multiple inputs needing different BRC-42 derivation paths?
- Performance of `num-bigint` in WASM — POC 2 validated compilation but didn't benchmark latency.
- Should the cggmp24 fork's `set_additive_shift()` be contributed upstream?
