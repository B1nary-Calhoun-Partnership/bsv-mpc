# bsv-mpc
> Decentralized MPC threshold signing network for autonomous AI agents on BSV.
>
> The agent's private key never exists. Two or more parties each hold one share.
> Valid ECDSA signatures require t+1 parties to cooperate. Neither party alone can sign.
> Nodes are discoverable via BSV overlay network. Fees distributed on-chain.

## CRITICAL: POCs are the source of truth — use BRC standards, not BIPs

**Every implementation must be ported from proven POC code.** We validated 16 POCs (15 on mainnet through M0, plus POC 16 inline-SM + Paillier pool in Phase G). The POC code in `poc/` is the authoritative source for how things work. If a stub description contradicts a POC, **the POC is correct** — fix the stub.

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

6 Rust crates in a Cargo workspace (`bsv-mpc-core`, `bsv-mpc-messagebox`, `bsv-mpc-proxy`, `bsv-mpc-worker`, `bsv-mpc-service`, `bsv-mpc-overlay`). The MPC Signing Proxy presents a BRC-100 wallet API on localhost:3322 — bsv-worm (or any BRC-100 client) calls it unchanged. Internally, every signing request becomes a 2-party CGGMP'24 threshold ECDSA ceremony with a remote Key Share Service (KSS). Ceremony round-messages flow over the canonical MessageBox transport (Phase A-F); a future Phase H crate will provide a wasm32-compatible CF Worker client.

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

bsv-worm requires ZERO code changes. The MPC Signing Proxy is a drop-in replacement for bsv-wallet-cli. See [docs/ECOSYSTEM.md](docs/ECOSYSTEM.md) for the full component map.

### Crates

#### bsv-mpc-core (~7.5K LOC, 14 files)
Core MPC protocol layer wrapping cggmp24 for threshold ECDSA on secp256k1. **All protocol modules fully implemented — zero todo!() stubs.** Coordinators are inline-driven (Phase G G-4b/c/d): no thread spawn, no tokio dep in this crate, wasm32-buildable + wasm32-runtime-verified via `tests/wasm32_dkg.rs`.
- `dkg.rs` — DKG coordinator (4-round CGGMP'24). Inline `StateMachineImpl` ownership; `init()` + `process_round()` drive `proceed()` synchronously.
- `signing.rs` — Threshold signing (1 round with presig, 4 without). BRC-42 additive offset support. Inline drive via shared `drive_inline` kernel.
- `presigning.rs` — Background presignature generation (3-round protocol). Inline drive. FIFO pool management.
- `paillier_pool.rs` — At-rest-encrypted Paillier safe-prime keypair pool per MPC-Spec §06.10.1 / ADR-0041. `PrimePoolStorage` trait + `InMemoryPoolStorage` + AES-256-GCM (BRC-42-derived key) + ≥2-keypair floor + `backfill_to_floor`. Consumed by `DkgCoordinator::with_pool()`.
- `ecdh.rs` — Partial ECDH for threshold key derivation. Lagrange interpolation reconstruction.
- `refresh.rs` — Key refresh via threshold resharing (ported from POC 13). Same joint key, 0 on-chain cost.
- `share.rs` — AES-256-GCM share encryption + HMAC-SHA256 BRC-42 key derivation.
- `hd.rs` — BRC-42 key derivation (NOT BIP-32). `derive_child_pubkey`, `derive_anyone_pubkey`, `compute_invoice`, `compute_brc42_hmac`.
- `proof.rs` — BRC-18 participation proofs — create, OP_RETURN serialize, verify.
- `canonical.rs` — Canonical encoders (CBOR / hash inputs) per MPC-Spec wire layer.
- `envelope.rs` — Canonical signed envelope (Phase A) — encode_strict / decode_strict, BRC-31 outer-auth wrapper.
- `types.rs` — All 10 core types: SessionId, ShareIndex, ThresholdConfig, JointPublicKey, EncryptedShare, Presignature, ParticipationProof, RoundMessage, DkgResult, SigningResult.
- `error.rs` — MpcError enum + From impls.
- **`unsafe impl Send` shield** on `DkgCoordinator`/`SigningCoordinator`/`PresigningManager` (G-4e `a9a7e18`) — safe under documented serialization invariant; structural `SendShield<T>` wrapper deferred to Phase I deployment audit per `docs/archive/PHASE-G-AUDIT.md` §2.5.

#### bsv-mpc-messagebox (~2.9K LOC, 8 files)
Native Rust MessageBox transport client (Phase A-F). Conforms to the canonical TS `@bsv/message-box-client` v2.0.7 spec at `~/bsv/message-box-client/src/MessageBoxClient.ts` — implementation conforms to the canonical TS, never the inverse (Path A, per [`feedback_canonical_ts_immutable`]). Uses native `tokio-tungstenite` for WebSocket subscribe; not yet wasm32-compatible (Phase H will produce a CF-Worker-compatible parallel client crate).
- `client.rs` — Public `MessageBoxClient` API — entry point for `bsv-mpc-service` + downstream consumers.
- `ws.rs` — `/ws` WebSocket subscribe per MPC-Spec §06.4 + §06.12 (reconnect with backoff, ping/pong, missed-message backfill).
- `http.rs` — `POST /sendMessage` + the HTTP polling/inbox path.
- `auth.rs` — BRC-31 mutual auth for the MessageBox transport (`bsv_rs::auth::Peer + SimplifiedFetchTransport`).
- `wire.rs` — Wrap/unwrap between canonical CBOR `MessageEnvelope` and the MessageBox JSON envelope.
- `types.rs` — Wire types matching the BSV `message-box-server` API.
- `error.rs` — `MessageBoxError` + `From` impls.
- `lib.rs` — Module exports + crate-level doc.

#### bsv-mpc-proxy (~8K LOC, 12 files)
BRC-100 compatible signing proxy. Drop-in replacement for bsv-wallet-cli at localhost:3322. Usable as library or binary.
- `server.rs` — Axum router with all 28 BRC-100 endpoints, AppState, background presig task.
- `wallet_api.rs` — All 28 BRC-100 handlers implemented (~3.4K LOC).
- `bridge.rs` — MPC protocol bridge to KSS. HTTP client, share loading/decryption, BRC-31 auth, session management.
- `fee_injector.rs` — Fee output injection into transactions. P2PKH split and bare multisig modes.
- `utxo_tracker.rs` — In-memory UTXO tracking with FIFO management, spending status, basket/tag metadata.
- `presign_manager.rs` — FIFO pool management, background replenishment loop with exponential backoff.
- `storage.rs` — Proxy-side storage layer.
- `config.rs` — `ProxyConfig::from_env()` reads `MPC_*` env vars.
- `error.rs` — ProxyError enum with HTTP status mapping.
- `main.rs` — Binary entry point.
- `lib.rs` — Module declarations + public API for library usage.

#### bsv-mpc-worker (~2.5K LOC, 5 files)
Cloudflare Worker Key Share Service (Rust -> WASM). Holds share_A.
- `lib.rs` — CF Worker router with all 8 endpoints.
- `api.rs` — All 8 handlers call bsv-mpc-core coordinators (DKG, signing, presigning, ECDH). 12 request/response types.
- `storage.rs` — static `ShareStorage` (HashMap/VecDeque) for dev/test only. The **deployed** worker uses `do_storage.rs` (durable DO-SQLite, #4 CLOSED) for shares, presig pool, auth sessions, and #9 KEK-sealed custody — all survive Worker restart. (Ephemeral-compute cosigners MUST persist `share_A` durably; MPC-Spec §16.6.4.)
- `auth.rs` — BRC-31 Authrite implementation including `verify_agent_authorization()`.

#### bsv-mpc-service (~1.2K LOC, 5 files)
Standalone Key Share Service binary. Same API as bsv-mpc-worker but backed by in-memory storage (planned: local SQLite).
- `lib.rs` — AppState struct, `build_router()`, module exports.
- `main.rs` — Axum server with all 10 routes, env config, tracing setup.
- `handlers.rs` — All 9 protocol handlers (DKG, signing, presigning, ECDH, health, share metadata) call bsv-mpc-core coordinators.
- `storage.rs` — HashMap/VecDeque storage for shares, protocol state, presignatures.

#### bsv-mpc-overlay (~1.9K LOC, 7 files)
BSV overlay network integration for MPC node discovery.
- `types.rs` — MpcNodeInfo, DiscoveryQuery, OverlayProof, FeeSettlement, NodeFeeShare, constants.
- `error.rs` — OverlayError with 8 variants.
- `proofs.rs` — `calculate_settlement()` for proportional fee distribution. Proof publication/querying stubs remain.
- `chip.rs` — CHIP token creation/parsing (BRC-23 PushDrop), overlay publication, SDK admin token wrappers.
- `discovery.rs` — SLAP/CLAP node discovery via BSV SDK `LookupResolver`, health checking, reputation scoring, client-side filtering/ranking.
- Topic: `tm_mpc_signing` on BRC-22 overlay.

## Project Layout

```
bsv-mpc/
  Cargo.toml                         # Workspace: 5 crates, shared deps + cggmp24 fork patches
  deny.toml                          # License/advisory policy (copyleft=deny)
  rust-toolchain.toml                # Stable + wasm32-unknown-unknown target
  CLAUDE.md                          # This file — full architecture context
  DECISIONS.md                       # Architectural Decision Log (16 ADRs)
  README.md                          # Project overview + quick start
  SPECS.md                           # Plain English specifications
  INTEGRATION.md                     # bsv-worm integration, wallet-cli architecture
  STATUS.md                          # Implementation status and timeline
  EXECUTION-PLAN.md                  # Parallel sprint coordination
  POCS.md                            # POC validation plan (POCs 1-7 fleshed out; POCs 1-16 all PASSED — see LESSONS.md + STATUS.md)
  TESTING.md                         # Test strategy (unit / integration / E2E)
  LESSONS.md                         # Technical findings from all 16 POCs
  HANDOFF.md                         # Quick-start for new sessions
  src/lib.rs                         # Root crate (exists solely to host integration tests)
  crates/
    bsv-mpc-core/src/                # 14 files, ~7.5K LOC — inline coordinators + paillier_pool
    bsv-mpc-messagebox/src/          # 8 files, ~2.9K LOC — native MessageBox client (Phase A-F)
    bsv-mpc-proxy/src/               # 12 files, ~8K LOC — all 28 BRC-100 handlers implemented
    bsv-mpc-worker/src/              # 5 files, ~2.5K LOC — all handlers + BRC-31 auth implemented
    bsv-mpc-service/src/             # 5 files, ~1.2K LOC — all handlers implemented, in-memory storage
    bsv-mpc-overlay/src/             # 7 files, ~1.9K LOC — chip + discovery implemented, proof pub TODO
  # cggmp24 fork is no longer a local submodule. Used to live at ./cggmp21-fork as a private partnership-org submodule; switched to the PUBLIC Calhooon-org fork pinned via root Cargo.toml [patch."https://github.com/LFDT-Lockness/cggmp21"] at commit 6c6421ee (Calhooon/cggmp21 branch brc42-additive-shift; tracks LFDT-Lockness/cggmp21 PR #200 which exposes set_additive_shift on SigningBuilder).
  poc/                               # 16 POCs, all VALIDATED (~13K LOC). Latest: poc16-sm-inline (Phase G G-3).
  tests/
    e2e.rs                           # E2E test suite: proxy + KSS over HTTP (6 scenarios)
  docs/
    ECOSYSTEM.md                     # How bsv-mpc fits into BSV agent infrastructure
    THREAT-MODEL.md                  # Security threat analysis
    THRESHOLD-ROADMAP.md             # Beta + GA deployment milestones
  brc-drafts/                        # 4 BRC specification drafts (~2K lines total)
  regulatory/                        # MPC regulatory analysis (5 files)
  research/                          # JIT-MPC architecture + network analysis
  contracts/mpc-fee-pool/            # sCrypt fee covenant (deferred to Phase 2)
```

Each crate also has its own `CLAUDE.md` with crate-specific architecture and implementation details.

## POC Validation Results

All 16 POCs PASSED. POCs 1-15 ran in M0 (Mar 2026) and de-risked the cryptographic + wire path; POC 16 (`poc16-sm-inline`) ran in Phase G Step 3 (2026-05-19) and proved the inline-SM + Paillier-pool design before the production port. See `LESSONS.md` for comprehensive technical findings.

| POC | Risk Validated | Result |
|-----|---------------|--------|
| POC 1: cggmp24 signing | DKG + signing on secp256k1 | **PASS** |
| POC 2: WASM compilation | cggmp24 compiles to wasm32-unknown-unknown | **PASS** — 636KB module |
| POC 3: Key derivation | MPC-derived keys match standard HD wallets | **PASS** — Self_ needs partial ECDH |
| POC 4: Real BSV transaction | MPC produces valid mainnet tx | **PASS** — mainnet tx confirmed |
| POC 5: HTTP latency | MPC signing fast enough over HTTP | **PASS** — 359us presigned, 135us HTTP RTT |
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
| POC 16: Inline SM + Paillier pool | Inline state-machine drive, no thread spawn, prime pool round-trip | **PASS** — 5 hard gates green, drove Phase G inline rewrite |

### Key POC Lessons (see LESSONS.md for full details)

- **Key derivation**: `Anyone` = local (0 round-trips), `Self_`/`Other` = partial ECDH with KSS (1 round-trip)
- **Transaction signing**: Use `PrehashedDataToSign::from_scalar()`, `TransactionSignature::to_checksig_format()` for DER + 0x41 sighash byte
- **BEEF**: Wallet's `internalizeAction` requires AtomicBEEF with full merkle proof ancestry. Use BSV SDK `Beef` struct.
- **DKG persistence**: ALWAYS persist DKG keys before funding — ephemeral keys = lost funds
- **BRC-31 auth**: 1 KSS round-trip for partial ECDH, then local HMAC offset. Additive share offset: `reconstruct(shares) + hmac = child_priv`
- **Key refresh**: Built from cggmp24 primitives (~50 LOC). Same joint key, 0 on-chain cost. cggmp24 lacks this natively.
- **CF Worker**: worker crate 0.7 required. DO storage for key shares (10KB JSON). 16ms HTTPS RTT.
- **Fee injection**: Must inject BEFORE sighash. Graceful failure when change < fee.
- **cggmp24 fork**: Published Calhooon/cggmp21 fork at commit `6c6421ee` (tracks upstream LFDT-Lockness/cggmp21 PR #200) exposes `set_additive_shift()` for BRC-42 derived key signing. Pinned via `[patch."https://github.com/LFDT-Lockness/cggmp21"]` in root Cargo.toml. No submodule.

## Implementation Status

~21.7K LOC production code + ~12.3K LOC POC code. 258 tests across all crates. **Zero remaining `todo!()` stubs in production code.** Remaining work: overlay proof publication, SQLite persistence for bsv-mpc-service.

| Layer | Status | Notes |
|-------|--------|-------|
| Types + errors (all crates) | **Complete** | All types defined, all error enums done |
| Config + routing (proxy, service, worker) | **Complete** | Axum/CF Worker routers wired, env config working |
| MPC protocol (DKG) | **Complete** | dkg.rs: 4-round CGGMP'24, inline SM (Phase G G-4b, no thread spawn, wasm32-verified) |
| MPC protocol (signing) | **Complete** | signing.rs: 1-round (presig) and 4-round (interactive) paths, inline SM (Phase G G-4c) |
| MPC protocol (presigning) | **Complete** | presigning.rs: 3-round offline generation, FIFO pool, inline SM (Phase G G-4d) |
| Paillier safe-prime pool | **Complete** | paillier_pool.rs (Phase G G-4a): MPC-Spec §06.10.1 / ADR-0041 — at-rest-encrypted, floor=2 default, `backfill_to_floor` API |
| Partial ECDH | **Complete** | ecdh.rs: Lagrange interpolation for threshold key derivation |
| Key refresh | **Complete** | refresh.rs: threshold resharing, ported from POC 13 |
| Share encryption (AES-256-GCM) | **Complete** | share.rs: encrypt/decrypt/derive_key |
| BRC-42 key derivation | **Complete** | hd.rs: all counterparty types |
| BRC-18 participation proofs | **Complete** | proof.rs: create/serialize/verify |
| MPC bridge (proxy -> KSS) | **Complete** | bridge.rs: HTTP client, share loading, session mgmt |
| Fee injection | **Complete** | fee_injector.rs: P2PKH + multisig modes |
| UTXO tracking | **Complete** | utxo_tracker.rs: in-memory FIFO management |
| Presign pool management | **Complete** | presign_manager.rs: FIFO + background replenishment |
| BRC-100 handlers (28 of 28) | **Complete** | All wallet API handlers implemented |
| Fee settlement calculation | **Complete** | proofs.rs: proportional distribution |
| E2E test suite | **Complete** | tests/e2e.rs: 6 scenarios incl mainnet tx signing |
| KSS handlers (worker + service) | **Complete** | All protocol handlers call bsv-mpc-core coordinators |
| BRC-31 auth (worker) | **Complete** | Authrite implementation in auth.rs |
| CHIP tokens + discovery | **Complete** | chip.rs + discovery.rs |
| KSS storage (worker) | **DO SQLite (deployed)** | `do_storage.rs` durable DO-SQLite is the deployed path (#4 CLOSED): shares (+owner_identity §08.1), presig pool, auth sessions, and #9 KEK-sealed custody all persist across restarts. The static in-mem store is dev/test only. |
| KSS storage (service) | **In-memory + durable custody** | HashMap for shares/presigs (ephemeral); `share_A` persisted KEK-sealed to the worker DO via #9 durable custody (recovered on restart → no fund-lock). Local SQLite not yet wired. |
| BRC-31 owner-authz (§07.6/§08.1) | **Complete + deployed** | Worker + service + deployed container enforce owner-authz on funded-boundary routes; deploy smoke-test guards it. |
| Durable share custody (#9) | **Complete + deployed** | KEK-sealed `share_A` on the DO via authed `/custody/{put,get}-share`; fail-closed at DKG; lazy recover on restart. |
| Overlay proof publication | **TODO** | publish_proof, query_proofs, count_proofs_by_node |

## Key Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| cggmp24 | published Calhooon/cggmp21 fork `rev = 6c6421ee` (tracks PR #200) | CGGMP'24 threshold ECDSA + `set_additive_shift()` for BRC-42 |
| cggmp24-keygen | published Calhooon/cggmp21 fork `rev = 6c6421ee` (same) | DKG protocol |
| bsv | **crates.io `bsv-rs` 0.3.0** (patched to `../bsv-rs`) | BSV primitives (features = ["transaction", "wallet"]) |
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
- **BSV SDK**: Published crate `bsv-rs 0.3.11` from crates.io, patched to local `../bsv-rs` for development. Features: `["transaction", "wallet"]`.
- **Config**: All via `MPC_*` environment variables (see proxy `config.rs`).
- **License**: MIT OR Apache-2.0 (workspace-level). deny.toml enforces copyleft=deny.
- **Rust edition**: 2021, minimum 1.85.
- **Mainnet only**: Never testnet. BSV mainnet is the target.
- **ADRs**: Architectural decisions are logged in [DECISIONS.md](DECISIONS.md) (16 ADRs).

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

| Draft | Content |
|-------|---------|
| brc-mpc-signing.md | Threshold ECDSA protocol specification |
| brc-mpc-discovery.md | Node discovery via SHIP/SLAP + CHIP tokens |
| brc-mpc-fees.md | Fee distribution and settlement (3 levels) |
| brc-mpc-proofs.md | Participation proof format and verification |

## Relationship to bsv-worm

bsv-mpc is a separate project that bsv-worm uses transparently. The proxy at `localhost:3322` presents the exact same BRC-100 HTTP API as bsv-wallet-cli. bsv-worm's `wallet.rs` calls it unchanged.

- `createAction` is the critical path — UTXO selection, tx construction, fee injection, MPC signing per input, broadcasting.
- `encrypt`/`decrypt`/`createHmac`/`verifyHmac` derive keys locally from the MPC share — no KSS communication.
- Fee outputs are injected transparently. bsv-worm sees slightly higher tx costs but doesn't account for them specially.

## Transaction Infrastructure

### Key repos (all at ~/bsv/)
| Repo | Path | Purpose |
|------|------|---------|
| **bsv-rs** | `~/bsv/bsv-rs` | BSV SDK — Transaction, Script, PublicKey, BRC-42, sighash, BEEF |
| **cggmp21-fork** | published Calhooon/cggmp21 `rev = 6c6421ee` (no submodule) | Local fork with `set_additive_shift()` for BRC-42 derived key signing |
| **bsv-wallet-cli** | `~/bsv/bsv-wallet-cli` | Reference BRC-100 wallet daemon. Use for funding MPC addresses. |
| **rust-wallet-toolbox** | `~/bsv/rust-wallet-toolbox` | Wallet engine — ProtoWallet, StorageSqlx, WalletSigner |
| **rust-middleware** | `~/bsv/rust-middleware` | `bsv-auth-cloudflare` — USE THIS for BRC-31 auth in bsv-mpc-worker |
| **agents** | `~/bsv/agents` | 11 production CF Workers — pattern reference for BRC-31 + BRC-29 in WASM |
| **BRCs** | `~/bsv/BRCs` | 114 BRC specifications (BRC-31, BRC-42, BRC-100, BRC-22/23/24/25) |

### Broadcasting
Use built-in broadcasters from bsv-rs (`WhatsOnChainBroadcaster`, `ArcBroadcaster`) or rust-wallet-toolbox (`services.post_beef()` with failover). Do NOT write raw HTTP calls.

### Mainnet only
Never testnet. BSV mainnet transactions cost fractions of a cent. Testnet has different behavior and hides real bugs.

## Development

```bash
cargo build                                                    # Build all crates
cargo test                                                     # Run all 258 unit tests
cargo test --test e2e                                          # Run E2E test suite
cargo test --test e2e -- --ignored --nocapture                 # Run mainnet E2E (needs E2E_MAINNET=1)
cargo clippy                                                   # Lint (must be warning-free)
cargo build -p bsv-mpc-worker --target wasm32-unknown-unknown  # WASM build for CF Worker
cargo run -p bsv-mpc-proxy                                     # Start signing proxy
cargo run -p bsv-mpc-service                                   # Start standalone KSS
```

Required: `rustup target add wasm32-unknown-unknown` for WASM builds.

## Key Decisions

See [DECISIONS.md](DECISIONS.md) for the full Architectural Decision Log (16 ADRs). Key choices:

- **cggmp24 over cb-mpc**: Pure Rust, WASM-compatible, MIT, Kudelski-audited. cb-mpc is C++ (no WASM, GG18/GG20).
- **cggmp24 local fork**: Adds `set_additive_shift()` for BRC-42 derived key signing. Git submodule patched in Cargo.toml.
- **`num-bigint` over `rug`**: Avoids LGPL contamination and enables WASM compilation.
- **Drop-in proxy pattern**: Any BRC-100 client gets MPC signing with zero code changes.
- **Presigning over on-demand**: Stockpile presigs in idle time (7ms effective) vs 4-round on-demand (180ms).
- **CF Workers for KSS**: $5/mo, 0ms cold start, global edge, WASM native, DO SQLite storage.
- **Separate CF accounts**: Agent container and KSS on different CF accounts for defense-in-depth.
- **Local symmetric crypto from share**: Only signing requires 2PC; encrypt/decrypt/HMAC are local.
- **Fee via multisig (Level 2)**: MPC nodes self-settle. Upgrade to sCrypt covenant (Level 3) for trustless enforcement.
- **Overlay topic `tm_mpc_signing`**: Uses existing SHIP/SLAP infrastructure.
- **Runar for covenants**: Rust-native BSV Script compiler instead of sCrypt TypeScript.
- **BSV SDK from crates.io**: Primary dependency is `bsv-rs 0.3.11` from crates.io, with local path override for development.

## Open Questions

- Should `fee_injector` use bare multisig P2MS or P2SH multisig for the fee output? (Both implemented, need to decide default.)
- How to handle `createAction` with multiple inputs needing different BRC-42 derivation paths?
- Performance of `num-bigint` in WASM — POC 2 validated compilation but didn't benchmark latency.
- Should the cggmp24 fork's `set_additive_shift()` be contributed upstream?
