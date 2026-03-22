# bsv-mpc
> Decentralized MPC threshold signing network for autonomous AI agents on BSV.
>
> The agent's private key never exists. Two or more parties each hold one share.
> Valid ECDSA signatures require t+1 parties to cooperate. Neither party alone can sign.
> Nodes are discoverable via BSV overlay network. Fees distributed on-chain.

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

#### bsv-mpc-core
Core MPC protocol layer wrapping cggmp24 for threshold ECDSA on secp256k1.
- `dkg.rs` — DKG coordinator (4-round CGGMP'24 EC-DKG). `DkgCoordinator` struct with `init()` and `process_round()`. Bodies: `todo!()`.
- `signing.rs` — Threshold signing (1 round with presig, 4 without). `SigningCoordinator` with `sign()`, `init_round()`, `process_round()`. Bodies: `todo!()`.
- `presigning.rs` — Presignature pool. `PresigningManager` with **working** pool management (take/add/should_replenish). `generate()`: `todo!()`.
- `share.rs` — AES-256-GCM share encryption. `validate_encrypted_share()` **implemented**. encrypt/decrypt/derive: `todo!()`.
- `hd.rs` — SLIP-10/BIP-32 HD derivation from MPC shares. `todo!()`.
- `proof.rs` — BRC-18 participation proofs. `todo!()`.
- `types.rs` — **Complete.** All 10 core types: SessionId, ShareIndex, ThresholdConfig, JointPublicKey, EncryptedShare, Presignature, ParticipationProof, RoundMessage, DkgResult, SigningResult.
- `error.rs` — **Complete.** MpcError enum with 9 variants + From impls.

#### bsv-mpc-proxy
BRC-100 compatible signing proxy. Drop-in replacement for bsv-wallet-cli at localhost:3322.
- `server.rs` — **Complete.** Axum router with all 28 BRC-100 endpoints, AppState, background presig task.
- `wallet_api.rs` — 28 handler stubs. 4 implemented (`get_network`, `get_version`, `is_authenticated`, `health`). 24 are `todo!()`.
- `bridge.rs` — MPC protocol bridge to KSS. `todo!()`.
- `fee_injector.rs` — Fee output injection into `createAction`. `todo!()`.
- `presign_manager.rs` — **Working.** FIFO pool management, background replenishment loop structure.
- `config.rs` — **Complete.** `ProxyConfig::from_env()` reads `MPC_*` env vars.
- `error.rs` — **Complete.** ProxyError enum with HTTP status mapping.
- `main.rs` — **Complete.** Binary entry point.

#### bsv-mpc-worker
Cloudflare Worker Key Share Service (Rust -> WASM). Holds share_A.
- `lib.rs` — **Complete.** CF Worker router with all 8 endpoints.
- `api.rs` — All 12 request/response types defined. Handler bodies: `todo!()`.
- `storage.rs` — ShareStorage struct + ShareMetadata. 3-table DO SQLite schema documented. Methods: `todo!()`.
- `auth.rs` — `verify_agent_authorization()` **implemented**. Other auth methods: `todo!()`.

#### bsv-mpc-service
Standalone Key Share Service binary. Same API as bsv-mpc-worker but backed by local SQLite.
- `main.rs` — **Complete.** Axum server with all 9 routes (8 KSS + Authrite handshake), AppState with RwLock storage.
- `handlers.rs` — Only `handle_health` implemented. 8 protocol handlers: `todo!()`.
- `storage.rs` — SqliteShareStorage with 5-table schema documented. 15+ methods: `todo!()`.

#### bsv-mpc-overlay
BSV overlay network integration for MPC node discovery.
- `types.rs` — **Complete.** MpcNodeInfo, DiscoveryQuery, OverlayProof, FeeSettlement, constants.
- `error.rs` — **Complete.** OverlayError with 8 variants.
- `proofs.rs` — `calculate_settlement()` **implemented** for proportional fee distribution. Proof publication: `todo!()`.
- `chip.rs` — CHIP token creation/parsing for node advertisement (BRC-23). `todo!()`.
- `discovery.rs` — SLAP/CLAP lookup to find MPC nodes (BRC-24/25). `todo!()`.
- Topic: `tm_mpc_signing` on BRC-22 overlay.

## Project Layout

```
bsv-mpc/
  Cargo.toml                         # Workspace: 5 crates, shared deps
  deny.toml                          # License/advisory policy (copyleft=deny)
  rust-toolchain.toml                # Stable + wasm32-unknown-unknown target
  CLAUDE.md                          # This file — full architecture context
  SPECS.md                           # Plain English specifications
  INTEGRATION.md                     # bsv-worm integration, wallet-cli architecture
  STATUS.md                          # Implementation status and timeline
  POCS.md                            # 7 POC validation plan (all 15 completed)
  TESTING.md                         # Test strategy (unit / integration / E2E)
  LESSONS.md                         # Technical findings from all 15 POCs
  HANDOFF.md                         # Quick-start for new sessions
  crates/
    bsv-mpc-core/src/                # 9 files, ~1.3K LOC
    bsv-mpc-proxy/src/               # 9 files, ~1.9K LOC
    bsv-mpc-worker/src/              # 4 files, ~1.0K LOC
    bsv-mpc-service/src/             # 4 files, ~0.8K LOC
    bsv-mpc-overlay/src/             # 6 files, ~0.9K LOC
  poc/                               # 15 POCs, all VALIDATED (~12,300 LOC)
    poc1-cggmp24-signing/            # DKG + signing on secp256k1
    poc2-wasm/                       # Compiles to wasm32-unknown-unknown (636KB)
    poc3-key-derivation/             # BRC-42 compatible with all counterparty types
    poc4-real-tx/                    # MPC-signed mainnet tx + BEEF internalization
    poc5-http-latency/               # 359µs presigned, 135µs HTTP RTT
    poc6-toolbox-dep/                # Toolbox reuse validated, ~30-line fork
    poc7-fee-injection/              # 3-output tx on mainnet (recipient+change+fee)
    poc8-brc31-auth/                 # BRC-31 auth via partial ECDH + share offset
    poc9-encrypt-decrypt/            # Byte-identical keys, zero migration data loss
    poc10-cf-worker-https/           # 1069KB WASM, 16ms RTT, deployed CF Worker
    poc11-fee-settlement/            # 2-of-3 settlement on mainnet
    poc12-three-of-five/             # 5-party DKG, any 3 sign, 4.4ms presig
    poc13-key-refresh/               # Threshold resharing (~50 LOC), 0 on-chain cost
    poc14-overlay-discovery/         # 4/4 SLAP trackers live, production-ready
    poc15-capstone/                  # bsv-worm think "2+2" through MPC proxy
  brc-drafts/                        # 4 BRC specification drafts (~2K lines total)
  contracts/mpc-fee-pool/            # sCrypt fee covenant (deferred to Phase 2)
  research/                          # Strategic analysis docs
  tests/                             # Integration tests (not yet written)
```

## POC Validation Results

Four POCs validated — the critical crypto path is fully de-risked:

| POC | Risk Validated | Result |
|-----|---------------|--------|
| POC 1: cggmp24 signing | Does cggmp24 API work for 2-of-2 DKG + signing on secp256k1? | **PASS** — DKG completes, signatures verify with bsv SDK |
| POC 2: WASM compilation | Does cggmp24 compile to `wasm32-unknown-unknown` and run? | **PASS** — 636KB module, 79.5MB RSS, 1ms presig combine |
| POC 3: Key derivation | Do MPC-derived keys match standard HD wallets? | **PASS** — Self_ needs partial ECDH w/ Lagrange interpolation |
| POC 4: Real BSV transaction | Can MPC produce a valid mainnet transaction? | **PASS** — [TXID on WhatsOnChain](https://whatsonchain.com/tx/2e4a3afa0ae5c9c92422f6c703e36590884165669775cf7c7705a2ae43046bb7) |
| POC 6: Wallet toolbox dep | Can proxy reuse rust-wallet-toolbox, swap only signer? | **PASS** — ZERO coupling in UTXO/fee/handlers. ~30-line fork to add WalletSignerApi trait. 4-6 week path confirmed. |
| POC 7: Fee injection | Can fee output be injected without breaking tx? | **PASS** — 3-output tx on mainnet. [TXID](https://whatsonchain.com/tx/6033e4fb4872d1d6a28acb6659f35641e63738bb8297bca56dc88b60276b2d42) |
| POC 5: HTTP latency | Is MPC signing fast enough over HTTP? | **PASS** — 359µs presigned (target <50ms), ~135µs HTTP overhead per round |
| POC 12: 3-of-5 threshold | Does production config work? | **PASS** — 5-party DKG 138ms, any 3-of-5 subset signs, 4.4ms presig combine, below-threshold correctly rejected |
| POC 13: Key refresh | Can shares be refreshed without moving funds? | **PASS** — Built threshold resharing (~50 LOC) from cggmp24 primitives. Same joint key, 0 on-chain cost, old shares invalidated. |
| POC 8: BRC-31 auth | Does Authrite work through MPC? | **PASS** — 1 KSS round-trip for partial ECDH (~135µs), then local HMAC offset. Server-side verification works. DER wire format correct. |
| POC 9: encrypt/decrypt | Is MPC encryption compatible with normal wallet? | **PASS** — Byte-identical symmetric keys. Zero data loss during migration. All 3 protocols (memory, state, conversation) validated. |
| POC 11: Fee settlement | Can MPC nodes co-sign a settlement tx using their own threshold signing? | **PASS** — 2-of-3 DKG among nodes, proportional split (45/35/20%), all 3 subsets sign, below-threshold rejected. [TXID](https://whatsonchain.com/tx/afbb7ecd746bf75c346303e863e9e6a4bd17184d8149ac68f0bdcc1003e485d7) |
| POC 10: CF Worker HTTPS | Does MPC signing work over real HTTPS to a deployed CF Worker? | **PASS** — 1069KB WASM, 1ms startup, 16ms HTTPS RTT p50, DKG in 52ms (2 requests), signing verified by BSV SDK. DO storage works. No CORS/header issues. |
| POC 14: Overlay discovery | Does SHIP/SLAP work for MPC node registration? | **PASS** — 4/4 mainnet SLAP trackers alive (BSV Association + Babbage). Live SHIP host discovered. tm_mpc_signing query works (0 results = nobody registered yet). No fallback needed — overlay is production-ready. |
| POC 15: Capstone integration | Does bsv-worm work unchanged through MPC proxy? | **PASS** — `bsv-worm status` + `bsv-worm think "what is 2+2"` both work. Full x402 payment via MPC threshold signing. [TXID](https://whatsonchain.com/tx/4653d09a9a0baca057d954237a5cbc0f6d95c385d1e4aa2e98fa1113283349b1). 8/28 BRC-100 endpoints functional, rest stubbed. |

### Critical Lessons from POC 3 + POC 4

**Key derivation (POC 3):**
- `Anyone` counterparty: derive locally from joint pubkey (0 round-trips)
- `Self_` counterparty: partial ECDH with KSS (1 round-trip, Lagrange interpolation on VSS shares)
- `Other(key)` counterparty: partial ECDH with KSS (1 round-trip)
- Memory encryption (`[2, "worm memory"]`, counterparty "self") hits the Self_ path

**Transaction signing (POC 4):**
- Use `PrehashedDataToSign::from_scalar()` for cggmp24 signing (not raw bytes)
- Use `TransactionSignature::to_checksig_format()` for DER + sighash byte (0x41 = ALL|FORKID)
- BIP-143 sighash uses internal byte order txid (reversed from display)
- cggmp24 auto-normalizes to low-S (BIP-62 compliant)
- ARC GorillaPool (`https://arc.gorillapool.io`) works without API key
- Fee rate: 100 sats/kb works on mainnet

**BEEF construction (POC 4):**
- Wallet's `internalizeAction` requires **AtomicBEEF** with complete merkle proof ancestry
- Use BSV SDK's `Beef` struct — don't build manually
- WoC TSC endpoint (`/tx/{txid}/proof/tsc`) works for merkle proofs; regular `/proof` returns 404
- TSC → BUMP conversion needed (`tsc_to_merkle_path` helper)
- The MPC proxy MUST maintain BEEF ancestry for its transactions

**DKG key persistence (POC 4):**
- **ALWAYS persist DKG keys before funding the MPC address** — ephemeral keys = lost funds
- POC 4 lost 3,000 sats (~$0.0015) from ephemeral DKG keys in failed runs

**Wallet toolbox reuse (POC 6):**
- **ZERO signer coupling** in StorageSqlx, Services, handlers, types — all reusable as-is
- **WalletSigner is the only blocker** — hardcoded concrete struct, not a trait
- **Fix: ~30-line fork** — add `WalletSignerApi` trait, make `Wallet` generic over it, implement `MpcSigner`
- **Alternative (no-fork):** Use `create_action(sign_and_process: false)` → sign externally → `sign_action` with pre-computed unlocking scripts
- **MpcSigner prototype works** — same SignerInput structs, same sighash, same unlocking script, only signing step changes

**BRC-31 auth (POC 8):**
- 1 KSS round-trip (~135µs) for partial ECDH, then each party adds HMAC offset locally (0 extra round-trips)
- Additive share offset proven: `reconstruct(shares) + hmac = child_priv`
- Server-side verification works via ECDH commutativity
- DER encoding for BRC-31 wire format confirmed working

**Encrypt/decrypt compatibility (POC 9):**
- **Byte-identical symmetric keys** between MPC and normal wallet — zero data loss during migration
- Existing bsv-worm encrypted memory readable after switching to MPC proxy
- Algorithm: 2 partial ECDH rounds with Lagrange interpolation
- All 3 protocols validated: `worm memory`, `worm state`, `worm conversation`

**Key refresh / threshold resharing (POC 13):**
- **Built from scratch** using cggmp24's existing primitives (`generic_ec_zkp::polynomial`, `lagrange_coefficient_at_zero`). ~50 LOC. No upstream library changes.
- Same joint key, same BSV address, 0 on-chain cost (vs re-DKG which needs ~188 sat fund transfer)
- Old shares cryptographically invalidated after reshare
- Port `threshold_reshare()` to `bsv-mpc-core` with Schnorr proofs for production hardening
- Enables Fireblocks-style automatic refresh (every few minutes, near-zero cost)
- **cggmp24 lacks this natively** — cggmp24 v0.7 only has aux_info_gen, cggmp21 v0.6 has non-threshold refresh but requires rug (LGPL, no WASM). Our solution avoids both limitations.

**Overlay discovery (POC 14):**
- **Production overlay is LIVE** — no fallback needed
- 4 mainnet SLAP trackers: 3 from BSV Association (US/EU/AP bsvb.tech) + 1 Babbage (bapp.dev)
- `LookupResolver` query works — `tm_mpc_signing` returns 0 outputs (correct, nobody registered yet)
- Path to production: `create_overlay_admin_token(Protocol::Ship, key, domain, "tm_mpc_signing")` → broadcast via `TopicBroadcaster` → nodes discoverable on live overlay
- Local registry pattern (register → discover → deregister) proven end-to-end

**Fee settlement (POC 11):**
- **Nodes' DKG is completely independent from agent's DKG** — same CGGMP'24 protocol, different participants, different joint key
- 2-of-3 among nodes: any 2 can settle, no single node can steal fees
- Proportional distribution with integer division; remainder to first node (matches `calculate_settlement()` in overlay crate)
- Settlement tx: 1 input (fee UTXO at nodes' joint address) → N outputs (one P2PKH per node, proportional)
- Total cost: 3000 sats input, 150 sats mining fee, 2850 sats distributed (45%/35%/20%)
- All 3 subsets (A+B, A+C, B+C) produce valid signatures verified by BSV SDK
- Below-threshold (single node) correctly rejected
- **Confirms Level 2 fee settlement architecture** — nodes self-settle using their own threshold signing

**CF Worker HTTPS (POC 10):**
- **cggmp24 compiles and runs inside CF Worker WASM** — 1069KB module (gzip 393KB), 1ms startup, no dep conflicts with worker 0.7
- **HTTPS RTT is ~16ms p50** (US West ↔ CF edge). Presigned signing will be ~16ms end-to-end — 12x under 200ms target
- **Deterministic replay works** for stateless protocol handling — Worker replays protocol from scratch each request using seeded RNG. DKG keygen completes in 52ms (2 HTTPS requests). Signing works but replay is slow (28s) due to Paillier prime re-generation
- **Production approach**: Store key shares in DO (KeyShare serializes to 10KB JSON via serde_json), load per signing request — eliminates Paillier replay. Or use DO WebSocket for persistent SM connection
- **DO storage confirmed** — put/get works for small (10B) and large (10KB) values. First access ~58ms (instance creation), subsequent ~24ms
- **No CORS, header size, or cold start issues** — all validated
- **worker crate 0.7 required** — 0.4 rejected by worker-build v0.7.5. DO API changed: `impl DurableObject` no longer needs `#[durable_object]` macro, `fetch(&self)` not `fetch(&mut self)`

**Fee injection (POC 7):**
- Fee output is a simple append + change reduction — no structural tx changes
- **Must inject BEFORE sighash** — fee is part of hashOutputs in BIP-143 (confirmed working)
- Split fee among N operators handles remainder correctly
- Graceful failure when change < fee (outputs not modified)
- 3-output tx (recipient + change + fee) works on mainnet at 150 sats mining fee

**Wallet integration quirks (POC 4 full loop):**
- **Wallet uses `Origin: http://admin.com` header** for default basket access
- **UTXO vout is NOT always 0** — wallet puts its own change outputs first, user output index varies
- **WoC indexing delay: 9-18s** before a tx appears after wallet broadcast — retry logic needed
- **BEEF needs full ancestry** — chain of unconfirmed txs back to a confirmed ancestor with BUMP
- **Full loop cost: 188 sats** (~$0.00009) for: wallet → fund MPC → MPC sign → return to wallet

**All 15 POCs PASSED.** See `LESSONS.md` for comprehensive technical findings organized by topic.

**Capstone integration (POC 15):**
- bsv-worm status + think both work through MPC proxy (port 3323)
- Full x402 payment: BRC-31 handshake → createAction → MPC signing → broadcast → refund internalized
- 8/28 BRC-100 endpoints functional (`isAuthenticated`, `getPublicKey`, `getNetwork`, `getVersion`, `createSignature`, `createAction`, `internalizeAction`, `listOutputs`)
- POC shortcuts to fix in production: BRC-31 auth uses reconstructed key (needs share offsets), encrypt/decrypt uses reconstructed key (needs partial ECDH), UTXO management queries WoC per request (needs local tracker)

## Implementation Status

~15% production code + ~12,300 LOC POC code. Scaffolding complete. All protocol logic is `todo!()` in crates but **fully proven in POCs**.

| Layer | Status | Notes |
|-------|--------|-------|
| Types + errors (core, proxy, overlay) | **Complete** | All types defined, all error enums done |
| Config + routing (proxy, service, worker) | **Complete** | Axum/CF Worker routers wired, env config working |
| Pool management (presign_manager) | **Complete** | FIFO take/add/replenish, background loop |
| POC validation (15 POCs) | **Complete** | 15/15 passed, ~12,300 LOC, all risks de-risked |
| MPC protocol (DKG, signing, presigning) | **POC-proven** | Patterns in poc1, poc5, poc12. Port to crates. |
| Share encryption (AES-256-GCM) | **Stub** | Validation done, encrypt/decrypt `todo!()` |
| BRC-42 key derivation | **POC-proven** | poc3, poc8, poc9 cover all counterparty types |
| Transaction signing | **POC-proven** | poc4 mainnet tx, poc6 toolbox integration, poc15 full flow |
| BRC-100 handlers (24 of 28) | **Stub** | 8 working in poc15, pseudocode in crate stubs |
| CF Worker KSS | **POC-proven** | poc10 deployed, 16ms RTT, DO storage validated |
| Fee injection | **POC-proven** | poc7 mainnet 3-output tx, lib.rs nearly production-ready |
| Fee settlement | **POC-proven** | poc11 mainnet settlement, 2-of-3 validated |
| BRC-31 auth | **POC-proven** | poc8 full chain, partial ECDH + share offset |
| Encrypt/decrypt | **POC-proven** | poc9 byte-identical keys, all protocols |
| Key refresh | **POC-proven** | poc13 ~50 LOC resharing, same key |
| Overlay discovery | **POC-proven** | poc14 live SLAP trackers, production-ready |
| KSS storage (SQLite) | **Stub** | Schema documented, methods `todo!()` |

### Revised Timeline

| Milestone | Due | Status |
|---|---|---|
| M0: POC Validation | Mar 21 | **DONE** (15/15) |
| M1: Core MPC Library | Mar 28 | Next |
| M2: Signing Proxy | Apr 4 | |
| M3: CF Worker Deployment | Apr 8 | |
| M4: Fee System | Apr 11 | |
| M5: Integration & BRCs | Apr 14 | |
| Beta: Overlay & Hardening | Apr 25 | |

## Key Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| cggmp24 | git (LFDT-Lockness/cggmp21) | CGGMP'24 threshold ECDSA |
| cggmp24-keygen | git (same repo) | DKG protocol |
| bsv | local path `../rust-sdk` | BSV primitives (features = ["transaction"]) |
| axum | 0.8 | HTTP server (proxy + service) |
| reqwest | 0.12 | HTTP client (proxy to KSS), rustls-tls |
| worker | 0.4 | CF Worker Rust SDK (bsv-mpc-worker only) |
| aes-gcm | 0.10 | Share encryption |
| sha2 | 0.10 | Hashing, BRC-42 derivation |
| tokio | 1 | Async runtime (full features) |
| thiserror | 2 | Error derive macros |

**CRITICAL**: cggmp24 MUST use `num-bigint` feature (not `rug`) for two reasons:
1. `rug` depends on GMP which is LGPL — copyleft contamination (deny.toml blocks this)
2. `rug` is a C library that does not compile to `wasm32-unknown-unknown`

## Why cggmp24

| Property | Value |
|----------|-------|
| Protocol | CGGMP'24 (state of the art threshold ECDSA) |
| License | MIT/Apache-2.0 (with `num-bigint` backend) |
| WASM | Confirmed via POC 2 |
| Audit | Kudelski Security |
| Production | Powers Dfns signing infrastructure |
| TSSHOCK | Fixed (CVE-2025-66017) |
| secp256k1 | Native support (Bitcoin's curve) |
| HD wallets | SLIP-10/BIP-32 confirmed via POC 3 |

## Conventions

- **Error handling**: `MpcError` in core, `ProxyError` in proxy, `OverlayError` in overlay. All use thiserror.
- **Share encryption**: BRC-42 HMAC-SHA256 key derivation to AES-256-GCM. Protocol ID: `[2, "mpc share"]`, key_id: session_id, counterparty: `"self"`.
- **Protocol messages**: JSON over HTTP (proxy to KSS). Format: `{ session_id, round, from, to, payload }`.
- **WASM target**: bsv-mpc-worker targets `wasm32-unknown-unknown`. Must use `getrandom/js` for entropy.
- **BSV SDK**: Local path dependency at `../rust-sdk` with `features = ["transaction"]`.
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

For POCs and testing that involve real BSV transactions (POC 4, POC 7, POC 11, etc.):

### Funding an MPC address
bsv-wallet-cli runs on the local machine at localhost:3322 (bsv-worm's wallet). Use it to send sats to the MPC joint address:
```bash
# From bsv-worm's working wallet:
cd ~/bsv/rust-bsv-worm && cargo run -- think "send 10000 sats to <mpc-joint-address>"
# Or use the wallet HTTP API directly:
curl -X POST http://localhost:3322/createAction -d '{"description":"fund MPC","outputs":[{"satoshis":10000,"lockingScript":"<p2pkh-script>"}]}'
```

### Building transactions manually (for POCs)
Use bsv SDK (`~/bsv/rust-sdk`) directly — `Transaction`, `Script`, `PublicKey`, `PrivateKey` types. Construct P2PKH transactions, compute BIP-143 sighashes, build unlocking scripts. No wallet needed for raw tx construction.

### Broadcasting
Use the built-in broadcasters from rust-sdk or rust-wallet-toolbox — do NOT write raw HTTP calls.

**rust-sdk** (`~/bsv/rust-sdk/src/transaction/broadcasters/`):
```rust
// Simple single-tx broadcast
use bsv::ArcBroadcaster; // or WhatsOnChainBroadcaster
let broadcaster = WhatsOnChainBroadcaster::mainnet();
let result = broadcaster.broadcast(&tx).await;
// ARC (TAAL):
let broadcaster = ArcBroadcaster::new("https://arc.taal.com", Some("api-key".into()));
```

**rust-wallet-toolbox** (`~/bsv/rust-wallet-toolbox/src/services/`):
```rust
// Multi-service with failover (WhatsOnChain → ARC TAAL → ARC GorillaPool → Bitails)
services.post_beef(&beef_bytes, &txids).await // UntilSuccess mode
```

Use the SDK broadcasters for POCs (simpler). Use the toolbox Services for production (failover).

### UTXO queries
WhatsOnChain API (free):
```
GET https://api.whatsonchain.com/v1/bsv/main/address/<address>/unspent
```
Returns UTXOs at an address. Use this to find spendable outputs at the MPC address.

### Key repos (all at ~/bsv/)
| Repo | Path | What it provides |
|------|------|-----------------|
| **rust-sdk** | `~/bsv/rust-sdk` | BSV SDK — Transaction, Script, PublicKey, BRC-42 key derivation, sighash, BEEF. Core dependency. |
| **bsv-wallet-cli** | `~/bsv/bsv-wallet-cli` | Reference BRC-100 wallet daemon (Rust + Axum + SQLite). The binary we're replacing. Use for funding MPC addresses during POCs. Has BRC-31 auth implementation. |
| **rust-wallet-toolbox** | `~/bsv/rust-wallet-toolbox` | Wallet engine — ProtoWallet (signing), StorageSqlx (UTXOs), WalletSigner (tx signing orchestration). If POC 6 passes, reuse this and only swap the signer. |
| **rust-wallet-infra** | `~/bsv/rust-wallet-infra` | CF Worker wallet (Rust → WASM, D1+R2 storage). Fallback patterns if toolbox doesn't work. Already deployed. |
| **rust-middleware** | `~/bsv/rust-middleware` | `bsv-auth-cloudflare` crate — **USE THIS** for BRC-31 auth + BRC-29 payment middleware in bsv-mpc-worker. Ready-made, production-proven. Don't rewrite auth from scratch. |
| **agents** | `~/bsv/agents` | 11 production CF Workers with BRC-31 auth + BRC-29 micropayments. **Best working example of BRC-31 in Rust WASM.** Pattern reference for WASM deployment, nonce-bound pricing, identity-scoped results, refund handling. Use these as the reference implementation for how bsv-mpc-worker should handle auth. |
| **BRCs** | `~/bsv/BRCs` | 114 BRC specifications. Key ones: BRC-31 (`peer-to-peer/0031.md` — Authrite mutual auth spec), BRC-42 (`key-derivation/0042.md`), BRC-100 (`wallet/0100.md`), BRC-22/23/24/25 (overlays). Read BRC-31 spec directly when implementing auth. |
| **rust-wallet-utils** | `~/bsv/rust-wallet-utils` | CLI wallet utility with BRC-42 key derivation. Test reference. |

### Mainnet only
Never testnet. BSV mainnet transactions cost fractions of a cent. Testnet has different behavior and hides real bugs.

## Development

```bash
cargo build                                                    # Build all crates
cargo test                                                     # Run tests
cargo clippy                                                   # Lint (must be warning-free)
cargo build -p bsv-mpc-worker --target wasm32-unknown-unknown  # WASM build for CF Worker
cargo run -p bsv-mpc-proxy                                     # Start signing proxy
cargo run -p bsv-mpc-service                                   # Start standalone KSS
```

Required: `rustup target add wasm32-unknown-unknown` for WASM builds.

## Key Decisions

- **cggmp24 over cb-mpc**: Pure Rust, WASM-compatible, MIT, Kudelski-audited. cb-mpc is C++ (no WASM, GG18/GG20).
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

- When will cggmp24 add key refresh? Currently missing in v0.7 (exists in older cggmp21). Could backport or contribute upstream.
- Should `fee_injector` use bare multisig P2MS or P2SH multisig for the fee output?
- Should bsv-mpc-proxy maintain its own UTXO set or delegate to bsv-wallet-cli for non-signing operations?
- How to handle `createAction` with multiple inputs needing different BRC-42 derivation paths?
- Performance of `num-bigint` in WASM — POC 2 validated compilation but didn't benchmark latency.
