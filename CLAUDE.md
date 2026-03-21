# bsv-mpc
> Decentralized MPC threshold signing network for autonomous AI agents on BSV.
>
> The agent's private key never exists. Two or more parties each hold one share.
> Valid ECDSA signatures require t+1 parties to cooperate. Neither party alone can sign.
> Nodes are discoverable via BSV overlay network. Fees distributed on-chain.

## IMPORTANT: This is a 100% Rust project

**Everything is Rust.** All 5 crates, all tests, the CF Worker (Rust → WASM), the standalone service, the overlay integration — all Rust. No TypeScript, no Go, no Python, no JavaScript. The only exception is the sCrypt fee covenant (contracts/mpc-fee-pool/) which is deferred to Phase 2 and uses sCrypt's TypeScript eDSL — but that is NOT part of the core build and should not be worked on until Level 2 multisig settlement is proven.

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
- `dkg.rs` -- Distributed Key Generation (CGGMP'24 EC-DKG). 4-round protocol: commitment, decommitment, share distribution, verification. Produces a joint secp256k1 public key (~230ms). `DkgCoordinator` struct with `init()` and `process_round()` methods. `DkgRoundResult` enum (NextRound/Complete).
- `signing.rs` -- Threshold signing. Two modes: 1 round with presignature, 4 rounds without. `SigningCoordinator` struct with `sign()` (fast path) and `init_round()`/`process_round()` (interactive). Produces DER-encoded ECDSA signatures with low-s normalization (BIP-62). `SigningRoundResult` enum (NextRound/Complete).
- `presigning.rs` -- Background presignature stockpiling. 3-round offline protocol generates nonce shares and range proofs. `PresigningManager` struct with `generate()`, `take()`, `should_replenish()`. FIFO consumption. Pool size configurable (default 20). Each presignature ~500 bytes serialized.
- `share.rs` -- Share encryption/decryption. AES-256-GCM with BRC-42 derived keys (`HMAC-SHA256(root_key, "bsv-mpc-share" || session_id)`). `encrypt_share()`, `decrypt_share()`, `derive_share_encryption_key()`, `validate_encrypted_share()`. Nonce: 12 bytes random per encryption. Shares never exist in plaintext at rest.
- `hd.rs` -- HD derivation from MPC shares. SLIP-10/BIP-32 compatible child key derivation for standard BSV paths (`m/44'/236'/0'/0/0`). Non-hardened derivation is public-key-only (no MPC communication). Hardened derivation requires MPC protocol (not yet implemented). `derive_child_key()`, `parse_derivation_path()`.
- `proof.rs` -- BRC-18 participation proof generation. `create_participation_proof()`, `proof_to_op_return()`, `verify_participation_proof()`. OP_RETURN format: protocol ID + session hash + signing hash + agent identity + participant identities + fee txid + timestamp.
- `types.rs` -- `SessionId`, `ShareIndex`, `ThresholdConfig`, `JointPublicKey`, `EncryptedShare`, `Presignature`, `ParticipationProof`, `RoundMessage`, `DkgResult`, `SigningResult`.
- `error.rs` -- `MpcError` enum (Dkg, Signing, ShareStorage, InvalidThreshold, InvalidShare, PresigningExhausted, Encryption, Serialization, Protocol). `Result<T>` alias.

#### bsv-mpc-proxy
BRC-100 compatible signing proxy. Drop-in replacement for bsv-wallet-cli at localhost:3322.
- `server.rs` -- Axum router with all 28 BRC-100 endpoints grouped by subsystem. `AppState` struct (config, bridge, presign_manager, fee_injector). Starts background presignature replenishment task.
- `wallet_api.rs` -- Handler implementations for each BRC-100 endpoint. Core signing (MPC-routed): `get_public_key`, `create_signature`, `create_action`, `internalize_action`. Local-only: `encrypt`, `decrypt`, `create_hmac`, `verify_hmac`, `verify_signature`. UTXO: `list_outputs`, `list_actions`, `relinquish_output`. Identity: `get_network`, `get_version`, `is_authenticated`. Certificates: `list_certificates`, `prove_certificate`, `acquire_certificate`, `relinquish_certificate`. Discovery: `discover_by_identity_key`, `discover_by_attributes`. Key linkage: `reveal_counterparty_key_linkage`, `reveal_specific_key_linkage`. Health: `health`.
- `bridge.rs` -- Translates BRC-100 wallet API calls into MPC protocol rounds with the KSS. `MpcBridge` struct holds decrypted share, joint public key, reqwest client for KSS communication.
- `fee_injector.rs` -- Adds MPC signing fee output to every `createAction` transaction. Configurable fee amount (default 1,000 sats). Supports P2PKH split or bare P2MS multisig output.
- `presign_manager.rs` -- Background presignature pool management. `PresignManager` struct. `background_replenish()` runs forever, generating presignatures during idle time.
- `config.rs` -- `ProxyConfig` from environment variables. Port (3322), KSS URL, share path, fee per signing (1000 sats), fee addresses, fee threshold, max presignatures (20), encryption key.
- `error.rs` -- `ProxyError` enum (ShareLoad, KssError, Protocol, FeeInjection, Transaction, PresignatureExhausted, InvalidRequest, Utxo, Encryption, Certificate, Internal). Maps to HTTP status codes (400/502/503/500). Converts from `MpcError`, `reqwest::Error`, `serde_json::Error`, `io::Error`.
- `main.rs` -- Binary entry point. Loads `ProxyConfig`, starts server.

#### bsv-mpc-worker
Cloudflare Worker Key Share Service (Rust to WASM). Holds share_A.
- Target: `wasm32-unknown-unknown` (crate-type `cdylib`)
- `lib.rs` -- CF Worker fetch event handler. Routes requests to protocol handlers. Endpoints: POST `/dkg/init`, `/dkg/round`, `/sign/init`, `/sign/round`, `/presign/init`, `/presign/round`. GET `/health`, `/shares/:agent_id`.
- `api.rs` -- Protocol HTTP handlers. Request/response types: `DkgInitRequest`/`Response`, `DkgRoundRequest`/`Response`, `SignInitRequest`/`Response`, `SignRoundRequest`/`Response`, `PresignInitRequest`/`Response`, `PresignRoundRequest`/`Response`, `HealthResponse`. All mutation endpoints require BRC-31 auth.
- `storage.rs` -- Durable Object SQLite storage. `ShareStorage` struct. 3 tables: `shares` (agent_id PK, encrypted share blob, config JSON), `presigning_state` (intermediate round state), `presignatures` (completed presigs, consumed flag). `ShareMetadata` struct for safe wire exposure. Methods: `store_share`, `get_share`, `delete_share`, `list_agents`, `share_count`, `get_share_metadata`, `store_presigning_state`, `get_presigning_state`, `store_presignature`, `consume_presignature` (atomic FIFO), `presignature_count`.
- `auth.rs` -- BRC-31 Authrite verification for incoming requests. Only the agent that owns a share can request signing with that share.

#### bsv-mpc-service
Standalone Key Share Service binary. Same API as bsv-mpc-worker but backed by local SQLite. For self-hosted deployments, independent operators, Mode A (Split Stack). Currently a placeholder (`lib.rs` only).

#### bsv-mpc-overlay
BSV overlay network integration for MPC node discovery. Currently a placeholder (`lib.rs` only).
- Planned: `chip.rs` -- CHIP token creation/parsing for node advertisement (BRC-23)
- Planned: `discovery.rs` -- SLAP/CLAP lookup to find MPC nodes (BRC-24/25)
- Planned: `proofs.rs` -- Publish/query participation proofs on `tm_mpc_signing` overlay
- Topic: `tm_mpc_signing` on BRC-22 overlay

## Project Layout

```
bsv-mpc/
  Cargo.toml                         # Workspace: 5 crates, shared deps
  deny.toml                          # License/advisory policy (copyleft=deny)
  rust-toolchain.toml                # Stable + wasm32-unknown-unknown target
  crates/
    bsv-mpc-core/
      Cargo.toml                     # cggmp24, cggmp24-keygen, bsv, aes-gcm, sha2
      src/
        lib.rs                       # Module re-exports
        dkg.rs                       # DKG coordinator (4 rounds)
        signing.rs                   # Signing coordinator (1 or 4 rounds)
        presigning.rs                # Presignature pool manager (3 rounds)
        share.rs                     # AES-256-GCM encryption, BRC-42 key derivation
        hd.rs                        # SLIP-10/BIP-32 HD derivation
        proof.rs                     # BRC-18 participation proofs
        types.rs                     # Core data types
        error.rs                     # MpcError enum
    bsv-mpc-proxy/
      Cargo.toml                     # bsv-mpc-core, axum, reqwest
      src/
        main.rs                      # Binary entry point
        lib.rs                       # Module declarations
        server.rs                    # Axum router, AppState, 28 BRC-100 routes
        wallet_api.rs                # BRC-100 handler implementations
        bridge.rs                    # Wallet API to MPC protocol translation
        fee_injector.rs              # Fee output injection in createAction
        presign_manager.rs           # Background presig replenishment
        config.rs                    # ProxyConfig from MPC_* env vars
        error.rs                     # ProxyError enum + HTTP status mapping
    bsv-mpc-worker/
      Cargo.toml                     # bsv-mpc-core, worker 0.4, getrandom/js
      src/
        lib.rs                       # CF Worker fetch handler + routing
        api.rs                       # Protocol handlers + request/response types
        storage.rs                   # DO SQLite: shares, presigning_state, presignatures
        auth.rs                      # BRC-31 request verification
    bsv-mpc-service/
      Cargo.toml                     # Placeholder
      src/
        lib.rs                       # Placeholder
    bsv-mpc-overlay/
      Cargo.toml                     # Placeholder
      src/
        lib.rs                       # Placeholder
  contracts/
    mpc-fee-pool/                    # sCrypt fee covenant (planned, TypeScript)
      src/
  brc-drafts/                        # 4 BRC proposal documents (planned)
  research/                          # Analysis docs (empty)
  tests/                             # Integration tests (empty)
```

## Implementation Status

The project has scaffolding and well-documented `todo!()` stubs. No cggmp24 integration is wired yet.

| Module | Status | Notes |
|--------|--------|-------|
| `bsv-mpc-core/types.rs` | **Complete** | All 10 types defined with full doc comments |
| `bsv-mpc-core/error.rs` | **Complete** | MpcError enum with 9 variants + From impls |
| `bsv-mpc-core/share.rs` | Stub + `validate_encrypted_share()` | Validation logic complete, encrypt/decrypt/derive are todo |
| `bsv-mpc-core/dkg.rs` | Stub | `DkgCoordinator` struct, `init()`, `process_round()` are todo |
| `bsv-mpc-core/signing.rs` | Stub | `SigningCoordinator` struct, `sign()`, `init_round()`, `process_round()` are todo |
| `bsv-mpc-core/presigning.rs` | Partial | `PresigningManager` pool logic works, `generate()` is todo |
| `bsv-mpc-core/hd.rs` | Stub | `derive_child_key()`, `parse_derivation_path()` are todo |
| `bsv-mpc-core/proof.rs` | Stub | `create_participation_proof()`, `proof_to_op_return()`, `verify_participation_proof()` are todo |
| `bsv-mpc-proxy/config.rs` | **Complete** | `ProxyConfig::from_env()` + test |
| `bsv-mpc-proxy/error.rs` | **Complete** | `ProxyError` enum + HTTP response mapping |
| `bsv-mpc-proxy/server.rs` | **Complete** | Axum router, AppState, all 28 routes wired + background presig task |
| `bsv-mpc-proxy/wallet_api.rs` | Stubs | All 28 handlers declared with doc comments, bodies are todo (except `get_network`, `get_version`, `is_authenticated`, `health`) |
| `bsv-mpc-proxy/main.rs` | **Complete** | Binary entry point |
| `bsv-mpc-worker/lib.rs` | **Complete** | CF Worker router with all 8 endpoints |
| `bsv-mpc-worker/api.rs` | Stubs | All request/response types defined, handler bodies are todo |
| `bsv-mpc-worker/storage.rs` | Stubs | `ShareStorage` struct + `ShareMetadata`, all methods are todo, SQL schemas documented |
| `bsv-mpc-service` | Placeholder | Empty lib.rs |
| `bsv-mpc-overlay` | Placeholder | Empty lib.rs |
| `contracts/mpc-fee-pool` | Placeholder | Empty src/ directory |
| `brc-drafts/` | Placeholder | Empty directory |

## Key Dependencies

| Crate | Version | Purpose | License | Notes |
|-------|---------|---------|---------|-------|
| cggmp24 | 0.7.0-alpha.3 (git) | CGGMP'24 threshold ECDSA | MIT/Apache-2.0 | MUST use `num-bigint` feature, NOT `rug` |
| cggmp24-keygen | git (same repo) | DKG protocol | MIT/Apache-2.0 | Same `num-bigint` constraint |
| bsv | local path `../rust-sdk` | BSV primitives (PublicKey, Transaction, Script) | -- | `features = ["transaction"]` |
| worker | 0.4 | CF Worker Rust SDK (WASM) | MIT | Only for bsv-mpc-worker |
| axum | 0.8 | HTTP server (proxy + service) | MIT | With `ws` feature |
| reqwest | 0.12 | HTTP client (proxy to KSS) | MIT | `rustls-tls`, no default features |
| aes-gcm | 0.10 | Share encryption | MIT/Apache-2.0 | |
| sha2 | 0.10 | Hashing (session IDs, BRC-42 derivation) | MIT/Apache-2.0 | |
| getrandom | 0.2 | Entropy in WASM | MIT/Apache-2.0 | Must use `js` feature for CF Worker |
| thiserror | 2 | Error derive macros | MIT/Apache-2.0 | |
| tokio | 1 | Async runtime | MIT | Full features |

**CRITICAL**: cggmp24 MUST use `num-bigint` feature (not `rug`) for two reasons:
1. `rug` depends on GMP which is LGPL -- copyleft contamination (deny.toml blocks this)
2. `rug` is a C library that does not compile to `wasm32-unknown-unknown`

## Why cggmp24

cggmp24 (LFDT-Lockness) is the only MPC crate satisfying all requirements simultaneously:

| Property | Value |
|----------|-------|
| Protocol | CGGMP'24 (state of the art threshold ECDSA) |
| License | MIT/Apache-2.0 (with `num-bigint` backend) |
| WASM | Confirmed `wasm32-unknown-unknown` compilation |
| Audit | Kudelski Security |
| Production | Powers Dfns signing infrastructure |
| TSSHOCK | Fixed (CVE-2025-66017, v0.7.0-alpha.2+) |
| Threshold | Arbitrary 2 <= t <= n |
| HD wallets | SLIP-10/BIP-32 from MPC shares |
| Signing speed | 3-15ms crypto per round |
| secp256k1 | Native support (Bitcoin's curve) |
| Identifiable abort | If a party cheats, protocol identifies them |

### Rejected Alternatives

| Library | Reason |
|---------|--------|
| cb-mpc (Coinbase) | C++, no WASM, needs FFI. GG18/GG20 (older protocol) |
| multi-party-ecdsa (ZenGo) | GPL-3.0, abandoned, TSSHOCK vulnerable ("won't fix"), no WASM |
| synedrion (entropyxyz) | AGPL-3.0, unaudited, company shut down Jan 2026 |
| Fireblocks mpc-lib | GPL-3.0 |
| tss-lib (Binance) | Go, no Rust |
| tss-ecdsa (Bolt Labs) | Unaudited, low activity |
| tofn (Axelar) | GG20 deprecated/removed after TSSHOCK |

### Current Limitations

| Gap | Impact | Mitigation |
|-----|--------|------------|
| No key refresh (in cggmp24 v0.7; exists in older cggmp21 v0.6.3) | Cannot replace a dead node's share without re-DKG | Periodic proactive re-DKG; contribute key refresh upstream |
| No identifiable abort (in cggmp24; exists in cggmp21) | Cannot identify which node cheated on failure | In 2-of-2, there's only one other party |
| Alpha status (v0.7.0-alpha.3) | API may change | Pin version; crypto core is Kudelski-audited |
| WASM entropy | `getrandom` needs `js` feature in WASM | Solvable with `getrandom/js` feature flag |

## Signature Latency

| Scenario | Latency |
|----------|---------|
| Presigned, same CF colo | ~7ms |
| Presigned, CF Worker to CF Container | ~15ms |
| Presigned, cross-region | ~45ms |
| No presign, same colo | ~28ms |
| No presign, cross-region | ~180ms |
| No presign, cross-cloud | ~220ms |
| Distributed internet nodes | ~640ms |

### Presigning Strategy

The agent knows it will need signatures in the future. Between tasks (idle time, ~30 seconds between LLM calls), the MPC proxy runs presigning rounds in the background -- stockpiling presignatures. At 10 signings per task and ~30 seconds idle between tasks, presignatures are stockpiled faster than consumed. The agent never waits for a multi-round protocol.

Effective signing latency with presigning: **7-15ms** against a 10-second LLM call (0.1% overhead).

### Protocol Round Counts

| Operation | Offline rounds | Online rounds | Total at signing time |
|-----------|---------------|---------------|----------------------|
| DKG (one-time per agent) | -- | 4 | 4 (~250ms co-located) |
| Signing with presignature | 3 (done in idle time) | **1** | 1 |
| Signing without presignature | 0 | 4 | 4 |
| Presigning | 3 | -- | 3 (done in background) |

## Overlay Network

| Component | BRC | Use |
|-----------|-----|-----|
| CHIP tokens | BRC-23 | Node advertisement (identity, domain, capabilities, pricing) |
| SLAP lookup | BRC-24/25 | Agent discovers available MPC nodes |
| BRC-22 /submit | BRC-22 | Publish proofs, register nodes on `tm_mpc_signing` topic |
| BRC-33 MessageBox | BRC-33 | Real-time MPC protocol rounds (DKG, signing, presigning) |
| BRC-31 Authrite | BRC-31 | Mutual auth between all parties |
| BRC-18 proofs | BRC-18 | Participation proofs for fee distribution |
| BRC-56 Peer Discovery | BRC-56 | Agent-to-node identity verification |

Topic name: `tm_mpc_signing`

### Discovery Flow

```
Agent needs MPC signing:
  1. Query BRC-24 /lookup provider="CHIP" query: { topic: "tm_mpc_signing" }
  2. Gets list: [{ domain, identity_key, capabilities, pricing }, ...]
  3. Selects t+1 nodes by reputation, proximity, price
  4. Initiates DKG via BRC-33 MessageBox (real-time rounds)
```

### Protocol Rounds via BRC-33

```
Proxy (share_B)                  KSS (share_A)
    |                                |
    |-- POST /sign/init { hash } --->|  Load share + presig
    |<-- { round_1_msg } -----------|  Return online round
    |                                |
    |-- POST /sign/round { r1 } --->|  Combine partial sigs
    |<-- { signature } -------------|  Return complete ECDSA sig
```

## Fee Economics

### Fee Structure

Each MPC-signed agent transaction includes a fee output (default 1,000 sats, ~2% of average 50K sat LLM call). Fee is injected by the MPC Signing Proxy when it intercepts `createAction`. bsv-worm does not know or care.

### Three Settlement Levels

**Level 1: Trusted accumulator (simplest)**
Agent tracks participation, periodically creates settlement tx. Trust: agent reports honestly.

**Level 2: Multisig self-settlement (recommended)**
Fee UTXOs locked in t-of-n multisig of participating MPC nodes. Nodes settle themselves -- they agree on the split before co-signing. The MPC nodes use the same threshold signing for fee settlement that they provide as a service.

**Level 3: sCrypt covenant enforcement (trustless)**
On-chain covenant enforces proportional distribution via `hashOutputs` introspection. `DesignatedReceivers` pattern (proven on BSV mainnet). Script-enforced: nobody can spend the fee pool without creating outputs in correct proportions.

### Node Revenue by Scale

| Scale | Agents | Signings/day | Per Node Revenue/mo (3-way split) | Node Cost/mo | Margin |
|-------|--------|-------------|-----------------------------------|--------------|---------|
| Seed | 100 | 1,000 | $5 | $5 | Breakeven |
| Alpha | 1,000 | 10,000 | $50 | $5 | 90% |
| Beta | 10,000 | 100,000 | $500 | $5.30 | 99% |
| v1.0 | 100,000 | 1,000,000 | $5,000 | $19 | 99.6% |

Extreme margins because: compute is 15ms of WASM (essentially free), CF Workers have zero idle cost, storage is 1KB per agent (1M agents = 1GB, free tier).

### Agent Cost Impact

An agent doing 10 LLM calls per task:

| Cost component | Sats | USD (at $50/BSV) |
|---|---|---|
| LLM inference (10 calls) | 500,000 | $0.250 |
| On-chain proofs (10 iterations) | 2,000 | $0.001 |
| MPC signing fees (10 signings) | 10,000 | $0.005 |
| **Total MPC overhead** | **2%** | |

## BRC Standards (Drafts)

| BRC | Title | Status |
|-----|-------|--------|
| BRC-1XX | Threshold ECDSA Signing Protocol for BSV | Planned (brc-drafts/) |
| BRC-1XX | MPC Overlay Service Discovery | Planned |
| BRC-1XX | MPC Participation Proofs | Planned |
| BRC-1XX | MPC Fee Distribution | Planned |

## Deployment Modes

| Mode | Proxy | KSS | Defense-in-depth |
|------|-------|-----|-----------------|
| Same CF (Alpha) | CF Container | CF Worker (different account) | Medium |
| Cross-cloud | CF Container | GCP Cloud Run / self-hosted | High |
| Self-hosted | Local binary | Local binary (`bsv-mpc-service`) | User-controlled |
| Managed | CF Container | Dfns ($60/mo) | High |

Default (Alpha): both on CF in different accounts. Offer Dfns or self-hosted as cross-cloud options. BRC standard is provider-agnostic.

## Conventions

- **Error handling**: `MpcError` in bsv-mpc-core, `ProxyError` in bsv-mpc-proxy. All use thiserror.
- **Share encryption**: BRC-42 HMAC-SHA256 key derivation to AES-256-GCM. `HMAC-SHA256(root_key, "bsv-mpc-share" || session_id)`. Nonce: 12 bytes random. Protocol ID: `[2, "mpc share"]`, key_id: session_id, counterparty: `"self"`.
- **Protocol messages**: JSON over HTTP (proxy to KSS). Format: `{ session_id, round, from, to, payload }`. For overlay mode, BRC-33 MessageBox as transport.
- **WASM target**: bsv-mpc-worker targets `wasm32-unknown-unknown`. Must use `getrandom/js` for entropy. Must use `num-bigint` backend for cggmp24 (not `rug`).
- **BSV SDK**: Local path dependency at `../rust-sdk` with `features = ["transaction"]`. Same as bsv-worm.
- **Config**: All via `MPC_*` environment variables (see `config.rs` for full list). Container-deployment friendly.
- **Tests**: Planned -- one test file per crate module. Use `tempfile` for filesystem tests.
- **License**: MIT OR Apache-2.0 (workspace-level). deny.toml enforces copyleft=deny.
- **Rust edition**: 2021, minimum 1.85 (for time crate compatibility, matching bsv-worm).

## BRC-100 Proxy Endpoint Map

All 28 BRC-100 endpoints are routed in `server.rs`. They fall into two categories:

### MPC-routed (require KSS communication)

| Endpoint | Handler | Notes |
|----------|---------|-------|
| `getPublicKey` | Returns joint MPC key or BRC-42 derived child key | No KSS call for public key derivation |
| `createSignature` | 2PC ECDSA with KSS | Uses presignature when available |
| `createAction` | UTXO select + tx build + fee inject + MPC sign (per input) + broadcast | Most complex handler |
| `internalizeAction` | Accept incoming payment, add outputs to UTXO tracker | No signing needed |

### Local-only (no MPC rounds)

| Endpoint | Handler | Notes |
|----------|---------|-------|
| `encrypt` / `decrypt` | BRC-42 derived symmetric key | Local key derivation from share |
| `createHmac` / `verifyHmac` | BRC-42 derived HMAC key | Local |
| `verifySignature` | Pure ECDSA verification | No secret key needed |
| `listOutputs` / `listActions` | Local UTXO tracker | BRC-46 baskets, tags, pagination |
| `relinquishOutput` | Remove UTXO from tracker | |
| `getNetwork` / `getVersion` / `isAuthenticated` | Static responses | |
| `listCertificates` / `proveCertificate` / `acquireCertificate` / `relinquishCertificate` | Local cert store | Signing uses MPC bridge |
| `discoverByIdentityKey` / `discoverByAttributes` | Forward to overlay | |
| `revealCounterpartyKeyLinkage` / `revealSpecificKeyLinkage` | BRC-42 key derivation | |

## KSS API (Worker/Service)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/dkg/init` | BRC-31 | Start DKG ceremony, return round 1 message |
| POST | `/dkg/round` | BRC-31 | Process DKG round, return next or complete |
| POST | `/sign/init` | BRC-31 | Start signing, return round 1 message |
| POST | `/sign/round` | BRC-31 | Process signing round, return sig or next |
| POST | `/presign/init` | BRC-31 | Start presigning protocol |
| POST | `/presign/round` | BRC-31 | Process presigning round |
| GET | `/health` | none | Liveness check + share count |
| GET | `/shares/:agent_id` | BRC-31 | Share metadata (no secrets exposed) |

## KSS Storage Schema (Durable Object SQLite)

```sql
CREATE TABLE IF NOT EXISTS shares (
    agent_id       TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL,
    share_index    INTEGER NOT NULL,
    encrypted_share BLOB NOT NULL,
    config_json    TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS presigning_state (
    id         TEXT PRIMARY KEY,
    agent_id   TEXT NOT NULL,
    session_id TEXT NOT NULL,
    round      INTEGER NOT NULL,
    state      BLOB NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (agent_id) REFERENCES shares(agent_id)
);

CREATE TABLE IF NOT EXISTS presignatures (
    id         TEXT PRIMARY KEY,
    agent_id   TEXT NOT NULL,
    session_id TEXT NOT NULL,
    data       BLOB NOT NULL,
    created_at TEXT NOT NULL,
    consumed   INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (agent_id) REFERENCES shares(agent_id)
);
```

## Relationship to bsv-worm

bsv-mpc is a separate project that bsv-worm uses transparently. The MPC Signing Proxy sits at `localhost:3322` and presents the exact same BRC-100 HTTP API that bsv-wallet-cli exposes. bsv-worm's `wallet.rs` calls it unchanged -- same paths, same request/response shapes.

Key integration points:
- `wallet.rs` in bsv-worm is the only module that talks to the wallet HTTP API. It doesn't know or care whether the backend is bsv-wallet-cli or bsv-mpc-proxy.
- `createAction` is the critical path -- bsv-worm calls it for every on-chain operation (proofs, state tokens, payments, x402). The proxy must handle UTXO selection, transaction construction, fee injection, MPC signing per input, and broadcasting.
- Encryption/decryption (`encrypt`, `decrypt`) use locally-derived symmetric keys from the MPC share -- no network round-trips needed.
- The proxy injects MPC signing fee outputs transparently. bsv-worm's budget tracking sees slightly higher transaction costs but doesn't need to account for them specially.

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

### Build Order (Implementation Roadmap)

| Week | Deliverable | Details |
|------|------------|---------|
| 1-2 | `bsv-mpc-core` | Wire cggmp24 for DKG + signing on secp256k1. Share encryption. WASM validation. |
| 3-4 | `bsv-mpc-proxy` | BRC-100 proxy at localhost:3322. `createAction` with fee injection + MPC signing. bsv-worm works unchanged. |
| 5-6 | `bsv-mpc-worker` | CF Worker KSS. Rust to WASM. DO SQLite. BRC-31 auth. All protocol endpoints. |
| 7 | Fee system + overlay | Fee output injection. Multisig settlement (Level 2). CHIP tokens. SLAP discovery. |
| 8 | sCrypt covenant | `MpcFeePool` contract. Proportional distribution. Testnet. |
| 9-10 | Integration + BRC drafts | End-to-end: agent onboards, DKG, signs, fee accrues, settles. 4 BRC drafts. |

## Decisions Made

- **cggmp24 over cb-mpc**: Pure Rust, WASM-compatible, MIT, Kudelski-audited, powers Dfns. cb-mpc is C++ (no WASM, needs FFI, GG18/GG20 older protocol).
- **CF Workers for KSS**: $5/mo, 0ms cold start, global edge, WASM native, DO SQLite for storage. Containers are for the agent, not the KSS.
- **Presigning over on-demand**: Stockpile presigs in idle time (7ms effective signing) vs 4-round on-demand (180ms). Worth the complexity for latency-sensitive BSV transaction signing.
- **Fee covenant via multisig (Level 2)**: MPC nodes self-settle using their own threshold signing. No trusted third party. Upgrade to sCrypt covenant (Level 3) when network has independent operators who need trustless enforcement.
- **Overlay topic `tm_mpc_signing`**: Uses existing SHIP/SLAP infrastructure. No new overlay protocol needed.
- **BRC-33 for protocol rounds**: Already built in bsv-worm. Supports NAT traversal. Direct WebSocket as optimization later.
- **1,000 sats per signing default**: 2% overhead on average LLM call. Configurable. Market-driven via CHIP token advertisements.
- **Drop-in proxy pattern**: bsv-worm requires zero code changes. The proxy presents BRC-100 API surface identically. This means any BRC-100 client (not just bsv-worm) gets MPC signing for free.
- **`num-bigint` over `rug`**: Avoids LGPL contamination (GMP) and enables WASM compilation. May be slower than GMP-backed but 15ms is acceptable.
- **Separate CF accounts for defense-in-depth**: Agent container and KSS on different CF accounts with separate credentials and audit logs. Not true cross-cloud but significantly better than same account.
- **Local symmetric encryption from share**: `encrypt`/`decrypt`/`createHmac`/`verifyHmac` derive symmetric keys locally via BRC-42 from the MPC share -- no KSS communication needed. Only signing requires 2PC.
- **Atomic presignature consumption**: `consume_presignature()` in DO SQLite uses BEGIN/SELECT/UPDATE/COMMIT for FIFO atomic consumption. Each presignature used exactly once (nonce reuse would leak the private key).

## Open Questions

- Does cggmp24 actually compile and run correctly in CF Worker V8 isolate? Need to validate `getrandom/js` and `num-bigint` in WASM environment. Budget 2-3 days for WASM debugging.
- When will cggmp24 add key refresh? Currently missing in v0.7.0-alpha.3 (exists in older cggmp21). Could backport or contribute upstream.
- Should the proxy implement all 28 BRC-100 endpoints from day one, or start with the ~10 that bsv-worm actively uses? (`createAction`, `getPublicKey`, `createSignature`, `encrypt`, `decrypt`, `listOutputs`, `internalizeAction`, `isAuthenticated`, `getNetwork`, `getVersion`)
- Should `fee_injector` use bare multisig P2MS or P2SH multisig for the fee output?
- How to handle overlay node bootstrapping (initially just us running the overlay)?
- Should bsv-mpc-proxy maintain its own UTXO set or delegate to bsv-wallet-cli for non-signing operations? A hybrid approach (proxy for signing, passthrough to wallet for UTXO management) could reduce implementation surface.
- How to handle `createAction` with multiple inputs that need different derived keys? Each input may have a different BRC-42 derivation path, requiring separate 2PC signing sessions (or batching).
- Performance of `num-bigint` vs `rug` in WASM -- if 15ms becomes 50ms, still acceptable for BSV transaction signing, but should benchmark.

## Challenges & Risks

### Technical

| Risk | Severity | Mitigation |
|------|----------|------------|
| cggmp24 WASM compilation in V8 isolate | Medium | Budget 2-3 days debugging. `getrandom/js` feature flag. |
| BRC-100 proxy surface area | Medium | Start with minimum viable endpoints (~10). Add as needed. |
| Key refresh gap | Low-Medium | Proactive re-DKG. Monitor node health. Backport from cggmp21. |
| CF Worker 128MB memory limit | Low | ~5-20MB WASM module + ~50KB protocol state. Well under limit. |
| BRC-33 MessageBox latency for rounds | Low | Use presigning (1 online round). Direct WebSocket as optimization. |
| Overlay bootstrap (chicken-and-egg) | Low | Run all initial nodes. Architecture ready for permissionless joining. |

### Economic

| Risk | Severity | Mitigation |
|------|----------|------------|
| Fee too low for independent operators at small scale | Expected | Run all nodes initially. Economic incentives at ~1K agents. |
| BSV price volatility | Low | Fee in sats is adjustable. Dynamic pricing via CHIP tokens. |

### Security

| Risk | Severity | Mitigation |
|------|----------|------------|
| Both shares on same cloud provider | Medium | Different CF accounts. Offer Dfns/self-hosted for cross-cloud. |
| Future protocol vulnerabilities | Low | Pin audited version. Monitor advisories. Modular crate = swappable core. |
