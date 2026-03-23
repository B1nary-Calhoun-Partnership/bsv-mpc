# Ecosystem Map

> How bsv-mpc relates to the broader BSV agent infrastructure.

## System Diagram

```
                          BSV Blockchain
                    ┌─────────┴──────────┐
                    │  Overlay Network    │
                    │  (BRC-22/23/24/25)  │
                    │  tm_mpc_signing     │
                    └────────┬───────────┘
                             │ SHIP/SLAP discovery
                             │
┌──────────────┐    ┌────────┴───────────┐    ┌──────────────────┐
│              │    │                    │    │                  │
│  bsv-worm   │───▶│   bsv-mpc-proxy   │───▶│  Key Share       │
│  (AI Agent)  │    │   localhost:3322   │    │  Service (KSS)   │
│              │    │                    │    │                  │
│  BRC-100     │    │  BRC-100 API       │    │  bsv-mpc-service │
│  wallet calls│    │  + MPC orchestration│   │  (standalone)    │
│              │    │  + fee injection   │    │                  │
└──────────────┘    └────────┬───────────┘    └──────────────────┘
                             │
                    ┌────────┴───────────┐
                    │                    │
                    │  bsv-mpc-core      │
                    │  (protocol layer)  │
                    │                    │
                    │  CGGMP'24 DKG      │
                    │  Threshold signing │
                    │  Presigning        │
                    │  Partial ECDH      │
                    │  Key refresh       │
                    └────────────────────┘
```

## Components

### bsv-mpc (this project)

Five Rust crates implementing decentralized MPC threshold signing:

| Crate | Role |
|-------|------|
| **bsv-mpc-core** | Protocol layer: DKG, signing, presigning, ECDH, key refresh, share encryption, BRC-42 derivation, BRC-18 proofs |
| **bsv-mpc-proxy** | BRC-100 signing proxy at localhost:3322. Drop-in replacement for bsv-wallet-cli. Orchestrates MPC ceremonies, injects fees, tracks UTXOs |
| **bsv-mpc-service** | Standalone Key Share Service binary. Holds one MPC share, participates in ceremonies over HTTP |
| **bsv-mpc-worker** | (Private) Alternative KSS deployment target |
| **bsv-mpc-overlay** | BSV overlay integration: CHIP token creation, SLAP/CLAP node discovery, fee settlement |

### bsv-worm

Autonomous AI agent framework. Calls the BRC-100 wallet API at localhost:3322. With bsv-mpc-proxy running at that address, bsv-worm gets threshold signing with **zero code changes**. The agent's private key never exists — two or more parties must cooperate to sign.

- Repo: `~/bsv/rust-bsv-worm`
- Integration point: `wallet.rs` calls BRC-100 HTTP API
- Key flow: `createAction` → proxy builds tx → fee injection → MPC signing per input → broadcast

### bsv-wallet-cli

Reference BRC-100 wallet daemon. Used to fund MPC-derived addresses during development. The MPC proxy API is designed to be interface-compatible with bsv-wallet-cli.

- Repo: `~/bsv/bsv-wallet-cli`
- Role: Development tool, funding source, API reference

### rust-sdk (BSV SDK)

Core BSV primitives: Transaction, Script, PublicKey, PrivateKey, BRC-42 key derivation, sighash computation, BEEF construction, broadcasting.

- Repo: `~/bsv/rust-sdk`
- Used by: All bsv-mpc crates (features: `transaction`, `wallet`)
- Key types: `Transaction`, `PublicKey`, `PrivateKey`, `Script`, `Beef`

### cggmp21-fork

Local fork of the cggmp24 crate (Kudelski Security). Adds `set_additive_shift()` for BRC-42 derived key signing — the ability to apply an additive offset to the secret share during threshold signing.

- Repo: `~/bsv/cggmp21-fork`
- Used by: bsv-mpc-core (DKG, signing, presigning, key refresh)
- MUST use `num-bigint` feature (not `rug`) for WASM compatibility and license compliance

### rust-wallet-toolbox

Wallet engine with ProtoWallet, StorageSqlx, WalletSigner. In hosted mode, the MPC proxy delegates UTXO storage to rust-wallet-infra (which uses this toolbox) rather than reimplementing storage.

- Repo: `~/bsv/rust-wallet-toolbox`
- Role: Storage and wallet primitives for hosted deployments

### rust-middleware

BSV authentication middleware. The `bsv-auth-cloudflare` crate provides BRC-31 (Authrite) auth for service endpoints. Used by KSS for verifying agent authorization.

- Repo: `~/bsv/rust-middleware`
- Role: BRC-31 auth implementation for KSS endpoints

### BRC Specifications

114 BSV Request for Comments specifications. The ones most relevant to bsv-mpc:

| BRC | Name | Relevance |
|-----|------|-----------|
| BRC-31 | Authrite | Mutual authentication between proxy and KSS |
| BRC-42 | Key Derivation | ECDH + HMAC-SHA256 with invoice strings (protocolID, keyID, counterparty) |
| BRC-100 | Wallet API | 28-endpoint HTTP API that the proxy implements |
| BRC-18 | OP_RETURN | Participation proof format |
| BRC-22 | Overlay | Transaction overlay network |
| BRC-23 | SHIP | Synchronization Host Interconnect Protocol |
| BRC-24 | SLAP | Service Lookup Availability Protocol |
| BRC-25 | CHIP | Capability Host Interconnect Protocol |

- Repo: `~/bsv/BRCs`

### BSV Overlay Network

Decentralized node discovery using BRC-22/23/24/25. MPC nodes register on topic `tm_mpc_signing` via SLAP trackers. Clients discover available KSS nodes through SLAP/CLAP queries, filter by health and reputation.

- 4 mainnet SLAP trackers confirmed alive (POC 14)
- CHIP tokens encode node capability and fee information
- Discovery flow: SLAP query → health check → reputation scoring → node selection

## Data Flow

```
User message
    │
    ▼
bsv-worm (agent loop)
    │
    │ BRC-100: createAction(outputs, description)
    ▼
bsv-mpc-proxy
    │
    ├─ UTXO selection (local)
    ├─ Transaction construction (rust-sdk)
    ├─ Fee output injection (fee_injector)
    ├─ For each input:
    │   ├─ BRC-42 key derivation (local HMAC or partial ECDH with KSS)
    │   ├─ Presig retrieval or interactive signing
    │   └─ MPC signing ceremony with KSS (1 or 4 rounds)
    ├─ BEEF construction
    └─ Broadcast (ARC/WhatsOnChain)
    │
    ▼
BSV Blockchain (mainnet)
```

## Key Boundaries

- **bsv-worm ↔ proxy**: BRC-100 HTTP API. No MPC awareness in bsv-worm.
- **proxy ↔ KSS**: Custom HTTP API (8 endpoints). BRC-31 authenticated.
- **proxy ↔ blockchain**: Broadcast via rust-sdk (ARC, WhatsOnChain).
- **overlay ↔ blockchain**: SHIP/SLAP/CHIP via BRC-22/23/24/25.
- **core ↔ everything**: Pure library. No I/O. Called by proxy, service, and worker.
