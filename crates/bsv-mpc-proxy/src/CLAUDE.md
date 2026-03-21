# bsv-mpc-proxy/src
> BRC-100 signing proxy that translates wallet API calls into 2-party CGGMP'24 threshold ECDSA.

## Overview

This is the HTTP server that bsv-worm (or any BRC-100 client) talks to at `localhost:3322`. It presents the exact same API surface as bsv-wallet-cli — same paths, same request/response shapes — so clients need zero code changes. Internally, every signing request becomes a 2-party threshold ECDSA ceremony with a remote Key Share Service (KSS). A presignature pool enables single-round online signing (~50-100ms) instead of the full 4-round protocol (~300-500ms).

```
BRC-100 client ──HTTP──► bsv-mpc-proxy ──HTTPS──► KSS (remote party)
(bsv-worm)           localhost:3322           holds share_A
                     holds share_B
                     presig pool + fee injector
```

## Files

| File | Lines | Status | Purpose |
|------|-------|--------|---------|
| `lib.rs` | 44 | Complete | Module declarations and crate-level docs |
| `main.rs` | 41 | Complete | Binary entry point — loads `ProxyConfig`, inits tracing, calls `server::run()` |
| `config.rs` | 146 | Complete | `ProxyConfig` from `MPC_*` env vars, with defaults and test |
| `error.rs` | 125 | Complete | `ProxyError` enum (11 variants), HTTP status mapping, `From` impls |
| `server.rs` | 183 | Complete | Axum router, `AppState` struct, all 28 BRC-100 routes, background presig task |
| `wallet_api.rs` | 796 | Mostly stubs | 28 handler functions — 4 implemented (`get_network`, `get_version`, `is_authenticated`, `health`), 24 are `todo!()` |
| `bridge.rs` | 228 | Stub | `MpcBridge` struct with field definitions; `new()`, `sign()`, `presign()` are `todo!()` |
| `fee_injector.rs` | 249 | Partial | `FeeInjector` struct, `is_enabled()`, `parse_threshold()` work; `inject_fee()` is `todo!()` |
| `presign_manager.rs` | 268 | Complete | `PresignManager` FIFO pool, `background_replenish()` loop with exponential backoff |

## Key Exports

### `config::ProxyConfig`
Configuration loaded from environment variables. All fields have defaults except none are strictly required (share_path defaults to `"share.enc"`).

| Field | Env Var | Default | Type |
|-------|---------|---------|------|
| `port` | `MPC_PROXY_PORT` | `3322` | `u16` |
| `kss_url` | `MPC_KSS_URL` | `https://kss.lobsterfarm.com` | `String` |
| `share_path` | `MPC_SHARE_PATH` | `share.enc` | `String` |
| `fee_per_signing` | `MPC_FEE_SATS` | `1000` | `u64` |
| `fee_addresses` | `MPC_FEE_ADDRESSES` | `[]` (empty) | `Vec<String>` |
| `fee_threshold` | `MPC_FEE_THRESHOLD` | `None` | `Option<String>` |
| `max_presignatures` | `MPC_MAX_PRESIGS` | `20` | `usize` |
| `encryption_key` | `MPC_ENCRYPTION_KEY` | `None` | `Option<String>` |

### `server::AppState`
Shared state passed to all Axum handlers via `State<Arc<AppState>>`:
- `config: ProxyConfig` — immutable after startup
- `bridge: MpcBridge` — holds decrypted share, joint key, reqwest client, session ID
- `presign_manager: Arc<RwLock<PresignManager>>` — presignature pool (RwLock for concurrent reads)
- `fee_injector: FeeInjector` — constructs fee outputs for `createAction` transactions

### `bridge::MpcBridge`
Core translation layer between BRC-100 API and MPC protocol:
- `new(config) -> Result<Self>` — loads/decrypts share, establishes KSS session (stub)
- `sign(hash, presignature) -> Result<SigningResult>` — 2PC ECDSA: 1 round with presig, 4 without (stub)
- `presign() -> Result<Presignature>` — 3-round offline protocol to generate reusable presignature (stub)
- `joint_public_key()` — returns the secp256k1 compressed public key for on-chain use
- `session_id()` — KSS session identifier
- `kss_url()` — KSS endpoint

### `error::ProxyError`
11-variant error enum with HTTP status mapping:

| Variant | HTTP Status | Trigger |
|---------|-------------|---------|
| `InvalidRequest` | 400 | Malformed BRC-100 request |
| `Utxo` | 422 | Insufficient funds, output not found |
| `KssError` | 502 | KSS unreachable or returned error |
| `PresignatureExhausted` | 503 | Pool empty (falls back to 4-round) |
| `Protocol` | 500 | MPC protocol failure (wraps `MpcError`) |
| `ShareLoad` | 500 | Share file read/decrypt failure |
| `FeeInjection` | 500 | Invalid fee config |
| `Transaction` | 500 | Tx construction/serialization |
| `Encryption` | 500 | Local encrypt/decrypt failure |
| `Certificate` | 500 | Certificate operation failure |
| `Internal` | 500 | Catch-all |

`From` impls: `reqwest::Error` → `KssError`, `serde_json::Error` → `InvalidRequest`, `io::Error` → `ShareLoad`, `MpcError` → `Protocol`.

### `fee_injector::FeeInjector`
Adds MPC signing fee outputs to `createAction` transactions:
- `new(fee_sats, fee_addresses, fee_threshold)` — constructor
- `is_enabled()` — true when both fee > 0 and addresses are non-empty
- `inject_fee(tx_bytes) -> Result<Vec<u8>>` — appends fee output(s) to serialized tx (stub)
- `parse_threshold()` — parses `"2-of-3"` format into `(t, n)` with validation
- Two fee models: bare P2MS multisig (when threshold set) or split P2PKH (default)

### `presign_manager::PresignManager`
FIFO pool of pre-computed presignatures:
- `new(max_size)` — creates empty pool
- `take() -> Option<Presignature>` — FIFO consumption from front
- `add(presig)` — push to back, silently drops if at capacity
- `should_replenish()` — true when pool < 50% capacity
- `len()`, `is_empty()`, `max_size()`, `utilization()` — pool status
- `total_generated()`, `total_consumed()` — lifetime metrics

### `presign_manager::background_replenish(state)`
Async loop that runs forever as a spawned Tokio task:
- Checks `should_replenish()` every 5 seconds
- Calls `bridge.presign()` to generate one presignature per cycle
- Exponential backoff on failure (5s → 10s → 20s → ... → 60s max)
- Resets backoff on success or when pool is healthy

## Handler Categories

### MPC-routed (require KSS round-trips)
| Handler | Route | Status |
|---------|-------|--------|
| `get_public_key` | `POST /getPublicKey` | Stub — returns joint key or BRC-42 derived child |
| `create_signature` | `POST /createSignature` | Stub — 2PC ECDSA with presig fast path |
| `create_action` | `POST /createAction` | Stub — UTXO select + build + fee inject + MPC sign + broadcast |
| `internalize_action` | `POST /internalizeAction` | Stub — accept incoming payment |

### Local-only (no MPC rounds)
| Handler | Route | Status |
|---------|-------|--------|
| `encrypt` / `decrypt` | `POST /encrypt`, `/decrypt` | Stub — BRC-42 derived AES-256-GCM |
| `create_hmac` / `verify_hmac` | `POST /createHmac`, `/verifyHmac` | Stub — BRC-42 derived HMAC key |
| `verify_signature` | `POST /verifySignature` | Stub — pure ECDSA verify |
| `list_outputs` / `list_actions` | `POST /listOutputs`, `/listActions` | Stub — local UTXO/action tracker |
| `relinquish_output` | `POST /relinquishOutput` | Stub |
| `get_network` | `POST /getNetwork` | **Implemented** — returns `"mainnet"` |
| `get_version` | `POST /getVersion` | **Implemented** — returns `"bsv-mpc-proxy {version}"` |
| `is_authenticated` | `POST /isAuthenticated` | **Implemented** — returns `true` (share loaded at startup) |
| `health` | `GET /health` | **Implemented** — status, version, presig count, KSS URL, fee |
| Certificate handlers | 4 POST routes | Stub |
| Discovery handlers | 2 POST routes | Stub |
| Key linkage handlers | 2 POST routes | Stub |

## Startup Flow

1. `main.rs`: init tracing, load `ProxyConfig::from_env()`
2. `server::run()`:
   - `MpcBridge::new(&config)` — load share, decrypt, validate, connect to KSS
   - Construct `FeeInjector` from config
   - Construct `PresignManager` with `max_presignatures` capacity
   - Bundle into `Arc<AppState>`
   - Spawn `background_replenish()` as a Tokio task
   - Build Axum router with all 28 routes + `/health`
   - Bind `0.0.0.0:{port}` and serve

## `createAction` Pipeline (when implemented)

This is the most complex handler — called by bsv-worm for every on-chain operation:

1. Parse `description`, `inputs`, `outputs`, `labels`, `options`
2. Select UTXOs from local tracker for inputs
3. Build unsigned transaction with requested outputs
4. `fee_injector.inject_fee()` — append MPC signing fee output(s)
5. Calculate miner fee, add change output
6. For each input:
   - Derive child share via BRC-42 from input's `protocolID`/`keyID`
   - Compute sighash
   - `presign_manager.take()` for fast path
   - `bridge.sign(sighash, presignature)` — 2PC with KSS
   - Apply signature to input
7. Broadcast signed transaction
8. Update local UTXO set
9. Return `{ txid, tx, outputMap, mapiResponses }`

## Dependencies

| Crate | Use in this module |
|-------|-------------------|
| `bsv-mpc-core` | `MpcError`, `Presignature`, `EncryptedShare`, `JointPublicKey`, `SessionId`, `SigningResult` |
| `axum` (0.8) | HTTP router, `State`, `Json`, `IntoResponse` |
| `reqwest` (0.12) | HTTP client for KSS communication (in `MpcBridge`) |
| `tokio` (1) | Async runtime, `RwLock`, `spawn`, `time::sleep` |
| `serde` / `serde_json` | Request/response serialization |
| `thiserror` (2) | `ProxyError` derive macro |
| `tracing` | Structured logging throughout |
| `anyhow` | Error handling in `ProxyConfig`, `FeeInjector`, `MpcBridge` |

## Tests

Tests exist in `config.rs`, `fee_injector.rs`, and `presign_manager.rs`:

```bash
cargo test -p bsv-mpc-proxy
```

- `config::tests::defaults_are_sane` — verifies default env var parsing
- `fee_injector::tests` — 7 tests: enabled/disabled states, threshold parsing (valid, none, invalid format, t > n, n mismatch), inject noop when disabled
- `presign_manager::tests` — 6 tests: empty pool, take from empty, should_replenish, utilization, zero max, metrics

## Related

- [`../../CLAUDE.md`](../../CLAUDE.md) — project root: architecture, deployment modes, fee economics, protocol latency
- [`../bsv-mpc-core/src/`](../../bsv-mpc-core/src/) — `MpcError`, `Presignature`, `SigningResult`, and all MPC protocol types this proxy depends on
- [`../bsv-mpc-worker/src/`](../../bsv-mpc-worker/src/) — CF Worker KSS that this proxy communicates with (the remote party)
- [`../bsv-mpc-service/src/`](../../bsv-mpc-service/src/) — standalone KSS binary (same API as worker, for self-hosted deployments)
