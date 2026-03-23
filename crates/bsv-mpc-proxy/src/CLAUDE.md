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

Usable as a library or binary. `ProxyBuilder` constructs an `AppState` programmatically; `_impl` handler variants accept `&AppState` + `Value` directly (no HTTP).

## Files

| File | Lines | Status | Purpose |
|------|-------|--------|---------|
| `lib.rs` | 83 | Complete | Module declarations, crate-level docs, public re-exports (`AppState`, `ProxyBuilder`, `MpcBridge`, `ProxyConfig`, `StorageBackend`, etc.) |
| `main.rs` | 41 | Complete | Binary entry point — loads `ProxyConfig`, inits tracing, calls `server::run()` |
| `config.rs` | 162 | Complete | `ProxyConfig` from `MPC_*` env vars (9 fields), with defaults and test |
| `error.rs` | 125 | Complete | `ProxyError` enum (11 variants), HTTP status mapping, `From` impls |
| `server.rs` | 324 | Complete | `AppState`, `ProxyBuilder`, Axum router with all 30 BRC-100 routes, background presig task |
| `storage.rs` | 471 | Complete | `StorageBackend` trait, `InMemoryBackend` (wraps `UtxoTracker`), `WalletInfraBackend` (stub). 10 tests. |
| `wallet_api.rs` | 3788 | Complete | All 30 handlers implemented (dual Axum + `_impl` variants). BEEF construction + multi-tier broadcasting. 71 tests. |
| `bridge.rs` | 1420 | Complete | `MpcBridge` with BRC-31 auth, sign/presign/partial_ecdh, key derivation. 13 tests. |
| `fee_injector.rs` | 984 | Complete | Fee injection with raw tx parse/serialize, P2PKH + P2MS scripts. 29 tests. |
| `presign_manager.rs` | 268 | Complete | `PresignManager` FIFO pool, `background_replenish()` loop with exponential backoff. 6 tests. |
| `utxo_tracker.rs` | 403 | Complete | In-memory UTXO tracker with basket/tag filtering, greedy UTXO selection. 12 tests. |

## Key Exports

### `config::ProxyConfig`
Configuration loaded from environment variables. All fields have defaults (share_path defaults to `"share.enc"`).

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
| `arc_api_key` | `MPC_ARC_API_KEY` | TAAL mainnet key | `String` |

### `server::AppState`
Shared state passed to all Axum handlers via `State<Arc<AppState>>`:
- `config: ProxyConfig` — immutable after startup
- `bridge: MpcBridge` — holds decrypted share, joint key, BRC-31 auth session, reqwest client
- `presign_manager: Arc<RwLock<PresignManager>>` — presignature pool (RwLock for concurrent reads)
- `fee_injector: FeeInjector` — constructs fee outputs for `createAction` transactions
- `storage: Arc<dyn StorageBackend>` — pluggable UTXO storage (in-memory or wallet-infra)
- `http_client: reqwest::Client` — shared client for broadcasting and outbound requests (30s timeout)

### `server::ProxyBuilder`
Builder for constructing `AppState` programmatically (library usage):
- `new(config)` — create builder from config
- `with_bridge(bridge)` — override MPC bridge (skip KSS connection)
- `with_fee_injector(injector)` — override fee injector
- `with_presign_manager(manager)` — override presign pool
- `with_storage(backend)` — override storage backend (default: `InMemoryBackend`)
- `with_http_client(client)` — override HTTP client
- `build() -> Result<Arc<AppState>>` — construct state, connecting to KSS if no bridge provided

### `storage::StorageBackend`
Async trait for UTXO management. All methods return boxed futures for dyn-compatibility (`Arc<dyn StorageBackend>`). Implementations must be `Send + Sync`.
- `add_output(output)` — persist a new tracked output
- `mark_spent(txid, vout, spending_txid) -> bool` — mark as spent
- `list_unspent(basket, tags) -> Vec<TrackedOutput>` — filtered listing (tags use "any" matching)
- `select_utxos(target_sats) -> (Vec<TrackedOutput>, u64)` — greedy largest-first selection
- `total_balance() -> u64` — total unspent satoshis

### `storage::InMemoryBackend`
Default backend wrapping `UtxoTracker` with internal `RwLock`. For standalone/dev deployments.
- `new()` — empty UTXO set
- `from_tracker(tracker)` — wrap existing `UtxoTracker`

### `storage::WalletInfraBackend`
Stub for hosted mode where UTXOs live in rust-wallet-infra's `StorageClient`. Trait methods are defined but return errors pending integration.

### `bridge::MpcBridge`
Core translation layer between BRC-100 API and MPC protocol. All methods fully implemented.
- `new(config) -> Result<Self>` — reads share file, optionally decrypts (AES-256-GCM), validates share, parses root pubkey and share scalar/VSS points, determines signing participants, creates HTTP client, performs BRC-31 handshake with KSS
- `sign(hash, presignature, hmac_offset) -> Result<SigningResult>` — 4-round interactive 2PC ECDSA via `spawn_blocking`. Creates ephemeral `SigningCoordinator`, exchanges bundled messages with KSS. Optional HMAC offset for BRC-42 derived key signing.
- `presign() -> Result<Presignature>` — 3-round offline presigning via `spawn_blocking`. Creates ephemeral `PresigningManager` with pool_size=1.
- `partial_ecdh(counterparty_pub) -> Result<PublicKey>` — threshold partial ECDH: local computation + KSS `/ecdh` endpoint, combined with Lagrange interpolation
- `derive_symmetric_key(counterparty, level, protocol_name, key_id) -> Result<[u8; 32]>` — BRC-42 symmetric key for any counterparty type. "anyone" = 0 round-trips, "self"/"other" = 2 partial ECDH rounds.
- `derive_child_key(counterparty, level, protocol_name, key_id, for_self) -> Result<PublicKey>` — BRC-42 child public key derivation. "anyone" = local, "self"/"other" = 1 partial ECDH round.
- `root_pub()`, `joint_public_key()`, `session_id()`, `kss_url()`, `agent_id()` — accessors
- `new_for_test(joint_key)` — `#[cfg(test)]` constructor for unit tests (no KSS connection)

Internal types: `BridgeAuth` (BRC-31 client session), `SignInitRequest/Response`, `SignRoundRequest/Response`, `PresignInitRequest/Response`, `PresignRoundRequest/Response`, `EcdhRequest/Response`.

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
Adds MPC signing fee outputs to `createAction` transactions. Fully implemented.
- `new(fee_sats, fee_addresses, fee_threshold)` — constructor
- `is_enabled()` — true when both fee > 0 and addresses are non-empty
- `inject_fee(tx_bytes) -> Result<Vec<u8>>` — parses raw tx, injects fee output(s), reduces change, re-serializes
- `inject_fee_into_outputs(outputs, change_index) -> Result<FeeInjectionInfo>` — direct output list manipulation (used by `createAction`)
- `parse_threshold()` — parses `"2-of-3"` format into `(t, n)` with validation
- `fee_sats()`, `fee_addresses()` — accessors
- Two fee models: bare P2MS multisig (when threshold set) or split P2PKH (default, remainder to first address)
- Internal helpers: `resolve_address_to_p2pkh_script()` (supports hex pubkeys and Base58Check addresses), `build_p2ms_script()`, `split_fee_outputs()`, raw tx parser/serializer

### `utxo_tracker::UtxoTracker`
In-memory UTXO tracker. Used inside `InMemoryBackend` (wrapped in `RwLock`).
- `TrackedOutput` — struct with txid, vout, satoshis, locking_script, spending_txid, basket, tags, created_at
- `add_output(output)` — add new tracked output
- `mark_spent(txid, vout, spending_txid) -> bool` — mark as spent (returns false if not found or already spent)
- `list_unspent(basket, tags) -> Vec<&TrackedOutput>` — filtered listing; tags use "any" matching
- `select_utxos(target_sats) -> (Vec<TrackedOutput>, u64)` — greedy largest-first selection
- `total_balance()`, `len()`, `is_empty()`, `unspent_count()` — status

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

Every handler has two forms: an Axum handler (`fn handler(State, Json) -> Json<Value>`) and a library variant (`fn handler_impl(&AppState, Value) -> Value`). The Axum handler delegates to `_impl`.

### MPC-routed (require KSS round-trips)
| Handler | Route | Description |
|---------|-------|-------------|
| `get_public_key` | `POST /getPublicKey` | Returns root joint key or BRC-42 derived child. "anyone" = local, "self"/"other" = 1 partial ECDH round. |
| `create_signature` | `POST /createSignature` | 2PC ECDSA with presig pool fast path. Supports `hashToDirectlySign`, BRC-42 HMAC offset for "anyone" counterparty. |
| `create_action` | `POST /createAction` | Full pipeline: parse outputs → UTXO select → build tx → inject fee → BIP-143 sighash → MPC sign per input → construct BEEF → broadcast (ARC + WoC fallback) → update UTXO tracker. |
| `internalize_action` | `POST /internalizeAction` | Handles both raw tx hex AND BEEF/AtomicBEEF format. Detects format via magic bytes, extracts tx using BSV SDK `Beef` parser. Accepts specific outputs or auto-scans for root-key P2PKH matches. |

### Local-only (no MPC rounds)
| Handler | Route | Description |
|---------|-------|-------------|
| `encrypt` / `decrypt` | `POST /encrypt`, `/decrypt` | AES-256-GCM with BRC-42 derived key. Random 12-byte nonce. All counterparty types supported via `derive_symmetric_key`. |
| `create_hmac` / `verify_hmac` | `POST /createHmac`, `/verifyHmac` | HMAC-SHA256 with BRC-42 derived key. `verify_hmac` uses constant-time comparison. |
| `verify_signature` | `POST /verifySignature` | ECDSA verify against BRC-42 derived pubkey. Supports `forSelf`, `hashToDirectlySign`. |
| `list_outputs` | `POST /listOutputs` | Basket/tag filtering, pagination (limit/offset), optional locking script inclusion. Uses `StorageBackend`. |
| `list_actions` | `POST /listActions` | Stub — returns empty list. Action history not yet tracked. |
| `relinquish_output` | `POST /relinquishOutput` | Stub — returns success. Full implementation would remove from storage. |
| `get_network` | `POST /getNetwork` | Returns `"mainnet"` |
| `get_version` | `POST /getVersion` | Returns `"bsv-mpc-proxy {version}"` |
| `is_authenticated` | `POST /isAuthenticated` | Returns `true` (share loaded at startup) |
| `get_height` | `POST /getHeight` | Stub — returns `{ height: 0 }` |
| `wait_for_authentication` | `POST /waitForAuthentication` | Returns `{ authenticated: true }` immediately |
| `health` | `GET /health` | Status, version, presig count, KSS URL, fee config |
| Certificate handlers | 4 POST routes | Stubs — `listCertificates` returns empty, `proveCertificate`/`acquireCertificate` return error, `relinquishCertificate` returns success |
| Discovery handlers | 2 POST routes | Stubs — return empty results. Overlay discovery not yet wired. |
| Key linkage handlers | 2 POST routes | Stubs — return error. Not supported in MPC proxy. |

## Startup Flow

1. `main.rs`: init tracing, load `ProxyConfig::from_env()`
2. `server::run()`:
   - `MpcBridge::new(&config)` — read share file, optionally decrypt, validate, parse root pubkey + share scalar + VSS points, determine participants, create HTTP client, BRC-31 handshake with KSS
   - Construct `FeeInjector` from config
   - Construct `PresignManager` with `max_presignatures` capacity
   - Create `InMemoryBackend` as the default `StorageBackend`
   - Create shared `reqwest::Client` (30s timeout)
   - Bundle into `Arc<AppState>`
   - Spawn `background_replenish()` as a Tokio task
   - Build Axum router with all 30 routes + `/health`
   - Bind `0.0.0.0:{port}` and serve

## `createAction` Pipeline

This is the most complex handler — called by bsv-worm for every on-chain operation:

1. Parse `outputs` array (each with `satoshis` and `lockingScript` hex)
2. Compute P2PKH change script from root joint key
3. Determine MPC fee amount and output count (multisig=1, split=N addresses)
4. Select UTXOs via `storage.select_utxos()` (greedy largest-first)
5. Compute exact mining fee (`estimate_mining_fee`: 110 sats/KB, ceil division)
6. Build output list: user outputs + change (change includes MPC fee, deducted next)
7. `fee_injector.inject_fee_into_outputs()` — append fee output(s), reduce change
8. For each input:
   - Compute BIP-143 sighash (SIGHASH_ALL | SIGHASH_FORKID = 0x41)
   - Try `presign_manager.take()` for fast path
   - `bridge.sign(sighash, presig, None)` — 2PC with KSS (root key for now)
   - Build P2PKH unlocking script: `<DER sig + 0x41> <33-byte compressed pubkey>`
9. Serialize signed transaction
10. Construct BEEF (BRC-62/96) wrapping parent merkle proofs for ARC compliance
11. Broadcast via multi-tier strategy (see Broadcasting below)
12. Update storage: mark inputs as spent, add change output
13. Return `{ txid, rawTx }` (includes rawTx even on broadcast failure for client retry)

## BEEF Construction + Broadcasting

### BEEF Construction (`construct_beef`)
ARC miners require BEEF (Background Evaluation Extended Format) wrapping parent merkle proofs. The construction algorithm:
1. For each parent txid, fetch raw tx from WhatsOnChain (WoC)
2. Try to get TSC merkle proof from WoC, convert to BRC-74 `MerklePath`
3. If parent is confirmed: add with its BUMP (merkle proof)
4. If parent is unconfirmed: recurse one level to find a confirmed grandparent
5. Add the broadcasting transaction as the tip (no proof)
6. Validate the BEEF before returning

### Broadcasting Strategy (`broadcast_tx`)
Multi-tier failover:
1. **ARC with BEEF** — GorillaPool (no API key) then TAAL (Bearer token from `arc_api_key`)
2. **ARC with raw tx** — TAAL only (for cases where parents are already known to ARC)
3. **WoC fallback** — WhatsOnChain raw tx broadcast (up to 3 retries with 3s delay for propagation)

Accepts `SEEN_ON_NETWORK` and `MINED` as success (standard ARC de-duplication).

### BEEF Detection (`is_beef_format`)
Detects BEEF/AtomicBEEF by magic bytes (little-endian u32): AtomicBEEF `0x01010101`, BEEF V1 `0xEFBE0001`, BEEF V2 `0xEFBE0002`. Raw transactions (`0x00000001`/`0x00000002`) do not match.

### Internal Helpers
- `parse_input_txids(raw_tx)` — extract deduplicated parent txids (display byte order)
- `get_raw_tx_from_woc(client, txid)` — fetch raw tx bytes from WoC API
- `get_merkle_proof_from_woc(client, txid)` — fetch TSC proof + block height, convert to `MerklePath`
- `tsc_to_merkle_path(block_height, tx_index, txid, nodes)` — convert TSC proof array to BRC-74 `MerklePath` with proper leaf offsets and duplicate handling
- `extract_tx_from_beef(bytes)` — parse BEEF/AtomicBEEF, find target tx, return outputs + txid

## Dependencies

| Crate | Use in this module |
|-------|-------------------|
| `bsv-mpc-core` | `MpcError`, `Presignature`, `EncryptedShare`, `JointPublicKey`, `SessionId`, `SigningResult`, `SigningCoordinator`, `PresigningManager`, `ecdh`, `hd` |
| `bsv` | `PublicKey`, `PrivateKey`, `Signature` — BSV primitives; `Beef`, `MerklePath`, `MerklePathLeaf`, `Transaction` — BEEF construction and parsing |
| `axum` (0.8) | HTTP router, `State`, `Json`, `IntoResponse` |
| `reqwest` (0.12) | HTTP client for KSS communication, tx broadcasting, WoC API calls |
| `tokio` (1) | Async runtime, `RwLock`, `spawn`, `spawn_blocking`, `time::sleep` |
| `aes-gcm` | AES-256-GCM for encrypt/decrypt handlers |
| `hmac` / `sha2` | HMAC-SHA256 for createHmac/verifyHmac, SHA-256 for hashing |
| `serde` / `serde_json` | Request/response serialization |
| `thiserror` (2) | `ProxyError` derive macro |
| `tracing` | Structured logging throughout |
| `anyhow` | Error handling in `ProxyConfig`, `FeeInjector`, `MpcBridge` |
| `chrono` | UTC timestamps for `TrackedOutput.created_at` |
| `base64` | Encode/decode for encrypt/decrypt/HMAC payloads |
| `rand` | Random nonce generation (OsRng) |
| `hex` | Hex encode/decode throughout |

## Tests

142 tests across 7 files:

```bash
cargo test -p bsv-mpc-proxy
```

- `config::tests` — 1 test: default env var parsing (including `arc_api_key`)
- `bridge::tests` — 13 tests: hex encode/decode, API type serialization, share loading (plaintext, missing file, 2-of-3 participants)
- `fee_injector::tests` — 29 tests: enabled/disabled states, threshold parsing, inject into output list (single/split/multisig/remainder/insufficient/exact), raw tx round-trip injection, address resolution (hex pubkey, BSV address), P2MS script structure, split fee edge cases, balance equation verification
- `presign_manager::tests` — 6 tests: empty pool, take from empty, should_replenish, utilization, zero max, metrics
- `utxo_tracker::tests` — 12 tests: empty tracker, add/list, mark spent (found/not found/already spent), basket filter, tag filter ("any" mode), greedy UTXO selection (exact/insufficient/skips spent), outpoint format
- `storage::tests` — 10 tests: InMemoryBackend (empty, add/list, mark spent, not found, basket filter, tag filter, select utxos, from_tracker), WalletInfraBackend stubs return error, dyn compatibility
- `wallet_api::tests` — 71 tests: protocol param parsing, symmetric key derivation (anyone/deterministic/different invoices/self errors/other errors), encrypt/decrypt round-trip (normal/empty/large), nonce randomness, wrong key fails, short ciphertext rejected, self counterparty errors without KSS, HMAC create/verify (deterministic, valid, invalid, wrong data), verify_signature (valid anyone, invalid, self errors, bad data length, forSelf=false), getPublicKey (identity, no params, derived anyone, self errors), tx helpers (sha256d, P2PKH script, unlocking script, BIP-143 sighash deterministic/changes with output, serialize/parse roundtrip, txid, mining fee, varint roundtrip), internalizeAction (specific outputs, auto-scan, then list, invalid tx, missing tx, output out of range), BEEF detection (atomic/v1/v2/raw-tx-v1/raw-tx-v2/too-short), BEEF extraction (valid AtomicBEEF with real tx), input txid parsing (single/dedup/two-parents/real-tx/too-short/serialize-roundtrip), TSC merkle path (basic/duplicate/odd-index/empty-fails/roundtrip-binary)

## Related

- [`../../CLAUDE.md`](../../CLAUDE.md) — project root: architecture, deployment modes, fee economics, protocol latency
- [`../bsv-mpc-core/src/`](../../bsv-mpc-core/src/) — `MpcError`, `Presignature`, `SigningResult`, `SigningCoordinator`, `PresigningManager`, `ecdh`, `hd`, and all MPC protocol types this proxy depends on
- [`../bsv-mpc-worker/src/`](../../bsv-mpc-worker/src/) — CF Worker KSS that this proxy communicates with (the remote party)
- [`../bsv-mpc-service/src/`](../../bsv-mpc-service/src/) — standalone KSS binary (same API as worker, for self-hosted deployments)
