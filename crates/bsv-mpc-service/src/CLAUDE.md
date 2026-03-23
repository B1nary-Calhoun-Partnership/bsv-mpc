# bsv-mpc-service/src
> Standalone MPC Key Share Service binary for self-hosted deployments.

## Overview

Self-hosted alternative to the Cloudflare Worker KSS (`bsv-mpc-worker`). Exposes the same HTTP API over axum, backed by in-memory storage (planned: local SQLite). Suitable for Mode A (Split Stack) deployments, independent node operators, and local development/testing. Listens on port 4322 by default.

This binary holds **share_A** — the remote party's key share. The MPC Signing Proxy (`bsv-mpc-proxy`) holds share_B and communicates with this service over HTTP for DKG, signing, presigning, and ECDH protocol rounds.

## Files

| File | Lines | Purpose |
|------|-------|---------|
| `lib.rs` | 50 | Library interface: `AppState`, `build_router()`, re-exports `SqliteShareStorage` |
| `main.rs` | 85 | Binary entry point: env config, tracing setup, server start |
| `handlers.rs` | 700 | HTTP request handlers for all 10 endpoints (9 KSS API + Authrite) |
| `storage.rs` | 366 | `SqliteShareStorage` — in-memory persistence for shares, protocol state, presignatures |

## Implementation Status

- `lib.rs` — **Complete**: `AppState` struct, `build_router()` with all 10 routes, module exports
- `main.rs` — **Complete**: env parsing, tracing setup, storage init, server start
- `handlers.rs` — **Implemented**: All protocol handlers (DKG, signing, presigning, ECDH) have working implementations using `bsv-mpc-core` coordinators. `handle_authrite` is a stub returning zeroed identity. BRC-31 auth verification is absent — TODO comments exist on `handle_dkg_init`, `handle_ecdh`, and `handle_get_share_metadata` but all mutation endpoints lack auth.
- `storage.rs` — **Implemented (in-memory)**: All methods work using `HashMap`/`VecDeque`. SQLite driver not yet wired (`rusqlite` not in Cargo.toml). 5-table SQL schema documented in module doc comments for future migration.

## Key Types

### `AppState` (lib.rs:18)
Shared axum state holding config and storage:
- `data_dir: String` — path where SQLite DB lives (logged, not yet used for persistence)
- `storage: std::sync::RwLock<SqliteShareStorage>` — thread-safe storage access
- `started_at: chrono::DateTime<chrono::Utc>` — for uptime reporting

### `CoordinatorStore` (handlers.rs:41)
Global `LazyLock<Mutex<...>>` holding live protocol coordinators between HTTP requests:
- `dkg: HashMap<String, DkgCoordinator>` — active DKG ceremonies
- `signing: HashMap<String, SigningCoordinator>` — active signing sessions
- `presigning: HashMap<String, PresigningManager>` — active presigning batches

Coordinators contain threads and channels, so they must stay alive in memory between requests (cannot be serialized to storage). No TTL or eviction — abandoned sessions leak memory.

### `SqliteShareStorage` (storage.rs:74)
In-memory share storage (production: local SQLite). Fields:
- `db_path: String` — planned SQLite path (display/logging only)
- `shares: HashMap<String, StoredShare>` — encrypted shares keyed by agent_id
- `protocol_state: HashMap<String, Vec<u8>>` — protocol state keyed by prefixed session_id
- `presignatures: HashMap<String, VecDeque<StoredPresignature>>` — FIFO queues per agent

5 tables (schemas documented in `storage.rs` module doc comments for future SQLite migration):
- `shares` — encrypted key shares, one per agent (PK: `agent_id`)
- `presigning_state` — intermediate presigning round state
- `presignatures` — completed presignatures with FIFO consumption
- `dkg_state` — intermediate DKG coordinator state between rounds
- `signing_state` — intermediate signing coordinator state between rounds

### Internal Storage Types (storage.rs)
- `StoredShare` (storage.rs:86) — private wrapper: `share: EncryptedShare`, `created_at: String`, `updated_at: String`
- `StoredPresignature` (storage.rs:94) — private wrapper: `id`, `session_id`, `data: Vec<u8>`, `created_at` (fields used for audit/debugging in production SQLite)

### `ShareMetadata` (storage.rs:103)
Wire-safe share info (no secrets): `agent_id`, `session_id`, `share_index`, `threshold`, `parties`, timestamps, `presignature_count`.

### Session State Types (storage.rs)
- `DkgSessionState` (storage.rs:124) — persisted DKG coordinator: `session_id`, `agent_id`, `round`, serialized `state`
- `SigningSessionState` (storage.rs:137) — persisted signing coordinator: adds `sighash` (Vec<u8>)

Note: `get_dkg_state()` and `get_signing_state()` do not fully round-trip — `agent_id`, `round`, and `sighash` are lost on retrieval (returned as empty/zero). These fields are only preserved for the planned SQLite migration where they would be stored as separate columns.

### Request/Response Types (handlers.rs)
Mirror the types in `bsv-mpc-worker::api`. Could be extracted to a shared crate in the future.

| Type | Endpoint |
|------|----------|
| `DkgInitRequest` / `DkgInitResponse` | `POST /dkg/init` |
| `DkgRoundRequest` / `DkgRoundResponse` | `POST /dkg/round` |
| `SignInitRequest` / `SignInitResponse` | `POST /sign/init` |
| `SignRoundRequest` / `SignRoundResponse` | `POST /sign/round` |
| `PresignInitRequest` / `PresignInitResponse` | `POST /presign/init` |
| `PresignRoundRequest` / `PresignRoundResponse` | `POST /presign/round` |
| `EcdhRequest` / `EcdhResponse` | `POST /ecdh` |
| `HealthResponse` | `GET /health` |

## API Endpoints

10 routes defined in `lib.rs:28-50`:

| Method | Path | Handler | Auth | Status |
|--------|------|---------|------|--------|
| POST | `/dkg/init` | `handle_dkg_init` | BRC-31 (TODO) | **Implemented** |
| POST | `/dkg/round` | `handle_dkg_round` | BRC-31 (TODO) | **Implemented** |
| POST | `/sign/init` | `handle_sign_init` | BRC-31 (TODO) | **Implemented** |
| POST | `/sign/round` | `handle_sign_round` | BRC-31 (TODO) | **Implemented** |
| POST | `/ecdh` | `handle_ecdh` | BRC-31 (TODO) | **Implemented** |
| POST | `/presign/init` | `handle_presign_init` | BRC-31 (TODO) | **Implemented** |
| POST | `/presign/round` | `handle_presign_round` | BRC-31 (TODO) | **Implemented** |
| GET | `/health` | `handle_health` | None | **Implemented** |
| GET | `/shares/{agent_id}` | `handle_get_share_metadata` | BRC-31 (TODO) | **Implemented** |
| POST | `/.well-known/auth` | `handle_authrite` | None | Stub |

### Handler Implementation Details

**DKG** (`handle_dkg_init`, `handle_dkg_round`): Creates `DkgCoordinator` with `ShareIndex(0)`, runs 4-round CGGMP'24 protocol. On completion, stores the resulting share via `storage.store_share()` keyed by `dkg_result.session_id` (not agent_id) and removes the coordinator from `COORDINATOR_STORE`. Note: `DkgInitRequest.agent_id` is received but not currently used as the storage key — the DKG session ID is used instead. This means share retrieval for signing/ECDH must use the session ID as the agent lookup key.

**Signing** (`handle_sign_init`, `handle_sign_round`): Loads agent's share from storage, creates `SigningCoordinator` with all parties as participants (`0..config.parties`). The coordinator is created with the DKG `session_id` (from the request body) but stored in `COORDINATOR_STORE` under a newly generated `signing_session_id` — subsequent round calls use the signing session ID. Supports optional `hmac_offset` field (32-byte hex) for BRC-42 derived key signing via `set_additive_shift()`. On completion, returns `SigningResult` and cleans up coordinator. `handle_sign_round` returns `round_message: None` when the coordinator produces an empty message vec (can happen in certain protocol transitions).

**ECDH** (`handle_ecdh`): Computes partial ECDH for BRC-42 key derivation. Parses counterparty public key (33-byte compressed hex), loads agent's share, extracts scalar via `bsv_mpc_core::ecdh::parse_share_scalar()`, computes `counterparty_pub * share_scalar` via `compute_partial_ecdh_point()`. Returns compressed point as hex.

**Presigning** (`handle_presign_init`, `handle_presign_round`): Creates `PresigningManager` for batch generation. Validates count is 1-100 (rejects 0 or >100 with 400 BAD_REQUEST). 3-round protocol. On completion, cleans up coordinator. Note: `presignatures_generated` is hardcoded to `Some(1)` on completion rather than reflecting the actual batch count from the request.

**Health** (`handle_health`): Returns `CARGO_PKG_VERSION`, share count, total presignatures summed across all agents, uptime in seconds, data directory path.

**Share Metadata** (`handle_get_share_metadata`): Returns `ShareMetadata` for a single agent (no secrets exposed). Includes presignature count.

**Authrite** (`handle_authrite`): Stub that returns a zeroed 33-byte identity key, `"development-stub-nonce"`, and empty certificates array. Accepts `identityKey` and `nonce` from body but doesn't process them.

### Helper Functions (handlers.rs)

- `generate_session_id(prefix)` (handlers.rs:211) — 32 bytes from `getrandom`, SHA-256 hashed, formatted as `"{prefix}-{hex(first_16_bytes)}"`. Used for all session IDs (dkg, sign, presign).
- `err_response(status, msg)` (handlers.rs:219) — Returns `(StatusCode, Json({"error": "..."}))` tuple for error responses.
- `bundle_outgoing_messages(messages)` (handlers.rs:227) — Combines multiple `RoundMessage`s into one by JSON-array-encoding their payloads. Preserves `session_id`, `round`, `from` from the first message, sets `to: None`.
- `unbundle_incoming_message(msg)` (handlers.rs:254) — Splits a transport `RoundMessage` back into individual messages. Detects bundled payloads by checking if the first byte is `[` (JSON array). If not an array, returns the message as-is in a single-element vec. **Currently unused** — handlers pass bundled messages directly to coordinators as a single-element vec (coordinators handle unbundling internally via their SM thread).

### Message Flow

Outgoing messages from coordinators are **bundled** via `bundle_outgoing_messages()` before being returned to the proxy. Incoming messages from the proxy are passed to coordinators as-is in a single-element vec (the coordinator's internal SM thread handles unbundling). The `unbundle_incoming_message()` helper exists for future use but is not called by any handler.

## Configuration

All via environment variables (parsed in `main.rs:60-64`):

| Variable | Default | Description |
|----------|---------|-------------|
| `MPC_SERVICE_PORT` | `4322` | TCP port to bind |
| `MPC_DATA_DIR` | `./shares` | Directory for SQLite database |
| `RUST_LOG` | `bsv_mpc_service=info` | Tracing filter (via `tracing-subscriber`) |

The data directory is created automatically on startup (`std::fs::create_dir_all`). SQLite database path: `{data_dir}/mpc-shares.db` (logged but not yet opened).

## Storage Methods

All methods return `anyhow::Result`. Currently in-memory; SQL schemas documented in module doc comments.

### Share CRUD
- `open(data_dir)` — create in-memory storage, record planned db path
- `store_share(agent_id, share)` — upsert encrypted share with timestamps
- `get_share(agent_id)` -> `Option<EncryptedShare>`
- `delete_share(agent_id)` — cascading delete of share + presignatures
- `list_agents()` -> `Vec<String>` — sorted agent IDs
- `share_count()` -> `usize`
- `get_share_metadata(agent_id)` -> `Option<ShareMetadata>` — includes presignature count

### DKG State
- `store_dkg_state(state)` — persist between rounds (keyed as `dkg:{session_id}`)
- `get_dkg_state(session_id)` -> `Option<DkgSessionState>` — `agent_id` and `round` are not preserved (returned as empty/zero)
- `delete_dkg_state(session_id)` — cleanup after completion

### Signing State
- `store_signing_state(state)` — persist between rounds (keyed as `sign:{session_id}`)
- `get_signing_state(session_id)` -> `Option<SigningSessionState>` — `agent_id`, `round`, `sighash` are not preserved (returned as empty/zero/empty)
- `delete_signing_state(session_id)` — cleanup after completion

### Presigning
- `store_presigning_state(agent_id, session_id, round, state)` — keyed as `presign:{agent_id}:{session_id}:{round}`
- `get_presigning_state(agent_id, round)` -> `Option<Vec<u8>>` — prefix-match search across all sessions
- `store_presignature(agent_id, session_id, presig_id, data)` — append to FIFO queue
- `consume_presignature(agent_id)` -> `Option<Vec<u8>>` — FIFO pop_front
- `presignature_count(agent_id)` -> `u64`
- `prune_consumed_presignatures(older_than)` -> `u64` — no-op for in-memory (consumed entries already removed)

Note: The DKG/signing/presigning state methods (`store_dkg_state`, `get_dkg_state`, etc.) are defined in storage but not called by any handler. Handlers use the in-memory `COORDINATOR_STORE` instead. These methods exist for the planned SQLite migration where coordinator state would need to survive process restarts.

## Thread Safety

`SqliteShareStorage` is wrapped in `std::sync::RwLock` inside `AppState`. Read operations acquire a read lock; write operations acquire a write lock. Live coordinators use a separate global `Mutex<CoordinatorStore>` since they can't be stored in the RwLock-guarded storage (they contain threads/channels).

Note: `storage.rs` module doc comments say `tokio::sync::RwLock` but the actual code uses `std::sync::RwLock`. The synchronous `RwLock` is correct here since storage operations are fast in-memory lookups and don't cross `.await` points.

## Dependencies

| Crate | Purpose |
|-------|---------|
| `bsv-mpc-core` | MPC coordinators + types (`DkgCoordinator`, `SigningCoordinator`, `PresigningManager`, `RoundMessage`, `EncryptedShare`) |
| `bsv` | BSV primitives (`PublicKey` for ECDH endpoint) |
| `axum` | HTTP server framework |
| `tokio` | Async runtime |
| `serde` / `serde_json` | Request/response serialization |
| `chrono` | Timestamps, uptime calculation |
| `tracing` / `tracing-subscriber` | Structured logging |
| `anyhow` | Error handling in main + storage |
| `getrandom` | Entropy for session ID generation (v0.2) |
| `sha2` | SHA-256 for session ID hashing |
| `hex` | Hex encoding/decoding for sighash, keys, session IDs |

## What Needs Implementation

1. **BRC-31 auth verification** — All mutation endpoints lack auth. TODO comments exist on `handle_dkg_init`, `handle_ecdh`, and `handle_get_share_metadata`. Reference: `~/bsv/rust-middleware` (`bsv-auth-cloudflare`).
2. **SQLite persistence** — Add `rusqlite` dependency, implement `SqliteShareStorage::open()` with WAL mode + table creation, migrate all methods from HashMap to SQL. Schema is already documented in `storage.rs` module doc comments.
3. **Full Authrite handshake** (`handle_authrite`) — Currently returns a zeroed identity key and stub nonce. Must implement BRC-31 handshake per `~/bsv/BRCs/peer-to-peer/0031.md`.
4. **Coordinator cleanup** — No TTL or eviction for abandoned sessions in `COORDINATOR_STORE`. Long-running server could leak memory from incomplete protocol sessions.
5. **DKG share keying** — `handle_dkg_round` stores shares keyed by `dkg_result.session_id.0` rather than the `agent_id` from the init request. This works but means callers must know the DKG session ID to look up shares for signing/ECDH.
6. **Presign batch count** — `handle_presign_round` hardcodes `presignatures_generated: Some(1)` on completion instead of reporting the actual batch count.
7. **Wire storage state methods to handlers** — `store_dkg_state`/`store_signing_state` etc. are implemented in storage but handlers use only `COORDINATOR_STORE`. These need to be wired for crash recovery when SQLite is added.

## Differences from bsv-mpc-worker

| Aspect | bsv-mpc-worker | bsv-mpc-service |
|--------|---------------|-----------------|
| Runtime | CF Worker V8 isolate | Tokio on bare metal/VPS |
| HTTP framework | `worker` crate | `axum` |
| Storage | Durable Object SQLite | In-memory (planned: local SQLite) |
| Target | `wasm32-unknown-unknown` | Native (`x86_64`/`aarch64`) |
| Scaling | Automatic (CF edge) | Manual (reverse proxy, replicas) |
| Cost | ~$5/mo (CF Workers plan) | VPS cost |
| Coordinator state | Global statics | Global `LazyLock<Mutex<CoordinatorStore>>` |
| Auth | BRC-31 implemented (`auth.rs`) | Stub only |

The API surface is identical — `bsv-mpc-proxy` can point at either backend by changing the KSS URL.

## Related

- [Root CLAUDE.md](../../../CLAUDE.md) — project architecture, conventions, all crate descriptions
- `../bsv-mpc-worker/src/` — CF Worker equivalent (same API, Durable Object storage)
- `../bsv-mpc-core/src/` — MPC protocol layer (DKG, signing, presigning coordinators)
- `../bsv-mpc-proxy/src/` — BRC-100 signing proxy that calls this service
