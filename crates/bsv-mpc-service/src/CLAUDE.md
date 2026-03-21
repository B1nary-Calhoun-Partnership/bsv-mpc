# bsv-mpc-service/src
> Standalone MPC Key Share Service binary for self-hosted deployments.

## Overview

Self-hosted alternative to the Cloudflare Worker KSS (`bsv-mpc-worker`). Exposes the same HTTP API over axum, backed by local SQLite instead of Durable Object SQLite. Suitable for Mode A (Split Stack) deployments, independent node operators, and local development/testing. Listens on port 4322 by default.

This binary holds **share_A** — the remote party's key share. The MPC Signing Proxy (`bsv-mpc-proxy`) holds share_B and communicates with this service over HTTP for DKG, signing, and presigning protocol rounds.

## Files

| File | Lines | Purpose |
|------|-------|---------|
| `main.rs` | 119 | Binary entry point, env config, axum router setup, `AppState` definition |
| `handlers.rs` | 345 | HTTP request handlers for all 9 endpoints (8 KSS API + Authrite) |
| `storage.rs` | 323 | `SqliteShareStorage` — local SQLite persistence for shares, protocol state, presignatures |

## Implementation Status

- `main.rs` — **Complete**: router wiring, env parsing, tracing setup, server start
- `handlers.rs` — **Partial**: `handle_health` works (returns uptime, version, data dir). All other handlers are `todo!()` stubs with detailed pseudocode
- `storage.rs` — **All stubs**: `SqliteShareStorage::open()` and all methods are `todo!()` with SQL queries documented in comments

No SQLite driver is wired yet (`rusqlite` or equivalent not in Cargo.toml dependencies).

## Key Types

### `AppState` (main.rs:61)
Shared axum state holding config and storage:
- `data_dir: String` — path where SQLite DB lives
- `storage: RwLock<SqliteShareStorage>` — thread-safe storage access
- `started_at: chrono::DateTime<chrono::Utc>` — for uptime reporting

### `SqliteShareStorage` (storage.rs:78)
Local SQLite persistence. Currently holds only `db_path: String`. Planned: `rusqlite::Connection`.

5 tables (schemas documented in module doc comments):
- `shares` — encrypted key shares, one per agent (PK: `agent_id`)
- `presigning_state` — intermediate presigning round state
- `presignatures` — completed presignatures with FIFO consumption flag
- `dkg_state` — intermediate DKG coordinator state between rounds
- `signing_state` — intermediate signing coordinator state between rounds

### `ShareMetadata` (storage.rs:86)
Wire-safe share info (no secrets): `agent_id`, `session_id`, `share_index`, `threshold`, `parties`, timestamps, `presignature_count`.

### Session State Types (storage.rs)
- `DkgSessionState` (storage.rs:107) — persisted DKG coordinator: `session_id`, `agent_id`, `round`, serialized `state`
- `SigningSessionState` (storage.rs:119) — persisted signing coordinator: adds `sighash` (32 bytes)

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
| `HealthResponse` | `GET /health` |

## API Endpoints

9 routes defined in `main.rs:98-113`:

| Method | Path | Handler | Auth | Status |
|--------|------|---------|------|--------|
| POST | `/dkg/init` | `handle_dkg_init` | BRC-31 | Stub |
| POST | `/dkg/round` | `handle_dkg_round` | BRC-31 | Stub |
| POST | `/sign/init` | `handle_sign_init` | BRC-31 | Stub |
| POST | `/sign/round` | `handle_sign_round` | BRC-31 | Stub |
| POST | `/presign/init` | `handle_presign_init` | BRC-31 | Stub |
| POST | `/presign/round` | `handle_presign_round` | BRC-31 | Stub |
| GET | `/health` | `handle_health` | None | **Working** |
| GET | `/shares/:agent_id` | `handle_get_share_metadata` | BRC-31 | Stub |
| POST | `/.well-known/auth` | `handle_authrite` | None | Stub |

## Configuration

All via environment variables (parsed in `main.rs:79-83`):

| Variable | Default | Description |
|----------|---------|-------------|
| `MPC_SERVICE_PORT` | `4322` | TCP port to bind |
| `MPC_DATA_DIR` | `./shares` | Directory for SQLite database |
| `RUST_LOG` | `bsv_mpc_service=info` | Tracing filter (via `tracing-subscriber`) |

The data directory is created automatically on startup (`main.rs:86`). SQLite database file: `{data_dir}/mpc-shares.db`.

## Storage Methods

### Share CRUD
- `store_share(agent_id, share)` — upsert encrypted share
- `get_share(agent_id)` → `Option<EncryptedShare>`
- `delete_share(agent_id)` — cascading delete of share + all associated state
- `list_agents()` → `Vec<String>` — all agent IDs
- `share_count()` → `usize`
- `get_share_metadata(agent_id)` → `Option<ShareMetadata>` — includes presignature count

### DKG State
- `store_dkg_state(state)` — persist between rounds
- `get_dkg_state(session_id)` → `Option<DkgSessionState>`
- `delete_dkg_state(session_id)` — cleanup after completion

### Signing State
- `store_signing_state(state)` — persist between rounds
- `get_signing_state(session_id)` → `Option<SigningSessionState>`
- `delete_signing_state(session_id)` — cleanup after completion

### Presigning
- `store_presigning_state(agent_id, session_id, round, state)` — intermediate round state
- `get_presigning_state(agent_id, round)` → `Option<Vec<u8>>`
- `store_presignature(agent_id, session_id, presig_id, data)` — completed presignature
- `consume_presignature(agent_id)` → `Option<Vec<u8>>` — atomic FIFO consumption
- `presignature_count(agent_id)` → `u64` — unconsumed count
- `prune_consumed_presignatures(older_than)` → `u64` — audit retention cleanup

## Thread Safety

`SqliteShareStorage` is wrapped in `tokio::sync::RwLock` inside `AppState`. Read operations acquire a read lock; write operations acquire a write lock. Appropriate for the expected concurrency (one agent per share, low QPS).

## Dependencies

| Crate | Purpose |
|-------|---------|
| `bsv-mpc-core` | Core MPC types (`RoundMessage`, `ThresholdConfig`, `EncryptedShare`, etc.) |
| `axum` | HTTP server framework |
| `tokio` | Async runtime |
| `serde` / `serde_json` | Serialization for request/response types |
| `chrono` | Timestamps, uptime calculation |
| `tracing` / `tracing-subscriber` | Structured logging |
| `anyhow` | Error handling (used via `main()` return type, not in Cargo.toml — comes transitively) |

Missing dependency needed for implementation: `rusqlite` (or similar SQLite driver).

## What Needs Implementation

1. **Add `rusqlite` dependency** to Cargo.toml
2. **`SqliteShareStorage::open()`** — connect, set WAL mode, create tables
3. **All storage methods** — straightforward SQL (queries documented in `todo!()` strings)
4. **BRC-31 auth verification** — extract from headers, verify signature. Needed by all mutation handlers
5. **Handler bodies** — each handler's `todo!()` contains step-by-step pseudocode describing the exact logic
6. **`handle_authrite`** — Authrite handshake (server identity key + nonce exchange)

## Handler Pseudocode Pattern

Every protocol handler follows the same pattern (documented in `todo!()` blocks):
1. Verify BRC-31 auth from request headers
2. Load state from storage (share, session state, or presignature)
3. Delegate to `bsv-mpc-core` protocol coordinator
4. If round complete: finalize, store result, clean up intermediate state
5. If more rounds needed: persist updated state, return next round message

## Differences from bsv-mpc-worker

| Aspect | bsv-mpc-worker | bsv-mpc-service |
|--------|---------------|-----------------|
| Runtime | CF Worker V8 isolate | Tokio on bare metal/VPS |
| HTTP framework | `worker` crate | `axum` |
| Storage | Durable Object SQLite | Local SQLite file |
| Target | `wasm32-unknown-unknown` | Native (`x86_64`/`aarch64`) |
| Scaling | Automatic (CF edge) | Manual (reverse proxy, replicas) |
| Cost | ~$5/mo (CF Workers plan) | VPS cost |
| Auth session storage | DO transient state | Local (planned) |

The API surface is identical — `bsv-mpc-proxy` can point at either backend by changing the KSS URL.

## Related

- [Root CLAUDE.md](../../../CLAUDE.md) — project architecture, conventions, all crate descriptions
- `../bsv-mpc-worker/src/` — CF Worker equivalent (same API, Durable Object storage)
- `../bsv-mpc-core/src/` — MPC protocol layer (DKG, signing, presigning coordinators)
- `../bsv-mpc-proxy/src/` — BRC-100 signing proxy that calls this service
