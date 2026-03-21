# bsv-mpc-worker/src
> Cloudflare Worker Key Share Service — holds share_A for 2-of-2 threshold ECDSA signing.

## Overview

This crate implements the remote Key Share Service (KSS) as a Cloudflare Worker compiled to WASM (`wasm32-unknown-unknown`, crate-type `cdylib`). It stores one half of a 2-of-2 MPC key share (share_A) while the MPC Signing Proxy holds share_B. The Worker exposes 8 HTTP endpoints for DKG, signing, and presigning protocols, with all mutation endpoints protected by BRC-31 Authrite authentication. Shares are stored encrypted (AES-256-GCM) in Durable Object SQLite — the Worker never sees plaintext key material.

All handler bodies are currently `todo!()` stubs with detailed pseudocode. The request/response types, storage schema, and auth types are fully defined.

## Files

| File | Lines | Purpose |
|------|-------|---------|
| `lib.rs` | 95 | CF Worker `#[event(fetch)]` entry point. Routes requests via `worker::Router` to 8 endpoints across 3 modules (`api`, `auth`, `storage`). |
| `api.rs` | 410 | Protocol HTTP handlers and all request/response types. 8 handler functions + 12 serde structs. All handler bodies are `todo!()` with pseudocode. |
| `auth.rs` | 152 | BRC-31 Authrite verification. `AuthenticatedIdentity` struct, `AuthError` enum (5 variants), `verify_request()`, `verify_agent_authorization()`, `handle_authrite_handshake()`. Only `verify_agent_authorization()` is implemented; rest are `todo!()`. |
| `storage.rs` | 258 | Durable Object SQLite wrapper. `ShareStorage` struct with 10 methods for CRUD on 3 tables (`shares`, `presigning_state`, `presignatures`). `ShareMetadata` struct for wire-safe metadata. All methods are `todo!()` with SQL pseudocode. |

## Key Exports

### Entry Point (`lib.rs`)

- `fetch()` — `#[event(fetch)]` handler. Creates a `worker::Router` and maps all 8 HTTP routes to `api::` handlers. GET routes: `/health`, `/shares/:agent_id`. POST routes: `/dkg/init`, `/dkg/round`, `/sign/init`, `/sign/round`, `/presign/init`, `/presign/round`.

### Request/Response Types (`api.rs`)

| Type | Direction | Endpoint |
|------|-----------|----------|
| `DkgInitRequest` | Request | `POST /dkg/init` |
| `DkgInitResponse` | Response | `POST /dkg/init` |
| `DkgRoundRequest` | Request | `POST /dkg/round` |
| `DkgRoundResponse` | Response | `POST /dkg/round` |
| `SignInitRequest` | Request | `POST /sign/init` |
| `SignInitResponse` | Response | `POST /sign/init` |
| `SignRoundRequest` | Request | `POST /sign/round` |
| `SignRoundResponse` | Response | `POST /sign/round` |
| `PresignInitRequest` | Request | `POST /presign/init` |
| `PresignInitResponse` | Response | `POST /presign/init` |
| `PresignRoundRequest` | Request | `POST /presign/round` |
| `PresignRoundResponse` | Response | `POST /presign/round` |
| `HealthResponse` | Response | `GET /health` |

### Handlers (`api.rs`)

| Function | Endpoint | Auth | Status |
|----------|----------|------|--------|
| `handle_dkg_init()` | `POST /dkg/init` | BRC-31 | `todo!()` |
| `handle_dkg_round()` | `POST /dkg/round` | BRC-31 | `todo!()` |
| `handle_sign_init()` | `POST /sign/init` | BRC-31 | `todo!()` |
| `handle_sign_round()` | `POST /sign/round` | BRC-31 | `todo!()` |
| `handle_presign_init()` | `POST /presign/init` | BRC-31 | `todo!()` |
| `handle_presign_round()` | `POST /presign/round` | BRC-31 | `todo!()` |
| `handle_health()` | `GET /health` | None | `todo!()` |
| `handle_get_share_metadata()` | `GET /shares/:agent_id` | BRC-31 | `todo!()` |

### Authentication (`auth.rs`)

- `AuthenticatedIdentity` — Struct holding verified BRC-31 identity: `identity_key` (33-byte compressed secp256k1 pubkey hex), `nonce`, `established_at`.
- `AuthError` — 5 variants: `NotAuthenticated`, `InvalidSignature(String)`, `SessionExpired { established, now }`, `IdentityMismatch { authenticated, requested }`, `VerificationError(String)`.
- `verify_request(req) -> Result<AuthenticatedIdentity, AuthError>` — Validates `x-authrite-identity-key`, `x-authrite-signature`, `x-authrite-nonce`, `x-authrite-yournonce` headers. `todo!()`.
- `verify_agent_authorization(auth, agent_id) -> Result<(), AuthError>` — **Implemented.** Ensures the authenticated identity matches the `agent_id` in the request body, preventing cross-agent share access.
- `handle_authrite_handshake(req) -> Result<Response>` — Handles `/.well-known/auth` key exchange. `todo!()`.

### Storage (`storage.rs`)

- `ShareStorage` — Wraps Durable Object SQLite. Constructed via `ShareStorage::new(ctx)` which initializes tables with `CREATE TABLE IF NOT EXISTS`.
- `ShareMetadata` — Wire-safe struct: `agent_id`, `session_id`, `share_index`, `threshold`, `parties`, `created_at`, `updated_at`, `presignature_count`.

**ShareStorage methods** (all `todo!()` with SQL pseudocode):

| Method | Description |
|--------|-------------|
| `new(ctx)` | Initialize schema, return storage instance |
| `store_share(agent_id, share)` | `INSERT OR REPLACE` encrypted share |
| `get_share(agent_id)` | Retrieve encrypted share or `None` |
| `delete_share(agent_id)` | Transactional delete: presignatures → presigning_state → shares |
| `list_agents()` | Return all agent IDs |
| `share_count()` | `COUNT(*)` on shares table |
| `get_share_metadata(agent_id)` | Join shares + presignature count |
| `store_presigning_state(agent_id, session_id, round, state)` | Persist intermediate round state |
| `get_presigning_state(agent_id, round)` | Retrieve round state blob |
| `store_presignature(agent_id, session_id, presig_id, data)` | Store completed presignature |
| `consume_presignature(agent_id)` | Atomic FIFO consumption (BEGIN → SELECT → UPDATE → COMMIT) |
| `presignature_count(agent_id)` | Count unconsumed presignatures |

## Protocol Flows

### DKG (4 rounds)
1. Proxy sends `POST /dkg/init` with `agent_id` and `ThresholdConfig`
2. Worker creates coordinator, returns round 1 message (commitments + ZK proofs)
3. Proxy sends 3 more `POST /dkg/round` requests, each with the previous round's message
4. On final round: Worker stores encrypted share, returns `JointPublicKey`

### Signing with presignature (1 online round)
1. Proxy sends `POST /sign/init` with `sighash` and `use_presignature: true`
2. Worker atomically consumes a presignature (FIFO), returns round 1 message
3. Proxy sends `POST /sign/round`, Worker returns complete ECDSA signature

### Signing without presignature (4 rounds)
Same as above but `use_presignature: false` (or no presigs available), resulting in up to 4 rounds.

### Presigning (3 offline rounds)
1. Proxy sends `POST /presign/init` with batch `count` (max 100)
2. Worker generates round 1 messages (one per presignature)
3. Two more `POST /presign/round` exchanges complete the protocol
4. Completed presignatures stored for future consumption

## Storage Schema

Three SQLite tables in the Durable Object:

- **`shares`** — One row per agent. PK: `agent_id`. Columns: `session_id`, `share_index`, `encrypted_share` (BLOB), `config_json` (plaintext t/n), `created_at`, `updated_at`.
- **`presigning_state`** — Intermediate round state. PK: `id` (agent_id:round). FK to shares. Columns: `session_id`, `round`, `state` (BLOB), `created_at`.
- **`presignatures`** — Completed presignatures. PK: `id`. FK to shares. Columns: `session_id`, `data` (BLOB), `created_at`, `consumed` (0/1). Consumed FIFO via atomic transaction.

## Security Model

- All mutation endpoints require BRC-31 Authrite mutual authentication
- `verify_agent_authorization()` prevents agent A from accessing agent B's share
- Shares stored encrypted with AES-256-GCM (BRC-42 derived keys) — Worker never sees plaintext
- Presignature consumption is atomic to prevent nonce reuse (which would leak the private key)
- Auth sessions expire after 1 hour (`SessionExpired` error)
- `config_json` is the only plaintext field (contains only threshold/party counts, no secrets)

## Dependencies

| Crate | Purpose |
|-------|---------|
| `bsv-mpc-core` | Core MPC types (`RoundMessage`, `SessionId`, `ThresholdConfig`, `EncryptedShare`, etc.) |
| `worker` 0.4 | CF Worker SDK (Router, Request, Response, Env, Context, Durable Objects) |
| `serde` / `serde_json` | JSON serialization for request/response types |
| `sha2` | SHA-256 for signature verification in BRC-31 auth |
| `thiserror` | `AuthError` derive macro |
| `chrono` | Timestamp handling for session TTL |
| `getrandom` 0.2 (`js` feature) | Entropy source in WASM — required for V8 isolate |

## WASM Constraints

- Target: `wasm32-unknown-unknown` (crate-type `cdylib`)
- Must use `getrandom/js` for entropy (no OS random in V8 isolate)
- `bsv-mpc-core` must use `num-bigint` backend for cggmp24 (not `rug` — GMP is LGPL and doesn't compile to WASM)
- CF Worker memory limit: 128MB (this crate uses ~5-20MB WASM module + ~50KB protocol state)
- Worker may restart between protocol rounds — all intermediate state persisted in DO SQLite

## Related

- [Root CLAUDE.md](../../../CLAUDE.md) — Project-wide architecture, conventions, and decisions
- [bsv-mpc-core](../../bsv-mpc-core/src/) — Core MPC protocol types used by this crate
- [bsv-mpc-proxy](../../bsv-mpc-proxy/src/) — The other half: MPC Signing Proxy that holds share_B and calls this Worker
- [bsv-mpc-service](../../bsv-mpc-service/src/) — Standalone KSS alternative (same API, local SQLite instead of DO)
