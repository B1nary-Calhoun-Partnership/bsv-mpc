# bsv-mpc-worker/src
> Cloudflare Worker Key Share Service — holds share_A for 2-of-2 threshold ECDSA signing.

## Overview

This crate implements the remote Key Share Service (KSS) as a Cloudflare Worker compiled to WASM (`wasm32-unknown-unknown`, crate-type `cdylib`). It stores one half of a 2-of-2 MPC key share (share_A) while the MPC Signing Proxy holds share_B. The Worker exposes 10 HTTP endpoints for DKG, signing, presigning, and partial ECDH protocols, with all mutation endpoints protected by BRC-31 Authrite authentication. Shares are stored encrypted (AES-256-GCM) in memory (development) with planned migration to Durable Object SQLite for production persistence.

**All handlers, auth, and storage are fully implemented — zero `todo!()` stubs.**

## Files

| File | Lines | Purpose |
|------|-------|---------|
| `lib.rs` | 173 | CF Worker entry point: `#[event(fetch)]` router, `MpcStorage` Durable Object stub, CORS preflight, auth wiring for all protected endpoints. |
| `api.rs` | 935 | All 9 protocol handlers (implemented), 14 request/response types, message bundling helpers, live coordinator state management. 14 unit tests. |
| `auth.rs` | 963 | Full BRC-31 Authrite implementation: handshake, request verification, BRC-42 key derivation, session management, CORS, response signing. Ported from bsv-auth-cloudflare. 13 unit tests. |
| `storage.rs` | 478 | In-memory storage for shares, protocol state, and presignatures. `ShareStorage` (15 methods) + `ShareMetadata`. 9 unit tests. |

## Key Exports

### Entry Point (`lib.rs`)

- `MpcStorage` — Durable Object struct (stub). Holds `State` and `Env`, returns JSON status on fetch. Required by wrangler for `MPC_STORAGE` binding.
- `fetch()` — `#[event(fetch)]` handler. Routes via `worker::Router` to 10 endpoints plus CORS preflight. Each protected endpoint loads `AuthConfig::from_env()` and calls `auth::verify_or_allow()` before delegating to the handler.

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
| `EcdhRequest` | Request | `POST /ecdh` |
| `EcdhResponse` | Response | `POST /ecdh` |
| `HealthResponse` | Response | `GET /health` |

### Handlers (`api.rs`)

All handlers are **fully implemented** — they create/lookup coordinators, call bsv-mpc-core, and return results.

| Function | Endpoint | Auth | Description |
|----------|----------|------|-------------|
| `handle_dkg_init()` | `POST /dkg/init` | BRC-31 | Creates DKG coordinator (party 0), returns round 1 messages |
| `handle_dkg_round()` | `POST /dkg/round` | BRC-31 | Processes DKG round, stores share on completion |
| `handle_sign_init()` | `POST /sign/init` | BRC-31 | Loads share, creates signing coordinator, returns round 1 |
| `handle_sign_round()` | `POST /sign/round` | BRC-31 | Processes signing round, returns ECDSA signature on completion |
| `handle_presign_init()` | `POST /presign/init` | BRC-31 | Creates presigning manager (count 1-100), returns round 1 |
| `handle_presign_round()` | `POST /presign/round` | BRC-31 | Processes presigning round, stores presignatures on completion |
| `handle_ecdh()` | `POST /ecdh` | BRC-31 | Computes partial ECDH: `counterparty_pub * share_A` |
| `handle_health()` | `GET /health` | None | Returns status, version, share count, presignature count |
| `handle_get_share_metadata()` | `GET /shares/:agent_id` | BRC-31 | Returns share metadata (no secrets exposed) |

### Live Coordinator State (`api.rs`)

Protocol coordinators contain threads and channels that cannot be serialized, so they are kept alive in global statics between HTTP round-trip requests:

- `DKG_SESSIONS` — `LazyLock<Mutex<HashMap<String, DkgCoordinator>>>`
- `SIGNING_SESSIONS` — `LazyLock<Mutex<HashMap<String, SigningCoordinator>>>`
- `PRESIGNING_SESSIONS` — `LazyLock<Mutex<HashMap<String, PresigningManager>>>`

Sessions are created in `*_init` handlers and removed on protocol completion or error.

### Message Bundling (`api.rs`)

Each protocol round may produce multiple wire messages (broadcast + p2p). For HTTP transport, they are bundled/unbundled:

- `bundle_outgoing_messages(msgs) -> RoundMessage` — Combines multiple wire messages into a single `RoundMessage` with a JSON array payload.
- `unbundle_incoming_message(msg) -> Vec<RoundMessage>` — Recovers individual messages. Handles both bundled (JSON array) and single-message formats.
- `generate_session_id(prefix) -> String` — Creates unique session IDs using `getrandom` + SHA-256. Format: `{prefix}-{32 hex chars}`.

### Authentication (`auth.rs`)

Full BRC-31 Authrite implementation ported from `bsv-auth-cloudflare`.

**Configuration:**
- `AuthConfig` — Loaded from CF Worker env via `from_env()`. Reads `SERVER_PRIVATE_KEY` secret. Falls back to `allow_unauthenticated` mode if not set (development).
- `headers` module — 7 BRC-104 header constants (`x-bsv-auth-*`).

**Core functions (all implemented):**
- `verify_or_allow(req, config) -> Result<AuthenticatedIdentity, Response>` — Main entry point called by each protected endpoint. Returns identity if authenticated, or allows through in dev mode.
- `verify_request(req, config) -> Result<AuthenticatedIdentity, AuthError>` — Full BRC-31 verification: extract BRC-104 headers, lookup session by `your_nonce`, check TTL, verify identity matches session, derive BRC-42 verification key via ECDH, verify ECDSA signature.
- `handle_initial_request(req, config) -> Result<Response>` — BRC-31 handshake (`POST /.well-known/auth`). Extracts peer identity/nonce, generates server nonce, stores session, signs response with BRC-42 derived key, returns BRC-104 headers.
- `sign_response_headers(body, req_nonce, ...) -> Vec<(String, String)>` — Generates BRC-104 auth headers for signed responses.
- `verify_agent_authorization(auth, agent_id) -> Result<(), AuthError>` — Ensures authenticated identity matches `agent_id` in request body. Dev mode (empty identity_key) allows all.
- `handle_cors_preflight() -> Result<Response>` — Returns 204 with CORS headers allowing BRC-104 auth headers.

**Session management:**
- `AuthSession` — Server-side session state: `server_nonce`, `peer_identity_key`, `peer_nonce`, `created_at`.
- `AUTH_SESSIONS` — In-memory `LazyLock<Mutex<HashMap>>`, keyed by `server_nonce`.
- `store_session()`, `get_session()`, `session_count()` — CRUD on session storage.

**Types:**
- `AuthenticatedIdentity` — Verified BRC-31 identity: `identity_key` (33-byte hex pubkey), `nonce`, `established_at`.
- `AuthError` — 6 variants: `NotAuthenticated`, `InvalidSignature(String)`, `SessionExpired`, `SessionNotFound`, `IdentityMismatch`, `VerificationError(String)`. Each maps to HTTP status (401/403/500).

### Storage (`storage.rs`)

In-memory storage using `HashMap`/`VecDeque` behind a global `LazyLock<Mutex<InnerStorage>>`. All methods are **fully implemented** with comprehensive tests. Production will migrate to Durable Object SQLite.

- `ShareStorage` — Zero-sized marker struct providing typed method access to the global `STORAGE` static.
- `ShareMetadata` — Wire-safe struct: `agent_id`, `session_id`, `share_index`, `threshold`, `parties`, `created_at`, `updated_at`, `presignature_count`.

**ShareStorage methods:**

| Method | Description |
|--------|-------------|
| `new()` | No-op constructor (in-memory impl) |
| `store_share(agent_id, share)` | Upsert encrypted share with timestamps |
| `get_share(agent_id)` | Retrieve encrypted share or `None` |
| `delete_share(agent_id)` | Cascading delete: share + presignatures |
| `list_agents()` | Return sorted list of agent IDs |
| `share_count()` | Count total shares |
| `get_share_metadata(agent_id)` | Share metadata + presignature count |
| `store_protocol_state(session_id, state)` | Persist coordinator bytes between HTTP requests |
| `get_protocol_state(session_id)` | Retrieve coordinator state |
| `delete_protocol_state(session_id)` | Clean up after ceremony completion |
| `store_presignature(agent_id, session_id, presig_id, data)` | Append to per-agent FIFO queue |
| `consume_presignature(agent_id)` | Pop oldest presignature (FIFO) |
| `presignature_count(agent_id)` | Count per-agent presignatures |
| `total_presignature_count()` | Count across all agents |
| `reset()` | Clear all storage (`#[cfg(test)]` only) |

## Protocol Flows

### DKG (4 rounds)
1. Proxy sends `POST /dkg/init` with `agent_id` and `ThresholdConfig`
2. Worker creates `DkgCoordinator` for party 0, returns bundled round 1 message
3. Proxy sends 3 more `POST /dkg/round` requests, each with the previous round's message
4. On final round: Worker stores encrypted share via `ShareStorage`, cleans up coordinator, returns `JointPublicKey`

### Signing (4 rounds without presignature)
1. Proxy sends `POST /sign/init` with `agent_id`, `session_id`, `sighash` (32-byte hex)
2. Worker loads share, creates `SigningCoordinator` for party 0, returns round 1 message
3. Proxy sends up to 3 more `POST /sign/round` requests
4. On completion: Worker returns ECDSA `SigningResult`, cleans up coordinator

### Presigning (3 offline rounds)
1. Proxy sends `POST /presign/init` with `agent_id`, `session_id`, `count` (1-100)
2. Worker creates `PresigningManager`, returns round 1 messages
3. Two more `POST /presign/round` exchanges complete the protocol
4. Presignatures stored in manager's pool; session cleaned up

### Partial ECDH (1 round)
1. Proxy sends `POST /ecdh` with `agent_id` and `counterparty_pub` (33-byte hex)
2. Worker loads share, computes `counterparty_pub * share_scalar`
3. Returns partial ECDH point (33-byte hex)
4. Used for distributed BRC-42 key derivation (Self_/Other counterparty types)

### BRC-31 Handshake
1. Proxy sends `POST /.well-known/auth` with BRC-104 headers (`identity-key`, `nonce`)
2. Worker generates server nonce, stores `AuthSession`, signs response with BRC-42 derived key
3. Returns BRC-104 response headers (server identity, nonce, signature)
4. Subsequent requests include `your-nonce` (server's nonce) for session lookup

## Storage Model

Three logical stores backed by `HashMap`/`VecDeque` in a global `Mutex<InnerStorage>`:

- **Shares** — `HashMap<String, StoredShare>` keyed by `agent_id`. Each entry holds `EncryptedShare`, `created_at`, `updated_at`.
- **Protocol state** — `HashMap<String, Vec<u8>>` keyed by `session_id`. Serialized coordinator state persisted between HTTP round-trips.
- **Presignatures** — `HashMap<String, VecDeque<StoredPresignature>>` keyed by `agent_id`. FIFO queue per agent.

Data is lost on Worker restart (acceptable for development). Production migration target: DO SQLite with the same 3-table schema.

## Security Model

- All mutation endpoints require BRC-31 Authrite mutual authentication (via `verify_or_allow()` in each route handler)
- `verify_agent_authorization()` prevents agent A from accessing agent B's share
- Full BRC-31 verification chain: extract headers → lookup session → check TTL (1h) → verify identity → ECDH + BRC-42 derive verification key → ECDSA verify
- Shares stored encrypted with AES-256-GCM (BRC-42 derived keys) — Worker never sees plaintext
- Development mode: when `SERVER_PRIVATE_KEY` env is absent, auth is bypassed (`allow_unauthenticated`)
- CORS preflight support for browser-context proxies
- BRC-104 response signing via `sign_response_headers()`
- Session nonces prevent replay attacks; BRC-42 derivation binds signatures to sessions

## Dependencies

| Crate | Purpose |
|-------|---------|
| `bsv-mpc-core` | Core MPC types + coordinators (`DkgCoordinator`, `SigningCoordinator`, `PresigningManager`, `ecdh`) |
| `bsv` | BSV primitives (`PrivateKey`, `PublicKey`, `Signature`, `KeyDeriver`) for BRC-31 auth |
| `worker` 0.7 | CF Worker SDK (Router, Request, Response, Env, Context, Durable Objects) |
| `serde` / `serde_json` | JSON serialization for request/response types |
| `sha2` | SHA-256 for signing data and session ID generation |
| `thiserror` | `AuthError` derive macro |
| `chrono` | Timestamp handling for share metadata and session TTL |
| `getrandom` (`js` feature) | Entropy source in WASM — required for V8 isolate |
| `hex` | Hex encoding/decoding for keys, signatures, sighashes |
| `base64` | Base64 encoding for auth nonces |

## WASM Constraints

- Target: `wasm32-unknown-unknown` (crate-type `cdylib`)
- Must use `getrandom/js` for entropy (no OS random in V8 isolate)
- `bsv-mpc-core` must use `num-bigint` backend for cggmp24 (not `rug` — LGPL and doesn't compile to WASM)
- CF Worker memory limit: 128MB
- Live coordinators kept in global statics between requests; data lost on Worker restart

## Test Coverage

36 unit tests across all modules:
- `api.rs` (14 tests) — Session ID generation, message bundling/unbundling roundtrips, health response shape
- `auth.rs` (13 tests) — BRC-42 key derivation matching POC 8, ECDH commutativity, sign/verify roundtrip, wrong nonce/key rejection, session storage, nonce generation, auth error status codes, agent authorization, BRC-104 header constants, DER signature roundtrip
- `storage.rs` (9 tests) — Share CRUD, cascading delete, list/count, metadata, protocol state roundtrip, presignature FIFO consumption, total count, upsert

## Related

- [Root CLAUDE.md](../../../CLAUDE.md) — Project-wide architecture, conventions, and decisions
- [bsv-mpc-core](../../bsv-mpc-core/src/) — Core MPC protocol types and coordinators used by this crate
- [bsv-mpc-proxy](../../bsv-mpc-proxy/src/) — The other half: MPC Signing Proxy that holds share_B and calls this Worker
- [bsv-mpc-service](../../bsv-mpc-service/src/) — Standalone KSS alternative (same API, in-memory storage)
