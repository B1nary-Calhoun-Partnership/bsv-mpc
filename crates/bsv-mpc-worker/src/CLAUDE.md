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
- `fetch()` — `#[event(fetch)]` handler. A thin forwarder: routes via `worker::Router` and forwards every route to the per-identity `CosignerSessionDo` (`poc::forward_to_cosigner_do`). Auth runs INSIDE that DO: `CosignerSessionDo::fetch` calls `auth::process_request_auth()` (canonical BRC-31, #8 leg 2) for the handshake + every authed route before delegating to the handler.

### Request/Response Types (`api.rs`)

| Type | Direction | Endpoint |
|------|-----------|----------|
| `DkgInitRequest` | Request | `POST /dkg/init` |
| `DkgInitResponse` | Response | `POST /dkg/init` |
| `DkgRoundRequest` | Request | `POST /dkg/round` |
| `DkgRoundResponse` | Response | `POST /dkg/round` |
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

### Authentication (`auth.rs`) — CANONICAL BRC-31 wire (#8 leg 2)

The worker DO verifies the **canonical BRC-31 wire** via the
`bsv-middleware-cloudflare` server middleware (we maintain it; consumed via a
pinned git rev). This replaced the old custom "sign `SHA-256(nonce)`" profile:
the leg-1 proxy now emits canonical-wire requests, so the DO must verify the
canonical wire to match. The proven wire is exactly what
`bsv-mpc-core/tests/conformance_07_brc31_auth.rs` produces.

**Where auth runs:** INSIDE the per-identity `CosignerSessionDo` (NOT the
entrypoint), backed by that DO's co-located SQLite session store. The
handshake-write and the per-request read hit the same store regardless of which
entrypoint isolate served them (the auth-session-isolate fix, #5). Sessions stay
in DO-SQLite (NOT KV).

**Core functions:**
- `process_request_auth(req, storage, env) -> Result<AuthOutcome>` — the single
  DO-side entry for BOTH the handshake (`/.well-known/auth`) and the per-request
  verify on authed routes. Clones the request (so the handler keeps the
  body-bearing original), runs the canonical
  `process_auth_with_storage(req, &DoSqlStorage, &options)`, returns
  `AuthOutcome::Respond(resp)` (handshake / auth error) or
  `AuthOutcome::Proceed { caller, request }`. On `Authenticated` it enforces (a)
  §07 identity binding (the `x-bsv-auth-identity-key` header == the
  session-bound identity → else 403) and (b) §07.1 replay (a reused
  `(your_nonce, nonce)` pair → 401).
- `auth_options(env)` — builds `AuthMiddlewareOptions`: `SERVER_PRIVATE_KEY` set
  ⇒ enforced; unset ⇒ `allow_unauthenticated` (dev mode).
- `verify_agent_authorization(caller, agent_id) -> Result<(), String>` — compat
  helper; dev mode (no caller) allows all. The live owner-authz path is
  `api::authz_owner_or_reject` (checks the share's bound `owner_identity` BEFORE
  share material loads).
- `handle_cors_preflight()` — delegates to the middleware (canonical header set).
- `headers` module — 8 BRC-104 header constants (`x-bsv-auth-*`).

**Session storage (canonical):** `DoSqlStorage` implements
`bsv_middleware_cloudflare::SessionStorage` (async, `?Send`) over its
`mpc_canonical_sessions` table (full `StoredSession` as JSON). §07.1 replay uses
`mpc_consumed_nonces` (TTL-swept, PK = `(session_nonce, request_nonce)`).

**Legacy (compat only):** `AuthSession` + `AuthSessionStore` + the
`mpc_auth_sessions` table are retained ONLY for the `/poc/auth-session-roundtrip`
deterministic-proof route; the canonical path never touches them.

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

### Signing (relay-only since #13)
The legacy 4-round HTTP `/sign/{init,round}` path was retired. Online signing
runs over the MessageBox relay: the cosigner consumes a correlated
`Presignature_A` from its DO pool and issues its partial over the authed
`/sign-relay` route (`poc.rs::handle_prod_sign_relay`), which the proxy combines
into the final ECDSA signature. The DKG share is only used during presig
generation; online signing consumes presigs.

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
