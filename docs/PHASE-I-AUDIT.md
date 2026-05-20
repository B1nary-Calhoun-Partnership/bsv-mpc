# Phase I Audit — deployed `bsv-mpc-worker` CF cosigner (G+H wired, DO-SQLite-persisted)

> Tracking issue: **bsv-mpc#4**. Parent: #2 (v1.0 umbrella). Predecessor: #3 (Phase H, Step 4 closed).
> Step 1 (Investigate) — DONE (3-agent swarm, 2026-05-20). This doc is Step 2 (Audit).

## 0. Goal

Make the **deployed** `bsv-mpc-worker` Cloudflare Worker a first-class MPC
cosigner: it holds `share_A`, drives CGGMP'24 DKG/signing ceremonies over
the **Phase H Socket.IO + BRC-103 MessageBox transport** (the spec-normative
§06 cross-cosigner channel), and persists the share **durably** on Durable
Object SQLite. This is the **wasm32 runtime home** for the transport built
in Phase H — it satisfies the Phase H merge-gate items deferred here
(#3: wasm32-runtime test, deployed test Worker). Merge gate: a real
mainnet TXID co-signed by the *deployed* worker, shape-matching G-5d.

## 1. Current state (verified)

- **Protocol:** HTTP/JSON + BRC-31 only. `bsv-mpc-worker/src/api.rs` runs
  DKG/signing as HTTP request/response against `bsv-mpc-core` coordinators
  held in `static LazyLock<Mutex<HashMap<..>>>` between requests. No
  outbound WS / relay path.
- **Storage:** in-memory — `storage.rs:30` `static STORAGE: LazyLock<Mutex<InnerStorage>>`
  (HashMaps; "lost on Worker restart"). The `MpcStorage` DO (`lib.rs:64`) is an
  **unrouted stub** (`fetch` returns `{"status":"ok"}`); the BRC-100 KSS
  handlers hit the in-memory static, not the DO.
- **Identity:** `SERVER_PRIVATE_KEY` handled in `auth.rs` (`AuthConfig::from_env`),
  not yet wired to a DO.
- **Deploy:** `worker-build --release` → `build/worker/shim.mjs` → `wrangler deploy`;
  `[[durable_objects.bindings]] MPC_STORAGE/MpcStorage`; `[[migrations]] new_classes`.
  Calhoun **dev-a3e** account. `wrangler.toml` gitignored; `wrangler.toml.example` committed.

## 2. What we can lift vs must build

**Reusable (wasm32-compatible, verified):**
- `bsv-mpc-core` `DkgCoordinator` / `SigningCoordinator` + the sync
  `drive_inline()` kernel (`dkg.rs:760`) — no tokio, proven on wasm32
  (`bsv-mpc-core/tests/wasm32_dkg.rs`). The worker already calls these.
- Envelope glue `wrap_round_message` / `unwrap_envelope_to_round_message`,
  `MessageEnvelope`, canonical `ExecutionId` — target-agnostic.
- The Phase H wasm32 transport: `bsv-mpc-messagebox::transport_wasm::{WsHandle, WsSender}`
  + upstream `bsv::auth::{SocketIoTransport, run_dispatch, install_app_event_listener, Peer, build_envelope_payload}`.
- **poc17's DO pattern** (recoverable from `7a1f8e3`): per-identity
  `#[durable_object]`, outbound WS dialed via `transport_wasm` +
  `spawn_local(run_dispatch(..))`, identity loaded from `SERVER_PRIVATE_KEY`
  every wake, `id_from_name("<cosigner-id>")` keying, hibernation-survival
  harness (`instance_constructed_at_ms` + deploy + idle + curl-pair).

**NOT reusable → Phase I builds:**
- Native `MessageBoxListener` / `DkgHandler` / `SigningHandler` — tokio +
  `spawn_blocking` + native-only `MessageBoxClient`. The worker needs a
  **wasm32 cosigner loop** instead.
- `MessageBoxClient` (native-only). The worker must send + receive over the
  Socket.IO channel directly (see §3.2).
- Durable share persistence — **not done anywhere** (worker in-memory; poc17
  only persisted ~200-byte telemetry via KV).

## 3. Architecture

### 3.1 Topology — per-identity DO cosigner over the relay

One `#[durable_object]` **per cosigner identity** (`id_from_name`), lifting
poc17's `EngineIoSessionDo`. The DO holds `share_A` (in DO SQLite), dials an
outbound Socket.IO + BRC-103 WS to the relay, joins its DKG/sign rooms, and
drives ceremonies with the *other* party over the relay.

**Topology (OQ-I1 RESOLVED → relay replaces proxy↔KSS HTTP):** the relay is
the signing channel between the proxy's party (`share_B`) and the worker's
party (`share_A`). The HTTP `bridge.rs` signing path is retired; both
parties are spec-normative §06 relay cosigners. The **proxy** (native)
drives ceremonies via the native `MessageBoxClient` + the `bsv-mpc-service`
handler pattern (`MessageBoxListener` + `DkgHandler`/`SigningHandler`); the
**worker** (wasm32, deployed) drives them via the §3.2 wasm32 cosigner loop.
Sequencing within Phase I: the deployed-worker substrate (Step 3 POC) is
topology-agnostic, so it lands first; the proxy `bridge.rs` migration +
the worker cosigner loop land in Step 4; the merge gate is proxy↔deployed-
worker over the relay.

### 3.2 wasm32 cosigner loop

Per ceremony (DKG or sign), inside the DO:
1. `transport_wasm::polling_handshake` → `WsHandle::open_and_upgrade` →
   Socket.IO `CONNECT`.
2. `SocketIoTransport::new(ws_sender)` + `Peer::new(ProtoWallet from SERVER_PRIVATE_KEY)`;
   `peer.start()`; `install_app_event_listener(&peer)`; `spawn_local(run_dispatch(ws, sink, cb))`.
3. First `peer.to_peer(build_envelope_payload("joinRoom", roomId), None, _)` →
   completes the BRC-103 handshake + joins the room; learn the server
   identity from the first inbound General; reuse `Some(server_id)` after.
4. **Inbound** round-messages arrive as `sendMessage-{roomId}` Generals →
   `AppEvent` → `unwrap_envelope_to_round_message` → feed the
   `DkgCoordinator`/`SigningCoordinator` (`process_round`).
5. **Outbound** round-messages: `wrap_round_message(..)` →
   `build_envelope_payload("sendMessage", {messageBox, message:{messageId,
   recipient, body}})` → `peer.to_peer(payload, Some(server_id), _)`. The
   relay routes to the recipient's room. **(Send rides the same WS — the
   worker has no native HTTP `MessageBoxClient`; this send path is the one
   proven in H-4.3's envelope round-trip.)**
6. On `Complete(result)`: DKG → persist `share_A` to DO SQLite; signing →
   return the `SigningResult`.

This is a thin, sync glue layer over the already-wasm32-proven coordinators.
Candidate: factor a shared, wasm32-safe `RoundMessage ↔ AppEvent` codec so
native + wasm32 share it.

### 3.3 Persistence — DO SQLite (FUND-SAFETY GATE)

`share_A` (and protocol/presig state) persist to the DO's **own co-located
SQLite** (`state.storage().sql().exec(..)`, in `worker` 0.7.5) — NOT D1/R2/KV.
Rationale (see issue #4 + the storage discussion): co-located (zero-latency
on the signing hot path), strongly consistent + single-writer (matches the
DO model), survives hibernation/eviction, and **per-agent isolation** (one
DO = one cosigner's share = smaller blast radius than a shared D1).

- Schema (3 tables, mirrors the in-memory model): `shares(agent_id PK,
  ciphertext, nonce, session_id, share_index, threshold, parties,
  created_at, updated_at)`, `protocol_state(session_id PK, blob)`,
  `presignatures(id PK, agent_id, session_id, data, created_at)`.
- **Encrypted at rest:** shares stay AES-256-GCM (already); the store holds
  ciphertext only; decryption capability tied to the `SERVER_PRIVATE_KEY`
  CF secret. Leaked DO storage = useless ciphertext; only `share_A`, never
  the full key.
- **R2 (optional, secondary):** append-only audit log (BRC-18 participation
  proofs / signing trail) as WORM blobs. Not the hot-path share.
- **Migration:** a SQLite-backed DO requires `new_sqlite_classes = [..]` in
  `[[migrations]]` (NOT `new_classes`) — a new migration tag for the Phase I
  DO class.

### 3.4 Hibernation & liveness

CF-confirmed: **outbound client WebSockets do not hibernate** ("Outgoing
WebSockets do not hibernate"); a DO is evicted after ~70–140s idle and loses
in-memory state (incl. the live WS). So:
- **Strategy 1 — re-handshake on wake** (poc17-proven): the share is durable
  (SQLite); on wake the DO reloads identity + share, re-dials the WS, fresh
  Engine.IO sid + BRC-103 handshake, re-joins rooms. Ceremony coordinator
  state is **ephemeral** — but an *active* ceremony has continuous WS traffic
  that keeps the DO warm, so mid-ceremony eviction is unlikely; if it does
  happen the ceremony fails + retries (no fund loss, share is safe).
- **Liveness/wake trigger (OQ-I2 RESOLVED → wake-on-HTTP + Alarm reconnect):**
  the proxy/initiator pokes the worker over HTTP → the DO wakes, dials the
  relay, and drives the ceremony (deterministic, no keep-warm cost). A
  periodic DO Alarm provides reconnect resilience (re-establish the WS if it
  dropped). Alarms can lag up to ~1 min, so they are the resilience layer,
  not the primary trigger.

### 3.5 Deploy / secrets / identity

`worker-build --release` + `wrangler deploy` on dev-a3e; `SERVER_PRIVATE_KEY`
via `wrangler secret put` (the cosigner's stable identity, loaded every
wake — never in-memory-only). New `[[migrations]]` tag with
`new_sqlite_classes` for the Phase I DO. `RELAY_URL` var = the live relay.

## 4. Steps (5-step discipline)

- [x] **Step 1 — Investigate** (3-agent swarm, 2026-05-20).
- [→] **Step 2 — Audit doc** (this file).
- [ ] **Step 3 — POC** — deployed worker: outbound Socket.IO + BRC-103 +
  envelope round-trip + forced-hibernation reconnect against the live relay
  (lift poc17's harness; satisfies #3's deferred wasm32-runtime/deployed-worker).
  + DO SQLite share persist/reload across a forced eviction.
- [ ] **Step 4 — Implement** — (a) bump `worker` crate to 0.8.x; (b) worker
  wasm32 DO cosigner loop (§3.2) + DO SQLite storage (§3.3, replace the
  in-memory `STORAGE` static) + wake-on-HTTP/Alarm (§3.4) + route KSS
  handlers through the DO; (c) **migrate `bsv-mpc-proxy` `bridge.rs`** signing/
  DKG path from HTTP to the MessageBox relay transport (native
  `MessageBoxClient` + the `bsv-mpc-service` handler pattern) — retiring the
  HTTP `/sign|/dkg` round-trips (OQ-I1).
- [ ] **Step 5 — Quality gate / merge** — see §6.

## 5. 🔒 Fund-safety gate (non-negotiable)

No deployed worker may hold a **funded** `share_A` on in-memory storage.
Before any mainnet sats touch a worker-held joint key:
- [ ] `share_A` persisted to DO SQLite, survives forced eviction (reload-and-sign proven).
- [ ] Multi-round DKG protocol state persisted across requests (CF globals are not request-stable).
- [ ] Ciphertext-only at rest; decryption tied to `SERVER_PRIVATE_KEY`.

## 6. Merge gate

- [ ] **Deployed-cosigner real-sats mainnet TXID** — 2-of-2 DKG + sign +
  broadcast with the **proxy's party (native, over the relay) co-signing
  with the *deployed* CF Worker cosigner** (OQ-I1 topology), shape-matching
  G-5d (`442bd391…`: DER + `SIGHASH_ALL|FORKID`, joint P2PKH, low-s,
  pre-flight verify).
- [ ] wasm32 runtime proof of the transport (Phase H #39/#40 satisfied here).
- [ ] `cargo build --workspace --all-targets` + clippy `-D warnings` + fmt clean; CI green.

## 7. Decisions (resolved 2026-05-20)

- **OQ-I1 — cross-cosigner topology: RESOLVED → relay REPLACES proxy↔KSS HTTP.**
  The relay becomes the signing channel between the proxy's party (holds
  `share_B`) and the worker's party (holds `share_A`); the HTTP `bridge.rs`
  signing path (`/sign/init`, `/sign/round`, `/dkg/*`) is retired. Both
  parties are spec-normative §06 relay cosigners. **Scope implication:**
  Phase I modifies `bsv-mpc-proxy` too — its signing/DKG path migrates from
  HTTP to the MessageBox transport (native `MessageBoxClient` + the
  service's handler pattern), in addition to the wasm32 worker cosigner.
- **OQ-I2 — wake/liveness: RESOLVED → wake-on-HTTP + Alarm reconnect.** The
  initiator pokes the worker over HTTP → DO wakes, dials the relay, drives
  the ceremony; a periodic DO Alarm provides reconnect resilience.
- **OQ-I3 — `worker` crate: RESOLVED → bump to 0.8.x** (current; SQLite +
  alarms + outbound WS confirmed). Migrate the worker crate off 0.7.5.
- **OQ-I4 — second cosigner: the proxy's party** (native, via the migrated
  MessageBox path) co-signs with the deployed worker for the merge gate.

## 8. Risks

| | Risk | Mitigation |
|---|---|---|
| R1 | Mid-ceremony hibernation drops coordinator state | Active WS traffic keeps DO warm; ceremonies are short (DKG ~19s, sign ~6s); failure → retry, share is durable. Persist protocol_state per round as belt-and-suspenders. |
| R2 | Outbound WS can't survive eviction | Accepted (CF constraint); Strategy-1 reconnect + share durable. poc17-proven. |
| R3 | DO SQLite first use in this codebase | worker 0.7.5 exposes `sql()`; POC (Step 3) de-risks with a persist/reload-across-eviction gate before any funds. |
| R4 | Alarm delay up to ~1 min | Don't build tight liveness SLAs on alarms; wake-on-HTTP is the primary path. |
| R5 | `SERVER_PRIVATE_KEY` rotation | Stable identity (no runtime rotation in CF); documented. |

## 9. Key facts / citations

- Coordinators wasm32-ready: `bsv-mpc-core/src/dkg.rs:760` (`drive_inline`),
  `tests/wasm32_dkg.rs`. Native handlers tokio-bound: `bsv-mpc-service/src/{messagebox,dkg_handler,signing_handler}.rs`.
- poc17 DO recovered: `git show 7a1f8e3:poc/poc17-cf-outbound-ws/src/{worker_do.rs,lib.rs}` (+ `:wrangler.example.toml`).
- Worker today: `bsv-mpc-worker/src/{lib.rs:64 (stub DO), api.rs (HTTP coordinators), storage.rs:30 (in-memory)}`.
- worker 0.7.5 storage: `Storage::sql() -> SqlStorage` (`durable.rs:569`, `sql.rs:180`); KV `get/put`; alarms `set_alarm/get_alarm/delete_alarm`.
- CF: outbound WS don't hibernate ([DO WebSockets](https://developers.cloudflare.com/durable-objects/best-practices/websockets/)); SQLite-backed DO GA 2025-04-07, 10GB/DO, 2MB row ([SQLite storage](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/), [limits](https://developers.cloudflare.com/durable-objects/platform/limits/)); Alarms ([API](https://developers.cloudflare.com/durable-objects/api/alarms/)).
