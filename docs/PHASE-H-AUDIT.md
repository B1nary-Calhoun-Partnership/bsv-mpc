# Phase H Audit — `bsv-mpc-messagebox` wasm32 client + CF Durable Object outbound WS

> Investigation + design doc for Phase H of the v1.0 CF-native cosigner
> plan in [`NEXT-STEPS.md`](NEXT-STEPS.md). Written 2026-05-19, lands on
> `main` BEFORE the POC step (G-style 5-step workflow). Every claim has
> a `file:line` citation; if a claim is unsupported, it's flagged with
> "needs verification" inline.
>
> **Status:** draft 1 → **patched 2026-05-19** (twice same-day):
>   1. §2.5 superseded by §2.5b — server exposes Socket.IO + BRC-103
>      alongside raw-WS; the wasm32 client uses Socket.IO + BRC-103,
>      not the three raw-WS workarounds. Server is unchanged.
>   2. §11.2 revised — pure Rust+WASM Plan A leverages the existing
>      Calhoun-owned `engineio/codec.rs` (613 LOC, MIT, byte-identical
>      in both Rust servers); JS-bundle of `socket.io-client@4.x` is
>      Plan B fallback only; `rust-socketio` wasm32 upstream PR is a
>      post-merge ecosystem follow-up, not on the Phase H critical
>      path.

## TL;DR

Three interlocking design decisions for Phase H:

1. **Substrate: Socket.IO + BRC-103** (see §2.5b — supersedes the
   original §2.5 raw-WS+BRC-31 workarounds). Use the same
   browser-compatible path that the canonical TS `@bsv/message-box-client`
   v2.0.7 uses against the same servers — `socket.io-client`
   transport with BRC-103 mutual-auth post-handshake over the
   `authMessage` event channel. **Verified live**: the Calhoun
   production relay (`https://rust-message-box.dev-a3e.workers.dev`,
   `wrangler.toml` in `~/bsv/rust-message-box/`) exposes `/socket.io/`
   alongside `/ws` — a probe `GET /socket.io/?EIO=4&transport=polling`
   returns Engine.IO handshake JSON with a session id and the
   `["websocket"]` upgrade list. No server change is needed; we conform
   to the canonical TS via Path A. (Original raw-WS analysis preserved
   in §1.1 + §2.5 for the reasoning trail; both are SUPERSEDED.)

2. **Hibernation contract: outbound WS does NOT survive DO hibernation —
   reconnect-on-wake with `/listMessages` backfill is mandatory.** The
   `workers-rs` 0.8 `serialize_attachment`/`deserialize_attachment`
   pattern preserves *application* state across hibernate→wake but not
   the WS connection itself. The existing native client
   `crates/bsv-mpc-messagebox/src/ws.rs` already implements the
   canonical recover flow per MPC-Spec §06.12 (exponential backoff
   1s→30s cap, drain `/listMessages` BEFORE re-subscribing); the Phase
   H client adopts the same loop on wasm32, with one extra step —
   `MessageBoxAuth::sign_ws_upgrade()` re-runs on every reconnect to
   refresh the BRC-31 session.

3. **Wrap, don't rewrite: cfg-gate within the existing
   `bsv-mpc-messagebox` crate.** ~95% of the code (`client.rs`,
   `http.rs`, `auth.rs`, `types.rs`, `wire.rs`) is runtime-agnostic —
   tokio coupling is concentrated in `ws.rs` (uses
   `tokio_tungstenite::connect_async` + `tokio::net::TcpStream`) plus
   a small number of `tokio::spawn` sites in `client.rs`. Split `ws.rs`
   into `ws_native.rs` + `ws_wasm.rs` behind
   `#[cfg(target_arch = "wasm32")]`, replace `tokio::spawn` with a
   target-conditional spawn helper, swap the few `tokio::time::timeout`
   sites for `time`-feature-gated calls that work on both targets.
   **Diverges from the original NEXT-STEPS.md plan** that prescribed a
   separate `bsv-mpc-messagebox-worker` sibling crate — see §2.2 for
   the case.

Quality-gate target ([§7](#7-phase-h-quality-gate-step-5)): existing
Phase A-F mainnet TXID shape preserved on the native path + new
deployed-Worker forced-hibernation round-trip green + canonical CBOR
envelope byte-identical over the wasm32 path against the live Calhoun
relay.

## 1. Investigation findings (Phase H Step 1)

Three parallel Explore agents surveyed independently on 2026-05-19. Raw
reports preserved in the session transcript; the empirical headlines
are below with file:line citations.

### 1.1 Outbound WS substrate in CF Workers + wasm32 (H-1a)

**Survey conclusion: zero Rust prior art for DO-as-outbound-WS-client
anywhere in `~/bsv/`.** Four candidate substrates examined:

**(a) `web_sys::WebSocket` via `wasm-bindgen`** — recommended primary.
- `wasm-bindgen = "0.2"` already a workspace dep
  (`crates/bsv-mpc-worker/Cargo.toml:18`).
- `web-sys` exposes `WebSocket`, `MessageEvent`, `CloseEvent` types via
  feature flags; the canonical browser-target API.
- **Empirical unknown** (POC will burn): does the CF Worker / DO
  runtime expose `globalThis.WebSocket` to a WASM module's
  `wasm-bindgen` glue? Browser-target wasm32 works by construction;
  Cloudflare's V8 isolate is browser-class but their docs do not
  explicitly catalog `WebSocket` as a DO-available global. Zero
  precedent in `~/bsv/`.

**(b) `workers-rs` 0.7 / 0.8 outbound API** — not present.
- `crates/bsv-mpc-worker/Cargo.toml:18`: `worker = "0.7"`. Confirmed
  no public outbound-WS API.
- `bsv-messagebox-cloudflare-public/Cargo.toml:10`: `worker = { version = "0.8", features = ["d1"] }`
  (resolves to 0.8.3 per its Cargo.lock). Still no outbound-WS API
  surfaced; only `WebSocketPair::new()` for accepting inbound
  upgrades (`bsv-messagebox-cloudflare-public/src/message_hub.rs:416`).
- Phase G audit §1.3 conclusion (no outbound-WS in 0.7) extends to 0.8.

**(c) `fetch(url, { Upgrade: 'websocket' })` outbound pattern** — exists
in JS Workers, not in Rust SDK.
- Cloudflare's JS runtime supports it; useful for `worker → worker` WS
  bridges. No corresponding Rust binding in `workers-rs` 0.7/0.8.
- Not feasible to use directly from Rust without upstream work.

**(d) Paired JS sidecar Worker bridging** — viable fall-back.
- A separate TypeScript Worker accepts JSON-framed requests from the
  Rust DO, opens the outbound WS in JS-land, relays frames back.
- ~300-500 LOC TypeScript + a stable JSON contract.
- Zero precedent in `~/bsv/`, but architecturally sound; the canonical
  v8-isolate→v8-isolate communication is service bindings.

**Recommendation:** substrate (a); POC step burns the
`globalThis.WebSocket` accessibility unknown; substrate (d) is the
documented fall-back in the audit's "if A fails, do D" path.

**Reference:** raw H-1a agent transcript in session log.

### 1.2 DO hibernation + outbound-WS lifetime (H-1b)

**INBOUND-WS DOs survive hibernation cleanly via
`workers-rs 0.8`'s `serialize_attachment` / `deserialize_attachment`
contract.** Canonical example:
`~/bsv/bsv-messagebox-cloudflare-public/src/message_hub.rs:236-256` +
`:393-445`. Per-socket application state is serialized into the WS
attachment slot; survives hibernate→wake unchanged; recovered via
`deserialize_attachment` on any later event handler. The
`WebSocketRequestResponsePair::new("ping", "pong")` at
`message_hub.rs:251` is set once at DO construction and persists across
hibernation — that's why `bsv-mpc-messagebox/src/ws.rs:67-70`'s
text-frame `"ping"` heartbeat un-hibernates *nothing*.

**OUTBOUND-WS has NO hibernation contract.**
- The `web_sys::WebSocket` (or any client-side WS handle) is a
  non-serializable JavaScript object reference; the V8 isolate cannot
  preserve it across hibernate→wake.
- Connection is force-closed (or times out) when the DO hibernates.
- On wake, the DO MUST re-open the WS. Application state (subscribed
  rooms, last-seen sequence) survives via the standard
  `serialize_attachment` pattern.

**Reconnect+backfill flow (already implemented natively):**
`crates/bsv-mpc-messagebox/src/ws.rs:221-274` — the outer reconnect
loop:

1. On disconnect / error: log, sleep with exponential backoff
   (initial 1s, double, cap 30s; `RECONNECT_BACKOFF_INITIAL` at
   `ws.rs:74`, `_CAP` at `ws.rs:77`).
2. **Before reopening WS:** drain `/listMessages` for each subscribed
   box (`ws.rs:239-241`). Per MPC-Spec §06.12: "after reconnection, the
   receiver MUST re-fetch missed messages via `/listMessages`" —
   prevents the live-push-arrives-before-backfill race.
3. Refresh the BRC-31 session (`MessageBoxAuth::sign_ws_upgrade()` is
   re-called per reconnect — see `ws.rs:407-408` calling
   `auth.rs:46-47`).
4. Open new WS, await server `connected` greeting, emit `joinRoom` per
   box.

**Three risks the audit must explicitly call out:**

1. **Attachment capacity race** — the DO's serializable attachment is
   capped (~2KB per the inbound `SocketAttachment` size at ~70 bytes ×
   20 rooms ≈ 1.4KB). If Phase H also persists per-room MPC ceremony
   state in the attachment, it can hit the cap. **Mitigation:** keep
   the attachment to *subscription state only* (room ids, last-seen
   sequence); push ceremony state to DO `state.storage` (D1 / SQLite).
2. **Backfill window explosion under hibernation thrash** — if the DO
   hibernates and wakes repeatedly during a long-running ceremony, each
   wake triggers `/listMessages` across N boxes. **Mitigation:**
   track `last_synced_at` per room; paginate via server-assigned
   `message_id` ranges (`ws.rs:340-365`-style).
3. **Silent stale-auth signing on reconnect** — the BRC-31 session must
   be refreshed every reconnect. The native code does this at
   `ws.rs:265` via `auth.refresh_ws_session()`-equivalent (calls back
   into `MessageBoxAuth::sign_ws_upgrade`). If the Phase H wasm32 path
   forgets to invoke this, the reconnected WS uses a stale session and
   the server returns 401 on first message. **Mitigation:** the
   shared driver loop in `ws.rs` (which is being split — see §2)
   already wraps this; both `ws_native.rs` and `ws_wasm.rs` MUST call
   it before each reconnect attempt.

**Reference:** raw H-1b agent transcript in session log.

### 1.3 Wire conformance vs existing native Rust client (H-1c)

The canonical wire is `@bsv/message-box-client` v2.0.7 at
`~/bsv/message-box-client/src/MessageBoxClient.ts`. **Path A**: the
Rust implementation conforms to the TS, never the inverse, per
[`feedback_canonical_ts_immutable`].

**Endpoint inventory (existing native Rust mirror is line-by-line
faithful for the MPC use case):**

| TS method | Wire endpoint | Native Rust mirror | Status |
|---|---|---|---|
| `sendMessage` | `POST /sendMessage` | `http.rs:30-37` + `client.rs:117-160` | ✓ mirrors |
| `listMessages` | `POST /listMessages` | `http.rs:40-49` (`list_messages`) | ✓ mirrors |
| `acknowledgeMessage` | `POST /acknowledgeMessage` | `http.rs:52-61` | ✓ mirrors |
| `subscribe` (joinRoom + listen) | `WS /ws` + `{event: "joinRoom"}` | `ws.rs:154-196` + `client.rs:172-181` | ✓ mirrors |
| `joinRoom` (frame) | `{event: "joinRoom"}` text frame | `ws.rs:370-396` | ✓ mirrors |
| `leaveRoom` (frame) | `{event: "leaveRoom"}` text frame | `ws.rs:485-517` (shutdown path) | ✓ mirrors |
| `sendLiveMessage` (WS frame `{event: "sendMessage"}`) | WS-out via existing socket | **not implemented** | gap |

**Gaps the Phase H crate inherits (intentional, not blockers):**

- `sendLiveMessage` (WS-out path; native uses HTTP `sendMessage`
  exclusively). MPC ceremonies are fine with HTTP send + WS receive —
  the canonical wire only mandates the receive-side WS per §06.4.
  Phase H may add an extension later if profile-edge benchmarks show
  the round-trip benefit; out of scope for the audit.
- `permission`/`fee` auto-attachment (TS `sendMessage({..., checkPermissions: true})`).
  MPC ceremonies use stable zero-fee boxes; not needed.
- Multi-recipient broadcast helper. MPC unicasts per §05.4.7.

**BRC-31 handshake on WS upgrade:**

- TS: `AuthSocketClient` builds the upgrade GET, signs it with BRC-104
  `SimplifiedFetchTransport` headers via the wallet identity key
  (`MessageBoxClient.ts:332`).
- Rust: `MessageBoxAuth::sign_ws_upgrade()` at `auth.rs:46-47` runs a
  one-shot `/.well-known/auth` initialRequest/initialResponse exchange
  via `reqwest`, caches the resulting Session, then signs the upgrade
  GET by hand with the 7 BRC-31 headers. Called by `ws.rs:407-408`
  before each (re)connect.
- **One round-trip per (re)connect** — unchanged in Phase H. No
  per-frame signing; the upgrade's BRC-31 binds the channel.

**Reference:** raw H-1c agent transcript in session log.

## 2. Design direction A — Wrap-don't-rewrite, cfg-gate within `bsv-mpc-messagebox`

### 2.1 Target shape

Within the existing `bsv-mpc-messagebox` crate:

```
crates/bsv-mpc-messagebox/src/
  auth.rs          # unchanged (runtime-agnostic — BRC-31 + Peer wrapping)
  client.rs        # ~95% unchanged (spawn macro replaces tokio::spawn)
  error.rs         # unchanged
  http.rs          # tiny tweak — replace tokio::time::timeout call with a
                   # cfg-target_arch spawn shim if the time feature path
                   # diverges (see §2.3)
  types.rs         # unchanged
  wire.rs          # unchanged
  ws.rs            # SPLIT — see below
  ws_native.rs     # NEW — current ws.rs renamed; #[cfg(not(target_arch="wasm32"))]
  ws_wasm.rs       # NEW — web_sys::WebSocket implementation; #[cfg(target_arch="wasm32")]
  spawn.rs         # NEW — tiny module exposing `spawn(fut)` that dispatches
                   # to tokio::spawn on native, wasm_bindgen_futures::spawn_local
                   # on wasm32. ~20 LOC.
```

`lib.rs` re-exports stay identical — `subscribe()`, `WsSubscription`,
`InboundEnvelopeEvent`, `InboundVia` all unchanged in shape. Downstream
consumers (`bsv-mpc-service`, future `bsv-mpc-worker`) `use` the same
paths.

### 2.2 Why this beats the original "separate sibling crate" plan

The original NEXT-STEPS.md Phase H description prescribed a separate
`bsv-mpc-messagebox-worker` sibling crate. Re-examining after Phase G:

| Axis | Cfg-gate inside `bsv-mpc-messagebox` (this proposal) | Separate `bsv-mpc-messagebox-worker` crate (NEXT-STEPS.md original) |
|---|---|---|
| Code reuse | 95% — auth/client/http/types/wire shared | Either duplicated or extracted to a third "shared types" crate |
| Downstream import surface | `use bsv_mpc_messagebox::*` works everywhere; no cfg-target gymnastics | Consumers must conditionally choose `bsv-mpc-messagebox` vs `bsv-mpc-messagebox-worker` |
| New crate creation cost | zero | adds a 5th MessageBox-adjacent crate; partnership tracker has to learn it |
| Naming | `bsv-mpc-messagebox` is already the umbrella for "talks to message-box-server"; cfg-target is a transport detail | `*-worker` suffix is misleading (it's wasm32-compatible, not CF-specific — `bsv-mpc-service` also runs the existing client) |
| Wire-divergence risk | one source of truth for endpoints + auth | two implementations to keep in sync |
| Direction-change vs umbrella | **DIVERGES** from issue #2 + NEXT-STEPS.md naming — must be documented + propagated | follows the original plan as written |

**Recommendation: take the divergence.** Cfg-gating is the cheaper
maintenance shape and the single source-of-truth wire stays load-bearing
for cross-stack work (Phase K). Document the change in the merge
commit + propagate to umbrella #2 (precedent: G's LocalSet→inline
pivot, propagated in `02893e8`).

### 2.3 Cargo features + dep wiring

`crates/bsv-mpc-messagebox/Cargo.toml`:

```toml
[features]
default = ["native"]
native = ["dep:tokio-tungstenite", "dep:tokio", "tokio?/macros", "tokio?/rt-multi-thread", "tokio?/net", "tokio?/time"]
worker = ["dep:web-sys", "dep:wasm-bindgen", "dep:wasm-bindgen-futures", "dep:js-sys", "web-sys?/WebSocket"]

[dependencies]
# always
serde = { workspace = true }
serde_json = { workspace = true }
bsv = { workspace = true }
url = "2"
tracing = { workspace = true }
futures = { workspace = true }

# native-only (optional via "native" feature)
tokio = { workspace = true, optional = true, default-features = false }
tokio-tungstenite = { version = "0.24", optional = true }
reqwest = { workspace = true, optional = true }

# wasm32-only (optional via "worker" feature)
web-sys = { version = "0.3", optional = true, features = ["WebSocket", "MessageEvent", "CloseEvent", "Event"] }
wasm-bindgen = { version = "0.2", optional = true }
wasm-bindgen-futures = { version = "0.4", optional = true }
js-sys = { version = "0.3", optional = true }

[target.'cfg(target_arch = "wasm32")'.dependencies]
# default-on for wasm32 builds — saves consumers having to set features
# Optional: leave this out and require consumers to explicitly pass `--features worker`
```

Default features = `native` so the existing `bsv-mpc-service` build is
unchanged. `bsv-mpc-worker` (Phase I) opts into `worker` via its own
`Cargo.toml`.

### 2.4 `ws_wasm.rs` API contract

Mirrors `ws_native.rs::subscribe()`'s signature line-for-line:

```rust
pub async fn subscribe(
    relay_url: &str,
    boxes: Vec<String>,
    auth: Arc<MessageBoxAuth>,
    shutdown: oneshot::Receiver<()>,
) -> Result<WsSubscription>;
```

Internal differences:
- Open WS: `web_sys::WebSocket::new(url)` instead of
  `tokio_tungstenite::connect_async`.
- Pump loop: spawn via `wasm_bindgen_futures::spawn_local`; use
  `async_channel` or hand-rolled `Rc<RefCell<VecDeque<_>>>` for the
  inbound queue (the existing `tokio::sync::mpsc` is `!Send` /
  multi-thread-flavored — wasm32 is single-threaded, so simpler types
  fit).
- Heartbeat: `gloo-timers::callback::Interval` (or `setInterval` via
  `js-sys`) instead of `tokio::time::interval`.
- BRC-31 upgrade: `web_sys::WebSocket` does NOT support per-request
  headers — this is the load-bearing wasm32 constraint. **Workaround
  decision pending:** sub-protocol field encoding (RFC 6455 §1.9), or
  pre-issue a token via a `POST /upgrade-token` then pass via URL query
  param. **Empirical question for the POC** — see §6.

### 2.5 The BRC-31-on-WS-upgrade constraint **— SUPERSEDED, see §2.5b**

> 🚫 **This subsection is preserved as historical analysis only.** All
> three workaround candidates below require server-side changes to the
> message-box protocol, which is a community standard and IMMUTABLE.
> The right answer is **Socket.IO + BRC-103** — the browser-compatible
> path the canonical TS client already uses. **See [§2.5b](#25b-socketio--brc-103-the-canonical-browser-compatible-path-supersedes-25)** for the corrected design.

`web_sys::WebSocket::new(url)` accepts only a URL + an optional
sub-protocols array. There is no header-injection path in the browser
WebSocket API. The native `ws.rs:407-419` sends a full upgrade GET with
7 BRC-31 headers; the wasm32 path cannot do this directly.

Three workaround candidates, in order of preference:

**(a) Sub-protocol field encoding.** RFC 6455 §1.9 allows the client to
declare `Sec-WebSocket-Protocol` values; some servers (Kubernetes API,
GCP, AWS) carry auth tokens through it. Server-side support required
on `rust-message-box`. Format: base64-encoded(BRC-31 header bundle).
Pro: works in browser + CF Worker uniformly. Con: requires
`rust-message-box` server tweak.

**(b) Pre-issue token via `POST /ws-upgrade-token`, then connect with
`?token=...` query.** Server returns a short-lived single-use token
bound to the BRC-31-authed POST; client opens `wss://relay/ws?token=...`.
Pro: zero browser-side cryptography. Con: two-step connect (latency +
server route).

**(c) Send BRC-31 via the first WS frame after open.** First frame
after `WebSocket.onopen` is a JSON `{op: "auth", brc31_headers: {...}}`;
server validates and either upgrades the connection's identity or
closes. Pro: simplest server change. Con: race window between WS open
and auth — server must hold all messages received in that window.

**Audit recommendation: (a)** — sub-protocol encoding, since it's
cleanest spec-wise and the canonical TS client already supports a
sub-protocol path (`MessageBoxClient.ts:332` AuthSocketClient). POC
step verifies whether the existing `rust-message-box` server accepts
this; if not, fall-back to (b).

**This is the highest-risk substrate-level open question.** Putting it
in §8 for explicit user resolution before POC starts.

### 2.5b Socket.IO + BRC-103 — the canonical browser-compatible path (supersedes 2.5)

This subsection was added 2026-05-19 after a follow-up four-agent
investigation while reviewing the draft 1. The empirical finding
overturns §2.5: the canonical TS client `@bsv/message-box-client`
v2.0.7 does not use raw WebSocket at all — it uses Socket.IO with
post-handshake BRC-103 mutual auth. The same Rust servers we already
target expose this path alongside `/ws`. We do not need to invent a
workaround or change the server.

#### What the canonical TS client actually does

`~/bsv/message-box-client/src/MessageBoxClient.ts:332` constructs the
WebSocket transport via `AuthSocketClient(targetHost, { wallet, originator })`.
`AuthSocketClient` is in a sister package at
`~/bsv/authsocket-client/src/AuthSocketClient.ts:103-114`, and its
implementation is:

```typescript
const socket = realIo(url, opts.managerOptions)          // socket.io-client@4.x
const transport = new SocketClientTransport(socket)      // wraps socket as a BRC-103 Transport
const peer = new Peer(opts.wallet, transport, ...)       // @bsv/sdk Peer = BRC-103 state machine
return new AuthSocketClientImpl(socket, peer)
```

The wire shape:

1. **Socket.IO HTTP(S) handshake to `/socket.io/?EIO=4&transport=...`** —
   anonymous (no auth headers, no BRC-31). Server returns a session id
   + `upgrades: ["websocket"]` per Engine.IO 4.
2. **Socket.IO upgrades to WebSocket** — anonymous still.
3. **BRC-103 handshake over the `authMessage` Socket.IO event** —
   `~/bsv/authsocket-client/src/SocketClientTransport.ts:17-28` —
   `socket.emit('authMessage', message)` + `socket.on('authMessage', ...)`.
   Client and server exchange `AuthMessage` frames (initialRequest →
   initialResponse → general) per BRC-103. After this, the socket is
   bound to the verified identity.
4. **App-level events** (`joinRoom`, `sendMessage`, etc.) emit on
   Socket.IO normally, with no per-frame signing — channel trust from
   the BRC-103 handshake.

#### The Rust servers already serve this path (Calhoun included)

`~/bsv/bsv-messagebox-cloudflare-public/src/lib.rs:97-98` registers
the route `/socket.io/*` → `route_socketio_request` (lib.rs:373-455).
Engine.IO + Socket.IO frame handling lives in `src/engineio/` +
`src/socketio_worker.rs`. The BRC-103 state machine on the server side
is `src/engineio/auth.rs:1-72` — its module comment is explicit:

> *"BRC-103 mutual authentication driver for Socket.IO `authMessage`
> events (M10 #61 — Phase B). That matches the TypeScript
> SocketServerTransport/SocketClientTransport pair from the
> @bsv/authsocket and @bsv/authsocket-client libraries."*

**Live verification (2026-05-19)**:
```
$ curl -sS 'https://rust-message-box.dev-a3e.workers.dev/socket.io/?EIO=4&transport=polling'
0{"maxPayload":1000000,"pingInterval":25000,"pingTimeout":20000,"sid":"OjG_sVWIRbe8BaQW80ax2Q","upgrades":["websocket"]}
```

Worker URL is in `~/bsv/rust-message-box/wrangler.toml` (and verifiable
via the Cloudflare API token; the project name + custom domain are
recorded there).

`rust-message-box` and `bsv-messagebox-cloudflare-public` are byte-
identical handlers per the sister-agent server matrix. The Socket.IO
route is on both.

#### `bsv_rs::auth::Peer` already has BRC-103 — we just need a new Transport

`~/bsv/bsv-rs/src/auth/transports/` exposes the `Transport` trait. The
existing `SimplifiedFetchTransport` is used by the native client's HTTP
routes; a `WebSocketTransport` (raw-WS + BRC-103 frame-by-frame) also
exists. **Phase H adds `SocketIoTransport`** — the Rust analog of the
TS `SocketClientTransport`. Its job is:

- Hold a Socket.IO client handle.
- `send(AuthMessage)` → `socket.emit('authMessage', message_json)`.
- Register a `socket.on('authMessage', ...)` callback that
  `Peer.onData()` consumes.
- Lazily open the Socket.IO connection on first `send`.

Once `SocketIoTransport` exists, the existing `MessageBoxClient` in
`crates/bsv-mpc-messagebox/` can swap its hand-crafted `MessageBoxAuth`
+ `sign_ws_upgrade` flow for `bsv_rs::auth::Peer<ProtoWallet, SocketIoTransport>`
on wasm32 — and the BRC-103 protocol details are handled inside
`bsv-rs` rather than open-coded here.

#### Implementation strategy for Socket.IO in Rust wasm32

Two options:

**(i) Bundle the JS `socket.io-client@4.x` via `wasm-bindgen` + `js-sys`.**
Add `socket.io-client` as a JS dep in the wasm32 build; expose its
`io()` factory + `Socket` methods via `wasm-bindgen` `extern "C"`
bindings; Rust `SocketIoTransport` calls through. ~50-100 LOC of FFI
glue. Conformance to canonical TS is structural — we literally use the
same JS library the TS client uses.

**(ii) Implement Engine.IO + Socket.IO in Rust wasm32 from scratch.**
~500-800 LOC for Engine.IO 4 packet framing (open/close/ping/pong/
message/upgrade), polling + WS-upgrade transport, Socket.IO event
multiplexing. No JS dep. Subtle correctness risks (binary framing,
upgrade race, reconnect semantics).

**Audit recommendation: (i)**. Reasons:
- Path A says conform to TS; the TS client is literally this JS lib.
- Maintenance burden is orders of magnitude lower; Socket.IO
  protocol evolves under @bsv/socket.io-client's own maintainers.
- The JS dep stays inside the wasm32 build; native is unaffected.
- ~50-100 LOC of FFI vs ~500-800 LOC of protocol implementation.

POC step (§6) gates: (i) — bundle works, BRC-103 handshake completes,
canonical envelope round-trips.

#### Why this is strictly better than the §2.5 options

| Axis | §2.5 (a-c) raw-WS workarounds | §2.5b Socket.IO + BRC-103 |
|---|---|---|
| Server change | required | **none** |
| Conforms to canonical TS | no | **yes** (Path A) |
| Server-side already implemented | no | **yes** (engineio/auth.rs:1-72) |
| Browser-side already proven | no | **yes** (canonical TS client) |
| Auth strength | partial (workarounds had different security postures) | full BRC-103 mutual auth — same as TS |
| Rust dep cost | hand-crafted server tweak + Rust client | new `SocketIoTransport` (~100 LOC) + JS dep |
| Long-term direction | drift from canonical | unifies wasm32 + (eventually) native on canonical |

#### Consequence: native could eventually move to Socket.IO too

The existing native Rust client uses raw WS + 7 BRC-31 headers — a
Rust-only convenience path that only works because tokio-tungstenite
gives raw upgrade access. If we also unify NATIVE on Socket.IO +
BRC-103, both targets converge on the canonical TS wire and the
`MessageBoxAuth` + `sign_ws_upgrade` hand-crafted code path can be
deleted. **Out of Phase H scope**; tracked as a Phase H post-merge
follow-up.

#### Naming change implied

§2.1's `ws_wasm.rs` is misnamed if the wasm32 path uses Socket.IO.
Rename to `transport_wasm.rs` (or `socketio_wasm.rs`). The split is
still `ws_native.rs` (raw WS + BRC-31) + `transport_wasm.rs` (Socket.IO
+ BRC-103) behind the same `cfg(target_arch = "wasm32")` gate.

#### Updated open questions (supersedes the OQs in §8 marked)

- **OQ1 (substrate)** is resolved: Socket.IO + BRC-103.
- **OQ2 (BRC-31 workaround order)** is moot: no workaround needed.
- **OQ5 (server-side tweak ownership)** is moot: no server change.
- New: **OQ7 (Socket.IO substrate choice)** — bundle JS
  `socket.io-client@4.x` (recommended) vs. write a Rust Engine.IO
  client from scratch.
- New: **OQ8 (native unification)** — should native ALSO move to
  Socket.IO + BRC-103 as a Phase H post-merge cleanup, or keep the
  current raw-WS + BRC-31 path for Phase A-F regression safety?

## 3. Design direction B — Hibernation + reconnect flow

### 3.1 What survives DO hibernation

Per §1.2: only `serialize_attachment`-persisted application state
survives. For Phase H's DO this is:

```rust
#[derive(Serialize, Deserialize)]
struct WsAttachment {
    subscribed_boxes: Vec<String>,
    last_seen_message_id: HashMap<String, String>,  // per-box high watermark
    auth_identity_key: String,                       // for re-instantiating MessageBoxAuth
    relay_url: String,
}
```

Estimated size: 4 boxes × ~80 bytes + identity + URL ≈ 500 bytes.
Comfortable margin under the ~2KB attachment cap.

MPC ceremony state (KeyShare bytes, pending presignatures, in-flight
DKG round buffers) stays in DO `state.storage` (D1 / SQLite per Phase
I), NOT in the attachment. Audit doc Phase I will pin schema.

### 3.2 Reconnect+backfill flow on wake

Identical to native `ws.rs:221-274` but invoked from the DO's
`alarm()` / `fetch()` handler instead of a long-lived tokio task:

```
on_wake() {
    auth = MessageBoxAuth::from_attachment(attachment)
    for box in attachment.subscribed_boxes {
        new_msgs = http::list_messages(auth, box, since=attachment.last_seen[box])
        for msg in new_msgs {
            dispatch(msg)              // to the MPC handler
            attachment.last_seen[box] = msg.id
        }
    }
    persist_attachment(attachment)     // before opening WS
    ws = ws_wasm::subscribe(relay_url, attachment.subscribed_boxes, auth, shutdown)
}
```

The native path's outer `loop { ... backoff ... }` is replaced by the
DO's natural sleep-on-idle behavior — every wake is an implicit
reconnect attempt.

### 3.3 BRC-31 session refresh on every reconnect

`MessageBoxAuth::sign_ws_upgrade()` MUST be called BEFORE every
WS-open, on both targets. The wasm32 implementation can call this
identically (auth.rs is runtime-agnostic — `tokio::sync::RwLock` works
on single-threaded executors per
[tokio docs](https://docs.rs/tokio/latest/tokio/sync/struct.RwLock.html)).

POC verifies one full hibernate→wake→reconnect cycle preserves identity
+ doesn't drop messages.

## 4. API surface diff

**Public API: unchanged.** Existing consumers (`bsv-mpc-service`)
continue to compile + run unchanged on native. New wasm32 consumers
(`bsv-mpc-worker` post-Phase-I) compile via `--features worker`.

| Item | Before (Phase A-F) | After (Phase H) | Source |
|---|---|---|---|
| `MessageBoxClient::new(...)` | unchanged | unchanged | `client.rs` |
| `MessageBoxClient::subscribe(...)` | tokio-tungstenite under the hood | dispatch via cfg-target_arch | `client.rs:172-181` |
| `subscribe()` (low-level) | unchanged | unchanged signature, wasm32 impl swaps | `ws.rs:154-196` → `ws_native.rs` + `ws_wasm.rs` |
| `WsSubscription` | unchanged | unchanged | `ws.rs:112-142` → `ws_native.rs` + `ws_wasm.rs` |
| `MessageBoxAuth::sign_ws_upgrade(...)` | unchanged | unchanged | `auth.rs:46-47` |
| `Cargo.toml` features | (none) | `native` (default), `worker` | new |
| Tokio dep | unconditional | optional, behind `native` | `Cargo.toml` |
| Web-sys dep | absent | optional, behind `worker` | new |

## 5. Test strategy

### 5.1 Existing tests that MUST stay green

The full Phase A-F regression set:

| Test | Source | Why |
|---|---|---|
| `crates/bsv-mpc-service/tests/messagebox_listener_e2e.rs` | (live relay) | Phase B/C round-trip |
| `crates/bsv-mpc-service/tests/dkg_via_messagebox_e2e.rs` | (live relay) | Phase D |
| `crates/bsv-mpc-service/tests/sign_mainnet_via_messagebox_e2e.rs` | (live relay + sats) | Phase E baseline + Phase G re-verify TXID `442bd391…` |
| `crates/bsv-mpc-messagebox/src/**/*` unit tests | in-crate | Wire types + auth + envelope wrap |
| Conformance vectors (02/04/05) | `crates/bsv-mpc-core/tests/` | Byte-locked wire |

All run on the `native` feature path. No changes expected.

### 5.2 New tests

| Test | Target | What it proves |
|---|---|---|
| `crates/bsv-mpc-messagebox/tests/wasm32_subscribe.rs` (new) | `wasm32-unknown-unknown` via `wasm-pack test --node` | The wasm32 `subscribe()` opens against a mock WS server (running in the same Node test runner) + round-trips one envelope byte-exact. Mirrors the G-5b precedent at `crates/bsv-mpc-core/tests/wasm32_dkg.rs`. |
| `poc17-cf-outbound-ws` E2E (Phase H Step 3) | deployed test Worker | One canonical envelope from the test Worker to itself via the live relay byte-exact + forced-hibernation reconnect (POC step §6). |

### 5.3 What we explicitly do NOT add

- A within-stack mainnet TXID re-run — Phase E TXID already covers the
  native path; Phase H is about wasm32 transport, not signing
  correctness. The mainnet-TXID-via-deployed-Worker is the Phase I
  merge gate, not Phase H's.

## 6. POC scope — `poc/poc17-cf-outbound-ws/`

POC step (Phase H Step 3): smallest standalone Cloudflare Worker
deployable via `wrangler deploy` that proves the load-bearing unknowns.
**The POC commit lands on `main` BEFORE the implementation begins.**

### 6.1 Scope

`poc/poc17-cf-outbound-ws/` — a single Cargo crate + minimal `wrangler.toml`:

```
poc/poc17-cf-outbound-ws/
  Cargo.toml          # worker = "0.7" or "0.8", web-sys with WebSocket feature
  wrangler.toml       # account_id from ~/.cloudflare creds, single DO binding
  src/
    lib.rs            # CF Worker entry + DO impl
    ws_client.rs      # web_sys::WebSocket wrapper
  README.md           # what this POC proves + how to test
```

### 6.2 Gates (each a hard pass/fail) — **rewritten per §2.5b**

| Gate | Scenario | Pass criterion |
|---|---|---|
| **H-3.1** | `cargo build --target wasm32-unknown-unknown -p poc17-cf-outbound-ws` | clean build, no link errors. Bundles `socket.io-client@4.x` JS via wasm-bindgen. |
| **H-3.2** | Socket.IO handshake from DO via JS-bundled `socket.io-client` | `wrangler dev` test: DO `fetch /open` triggers Socket.IO `GET /socket.io/?EIO=4&transport=polling` to live relay; receives 200 with session id; upgrades to WS within 5s. |
| **H-3.3** | BRC-103 mutual auth completes over `authMessage` event | DO sends BRC-103 `InitialRequest` via `socket.emit('authMessage', ...)`; receives server `InitialResponse`; channel becomes identity-bound. New `SocketIoTransport` (Rust impl of `bsv_rs::auth::Transport`) drives `bsv_rs::auth::Peer` through the handshake. |
| **H-3.4** | Round-trip canonical envelope | POST `/relay` to DO; DO `emit('sendMessage', envelope)` to live relay's `/socket.io/`; DO receives the echo back on a `sendMessage` event from its own subscribed room; body byte-identical (CBOR `MessageEnvelope` per MPC-Spec §05). |
| **H-3.5** | Forced-hibernation reconnect | `wrangler dev` + `state.abort()` to force DO eviction; subsequent fetch wakes DO; DO re-runs Socket.IO connect → BRC-103 handshake → `/listMessages` drain → resubscribe; missed envelope reaches consumer byte-exact. |

### 6.3 What the POC does NOT do

- Full `MessageBoxClient` API surface — that's the H-4 implementation.
- MPC ceremony — Phase I.
- Multi-room subscribe — single room is enough to prove the substrate.
- Performance benchmarking — that's Phase I deployment audit.

## 7. Phase H quality gate (Step 5)

Phase H is "done" when **all** of the following are simultaneously
true. No asterisks.

### 7.1 Build + lint
- [ ] `cargo build --workspace --all-targets` clean.
- [ ] `cargo build -p bsv-mpc-messagebox --features worker --target wasm32-unknown-unknown` clean.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] `cargo fmt --all -- --check` clean.

### 7.2 Native tests
- [ ] All `bsv-mpc-messagebox` unit tests pass on native.
- [ ] Existing `crates/bsv-mpc-service/tests/messagebox_listener_e2e.rs` + `dkg_via_messagebox_e2e.rs` + Phase E real-sats TXID re-run all green.

### 7.3 wasm32 tests
- [ ] `crates/bsv-mpc-messagebox/tests/wasm32_subscribe.rs` runs via
      `wasm-pack test --node`: byte-identical envelope round-trip.
- [ ] CI `wasm` job adds the new test invocation.

### 7.4 Deployed-Worker live test (the merge gate)
- [ ] Test Worker (`poc17-cf-outbound-ws` final shape OR
      a small `e2e/phase-h-worker/`) deploys via `wrangler deploy`.
- [ ] Worker connects to `/socket.io/` on live
      `rust-message-box.dev-a3e.workers.dev` via bundled
      `socket.io-client@4.x` (§2.5b) and completes the BRC-103
      handshake over the `authMessage` Socket.IO event.
- [ ] Round-trips a canonical CBOR envelope byte-exact through the
      live relay.
- [ ] **Forced-hibernation reconnect test**: evict the DO mid-flight;
      next fetch wakes; Socket.IO re-handshakes; BRC-103 re-authenticates;
      `/listMessages` backfill recovers; missed envelope reaches the
      consumer.

### 7.5 Doc + tracker
- [ ] `docs/PHASE-H-AUDIT.md` checkboxes ticked in the merge-gate commit.
- [ ] Umbrella issue #2 Phase H box ticked; closing comment with
      deployed-Worker URL + a saved request/response trace.

## 8. Open questions

These do NOT block the audit-doc commit but should be resolved before
the POC step begins.

| | Question | Default if no answer |
|---|---|---|
| ~~OQ1~~ | ~~Substrate `web_sys::WebSocket` vs sidecar JS Worker~~ — **MOOT per §2.5b**: substrate is Socket.IO + BRC-103, not raw WS. | resolved |
| ~~OQ2~~ | ~~BRC-31 upgrade workaround order~~ — **MOOT per §2.5b**: no workaround needed; Socket.IO carries BRC-103 post-handshake. | resolved |
| **OQ3** | Cfg-gate inside existing `bsv-mpc-messagebox` vs separate `bsv-mpc-messagebox-worker` sibling crate — audit recommends cfg-gate (§2.2). User confirmed 2026-05-19. | ✓ confirmed |
| **OQ4** | DO topology — per-identity DO (recommended in NEXT-STEPS.md Q3 default) — confirm? | per-identity |
| ~~OQ5~~ | ~~Server tweak on `rust-message-box`~~ — **MOOT per §2.5b**: no server change. The server protocol is immutable; the canonical path (Socket.IO + BRC-103) is already exposed. | resolved |
| **OQ6** | Should H-3 POC's deployed-Worker LIVE in the bsv-mpc repo or in a separate dev account? — recommend in-repo under `poc/poc17-cf-outbound-ws/`, dev CF account, no production data. | yes |
| **OQ7** | Socket.IO client substrate (§2.5b) — (i) bundle JS `socket.io-client@4.x` via wasm-bindgen (recommended) vs (ii) write a Rust Engine.IO/Socket.IO client. | (i) bundle JS |
| **OQ8** | Native unification — should the existing native Rust client ALSO move to Socket.IO + BRC-103 as a Phase H post-merge cleanup, OR keep the current raw-WS + BRC-31 path for Phase A-F regression safety? | post-merge cleanup; not Phase H scope |

## 9. References

### Source files
- `crates/bsv-mpc-messagebox/src/lib.rs` — public surface
- `crates/bsv-mpc-messagebox/src/auth.rs` — BRC-31 wrap of bsv-rs Peer
- `crates/bsv-mpc-messagebox/src/client.rs` — `MessageBoxClient` + spawn sites
- `crates/bsv-mpc-messagebox/src/http.rs` — HTTP routes
- `crates/bsv-mpc-messagebox/src/ws.rs` — current native WS pump
- `crates/bsv-mpc-messagebox/src/wire.rs` — envelope wrap/unwrap
- `~/bsv/message-box-client/src/MessageBoxClient.ts` — canonical TS (Path A)
- `~/bsv/bsv-messagebox-cloudflare-public/src/message_hub.rs` — inbound-WS DO template (invert for outbound)
- `~/bsv/bsv-messagebox-cloudflare-public/tests/load_gen/src/{handshake,connect,serialize}.rs` — BRC-31 WS-upgrade reference impl

### Spec sections
- MPC-Spec §06 (transport) — §06.4 receive-side; §06.12 reconnect/backfill
- MPC-Spec §05 — canonical CBOR envelope
- BRC-31 — Authrite mutual auth
- BRC-103 / BRC-104 — SimplifiedFetchTransport payload + headers
- RFC 6455 §1.9 — WebSocket sub-protocol

### Related ADRs
- Audit §2.2 — Phase H direction-change from the original
  NEXT-STEPS.md sibling-crate plan to cfg-gate inside
  `bsv-mpc-messagebox`. Documented here; will propagate to umbrella
  issue #2 + NEXT-STEPS.md in the merge-gate commit.

### Memory references
- [[reference-messagebox-client-ts]] — canonical TS @ `~/bsv/message-box-client/`
- [[reference-brc31-messagebox-uses-peer]] — bsv-rs `Peer + SimplifiedFetchTransport` for non-KSS BRC-31
- [[feedback-canonical-ts-immutable]] — Path A
- [[feedback-spec-first-then-propose]] — read MPC-Spec section before proposing API shape

## 10. Headlines for quick review

1. **Substrate**: `web_sys::WebSocket` is the primary path; sidecar JS
   Worker is the well-scoped fall-back. POC step verifies whether CF
   exposes `globalThis.WebSocket` to WASM in the DO context.

2. **Hibernation**: outbound WS doesn't survive — full reconnect on
   wake. The existing native `ws.rs` already has the canonical
   `/listMessages`-drain-first + 1s→30s exponential backoff loop;
   wasm32 inherits the same logic, structured around the DO's
   `alarm()`/`fetch()` wake events rather than a tokio loop.

3. **Code structure**: cfg-gate inside the existing
   `bsv-mpc-messagebox` crate (single source of truth); split `ws.rs`
   into `ws_native.rs` + `ws_wasm.rs`; introduce a tiny `spawn.rs`
   target-conditional helper. **Diverges from the original umbrella
   plan that prescribed a separate `bsv-mpc-messagebox-worker` sibling
   crate** — §2.2 makes the case for the divergence; the merge-gate
   commit propagates it to umbrella #2.

4. **The wasm32 wire is Socket.IO + BRC-103, not raw WS + BRC-31.**
   The canonical TS `@bsv/message-box-client` uses Socket.IO with
   post-handshake BRC-103 mutual auth via the `authMessage` event;
   the Calhoun Rust relay already serves this path at `/socket.io/`
   alongside `/ws` (verified by live curl + lib.rs:97-98 +
   engineio/auth.rs:1-72). The wasm32 client bundles the same JS
   `socket.io-client@4.x` the canonical TS uses and adds a new
   `SocketIoTransport` Rust impl on top of `bsv_rs::auth::Peer`'s
   `Transport` trait. **No server change. Path A conformant.**
   §2.5b makes the case; §2.5 is preserved as the historical
   reasoning trail.

5. **Merge gate is real.** No asterisks: a deployed-Worker
   forced-hibernation round-trip with a fresh canonical envelope
   reaching the consumer byte-exact, BRC-103-authed (via Socket.IO),
   against the live Calhoun relay — **PLUS** a fresh real-sats mainnet
   TXID through the new native Socket.IO + BRC-103 path proving
   regression-safety on the existing Phase A-F flows. See §11 for the
   god-tier expansion.

## 11. God-tier scope expansion — resolutions for OQ4 / OQ7 / OQ8

This section was added 2026-05-19 after the user reviewed §2.5b and
endorsed the "no matter how long it takes" framing on the three live
open questions. Resolutions below; quality gate (§7), POC scope (§6),
and open questions (§8) are amended in-place to match.

### 11.1 OQ4 — DO topology: per-identity

**Resolved: per-identity DO.** Matches the server-side per-identity
`MessageHub` DO at `~/bsv/bsv-messagebox-cloudflare-public/src/message_hub.rs`,
isolates hibernation failure modes, makes BRC-31 + BRC-103 session
lifecycle natural (one identity → one session → one DO → one Socket.IO
connection multiplexing N rooms via `joinRoom`). No tradeoff worth
making against multi-tenant — its only benefit is shared memory,
which is irrelevant on CF DOs.

### 11.2 OQ7 — Socket.IO substrate: pure Rust+WASM, leverage existing Calhoun-owned codec — **revised 2026-05-19**

> **Correction over the draft 1 §11.2.** The original ranking led with
> `rust-socketio` (an external crate that turned out not to support
> wasm32) and listed "bundle the canonical JS `socket.io-client@4.x`"
> as a fall-back. User has clarified that the project goal is **pure
> Rust + WASM end-to-end**; JS bundling is Plan B only. This nuances
> OQ7 substantially. Below supersedes the original §11.2.

**Empirical finding (Phase H pre-scaffold prep, 2026-05-19)**:
`bsv-messagebox-cloudflare-public/src/engineio/codec.rs` (and the
byte-identical copy in `rust-message-box/src/engineio/codec.rs`, both
on the Calhoun-controlled `Calhooon/bsv-messagebox-cloudflare`
upstream) contains a **complete, direction-agnostic Engine.IO v4 +
Socket.IO v5 packet codec in pure Rust** — 613 LOC, depends only on
`serde_json` + Rust std, wasm32-compatible by construction, MIT
licensed (© Calhooon Contributors). This codec encodes + decodes both
server-bound AND client-bound packets identically; nothing in it is
server-only. We can vendor + extend for a client crate without
touching the existing servers.

**Plan A (pure Rust+WASM), in order of preference**:

1. **A1: Vendor + extend the existing Calhoun codec.** Pull
   `engineio/codec.rs` into our new client crate (with attribution
   header citing the Calhooon source) and build a minimal Engine.IO
   + Socket.IO CLIENT on top:
   - **HTTP polling** (Engine.IO `transport=polling` handshake phase):
     `worker::Fetch` on both targets — the `worker` crate's outbound
     fetch works inside CF Workers + DOs, and on native the proxy
     consumer can use `reqwest`.
   - **WS upgrade** (Engine.IO `transport=websocket` post-handshake):
     `web_sys::WebSocket` on wasm32 (Phase H POC H-3.2 verifies this
     works inside CF DO scope — that's the load-bearing empirical
     question); `tokio-tungstenite` on native.
   - **State machine**: CONNECTING → CONNECTED → UPGRADING →
     UPGRADED → CLOSED. ~100 LOC.
   - **Socket.IO event layer**: `emit(name, json)` /
     `on(name, callback)` over the codec. ~100 LOC.
   - **SocketIoTransport** (this is the BRC-103 layer): impl of
     `bsv_rs::auth::Transport`, wraps `emit('authMessage', ...)` /
     `on('authMessage', ...)`. ~150 LOC.
   - **Total**: ~1000 LOC including the vendored codec.
   - **Maintenance**: low. Engine.IO + Socket.IO protocols are
     stable; the codec doesn't churn.

2. **A2: Contribute wasm32 support to `rust-socketio` upstream.**
   Larger ecosystem contribution; replaces `reqwest+blocking+native-tls`,
   `tokio-tungstenite`, `native-tls` with wasm32-compatible alternates
   inside the external crate. ~500-1000 LOC substrate rewrite + wait
   for upstream review. **Defer to Phase H post-merge** as an
   ecosystem follow-up (track in STATUS.md "upstream contributions").
   Doing this would *also* benefit the broader Rust BSV ecosystem, but
   it's NOT on the Phase H critical path because A1 already gives us
   pure Rust+WASM via Calhoun-owned code.

**Plan B (fallback only — invoke if A1 hits an unforeseen blocker)**:
bundle the canonical JS `socket.io-client@4.x` via `wasm-bindgen` +
`js-sys` (~50-100 LOC FFI). Only if `web_sys::WebSocket` turns out
unusable inside CF DO scope and we can't get to ground on a pure-Rust
WS substrate. Acceptable as a last resort; suboptimal because it
violates the "pure Rust+WASM" project goal.

**`SocketIo` trait** (inside `bsv-mpc-messagebox`) — minimal
abstraction: `connect(url)`, `emit(event, payload)`,
`on(event, callback)`, `disconnect`. ~50 LOC. Native impl uses the
vendored codec + `reqwest` + `tokio-tungstenite`; wasm32 impl uses
the vendored codec + `worker::Fetch` + `web_sys::WebSocket`. Same
codec on both targets.

**`SocketIoTransport`** — Rust impl of `bsv_rs::auth::Transport` over
the `SocketIo` trait, dispatching BRC-103 `AuthMessage` frames on
`emit('authMessage', ...)` + `on('authMessage', ...)`. Rust analog of
TS `@bsv/authsocket-client::SocketClientTransport`. **Contribute
upstream to `bsv-rs`** at `~/bsv/bsv-rs/src/auth/transports/`
alongside the existing `SimplifiedFetchTransport` (HTTP per-request)
and `WebSocketTransport` (raw WS frame-by-frame). bsv-rs is
Calhoun-controlled (`Calhooon/bsv-rs`); upstream PR is trivial.

**Ecosystem follow-ups (out of Phase H critical path but tracked)**:

- **Extract codec into a shared crate** (`bsv-engineio-rs`?). Currently
  duplicated byte-for-byte in `bsv-messagebox-cloudflare-public` and
  `rust-message-box`. A shared crate would (a) eliminate the
  code-clone in the two servers, (b) be the canonical Rust Engine.IO +
  Socket.IO codec for the BSV ecosystem, (c) let our new client
  depend on it instead of vendoring. Coordination work; Phase H
  post-merge.
- **Publish a `bsv-authsocket-rs` crate** wrapping the upstream
  `SocketIoTransport` + `Peer`. Rust analog of TS
  `@bsv/authsocket-client`. Phase H post-merge.
- **A2 (wasm32 to `rust-socketio`)**: still worth doing as an
  ecosystem contribution after Phase H closes. Tracked in STATUS.md.

### 11.3 OQ8 — Native unification: pulled INTO Phase H scope

**Resolved: yes, native moves to Socket.IO + BRC-103 inside Phase H.**
Not a post-merge cleanup. Reasoning:

1. **Path A violation.** The existing native client at
   `crates/bsv-mpc-messagebox/src/ws.rs` uses raw WS + 7 BRC-31
   headers on the HTTP/1.1 upgrade — a Rust-only convenience that
   works only because `tokio-tungstenite` exposes raw upgrade access.
   The canonical TS path is Socket.IO + BRC-103. Per
   [[feedback-canonical-ts-immutable]], implementation conforms to TS,
   never the inverse. The current native client is non-conformant.

2. **Phase K (cross-stack with Binary) depends on this.** Binary's
   relay is the TS `message-box-server`, which exposes ONLY the
   Socket.IO path. As-is, the native Rust client cannot talk to
   Binary's server — the lib.rs comment in `bsv-mpc-messagebox` already
   flags this: *"raw WebSocket on the Calhoun relay; Socket.IO/EngineIO
   on Binary's relay"*. If we defer native unification, Phase K stays
   blocked on a hidden interop bug. Pulling it forward into Phase H
   means Phase K's only remaining risk is the joint ceremony itself,
   not the transport.

3. **Symmetric merge gate.** Once both targets are on Socket.IO +
   BRC-103, Phase H's merge gate exercises BOTH paths against the
   live Calhoun relay AND envelope round-trip against Binary's TS
   server. No asymmetry to hide bugs in.

### 11.4 Phase H scope (amended)

| Sub-goal | Status | Owner |
|---|---|---|
| **Vendor + extend Calhoun Engine.IO + Socket.IO codec** (per §11.2 revised) | new in Phase H | `bsv-mpc-messagebox` — `engineio/codec.rs` ported from `bsv-messagebox-cloudflare-public/src/engineio/codec.rs` with attribution |
| Minimal pure-Rust Engine.IO + Socket.IO **client** on top of the vendored codec | new in Phase H | `bsv-mpc-messagebox::socketio_client` (~300 LOC over the codec) |
| `SocketIo` trait + `SocketIoTransport` (BRC-103) | new in Phase H | `bsv-mpc-messagebox` + upstream PR to `bsv-rs` |
| `bsv-mpc-messagebox` cfg-gate (§2.1-§2.4) | new in Phase H | `ws_native.rs` + `transport_wasm.rs` split |
| **Native client migrated to Socket.IO + BRC-103** | new in Phase H per §11.3 | `bsv-mpc-messagebox` |
| `bsv-mpc-worker` (CF Worker) embedding the wasm32 client + DO | Phase I scope (unchanged) | — |

Removed from the new Phase H scope (vs draft 1 §11.4):
- `rust-socketio` wasm32 support — Plan A is the vendored codec; rust-socketio wasm32 PR remains an ecosystem follow-up post-Phase-H, not on the critical path.

Removed from Phase H scope:
- The old §2.5 BRC-31 workarounds (a/b/c). MOOT per §2.5b.
- The "separate `bsv-mpc-messagebox-worker` crate" approach. Cfg-gate
  inside existing crate per OQ3.

### 11.5 Phase H quality gate (Step 5), amended

Supersedes the §7 checklist where it diverges:

**Build + lint** (§7.1) — unchanged.

**Native tests** (§7.2) — unchanged, with one addition:
- [ ] **NEW mainnet TXID through the Socket.IO + BRC-103 native path.**
      Same shape as the G-5d re-verify (TXID `442bd391…`): 2-of-2 DKG
      + sign + broadcast via `bsv-mpc-service` against the live Calhoun
      relay over the NEW transport. ~100 sats real cost. Both DER
      signature shape AND joint pubkey shape match prior runs.

**wasm32 tests** (§7.3) — unchanged.

**Deployed-Worker live test** (§7.4) — extended:
- [ ] Worker connects to `/socket.io/` on live relay via the chosen
      substrate (rust-socketio or JS bundle).
- [ ] BRC-103 handshake completes over `authMessage`.
- [ ] Round-trips canonical CBOR envelope byte-exact.
- [ ] Forced-hibernation reconnect green.
- [ ] **NEW cross-stack readiness probe**: canonical envelope
      round-trips byte-exact against Binary's TS `message-box-server`
      from BOTH native and wasm32. Proves Phase K's transport
      precondition without requiring the joint ceremony.

**Upstream contributions** (§11.5 new, **revised per §11.2 patch**):
- [ ] `SocketIoTransport` filed upstream as a PR to `bsv-rs`
      (`~/bsv/bsv-rs/src/auth/transports/`). PR open and either merged
      or assigned for review before Phase H merges. bsv-rs is
      Calhoun-controlled — trivial coordination.
- [ ] **NOT a Phase H gate** but tracked in STATUS.md follow-ups:
      shared `bsv-engineio-rs` crate extraction (currently duplicated
      byte-for-byte in `bsv-messagebox-cloudflare-public` and
      `rust-message-box`); wasm32 PR to `rust-socketio` (ecosystem
      contribution, not needed for Phase H since A1 vendor-codec path
      gives pure Rust+WASM); `bsv-authsocket-rs` crate publication.

**Doc + tracker** (§7.5) — extended:
- [ ] `docs/PHASE-H-AUDIT.md` §7 + §11 checkboxes ticked in merge-gate commit.
- [ ] Umbrella issue #2 Phase H box ticked; closing comment cites:
      new native mainnet TXID + deployed-Worker URL + cross-stack
      envelope round-trip transcript + upstream PR links.

### 11.6 Cost + timeline

Phase H grows from the original ~3-4 weeks to **~5-7 weeks** to cover
native unification + upstream contributions + cross-stack readiness.
Acceptable per the user's "we love doing that shit no matter how long
it takes" framing; payoff is Phase K's transport risk drops to zero
and the Rust BSV ecosystem gets a canonical-TS-conformant Socket.IO +
BRC-103 client.

---

**Last updated:** 2026-05-19 (three same-day patches on top of draft 1):
§2.5b (Socket.IO + BRC-103 substrate); §11 (god-tier scope expansion
on OQ4/OQ7/OQ8 — pull native unification into scope); §11.2 revised
(pure Rust+WASM Plan A via vendored codec; JS bundle is Plan B
fallback only — user-corrected). POC step (H-3) ready to begin.
OQ3 confirmed; OQ1/OQ2/OQ5 obsolete; **OQ4/OQ7/OQ8 resolved per §11
+ §11.2 revised**; OQ6 is the only remaining trivial choice (POC
location — recommend in-repo, dev CF account, no production data).
