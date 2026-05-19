# Phase H Audit — `bsv-mpc-messagebox` wasm32 client + CF Durable Object outbound WS

> Investigation + design doc for Phase H of the v1.0 CF-native cosigner
> plan in [`NEXT-STEPS.md`](NEXT-STEPS.md). Written 2026-05-19, lands on
> `main` BEFORE the POC step (G-style 5-step workflow). Every claim has
> a `file:line` citation; if a claim is unsupported, it's flagged with
> "needs verification" inline.
>
> **Status:** draft 1 — pending user review before POC step (H-3) begins.

## TL;DR

Three interlocking design decisions for Phase H:

1. **Substrate: `web_sys::WebSocket` via `wasm-bindgen`.** No outbound-WS
   API in `workers-rs` 0.7 or 0.8; CF Workers' JS-runtime
   `fetch(url, { Upgrade: 'websocket' })` is not yet exposed in the
   Rust SDK. `web_sys::WebSocket` works in browser-targeted wasm32 by
   construction; whether the CF Worker / DO runtime exposes
   `globalThis.WebSocket` to the WASM module is the load-bearing
   empirical question the Phase H POC will burn. Fall-back if it
   doesn't: a paired JS sidecar Worker bridging via JSON frame relay
   (~300-500 LOC TS, well-scoped escape hatch).

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

### 2.5 The BRC-31-on-WS-upgrade constraint

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

### 6.2 Gates (each a hard pass/fail)

| Gate | Scenario | Pass criterion |
|---|---|---|
| **H-3.1** | `cargo build --target wasm32-unknown-unknown -p poc17-cf-outbound-ws` | clean build, no link errors |
| **H-3.2** | `web_sys::WebSocket::new()` works inside DO `fetch()` handler | `wrangler dev` test: DO returns "ws_open=true" within 5s of `fetch /open` |
| **H-3.3** | Round-trip canonical envelope through live relay | POST `/relay` to DO, DO sends via WS to `wss://rust-message-box.dev-a3e.workers.dev/ws`, receives echo back from self-room, returns body byte-identical |
| **H-3.4** | Forced-hibernation reconnect | `wrangler dev` + `state.abort()` to force evict DO; subsequent fetch wakes the DO; DO drains `/listMessages` first; missed envelope reaches consumer byte-exact |
| **H-3.5** | BRC-31 upgrade auth works through chosen workaround | sub-protocol or token-query (§2.5) path verified end-to-end against the live relay |

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
- [ ] Worker opens WS to live `rust-message-box.dev-a3e.workers.dev`,
      round-trips a canonical envelope byte-exact.
- [ ] **Forced-hibernation reconnect test**: evict the DO mid-flight;
      next fetch wakes; `/listMessages` backfill recovers; envelope
      reaches the consumer.
- [ ] BRC-31 upgrade-auth path verified end-to-end (whichever §2.5
      workaround is chosen).

### 7.5 Doc + tracker
- [ ] `docs/PHASE-H-AUDIT.md` checkboxes ticked in the merge-gate commit.
- [ ] Umbrella issue #2 Phase H box ticked; closing comment with
      deployed-Worker URL + a saved request/response trace.

## 8. Open questions

These do NOT block the audit-doc commit but should be resolved before
the POC step begins.

| | Question | Default if no answer |
|---|---|---|
| **OQ1** | Substrate (a) `web_sys::WebSocket` vs fall-back (d) sidecar JS Worker — start with (a); if POC H-3.2 fails, switch. Right? | yes |
| **OQ2** | BRC-31 upgrade workaround §2.5 — start with (a) sub-protocol field encoding; if `rust-message-box` server doesn't support, fall-back to (b) `POST /ws-upgrade-token` + query param. Which order? | (a) → (b) → (c) |
| **OQ3** | Cfg-gate inside existing `bsv-mpc-messagebox` vs separate `bsv-mpc-messagebox-worker` sibling crate — audit recommends cfg-gate (§2.2). Sign off on the direction change? | cfg-gate (this proposal) |
| **OQ4** | DO topology — per-identity DO (recommended in NEXT-STEPS.md Q3 default) — confirm? | per-identity |
| **OQ5** | Server tweak on `rust-message-box` to support OQ2 (a) sub-protocol — if (a) is chosen, who lands the server-side change? Calhoun-side, since `rust-message-box` is the Calhoun stack. ETA: 1 small PR alongside H-3 POC. | yes, Calhoun-side, before H-3 |
| **OQ6** | Should H-3 POC's deployed-Worker LIVE in the bsv-mpc repo or in a separate dev account? — recommend in-repo under `poc/poc17-cf-outbound-ws/`, dev CF account, no production data. | yes |

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

4. **The one Phase H wasm32 gotcha**: `web_sys::WebSocket::new(url)`
   has no header-injection path, so BRC-31 upgrade auth must move to
   sub-protocol field encoding or pre-issued token. POC step
   H-3.5 verifies whichever workaround the user picks.

5. **Merge gate is real.** No asterisks: a deployed-Worker
   forced-hibernation round-trip with a fresh canonical envelope
   reaching the consumer byte-exact, BRC-31-authed, against the live
   Calhoun relay.

---

**Last updated:** 2026-05-19. Pending user review before POC step (H-3) begins.
