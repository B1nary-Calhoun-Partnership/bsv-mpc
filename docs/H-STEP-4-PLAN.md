# Phase H Step 4 — `bsv-mpc-messagebox` cfg-gated unification plan

> For the Claude session picking up Phase H after Step 3 closes (H-3.5e
> landed, deployed-worker forced-hibernation transcript captured). Read
> this file alongside `docs/PHASE-H-AUDIT.md` §§11.3-11.5 (god-tier
> scope amendment — native pulled into Phase H) and
> `docs/H-3-5-PLAN.md` (the gold-standard plan-format this file
> mirrors).
>
> **Status:** plan-only. Step 4 implementation has NOT started.
>
> **Predecessor gates locked:**
>   * H-3.1 → H-3.5e (POC substrate proven on the live Calhoun relay,
>     including DO-owned outbound Socket.IO + BRC-103 + forced-
>     hibernation reconnect)
>
> **This step (Phase H Step 4):** migrate the POC17 proven substrate
> from `poc/poc17-cf-outbound-ws/src/` INTO the existing
> `crates/bsv-mpc-messagebox/` crate, cfg-gated so the SAME crate
> compiles for **native** (`x86_64`/`aarch64` with `tokio-tungstenite`
> + `reqwest`) AND **wasm32** (`wasm32-unknown-unknown` with
> `web_sys::WebSocket` + `worker::Fetch`). Per audit §11.3, the native
> path ALSO migrates onto Socket.IO + BRC-103 (no raw-WS + 7-BRC-31-
> header dual flavor) so wire shape is identical across targets and
> Phase K cross-stack with Binary's TS server has zero transport risk.

## TL;DR — the next concrete action

Sub-gate H-4.1 lifts `engineio_codec.rs` (target-agnostic, 629 LOC)
verbatim into `crates/bsv-mpc-messagebox/src/engineio/codec.rs`,
re-runs the existing native + new wasm32 tests, and proves the move
is byte-identical. No public API change yet; this is the foundation
for the next four sub-gates (transport split, native unification,
public API consolidation, consumer migration). Each sub-gate lands on
`main` with its own empirical proof before the next begins. Total
estimated work: ~3500-4500 LOC delta (net add ~1500-2000 after
deleting the POC17 directory at the end), one upstream `bsv-rs` PR
for `SocketIoTransport`, six sub-gates (H-4.1 → H-4.6).

## 1. Current state inventory

### 1.1 `crates/bsv-mpc-messagebox/src/` (native-only today)

| File | LOC | Purpose (one line) |
|---|---:|---|
| `lib.rs` | 57 | Crate root + re-exports (`MessageBoxClient`, `MessageBoxAuth`, `subscribe`, etc.). |
| `auth.rs` | 558 | `MessageBoxAuth` — BRC-31 mutual auth wrapper around `bsv-rs::Peer + SimplifiedFetchTransport` + one-shot `/.well-known/auth` for WS upgrade; `brc104` mod with wire helpers. |
| `client.rs` | 743 | Public `MessageBoxClient` API: `new`, `send`, `subscribe`, `acknowledge`, `subscribe_round_messages`, `send_round_message`. |
| `error.rs` | 51 | `MessageBoxError` enum (Http, WebSocket, WsTimeout, Auth, Envelope, Server, Json, Hex, Protocol). |
| `http.rs` | 191 | `POST /sendMessage`, `POST /listMessages`, `POST /acknowledgeMessage` over `Peer::to_peer`. |
| `types.rs` | 149 | Wire request/response structs (`SendMessageRequest`, `ListMessagesRequest`, `AcknowledgeRequest`, `MessagePayload`, box constants `BOX_SIGN`/`BOX_DKG`). |
| `wire.rs` | 195 | Canonical CBOR envelope ↔ MessageBox JSON body wrap/unwrap. |
| `ws.rs` | 948 | Raw-WS `/ws` subscribe with BRC-31-signed upgrade; reconnect+backfill loop. **This is the file native unification deletes.** |
| **Total** | **2892** | |

Tests:
- `tests/live_relay_proof.rs` (666 LOC) — `MESSAGEBOX_RELAY_URL`-gated live integration with two scenarios + typed `MessageBoxClient` round-trip.

### 1.2 `poc/poc17-cf-outbound-ws/src/` (wasm32-proven through H-3.5e)

| File | LOC | Purpose (one line) |
|---|---:|---|
| `lib.rs` | 388 | Worker fetch entry + routes (`/health`, `/open`, `/socketio-connect`, `/brc103-handshake`, `/relay-via-do/*` after H-3.5). |
| `engineio_codec.rs` | 629 | Engine.IO 4 + Socket.IO 5 packet codec — **vendored byte-identical from `bsv-messagebox-cloudflare-public`**, target-agnostic. |
| `socketio_client.rs` | 53 | `SocketIoClient` state-machine type (stub-level public surface; full state lives in `transport_socketio.rs`). |
| `transport_wasm.rs` | 559 | wasm32 substrate: `polling_handshake` (via `worker::Fetch`), `upgrade_to_websocket` + `WsHandle` (via `web_sys::WebSocket`), pump loop. |
| `transport_socketio.rs` | 499 | `SocketIoTransport` impl of `bsv_rs::auth::Transport` over Socket.IO `authMessage` event channel; `run_dispatch` loop. |
| `transport.rs` | 29 | Stub from H-3.1; **delete during migration** — subsumed by `transport_socketio.rs`. |
| `worker_do.rs` | 32 | H-3.5 DO scaffolding (`#[durable_object]` impl after H-3.5e lands). |
| **Total** | **2189** | |

## 2. Cfg-gating shape — **recommendation: Option B (two parallel concrete types, no shared trait initially)**

Three candidates were evaluated:

### Option A — single `MessageBoxClient` struct, internal `#[cfg]`-gated method bodies

Tightest public API; one type-name; downstream consumers don't pivot. But: every method has two cfg branches, the field set diverges (native has `auth: Arc<MessageBoxAuth>`, wasm32 has `do_stub: ObjectNamespace`), and the resulting struct is a `#[cfg]` chimera. High cfg-arithmetic cost for low ergonomic gain.

### Option B — `MessageBoxClient` is a `cfg`-aliased type pointing at one of two parallel impls

```rust
// In lib.rs:
#[cfg(not(target_arch = "wasm32"))]
pub use client_native::MessageBoxClient;
#[cfg(target_arch = "wasm32")]
pub use client_wasm::MessageBoxClient;
```

The two impls share method NAMES + signature shape (caller-visible) but have completely separate field sets + internals. No trait. Downstream code that uses `MessageBoxClient::new(url, priv)` works on both targets without #[cfg] gates. Cost: ~5% method-signature drift risk (two source-of-truth method bodies). **Recommended.**

### Option C — `trait MessageBoxClient { ... }` + two `impl`s

Most type-theoretically clean. But: `bsv_rs::auth::Peer`'s `Transport` trait already requires `Send + Sync`; the wasm32 impl uses a `!Send` shield. Forcing `MessageBoxClient` to be a `dyn Trait` re-introduces the same Send-bound headache that `unsafe impl Send for SocketIoTransport` shields against in `poc17`. Generic `MessageBoxClient<T: Transport>` propagates that generic parameter through every consumer. Rejected.

**Decision: Option B.** Each target's impl owns its own internals; the public surface (method names, return types modulo target-equivalent `Result<T, MessageBoxError>`) stays uniform. Method-drift risk is mitigated by sub-gate H-4.5's empirical contract: both impls must pass the SAME shared `tests/api_surface.rs` test set (compile-only assertions over the public surface).

## 3. `Cargo.toml` + workspace concerns

Files that need editing:

| Cargo.toml | Edit |
|---|---|
| `crates/bsv-mpc-messagebox/Cargo.toml` | Refactor `[dependencies]` into `[target.'cfg(not(target_arch = "wasm32"))'.dependencies]` (tokio, tokio-tungstenite, reqwest) + `[target.'cfg(target_arch = "wasm32")'.dependencies]` (web-sys, wasm-bindgen, wasm-bindgen-futures, js-sys, worker). Add `async-trait`, `getrandom = { version = "0.2", features = ["js"] }` under the wasm32 block. Add `[features]` block: default-features unchanged for native; add `worker` feature toggle for explicit consumer opt-in if needed (audit §2.3 sketch — though `[target]` gating alone should suffice, leaving `[features]` empty is simpler). |
| Workspace root `Cargo.toml` | Add `worker = "0.7"` to `[workspace.dependencies]` (currently only declared in `crates/bsv-mpc-worker/Cargo.toml:18` and `poc/poc17-cf-outbound-ws/Cargo.toml:18`). Add `web-sys`/`wasm-bindgen`/`wasm-bindgen-futures`/`js-sys` workspace declarations so messagebox + worker share versions. |
| `crates/bsv-mpc-worker/Cargo.toml` | Add `bsv-mpc-messagebox = { path = "../bsv-mpc-messagebox" }`. (Worker doesn't currently consume messagebox; Phase I will, but the type-surface check in H-4.5 already exercises wasm32 compilation through worker.) |
| `crates/bsv-mpc-service/Cargo.toml` | No edit — already consumes messagebox; new wire surface is API-compatible. |
| `crates/bsv-mpc-proxy/Cargo.toml` | No edit — doesn't depend on messagebox today; future bridge-via-messagebox is Phase I. |
| `poc/poc17-cf-outbound-ws/Cargo.toml` | DELETE at end of H-4.6 along with the entire `poc/poc17-cf-outbound-ws/` directory. Capture final state in commit message. |

**Per-consumer feature disambiguation:** none required. `bsv-mpc-worker` (wasm32 cdylib) picks the wasm32 impl by target; `bsv-mpc-service` (native bin) picks the native impl. No feature flag pivot needed because `[target.'cfg(...)']` is target-driven, not feature-driven.

## 4. POC files migration map

| POC source | LOC | Destination in `crates/bsv-mpc-messagebox/src/` | Cfg-gate | Changes during move | LOC after |
|---|---:|---|---|---|---:|
| `engineio_codec.rs` | 629 | `engineio/codec.rs` | none (target-agnostic) | Verbatim. Module path moves under `engineio/` mod tree. Re-vendor attribution comment unchanged. | ~629 |
| `socketio_client.rs` | 53 | merge into `engineio/socketio.rs` alongside `transport_socketio.rs` | none | Stub today; absorbed by `SocketIoTransport`'s state. | merged |
| `transport_socketio.rs` | 499 | `transport_socketio.rs` (crate root, target-agnostic) | none — Peer is target-agnostic; the `WsSender` it owns is the cfg'd part | Replace `WsSender` import from `crate::transport_wasm::WsSender` with a target-aliased type. Replace `unsafe impl Send` shield with `#[cfg(target_arch = "wasm32")]`-gated shield only. | ~480 |
| `transport_wasm.rs` | 559 | `transport_wasm.rs` | `#[cfg(target_arch = "wasm32")]` | Polling-handshake's `worker::Fetch` becomes the wasm32-only `relay_fetch`. `WsHandle` + `WsSender` unchanged. Error type unifies to `MessageBoxError::WebSocket(_)`. | ~570 |
| `transport.rs` (POC stub) | 29 | DELETED | — | Subsumed by `transport_socketio.rs`. | 0 |
| `worker_do.rs` | 32 (+ H-3.5 expansion) | NOT migrated in Step 4 | — | Stays in Phase I scope — Step 4 ships transport, not DO ownership. The H-3.5 DO is a POC-only artifact whose lessons feed `bsv-mpc-worker` redesign in Phase I. | 0 in messagebox |
| (NEW) `transport_native.rs` | — | `transport_native.rs` | `#[cfg(not(target_arch = "wasm32"))]` | Native equivalent of `transport_wasm.rs`: `tokio-tungstenite::connect_async` for WS, `reqwest` for the Engine.IO polling handshake. Re-uses the same `engineio_codec` byte-for-byte. New code; ~400 LOC budget. | ~400 |
| (REPLACED) `auth.rs` | 558 | `auth.rs` | none — BRC-103 wraps `bsv_rs::auth::Peer<ProtoWallet, SocketIoTransport>` | DELETE the `brc104` mod's `sign_ws_upgrade` (raw-WS workaround); keep the BRC-31 mutual-auth wrapper for the HTTP routes via SimplifiedFetchTransport. New ~150 LOC of `MessageBoxAuth::initialize_socketio_session` that drives the BRC-103 handshake via SocketIoTransport. | ~350 |
| (REPLACED) `ws.rs` | 948 | DELETED (file removed); replaced by `subscribe.rs` | target-agnostic (cfg-aliased internals) | The raw-WS subscribe loop is gone. New `subscribe.rs` (~300 LOC) drives `joinRoom`/`sendMessage`/`leaveRoom` over the Socket.IO `Peer`-owned channel. Reconnect+backfill via `/listMessages` (HTTP) stays. | ~300 |
| (NEW) `engineio/mod.rs` | — | `engineio/mod.rs` | none | `pub mod codec; pub mod socketio;` | ~10 |

Net delta: roughly `-948 (ws.rs) -210 (auth.rs trim) +400 (transport_native) +300 (subscribe) +1660 (lifted POC) = +1200 LOC`. Crate grows from 2892 → ~4100 LOC.

## 5. Public API consolidation

Today `bsv-mpc-messagebox` re-exports `MessageBoxClient` (typed) + `MessageBoxAuth` (low-level) + `subscribe` (raw `ws.rs` entry). After Step 4 the crate root exposes ONE canonical entry point.

The TS reference at `~/bsv/message-box-client/src/MessageBoxClient.ts` has 30+ public methods; we mirror the subset Phase H needs:

| TS method | Rust equivalent | Notes |
|---|---|---|
| `init(targetHost)` | `MessageBoxClient::new(relay_url, priv)` | Constructor + lazy connection (`initializeConnection` runs on first send/subscribe). |
| `getIdentityKey()` | `MessageBoxClient::identity_hex()` | Public-key hex. |
| `joinRoom(messageBox)` | `MessageBoxClient::subscribe(box)` returns `WsSubscription` | Subscribe-as-join semantics. |
| `listenForLiveMessages({ messageBox, onMessage })` | `WsSubscription::next()` stream | Consumer-pulled stream rather than callback. |
| `sendLiveMessage({ recipient, messageBox, body })` | `MessageBoxClient::send(recipient, box, envelope)` | Same wire shape; canonical envelope already wrapped. |
| `leaveRoom(messageBox)` | `WsSubscription::leave(box)` | Single subscription owns multiple rooms. |
| `disconnectWebSocket()` | `WsSubscription::shutdown()` | Already present. |
| `listMessages({ messageBox })` | `MessageBoxClient::list_messages(box)` | Backfill path; already present. |
| `acknowledgeMessage({ messageIds })` | `MessageBoxClient::acknowledge(ids)` | Already present. |

Public surface after Step 4 (`crates/bsv-mpc-messagebox/src/lib.rs`):

```rust
pub use client::{
    DecodedEnvelope, DecodedRoundMessage,
    EnvelopeSubscription, MessageBoxClient,    // ← canonical entry
    RoundMessageSubscription,
};
pub use error::{MessageBoxError, Result};
pub use types::{BOX_SIGN, BOX_DKG, ...};
// REMOVED: pub use ws::{subscribe, InboundEnvelopeEvent, InboundVia, WsSubscription};
// REPLACED with subscription handle types re-exported through `client`.
// REMOVED: pub use auth::MessageBoxAuth — auth becomes internal.
```

`MessageBoxAuth` becomes a crate-internal helper; consumers go through `MessageBoxClient` exclusively. This is a breaking change to the public surface (live_relay_proof.rs:35 uses `MessageBoxAuth::new` directly) — but `MessageBoxClient::new` covers every direct `MessageBoxAuth` use in the workspace (verified via grep). Migration of `live_relay_proof.rs` is in scope for H-4.5.

## 6. `bsv-mpc-worker` + `bsv-mpc-proxy` integration

Grep verifies (`grep -rn "bsv_mpc_messagebox" crates/`):

- `bsv-mpc-service/src/messagebox.rs` uses `MessageBoxClient`, `DecodedRoundMessage`, `RoundMessageSubscription`, `InboundVia` — all preserved.
- `bsv-mpc-service/src/signing_handler.rs`, `dkg_handler.rs` use `DecodedRoundMessage` + `BOX_SIGN`/`BOX_DKG` constants — all preserved.
- `bsv-mpc-service/tests/*_e2e.rs` use `MessageBoxClient` — preserved.
- `bsv-mpc-messagebox/tests/live_relay_proof.rs` uses `MessageBoxAuth::new` + `MessageBoxClient::new` — `MessageBoxAuth::new` use must be rewritten to `MessageBoxClient::new` (H-4.5 deliverable).
- `bsv-mpc-worker/`: no current import. Phase I adds one — out of Step 4 scope.
- `bsv-mpc-proxy/`: no current import. Phase I may add — out of scope.

**Migration plan:** `MessageBoxClient::new` signature is **already API-stable** (`relay_url: impl Into<String>, our_priv: PrivateKey`). No call-site rewrites needed in `bsv-mpc-service`. The only call-site delta is in `live_relay_proof.rs` — `MessageBoxAuth::new` → `MessageBoxClient::new` (plus stripping the now-irrelevant raw `MessageBoxAuth::peer()` accessor uses if any; verify in H-4.5).

## 7. Sub-gate breakdown — Step 4 into 6 commits

Each commit lands on `main` with its own empirical proof, mirroring H-3.3b/H-3.5a-e style. NO `--no-verify`. Each gate's empirical proof goes in the commit message body. `cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets -- -D warnings` clean before push.

| Gate | Scope | Empirical proof |
|---|---|---|
| **H-4.1** | Lift `engineio_codec.rs` into `crates/bsv-mpc-messagebox/src/engineio/codec.rs` byte-identical; add `engineio` mod tree. NO target gates yet — pure source-move. Re-run POC17's codec unit tests against the new path. | `cargo test -p bsv-mpc-messagebox engineio` runs the migrated tests (≥10 tests, all green); `diff poc/poc17-cf-outbound-ws/src/engineio_codec.rs crates/bsv-mpc-messagebox/src/engineio/codec.rs` shows only header attribution diff if any. |
| **H-4.2** | Add wasm32 cfg-gating + `transport_wasm.rs` + `transport_socketio.rs` to the crate, gated `#[cfg(target_arch = "wasm32")]`. NO public API change yet; native build is undisturbed. | `cargo build --target wasm32-unknown-unknown -p bsv-mpc-messagebox` clean; `cargo build -p bsv-mpc-messagebox` (native) clean. `cargo test -p bsv-mpc-messagebox` native tests still green (no regression). |
| **H-4.3** | Add `transport_native.rs` — Socket.IO + BRC-103 over `tokio-tungstenite` + `reqwest` on native. Mirrors `transport_wasm.rs` shape with native primitives. Codec is shared (H-4.1 outcome). No consumer-facing changes yet. | `cargo test -p bsv-mpc-messagebox transport_native` covers ≥5 unit tests + 1 ignored live-relay integration test that, when run with `MESSAGEBOX_RELAY_URL` set, drives a full Engine.IO polling-handshake → WS upgrade → BRC-103 InitialRequest → InitialResponse cycle through the native stack and prints the relay's `server_identity` hex. |
| **H-4.4** | **Native unification merge.** Replace `ws.rs` (948 LOC raw-WS) and `auth.rs::sign_ws_upgrade` with new `subscribe.rs` driving `bsv_rs::auth::Peer<ProtoWallet, SocketIoTransport>` over `transport_native`. Delete `ws.rs`. `MessageBoxClient::send/subscribe/acknowledge` keep their signatures but new internals. | `cargo test -p bsv-mpc-messagebox --test live_relay_proof -- --nocapture` against `MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev` shows the SAME 3 scenarios green (`MessageBoxAuth`-direct test rewritten to `MessageBoxClient`-only). `wrk-tail` of the relay shows `/socket.io/*` traffic, NOT `/ws` traffic — proving the wire shape switch. |
| **H-4.5** | Public API consolidation. Remove `pub use auth::MessageBoxAuth` from `lib.rs`; rewrite `live_relay_proof.rs` to use `MessageBoxClient` exclusively. Add `tests/api_surface.rs` (compile-only) asserting method-name parity across native + wasm32 cfg-branches. | `cargo test -p bsv-mpc-messagebox` green on native; `wasm-pack test --node crates/bsv-mpc-messagebox` runs the wasm32 portion of `api_surface.rs` green (the wasm32 paths compile + the type-level assertions pass). |
| **H-4.6** | **The Step 4 merge gate.** Delete `poc/poc17-cf-outbound-ws/` entirely. Remove it from the workspace `members =` list. Update `STATUS.md`, `EXECUTION-PLAN.md`, `POCS.md` to mark POC17 as graduated. File the upstream `SocketIoTransport` PR to `bsv-rs`. | Workspace `cargo build --workspace --all-targets` clean (proves no orphaned reference to `poc17-cf-outbound-ws`). `bsv-rs` PR URL recorded in commit message. `git log --diff-filter=D --summary` shows `poc/poc17-cf-outbound-ws/` deletion in the commit. |

## 8. Test strategy

### 8.1 Unit (every new module gets ≥3 tests)

- `engineio/codec.rs`: encode/decode round-trip for each Engine.IO type code (open/close/ping/pong/message/upgrade/noop); Socket.IO EVENT serialize; record-separator multi-packet decode. ≥12 tests (inherits POC17 coverage).
- `transport_native.rs`: polling-handshake parses `Open` packet; WS upgrade send/recv loop drives a probe/pong correctly against a mock TCP server; reconnect retries with backoff.
- `transport_socketio.rs`: `Transport::send` emits exactly `2["authMessage",<json>]` on the wire; `Transport::set_callback` invokes on inbound `authMessage` events; non-`authMessage` events are silently ignored.
- `subscribe.rs`: `joinRoom` emits the correct Socket.IO EVENT; inbound `sendMessage` maps to the same `DecodedEnvelope` shape today's `ws.rs` produces (regression).
- `auth.rs` (trimmed): `MessageBoxAuth::new` rejects malformed priv; `initialize_socketio_session` round-trips through a stubbed transport.

### 8.2 Vector tests (byte-exact fixtures)

Carry forward `transport_socketio.rs:tests` from POC17 (the byte-exact `authMessage` JSON fixture vs canonical TS) and expand:
- `tests/wire_vectors.rs`: pinned hex bytes for Engine.IO Open, Engine.IO Message-with-Socket.IO-CONNECT, Socket.IO EVENT with `authMessage` payload, BRC-103 `InitialRequest`/`InitialResponse` envelopes. These vectors must decode identically against the canonical TS reference output (frozen now from a recorded H-3.3b transcript).

### 8.3 E2E

- **Native:** `cargo test -p bsv-mpc-messagebox --test live_relay_proof -- --nocapture` with `MESSAGEBOX_RELAY_URL` set to the live Calhoun relay. Runs the three scenarios in `live_relay_proof.rs` (handshake, send/list/ack, typed `MessageBoxClient` round-trip).
- **wasm32:** `wasm-pack test --node crates/bsv-mpc-messagebox` against the same relay. The deployed `poc17` worker stays green as a parallel cosigner-side e2e harness through H-4.5; deleted in H-4.6 only after the in-crate wasm32 e2e is proven.
- **bsv-mpc-service E2E:** `cargo test -p bsv-mpc-service --test dkg_via_messagebox_e2e -- --nocapture` and `messagebox_listener_e2e.rs` MUST stay green throughout — they're the regression net for the consumer-facing API.

### 8.4 Real sats

Step 4 doesn't burn sats. Its OUTPUT (proven native + wasm32 transports on identical wire) is the precondition for Phase H Step 5's mainnet TXID gate (G-5d shape `442bd391…` — 2-of-2 DKG + sign + broadcast through the new Socket.IO native path). The H-3.5 deployed-worker forced-hibernation transcript stays committed as Step 3's mainnet-adjacent proof; Step 5 adds the real-sats burn.

## 9. Risks + mitigations

### R1 — cfg-gating subtleties around tokio's feature flags

| | Detail |
|---|---|
| **What** | Today's `Cargo.toml:20-21` has `tokio.workspace = true` + `reqwest.workspace = true` unconditional. Moving these under `[target.'cfg(not(target_arch = "wasm32"))']` may break the workspace's resolver-2 unification if some other crate also pulls tokio with a different feature set. |
| **Mitigation** | H-4.2's empirical bar includes BOTH native `cargo build -p bsv-mpc-messagebox` AND `cargo build --workspace --all-targets` — the latter catches workspace-wide resolver mismatches. Workspace-level `tokio` feature set already pins `["full"]` in root `Cargo.toml:49`; the per-target unification should be a no-op. |

### R2 — `cargo build --workspace --all-targets` straddles both targets and may fail on conflicting deps

| | Detail |
|---|---|
| **What** | `--all-targets` includes the wasm32 cdylib in `bsv-mpc-worker`. If messagebox's wasm32 deps conflict with worker's, the workspace build breaks. |
| **Mitigation** | The POC17 directory has already proven this exact dep set (web-sys, wasm-bindgen, worker = "0.7") coexists with the workspace; H-4.2 reuses it byte-identical. Worker-level `Cargo.toml` already declares `worker = "0.7"` + `getrandom = { features = ["js"] }`; no version skew. |

### R3 — `bsv-mpc-worker`'s existing wasm32 build path may conflict with messagebox's new wasm32 surface

| | Detail |
|---|---|
| **What** | `bsv-mpc-worker` is `cdylib`-only today, doesn't depend on messagebox. Adding messagebox as a worker dep (Phase I, but H-4.5's api_surface.rs may need it for wasm32 test coverage) could expose dep-resolution issues. |
| **Mitigation** | Step 4 does NOT add messagebox to `bsv-mpc-worker` as a runtime dep. wasm32 test coverage uses `wasm-pack test --node` directly against `bsv-mpc-messagebox` (the crate has `crate-type = ["rlib"]` by default; wasm-pack handles the cdylib wrapping for tests). Phase I deals with the worker integration. |

### R4 — POC17's `unsafe impl Send + Sync` shield doesn't translate cleanly to native

| | Detail |
|---|---|
| **What** | `transport_socketio.rs` in POC17 has `unsafe impl Send + Sync for SocketIoTransport` to satisfy `bsv_rs::auth::Transport`'s `Send + Sync` bound on a `!Send` `web_sys::WebSocket`. On native, `tokio-tungstenite`'s `WebSocketStream` IS `Send + Sync`, so the shield should be cfg-gated to wasm32 only. |
| **Mitigation** | Sub-gate H-4.3's transport_native uses real `Send + Sync` types; the unsafe shield in transport_socketio is `#[cfg(target_arch = "wasm32")]`-gated. Clippy `-D warnings` catches unintended unsafe propagation. |

### R5 — `bsv-rs` upstream PR for `SocketIoTransport` is a critical-path dep on a foreign repo

| | Detail |
|---|---|
| **What** | Per audit §11.5: "`SocketIoTransport` filed upstream as a PR to `bsv-rs` … PR open and either merged or assigned for review before Phase H merges." If upstream review stalls, Phase H merge stalls. |
| **Mitigation** | bsv-rs is Calhoun-controlled (`docs/PHASE-H-AUDIT.md:1006`). H-4.6 ships the PR; intermediate sub-gates use a local `[patch.crates-io]` override (already the standard workspace pattern at root `Cargo.toml:165-169` for cggmp24). If PR doesn't merge by Phase H Step 5, the `[patch]` ships in `main` as a documented temporary state. |

## 10. Out of scope for Step 4

1. **Phase I cosigner state machine.** Step 4 only migrates TRANSPORT; the MPC ceremony state machines (`bsv-mpc-service::messagebox::MessageBoxListener` orchestration, DKG/signing handlers) remain untouched. Their consumer-side API (`MessageBoxClient::send`, `subscribe_round_messages`) is preserved.
2. **`bsv-mpc-worker` DO integration.** The H-3.5 DO scaffolding stays in POC17 until H-4.6's deletion, at which point its lessons inform Phase I's `bsv-mpc-worker` redesign. Step 4 does NOT carry the DO over to messagebox or worker.
3. **Multi-room subscribe.** POC scope (audit §6.3) carries forward — single-room subscribe per `WsSubscription`. Phase I adds `joinRoom`/`leaveRoom` on a single long-lived subscription.
4. **FCM push transport.** §06.4 lists FCM for mobile profile; Step 4 keeps WS + HTTP only. FCM is a Phase J item.
5. **CHIP token discovery.** `MessageBoxClient::new(relay_url, …)` keeps the explicit `relay_url`; SHIP/SLAP overlay discovery on `tm_mpc_signing` topic lives in `bsv-mpc-overlay` and is consumed by callers.
6. **Per-cosigner key derivation.** All consumers pass their priv directly. DKG-output-derived per-cosigner privs are Phase I.
7. **Cross-stack readiness probe against Binary's TS server.** Audit §11.5 §7.4 lists this as the Phase H merge gate (Step 5), not Step 4. Step 4's deliverable enables it.

## 11. Open questions before Step 4 implementation can start

1. **Native unification sequencing — strict serial (H-4.4 before H-4.5) or parallel?** Recommended: strict serial. H-4.4 deletes 948 LOC of `ws.rs`; H-4.5 changes the public re-export surface. Mixing them in a single commit makes regressions hard to bisect.
2. **Keep `MessageBoxAuth` as a `pub(crate)` helper or fully internalize?** Recommended: `pub(crate)`. `MessageBoxClient::auth()` accessor at `client.rs:198` is currently `pub`; keeping it as a private helper means rewriting one external use (`live_relay_proof.rs`) without losing escape-hatch capability for ad-hoc debugging.
3. **`bsv-rs::SocketIoTransport` upstream PR — file before or after H-4.6?** Recommended: file at H-4.3 (when native impl is ready and proven against the live relay). Gives upstream the maximum review window before Step 4 closes.
4. **Should H-4.4 also migrate `bsv-mpc-service`'s `messagebox.rs` listener?** Recommended: no. The listener consumes `MessageBoxClient`'s public API only; if the API stays stable, the listener stays untouched. Audit at H-4.5 that no `bsv-mpc-service` source file changed.
5. **`wasm-pack test --node` integration with the workspace — separate target dir to avoid clobbering native cache?** Recommended: yes — add `CARGO_TARGET_DIR=target/wasm-test` to the wasm-pack invocation in the H-4.5 commit's empirical proof block. The pattern matches Phase G's `wasm32_dkg.rs` discipline.

## 12. Locked discipline (carried forward from H-3.5)

* 5-step workflow per phase. Step 4 has 6 sub-gates (H-4.1 → H-4.6), each its own commit.
* Each sub-gate's commit lands on `main` BEFORE the next gate begins.
* `cd ~/bsv/mpc/bsv-mpc/` for all commits (NEVER `bsv-mpc-old-unscrubbed/`).
* 110%-no-asterisks: every commit's gate must be empirically verified before the commit lands.
* `cargo fmt --all -- --check` AND `cargo clippy --workspace --all-targets -- -D warnings` clean before push.
* Pure Rust+WASM (audit §11.2 revised). No JS bundle.
* Path A: implementation conforms to canonical TS (`@bsv/message-box-client` v2.0.7 / `@bsv/authsocket-client` v2.0.7), never the inverse.
* god-tier + full-stack awareness — consult `~/bsv/bsv-rs/`, `~/bsv/bsv-messagebox-cloudflare-public/`, `~/bsv/message-box-client/`, `~/bsv/authsocket-client/` before proposing fixes.

## 13. Critical references — in suggested reading order

1. **`docs/PHASE-H-AUDIT.md` §11.3-11.5** — locked decisions on native unification + amended Phase H scope + revised merge gate.
2. **`docs/H-3-5-PLAN.md`** — the plan-format this file mirrors; also documents the DO that Step 4 does NOT carry over.
3. **`docs/HANDOFF-PHASE-H-3-3B.md`** — gold-standard sub-gate empirical-proof discipline.
4. **`crates/bsv-mpc-messagebox/src/auth.rs` + `client.rs` + `ws.rs`** — the native substrate being unified.
5. **`poc/poc17-cf-outbound-ws/src/transport_socketio.rs` + `transport_wasm.rs` + `engineio_codec.rs`** — the wasm32 substrate being lifted.
6. **`~/bsv/bsv-rs/src/auth/transports/`** — where `SocketIoTransport` lands upstream.
7. **`~/bsv/message-box-client/src/MessageBoxClient.ts`** — canonical TS API surface (public-method parity reference).
8. **`~/bsv/authsocket-client/src/AuthSocketClient.ts`** — canonical TS Socket.IO + BRC-103 wire pattern.
9. **`~/bsv/bsv-messagebox-cloudflare-public/src/engineio/auth.rs`** — server-side BRC-103 state machine; structural reference for the client side.

---

**Live MessageBox relay:** `https://rust-message-box.dev-a3e.workers.dev`
**Empirical bar for Step 4 (merge):** see §7 H-4.6 — workspace `cargo build --workspace --all-targets` clean after POC17 deletion + `bsv-rs::SocketIoTransport` upstream PR open + live_relay_proof.rs green with `MessageBoxClient`-only API + `wasm-pack test --node` green.
