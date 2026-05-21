# Handoff — Phase H Step 4, pickup at H-4.3

> For the next Claude session continuing Phase H Step 4 (native
> unification of `bsv-mpc-messagebox` onto Socket.IO + BRC-103). Read
> this + `docs/H-STEP-4-PLAN.md` + `docs/H-STEP-4-CONSUMER-MAP.md`
> first.
>
> **Status:** Step 3 fully closed. Step 4 sub-gates H-4.1 + H-4.2 green
> on `main`. Pick up at **H-4.3**.

## TL;DR — the next concrete action

**Sub-gate H-4.3**: port `transport_wasm.rs` + `transport_socketio.rs`
from `poc/poc17-cf-outbound-ws/src/` into `crates/bsv-mpc-messagebox/src/`
under `#[cfg(target_arch = "wasm32")]`, AND write a new
`transport_native.rs` (Socket.IO + BRC-103 over `tokio-tungstenite` +
`reqwest`) under `#[cfg(not(target_arch = "wasm32"))]`, both sharing the
already-lifted `crate::engineio::codec`. File the bsv-rs
`SocketIoTransport` upstream PR at the end of H-4.3 (OQ4.3 default).

The crate is ALREADY dual-target as of H-4.2 — `cargo build --target
wasm32-unknown-unknown -p bsv-mpc-messagebox` compiles the
target-agnostic core (engineio/error/types/wire). H-4.3 adds the
transport layer on both targets.

## What's done (this session, 2026-05-19 → 2026-05-20)

### Phase H Step 3 — CLOSED (all 8 sub-gates green + CI + tracker)

| Gate | Commit | Proof |
|---|---|---|
| H-3.1 | `cb923fc` | wasm32 build clean |
| H-3.2a/b | `bc8b0b4`/`6ff1a53` | Engine.IO polling + WS upgrade |
| H-3.3a | `0073e43` | Socket.IO CONNECT 51ms |
| H-3.3b (A/B/C) | `7d6b3a1`/`e725b38`/`358f121` | BRC-103 mutual auth, 49ms |
| H-3.4 (A/B/C) | `53931b2`/`fc8c738`/`bcce827` | envelope round-trip, `ack_message_id_matches_sent:true` |
| H-3.5 (a-e) | `f423ae0`/`d77765b`/`3c3bdcd`/`9141044`/`7a1f8e3` | DO hibernation: idled 138.3s, identity byte-identical |

GitHub tracker #3: Steps 1-3 ticked, OQ6 resolved, evidence comment posted.

### Phase H Step 4 — IN PROGRESS (2 of 6 gates)

| Gate | Commit | Proof |
|---|---|---|
| H-4.1 codec lift | `112fcbf` | codec → `engineio/codec.rs` byte-identical, 23 tests |
| consumer map | `594288b` | `docs/H-STEP-4-CONSUMER-MAP.md` |
| H-4.2 dual-target cfg | `d3d264e` | wasm32 build of crate now compiles |

### bsv-rs upstream — 2 releases PUBLISHED to crates.io

- **v0.3.8** (Calhooon/bsv-rs#2 merged) — `Peer::initiate_handshake`'s
  `tokio::time::timeout` → cfg-gated `futures-timer::Delay` on wasm32.
- **v0.3.9** (Calhooon/bsv-rs#3 merged) — `SystemTime::now()` →
  cfg-gated `js_sys::Date::now()` on wasm32 (8 production call sites).
- Workspace + poc17 already on `bsv-rs 0.3.9`.

## Current crate state — `crates/bsv-mpc-messagebox/`

```
src/
  lib.rs          — target-agnostic mods (engineio/error/types/wire) +
                    #[cfg(not(wasm32))] native mods (auth/client/http/ws)
  engineio/
    mod.rs        — pub mod codec;
    codec.rs      — Engine.IO + Socket.IO codec (target-agnostic, 23 tests) [H-4.1]
  error.rs        — target-agnostic
  types.rs        — target-agnostic (wire request/response structs)
  wire.rs         — target-agnostic (CBOR envelope ↔ MessageBox JSON)
  auth.rs         — NATIVE-ONLY: MessageBoxAuth (Peer + SimplifiedFetchTransport)
  client.rs       — NATIVE-ONLY: MessageBoxClient public API
  http.rs         — NATIVE-ONLY: POST sendMessage/listMessages/acknowledge
  ws.rs           — NATIVE-ONLY: raw-WS subscribe (948 LOC — DELETED in H-4.4)
tests/
  live_relay_proof.rs — the e2e gate (MESSAGEBOX_RELAY_URL-gated)
Cargo.toml        — 3 tiers: [dependencies] target-agnostic;
                    [target.'cfg(not(wasm32))'] native (tokio/reqwest/
                    tokio-tungstenite/chrono/bsv[auth,http]);
                    [target.'cfg(wasm32)'] wasm (worker/web-sys/wasm-bindgen/
                    js-sys/getrandom[js]/bsv[auth,wallet,transaction,wasm])
```

## H-4.3 → H-4.6 plan (with CORRECTIONS from the consumer map)

### H-4.3 — transport modules (native + wasm32) + bsv-rs PR

Port from `poc/poc17-cf-outbound-ws/src/`:
- `transport_wasm.rs` (559 LOC, wasm32-only) → `transport_wasm.rs`
  under `#[cfg(target_arch = "wasm32")]`. Uses `web_sys::WebSocket` +
  `worker::Fetch`. Has `WsHandle`, `WsSender`, `polling_handshake`,
  `upgrade_to_websocket`.
- `transport_socketio.rs` (~580 LOC after H-3.4) → `transport_socketio.rs`.
  `SocketIoTransport` (impl `bsv_rs::auth::Transport`), `AppEvent`,
  `parse_app_event_payload`, `build_envelope_payload`,
  `emit_signed_general`, `install_app_event_listener`, `run_dispatch`.
  Update the `use crate::engineio_codec::...` imports to
  `use crate::engineio::codec::...`. The `unsafe impl Send/Sync` shield
  stays `#[cfg(target_arch = "wasm32")]`-gated.
- **NEW** `transport_native.rs` under `#[cfg(not(wasm32))]`:
  `tokio-tungstenite::connect_async` for the WS, `reqwest` for the
  Engine.IO polling handshake. Mirror the `transport_wasm` method
  surface (`WsHandle`/`WsSender`/`polling_handshake`/upgrade dance) but
  with native primitives. Shares `crate::engineio::codec` byte-for-byte.
  ~400 LOC budget.
- **bsv-rs PR**: extract `SocketIoTransport` to
  `~/bsv/bsv-rs/src/auth/transports/socketio.rs`, file PR to
  Calhooon/bsv-rs. Worktree-isolated agent; admin-merge after CI green
  (Benchmark Regression Check is non-blocking, same as #2/#3). This is
  the audit §11.5 merge-gate precondition.

Empirical: `cargo build --target wasm32-unknown-unknown -p
bsv-mpc-messagebox` clean (now WITH transport_wasm + transport_socketio);
native build clean; `cargo test transport_native` unit tests + 1
`#[ignore]` live-relay integration test that drives the full native
handshake + prints `server_identity`.

### H-4.4 — native unification merge (BIGGEST + RISKIEST)

Replace `ws.rs` (948 LOC raw-WS) + `auth.rs::sign_ws_upgrade` with a
new `subscribe.rs` driving `bsv_rs::auth::Peer<ProtoWallet,
SocketIoTransport>` over `transport_native`. `MessageBoxClient::{send,
subscribe,acknowledge,subscribe_round_messages,send_round_message}` keep
their EXACT signatures (see consumer map "PRESERVE THESE SIGNATURES").

**CRITICAL per consumer map**: `live_relay_proof.rs:226,322` calls raw
`ws::subscribe(auth, vec![BOX_SIGN])`. Either (a) keep `ws::subscribe`
as a Socket.IO-backed shim re-export, or (b) migrate those test call
sites to `MessageBoxClient::subscribe`. `InboundEnvelopeEvent` (5
fields), `InboundVia` (WsPush/Backfill), `WsSubscription` layouts must
stay byte-stable.

Empirical: `MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev
cargo test -p bsv-mpc-messagebox --test live_relay_proof -- --ignored
--nocapture` — all 3 scenarios green. Relay traffic is `/socket.io/*`
not `/ws` (the wire-shape switch). Also keep `bsv-mpc-service` e2e tests
green (`dkg_via_messagebox_e2e`, `messagebox_listener_e2e`,
`sign_mainnet_via_messagebox_e2e`).

### H-4.5 — API consolidation [CORRECTED]

**DO NOT make `MessageBoxAuth` `pub(crate)`** — the consumer map proved
it has live consumers in `live_relay_proof.rs` (`::new`/`::start`/
`::identity_hex`) + `ws::subscribe` takes `Arc<MessageBoxAuth>`. KEEP
`pub use auth::MessageBoxAuth`; refactor internals only. Add
`tests/api_surface.rs` (compile-only) asserting `MessageBoxClient`
method-name parity across native + wasm32 cfg branches.

Empirical: native `cargo test` green; `CARGO_TARGET_DIR=target/wasm-test
wasm-pack test --node crates/bsv-mpc-messagebox` green (OQ4.5 isolated
target dir).

### H-4.6 — MERGE GATE

Delete `poc/poc17-cf-outbound-ws/` entirely + remove from workspace
`members`. Update `STATUS.md`/`EXECUTION-PLAN.md`/`POCS.md`. Confirm
bsv-rs `SocketIoTransport` PR open-or-merged. Tick tracker #3 Step 4 box.

Empirical: `cargo build --workspace --all-targets` clean (no orphan
poc17 ref); `git log --diff-filter=D` shows poc17 deletion.

## Step 5 (after Step 4) — the real-sats merge gate

Per audit §11.5: a fresh native real-sats mainnet TXID through the
unified Socket.IO + BRC-103 path, DER + joint-pubkey shape matching
G-5d's `442bd391cf8eda299f82dc1e4aeb1a9cb4f33610365d44c9c1c0e55d32f171b9`.
Wallet at `localhost:3321` (Origin: `http://admin.com`) is the funding
source. ~100 sats. Plus the cross-stack readiness probe against
Binary's TS `message-box-server`.

## Locked discipline (carry forward)

- **110% no asterisks**: every commit's gate empirically verified before
  push. `cargo fmt --all -- --check` + `cargo clippy --workspace
  --all-targets -- -D warnings` + `cargo test` + the gate's proof.
- Each sub-gate's commit lands on `main` BEFORE the next begins.
- `cd ~/bsv/mpc/bsv-mpc/` for commits (NEVER `bsv-mpc-old-unscrubbed/`).
- Pure Rust + WASM (audit §11.2). No JS bundle.
- Path A: conform to canonical TS (`@bsv/message-box-client` v2.0.7 /
  `@bsv/authsocket-client`), never the inverse.
  [[feedback_canonical_ts_immutable]]
- god-tier + full-stack: consult `~/bsv/` reference stack
  (`bsv-rs`, `bsv-messagebox-cloudflare-public`, `message-box-client`,
  `authsocket-client`, `agents`) before proposing fixes. Never
  recommend pragmatic-today / workaround when a real fix is reachable —
  this session fixed 2 wasm32 bugs upstream in bsv-rs rather than
  working around them. [[feedback_god_tier_full_stack]]
- **Swarm + orchestrate**: spawn parallel Explore/Plan agents for
  research (consumer maps, API surveys) + worktree-isolated
  general-purpose agents for the bsv-rs upstream PRs. Verify their
  output — they describe intent, not necessarily what they did.

## Deploy harness (for any wasm32 e2e — H-4.5 wasm-pack uses node, not deploy)

- CF auth: `eval "$(grep '^export CLOUDFLARE' ~/bsv/mpc/bsv-mpc/secrets.md)"`
  — sets `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID`. **secrets.md
  is gitignored — NEVER commit it; redact tokens from all output via
  `sed -E 's/[a-f0-9]{16,}/<redacted>/g'`.**
- Calhoun dev account_id: `ea3e6d176ed3893258fe34281f710c7f`.
- Deployed POC worker: `https://poc17-cf-outbound-ws.dev-a3e.workers.dev`
  (DELETED in H-4.6; the wasm32 e2e moves to `wasm-pack test --node`).
- `SERVER_PRIVATE_KEY` secret is set on that worker (fresh throwaway
  priv, lives only in CF secret store).
- `wrangler.toml` is gitignored (contains account_id); committed
  template is `wrangler.example.toml`. Pre-commit hook
  `.git/hooks/pre-commit:5` substring-matches `wrangler\.toml`.

## Auth note (gh)

`git push` to `B1nary-Calhoun-Partnership/bsv-mpc` + `Calhooon/bsv-rs`
requires the `Calgooon` gh account active (`gh auth switch -u Calgooon`).
The `jcalhoun-trifinlabs` account lacks push perms. bsv-rs remote is
HTTPS (flipped from SSH this session — SSH key not authorized).

## Critical references (read in order)

1. `docs/H-STEP-4-PLAN.md` — the 6-sub-gate plan (note: OQ4.2
   `pub(crate)` default is OVERRIDDEN by the consumer map — keep
   MessageBoxAuth public).
2. `docs/H-STEP-4-CONSUMER-MAP.md` — PRESERVE-THESE-SIGNATURES contract +
   call-site table + the H-4.5 correction.
3. `docs/PHASE-H-AUDIT.md` §11.3 (native unification) + §11.4 (scope) +
   §11.5 (Step 5 merge gate).
4. `poc/poc17-cf-outbound-ws/src/{transport_wasm,transport_socketio}.rs`
   — the wasm32 substrate to port (H-4.3 source).
5. `crates/bsv-mpc-messagebox/src/{ws,auth,client}.rs` — the native
   substrate being unified (H-4.4 target).
6. `~/bsv/bsv-rs/src/auth/transports/` — where `SocketIoTransport` lands
   upstream (H-4.3 PR).
7. `~/bsv/bsv-messagebox-cloudflare-public/src/message_hub.rs:952-998`
   — server-side sendMessage envelope shape (`{messageBox, message:
   {messageId, recipient, body}}`; server builds `roomId =
   {identity}-{messageBox}`). The `ClientSendMessage` struct is at
   `:143-149`.
8. GitHub tracker #3 (Phase H) + #2 (umbrella).

## What I am NOT doing in this handoff

- Starting H-4.3 (next session's work).
- Touching `crates/bsv-mpc-messagebox/src/{ws,auth,client}.rs` (H-4.4).
- Filing the bsv-rs `SocketIoTransport` PR (H-4.3).

---

**Last green commit on main:** `d3d264e` (H-4.2).
**bsv-rs:** 0.3.9 published.
**All session commits CI-green.**
**Working tree:** clean. No orphan processes. Port 8787 free.
