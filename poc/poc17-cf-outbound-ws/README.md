# POC 17 — Phase H Step 3: pure-Rust Engine.IO + Socket.IO client + BRC-103 transport

> Phase H POC per `docs/PHASE-H-AUDIT.md` §2.5b + §11 + §11.2 revised.
> Validates the pure-Rust+WASM substrate for the wasm32 MessageBox
> client. Lands on `main` per the 5-step phase workflow BEFORE H-4
> implementation begins.

## What this POC proves

Five hard gates per audit §6.2 (§2.5b-rewritten + §11.2 revised):

| Gate | What it proves | Pass criterion |
|---|---|---|
| **H-3.1** | wasm32 build clean | `cargo build --target wasm32-unknown-unknown -p poc17-cf-outbound-ws` clean. **THIS COMMIT.** |
| **H-3.2** | Socket.IO handshake from CF DO via pure-Rust client | `wrangler dev` test: DO `fetch /open` → polling GET to live `/socket.io/` → 200 + Engine.IO handshake JSON; WS upgrade within 5s. **Subsequent commit.** |
| **H-3.3** | BRC-103 mutual auth over `authMessage` | new `SocketIoTransport` drives `bsv_rs::auth::Peer` through `InitialRequest → InitialResponse`; channel identity-bound. **Subsequent commit.** |
| **H-3.4** | Canonical envelope round-trip | POST `/relay` to DO; DO `emit('sendMessage', envelope)`; DO receives echo on `sendMessage` event from own subscribed room; body byte-identical. **Subsequent commit.** |
| **H-3.5** | Forced-hibernation reconnect | `state.abort()` evicts DO; next fetch wakes; Socket.IO re-handshakes; `/listMessages` backfill recovers missed envelope. **Subsequent commit.** |

## Substrate (per audit §11.2 revised)

**Pure Rust+WASM.** No JS deps for the client.

- **Vendored codec**: [`src/engineio_codec.rs`](src/engineio_codec.rs) is byte-identical to `~/bsv/bsv-messagebox-cloudflare-public/src/engineio/codec.rs` (MIT, © Calhooon Contributors). Direction-agnostic Engine.IO v4 + Socket.IO v5 packet encode/decode.
- **Rust client**: [`src/socketio_client.rs`](src/socketio_client.rs) state machine + emit/on event layer over the codec.
- **wasm32 transport substrate**: `worker::Fetch` (Engine.IO polling phase) + `web_sys::WebSocket` (WS upgrade phase). Native counterpart (`reqwest` + `tokio-tungstenite`) lives in `crates/bsv-mpc-messagebox/` once the POC graduates.
- **BRC-103 transport**: [`src/transport.rs`](src/transport.rs) wraps the client's `authMessage` event channel into `bsv_rs::auth::Transport`. Lands upstream in `bsv-rs` per audit §11.2.

## Run

### H-3.1 (this commit) — wasm32 build

```bash
cargo build --target wasm32-unknown-unknown -p poc17-cf-outbound-ws
```

Expected: clean build, no warnings, no link errors. Verifies that the
vendored codec + bsv-rs (with `auth + wallet + transaction + wasm`
features) + `web_sys::WebSocket` + `worker` 0.7 all coexist on wasm32.

### H-3.2 and beyond — local dev

```bash
cp wrangler.example.toml wrangler.toml
# Fill in account_id + run `wrangler secret put SERVER_PRIVATE_KEY`
# with a one-shot identity priv (openssl rand -hex 32).
wrangler dev
# In another terminal:
curl http://localhost:8787/open
# Expected (H-3.2): {"socketio_status":"connected","sid":"...","upgrade_target":"websocket"}
```

### H-3.5 — forced hibernation

```bash
wrangler dev
curl -X POST http://localhost:8787/relay -d '<envelope_hex>'
# (force-evict DO via wrangler's local-dev tooling — TBD)
curl http://localhost:8787/poll
# Expected: missed envelope appears
```

## What this POC does NOT do

- Full `MessageBoxClient` API surface (Phase H Step 4).
- MPC ceremony (Phase I).
- Multi-room subscribe (single room suffices to prove the substrate).
- Performance benchmarking (Phase I deployment audit).

## Attribution

- Engine.IO + Socket.IO codec (`src/engineio_codec.rs`) vendored from
  [Calhooon/bsv-messagebox-cloudflare](https://github.com/Calhooon/bsv-messagebox-cloudflare)
  (MIT, © Calhooon Contributors).
