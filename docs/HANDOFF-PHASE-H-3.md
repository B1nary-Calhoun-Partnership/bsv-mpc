# Handoff — Phase H Step 3 (POC) pickup

> For the next Claude session picking up Phase H at the POC step
> (`poc/poc17-cf-outbound-ws/`). Read this + `docs/PHASE-H-AUDIT.md`
> §2.5b + §11 first; then scaffold the POC per the plan below.

## TL;DR — the next concrete action

**Phase H Step 3 — POC `poc/poc17-cf-outbound-ws/`.** A minimum
deployable Cloudflare Worker + Durable Object that proves five
hard gates (per audit `§6.2` as rewritten in §2.5b):

| Gate | What it proves | Pass criterion |
|---|---|---|
| **H-3.1** | wasm32 build works | `cargo build --target wasm32-unknown-unknown -p poc17-cf-outbound-ws` clean |
| **H-3.2** | Socket.IO handshake from a CF DO via JS-bundled `socket.io-client@4.x` | `wrangler dev` test: DO `fetch /open` triggers Socket.IO `GET /socket.io/?EIO=4&transport=polling` → 200 + Engine.IO handshake JSON; upgrades to WS within 5s |
| **H-3.3** | BRC-103 mutual auth completes over `authMessage` event | New `SocketIoTransport` (Rust impl of `bsv_rs::auth::Transport`) drives `bsv_rs::auth::Peer` through the BRC-103 `InitialRequest` → `InitialResponse` handshake; channel becomes identity-bound |
| **H-3.4** | Round-trip a canonical CBOR envelope | POST `/relay` to DO; DO emits `sendMessage` to live relay's `/socket.io/`; DO receives echo back on a `sendMessage` event from its own subscribed room; body byte-identical |
| **H-3.5** | Forced-hibernation reconnect | `wrangler dev` + `state.abort()` to force DO eviction; subsequent fetch wakes; Socket.IO re-handshakes; BRC-103 re-authenticates; `/listMessages` backfill recovers; missed envelope reaches consumer byte-exact |

After all five pass, Phase H is POC-green and the next phase step
(H-4 — implementation in `crates/bsv-mpc-messagebox`) can start.

## What's done as of this handoff

### Shipped on `bsv-mpc` main

| Commit | What |
|---|---|
| `254ff0f` H-2 | `docs/PHASE-H-AUDIT.md` draft 1 — substrate + hibernation + wrap-vs-rewrite design |
| `4a1f8bc` H-2b | §2.5b patch — **Socket.IO + BRC-103 supersedes raw-WS + BRC-31 workarounds** (canonical TS uses Socket.IO; Calhoun Rust relay exposes `/socket.io/` alongside `/ws`; no server change needed) |
| `ee6f52c` H-2c | §11 god-tier scope expansion — OQ4 + OQ7 + OQ8 resolved. Native unification pulled INTO Phase H scope; upstream `SocketIoTransport` to bsv-rs; ~5-7 wk total scope |
| `(this commit)` | HANDOFF-PHASE-H-3.md + empirical pre-H-3 prep recorded |

### Locked decisions (do NOT re-litigate without explicit user redirect)

1. **Substrate: Socket.IO + BRC-103, NOT raw WS + BRC-31.** Path A
   conformance to canonical TS `@bsv/message-box-client` v2.0.7. Server
   protocol is immutable; the canonical path is already served. Audit
   §2.5b.
2. **Code structure: cfg-gate inside existing `bsv-mpc-messagebox`
   crate.** NOT a separate sibling crate. Audit §2.2 + OQ3 (user-
   confirmed).
3. **DO topology: per-identity** (audit §11.1 / OQ4).
4. **Native unification pulled INTO Phase H scope** (audit §11.3 /
   OQ8). Phase H merges only when both targets converge on the
   canonical wire AND a fresh real-sats mainnet TXID through the new
   native path matches G-5d's shape.
5. **wasm32 substrate: JS-bundled `socket.io-client@4.x` via
   wasm-bindgen.** `rust-socketio` v0.6.0 does NOT support
   `wasm32-unknown-unknown` (see §Empirical findings below); upstreaming
   wasm32 to it is tracked as a Phase H post-merge ecosystem
   contribution, NOT a Phase H blocker.
6. **Native substrate: `rust-socketio` v0.6.0** as-is. ~5k stars,
   maintained, production-grade. Workspace deps already include
   compatible `reqwest`, `tokio-tungstenite`, `tokio` etc.
7. **Upstream PR for `SocketIoTransport` → `bsv-rs`** (audit §11.2 /
   OQ7). bsv-rs is **Calhoun-controlled** at
   `git@github.com:Calhooon/bsv-rs.git` — trivial coordination, no
   partnership/third-party gating.

### Empirical findings from pre-H-3 prep (this session)

**Q1: Does `rust-socketio` support wasm32?** No (v0.6.0 latest, April
2024). Evidence (`engineio/Cargo.toml`):
- `reqwest = { version = "0.12.4", features = ["blocking", "native-tls", "stream"] }` — `blocking` is native-thread-bound; `native-tls` requires OpenSSL/SChannel
- `tokio-tungstenite = { version = "0.21.0", features = ["native-tls"] }` — requires native sockets via `tokio::net::TcpStream`
- `native-tls = "0.2.12"` — direct native TLS dep

No `wasm32` / `web-sys` / `wasm-bindgen` feature flags. No open issues
or PRs targeting wasm32 (verified via `gh search code 'wasm32 repo:1c3t3a/rust-socketio'`: 0 matches). Upstreaming wasm32 support
would be substantial work (swap reqwest+blocking → wasm-fetch,
tokio-tungstenite → web_sys::WebSocket, eliminate native-tls).
Tracked as Phase H post-merge ecosystem contribution per audit §11.2.

**Q2: `bsv_rs::auth::Transport` trait shape.** Object-safe,
three-method trait — minimal:

```rust
// ~/bsv/bsv-rs/src/auth/transports/http.rs:29-41
#[async_trait]
pub trait Transport: Send + Sync {
    async fn send(&self, message: &AuthMessage) -> Result<()>;
    fn set_callback(&self, callback: Box<TransportCallback>);
    fn clear_callback(&self);
}

pub type TransportCallback = dyn Fn(AuthMessage)
    -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>
    + Send
    + Sync;
```

Existing impls for size reference:
- `SimplifiedFetchTransport` (HTTP per-request signing): ~381 LOC in
  `bsv-rs/src/auth/transports/http.rs`.
- `WebSocketTransport` (raw WS + BRC-103 frame-by-frame): ~599 LOC in
  `bsv-rs/src/auth/transports/websocket_transport.rs`.

A minimal `SocketIoTransport` for our use case: ~150-250 LOC
(connection management is delegated to the underlying Socket.IO
client; we just wrap `emit('authMessage', ...)` / `on('authMessage', ...)`
into the Transport trait).

**Q3: `Peer::new` API + usage shape.** Direct from
`bsv-rs/src/auth/peer.rs:127-149`:

```rust
pub struct PeerOptions<W: WalletInterface, T: Transport> {
    pub wallet: W,
    pub transport: T,
    pub certificates_to_request: Option<RequestedCertificateSet>,
    pub session_manager: Option<SessionManager>,
    pub auto_persist_last_session: bool,
    pub originator: Option<String>,
}

impl<W: WalletInterface + 'static, T: Transport + 'static> Peer<W, T> {
    pub fn new(options: PeerOptions<W, T>) -> Self { ... }
}
```

Concrete construction site (existing, in
`crates/bsv-mpc-messagebox/src/auth.rs:100-115`):

```rust
let wallet = ProtoWallet::new(Some(our_priv));
let transport = SimplifiedFetchTransport::new(&relay_url);
let peer = Peer::new(PeerOptions {
    wallet,
    transport,
    certificates_to_request: None,
    session_manager: None,
    auto_persist_last_session: true,
    originator: Some(originator),
});
peer.start();
```

For Phase H wasm32 path: swap `SimplifiedFetchTransport::new(&relay_url)`
for `SocketIoTransport::new(&relay_url)` — keep everything else.

## The H-3 POC concrete plan

### Scaffolding

```
poc/poc17-cf-outbound-ws/
  Cargo.toml         # worker = "0.7" or "0.8" + wasm-bindgen + js-sys
                     # bsv-rs (Calhooon fork) with a feature flag for
                     # the new SocketIoTransport (not yet upstreamed)
  wrangler.toml      # gitignored! pulls from secrets.md for CF token
  wrangler.toml.example  # tracked public template
  src/
    lib.rs           # CF Worker entry + DO impl
    socketio.rs      # thin wrapper over JS socket.io-client@4.x
                     # (target-conditional: this whole module is wasm32-only)
    transport.rs     # SocketIoTransport impl of bsv_rs::auth::Transport
    do.rs            # Durable Object holding the Peer + WS state
  README.md          # what this POC proves + how to run
  TESTING.md         # gates per audit §6.2 + how to verify each
```

`wrangler.toml` follows the established pattern (gitignored, secrets
in `secrets.md`, public `wrangler.toml.example` template).

### Substrate decisions for this POC

- **JS dep**: `socket.io-client@4.x` bundled via `wasm-bindgen` +
  `js-sys`. Add the npm package via wrangler's bundling.
- **Rust deps**: `worker` (CF SDK), `wasm-bindgen`, `js-sys`,
  `serde`, `serde_json`, `bsv-rs` (path or git dep with the new
  `SocketIoTransport` feature flag — see Step 4 notes below).

### `SocketIoTransport` sketch (~150-250 LOC)

The minimal implementation pattern for the POC:

```rust
use bsv::auth::{Transport, TransportCallback};
use bsv::auth::AuthMessage;
use std::sync::Arc;

// SocketIo trait abstraction (in poc17 first, eventually moves to bsv-mpc-messagebox).
// The wasm32 impl wraps the JS socket.io-client@4.x package.
#[async_trait]
trait SocketIo: Send + Sync {
    async fn connect(&self, url: &str) -> Result<()>;
    async fn emit(&self, event: &str, payload: &str) -> Result<()>;
    fn on(&self, event: &str, cb: Box<dyn Fn(String) + Send + Sync>);
}

pub struct SocketIoTransport<S: SocketIo> {
    inner: Arc<S>,
    callback: Arc<RwLock<Option<Box<TransportCallback>>>>,
}

impl<S: SocketIo> SocketIoTransport<S> {
    pub fn new(inner: Arc<S>) -> Self {
        let t = Self { inner: inner.clone(), callback: Default::default() };
        // wire inbound: on('authMessage', payload) → t.callback(AuthMessage::from_json(payload))
        let cb_ref = t.callback.clone();
        inner.on("authMessage", Box::new(move |json_str| {
            let msg = serde_json::from_str::<AuthMessage>(&json_str).unwrap();
            if let Some(cb) = &*cb_ref.read().unwrap() {
                let fut = cb(msg);
                wasm_bindgen_futures::spawn_local(async move {
                    let _ = fut.await;  // best-effort error swallow on wasm32
                });
            }
        }));
        t
    }
}

#[async_trait]
impl<S: SocketIo> Transport for SocketIoTransport<S> {
    async fn send(&self, message: &AuthMessage) -> Result<()> {
        let json = serde_json::to_string(message)?;
        self.inner.emit("authMessage", &json).await
    }
    fn set_callback(&self, cb: Box<TransportCallback>) {
        *self.callback.write().unwrap() = Some(cb);
    }
    fn clear_callback(&self) {
        *self.callback.write().unwrap() = None;
    }
}
```

### Five gates — verification path per gate

- **H-3.1**: `cargo build --target wasm32-unknown-unknown -p poc17-cf-outbound-ws` (no `wrangler` needed, just a build check)
- **H-3.2**: `wrangler dev`, then `curl localhost:8787/open` — DO uses the SocketIo wasm impl to connect; returns `{ socketio_status: "connected", sid: "...", upgrade_target: "websocket" }`
- **H-3.3**: extend `/open` to also trigger the BRC-103 handshake via `peer.start()`; assertion: `peer.identity_status()` reports `Authenticated { peer_identity_key }` after ~1s
- **H-3.4**: `curl localhost:8787/relay -d '<envelope_hex>'` — DO sends via `socket.emit('sendMessage', ...)`; receives on `sendMessage` event from own subscribed room; body byte-identical
- **H-3.5**: `curl localhost:8787/relay -d ...` while DO is in a hibernate-eligible state; force-evict; next fetch wakes DO; assertion: missed envelope appears in `/listMessages` drain before WS push.

### Wallet for any auth-signing during POC

The POC needs a BRC-31 identity key for the Peer's wallet. **DO NOT
generate this in the Worker.** Two options:

1. Pre-generate a one-shot identity priv locally (script: `openssl rand -hex 32`), commit only its PUBLIC key (P2PKH address) in the POC's README for reference, stash the priv as a `wrangler secret put SERVER_PRIVATE_KEY` value sourced from the local `secrets.md`.
2. Or use a wallet:3321 derived identity for the POC — pulls from the existing dev wallet. Less isolation; reasonable for dev-account POC use.

Audit recommends (1). The Phase I deployment also uses (1) via
`SERVER_PRIVATE_KEY` Wrangler secret per umbrella issue #2 body.

## Discipline lock (carried forward)

- 5-step workflow per phase (investigate → audit doc → POC → implement → 110%/no-asterisks gate); H-3 is the POC step.
- Each step's commit lands on main BEFORE the next step begins.
- Always `cd ~/bsv/mpc/bsv-mpc/` for commits (NEVER `bsv-mpc-old-unscrubbed/`).
- god-tier + full-stack awareness — consult `~/bsv/` Rust + TS reference stack before proposing.
- Spec interop: implementation conforms to MPC-Spec + canonical TS, never the inverse (Path A).
- E2E with real sats where applicable; Phase H merge gate requires a fresh native mainnet TXID through the unified Socket.IO + BRC-103 path.
- Phase H scope expanded — wasm32 + native unification + upstream PRs.
- Deadline-flexible. Quality > speed.
- Run BOTH `cargo fmt --all -- --check` AND `cargo clippy --workspace --all-targets -- -D warnings` locally before push (lesson from G-5b's fmt break).

## Open questions still live (per audit §8 post-§11)

| | Question | Default |
|---|---|---|
| **OQ6** | POC deployment location: in-repo `poc/poc17-cf-outbound-ws/`, dev CF account (account_id from `~/bsv/rust-message-box/wrangler.toml` = `ea3e6d176ed3893258fe34281f710c7f`), no production data. Confirm at H-3 start. | yes |

OQ1, OQ2, OQ5 obsoleted by §2.5b. OQ3, OQ4, OQ7, OQ8 resolved per §11
(see audit doc).

## Critical references in this order

1. **`docs/PHASE-H-AUDIT.md`** — design doc; especially §2.5b (substrate) + §11 (god-tier scope expansion).
2. **`docs/NEXT-STEPS.md`** Phase H section — phased v1.0 plan view.
3. **`docs/HANDOFF-PHASE-G-5.md`** — POC-step handoff structure precedent (Phase G's handoff into its merge-gate step; mirror the cadence).
4. **`~/bsv/message-box-client/src/MessageBoxClient.ts:332`** — canonical TS path; `AuthSocketClient` construction.
5. **`~/bsv/authsocket-client/src/SocketClientTransport.ts:17-28`** — the TS `SocketClientTransport` reference impl whose Rust analog is `SocketIoTransport`.
6. **`~/bsv/bsv-messagebox-cloudflare-public/src/engineio/auth.rs:1-72`** — server-side BRC-103-over-Socket.IO state machine.
7. **`~/bsv/bsv-messagebox-cloudflare-public/src/lib.rs:97-98`** — server route registration for `/socket.io/*`.
8. **`~/bsv/bsv-rs/src/auth/transports/http.rs:29-41`** — `Transport` trait literal.
9. **`~/bsv/bsv-rs/src/auth/peer.rs:127-149`** — `Peer::new` + `PeerOptions`.
10. **`crates/bsv-mpc-messagebox/src/auth.rs:100-115`** — existing native `Peer` construction site.

## What I am NOT doing in this handoff

- Scaffolding `poc/poc17-cf-outbound-ws/` (Phase H Step 3 work for the next session).
- Filing upstream PRs on `bsv-rs` (waits for the POC to confirm the `SocketIoTransport` shape works).
- Filing upstream issue on `rust-socketio` for wasm32 (waits for Phase H post-merge per audit §11.2 — not a blocker).
- Touching `crates/bsv-mpc-messagebox/src/` (Phase H Step 4 work).

Those are all H-3 / H-4 / Phase-H-post-merge work for subsequent sessions.

---

**Open MessageBox relay (live):** `https://rust-message-box.dev-a3e.workers.dev`
**Calhoun CF account_id:** `ea3e6d176ed3893258fe34281f710c7f` (from `~/bsv/rust-message-box/wrangler.toml`)
**CF API token:** in `~/bsv/mpc/bsv-mpc/secrets.md` (gitignored; never commit)
**Local wallet (mainnet sats source for native TXID gate):** `http://localhost:3321` with `Origin: http://admin.com`
**Phase E reference TXID (raw-WS path):** [`82ccb15c…`](https://whatsonchain.com/tx/82ccb15c49985a32b355a618f417bb7a09ec4ee5cf34e539e9baaebb74dadc29)
**Phase G re-verify TXID (raw-WS path, post-inline rewrite):** [`442bd391…`](https://whatsonchain.com/tx/442bd391cf8eda299f82dc1e4aeb1a9cb4f33610365d44c9c1c0e55d32f171b9)
**Phase H native-unification mainnet TXID (target):** _TBD_ — produced through the new Socket.IO + BRC-103 path; cited in the Phase H merge-gate commit.
