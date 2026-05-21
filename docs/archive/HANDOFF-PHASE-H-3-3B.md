# Handoff — Phase H Step 3.3b (BRC-103 via Peer) pickup

> For the next Claude session picking up Phase H Step 3 at gate
> H-3.3b. Read this + `docs/PHASE-H-AUDIT.md` §11.2 revised first;
> then plan the `SocketIoTransport` + `Peer` integration on top of
> the already-proven WS substrate.
>
> **Status:** Substrate green — `WsHandle` + Socket.IO CONNECT
> empirically verified against the live Calhoun relay. H-3.3b only
> needs BRC-103 via Peer; no new substrate exploration required.

## TL;DR — the next concrete action

**Phase H Step 3 gate H-3.3b** per `docs/PHASE-H-AUDIT.md` §6.2.
Wire `bsv_rs::auth::Peer` over a new `SocketIoTransport` that drives
the BRC-103 `authMessage` Socket.IO event channel on the already-
proven `WsHandle` substrate. **Pass criterion**: a new `/brc103-handshake`
route returns JSON with `brc103_authenticated: true` + a server
identity key extracted from the InitialResponse, after sending an
InitialRequest from a freshly-generated one-shot client identity.

Total estimated work: ~300-500 LOC of new code + iteration. Two
genuine risks ahead, both with known patterns to follow (see
§5.2 + §5.4 below).

## What's done as of this handoff

### Shipped on `bsv-mpc` main (this session)

| Commit | Gate | Empirical proof |
|---|---|---|
| `cb923fc` | H-3.1 | `cargo build --target wasm32-unknown-unknown -p poc17-cf-outbound-ws` clean (43.64s) |
| `3e7d13a` | docs §11.2 | pure Rust+WASM Plan A locked; JS bundle demoted to Plan B fallback |
| `bc8b0b4` | H-3.2a | `GET /open` → polling handshake returns `sid=UKcdeKWrQvyDtj3oKNFlIQ`, 151ms |
| `6ff1a53` | H-3.2b | `GET /open` → WS upgrade via `web_sys::WebSocket`, probe RTT 289ms |
| `0073e43` | H-3.3a | `GET /socketio-connect` → long-lived `WsHandle` + Socket.IO CONNECT, socket sid `wlTWUSygQMiDmWp7xe8XzQ`, connect RTT 51ms, zero intermediate frames |

All five CI runs green on `origin/main`. Empirical evidence path:
`https://rust-message-box.dev-a3e.workers.dev/socket.io/` is the live
target; `wrangler dev --local --port 8787` is the verification harness;
`curl /open` + `curl /socketio-connect` produce JSON proofs.

### What the substrate gives you (no need to re-prove)

After H-3.3a, the `WsHandle` exposes:

```rust
pub struct WsHandle { /* ... */ }
impl WsHandle {
    pub async fn open_and_upgrade(relay: &str, sid: &str) -> Result<Self, String>;
    pub fn send_text(&self, s: &str) -> Result<(), String>;
    pub fn send_engineio(&self, pkt: &EngineIoPacket) -> Result<(), String>;
    pub fn send_socketio(&self, pkt: &SocketIoPacket) -> Result<(), String>;
    pub async fn recv_text(&mut self) -> Option<Result<String, String>>;
    pub async fn recv_engineio(&mut self) -> Result<EngineIoPacket, String>;
    pub async fn recv_socketio(&mut self) -> Result<SocketIoPacket, String>;
}
```

It already:
- Keeps the WS alive across method calls.
- Has a persistent `futures::channel::mpsc::UnboundedReceiver<Result<String, String>>` inbound text-frame pipe.
- Holds `Closure` callbacks in named fields (cleanly dropped on `Drop` after JS-side `set_on_*(None)` calls).
- Encodes/decodes both Engine.IO + Socket.IO layers via the vendored codec.

**No substrate exploration is needed for H-3.3b** — the WS is proven
to work in CF Worker scope. Build on it.

### Locked decisions (do NOT re-litigate)

1. **Substrate: pure Rust+WASM via vendored Calhoun codec.** Audit
   §11.2 revised. JS bundle is Plan B fallback only.
2. **Code lives in `poc/poc17-cf-outbound-ws/`** for H-3.3b. Graduates
   to `crates/bsv-mpc-messagebox/` in Phase H Step 4.
3. **`worker = "0.7"`** matches `bsv-mpc-worker` for Phase I consistency.
4. **`bsv-rs` features `["auth", "wallet", "transaction", "wasm"]`**
   (declared directly, NOT via `workspace = true`, so the auth+wasm
   features stay scoped to this POC).
5. **Local wrangler.toml is gitignored**; `wrangler.example.toml`
   committed as template.
6. **The pre-commit hook at `.git/hooks/pre-commit:5` matches
   `wrangler\.toml` as a substring** — that's why the template is
   named `wrangler.example.toml` (not `wrangler.toml.example`).

## The substrate that's proven (reference snippets)

### Live-verified `/open` flow (H-3.2)

```
$ curl -sS http://localhost:8787/open | jq .
{
  "socketio_status": "ws_upgraded",
  "sid": "...",
  "probe_round_trip_ms": 289.0,
  "ws_url": "wss://rust-message-box.dev-a3e.workers.dev/socket.io/?EIO=4&transport=websocket&sid=...",
  "upgrades": ["websocket"],
  "pingInterval": 25000,
  "pingTimeout": 20000,
  "maxPayload": 1000000,
  "gate": "H-3.2 (H-3.2a polling + H-3.2b ws-upgrade)"
}
```

### Live-verified `/socketio-connect` flow (H-3.3a)

```
$ curl -sS http://localhost:8787/socketio-connect | jq .
{
  "socketio_status": "socketio_connected",
  "engineio_sid": "wlTWUSygQMiDmWp7xe8XzQ",
  "socketio_sid": "wlTWUSygQMiDmWp7xe8XzQ",
  "probe_round_trip_ms": 340.0,
  "connect_round_trip_ms": 51.0,
  "intermediate_frames": [],
  "ws_url": "...",
  "gate": "H-3.3a"
}
```

The Socket.IO CONNECT exchange completes in 51ms. The server replies
to a `40` (Socket.IO CONNECT to default namespace `/`) with another
`40` carrying `{sid: "..."}` as the payload — extracted via the
vendored codec's `SocketIoPacket::Connect { nsp, data }`.

## H-3.3b plan (concrete)

### 5.1 Generate a one-shot client identity priv

**API** (verified via `~/bsv/mpc/rust-mpc/tests/tests/brc103_auth.rs:220`):

```rust
use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::proto_wallet::ProtoWallet;

let client_priv = PrivateKey::from_random()
    .map_err(|e| format!("PrivateKey::from_random: {e:?}"))?;
let client_pub_hex = client_priv.to_public_key().to_hex();
let wallet = ProtoWallet::new(client_priv.clone());
```

**Source-of-truth references**:
- `~/bsv/bsv-rs/src/primitives/ec/private_key.rs:43` — `PrivateKey::random()`
- `~/bsv/mpc/rust-mpc/tests/tests/brc103_auth.rs:220, 309, 371, 447` — `PrivateKey::from_random()` usage (the `from_random` constructor)
- `~/bsv/rust-wallet-utils/` — the canonical Calhoun-side priv/pub gen + wallet management CLI; in particular `src/commands/init.rs` shows the
  end-to-end `ProtoWallet` + `Wallet` setup. **NOT NEEDED** for H-3.3b
  since we want a one-shot priv (no persistence) — but useful precedent
  for confirming feature flags + dep shapes.

**For the POC**: priv is ephemeral, per-request. Generate fresh in the
`/brc103-handshake` route handler. (No `SERVER_PRIVATE_KEY` env var
needed at this stage; identity persistence becomes a Phase H Step 4
or Phase I concern.)

### 5.2 `SocketIoTransport` impl of `bsv_rs::auth::Transport`

**Trait definition** at `~/bsv/bsv-rs/src/auth/transports/http.rs:29-44`:

```rust
#[async_trait]
pub trait Transport: Send + Sync {
    async fn send(&self, message: &AuthMessage) -> Result<()>;
    fn set_callback(&self, callback: Box<TransportCallback>);
    fn clear_callback(&self);
}

pub type TransportCallback = dyn Fn(AuthMessage)
    -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>
    + Send + Sync;
```

**The `Send + Sync` bound is the load-bearing concern.** `web_sys::WebSocket`
is `!Send` because it's a JS-handle. To satisfy the trait, the transport
needs an `unsafe impl Send` + `unsafe impl Sync` shield under a documented
single-thread invariant — **same pattern as Phase G §2.5** (commit `a9a7e18`
on the three inline coordinators). Cite that precedent in the safety comment.

**Sketch**:

```rust
use std::sync::Arc;
use parking_lot::Mutex; // or std::sync::Mutex; wasm32 is single-threaded
use bsv::auth::{Transport, TransportCallback};
use bsv::auth::AuthMessage;
use async_trait::async_trait;

pub struct SocketIoTransport {
    // The WS handle, behind a Mutex so the trait can be Send+Sync.
    // wasm32 is single-threaded — the Mutex contention is conceptual,
    // not real. Same invariant as Phase G's unsafe impl Send shield.
    ws: Arc<Mutex<WsHandle>>,
    callback: Arc<Mutex<Option<Box<TransportCallback>>>>,
}

// SAFETY: wasm32 is single-threaded. `web_sys::WebSocket` is !Send
// because the underlying Rc<RefCell<>>-like state cannot be sent
// across threads — but on wasm32 there's only one thread, so the
// invariant is vacuously true. Documented identical pattern in
// `crates/bsv-mpc-core/src/dkg.rs` (`unsafe impl Send for DkgCoordinator`,
// Phase G commit `a9a7e18`).
unsafe impl Send for SocketIoTransport {}
unsafe impl Sync for SocketIoTransport {}

impl SocketIoTransport {
    pub fn new(ws: WsHandle) -> Self {
        Self {
            ws: Arc::new(Mutex::new(ws)),
            callback: Arc::new(Mutex::new(None)),
        }
    }

    /// Spawn the background inbound dispatch task. Pulls Socket.IO
    /// events from `WsHandle::recv_socketio`; when we see an EVENT
    /// with `["authMessage", <payload>]`, deserialize the payload as
    /// AuthMessage and invoke the registered callback (if any).
    pub fn spawn_dispatch(self: Arc<Self>) {
        let me = self.clone();
        wasm_bindgen_futures::spawn_local(async move {
            loop {
                let ws_arc = me.ws.clone();
                // Drop the lock guard before .await — otherwise we hold
                // the Mutex across an await point. In wasm32 single-thread
                // this never deadlocks (no other task can take it), but
                // it's bad style.
                let frame = {
                    let mut ws = ws_arc.lock();
                    ws.recv_socketio().await
                    // ^ NOTE: this WILL deadlock conceptually because we
                    //   hold the lock across await. Need a smarter
                    //   pattern — e.g. split the WS into sender + receiver
                    //   halves and only lock for sends. See §5.2 notes
                    //   below on the channel-split refactor.
                };
                // ... decode authMessage event, invoke callback ...
            }
        });
    }
}

#[async_trait]
impl Transport for SocketIoTransport {
    async fn send(&self, message: &AuthMessage) -> Result<()> {
        // Serialize the AuthMessage as JSON, wrap in Socket.IO EVENT
        // packet (["authMessage", payload]), emit via ws.
        let json = serde_json::to_string(message)?;
        let event_payload = format!("[\"authMessage\",{json}]");
        let pkt = SocketIoPacket::Event {
            nsp: "/".to_string(),
            ack_id: None,
            data: vec![/* parsed from event_payload */],
        };
        let ws = self.ws.lock();
        ws.send_socketio(&pkt).map_err(/* convert to bsv-rs Error */)?;
        Ok(())
    }

    fn set_callback(&self, cb: Box<TransportCallback>) {
        *self.callback.lock() = Some(cb);
    }

    fn clear_callback(&self) {
        *self.callback.lock() = None;
    }
}
```

**The async-await-with-locked-Mutex pitfall** in `spawn_dispatch` above
is real and load-bearing. Two clean solutions:

(A) **Channel-split**: refactor `WsHandle` to expose two halves — a
    `WsSink` (send-only, `Send` via Arc<Mutex>) and a `WsStream`
    (recv-only, owned by the dispatch task). The dispatch task owns
    the stream; the `Transport::send` impl owns the sink. No lock
    contention.

(B) **try_lock with backoff**: dispatch task uses `try_lock`; if
    contended (which can't actually happen on single-thread wasm32),
    yields via `wasm_bindgen_futures::yield_now()`-equivalent. Hacky
    but works for single-thread.

**Recommend (A)** — clean ownership shape; mirrors the pattern in
tokio's `tokio_tungstenite::WebSocketStream::split()`. Refactor
`WsHandle` first to expose `into_split() -> (WsSink, WsStream)`.

### 5.3 `Peer` wiring

```rust
use bsv::auth::{Peer, PeerOptions};

let transport = Arc::new(SocketIoTransport::new(ws));
transport.clone().spawn_dispatch();

let peer = Peer::new(PeerOptions {
    wallet: ProtoWallet::new(client_priv.clone()),
    transport: (*transport).clone(),  // or Arc<SocketIoTransport> if Peer accepts that
    certificates_to_request: None,
    session_manager: None,
    auto_persist_last_session: false,  // POC is one-shot
    originator: Some("poc17-cf-outbound-ws".to_string()),
});

peer.start();  // registers the inbound callback
```

**API caveat**: `Peer::new` takes `T: Transport` BY VALUE (not Arc) — see
`~/bsv/bsv-rs/src/auth/peer.rs:127-149`. May need to clone or wrap. The
existing native client in `crates/bsv-mpc-messagebox/src/auth.rs:100-115`
constructs Peer with an owned `SimplifiedFetchTransport`. SocketIoTransport
similarly should be constructible by-value OR be Cloneable.

### 5.4 BRC-103 handshake trigger + verification

**Two paths** to trigger BRC-103 from a client:

**Path 1 — `Peer::to_peer` with `None` recipient** (untested, may not work):

```rust
peer.to_peer(b"hello", None, Some(5000)).await?;
```

`to_peer` calls `get_authenticated_session(identity_key, max_wait_time)`
internally per `~/bsv/bsv-rs/src/auth/peer.rs:321+`. If identity_key is
`None`, it would need an "anyone listening" semantic — not certain this
is supported.

**Path 2 — direct InitialRequest construction** (canonical fallback):

```rust
let my_identity = peer.get_identity_key().await?;
let mut initial_req = AuthMessage::new(MessageType::InitialRequest, my_identity);
// Fill in initial_nonce (32 random bytes, base64) — see Peer::send_initial_request in peer.rs:660+
initial_req.initial_nonce = Some(base64::encode(rand::random::<[u8; 32]>()));
transport.send(&initial_req).await?;

// Then wait for the registered callback to be invoked with InitialResponse.
// The callback Peer registers internally handles state transition.
```

**Verification** (the H-3.3b empirical gate):
1. After triggering the handshake, await a flag/event that signals
   "authenticated" — likely a oneshot channel that the SocketIoTransport
   wakes from inside the dispatch loop when it sees an InitialResponse.
2. `peer.get_identity_key()` always returns OUR identity. To get the
   SERVER's identity, query the SessionManager — but it's private per
   the existing native client's `bsv-mpc-messagebox/src/auth.rs:30-42`.
3. Workaround: the dispatch task can EXTRACT the server identity from
   the InitialResponse `identity_key` field before handing the message
   to Peer's callback, then expose it via a public `server_identity()`
   accessor on `SocketIoTransport`.

**Recommend Path 2** — bypasses the unknown `to_peer` semantics, gives
us full control over the handshake trigger and verification.

### 5.5 `/brc103-handshake` route in `lib.rs`

```rust
.get_async("/brc103-handshake", |_req, ctx| async move {
    let relay = /* same as /open */;
    let handshake = transport_wasm::polling_handshake(&relay).await?;
    let ws = WsHandle::open_and_upgrade(&relay, &handshake.sid).await?;

    // Send Socket.IO CONNECT first (H-3.3a substrate verified this works).
    // ...

    // Generate one-shot identity.
    let client_priv = PrivateKey::from_random()?;
    let client_pub_hex = client_priv.to_public_key().to_hex();

    // Wire SocketIoTransport + Peer.
    let transport = Arc::new(SocketIoTransport::new(ws));
    transport.clone().spawn_dispatch();
    let peer = Peer::new(PeerOptions { /* ... */ });
    peer.start();

    // Trigger handshake (Path 2).
    let server_identity_rx = transport.server_identity_oneshot();  // see §5.4
    let mut initial_req = AuthMessage::new(MessageType::InitialRequest, peer.get_identity_key().await?);
    initial_req.initial_nonce = Some(/* base64 32 bytes */);
    transport.send(&initial_req).await?;

    // Await InitialResponse via the oneshot.
    let server_identity_hex = server_identity_rx.await?;

    Response::from_json(&json!({
        "socketio_status": "brc103_authenticated",
        "engineio_sid": handshake.sid,
        "client_identity": client_pub_hex,
        "server_identity": server_identity_hex,
        "gate": "H-3.3b",
    }))
})
```

## Empirical gate (the H-3.3b 110%-no-asterisks bar)

```
$ curl -sS http://localhost:8787/brc103-handshake | jq .
{
  "socketio_status": "brc103_authenticated",
  "engineio_sid": "<...>",
  "client_identity": "<33-byte compressed pubkey hex starting with 02 or 03>",
  "server_identity": "<33-byte compressed pubkey hex starting with 02 or 03>",
  "gate": "H-3.3b"
}
```

Pass criteria:
- `socketio_status == "brc103_authenticated"`
- `client_identity` is a valid 33-byte compressed pubkey (66 hex chars
  starting with `02`/`03`)
- `server_identity` is similarly valid AND non-empty (proves we got
  an InitialResponse back, not just a timeout)
- Total wall-clock < 2s (handshake + 1 RTT)
- `wrangler dev` log: `GET /brc103-handshake 200 OK (<2000ms)`

## Locked discipline (carried forward)

- 5-step workflow per phase. H-3.3b is one sub-gate within H-3 Step 3.
- Each gate's commit lands on main BEFORE the next gate begins.
- `cd ~/bsv/mpc/bsv-mpc/` for commits (NEVER bsv-mpc-old-unscrubbed/).
- 110%-no-asterisks: every commit's gate must be empirically verified
  before the commit lands. The wrangler dev + curl loop is the
  canonical empirical harness.
- Run `cargo fmt --all -- --check` AND `cargo clippy --workspace
  --all-targets -- -D warnings` locally before push. (Lesson from
  G-5b's fmt break — never skip either.)
- Pure Rust+WASM. JS bundle is Plan B fallback only (audit §11.2 revised).
- Path A: implementation conforms to canonical TS (`@bsv/message-box-client`
  v2.0.7), never the inverse.
- god-tier + full-stack awareness — consult `~/bsv/` Rust + TS reference
  stack before proposing fixes; the canonical BRC-103 patterns live at
  `~/bsv/mpc/rust-mpc/tests/tests/brc103_auth.rs` (Binary's Rust impl),
  `~/bsv/authsocket-client/src/SocketClientTransport.ts` (canonical TS),
  and `~/bsv/bsv-messagebox-cloudflare-public/src/engineio/auth.rs:1-72`
  (server-side state machine).

## Critical references in this order

1. **`docs/PHASE-H-AUDIT.md`** — design doc; especially §2.5b (substrate)
   + §11.2 revised (pure Rust+WASM Plan A).
2. **`poc/poc17-cf-outbound-ws/src/transport_wasm.rs`** — the proven
   `WsHandle` substrate. Build on it.
3. **`~/bsv/bsv-rs/src/auth/peer.rs`** — `Peer` API. Key lines:
   - `:127-149` — `Peer::new(PeerOptions{...})`
   - `:159` — `Peer::start()` registers inbound callback
   - `:321+` — `to_peer(payload, identity_key, max_wait_time)`
   - `:660+` — internal `send_initial_request` (reference for Path 2)
4. **`~/bsv/bsv-rs/src/auth/transports/http.rs:29-44`** — `Transport`
   trait literal + `TransportCallback` type.
5. **`~/bsv/bsv-rs/src/auth/types.rs:80-110`** — `AuthMessage` struct
   + `MessageType` enum.
6. **`~/bsv/bsv-rs/src/primitives/ec/private_key.rs:43`** —
   `PrivateKey::random()`. Note: the `rust-mpc` tests use
   `PrivateKey::from_random()` — confirm which the current bsv-rs has;
   they may both exist.
7. **`~/bsv/mpc/rust-mpc/tests/tests/brc103_auth.rs:218-260`** —
   Binary's canonical Rust BRC-103 signature test. Shows
   `ProtoWallet::new` + `create_signature_sync` + BRC-103 protocol/key
   ids. Highly load-bearing reference for understanding what the
   server expects + what Peer signs.
8. **`crates/bsv-mpc-messagebox/src/auth.rs:46-160`** — the existing
   native client's Peer setup. Mirror the construction shape (swap
   transport).
9. **`~/bsv/bsv-messagebox-cloudflare-public/src/engineio/auth.rs:1-72`**
   — server-side BRC-103 state machine. Confirms the wire shape we
   need to match.
10. **`~/bsv/authsocket-client/src/SocketClientTransport.ts:17-28`** —
    canonical TS SocketClientTransport. Rust analog is what
    `SocketIoTransport` will be.
11. **`~/bsv/rust-wallet-utils/src/commands/init.rs`** — Calhoun-side
    wallet init CLI. Confirms `ProtoWallet` + `bsv-rs` feature flag
    shape `["auth", "wallet", "transaction"]` for native; we add
    `"wasm"` for the POC.
12. **Phase G §2.5 / commit `a9a7e18`** — `unsafe impl Send` shield
    precedent for `!Send` types behind a documented single-thread
    invariant. The SocketIoTransport's `unsafe impl Send + Sync` must
    cite this pattern with the same safety-comment discipline.

## What I am NOT doing in this handoff

- Writing the `SocketIoTransport` impl (H-3.3b work for the next session).
- Implementing the `WsHandle::into_split()` refactor (§5.2 path A).
- Filing upstream PR on `bsv-rs` for `SocketIoTransport` (waits for
  the POC to confirm shape; then graduates to bsv-rs upstream in
  Phase H Step 4 per audit §11.2).
- Touching `crates/bsv-mpc-messagebox/` (Phase H Step 4 work).
- Scaffolding the DO for hibernation (H-3.5).

## Running the existing substrate (sanity-check before H-3.3b)

```bash
# Build
cd ~/bsv/mpc/bsv-mpc/poc/poc17-cf-outbound-ws/
worker-build --release

# Start dev server
wrangler dev --local --port 8787 &

# Verify the existing gates still work
curl http://localhost:8787/health
curl -sS http://localhost:8787/open | jq .                    # H-3.2 — ws_upgraded
curl -sS http://localhost:8787/socketio-connect | jq .        # H-3.3a — socketio_connected
```

Both should return the JSON shapes shown in §"The substrate that's
proven" above. If either fails, debug the substrate before starting
H-3.3b.

## Out-of-tree files referenced

| Path | Why |
|---|---|
| `~/bsv/bsv-rs/` | Calhoun-controlled (`Calhooon/bsv-rs`); `Peer` + `Transport` + `AuthMessage` + `PrivateKey` |
| `~/bsv/mpc/rust-mpc/tests/tests/brc103_auth.rs` | Binary's canonical BRC-103 test suite (4 tests on lines 220/309/371/447) |
| `~/bsv/authsocket-client/` | Canonical TS `@bsv/authsocket-client` (Path A wire authority) |
| `~/bsv/bsv-messagebox-cloudflare-public/src/engineio/{auth,codec}.rs` | Server-side BRC-103 state machine + the codec we vendored |
| `~/bsv/rust-wallet-utils/` | Calhoun priv/pub gen + wallet CLI (reference for ProtoWallet patterns) |
| `~/bsv/mpc/bsv-mpc/secrets.md` | Gitignored; CF API token for any deploy work later |

---

**Open MessageBox relay (live):** `https://rust-message-box.dev-a3e.workers.dev`
**Local wrangler dev port:** `8787`
**Verified-green test routes:** `/health` · `/open` (H-3.2) · `/socketio-connect` (H-3.3a)
**H-3.3b target route:** `/brc103-handshake` (NEW — implement in this session)
**Substrate proven:** `WsHandle` + persistent mpsc inbound + Socket.IO emit/recv
**Empirical bar for H-3.3b:** `brc103_authenticated: true` + both client + server identity hexes returned in `/brc103-handshake` JSON.
