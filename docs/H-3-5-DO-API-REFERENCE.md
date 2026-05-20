# worker 0.7.5 Durable Object API Reference

Concrete patterns for H-3.5 implementation. All line references from `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/worker-0.7.5/src/durable.rs` unless otherwise noted.

## 1. Macro + Trait (lines 849–886)

```rust
#[durable_object]
pub struct EngineIoSession {
    state: State,
    env: Env,
    inner: RefCell<Option<SessionState>>,
}

impl DurableObject for EngineIoSession {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            inner: RefCell::new(None),
        }
    }
    async fn fetch(&mut self, req: Request) -> Result<Response> {
        // Dispatch here
    }
}
```

**Contract:** `#[durable_object]` macro enables the runtime's instantiation via `DurableObject::new(state, env)` on every fetch. The trait requires `new()` constructor + `async fn fetch(&mut self, req: Request) -> Result<Response>` handler. The method receives `&mut self` so the DO can mutate—interior mutability (RefCell) bridges non-Send state inside.

## 2. State API (lines 237–282)

```rust
pub struct State { /* ... */ }
impl State {
    pub fn id(&self) -> ObjectId { }
    pub fn storage(&self) -> Storage { }
    pub fn accept_web_socket(&self, ws: &WebSocket) { }
}
```

**Critical fields:**
- `state.id()` → `ObjectId`: stable per-DO instance. Convert to hex string via `.to_string()` for logging.
- `state.storage()` → `Storage`: KV-shaped API with `.get<T>(key)`, `.put(key, value)`, `.delete(key)`. All async; each method is a transaction.
- `state.accept_web_socket(&ws)` (line 280): INBOUND server socket only. Persists the socket's state via attachment (2 KB cap). **OUTBOUND client sockets do NOT survive hibernation.**

## 3. Storage API (lines 343–572)

```rust
pub async fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>>
pub async fn put<T: Serialize>(&self, key: &str, value: T) -> Result<()>
pub async fn delete(&self, key: &str) -> Result<bool>
```

**Pattern:** Serde-backed. Serializes to/from `JsValue` automatically. Returns `Ok(None)` if key missing. Each call is atomic—no explicit transaction needed for single keys.

H-3.5 usage:
```rust
let session: Option<PersistedBrc103Session> = self.state.storage().get("brc103_session").await?;
self.state.storage().put("brc103_session", &snapshot).await?;
```

## 4. Env (Secret Access) — from lib.rs:85–88 (test-agent)

```rust
let server_key = env
    .secret("SERVER_PRIVATE_KEY")
    .map_err(|_| Error::RustError("Missing SERVER_PRIVATE_KEY".into()))?
    .to_string();
```

**Pattern:** `env.secret(name)` returns `Result<Secret>`. Call `.to_string()` for hex string. Secrets are **NOT cached**—re-read every fetch. This is correct: the DO constructor runs only once per fetch, so caching the env is safe, but secrets must be readable fresh in case they're rotated.

**Inside a DO:** Read `SERVER_PRIVATE_KEY` in `fetch()` the same way, every time. The env outlives the request.

## 5. RefCell Interior Mutability (session.rs:290)

```rust
inner: RefCell<Option<SessionState>>,
```

**Why:** DOs are single-threaded (JS event loop). `RefCell` allows mutation behind `&self` without `&mut self` borrowing (incompatible with the trait's `fn fetch(&self, ...)`). The runtime guarantees no parallel access, so `RefCell::borrow_mut()` will never panic.

**H-3.5 shape:**
```rust
struct EngineIoSessionDO {
    state: State,
    env: Env,
    inner: RefCell<Option<SessionPeer>>,
}

struct SessionPeer {
    peer: Peer,
    ws_handle: WsHandle,
    server_identity: PublicKey,
}
```

Access: `self.inner.borrow_mut().as_mut().map(|p| { /* use p */ })`.

## 6. ObjectNamespace + Stub (lines 71–167, 38–65)

**From worker entry point** (lib.rs:347–349):
```rust
let namespace = env.durable_object("BINDING_NAME")?;
let stub = namespace.id_from_name("cosigner-test-1")?.get_stub()?;
stub.fetch_with_request(req).await
```

**API:**
- `env.durable_object(binding_name: &str)` → `Result<ObjectNamespace>`
- `namespace.id_from_name(name: &str)` → `Result<ObjectId>`
- `id.get_stub()` → `Result<Stub>`
- `stub.fetch_with_request(req: Request)` → `async Result<Response>`

**Behavior:** `id_from_name` deterministically derives a DO ID from a string (same name = same ID). The stub is a client handle to a remote DO; fetch returns the DO's response. Routing is per-identity (each cosigner gets a named DO, e.g., "cosigner-test-1").

## 7. wrangler.toml Bindings (rust-message-box:51–62)

```toml
[[durable_objects.bindings]]
name = "ENGINEIO_SESSION"
class_name = "EngineIoSession"

[[migrations]]
tag = "v4"
new_classes = ["EngineIoSession"]
```

**Pattern:** Binding name (used in `env.durable_object()`) is independent of class name (the Rust struct marked with `#[durable_object]`). Each new class requires a migration tag (allows Cloudflare to track class versions). The example shows v1→v4 progression (MessageRoom deleted in v2, MessageHub added in v3, EngineIoSession in v4).

## 8. Server-side Reference (bsv-messagebox-cloudflare-public/src/engineio/session.rs:276–300)

```rust
#[durable_object]
pub struct EngineIoSession {
    state: State,
    env: Env,
    inner: RefCell<Option<SessionState>>,
}

impl DurableObject for EngineIoSession {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            inner: RefCell::new(None),
        }
    }
}
```

**SessionState shape (lines 101–138):** Holds `sid`, `transport` enum (Polling/WebSocket/UpgradePending), `queue` (VecDeque), `auth` (SessionAuthState), `joined_rooms`. Serialized to `WsAttachment` and persisted to the inbound WS socket via `serialize_attachment()`.

**WsAttachment (lines 228–241):** Serde struct with `sid`, `connected`, `transport`, `auth`, `joined_rooms`, `authenticated_emitted`. All marked `#[serde(default)]` for forward compatibility. Size ~250 B + 70 B per room.

**Rehydration pattern (lines 159–170):**
```rust
fn from_attachment(att: &WsAttachment) -> Self {
    Self {
        sid: att.sid.clone(),
        transport: att.transport,
        connected: att.connected,
        queue: VecDeque::new(),
        closed: false,
        auth: att.auth.clone(),
        joined_rooms: att.joined_rooms.clone(),
        authenticated_emitted: att.authenticated_emitted,
    }
}
```

Note: queue and closed are NOT carried over (queue holds transient data; closed implies teardown). H-3.5 mirrors this for BRC-103 session: **always re-handshake on wake; only persist telemetry (relay URL, last-known peer identity hex, persist timestamp).**

## 9. Secret Loading Pattern (test-agent + production)

Both test-agent and bsv-messagebox follow this pattern:
```rust
let priv_hex = env.secret("SERVER_PRIVATE_KEY")?.to_string();
let client_priv = PrivateKey::from_hex(&priv_hex)?;
let wallet = ProtoWallet::new(Some(client_priv));
```

**H-3.5 adoption:** In the DO's `fetch()`, re-read the secret every time (no caching inside RefCell-mutated state). The priv is re-derived, not persisted to storage.

## 10. DO Identity Stability

Per audit §11.1 + H-3.5 topology: one DO per identity. Named via `id_from_name("cosigner-test-1")`. The cosigner's `client_identity` pubkey (derived from `SERVER_PRIVATE_KEY`) is stable across hibernation—the same secret yields the same priv yields the same pubkey every fetch.

---

**Summary:** H-3.5 scaffolds a `#[durable_object] EngineIoSessionDO` bound as `COSIGNER_SESSION` in wrangler.toml. The worker entry point calls `env.durable_object("COSIGNER_SESSION")?.id_from_name("cosigner-test-1")?.get_stub()?.fetch_with_request(req)`. The DO's `fetch()` reads `SERVER_PRIVATE_KEY` once per fetch (cheap; matches server pattern), uses `RefCell<Option<SessionPeer>>` for the Peer + WebSocket handle, and persists BRC-103 telemetry to `state.storage()` after handshake. On wake (DO eviction), `inner.is_none()` signals reconnect.
