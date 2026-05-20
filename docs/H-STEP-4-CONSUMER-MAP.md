# H-STEP-4 Consumer Impact Map: `bsv-mpc-messagebox` Public API

**Scope:** Comprehensive inventory of every consumer call site and signature for the `bsv-mpc-messagebox` crate to guide the risky H-4.4 (ws.rs replacement) and H-4.5 (MessageBoxAuth pub(crate)) refactors.

**Generated:** 2026-05-20  
**Crate:** `/Users/johncalhoun/bsv/mpc/bsv-mpc/crates/bsv-mpc-messagebox/`

---

## 1. CURRENT PUBLIC API SURFACE (lib.rs root re-exports)

From `src/lib.rs:52–57`:

```rust
pub use client::{
    DecodedEnvelope, DecodedRoundMessage, EnvelopeSubscription, MessageBoxClient,
    RoundMessageSubscription,
};
pub use error::{MessageBoxError, Result};
pub use ws::{subscribe, InboundEnvelopeEvent, InboundVia, WsSubscription};
```

**Not explicitly re-exported but declared `pub` in submodules:**
- `pub mod auth;` — exposes `auth::MessageBoxAuth` (used only in `live_relay_proof.rs`)
- `pub mod http;` — exposes `http::send_message`, `http::list_messages`, `http::acknowledge_messages`
- `pub mod types;` — exposes `BOX_SIGN`, `BOX_DKG`, `BOX_PRESIGN`, `BOX_ECDH`, `BOX_REFRESH`, and wire types
- `pub mod wire;` — exposes wrapping/unwrapping functions
- `pub mod client;` — primary entry point

---

## 2. PRESERVE THESE SIGNATURES (exact as-is, H-4.4/4.5 must not change)

### MessageBoxClient Constructors & Accessors

**Line 88** (`src/client.rs`):
```rust
pub fn new(relay_url: impl Into<String>, our_priv: PrivateKey) -> Result<Self>
```
- **Called by:**
  - `live_relay_proof.rs:428` (alice)
  - `live_relay_proof.rs:429` (bob)
  - `messagebox_listener_e2e.rs:60` (alice)
  - `messagebox_listener_e2e.rs:61` (bob)
  - `dkg_via_messagebox_e2e.rs:92` (alice_client)
  - `dkg_via_messagebox_e2e.rs:93` (bob_client)
  - `sign_mainnet_via_messagebox_e2e.rs:163` (client)

**Line 98** (`src/client.rs`):
```rust
pub async fn identity_hex(&self) -> Result<String>
```
- **Called by:**
  - `live_relay_proof.rs:430–431` (alice_pub, bob_pub)
  - `live_relay_proof.rs:569–570` (alice_pub, bob_pub)
  - (via `MessageBoxClient`, not `MessageBoxAuth` in 5/7 cases)

**Line 103** (`src/client.rs`):
```rust
pub fn relay_url(&self) -> &str
```
- **Called by:** `ws.rs:161` (internal build_ws_url)

### MessageBoxClient Send Operations

**Line 117** (`src/client.rs`):
```rust
pub async fn send(
    &self,
    recipient_pub_hex: &str,
    message_box: &str,
    envelope: &MessageEnvelope,
) -> Result<String>
```
- **Called by:**
  - `live_relay_proof.rs:452` (bob.send)
  - Internally by `send_with_id` (line 123)
  - Internally by `send_round_message` (line 233)

**Line 135** (`src/client.rs`):
```rust
pub async fn send_with_id(
    &self,
    recipient_pub_hex: &str,
    message_box: &str,
    message_id: &str,
    envelope: &MessageEnvelope,
) -> Result<String>
```
- **Called by:** `send` (line 123)

**Line 222** (`src/client.rs`):
```rust
pub async fn send_round_message(
    &self,
    recipient_pub_hex: &str,
    message_box: &str,
    round_msg: &RoundMessage,
    params: WrapParams,
) -> Result<String>
```
- **Called by:** `bsv-mpc-service/src/messagebox.rs` (internal handler dispatch, no direct test call)

### MessageBoxClient Subscribe Operations

**Line 172** (`src/client.rs`):
```rust
pub async fn subscribe(&self, message_box: &str) -> Result<EnvelopeSubscription>
```
- **Called by:**
  - `live_relay_proof.rs:437` (.subscribe(BOX_SIGN))
  - Internally by `subscribe_many` (line 179)
  - Internally by `subscribe_round_messages` (line 248)

**Line 178** (`src/client.rs`):
```rust
pub async fn subscribe_many(&self, boxes: Vec<String>) -> Result<EnvelopeSubscription>
```
- **Called by:** `subscribe` (line 179)

**Line 244** (`src/client.rs`):
```rust
pub async fn subscribe_round_messages(&self, message_box: &str) -> Result<RoundMessageSubscription>
```
- **Called by:**
  - `messagebox_listener_e2e.rs:68–71` (alice.subscribe_round_messages(TEST_BOX))
  - `bsv-mpc-service/src/messagebox.rs:112` (client.subscribe_round_messages(message_box))

### MessageBoxClient Acknowledge

**Line 187** (`src/client.rs`):
```rust
pub async fn acknowledge(&self, message_ids: &[String]) -> Result<()>
```
- **Called by:**
  - `live_relay_proof.rs:486` (client.acknowledge(&[decoded.message_id]))
  - Internally by `bsv-mpc-service/src/messagebox.rs` (not direct test call)

### MessageBoxClient Escape Hatch

**Line 198** (`src/client.rs`):
```rust
pub fn auth(&self) -> &Arc<MessageBoxAuth>
```
- **Called by:** None in live tests; internal only. **H-4.5 CRITICAL:** if removed, breaks any code holding `Arc<MessageBoxAuth>`.

---

## 3. CONSUMER CALL SITES TABLE

### `live_relay_proof.rs` (crate integration test — GATE: must stay green)

| Symbol | Line | Usage |
|--------|------|-------|
| `MessageBoxAuth::new` | 94, 213, 218 | Direct auth construction (3×) |
| `auth.start()` | 95, 215, 219 | Peer transport init (3×) |
| `auth.identity_hex().await` | 97, 216, 220 | Identity lookup (3×) |
| `http::send_message(&auth, &req)` | 128 | Direct HTTP send via auth |
| `http::list_messages(&auth, BOX_SIGN)` | 140 | Direct HTTP list via auth |
| `http::acknowledge_messages(&auth, &ids)` | 180 | Direct HTTP ack via auth |
| `MessageBoxClient::new` | 428–429 | Client construction (2×) |
| `client.identity_hex().await` | 430–431 | Identity lookup via client (2×) |
| `client.subscribe(BOX_SIGN).await` | 437 | Client subscribe |
| `client.send(&recipient, BOX_SIGN, &env).await` | 452 | Client send |
| `client.acknowledge(&[id]).await` | 486 | Client ack |
| `subscribe(alice, vec![BOX_SIGN]).await` | 226 | Direct ws::subscribe() call (low-level) |
| `subscribe(alice, vec![BOX_SIGN]).await` | 322 | Direct ws::subscribe() re-subscribe |
| `wire::wrap_envelope_to_body` | 111 | Envelope wrapping |
| `wire::unwrap_inbound_body` | 165 | Envelope unwrapping |
| `BOX_SIGN` | 37, 122, 226, 322 | Constant reference (4×) |

**CRITICAL METHODS USED:**
- `MessageBoxAuth` methods: `new()`, `start()`, `identity_hex()`, `peer()` (escape hatch via `client.auth()`)
- `MessageBoxClient` methods: all listed above are used
- `ws::subscribe()` function: 2 direct calls

### `messagebox_listener_e2e.rs` (bsv-mpc-service test)

| Symbol | Line | Usage |
|--------|------|-------|
| `MessageBoxClient::new` | 60–61 | Client construction (2×: alice, bob) |
| `client.subscribe_round_messages(TEST_BOX).await` | 68–71 | Typed round-message subscription |
| `BOX_DKG` | 26, 45 | Constant reference (2×) |
| `DecodedRoundMessage` | 83, 204, 224 | Type usage (handler param, receive path) |
| `RoundMessageSubscription` | 68, 200 | Type usage (subscription handle) |

**CRITICAL METHODS USED:**
- `MessageBoxClient::new()`, `subscribe_round_messages()`
- Types: `DecodedRoundMessage`, `RoundMessageSubscription`

### `dkg_via_messagebox_e2e.rs` (bsv-mpc-service test)

| Symbol | Line | Usage |
|--------|------|-------|
| `MessageBoxClient::new` | 92–93 | Client construction (2×: alice, bob) |
| `BOX_DKG` | 51, 145, 149 | Constant reference (3×) |

**CRITICAL METHODS USED:**
- `MessageBoxClient::new()`

### `sign_mainnet_via_messagebox_e2e.rs` (bsv-mpc-service test)

| Symbol | Line | Usage |
|--------|------|-------|
| `MessageBoxClient::new` | 163 | Client construction (1×) |
| `BOX_SIGN`, `BOX_DKG` | 61, 171, 175 | Constant reference (3×) |

**CRITICAL METHODS USED:**
- `MessageBoxClient::new()`

### `bsv-mpc-service/src/messagebox.rs` (Phase C dispatcher primitive)

| Symbol | Line | Usage |
|--------|------|-------|
| `MessageBoxClient` | 52, 104, 154 | Type import + struct fields |
| `DecodedRoundMessage` | 30, 52, 210, 273, 292, 318 | Type usage (handler param, field, synthetic construction) |
| `RoundMessageSubscription` | 155 | Type usage (subscription field) |
| `InboundVia` | 231, 329 | Enum type (pattern matching, enum construction) |
| `client.subscribe_round_messages(message_box).await` | 112 | Subscription call |
| `client.send_round_message(…).await` | (implicit) | Called in `OutgoingRoundMessage` handling (line 115–118 range) |

**Details:**
- Line 104: `client: MessageBoxClient,` (struct field)
- Line 155: `mut sub: bsv_mpc_messagebox::RoundMessageSubscription,` (parameter type)
- Line 112–114: `.subscribe_round_messages(message_box).await?;` (call)
- Line 318–329: Synthetic `DecodedRoundMessage` construction in test helper (lines 318–329)

### `bsv-mpc-service/src/signing_handler.rs`

| Symbol | Line | Usage |
|--------|------|-------|
| `DecodedRoundMessage` | 43, 190, 192, 210 | Type import + handler closure param (2 closures) |
| `bsv_mpc_messagebox::types::BOX_SIGN` | 314 | Constant reference (1×) |

**Details:**
- Line 43: `use bsv_mpc_messagebox::DecodedRoundMessage;`
- Line 190: `|inbound: DecodedRoundMessage| -> HandlerFuture { … }`
- Line 192: `move |inbound: DecodedRoundMessage| -> HandlerFuture { … }`
- Line 210: `fn process_round(inbound: DecodedRoundMessage, …)`

### `bsv-mpc-service/src/dkg_handler.rs`

| Symbol | Line | Usage |
|--------|------|-------|
| `DecodedRoundMessage` | 34, 191, 193, 211 | Type import + handler closure param (2 closures) |
| `bsv_mpc_messagebox::types::BOX_DKG` | 326 | Constant reference (1×) |

**Parallel structure to `signing_handler.rs`.**

---

## 4. BREAKS IF REMOVED (H-4.5 Impact Analysis)

### `pub mod auth; pub use auth::MessageBoxAuth` → `pub(crate)`?

**Current Users:**
1. `live_relay_proof.rs:35,94,213,218` — **Direct construction and method calls**
   - `MessageBoxAuth::new()` (3 call sites)
   - `auth.start()` (3 call sites)
   - `auth.identity_hex()` (3 call sites)
   - Via `http::send_message(&auth, …)` (line 128) — needs `&Arc<MessageBoxAuth>` parameter
   - Via `http::list_messages(&auth, …)` (line 140) — needs `&Arc<MessageBoxAuth>` parameter
   - Via `http::acknowledge_messages(&auth, …)` (line 180) — needs `&Arc<MessageBoxAuth>` parameter

2. `ws::subscribe()` function (line 154) — takes `Arc<MessageBoxAuth>` parameter
   - Called at `live_relay_proof.rs:226,322` with `alice` (type `Arc<MessageBoxAuth>`)

**Conclusion:** `MessageBoxAuth` **CANNOT** be made `pub(crate)` without breaking `live_relay_proof.rs`.  
**H-4.5 Decision:** Keep `pub mod auth;` and `pub use auth::MessageBoxAuth`. The test is the gate.

---

### `pub async fn subscribe()` from `ws::subscribe` → delete or refactor?

**Current Users:**
- Direct calls: `live_relay_proof.rs:226,322` (2 call sites)
- **This is the raw WS entry point, used in the raw `InboundEnvelopeEvent` flow.**
- The `MessageBoxClient::subscribe_many` → `ws::subscribe()` path is the typed wrapper.

**Conclusion:** H-4.4 refactors **away from raw WebSocket** to **Socket.IO/BRC-103**.  
- If H-4.4 deletes `ws::subscribe()` from `src/ws.rs`, it must either:
  1. Keep a wrapper re-export in `lib.rs` that internally calls Socket.IO, or
  2. Update `live_relay_proof.rs` to use `MessageBoxClient::subscribe()` instead (which internally uses Socket.IO)
- **live_relay_proof.rs:226,322 are CURRENTLY calling the raw `ws::subscribe()`** — they will break unless a Socket.IO-backed shim is provided.

---

### `pub use ws::{subscribe, InboundEnvelopeEvent, InboundVia, WsSubscription}`

**Affected by H-4.4:**
- `subscribe` — delete if raw WS is gone; must provide Socket.IO equivalent or update callers
- `WsSubscription` — type will change shape (Socket.IO vs WebSocket)
- `InboundVia` — may remain unchanged (backfill vs live push is protocol-agnostic)
- `InboundEnvelopeEvent` — used in `live_relay_proof.rs`, may need field reordering if Socket.IO payload shape differs

**Affected call sites:**
- `live_relay_proof.rs:39–41` — imports all four; uses them in type annotations and pattern matching
- `live_relay_proof.rs:260,264,332` — `InboundVia::WsPush`, `InboundVia::Backfill` enum variants
- `messagebox.rs:231` — uses `InboundVia` in test helper

---

## 5. CARGO.toml DEPENDENCIES

From `/Users/johncalhoun/bsv/mpc/bsv-mpc/crates/bsv-mpc-messagebox/Cargo.toml`:

### Native-Only (WebSocket + HTTP)
- `tokio` (workspace)
- `tokio-tungstenite = "0.24"` — raw WebSocket (H-4.4 candidate for removal/replacement)
- `reqwest` (workspace) — HTTP client

### Shared (Serialization, Crypto, Logging)
- `serde`, `serde_json`, `hex`, `base64` (workspace)
- `sha2` (workspace) — BRC-31 signature
- `rand` (workspace) — nonce generation
- `chrono` (workspace) — timestamps
- `url = "2"` — URL parsing
- `futures` (workspace) — `SinkExt`, `StreamExt` for streams

### Core Dependencies
- `bsv` (workspace, features `["auth", "http"]`) — Peer, SimplifiedFetchTransport, ProtoWallet
- `bsv-mpc-core` (path) — MessageEnvelope, RoundMessage, WrapParams

### No Workspace Features Block

**No `[features]` block** — all code compiles as-is. The plan mentions cfg-gating for wasm32.

### wasm32 Compatibility Needs (for Phase H Step 4)
- `tokio-tungstenite` → likely replaced with `wasm-bindgen` WebSocket or Socket.IO WASM client
- `reqwest` → `web-sys` `fetch()` API or similar
- `tokio` → already has wasm support, but `tokio::time::interval` will need wasm-timer on wasm32
- `sha2`, `rand`, `serde*`, `hex`, `base64`, `chrono` — mostly wasm-compatible, may need feature flags

---

## 6. HIGHEST-RISK CONSUMER CALL SITES

### TIER 1 (Breaks H-4.4/4.5 completely)

1. **`live_relay_proof.rs:94` — `MessageBoxAuth::new(relay_url, priv)`**
   - **Risk:** If `MessageBoxAuth` becomes `pub(crate)`, test cannot construct it.
   - **Mitigation:** Keep `pub use auth::MessageBoxAuth`.
   - **Impact:** This is the gate. Must stay green.

2. **`live_relay_proof.rs:226` — `subscribe(alice, vec![BOX_SIGN]).await`**
   - **Risk:** If H-4.4 deletes raw `ws::subscribe()`, this call fails.
   - **Mitigation:** Keep a Socket.IO-backed wrapper or update test to use `MessageBoxClient::subscribe()`.
   - **Impact:** e2e wire proof breaks. **HIGHEST single-point-of-failure.**

3. **`bsv-mpc-service/src/messagebox.rs:112` — `client.subscribe_round_messages().await`**
   - **Risk:** If `RoundMessageSubscription::new()` signature changes, dispatcher breaks.
   - **Mitigation:** Preserve `MessageBoxClient::subscribe_round_messages()` signature exactly.
   - **Impact:** All Phase C/D/E operations fail.

### TIER 2 (Requires signature preservation)

4. **`messagebox_listener_e2e.rs:68` — `alice.subscribe_round_messages(TEST_BOX).await`**
   - **Risk:** Type shape change on `RoundMessageSubscription`.
   - **Mitigation:** Stable signature.
   - **Impact:** Service-level e2e test.

5. **`signing_handler.rs:192`, `dkg_handler.rs:193` — Handler closure parameter type**
   - **Risk:** If `DecodedRoundMessage` fields reorder or rename, closures break.
   - **Mitigation:** Keep `DecodedRoundMessage` struct layout + field names stable.
   - **Impact:** All ceremonies fail (both DKG and signing).

---

## 7. SIGNATURE BYTE-FOR-BYTE PRESERVATIONS REQUIRED

These signatures are **load-bearing** — changing them breaks consumers:

```rust
// MessageBoxClient::new — public constructor
pub fn new(relay_url: impl Into<String>, our_priv: PrivateKey) -> Result<Self>

// MessageBoxClient send/subscribe — main async APIs
pub async fn send(&self, recipient_pub_hex: &str, message_box: &str, envelope: &MessageEnvelope) -> Result<String>
pub async fn subscribe(&self, message_box: &str) -> Result<EnvelopeSubscription>
pub async fn subscribe_round_messages(&self, message_box: &str) -> Result<RoundMessageSubscription>
pub async fn acknowledge(&self, message_ids: &[String]) -> Result<()>

// RoundMessageSubscription — subscription handle
pub async fn next(&mut self) -> Option<Result<DecodedRoundMessage>>
pub async fn shutdown(mut self)

// EnvelopeSubscription — subscription handle
pub async fn next(&mut self) -> Option<Result<DecodedEnvelope>>
pub async fn shutdown(mut self)

// ws::subscribe — low-level direct WS
pub async fn subscribe(auth: Arc<MessageBoxAuth>, boxes: Vec<String>) -> Result<WsSubscription>

// WsSubscription — low-level WS handle
pub async fn shutdown(mut self)

// MessageBoxAuth — BRC-31 auth (CURRENTLY PRIVATE MODULE EXPORT)
pub fn new(relay_url: impl Into<String>, our_priv: PrivateKey) -> Result<Self>
pub fn start(&self)
pub async fn identity_hex(&self) -> Result<String>
pub fn relay_url(&self) -> &str
pub async fn sign_ws_upgrade(&self, path: &str, query: &str) -> Result<SignedWsHeaders>
```

---

## 8. CRITICAL STRUCTURAL TYPES (must preserve layout)

```rust
// live_relay_proof.rs:369 — field-based unwrap
pub struct InboundEnvelopeEvent {
    pub message_box: String,
    pub sender: String,
    pub message_id: String,
    pub body: String,
    pub via: InboundVia,
}

// handler closures (signing_handler.rs:192, dkg_handler.rs:193) — parameter type
pub struct DecodedRoundMessage {
    pub message_id: String,
    pub message_box: String,
    pub sender_pub: PublicKey,
    pub round_msg: RoundMessage,
    pub via: InboundVia,
}

// enum variants used in pattern matching (live_relay_proof.rs:260, 332)
pub enum InboundVia {
    WsPush,
    Backfill,
}
```

---

## 9. CONSTANTS USED IN TESTS & HANDLERS

From `crates/bsv-mpc-messagebox/src/types.rs`:

```rust
pub const BOX_DKG: &str = "mpc-dkg";          // Used in: dkg_via_messagebox_e2e, dkg_handler, messagebox_listener_e2e
pub const BOX_SIGN: &str = "mpc-sign";        // Used in: live_relay_proof, signing_handler, sign_mainnet_via_messagebox_e2e
pub const BOX_PRESIGN: &str = "mpc-presign";  // Not currently used in consumers
pub const BOX_ECDH: &str = "mpc-ecdh";        // Not currently used in consumers
pub const BOX_REFRESH: &str = "mpc-refresh";  // Not currently used in consumers
```

**All references are safe — constants are const and signature-free.**

---

## FINAL SUMMARY

### MessageBoxAuth pub(crate) H-4.5 Decision

**CANNOT MAKE pub(crate).** It is used in `live_relay_proof.rs` (the gate test):
- Direct construction: 3 call sites
- Direct method calls: 6 call sites
- Escape hatch via `ws::subscribe(auth, ...)`: 2 call sites

**Decision: Keep `pub mod auth;` and `pub use auth::MessageBoxAuth`.** The H-4.5 plan to remove this export would break the e2e proof immediately.

### ws::subscribe H-4.4 Risk

The raw `ws::subscribe()` function is called directly at `live_relay_proof.rs:226` and `322`. If H-4.4 deletes the raw WebSocket implementation:

1. **Option A (Safer):** Keep a wrapper `pub async fn subscribe(auth, boxes) -> Result<WsSubscription>` that internally uses Socket.IO instead of raw tungstenite.
2. **Option B (Breaking):** Delete the function and force the test to use `MessageBoxClient::subscribe()` (which will internally call Socket.IO).

Option A is lower-risk and preserves the public API contract. Option B requires updating all direct `ws::subscribe()` callers (2 in tests).

### Consumer Impact by Phase

| Phase | Consumer | Risk Level | Mitigation |
|-------|----------|-----------|-----------|
| H-4.4 (ws.rs replace) | `live_relay_proof.rs:226,322` | **CRITICAL** | Socket.IO wrapper or update test |
| H-4.4 (ws.rs replace) | `ws::subscribe()` signature | **CRITICAL** | Preserve as re-export wrapping Socket.IO |
| H-4.5 (MessageBoxAuth pub(crate)) | `live_relay_proof.rs:94,128,140,180` | **CRITICAL** | Keep `pub` export |
| H-4.4/4.5 (config gates) | `signing_handler.rs:192`, `dkg_handler.rs:193` | **HIGH** | Preserve `DecodedRoundMessage` layout |
| H-4.4/4.5 (config gates) | `messagebox.rs:112` | **HIGH** | Preserve `subscribe_round_messages()` signature |

---

## FILES MODIFIED BY THIS INVENTORY

- **Path:** `/Users/johncalhoun/bsv/mpc/bsv-mpc/docs/H-STEP-4-CONSUMER-MAP.md`
- **Line Count:** This document (approximately 650 lines)
- **Timestamp:** 2026-05-20

---

## REFERENCES

- **Plan:** `/Users/johncalhoun/bsv/mpc/bsv-mpc/docs/H-STEP-4-PLAN.md`
- **Crate:** `/Users/johncalhoun/bsv/mpc/bsv-mpc/crates/bsv-mpc-messagebox/`
- **Key Test (GATE):** `/Users/johncalhoun/bsv/mpc/bsv-mpc/crates/bsv-mpc-messagebox/tests/live_relay_proof.rs`
- **Service Integration:** `/Users/johncalhoun/bsv/mpc/bsv-mpc/crates/bsv-mpc-service/src/{messagebox,signing_handler,dkg_handler}.rs`

