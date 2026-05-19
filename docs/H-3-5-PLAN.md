# Phase H Step 3 — Gate H-3.5 plan (forced-hibernation reconnect via DO)

> For the Claude session picking up Phase H after H-3.4 lands. Read this
> file alongside `docs/PHASE-H-AUDIT.md` §11 (god-tier scope) and
> `docs/HANDOFF-PHASE-H-3-3B.md` (the gold-standard handoff style this
> plan mirrors).
>
> **Status:** plan-only. H-3.5 implementation has NOT started.
>
> **Predecessor gates locked:**
>   * `cb923fc` (H-3.1 build)
>   * `bc8b0b4` (H-3.2a polling)
>   * `6ff1a53` (H-3.2b WS upgrade)
>   * `0073e43` (H-3.3a Socket.IO CONNECT)
>   * H-3.3b (BRC-103 mutual auth via `SocketIoTransport` + `Peer`) — **just landed**
>   * H-3.4 (canonical envelope round-trip via signed Generals on `authMessage`) — **in progress**
>
> **This gate (H-3.5):** the deployed CF Worker survives a forced DO
> hibernation cycle and reconnects, with BRC-103 session state restored
> from DO storage so the wire identity remains continuous from the
> cosigner's perspective.

## TL;DR — the next concrete action

Scaffold a real `EngineIoSession`-style Durable Object inside
`poc/poc17-cf-outbound-ws/` that owns one outbound Socket.IO + BRC-103
session against the live relay. The DO replaces the per-request
ephemeral `PrivateKey::random()` + `WsHandle` shape with: a stable
identity priv (loaded from `SERVER_PRIVATE_KEY` secret, mirroring every
production Calhoun worker), a serialised `PeerSession` snapshot in
`state.storage` (NOT in the WS attachment — the outbound WS is **NOT**
hibernation-eligible per audit §1.2), and a reconnect-on-wake driver
that re-runs the BRC-103 handshake whenever the DO is invoked after
eviction. Pass criterion: a `/relay-via-do` route round-trips a
canonical envelope before AND after a forced hibernation cycle, with
both pre- and post-hibernation transcripts showing the SAME
`server_identity` value (proof of continuity) and the SAME
`client_identity` value (proof of stable identity).

Total estimated work: ~600-900 LOC + iteration over five sub-gates
(A → E), each its own commit with empirical proof. All five sub-gates
must land green before H-3.5 is considered closed.

## What this gate is — the DO's actual role

Per audit §11.4 ("DO scaffolding lands here") and §1.2 ("OUTBOUND-WS
has NO hibernation contract — reconnect-on-wake is mandatory"), the
DO in H-3.5 has **two distinct roles** that we previously kept
implicit. Make both explicit here so the implementation owns the
right surface:

### Role A — owner of the long-lived outbound Socket.IO + BRC-103 session

The DO is the cosigner's network presence. Its lifecycle:

1. **First fetch after creation**: load `SERVER_PRIVATE_KEY` from
   secret, build `ProtoWallet`, build `SocketIoTransport`, build
   `Peer`, drive the BRC-103 handshake against the live relay,
   serialise the resulting `PeerSession` to `state.storage`, return
   the synchronous result (e.g. an authenticated handle or a
   `server_identity` proof).
2. **Subsequent fetches while DO is hot**: re-use the in-memory `Peer`
   + `WsHandle`. No new handshake.
3. **Fetch after DO eviction (CF cost optimisation)**: the in-memory
   state is gone; the outbound WS to the relay is gone; ONLY the
   `state.storage`-persisted `PeerSession` snapshot and the identity
   priv (re-readable from the secret) survive. Reconnect: open a fresh
   Socket.IO + BRC-103 session to the relay, then DECIDE whether the
   persisted session can be reused or a fresh handshake is required
   (see §4 below).

### Role B — stable identity surface to consumers

External callers (the route handler that POSTs the relay request, or
future cosigner-side HTTP) address the DO by name (e.g. `id_from_name(
"cosigner-test-1")`); per-identity-DO is the topology lock per audit
§11.1. The DO presents a CONTINUOUS identity to its consumers across
hibernation — the cosigner's `client_identity` pubkey hex does NOT
change after a wake-cycle. The relay-side `server_identity` they see
ALSO does not change (it's the same relay's `SERVER_PRIVATE_KEY` →
public key). What MAY change after a wake-cycle: the Engine.IO `sid`,
the BRC-103 `session_nonce`, the `peer_nonce` — but those are
session-internal; consumers don't observe them.

### Locked decision: outbound-WS is NOT hibernation-eligible

`state.accept_web_socket()` (durable.rs:280) is for INBOUND
`WebSocketPair`-server sockets. There is zero Cloudflare-runtime
contract that says a `web_sys::WebSocket::new(url)`-created OUTBOUND
client socket can be passed to `accept_web_socket()` and survive
hibernation. The audit §1.2 already concluded this; H-3.5 implements
the consequence — reconnect-on-wake — rather than litigating it again.
The server-side DO at
`~/bsv/bsv-messagebox-cloudflare-public/src/engineio/session.rs:653`
calls `self.state.accept_web_socket(&pair.server)` on the SERVER half
of a `WebSocketPair` (inbound), which is why the server's WS survives
hibernation; the client (our DO) doesn't get that luxury.

## Identity persistence — stable per DO instance

H-3.3b uses `PrivateKey::random()` per request (`lib.rs:318`). H-3.5
replaces this with a stable identity. **Decision: load from
`SERVER_PRIVATE_KEY` secret, mirror every production Calhoun worker.**

### Evidence: this is the universal Calhoun pattern

| Reference | Pattern |
|---|---|
| `~/bsv/bsv-messagebox-cloudflare-public/src/lib.rs:61-64` | `env.secret("SERVER_PRIVATE_KEY").to_string()` → `AuthMiddlewareOptions.server_private_key` |
| `~/bsv/bsv-messagebox-cloudflare-public/src/engineio/auth.rs:174-177` | `make_wallet(hex)` → `PrivateKey::from_hex(hex)` → `ProtoWallet::new(Some(pk))` |
| `~/bsv/agents/test-agent/src/lib.rs:86-87, 427` | `env.secret("SERVER_PRIVATE_KEY")` per fetch |
| `~/bsv/agents/CLAUDE.md:85` | `npx wrangler secret put SERVER_PRIVATE_KEY` is the documented onboarding |
| `~/bsv/agents/CLAUDE.md:105` | `.dev.vars` carries `SERVER_PRIVATE_KEY` for local dev |
| `~/bsv/bsv-wallet-toolbox-rs/src/storage/client/storage_client.rs:227` | `ProtoWallet::new(Some(PrivateKey::from_wif("...")?))` is the canonical wallet construction Calhoun ships in production |

### Why NOT DO `state.storage` for the priv

We could persist a freshly-`random()` priv into `state.storage` on
first fetch and re-read it on every subsequent fetch. **Rejected.**
Reasons:

1. **Operational opacity.** A `SERVER_PRIVATE_KEY` secret is visible
   in `wrangler secret list` and can be rotated by ops; a
   storage-persisted priv is invisible to ops + un-rotatable without
   a bespoke admin route.
2. **DO eviction != identity rotation.** The cosigner's identity must
   be stable across the entire cosigner lifetime, not just within one
   DO incarnation. Using a secret means the identity is exactly
   "whoever holds `SERVER_PRIVATE_KEY` for this Worker", which is the
   correct semantic.
3. **Conformance with production.** Every shipped Calhoun cosigner
   pattern uses `SERVER_PRIVATE_KEY` from `env.secret`. Diverging
   here would split the operations story.

### Why NOT a future "wallet bind" (BRC-100)

A future iteration could connect to a BRC-100 wallet at
`localhost:3321` for derived per-cosigner keys (the `WALLET-3321.md`
pattern). **Out of scope for Phase H** — that's Phase I work where
the cosigner-as-CF-Worker has a separate signing wallet. H-3.5 just
needs a stable identity; the secret is the simplest correct path.

### Implementation shape for H-3.5

```rust
// In the DO's fetch() entry point:
let priv_hex = self.env
    .secret("SERVER_PRIVATE_KEY")
    .map_err(|_| Error::RustError("SERVER_PRIVATE_KEY not set".into()))?
    .to_string();
let client_priv = PrivateKey::from_hex(&priv_hex)
    .map_err(|e| Error::RustError(format!("invalid SERVER_PRIVATE_KEY: {e}")))?;
let wallet = ProtoWallet::new(Some(client_priv));
```

The priv is re-read on every fetch (cheap; matches the server
pattern at `engineio/auth.rs:174` which re-creates the wallet per
auth-message dispatch for the same reason — caching across
RefCell-bound mutations breaks Send bounds).

## Session restoration — what survives hibernation

BRC-103 session state, per `bsv-rs/src/auth/types.rs:288-311`:

```rust
pub struct PeerSession {
    pub is_authenticated: bool,
    pub session_nonce: Option<String>,           // our session id
    pub peer_nonce: Option<String>,              // server's nonce
    pub peer_identity_key: Option<PublicKey>,    // server identity
    pub last_update: u64,
    pub certificates_required: bool,
    pub certificates_validated: bool,
}
```

`PeerSession` is `Serialize + Deserialize` (line 288). It can be
written to DO `state.storage` directly.

### What we persist

A single record at storage key `brc103_session`:

```rust
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct PersistedBrc103Session {
    /// Full PeerSession snapshot — re-injectable into a fresh Peer
    /// via SessionManager::add_session() on wake.
    pub session: bsv::auth::types::PeerSession,
    /// Wall-clock ms when last serialised. Stored so a stale session
    /// (e.g. older than the relay-side server-session-TTL) can be
    /// discarded on wake rather than reused.
    pub persisted_at_ms: u64,
    /// The relay URL we authenticated against. Pinned so a config
    /// change to RELAY_URL invalidates the cached session.
    pub relay_url: String,
}
```

Estimated size: 2× 32-byte nonces hex + 33-byte pubkey hex + small
scalar fields + relay URL ≈ 300-500 bytes. Comfortable; `state.storage`
has no 2 KB cap (that's only the WS attachment slot).

### What we can re-derive without persisting

| Field | Re-derivable? | How |
|---|---|---|
| `client_priv` | yes | re-read `SERVER_PRIVATE_KEY` secret |
| `client_identity_pubkey` | yes | `client_priv.public_key()` |
| Engine.IO `sid` | NO — relay-assigned | a fresh polling handshake yields a new sid; we do NOT persist the old one |
| Socket.IO `sid` | NO — relay-assigned | same — fresh on every new Engine.IO session |
| `PeerSession.session_nonce` | NO | we generate this client-side; the relay tracks it |
| `PeerSession.peer_nonce` | NO | the relay generates this in `InitialResponse` |
| `PeerSession.peer_identity_key` | yes (stable) | the relay's identity is stable; could be re-read from a fresh handshake's `InitialResponse`, but persisting it lets us short-circuit the verify step |

### The server's deferred-emit behaviour, restated for the client side

The server defers the `authenticated` follow-up General until the
client's first post-auth General arrives (audit "the server-side
state machine" reference + `engineio/auth.rs:49-66`). On the CLIENT
side this means:

* After our `InitialRequest` → server's `InitialResponse`: we are
  authenticated FROM OUR PERSPECTIVE. `Peer::initiate_handshake`'s
  oneshot resolves with a successfully populated `PeerSession`.
* But the relay-side `authenticated_emitted` flag is `false` until
  we emit our first post-auth General.
* After hibernation+wake, if we reconnect via a fresh
  `InitialRequest`/`InitialResponse` cycle, the relay's
  `authenticated_emitted` resets too (new sid → fresh
  `SessionState` per `engineio/session.rs:141-152` and the storage
  rehydrate path at `:159-170`).
* Therefore: **a fresh BRC-103 handshake on wake is functionally
  identical to the first one from the relay's perspective.** The
  decision below ("when to reuse cached session vs re-handshake")
  reduces to: is reusing a still-live session WORTH the saved
  handshake RTT vs the extra failure-mode complexity of a stale
  cached session.

## Reconnect strategy — reuse vs re-handshake

### The two strategies

**Strategy 1 — re-handshake on every wake.** Throw away the
persisted `PeerSession`, do a fresh `polling_handshake +
WsHandle::open_and_upgrade + Socket.IO CONNECT + Peer::start +
SocketIoTransport::send(InitialRequest) → InitialResponse` cycle.
~3-4 RTTs total (matches the H-3.3b empirical bar: <2s wall-clock).
This is what the SERVER does — `engineio/session.rs:159-170` rebuilds
in-memory `SessionState` from the attachment, but the WS-LEVEL
session is the same one (the attachment survives because the WS
survived). For the CLIENT, the WS does NOT survive, so the entire
session is fresh.

**Strategy 2 — try to reuse the persisted `PeerSession`.** On wake,
do a fresh `polling_handshake + WsHandle + Socket.IO CONNECT` (those
ARE necessarily fresh — new sid), but SKIP the BRC-103
InitialRequest/InitialResponse exchange by injecting the persisted
`PeerSession` directly into a fresh `Peer`'s `SessionManager`. Send
the next outbound General signed with the cached `session_nonce`. If
the relay-side `engineio/auth.rs:` verify path accepts it (lookup by
`yourNonce` finds a Server-side session with the same nonces), we
saved one RTT.

### Strategy 1 wins for H-3.5

**Why.** The relay's per-sid `SessionState` is in the DO's
`inner: RefCell<Option<SessionState>>` (server `session.rs:290`).
On the relay side:

* The server-side `EngineIoSession` DO is keyed by Engine.IO sid.
* A new sid (which is forced on the client by a fresh polling
  handshake) means a fresh `EngineIoSession` DO instance with
  `inner = None` and no carry-over session state.
* The relay's `SessionAuthState` for that sid starts at
  `Unauthenticated`.
* Sending a signed General with our cached `session_nonce` against
  this fresh DO would be looked up by `yourNonce` in the relay's
  per-DO `SessionManager` — and find nothing, because the relay's
  SessionManager is fresh.
* Result: relay rejects the General. We waste a round-trip.

The only way Strategy 2 would work is if the relay's
`SessionAuthState` were keyed by *client identity* not *Engine.IO
sid*. It isn't — `session.rs:119` (`auth: SessionAuthState`) is a
per-`SessionState` field, and `SessionState` is per-sid. So the
relay-side server cannot honour a "resume by session nonce" without
a server-side change, which we will not make per
[[feedback_canonical_ts_immutable]].

**Conclusion: Strategy 1.** Re-handshake on every wake. Drop the
persisted `PeerSession.session_nonce` / `peer_nonce` after every
restored use; only keep `peer_identity_key` for short-circuit
verification of "this is still the same relay" (optional sanity
check).

### Refined: what we DO persist + what we drop on wake

After accepting Strategy 1, the `PersistedBrc103Session` shape
simplifies. We keep it (for the rare case where we need to verify
"the relay's identity is stable across our hibernation") but we don't
INJECT it into the SessionManager — we re-handshake unconditionally.

```rust
pub struct PersistedBrc103Session {
    /// Last-known relay identity. Used ONLY for a soft-check that
    /// the relay hasn't been replaced under us; if the fresh
    /// InitialResponse's identity_key differs from this, log a
    /// warning and proceed (a re-keyed relay is a legitimate state).
    pub last_known_peer_identity_hex: String,
    /// Wall-clock ms when last serialised. Useful for ops dashboards.
    pub persisted_at_ms: u64,
    /// The relay URL we authenticated against. Stored for telemetry.
    pub relay_url: String,
}
```

This is ~200 bytes max. The cached `peer_identity` is for telemetry
only; the *authoritative* server identity is whatever the fresh
`InitialResponse` carries.

### Reconnect-loop topology

```
DO.fetch(req):
  1. Ensure identity: load SERVER_PRIVATE_KEY → priv → wallet (cheap; re-read every fetch per server pattern).
  2. Ensure session: if `inner.peer.is_none()`:
       a. Try `state.storage.get("brc103_session")` → PersistedBrc103Session (log-only sanity).
       b. polling_handshake(relay) → handshake.
       c. WsHandle::open_and_upgrade(relay, handshake.sid).
       d. SocketIO CONNECT to default namespace.
       e. Build SocketIoTransport + Peer::new + peer.start().
       f. Manually send AuthMessage::InitialRequest (Path 2 from H-3.3b).
       g. snoop_rx.await → server_identity. Compare to persisted; log mismatch.
       h. Spawn dispatch task (run_dispatch).
       i. Persist new PersistedBrc103Session with persisted_at_ms = now.
       j. Stash {peer, ws_sender, server_identity} into `inner`.
  3. Dispatch the request to the in-memory Peer (send a General, etc.)
  4. Return response.

DO.alarm() (future — Phase I):
  - Periodic keepalive or pre-emptive reconnect.
  - Not needed for H-3.5 — sufficient that re-entry through fetch()
    triggers reconnect.
```

## Sub-gates — H-3.5 broken into 5 commits

Each commit lands on `main` with its own empirical proof, mirroring
the H-3.3a/b style. NO `--no-verify`. Each gate's wrangler dev curl
output is included in the commit message.

| Gate | Scope | Empirical proof |
|---|---|---|
| **H-3.5a** | DO scaffolding compiles + routes through DO. Replace the per-request `PrivateKey::random()` + inline route with a real `EngineIoSessionDO` DO bound in `wrangler.toml`, keyed by `id_from_name("cosigner-test-1")`. Just enough to prove the DO routes a fetch through and reads `SERVER_PRIVATE_KEY`. No session persistence yet. | `cargo build --target wasm32-unknown-unknown -p poc17-cf-outbound-ws` clean; `curl /relay-via-do/identity` returns `{"client_identity":"02..."}` with the SAME hex on two consecutive calls (proves stable priv). |
| **H-3.5b** | In-DO Socket.IO + BRC-103 handshake. Move the H-3.3b handshake logic from `lib.rs:223-385` INTO the DO's `fetch()`. Same wire shape, same proof JSON, but now driven by the DO. No persistence yet. | `curl /relay-via-do/handshake` returns `{client_identity, server_identity, gate: "H-3.5b"}` — both hex pubkeys non-empty. |
| **H-3.5c** | Round-trip canonical envelope through the DO-owned `Peer`. Wire the DO to accept a `/relay-via-do/echo` POST that emits a signed General to the relay and surfaces the relay's echo back. Uses the canonical MPC-Spec §05 envelope shape verified in H-3.4. **Depends on H-3.4 landing first.** | `curl -X POST /relay-via-do/echo -d '<envelope cbor base64>'` returns the same envelope CBOR; byte-equality with the input. Sanity-print the General's `your_nonce` to verify it matches `session_nonce` from the handshake. |
| **H-3.5d** | Persist BRC-103 session state to `state.storage` after handshake. Implement `PersistedBrc103Session` + read-on-fetch + write-after-handshake. Add a sanity check: if persisted `last_known_peer_identity_hex` differs from a fresh handshake's `InitialResponse.identity_key`, log a warning but proceed. | `curl /relay-via-do/identity` → JSON includes `persisted_at_ms: N`; immediately re-curl → same `persisted_at_ms` (proves persistence read worked, no re-write); rotate the DO's name → `persisted_at_ms` resets (proves per-DO scoping). |
| **H-3.5e** | **The H-3.5 merge gate.** Forced-hibernation reconnect proof. Drive a hibernation cycle and confirm a subsequent fetch reconnects + re-handshakes + returns the same `client_identity` + same `server_identity` as before. Persisted `last_known_peer_identity_hex` survives the cycle. | See §6 for the empirical harness. JSON proof contract: `curl /relay-via-do/handshake`, persist `request_a` (pre-hibernation). Force hibernation (see §6). `curl /relay-via-do/handshake`, persist `request_b` (post-hibernation). `jq '.client_identity == "<request_a.client_identity>"'` → true. `jq '.server_identity == "<request_a.server_identity>"'` → true. `jq '.handshake_round_trip_ms < 2000'` → true on BOTH sides. |

## Empirical proof harness — forcing hibernation

`wrangler dev --local` (miniflare) does NOT hibernate DOs by default;
they live for the lifetime of the dev process. Two viable paths:

### Path 1 (recommended): deploy to dev CF, idle-out, retry

1. `wrangler deploy` to the Calhoun dev CF account (account_id is in
   `~/bsv/rust-message-box/wrangler.toml`; the bsv-mpc POC has been
   getting routed locally via `wrangler.example.toml`).
2. `curl /relay-via-do/handshake` → save as `pre.json`.
3. Wait ≥ ~70s — CF evicts idle DOs aggressively (the exact threshold
   isn't documented but anecdotally is between 30s and 90s of zero
   incoming requests; the audit §1.2 third risk's mitigation
   assumes this behaviour).
4. `curl /relay-via-do/handshake` → save as `post.json`.
5. `jq '.client_identity' pre.json post.json` → both equal.
6. `jq '.server_identity' pre.json post.json` → both equal.
7. `jq '.handshake_round_trip_ms < 2000' post.json` → true.

Save the full transcript in the H-3.5e commit message. The
`wrangler tail` output for the post-hibernation request MUST
include `EngineIoSession: rehydrated …` style log lines (we add a
mirror log call to our DO indicating "cold-wake from storage" so the
proof is unambiguous).

### Path 2 (best-effort local): force-evict via dev-only admin route

If Path 1's idle-timeout is too slow for iteration, add a
`#[cfg(feature = "dev")]`-gated route `/relay-via-do/_force_evict`
that drops the in-memory `inner` (mutates the `RefCell<Option<...>>`
to `None`). This SIMULATES hibernation behaviourally (the next fetch
sees `inner is None` → triggers the storage reload + reconnect path)
without forcing the CF runtime to actually evict the DO. Use it
during iteration, but the H-3.5e merge-gate commit MUST include the
Path 1 deploy + idle-out transcript — not just the dev-eviction
simulation. The simulation is for fast iteration, the deploy is for
truth.

**No `state.abort()` API exists** in worker 0.7.5
(`abort.rs` is for `Fetch` request aborts, not DO eviction; see
`/Users/johncalhoun/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/worker-0.7.5/src/abort.rs:5-58`).
This is the same conclusion the audit §6.2 H-3.5 row reaches when it
references `state.abort()` as a hypothetical.

## DO topology — confirmed: per-identity

Audit §11.1 already locked: per-identity DO. Confirmed for H-3.5:

* The DO is keyed by `id_from_name(<cosigner-id>)` (worker 0.7.5
  durable.rs:81), where `<cosigner-id>` is a stable per-cosigner string
  (for the POC: `"cosigner-test-1"`; Phase I will inject the real
  cosigner-id from the DKG ceremony or from a header).
* One DO instance owns one outbound Socket.IO + BRC-103 session.
* The `state.storage` for that DO holds the persisted
  `PersistedBrc103Session`.
* Multiple cosigners → multiple DOs, each with its own session +
  storage, all sharing the same `SERVER_PRIVATE_KEY` secret in the
  POC (Phase I will derive per-cosigner privs from the secret +
  cosigner-id, or move to a wallet-bind pattern).

No need to re-litigate: per-identity is the canonical Calhoun pattern
(`bsv-messagebox-cloudflare-public/src/message_hub.rs:236-256` is
per-identity), and isolating one BRC-103 session per DO matches the
server's own per-sid `EngineIoSession` isolation
(`bsv-messagebox-cloudflare-public/src/engineio/session.rs:276-291`).

## Risks + mitigations

### R1 — `web_sys::WebSocket` from outbound DO context may not hibernate

| | Detail |
|---|---|
| **What** | The audit §1.2 conclusion ("outbound WS does NOT survive hibernation") is based on docs + the absence of an outbound contract; H-3.5e empirically proves the runtime behaviour matches. If it does, fine — Strategy 1 (re-handshake on wake) is correct. If somehow the WS DOES survive, we waste effort but don't break correctness. |
| **Mitigation** | The reconnect-on-wake path is correct EITHER WAY. If the WS happens to survive, our `inner.peer.is_none()` check correctly notices it and rebuilds anyway (we cannot rely on a `web_sys::WebSocket` reference outliving an isolate eviction, regardless of what runtime tricks may technically exist). |

### R2 — DO eviction in `wrangler dev` is unobservable

| | Detail |
|---|---|
| **What** | Miniflare doesn't hibernate; our dev-loop can't easily exercise the wake path. |
| **Mitigation** | Two-track empirical: Path 2 (force-evict simulation) for iteration speed, Path 1 (deploy + idle-out) for truth. H-3.5e commit MUST include the Path 1 transcript; lab-bench acceptance via Path 2 is insufficient. |

### R3 — relay-side `EngineIoSession` DO may also have evicted between our wakes

| | Detail |
|---|---|
| **What** | The Calhoun relay's per-sid DO has the same eviction model. If we wake at hour 1 and the relay's per-sid DO was evicted at hour 0:30, our session's relay-side state is gone too. But — relay-side state rehydrates from WS attachment (`engineio/session.rs:159-170` reading the attachment that survived). The relay's WS attachment survives because the relay's WS-server-end survives (it's accepted via `accept_web_socket`). |
| **Mitigation** | Our reconnect uses a fresh sid, so we open a fresh per-sid DO on the relay anyway — no dependency on relay-side state surviving. This works by construction of Strategy 1. |

### R4 — `SERVER_PRIVATE_KEY` secret not set in local dev

| | Detail |
|---|---|
| **What** | `wrangler dev --local` reads from `.dev.vars`; if absent the `env.secret("SERVER_PRIVATE_KEY")` call errors. |
| **Mitigation** | Document in `poc/poc17-cf-outbound-ws/README.md` that H-3.5 requires a `.dev.vars` with `SERVER_PRIVATE_KEY=<hex>`. The H-3.5a sub-gate commit adds a `.dev.vars.example`. The `.git/hooks/pre-commit:5` pattern is `wrangler\.toml` (per H-3.3b handoff §"Locked decisions"), NOT `dev.vars`, so the example file is committable as-is; the real `.dev.vars` is `.gitignore`'d by miniflare convention. |

### R5 — `state.storage.get` returning `None` ≠ first-time DO

| | Detail |
|---|---|
| **What** | After H-3.5d ships, a brand-new DO has `state.storage.get("brc103_session") == None`. After a SECOND wake the get returns `Some(...)`. Easy to mis-handle: if we write code that assumes `None` means "fresh DO, do handshake" and `Some` means "reuse session", we conflate first-time and post-wake — both should re-handshake. |
| **Mitigation** | Code-level: the "fetch a brc103 session" function returns `Option<PersistedBrc103Session>` for telemetry-only; the reconnect ALWAYS handshakes regardless. The persisted record is consulted purely for the "did the relay identity flip" sanity check. |

### R6 — `wrangler dev --local` outbound network policy

| | Detail |
|---|---|
| **What** | Some CF runtime versions sandbox local DOs from outbound networking. H-3.2 + H-3.3a/b already proved outbound WS works from a CF Worker fetch handler in local dev; H-3.5 needs the same to work from inside a DO's fetch handler. Different scope, different risk. |
| **Mitigation** | H-3.5a's empirical proof is exactly this: a DO that loads the priv from secret and returns its pubkey. If the DO can't even READ a secret in local dev, we discover it at the first sub-gate. H-3.5b then proves outbound network from inside the DO. |

## Out of scope for H-3.5

Explicit list of things H-3.5 does NOT do:

1. **D1 / SQLite-backed cosigner state persistence.** The DO uses
   `state.storage` (KV-shaped) for the BRC-103 session record. MPC
   ceremony state (KeyShares, presigs, DKG round buffers) is Phase I.
2. **Native unification onto Socket.IO + BRC-103.** Audit §11.3
   pulled this INTO Phase H scope, but it's Phase H Step 4
   (graduation into `crates/bsv-mpc-messagebox/`), not H-3.5.
3. **`/listMessages` backfill on reconnect.** Audit §1.2 lists this
   as a hibernation contract item; it's a Phase H Step 4 concern
   (the existing native `ws.rs:239-241` flow gets ported to the new
   transport). The H-3.5 POC has no concept of "messages missed" yet
   — only the BRC-103 session is exercised.
4. **Reconnect backoff / retry loop.** The native `ws.rs:218-274`
   has exponential backoff 1s→30s. H-3.5 does NOT add a backoff
   loop — the DO's lazy reconnect-on-fetch is sufficient for the POC.
   Phase I adds the loop in `alarm()` / `ws_native.rs`-equivalent.
5. **Per-cosigner key derivation.** All POC DOs share
   `SERVER_PRIVATE_KEY`. Real per-cosigner privs are Phase I work
   (DKG ceremony output → cosigner identity priv, OR wallet-bind).
6. **Multi-room subscribe.** The POC's `/relay-via-do/echo` is a
   single-shot envelope round-trip, no `joinRoom`/`leaveRoom`. Audit
   §6.3 already excluded multi-room from POC scope; H-3.5 inherits.
7. **`Peer::initiate_handshake` use.** H-3.3b proved Path 2
   (manual InitialRequest construction) works around the
   tokio-bound timeout machinery; H-3.5 reuses Path 2 unchanged.
   `Peer::initiate_handshake`'s wasm32 fix is a bsv-rs upstream
   ecosystem follow-up, not Phase H.
8. **Cross-stack readiness probe against Binary's TS server.** Audit
   §11.5 §7.4 lists this as a Phase H merge gate; it's a Phase H
   Step 5 task, not H-3.5.

## Critical references — in suggested reading order

1. **`docs/PHASE-H-AUDIT.md` §§11.1, 11.3, 11.4, 11.5** — locked
   decisions on per-identity DO + native unification + amended merge
   gate.
2. **`docs/HANDOFF-PHASE-H-3-3B.md`** — gold-standard handoff
   format; this plan mirrors its sub-gate + empirical proof
   discipline.
3. **`~/bsv/bsv-messagebox-cloudflare-public/src/engineio/session.rs`**
   — server-side DO state machine. Key lines:
   * `:82-97` — `Transport` enum; serde-roundtrip pattern.
   * `:101-152` — `SessionState` + `from_attachment` / `to_attachment`.
   * `:159-184` — the persist/rehydrate methods we MIRROR on the
     client side (with `state.storage` not WS attachment).
   * `:228-241` — `WsAttachment` serde-roundtrip shape; size
     calculus reference (~250B baseline).
   * `:467-503` — `rehydrate_from_ws_attachment` — the exact
     "DO awoke; state.inner is None; recover from persisted slot"
     pattern, just with `state.storage` instead of WS attachment
     since our WS is outbound.
4. **`~/bsv/bsv-messagebox-cloudflare-public/src/engineio/auth.rs:87-118`**
   — `SessionAuthState` enum that's the structural inspiration for
   our `PersistedBrc103Session`. Note: their state machine is
   `Unauthenticated`/`Authenticated{nonces, peer_identity_key}`;
   we collapse to "always re-handshake" so we don't need the
   `Authenticated` enum variant — just the
   `last_known_peer_identity_hex` telemetry field.
5. **`~/bsv/bsv-rs/src/auth/types.rs:288-311`** — `PeerSession`
   shape that we DON'T persist (we re-derive). Keep in mind that
   if Phase I needs to persist it (e.g. to skip the handshake when
   the relay does support resume-by-identity-key), the
   `Serialize + Deserialize` is already there.
6. **`~/bsv/bsv-rs/src/auth/peer.rs:103-149`** — `Peer` struct +
   `Peer::new`. Note that the session_manager is an
   `Arc<RwLock<SessionManager>>` (line 106) — we can't share a `Peer`
   across multiple DOs but we don't need to (per-identity DO).
7. **`~/bsv/bsv-rs/src/auth/peer.rs:524-525`** — `session_manager()`
   public accessor; useful if Phase I wants to interrogate the
   session state directly.
8. **`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/worker-0.7.5/src/durable.rs`**
   — worker 0.7.5 DO API. Key lines:
   * `:81-92` — `Namespace::id_from_name` + `Namespace::get_stub`.
   * `:253` — `State::storage()` for the KV-shaped storage.
   * `:280-282` — `accept_web_socket` (for INBOUND sockets — NOT
     used by H-3.5; the WS is outbound).
   * `:292-308` — `get_websockets` (also for inbound; NOT used).
   * `:481-509` — `get_alarm` / `set_alarm` (NOT used in H-3.5;
     potentially Phase I).
9. **`~/bsv/agents/test-agent/src/lib.rs:86, 427-444`** — the
   canonical Calhoun pattern for `env.secret("SERVER_PRIVATE_KEY")`
   + `PrivateKey::from_hex` + exposing the `serverIdentityKey` JSON
   field. Mirror this exactly for the H-3.5a `/identity` route.
10. **`poc/poc17-cf-outbound-ws/src/worker_do.rs`** — the EXISTING
    stub (`WsAttachment` placeholder, ~33 LOC). H-3.5a replaces it
    with the real `#[durable_object]` impl.
11. **`poc/poc17-cf-outbound-ws/src/lib.rs:223-385`** — H-3.3b
    inline handshake. The H-3.5b sub-gate MOVES this logic into the
    DO; the existing route either deletes or becomes a thin proxy.
12. **`poc/poc17-cf-outbound-ws/src/transport_socketio.rs`** —
    `SocketIoTransport` (Clone-able via internal `Arc`-shared
    state). Already H-3.3b-proven; no changes for H-3.5.
13. **`~/bsv/agents/CLAUDE.md:85, 105`** — `SERVER_PRIVATE_KEY`
    secret management discipline (wrangler secret put + .dev.vars).

## Locked discipline (carried forward from H-3.3b)

* 5-step workflow per phase. H-3.5 has 5 sub-gates (a/b/c/d/e), each
  its own commit.
* Each gate's commit lands on `main` BEFORE the next gate begins.
* `cd ~/bsv/mpc/bsv-mpc/` for all commits (NEVER
  `bsv-mpc-old-unscrubbed/`).
* 110%-no-asterisks: every commit's gate must be empirically
  verified before the commit lands. wrangler dev + curl is the
  iteration harness; **for H-3.5e specifically, the deploy + idle-out
  Path 1 evidence is REQUIRED** — not optional.
* `cargo fmt --all -- --check` AND `cargo clippy --workspace
  --all-targets -- -D warnings` clean before push (lesson from
  G-5b's fmt break).
* Pure Rust+WASM. JS bundle is Plan B fallback only (audit §11.2
  revised); H-3.5 inherits this.
* Path A: implementation conforms to canonical TS, never the
  inverse.
* god-tier + full-stack awareness — consult `~/bsv/` Rust + TS
  reference stack before proposing fixes; the canonical patterns
  for hibernation live at
  `~/bsv/bsv-messagebox-cloudflare-public/src/engineio/session.rs`
  (server-side) and the identity pattern lives in
  `~/bsv/agents/*/src/lib.rs` (every production Calhoun worker).

## Out-of-tree files referenced

| Path | Why |
|---|---|
| `~/bsv/bsv-rs/` | Calhoun-controlled. `PeerSession`, `Peer`, `SessionManager`. |
| `~/bsv/bsv-messagebox-cloudflare-public/src/engineio/session.rs` | Server-side DO + persist/rehydrate pattern we mirror. |
| `~/bsv/bsv-messagebox-cloudflare-public/src/engineio/auth.rs` | Server-side BRC-103 state-machine shape; structural reference for `PersistedBrc103Session`. |
| `~/bsv/agents/test-agent/src/lib.rs` | Canonical Calhoun secret-loading pattern. |
| `~/bsv/agents/CLAUDE.md` | Secret-management ops discipline. |
| `~/bsv/bsv-wallet-toolbox-rs/src/storage/client/storage_client.rs` | ProtoWallet construction pattern (Calhoun reference). |
| `~/.cargo/registry/.../worker-0.7.5/src/durable.rs` | Worker 0.7.5 DO API surface. |
| `~/bsv/mpc/bsv-mpc/secrets.md` | Gitignored; CF API token for deploys. Path 1 forced-hibernation harness requires this. |

## Open questions before H-3.5 implementation can start

1. **Which DO name for the POC?** Recommend `"cosigner-test-1"` for
   H-3.5a (matches the test-agent / e2e naming convention). User
   confirmation requested.
2. **Local `.dev.vars` priv — disposable test key, or reuse a
   gitignored existing one?** Recommend a freshly generated
   throwaway key just for the POC, documented in
   `poc/poc17-cf-outbound-ws/README.md` with a one-liner shell to
   generate. NOT reusing any existing Calhoun priv (no risk of
   accidental cross-environment use).
3. **Path 2 force-evict simulation — feature-gate name?** Recommend
   `#[cfg(feature = "dev-evict")]` (NOT `default-features`). Keeps it
   off in CI + deploy builds.
4. **`/relay-via-do` URL prefix vs. replacing `/brc103-handshake` in
   place?** Recommend NEW prefix `/relay-via-do/*` so the H-3.3b
   route stays green as a regression safety net. If H-3.5b breaks the
   handshake, the old `/brc103-handshake` route can re-prove the
   substrate didn't regress.
5. **H-3.4 dependency on H-3.5?** H-3.5c needs the H-3.4 envelope
   round-trip semantics to be locked. Confirm H-3.4 ships before
   H-3.5c starts. (H-3.5a + H-3.5b can run in parallel with H-3.4
   since they don't touch envelope CBOR — only the BRC-103 transport.)

## What I'm NOT doing in this plan

* Writing any of the implementation (H-3.5a-e is the next session's
  work).
* Picking the exact `worker_do.rs` module layout (let H-3.5a's
  implementation pick the shape that fits cleanest with the worker
  0.7.5 `#[durable_object]` macro).
* Pre-empting the user's choice on the open questions above —
  resolve them before H-3.5a starts.

---

**Live MessageBox relay:** `https://rust-message-box.dev-a3e.workers.dev`
**Local wrangler dev port:** `8787`
**H-3.5 target routes:** `/relay-via-do/identity`, `/relay-via-do/handshake`, `/relay-via-do/echo`
**Empirical bar for H-3.5 (merge):** see §6 — `pre.json` + `post.json` from a deploy+idle-out cycle, with `client_identity` + `server_identity` byte-identical across the hibernation boundary, post-hibernation `handshake_round_trip_ms < 2000`.
