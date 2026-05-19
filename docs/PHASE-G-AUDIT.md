# Phase G Audit — `bsv-mpc-core` SM bridge rewrite + Paillier safe-prime pool

> Investigation + design doc for Phase G of the v1.0 CF-native cosigner
> plan in [`NEXT-STEPS.md`](NEXT-STEPS.md). Written 2026-05-19. Lands on
> `main` BEFORE the POC + implementation commits. Every claim here has
> a `file:line` citation; if a claim is unsupported, it's flagged with
> "needs verification" inline.
>
> **Status:** draft 1 — pending user review before POC step starts.

## TL;DR

Two interlocking design decisions for Phase G:

1. **Drop the `std::thread` + `std::sync::mpsc` SM bridge entirely.**
   Investigation surfaced that `round_based::StateMachine::proceed()` is
   non-blocking by construction — it returns `NeedsOneMoreMessage` when
   it wants input. The existing thread+mpsc bridge added the blocking
   artificially. Hold the `StateMachineImpl` directly on each
   coordinator struct. `process_round()` becomes a sync function that
   feeds incoming → drives `proceed()` until `NeedsOneMoreMessage` →
   returns outbound. No tokio dep added to `bsv-mpc-core`. WASM-compatible
   by construction. ~150-200 LOC simpler than the spawn-based bridge,
   ~300 LOC simpler than the originally-anticipated `LocalSet` rewrite.

2. **Add a Paillier safe-prime pool** (`crates/bsv-mpc-core/src/paillier_pool.rs`)
   per [MPC-Spec §06.10.1](../../MPC-Spec/06-transport.md) and
   [ADR-0041](../../MPC-Spec/decisions/0041-network-profile-latency-budgets.md).
   `aux_info_gen` already accepts `PregeneratedPrimes<L>` (cggmp24
   exposes `TryFrom<[Integer; 4]>` for injection); `DkgCoordinator`
   already has `set_pregenerated_primes()`. What's missing is the pool
   itself: at-rest-encrypted, ≥2 keypair floor, idle regen. ~200-300
   LOC + tests per ADR-0041 § Consequences.

These two changes are intentionally bundled in Phase G because the
inline rewrite removes the threading concern that previously made
prime-gen-pool integration awkward, and the prime-gen pool is the only
honest answer to the "CPU budget" question (the thread/spawn rewrite
alone does not solve it — both options run on the same CF executor and
both block under the 30s wall-clock cap during Paillier safe-prime gen).

Quality-gate target unchanged from [`NEXT-STEPS.md`](NEXT-STEPS.md):
existing Phase D + E mainnet TXID byte-shape preserved, plus new
`wasm32-unknown-unknown` 2-of-2 DKG sim test green end-to-end, plus
prime-pool-fed `aux_info_gen` produces byte-identical `AuxInfo` to the
inline-generated version.

## 1. Investigation findings (Phase G Step 1)

Three parallel Explore agents surveyed independently on 2026-05-19. Raw
agent reports preserved in the session transcript; the empirical
headlines are below with file:line citations.

### 1.1 Current `std::thread` + `std::sync::mpsc` bridge — what we have today

Three coordinators each spawn a dedicated OS thread to host the cggmp24
state machine and bridge in/out messages via unbuffered, blocking
`std::sync::mpsc` channels. The pattern is **identical across all
three** (DKG, signing, presigning); only the SM input type differs.

**DKG** (`crates/bsv-mpc-core/src/dkg.rs`):
- `DkgCoordinator::start_keygen_sm()` at `dkg.rs:410-431` — spawns the
  keygen thread; thread body at `dkg.rs:759-908`. Calls
  `run_keygen_sm(eid, my_index, n, t, inbound_rx, outbound_tx)`.
- `DkgCoordinator::start_aux_info_sm()` at `dkg.rs:437-475` — spawns
  the auxinfo thread; thread body at `dkg.rs:914-1081`. Calls
  `run_aux_info_sm(eid, my_index, n, pregenerated_primes, inbound_rx,
  outbound_tx)`.
- Public surface: `init() -> Result<Vec<RoundMessage>>` (returns initial
  outbound), `process_round(Vec<RoundMessage>) ->
  Result<DkgRoundResult>` (returns `NextRound(Vec<RoundMessage>) |
  Complete(DkgResult)`).
- Channel message types `SmInbound` / `SmOutbound` at `dkg.rs:137-154`.

**Signing** (`crates/bsv-mpc-core/src/signing.rs`):
- `SigningCoordinator::start_signing_sm()` at `signing.rs:348-392`;
  thread body `run_signing_sm()` at `signing.rs:555-736`.
- Channel message types `SmInbound` / `SmOutbound` at `signing.rs:83-98`.

**Presigning** (`crates/bsv-mpc-core/src/presigning.rs`):
- `PresigningManager::start_presigning_sm()` at `presigning.rs:372-434`;
  thread body `run_presigning_sm()` at `presigning.rs:590-719`.
- Channel message types `SmInbound` / `SmOutbound` at `presigning.rs:80-98`.

**Shared SM driver-loop shape** across all three (cited from
`run_keygen_sm`, identical structure elsewhere):
```rust
loop {
    match sm.proceed() {
        SendMsg(out)         => outbound_tx.send(OutgoingMessage(...))?,
        NeedsOneMoreMessage  => {
            outbound_tx.send(NeedsMessage)?;
            let inbound = inbound_rx.recv()?;   // ← BLOCKS HERE
            sm.received_msg(inbound)?;
        }
        Yielded              => continue,
        Output(result)       => { outbound_tx.send(Complete(...))?; return; }
        Error(e)             => { outbound_tx.send(Error(...))?; return; }
    }
}
```

**The blocking is entirely artificial.** `proceed()` itself returns
immediately when it needs input. We block only because we put
`inbound_rx.recv()` inside the SM thread loop. This is the single most
important investigation finding for Phase G.

**Other concerns observed:**
- `OsRng` is sourced inside each thread (no thread-local; no cross-call
  determinism needed): `dkg.rs:773` (keygen), `dkg.rs:946` (auxinfo),
  `signing.rs:598`, `presigning.rs:615`.
- `Send + 'static` bounds are implicit via `std::thread::Builder::spawn`;
  not visible in any public API.
- Unit tests use `round_based::sim::run()` (in-process simulation): DKG
  `dkg.rs:1550-1648`, signing `signing.rs:1270-1371`, presigning
  `presigning.rs:1054-1140`. These do NOT spawn threads — they drive
  the SM via the framework's own simulator. **These tests are
  threading-agnostic** and will pass unchanged after the inline rewrite.
- ~3,325 LOC across the three coordinator files (dkg.rs ~1,563 +
  signing.rs ~1,562 + presigning.rs ~1,200, including tests + helpers).

### 1.2 `round_based` + cggmp24 async surface — what we have to work with

**`round_based::StateMachine` trait** (cargo registry,
`round-based-0.4.1/src/state_machine/mod.rs:76-104`):
```rust
pub trait StateMachine {
    type Output;
    type Msg;

    fn proceed(&mut self) -> ProceedResult<Self::Output, Self::Msg>;
    fn received_msg(&mut self, msg: crate::Incoming<Self::Msg>)
        -> Result<(), crate::Incoming<Self::Msg>>;
}
```

Both methods are `fn`, not `async fn`. No `Send` or `Sync` bound on the
trait itself.

**`StateMachineImpl` is `!Send`.** Internal state holds
`SharedStateRef<M>(Rc<RefCell<SharedState<M>>>)` —
`round-based-0.4.1/src/state_machine/shared_state.rs:3`. Both `Rc` and
`RefCell` are `!Send`, so any `StateMachine` instance is `!Send`.

**Implication:** `tokio::task::spawn()` is unavailable (it requires
`Send`); only `tokio::task::spawn_local()` + `LocalSet` would work for
the originally-anticipated rewrite. BUT — since `proceed()` is
non-blocking, we don't need to spawn at all (§2 below).

**No async StateMachine variant exists** in `round_based` v0.4.1.
`async fn` protocols are wrapped via `wrap_protocol()` and polled with
`noop_waker()` — proven at `round-based-0.4.1/src/state_machine/mod.rs:189,243-264`.

**Heavy synchronous compute lives inside `proceed()`** for the auxinfo
flow: Paillier 2048-bit safe-prime generation, plus ~64KB `paillier-blum`
and ~32KB Pedersen `prm` ZK proofs per round
([§06.10.3 source notes](../../MPC-Spec/06-transport.md)). Wall-clock
reference for safe-prime gen: 1-3s desktop / 5-15s ARM mobile per
prime, 4 primes per party (Mobile p99 ≈ 33s).

**cggmp24 fork already exposes the prime-injection API:**
- `PregeneratedPrimes<L>` struct at
  `cggmp21-fork/cggmp24/src/key_refresh.rs:31`.
- `TryFrom<[Integer; 4]>` impl for injection at
  `cggmp21-fork/cggmp24/src/key_refresh.rs:36`.
- `PregeneratedPrimes::generate(rng)` (inline-gen) at
  `cggmp21-fork/cggmp24/src/key_refresh.rs:60-78`.
- `aux_info_gen(eid, i, n, pregenerated)` signature at
  `cggmp21-fork/cggmp24/src/lib.rs:400-415` — takes
  `PregeneratedPrimes<L>` as a parameter.

**Fork-only patch `set_additive_shift()` is irrelevant to Phase G** —
pure builder method on a signing config, no Send/Sync implications.

**POC 2 (`poc/poc2-wasm/`) ran a full end-to-end protocol on WASM**
(DKG → aux_info_gen → signing → presigning) — `poc/poc2-wasm/src/lib.rs:59-296`.
But monolithically, in a single `wasm_bindgen` fn call. It does NOT
prove multi-round HTTP-paced execution, state suspension/resume, or CF
30s budget compliance under realistic load. POC 10 is the canonical
multi-round runtime proof for those — `poc/poc10-cf-worker-https/`.

### 1.3 CF Worker prior art — what `~/bsv/` already proves

**Zero prior art in `~/bsv/` for `tokio::task::LocalSet` + `spawn_local`
in Rust CF Workers.** Every Rust CF Worker examined uses `worker = "0.7"`
executor only, no tokio dependency:
- `bsv-mpc/crates/bsv-mpc-worker/Cargo.toml:18` — `worker = "0.7"`, no tokio.
- `poc/poc2-wasm/Cargo.toml:16-28` — same.
- `poc/poc10-cf-worker-https/worker/Cargo.toml:16-37` — same.
- `~/bsv/agents/reader-agent/Cargo.toml:10-18` — same.
- `~/bsv/teraworm/worker/` — same (per Explore G-1c).

**Durable Object state patterns avoid `!Send` types entirely.** The
inbound-WS DO in `bsv-messagebox-cloudflare-public/src/message_hub.rs`
holds per-socket state as a serializable `SocketAttachment` via
`workers-rs 0.8`'s `serialize_attachment()` / `deserialize_attachment()`
API, recovered per event handler. No `Rc<RefCell<_>>` anywhere in
production DO fields. This shape generalizes: **inside a CF Worker, the
async runtime is single-threaded but `!Send` state lives only inside the
fetch-handler scope, not in DO struct fields.** A `StateMachineImpl`
held in a coordinator passed through the fetch-handler scope is fine.

**`tokio::task::yield_now()` exists in cggmp24 signing.rs but is
protocol-internal** (8 call sites, e.g.
`cggmp21-fork/cggmp24/src/signing.rs:385,475,...`). These yields run
through the cggmp24 internal `MpcParty.runtime.yield_now().await`
abstraction; they fire only when driven via the async-fn-protocol
path, not under the synchronous `proceed()` API. **The Phase G rewrite
cannot rely on these to break up CPU bursts.** The CPU budget problem
must be solved at the bsv-mpc-core / pool layer.

**`getrandom = { version = "0.2", features = ["js"] }`** is the
canonical WASM entropy line — already in `poc2-wasm/Cargo.toml`,
`bsv-mpc-worker/Cargo.toml`, etc.

### 1.4 Existing prime-pool wiring in `bsv-mpc-core` — what's already there

`DkgCoordinator` already has Phase-G-friendly bones:
- `pregenerated_primes: Option<cggmp24::PregeneratedPrimes<SecurityLevel128>>`
  field at `crates/bsv-mpc-core/src/dkg.rs:248-252`.
- `set_pregenerated_primes(self, primes)` method at `dkg.rs:297-302`.
- `start_aux_info_sm()` pulls from the field at `dkg.rs:460` and passes
  it through to `run_aux_info_sm()` at `dkg.rs:918`.
- `run_aux_info_sm()` consumes the injected primes if `Some`, else
  generates inline via `PregeneratedPrimes::generate(&mut OsRng)` at
  `dkg.rs:937` — proven path either way.
- Test-only `generate_test_primes()` using Blum primes (faster, NOT
  safe primes — for tests only) at `dkg.rs:1129-1156`.

**What's missing for §06.10.1 conformance:**
- The pool storage itself — at-rest-encrypted via §16.1 share-encryption
  pattern (AES-256-GCM + BRC-42-derived key).
- The ≥2-keypair floor + drain-trigger backfill task.
- Idle-time regen scheduling.
- A consumer API that the DkgCoordinator calls instead of
  `PregeneratedPrimes::generate()`.

Per [ADR-0041 § Consequences](../../MPC-Spec/decisions/0041-network-profile-latency-budgets.md),
the target file is `crates/bsv-mpc-core/src/paillier_pool.rs` (new),
budget ~200-300 LOC + tests.

## 2. Design direction A — Inline SM rewrite

### 2.1 Target shape

Each coordinator owns its `StateMachineImpl` directly. The SM is held
across `process_round()` calls. No spawning, no channels, no tokio dep
added to `bsv-mpc-core`.

```rust
pub struct DkgCoordinator {
    // ... existing config fields ...

    // Phase G: SM held inline, !Send is fine — coordinators don't
    // cross thread boundaries in CF Workers, and tests use
    // round_based::sim which is also single-threaded.
    keygen_sm: Option<StateMachineImpl<KeygenOutput, KeygenMsg, _>>,
    aux_info_sm: Option<StateMachineImpl<AuxInfoOutput, AuxInfoMsg, _>>,
    pregenerated_primes: Option<PregeneratedPrimes<SecurityLevel128>>,
    // ... presig field analogous ...
}

impl DkgCoordinator {
    pub fn init_keygen(&mut self) -> Result<Vec<RoundMessage>> {
        let sm = cggmp24::keygen(self.eid, self.my_index, self.n)
            .into_state_machine(&mut OsRng);
        self.keygen_sm = Some(sm);
        self.drive_keygen()
    }

    pub fn process_keygen_round(&mut self, msgs: Vec<RoundMessage>)
        -> Result<DkgRoundResult>
    {
        let sm = self.keygen_sm.as_mut().ok_or(...)?;
        for m in msgs { sm.received_msg(decode(m)?)?; }
        self.drive_keygen()
    }

    fn drive_keygen(&mut self) -> Result<DkgRoundResult> {
        let sm = self.keygen_sm.as_mut().expect("init_keygen first");
        let mut out = vec![];
        loop {
            match sm.proceed() {
                ProceedResult::SendMsg(m)        => out.push(encode(m)?),
                ProceedResult::NeedsOneMoreMessage
                    => return Ok(DkgRoundResult::NextRound(out)),
                ProceedResult::Yielded           => continue,
                ProceedResult::Output(share)     => {
                    self.keygen_sm = None;
                    return Ok(DkgRoundResult::Complete(share, out));
                }
                ProceedResult::Error(e)
                    => return Err(MpcError::Dkg(e.to_string())),
            }
        }
    }
}
```

Same shape for `signing.rs` (`signing_sm`), `presigning.rs`
(`presigning_sm`), and the second `aux_info_sm` field above.

### 2.2 Why this is strictly better than the originally-anticipated LocalSet path

| Axis | Inline (this proposal) | LocalSet + spawn_local (NEXT-STEPS.md original) |
|---|---|---|
| `bsv-mpc-core` external deps | unchanged (no tokio, no LocalSet) | adds tokio dep + LocalSet runtime |
| LOC delta vs. current | **-150 to -200** (delete thread+mpsc) | **+100 to +300** (replace + yield strategy) |
| WASM compatibility | by construction (no spawn at all) | requires single-threaded executor wiring per call site |
| Coordinator API | unchanged signatures, blocking-style call | becomes `async fn` everywhere upstream |
| CPU-budget problem | not solved (same on all paths — §3) | not solved (same on all paths — §3) |
| Test impact | existing `round_based::sim::run()` tests pass unchanged | tests must move to `LocalSet::run_until` shape |
| Reasoning load | "where does the SM live?" → one field | "where does the SM run?" → spawned task lifetime |

### 2.3 What the inline path explicitly does NOT solve

- The 30s CF Worker CPU-time budget during `aux_info_gen` safe-prime
  generation. Inline keeps `proceed()` synchronous; the spawn rewrite
  would have run it on the same single-threaded executor too. **§3
  (Paillier pool) is the only honest answer** — pre-generate primes
  outside the ceremony, inject them at ceremony start.
- Any genuinely-async I/O concern. The coordinator is sync; transports
  (MessageBox / HTTP) live outside `bsv-mpc-core` (in
  `bsv-mpc-service` / `bsv-mpc-proxy` / future `bsv-mpc-worker`) and
  can be async-on-top without changing the SM driver.

### 2.4 Per-file patch shape

**`crates/bsv-mpc-core/src/dkg.rs` (~600 LOC delta, mostly deletions):**
- Delete `run_keygen_sm()` (lines 759-908) — replaced by `drive_keygen()`.
- Delete `run_aux_info_sm()` (lines 914-1081) — replaced by `drive_aux_info()`.
- Delete `SmInbound` / `SmOutbound` enums (lines 137-154).
- Delete `start_keygen_sm()` / `start_aux_info_sm()` thread-spawn fns
  (lines 410-475).
- Add `keygen_sm` / `aux_info_sm` fields on `DkgCoordinator`.
- Replace existing thread-driven `init` / `process_round` with the
  inline drive loop shown in §2.1.
- Keep `pregenerated_primes` field + `set_pregenerated_primes()` setter
  (already correct shape).
- Keep `generate_test_primes()` test helper (already useful).

**`crates/bsv-mpc-core/src/signing.rs` (~500 LOC delta):**
- Delete `run_signing_sm()` (lines 555-736).
- Delete `SmInbound` / `SmOutbound` (lines 83-98).
- Delete `start_signing_sm()` (lines 348-392).
- Add `signing_sm` field on `SigningCoordinator`.
- Inline drive in `init_round` / `process_round`.

**`crates/bsv-mpc-core/src/presigning.rs` (~450 LOC delta):**
- Delete `run_presigning_sm()` (lines 590-719).
- Delete `SmInbound` / `SmOutbound` (lines 80-98).
- Delete `start_presigning_sm()` (lines 372-434).
- Add `presigning_sm` field on `PresigningManager`.
- Inline drive in `init_generate` / `process_generate_round`.

**Callers (`bsv-mpc-service`, `bsv-mpc-proxy`):** no API change
required. Public method signatures stay the same (`init_*` →
`Vec<RoundMessage>`, `process_round` → `*RoundResult`). The change is
purely internal.

**`Cargo.toml`:** no dep changes.

## 3. Design direction B — Paillier safe-prime pool

### 3.1 Source: MPC-Spec §06.10.1 + ADR-0041

Per [`06-transport.md` line 91-93](../../MPC-Spec/06-transport.md):

> Implementations SHOULD maintain an at-rest-encrypted pool of
> pre-generated 2048-bit Paillier safe-prime keypairs, consumed by
> auxinfo and refresh ceremonies. Recommended pool floor: 2 keypairs
> per profile; regenerated at idle. This converts the auxinfo p99
> mobile budget from 33s to ~6s.

Per [`ADR-0041` line 28-37](../../MPC-Spec/decisions/0041-network-profile-latency-budgets.md):

- Floor: 2 keypairs per profile
- Regenerated at idle (when CPU is otherwise unused)
- Pool drain triggers a backfill task
- At-rest encryption via §16.1 share-encryption pattern (AES-256-GCM
  with BRC-42-derived key)

Per [`ADR-0041` line 70-75](../../MPC-Spec/decisions/0041-network-profile-latency-budgets.md):

> `bsv-mpc` (Calhoun): Implement Paillier safe-prime pool
> (at-rest-encrypted, ~2-keypair floor, idle regen). Likely
> `crates/bsv-mpc-core/src/paillier_pool.rs` (new). ~200-300 LOC + tests.

### 3.2 Module shape

New file `crates/bsv-mpc-core/src/paillier_pool.rs` (target ~250 LOC +
tests).

```rust
//! Paillier safe-prime keypair pool — MPC-Spec §06.10.1 / ADR-0041.
//!
//! At-rest-encrypted pool of pre-generated 2048-bit Paillier safe-primes
//! consumed by auxinfo + refresh ceremonies. Reduces aux_info_gen p99
//! on profile-mobile / profile-edge from ~33s to ~6s.

use cggmp24::{key_refresh::PregeneratedPrimes, security_level::SecurityLevel128};
use crate::share::derive_brc42_key;  // §16.1 share-encryption pattern, reused

pub trait PrimePoolStorage: Send + Sync {
    fn put_encrypted(&self, blob: Vec<u8>) -> Result<(), PoolError>;
    fn take_encrypted(&self) -> Result<Option<Vec<u8>>, PoolError>;
    fn count(&self) -> Result<usize, PoolError>;
}

pub struct PaillierPool<S: PrimePoolStorage> {
    storage: S,
    encryption_key: [u8; 32],  // BRC-42-derived; see §16.1
    floor: usize,              // default 2
}

impl<S: PrimePoolStorage> PaillierPool<S> {
    /// Pull one pregenerated keypair from the pool. Returns None if the
    /// pool is empty (caller falls back to inline generation).
    pub fn take(&self) -> Result<Option<PregeneratedPrimes<SecurityLevel128>>, PoolError> { ... }

    /// Add freshly-generated primes to the pool, encrypting at rest.
    /// Called by the backfill task.
    pub fn put(&self, primes: PregeneratedPrimes<SecurityLevel128>) -> Result<(), PoolError> { ... }

    /// Run one backfill cycle: while count() < floor, generate + put.
    /// Synchronous; the caller decides scheduling (idle-time or eager).
    pub fn backfill_to_floor(&self) -> Result<usize, PoolError> { ... }
}
```

**At-rest encryption.** AES-256-GCM with a BRC-42-derived key. Reuse
existing `share.rs::derive_brc42_key()` plumbing — Protocol ID `[2,
"mpc paillier pool"]`, key_id `"pool"`, counterparty `Self_`. Same
crypto pattern used for share-at-rest in `share.rs`.

**Storage backends:**
- `InMemoryPoolStorage` — `Vec<Vec<u8>>` behind a `Mutex`. For
  `bsv-mpc-service` (in-process daemon) and tests.
- `D1PoolStorage` — Cloudflare D1 backed. For `bsv-mpc-worker` (Phase I).
- The storage trait stays minimal so the DO-bound storage is trivially
  derivable.

**Scheduling.** Idle-time backfill scheduling is **out of scope for
Phase G's core delivery** but in scope for the POC (G-3). The pool
exposes `backfill_to_floor()` as a synchronous primitive; consumers
schedule it on whatever idle signal they have (DO `alarm()` in CF;
periodic tokio task in `bsv-mpc-service`).

### 3.3 Wiring into the inline DKG

The DKG coordinator already has the slot:

```rust
// crates/bsv-mpc-core/src/dkg.rs:248-252 (existing)
pregenerated_primes: Option<cggmp24::PregeneratedPrimes<SecurityLevel128>>,
```

Phase G adds an optional pool reference and a pull-from-pool helper:

```rust
impl DkgCoordinator {
    // NEW in Phase G — non-breaking add-on.
    pub fn with_pool<S: PrimePoolStorage>(mut self, pool: &PaillierPool<S>) -> Self {
        if let Ok(Some(primes)) = pool.take() {
            self.pregenerated_primes = Some(primes);
        }
        self
    }
}
```

At ceremony start the consumer (`bsv-mpc-service`, future
`bsv-mpc-worker`) calls `.with_pool(&pool)` once; the inline
`drive_aux_info()` consumes the field exactly as today. **Zero change
to the existing aux_info code path** — the prime pool is purely a
producer-side addition.

### 3.4 Why pool work belongs in Phase G

Three reasons:

1. **Honesty about the CPU budget.** The audit doc would be misleading
   if it claimed "Phase G makes bsv-mpc-core WASM-ready" without
   addressing the 5-15s safe-prime burn per aux_info_gen on the WASM
   target. The pool is the only fix.
2. **Surface-the-info-early** (user direction). Confirming the pool
   shape now means Phase I's deployment audit doesn't have to litigate
   it. It also unblocks anyone (Quaakee, Mitch) reviewing the spec
   conformance posture before v1 ships.
3. **Low marginal cost.** The cggmp24 injection API + the DkgCoordinator
   slot are already in place. The module is ~250 LOC + tests, plus the
   inline-rewrite is already touching `dkg.rs`. Bundling reduces review
   churn.

## 4. API surface diff per coordinator

Public API is **unchanged** in shape — only internal plumbing moves.
The diff below shows what callers (`bsv-mpc-service`, `bsv-mpc-proxy`)
see, with citations to current code.

### 4.1 DkgCoordinator

| Method | Before (current) | After (Phase G) | Source |
|---|---|---|---|
| `new(config) -> Self` | unchanged | unchanged | `dkg.rs:264-287` |
| `set_pregenerated_primes(primes)` | unchanged | unchanged | `dkg.rs:297-302` |
| `with_pool(pool)` (NEW) | n/a | optional helper that pulls from pool into `pregenerated_primes` | new in Phase G |
| `init() -> Result<Vec<RoundMessage>>` | spawns thread, awaits initial outbound on channel | inline: instantiates SM, drives `proceed()` until `NeedsOneMoreMessage`, returns outbound | rewrites `dkg.rs:410-431` |
| `process_round(Vec<RoundMessage>) -> Result<DkgRoundResult>` | sends to thread via mpsc, blocks on channel reply | inline: feeds incoming + drives `proceed()`, returns outbound or completion | rewrites the existing process loop |
| (internal) `run_keygen_sm` / `run_aux_info_sm` | thread bodies | DELETED — replaced by `drive_keygen()` / `drive_aux_info()` methods on `Self` | `dkg.rs:759-908` + `914-1081` removed |

### 4.2 SigningCoordinator

| Method | Before | After | Source |
|---|---|---|---|
| `new(share, threshold_config) -> Result<Self>` | unchanged | unchanged | `signing.rs` |
| `init_round(message_hash, hmac_offset) -> Result<Vec<RoundMessage>>` | spawns thread | inline drive | rewrites `signing.rs:348-392` |
| `process_round(Vec<RoundMessage>) -> Result<SigningRoundResult>` | mpsc to/from thread | inline | rewrites the existing process loop |
| (internal) `run_signing_sm` | thread body | DELETED | `signing.rs:555-736` removed |

### 4.3 PresigningManager

| Method | Before | After | Source |
|---|---|---|---|
| `init_generate() -> Result<Vec<RoundMessage>>` | spawns thread | inline drive | rewrites `presigning.rs:372-434` |
| `process_generate_round(Vec<RoundMessage>) -> Result<PresigningRoundResult>` | mpsc | inline | rewrites existing process loop |
| `take_raw() -> Box<dyn Any + Send>` | unchanged | unchanged | `presigning.rs:321` |
| (internal) `run_presigning_sm` | thread body | DELETED | `presigning.rs:590-719` removed |

### 4.4 New module `paillier_pool` (public)

| Item | Surface | Notes |
|---|---|---|
| `trait PrimePoolStorage` | `put_encrypted`, `take_encrypted`, `count` | storage abstraction |
| `struct PaillierPool<S>` | `new`, `take`, `put`, `backfill_to_floor` | wraps storage + encryption key |
| `struct InMemoryPoolStorage` | impl trait | for tests + `bsv-mpc-service` |
| `enum PoolError` | + `From<MpcError>` | follows existing error-type convention |

## 5. Test strategy

### 5.1 Existing tests that MUST stay green

All cited tests use `round_based::sim::run()` (in-process, threading-
agnostic). The inline rewrite changes only the bridge between
coordinator and SM — the SM behavior is unchanged. Therefore these
tests pass without modification.

| Test | Source | Why it covers the rewrite |
|---|---|---|
| `dkg.rs::two_coordinators_keygen_message_exchange` | `dkg.rs:1550-1648` | Full DKG keygen with message relay; proves inline drive matches threaded drive byte-for-byte |
| `dkg.rs::full_2of2_dkg_via_sim` | `dkg.rs:1366`-onward | End-to-end DKG via sim |
| `signing.rs::two_coordinators_signing_message_exchange` | `signing.rs:1270-1371` | Full signing via sim |
| `signing.rs::presigning_and_combine_via_sim` | `signing.rs:1464-onward` | Presig + signing combined |
| `presigning.rs::two_managers_generate_presignature` | `presigning.rs:1054-1140` | Presigning gen via sim |
| Conformance vectors (02, 04, 05) | `tests/conformance_*.rs` | Wire-format unchanged, must reproduce byte-exact |

Plus the byte-locked DKG/sign vectors used by Phase A's canonical
envelope helpers — they're consumed by the conformance tests above
and have no internal-bridge dependency.

### 5.2 Phase E mainnet TXID byte-shape re-test

[`82ccb15c…`](https://whatsonchain.com/tx/82ccb15c49985a32b355a618f417bb7a09ec4ee5cf34e539e9baaebb74dadc29)
is the within-stack mainnet TXID from Phase E. Re-running
`crates/bsv-mpc-service/tests/sign_mainnet_via_messagebox_e2e.rs` after
the inline rewrite must produce a TX with **byte-identical DER
signature shape and joint pubkey** for the same input share and
message-hash inputs. This is part of the merge gate — it proves the SM
output is identical regardless of bridge implementation.

(Note: re-running consumes new sats. Per the user's "e2e with real
sats" feedback, this stays in the merge-gate set even when costly.)

### 5.3 New tests for Phase G

| Test | What it proves | Where it lives |
|---|---|---|
| `dkg::tests::inline_keygen_no_thread_spawn` | `cargo test` of `bsv-mpc-core` builds + runs with `#[forbid(unsafe_code)]` + a static check that `std::thread::Builder` / `std::thread::spawn` are not imported in `dkg.rs/signing.rs/presigning.rs` | `crates/bsv-mpc-core/src/dkg.rs` (test mod) |
| `wasm32_dkg_2of2_inline_sim` | `cargo build --target wasm32-unknown-unknown -p bsv-mpc-core` succeeds; a wasm-test runs 2-of-2 DKG end-to-end via sim in `wasm_bindgen_test` | `crates/bsv-mpc-core/tests/wasm32_dkg.rs` (new, gated by `wasm32-unknown-unknown` target) |
| `paillier_pool::tests::backfill_to_floor_idempotent` | Pool with empty storage backfills to floor=2; calling again is a no-op | `crates/bsv-mpc-core/src/paillier_pool.rs` (test mod) |
| `paillier_pool::tests::take_returns_byte_identical_aux_info` | Pre-generate primes via `PregeneratedPrimes::generate()`, put into pool, take back out, run `aux_info_gen` with both; compare `AuxInfo` byte-for-byte | `crates/bsv-mpc-core/src/paillier_pool.rs` (test mod) |
| `paillier_pool::tests::at_rest_encryption_round_trip` | Put + take returns plaintext-equivalent primes; ciphertext at storage layer is decryptable only with the BRC-42-derived key | same |
| `dkg::tests::with_pool_consumes_one_keypair` | Coordinator `.with_pool(&pool)` decrements pool count by exactly 1 per ceremony | `dkg.rs` test mod |

### 5.4 What we explicitly do NOT add as a Phase G test

- A "30s CPU budget compliance under realistic load" CF Worker
  integration test. That's a Phase I (deployed-Worker) test — Phase G's
  contribution is "remove threads + add pool"; Phase I's contribution
  is "deploy and verify the pool actually keeps us under budget."
- A cross-stack TX with rust-mpc using the new pool. That's Phase K.

## 6. POC scope — `poc/poc16-sm-inline/`

POC step (Step 3 of Phase G workflow): ship a minimum standalone proof
that the inline-SM + prime-pool design actually works. **The POC
commit lands on `main` BEFORE the full implementation begins.**

### 6.1 Scope

`poc/poc16-sm-inline/` — a single Cargo crate under the existing
`poc/poc<N>-<name>/` convention. Contents:

- `Cargo.toml` — minimal: `cggmp24` (path = `../../cggmp21-fork/cggmp24`),
  `round_based` 0.4.1, `rand`, `serde`, `aes-gcm`, `hmac`, `sha2`.
- `src/main.rs` — runs the POC scenarios; prints byte-shape comparisons.
- `tests/poc.rs` — `#[test]` versions of the scenarios for CI.
- `README.md` — what this POC proves, how to run, expected output.

### 6.2 What the POC proves (each is a hard gate)

| Gate | Scenario | Pass criterion |
|---|---|---|
| G-3.1 | Inline 2-of-2 DKG keygen with no `std::thread::spawn` | Two `DkgCoordinator`-like minimal harnesses message-relay to each other in a single thread; produce valid `IncompleteKeyShare`s; joint pubkey matches; zero use of `thread::spawn` or `tokio::spawn` (grep-checkable) |
| G-3.2 | Inline auxinfo with INJECTED primes | `aux_info_gen` runs with `PregeneratedPrimes` constructed via `TryFrom<[Integer; 4]>` from out-of-band Blum primes; produces valid `AuxInfo` |
| G-3.3 | Pool round-trip preserves `PregeneratedPrimes` byte-for-byte + auxinfo runs end-to-end on the round-tripped primes | Empirical: `cggmp24::aux_info_gen` is non-deterministic on internal RNG state (ZK proof nonces), so the testable invariant is "primes go in, the same primes come out" + "round-tripped primes still drive `aux_info_gen` to a valid AuxInfo." Original phrasing ("byte-identical AuxInfo") corrected by POC empirical run, see this gate's `tests/poc.rs` doc-comment. |
| G-3.4 | At-rest encryption round-trip | A minimal `InMemoryPoolStorage` + AES-256-GCM + BRC-42 key derivation: put → take → use → produces same `AuxInfo` as direct injection. Ciphertext blob is non-trivial (not the plaintext) |
| G-3.5 | `cargo build --target wasm32-unknown-unknown` succeeds on poc16 itself | Compiles to WASM. (Empirical run not required — the production build covers that in G-5.) |

### 6.3 What the POC does NOT do

- Full coordinator API rewrite — that's G-4.
- Real DKG signing TX — that's G-5 (re-using Phase E harness).
- D1-backed pool storage — that's Phase I.
- Idle-time scheduling — out of scope; scheduling is a consumer concern.
- Performance benchmarking on WASM (cold p99 etc.) — out of scope;
  empirical perf is Phase I deployment work.

## 7. Phase G quality gate (Step 5)

Phase G is "done" when **all** of the following are simultaneously
true. No asterisks — if any single item is open, the phase stays open.

### 7.1 Unit tests
- [ ] All existing coordinator unit tests in `dkg.rs`, `signing.rs`,
      `presigning.rs` pass (~24 tests on the bridge layer, ~50+ total
      across the crate).
- [ ] All conformance tests under `crates/bsv-mpc-core/tests/` pass
      (conformance_02 / 04 / 05 — wire-format byte-exact).
- [ ] New `paillier_pool` unit tests pass (5 scenarios per §5.3).
- [ ] `cargo clippy -p bsv-mpc-core` warning-free.

### 7.2 Vector reproducibility
- [ ] Byte-locked DKG vector reproduces (existing).
- [ ] Byte-locked signing vector reproduces (existing).
- [ ] New byte-locked **PregeneratedPrimes-round-trip-through-pool**
      vector reproduces (proves pool path preserves primes; AuxInfo is
      not byte-locked because `aux_info_gen` consumes internal RNG
      state — see G-3.3).

### 7.3 E2E (within-stack, real sats)
- [ ] `cargo test --test sign_mainnet_via_messagebox_e2e -- --ignored`
      produces a fresh mainnet TXID with the inline coordinators.
- [ ] DER signature shape byte-identical to Phase E's
      [`82ccb15c…`](https://whatsonchain.com/tx/82ccb15c49985a32b355a618f417bb7a09ec4ee5cf34e539e9baaebb74dadc29)
      (joint pubkey + signature canonical encoding).
- [ ] New mainnet TXID cited in the merge-gate commit message.

### 7.4 WASM proof
- [ ] `cargo build --target wasm32-unknown-unknown -p bsv-mpc-core`
      succeeds without `[patch.crates-io]` workarounds.
- [ ] New `crates/bsv-mpc-core/tests/wasm32_dkg.rs` runs a 2-of-2 DKG
      sim end-to-end in a `wasm32-unknown-unknown` test runner
      (`wasm-bindgen-test`).
- [ ] No `std::thread::spawn` reachable on the wasm32 build (grep
      verified + the build itself enforces it on `wasm32-unknown-unknown`).

### 7.5 Pool spec conformance
- [ ] `paillier_pool` exposes the floor + put + take + backfill API per
      §3.2.
- [ ] At-rest encryption uses the §16.1 share-encryption pattern
      (AES-256-GCM + BRC-42-derived key); a unit test asserts the
      ciphertext is non-plaintext and that the key is BRC-42-derived.
- [ ] Default floor = 2, configurable.

## 8. Open questions

These do NOT block the audit-doc commit. They're flagged here so user
review can resolve them before the POC step.

| | Question | Default if no answer |
|---|---|---|
| **OQ1** | Per ADR-0041 the pool is "RECOMMENDED" — make it `Option<PaillierPool>` on `DkgCoordinator` (pool is opt-in, default = inline `generate`) or required (pool is wired in but defaults to a `LazyInline` pool that just generates on demand)? | **Optional with `with_pool(&pool)` setter** — keeps existing tests unchanged; consumers who want the pool wire it explicitly |
| **OQ2** | At-rest encryption key derivation parameters for the pool — Protocol ID `[2, "mpc paillier pool"]`, key_id `"pool"`, counterparty `Self_` (consistent with existing share.rs pattern), OR a new dedicated protocol? | **Reuse share.rs pattern** (`[2, "mpc paillier pool"]`) — fewer surfaces, same audit-doc trail; rotates with share encryption naturally |
| **OQ3** | `PrimePoolStorage` trait — `Send + Sync` for native multithreaded use, or just `Send`? CF Worker DOs are single-threaded so `Sync` is over-spec there, but it makes native consumers simpler. | **`Send + Sync`** — CF cost is zero (DO never crosses threads anyway), native benefit is real |
| **OQ4** | Should `bsv-mpc-service` startup eagerly call `pool.backfill_to_floor()`, or wait until first DKG ceremony triggers a drain-based backfill? | **Eager backfill** during service startup — matches the spec "regenerated at idle" intent (startup IS idle); ~10-15s one-shot cost |
| **OQ5** | Does the POC ship its OWN minimal `PaillierPool` impl, or reuse the production module via a path dep? | **Path dep on `bsv-mpc-core`** — POC's job is to validate the production API works; a parallel POC impl would defeat that |

## 9. References

### Source files (all under `~/bsv/mpc/bsv-mpc/`)
- `crates/bsv-mpc-core/src/dkg.rs` — DKG coordinator + bridge to rewrite
- `crates/bsv-mpc-core/src/signing.rs` — Signing coordinator + bridge to rewrite
- `crates/bsv-mpc-core/src/presigning.rs` — Presigning manager + bridge to rewrite
- `crates/bsv-mpc-core/src/share.rs` — BRC-42 + AES-256-GCM pattern to reuse for pool encryption
- `crates/bsv-mpc-core/src/types.rs` — `RoundMessage`, `SessionId`, `MpcError`
- `crates/bsv-mpc-core/src/lib.rs` — module exports
- `poc/poc2-wasm/src/lib.rs` — WASM-compile precedent + full protocol on WASM
- `poc/poc10-cf-worker-https/worker/src/lib.rs` — multi-round HTTP runtime precedent
- `cggmp21-fork/cggmp24/src/key_refresh.rs` — `PregeneratedPrimes` + `TryFrom<[Integer; 4]>`
- `cggmp21-fork/cggmp24/src/lib.rs:400-415` — `aux_info_gen` signature
- `cggmp21-fork/cggmp24/src/signing.rs` — yield_now sites + `set_additive_shift()` patch

### Spec sections
- [`MPC-Spec/06-transport.md`](../../MPC-Spec/06-transport.md) §06.10, §06.10.1, §06.10.3
- [`MPC-Spec/decisions/0041-network-profile-latency-budgets.md`](../../MPC-Spec/decisions/0041-network-profile-latency-budgets.md)
- [`MPC-Spec/16-operations.md`](../../MPC-Spec/16-operations.md) §16.1 share-encryption pattern (to reuse for pool at-rest)

### Locked decisions referenced
- [`docs/NEXT-STEPS.md`](NEXT-STEPS.md) — Phase G shape + 5-step workflow + 110%-no-asterisks framing
- [`docs/HANDOFF-2026-05-19.md`](HANDOFF-2026-05-19.md) — session context
- [`docs/WALLET-3321.md`](WALLET-3321.md) — wallet:3321 admin Origin for mainnet sat-funded E2E

### Out-of-tree cargo-registry citations
- `round-based-0.4.1/src/state_machine/mod.rs:76-104` — `StateMachine` trait
- `round-based-0.4.1/src/state_machine/shared_state.rs:3` — `Rc<RefCell<_>>` → `!Send`
- `round-based-0.4.1/src/state_machine/mod.rs:189,243-264` — `wrap_protocol()` + `noop_waker()`

### Prior-art (no-pattern-found) negatives
- No `tokio::task::LocalSet` / `spawn_local` site found anywhere in
  `~/bsv/` Rust corpus. The POC + implementation in Phase G are
  building this pattern from spec, not adapting prior art.
- No `Rc<RefCell<_>>` in any production CF Worker DO field across
  `~/bsv/`. DO state-holding always uses serializable `Send + Sync`
  types and per-event attachment recovery (workers-rs 0.8 contract).

## 10. Headlines for quick review

1. **Inline beats LocalSet.** `proceed()` is non-blocking by
   construction; the threading bridge was incidental complexity. Drop
   the spawn entirely; coordinator owns the SM directly. **~150-200
   LOC simpler than current; ~300 LOC simpler than the originally-
   anticipated LocalSet rewrite. No tokio added to bsv-mpc-core.**

2. **Pool is in scope.** Per user direction "surface info early" and
   per ADR-0041 the prime-gen pool is the only honest CPU-budget
   answer. Module `paillier_pool.rs` (~250 LOC + tests). cggmp24 +
   `DkgCoordinator` already expose the slots needed for injection.

3. **No public API change.** Callers (`bsv-mpc-service`, future
   `bsv-mpc-worker`) see the same coordinator method signatures.
   Inline rewrite is purely internal plumbing.

4. **Existing tests pass unchanged.** All `round_based::sim::run()`-
   based tests are threading-agnostic. The merge gate adds new tests
   (wasm32 DKG sim, pool tests) without invalidating the existing 24+
   bridge tests or the byte-locked vectors.

5. **Merge gate is real.** Phase E's mainnet TXID byte-shape preserved
   on a fresh run + new wasm32 2-of-2 DKG sim + byte-identical
   `PregeneratedPrimes` round-trip through pool. (The original audit
   draft claimed byte-identical AuxInfo; POC empirically showed
   `cggmp24::aux_info_gen` is non-deterministic on internal RNG state,
   so we test the stronger pool-specific invariant instead.) No
   asterisks; on-chain artifact in the merge commit.

---

**Last updated:** 2026-05-19. Pending user review before POC step (G-3) begins.
