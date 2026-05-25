# SCALING — bsv-mpc threshold signing to 10K → 1M users

> **Thesis.** The *cryptography* scales trivially (every user's key is independent — embarrassingly parallel, no global ceremony). What does **not** scale is the **demo deployment**: one singleton CF Container holding all state on a 12 GiB box. The god-tier design separates the workload into three tiers, each scaled by the right Cloudflare primitive, and ultimately spreads users across overlay-discovered operator nodes. This doc is the target architecture + the concrete path.

---

## 1. Workload model — what runs, how often, how heavy

The KSS (CF Worker isolate or CF Container) is the **cosigner** holding `share_A`; the client (proxy / device) holds `share_B` and coordinates. Per user/key:

| Op | When | Cost | Why |
|----|------|------|-----|
| **DKG** | once, at provisioning | **HEAVY** (~minutes) | generates the 2048-bit Paillier safe primes (aux-info). The OOM-prone step. |
| **Presign** | background, idle-time, pooled (FIFO) | **MODERATE** (3-round MtA) | **reuses** the Paillier keys from DKG — NO new safe-prime gen per presig. |
| **Sign** | per transaction | **CHEAP** (1 round, ~ms + 1 relay RTT) | consumes a pooled presig; the common case by 1000×. |
| **Reshare / recovery (#40)** | rare (device loss, rotation) | **HEAVY** (throwaway DKG → more safe primes) | the rarest op; the only one that does the full DKG+2-reshare+presign chain (the worst case in the whole system). |

**Load shape for 10K users** (assume ~10 tx/day each):
- **Signs:** ~100K/day ≈ **~1/sec average** — trivial, 1-round combines.
- **Presign top-up:** matches the sign rate (~1/sec) — moderate background load.
- **DKG:** 10K one-time, spread over signups — heavy but amortized; only a *burst* of signups stresses it.
- **Reshare/recovery:** a long-tail trickle — negligible steady-state.

**Key fact:** the expensive safe-prime generation is at **DKG and reshare only**, never per-signature. Routine signing is cheap. The `#40` recovery gate (DKG + 2 reshares + presign back-to-back on one instance) is the **single heaviest path in the system** — a worst-case test, not steady state.

---

## 2. Why the current deployment can't scale

- **Singleton routing:** `getContainer(env.BSV_MPC_SERVICE, "singleton")` pins **every** ceremony for **every** user to **one** container instance, serialized, with in-memory state.
- **12 GiB OOM ceiling, no swap:** `standard-4` (4 vCPU / 12 GiB) is the *largest* CF Container instance type. Back-to-back safe-prime gen exceeds it → OOM → restart → lost in-memory MPC state → hung ceremony. (This is exactly the instability that blocked the #40 mainnet proof.)
- **In-memory coordinator state** is lost on any restart → no resilience, no flexible routing.

This is fine for a demo; it falls over at ~tens of concurrent heavy ceremonies and has a hard single-box ceiling.

---

## 3. God-tier architecture — three tiers, each scaled by the right primitive

```
                         ┌───────────────────────────────────────────────┐
  client / proxy ──sign──▶ TIER 1 — CF Worker isolates (light sign)        │  ~unlimited, global edge
  (device holds share_B)  │  1-round combine w/ pooled presig (issue_partial)│  millions/sec
                         └───────────────────────────────────────────────┘
        │ DKG / presign / reshare (heavy, stateful)
        ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │ TIER 2 — CF Containers, PER-SESSION DO routing                        │  horizontal: 100s of instances
  │  getContainer(env, sessionId) → one instance per ceremony             │  (acct ceiling ~1,500 vCPU / 6 TiB)
  │  state persisted to DO-SQLite → any instance resumes; restart-safe     │
  │  consumes safe primes from the pool (no on-path generation)            │
  └─────────────────────────────────────────────────────────────────────┘
        │ pull safe primes
        ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │ TIER 3 — safe-prime "factory" (background)                            │  decouples DKG latency from
  │  continuous 2048-bit safe-prime gen, at-rest-encrypted pool           │  the ~minutes of prime gen
  │  (paillier_pool.rs), backfilled to a floor; sized to DKG+reshare rate  │
  └─────────────────────────────────────────────────────────────────────┘

  ════════════════════════════ across the network ════════════════════════════
  TIER 0 — many independent operator nodes, overlay-discovered (tm_mpc_signing,
  SHIP/SLAP), fees settled on-chain. Users sharded across operators; each operator
  runs its own Tier 1-3 fleet. This is the vendor-neutral end-state.
```

### Tier 1 — light signing on Worker isolates (handles 99%+ of traffic)
The Worker isolate already does light online signing (`issue_partial`; it **cannot** run DKG/presign — CF isolate CPU budget). Route every **sign** here: a pooled presig makes signing a 1-round partial + combine (~ms). CF Workers scale to millions of req/sec on the global edge with 0ms cold start. **This is where ~all production volume goes**, and it scales effectively without limit. Shares + presig pools live in DO-SQLite (`do_storage.rs`, already the deployed path), so any isolate serves any user.

### Tier 2 — heavy ceremonies on Containers, per-session routed
DKG / presign-gen / reshare are CPU+memory heavy and stateful → CF Containers. The fix to the singleton bottleneck:
- **Per-session DO routing:** `getContainer(env.BSV_MPC_SERVICE, sessionId)` (or per-user) instead of `"singleton"`. Each ceremony pins to its own instance — in-memory SM state stays coherent — and load spreads across many instances. Raise `max_instances` (account ceiling ≈ 1,500 vCPU / 6 TiB RAM → hundreds of `standard-4`s).
- **DO-SQLite-backed coordinator state:** persist round-state (not just `share_A` custody, which is already durable per #9) so an OOM/host restart **resumes** instead of hanging — this is what makes both resilience *and* flexible routing possible.
- **Readiness barrier:** override the Container `fetch()` with `startAndWaitForPorts(...)` + `onStop({exitCode,reason})` so requests never race a cold instance and OOMs are observable.

### Tier 3 — the safe-prime factory (kills the OOM + decouples DKG latency)
Safe-prime generation is THE bottleneck and the OOM source. Don't generate on the hot path:
- **Pre-generate** raw 2048-bit safe primes continuously in the background, at-rest-encrypted, into a pool (`paillier_pool.rs` `backfill_to_floor`, floor ≥ 2). DKG **consumes** from the pool (instant) rather than generating (~minutes).
- **Serialize** any unavoidable on-instance generation (never N-parallel) + `MALLOC_ARENA_MAX=2` to cap RSS — so a single instance never OOMs.
- Result: DKG becomes pool-limited, not CPU-limited; bursts are absorbed by pool depth + instance count, not by one box's 12 GiB.

### Tier 0 — network of operators (the decentralized end-state)
The project is a *network*, not one deployment. Users shard across **independent operator nodes** discovered via the BSV overlay (`tm_mpc_signing`, SHIP/SLAP — `bsv-mpc-overlay`), each running its own Tier 1–3 fleet, with fees settled on-chain (BRC-18 proofs, fee covenant). 1M users = N operators × (users/operator); no operator is a global bottleneck and no single vendor is trusted. This is the partnership's vendor-neutral target.

---

## 4. Capacity math

| Scale | Signs | Presign top-up | DKG | What it needs |
|------|-------|----------------|-----|---------------|
| **10K users** | ~1/sec | ~1/sec | 10K one-time, spread | Tier 1 trivial; a **handful** of Tier-2 `standard-4`s + a stocked prime pool; DO-SQLite state. |
| **100K users** | ~10/sec | ~10/sec | 100K, spread | Tier 1 still trivial; **tens** of Tier-2 instances; prime factory sized to signup rate. |
| **1M users** | ~100/sec | ~100/sec | bursty at signup | Tier 1 fine; **shard across operator nodes** (Tier 0); per-operator Tier-2 fleet + prime factory. |

The throughput constraint is **DKG burst rate** (the only heavy, latency-visible op). With a pre-stocked prime pool, each DKG is fast; concurrency = instance count. Everything else (sign, presign) is pooled and cheap. **There is no global serialization point** once routing is per-session and state is in DO-SQLite.

---

## 5. Concrete changes, ranked by impact

1. **Route signing to the Worker isolate, heavy ceremonies to Containers** (lean into the existing split). 99% of volume leaves the bottleneck entirely. *(Architecture: confirm `createSignature`/`/sign-relay` hit the Worker; DKG/presign/reshare hit the Container.)*
2. **Per-session DO routing** — `getContainer(env, sessionId)` not `"singleton"` (`poc/cf-container-p2/worker.js`); raise `max_instances`. Removes the single-instance ceiling.
3. **Safe-prime factory** — background `backfill_to_floor` on `paillier_pool.rs`, sized to DKG+reshare rate; DKG consumes from the pool. Serialize any on-path gen + `MALLOC_ARENA_MAX=2`. *Kills the OOM.*
4. **DO-SQLite coordinator state** — persist round-state (extend the #9 custody pattern in `do_storage.rs`) so restarts resume, not hang. Enables resilience + flexible routing.
5. **Readiness barrier + OOM observability** — `startAndWaitForPorts` + `onStop/onError` in the Container class (kills the cold "not running" race; makes OOM visible).
6. **Network sharding (Tier 0)** — overlay-discovered operators for ≥100K; fees on-chain. The long-horizon scale + decentralization play.

(1)–(3) get you to a solid 10K–100K on one operator; (4)–(5) make it resilient; (6) is the path to 1M and vendor-neutrality.

---

## 6. Honest limits & caveats

- **12 GiB / no-swap per instance is a hard CF ceiling.** Scaling is strictly *horizontal* (more instances, smaller per-instance peak) — never make one ceremony bigger. The architecture must not pin everything to one DO. (This is precisely the limit that blocked the #40 mainnet proof on the singleton.)
- **Per-instance request concurrency is undocumented by CF.** Treat each container instance as effectively serial for heavy ceremonies and size instance count to concurrency, not to a per-instance multiplier — revisit if CF documents autoscaling/concurrency.
- **In-memory state is the fragility** until DO-SQLite-backed resume lands; a restart mid-ceremony fails that ceremony (client retries). Acceptable short-term; (4) removes it.
- **These are deployment/architecture changes, not protocol changes** — the `bsv-mpc-core` crypto layer is unaffected. DKG-burst throughput at signup is the metric to load-test before a big launch.
- **Reshare/recovery (the #40 path)** is the rarest + heaviest op; it does not factor into steady-state capacity. Keep it off the hot path (its own queue/instances).

---

## 7. References
- CF Containers limits/architecture/rollouts/scaling-and-routing + DO Container API (the 12 GiB ceiling, per-session routing, `startAndWaitForPorts`) — see `docs/HANDOFF-40-deployed-reshare-fixed.md` §0 "CF CONTAINERS ROOT CAUSE".
- Codebase: `paillier_pool.rs` (prime pool), `presign_manager.rs` (presig FIFO + background replenish), `bsv-mpc-worker/do_storage.rs` (DO-SQLite, deployed), `bsv-mpc-overlay` (SHIP/SLAP discovery), the Worker-isolate (light sign) vs Container (heavy MPC) split in the root `CLAUDE.md`.
