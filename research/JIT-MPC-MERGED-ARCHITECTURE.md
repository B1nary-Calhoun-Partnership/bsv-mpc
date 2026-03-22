# Decision: Merged JIT+MPC Architecture

> **Date:** March 22, 2026
> **Status:** Decision made — implementation phased across Alpha/Beta/GA
> **Participants:** John, Claude Code
> **Context:** Cross-project analysis of bsv-mpc, rust-bsv-worm, rust-wallet-infra, WAB, and recovered strategy docs

---

## The Decision

The JIT payment proxy and MPC signing proxy merge into a single service. The agent container becomes stateless — it has no signing keys, no UTXO storage, no wallet state. All wallet operations go through the remote JIT+MPC service, which combines USD credit management with threshold ECDSA signing.

```
Endgame architecture:

User browser (signup only)
  ↓ DKG with KSS → share_B delivered to JIT+MPC service

Agent container (stateless — NO shares, NO wallet)
  ↓ BRC-100 HTTP (WORM_WALLET_URL)

JIT+MPC Service (share_B + credit ledger + BRC-100 API)
  ├── StorageClient → rust-wallet-infra (D1/R2) for UTXO/tx persistence
  ├── MPC bridge → KSS (share_A) for threshold signing
  └── Credit ledger → Stripe for USD management

Independent KSS (share_A)
  └── At GA: overlay-discovered, independently operated
```

---

## Why We Made This Decision

### Problem: The "Mathematically Cannot Sign" Claim

The executive brief for investors states: "The platform literally cannot sign a user's transactions — not 'we promise we won't,' but 'the math doesn't allow it.'"

With the previous design (MPC proxy in agent container), the platform operates both sides of the MPC in hosted mode:
- share_A: KSS on CF Account #1 (platform operated)
- share_B: MPC proxy in container on CF Account #2 (platform operated)

A determined platform admin could access both shares. The claim is defense-in-depth, not mathematical truth.

### Solution: Separate Legal Entities Hold Shares

With merged JIT+MPC, the architecture naturally progresses to genuine non-custody:

| Phase | share_B holder | share_A holder | Platform can sign alone? |
|-------|---------------|---------------|------------------------|
| Alpha | JIT+MPC service (platform) | KSS (platform, separate CF account) | Yes (defense-in-depth) |
| Beta | JIT+MPC service (platform) | KSS (**GCP/Dfns, external**) | **No** |
| GA | JIT+MPC service (platform) | KSS (**independent operator**) | **No** |

At Beta: "Signing requires cooperation between independent parties."
At GA: "The platform mathematically cannot sign. Different legal entities hold each share."

### Why Merge Instead of Keeping Separate?

| Concern | Separate (JIT + MPC proxy) | Merged (JIT+MPC) |
|---------|---------------------------|-------------------|
| Fund sweep on deletion | Requires share reconstruction — trust exception | Normal MPC signing — no exception |
| Share delivery to container | Complex: browser → WAB → container startup | Simple: browser → JIT+MPC service |
| UTXO persistence | Unclear: in-memory tracker needs migration | Clear: StorageClient → rust-wallet-infra |
| Container restarts | Must recover share_B + rebuild wallet state | Stateless container, nothing to recover |
| Transaction flow | Two txs per payment (fund + spend) | One tx per payment (direct MPC sign) |
| Treasury hot wallet | Platform holds BSV in separate treasury | BSV lives in MPC wallet, split-key controlled |
| Code reuse | All MPC proxy code used directly | Same code, embedded as library |
| Agent autonomy | Agent has local signing capability | Agent depends on remote service |

The only downside is the remote dependency — the agent can't sign without the JIT+MPC service. For hosted mode this is fine (the platform runs both). For sovereign mode, the user runs `bsv-wallet-cli` (full key, no MPC) — they manage their own keys directly.

---

## What This Means for Each System

### bsv-mpc (this repo)

**bsv-mpc-proxy becomes a library + binary:**
- `lib.rs` exports: `MpcBridge`, `FeeInjector`, `PresignManager`, `UtxoTracker`, all 28 handler functions
- `main.rs` remains the standalone binary for sovereign mode
- JIT+MPC service imports `bsv-mpc-proxy` as a Cargo dependency

**No code is thrown away.** All 130 proxy tests, all E2E tests remain valid. The handlers are pure business logic — they don't care whether they're called from a standalone Axum server or embedded in another service.

**Crate structure (unchanged):**
- `bsv-mpc-core`: MPC protocol (121 tests) — unchanged
- `bsv-mpc-proxy`: wallet API library + standalone binary — add lib.rs exports
- `bsv-mpc-worker`: KSS CF Worker — unchanged
- `bsv-mpc-service`: standalone KSS binary — unchanged
- `bsv-mpc-overlay`: discovery — unchanged

### rust-wallet-infra

**Becomes more important.** It's the UTXO/transaction storage backend for ALL hosted agent wallets.

The JIT+MPC service uses `StorageClient` from `rust-wallet-toolbox` to persist:
- UTXOs (outputs table)
- Transaction lifecycle (transactions table)
- Merkle proofs (proven_txs table)
- Certificates (certificates table)
- All 16 tables from the standard wallet schema

Multi-tenant by design — rust-wallet-infra scopes everything by `user_id` via BRC-31 auth. Each agent gets its own user_id (derived from the MPC joint key).

Already deployed at `wallet-infra.x402agency.com`.

### rust-bsv-worm (agent runtime)

**The agent container becomes simpler:**
- No MPC proxy sidecar process
- No share file to manage
- No UTXO state to persist
- Just the agent runtime connecting to a remote wallet URL

**Configuration:**
```toml
# worm.toml — sovereign mode (user manages own keys, no MPC)
[wallet]
url = "http://localhost:3321"  # bsv-wallet-cli (full key, user-controlled)

# worm.toml — hosted mode (MPC + JIT, platform-operated)
[wallet]
url = "https://jit.lobsterfarm.com/agents/{agent_id}"  # remote JIT+MPC
```

The agent's `wallet.rs` doesn't change at all — it sends BRC-100 JSON to a URL. Sovereign mode uses `bsv-wallet-cli` (no MPC at all — the user holds their full private key). MPC only exists for hosted mode where the platform cannot be trusted with a complete key.

### WAB

**Role simplified:** WAB authenticates the user during signup and stores the BRC-52 ownership certificate. It no longer needs to store share_B (that goes to the JIT+MPC service directly).

WAB's existing Shamir share storage (`ShareService`) could still be used as a backup for share_B, but it's not on the critical path.

---

## Signup Flow (Deferred DKG Binding + JIT+MPC)

```
1. User opens lobsterfarm.com → clicks "Create Agent"
   → Browser starts DKG with KSS in Web Worker (30-60s)
   → User configures agent (name, skills, budget) during DKG
   → Progress bar: "Preparing your agent's secure wallet..."

2. DKG completes
   → share_A stored on KSS (keyed by joint_key, unbound)
   → share_B held in browser memory
   → joint_key known, unfunded, unbound

3. User logs in via WAB → rootPrimaryKey available (120s)
   → Signs BRC-52 certificate: user owns this agent (~instant)
   → Encrypts share_B with provisioning key (~instant)
   → Sends encrypted share_B to JIT+MPC service (~instant)
   → JIT+MPC service stores share_B, binds to user
   → Time in 120s window: <1 second

4. JIT+MPC service initializes agent wallet
   → Creates user in rust-wallet-infra (findOrInsertUser)
   → Connects MPC bridge to KSS
   → Agent wallet ready at URL

5. Platform provisions CF Container
   → Container runs bsv-worm with WALLET_URL = JIT+MPC service
   → Agent starts, calls wallet API, everything works
   → No shares in container, no wallet state to manage

6. User adds funds via Stripe
   → USD credits in JIT ledger
   → JIT converts USD → BSV, funds MPC wallet via exchange/OTC
   → Agent starts spending autonomously
```

---

## Agent Lifecycle

| Action | User Experience | System Behavior |
|--------|----------------|-----------------|
| **Create** | Configure agent, brief spinner, agent starts | DKG + bind + provision (see above) |
| **Run** | Agent executes tasks, sees results | Agent calls JIT+MPC for all wallet ops |
| **Top up** | "Add $10" → Stripe checkout | USD credited, BSV funded to MPC wallet |
| **Pause** | Toggle switch | Container sleeps (CF sleepAfter), JIT+MPC retains state |
| **Resume** | Toggle switch | Container wakes, reconnects to JIT+MPC |
| **Delete** | "Delete Agent" → confirm | JIT+MPC sweeps funds (normal MPC sign) → USD credit → container terminated |
| **Export** | "Export Data" → download zip | R2 blobs decrypted client-side (WAB login), wallet data from JIT+MPC |

---

## Security Model

### Trust Boundaries

```
┌─────────────────────────────────────────────────────┐
│ Platform Trust Domain                                │
│                                                      │
│  ┌──────────────┐    ┌──────────────────────────┐   │
│  │ Agent         │    │ JIT+MPC Service          │   │
│  │ Container     │    │ (share_B + credits)      │   │
│  │ (stateless)   │───▶│ → rust-wallet-infra      │   │
│  └──────────────┘    └───────────┬──────────────┘   │
│                                  │                   │
└──────────────────────────────────┼───────────────────┘
                                   │ MPC signing
                                   ▼
                    ┌──────────────────────────┐
                    │ KSS (share_A)            │
                    │ INDEPENDENT (Beta/GA)     │
                    │ Different legal entity    │
                    └──────────────────────────┘
```

### Defense-in-Depth Progression

| Layer | Alpha | Beta | GA |
|-------|-------|------|-----|
| Share separation | Different CF accounts | **Different cloud providers** | **Different companies** |
| Code verification | Open source (MIT) | + Reproducible builds | + Binary hash on-chain |
| Data encryption | MPC-derived keys, platform sees ciphertext | Same | Same |
| Audit trail | On-chain BRC-18 proofs | Same | + Independent auditors |
| Key refresh | Threshold resharing (same key, 0 cost) | Same | Same |
| Veto prevention | 2-of-2 (KSS can veto) | **2-of-3 (no single-party veto)** | + User holds share_C |

### What the Platform CAN and CANNOT Do

| | Alpha | Beta | GA |
|---|---|---|---|
| Read agent data | No (encrypted with MPC-derived keys) | No | No |
| Sign agent transactions | Yes (operates both shares) | **No** (external KSS) | **No** |
| Block agent transactions | Yes (operates KSS) | Yes (can refuse to relay) | **No** (multiple KSS via overlay) |
| Sweep agent funds | Yes (needed for deletion) | Only with KSS cooperation | Only with KSS cooperation |
| Modify agent code | Detectable (reproducible builds) | Detectable | Detectable |

---

## Regulatory Alignment

### Executive Brief Claims vs. Architecture

| Claim | Alpha | Beta | GA |
|-------|-------|------|-----|
| "Platform cannot sign" | Defense-in-depth (honest caveat needed) | **True** (independent KSS) | **True** |
| "We don't hold user assets" | True — BSV in MPC wallet, not platform treasury | True | True |
| "Users never touch crypto" | True — USD credits via Stripe | True | True |
| "Non-custodial MPC 2-of-2" | Architecturally separated | **Independently operated** | **Independently operated** |
| "Integral part exemption" | BSV is internal infra for AI compute | Same | Same |
| "USD credits aren't stored value" | Non-refundable, single-merchant prepaid | Same | Same |

### Recommended Language by Phase

**Alpha:** "The agent's signing key is split across separate infrastructure under separate access controls. No single system holds a complete key."

**Beta:** "The agent's signing key is split between our platform and an independent key custodian. Neither party can sign alone. Signing requires active cooperation between independent parties."

**GA:** "The agent's signing key is split between independent operators discovered via the BSV overlay network. The platform mathematically cannot sign a user's transactions — this is a cryptographic fact, not a policy assertion."

---

## Impact on Existing Issues

### bsv-mpc

| # | Title | Impact |
|---|-------|--------|
| #48 | Replace UtxoTracker with StorageClient | Still critical-path. Now applies to JIT+MPC service embedding, not standalone proxy. Same work. |
| #49 | Define deployment modes | Update: Sovereign = bsv-wallet-cli (no MPC). Hosted = remote JIT+MPC. Decentralized = overlay KSS. |
| #55 | internalizeAction for JIT batch funding | Simplified: JIT IS the MPC proxy. No separate internalization. Close or reduce scope. |
| NEW | Export bsv-mpc-proxy as library crate | Add lib.rs exports so JIT+MPC service can embed it. Small refactor. |

### rust-bsv-worm

| # | Title | Impact |
|---|-------|--------|
| #13 | J.2: BRC-100 compatible wallet proxy | Major update: JIT proxy now embeds MPC signing, becomes JIT+MPC service. |
| #20 | J.6: Mode switching | Update: Hosted = WALLET_URL points to JIT+MPC service URL. |
| #138 | Deferred DKG binding | Update: share_B goes to JIT+MPC service, not container. |
| #139 | Share_B storage and delivery | Simplified: no container delivery. Browser → JIT+MPC service directly. |
| #140 | JIT batch pre-funding | Simplified: no separate treasury. BSV in MPC wallet, JIT+MPC signs directly. |
| #141 | Fund sweep | Simplified: normal MPC signing, no reconstruction needed. |

---

## Implementation Phases

### Phase 1: Alpha (Current → May 2026)

**Ship with what we have.** MPC proxy in container, separate JIT credit-checking proxy.
- Sovereign mode: `bsv-wallet-cli` at localhost:3321 (no MPC, user holds full key)
- Hosted mode: MPC proxy at localhost:3322 in container + JIT proxy in front
- KSS on separate CF account
- Honest claim: "architecturally separated"

**Prep work for Beta:**
- Export bsv-mpc-proxy as library (add lib.rs, ~2-3 hours)
- Ensure all handlers are callable without Axum context
- Build JIT credit ledger + Stripe integration

### Phase 2: Beta (July 2026)

**Merge JIT+MPC. Move KSS external.**
- JIT+MPC service imports bsv-mpc-proxy as library
- JIT+MPC uses StorageClient → rust-wallet-infra for persistence
- Agent container drops MPC proxy sidecar
- KSS moves to GCP or Dfns (genuinely independent)
- Claim upgrades to: "independent parties required"

### Phase 3: GA (Fall 2026)

**Independent KSS operators. Overlay discovery.**
- Multiple KSS operators compete (overlay-discovered via SHIP/SLAP)
- 2-of-3 threshold (no single-party veto)
- MPC signing fees via subscription model
- Claim upgrades to: "mathematical impossibility"

---

## What We Preserve

- All bsv-mpc-core code (121 tests) — unchanged
- All bsv-mpc-proxy handlers (130 tests) — embedded, not rewritten
- All E2E tests (8 scenarios) — just change wallet URL
- Agent's wallet.rs — unchanged (it's just a URL)
- rust-wallet-infra — unchanged (gets more clients)
- KSS (worker + service) — unchanged
- Overlay discovery — unchanged
- All 15 POC validations — still applicable

---

## References

- ~/bsv/strategy/CROSS-PROJECT-STRATEGY.md — locked decisions, JIT+MPC always together for hosted
- ~/bsv/strategy/CLOUDFLARE-PERSISTENCE-SECURITY.md — 5 deployment modes, ROOT_KEY problem
- ~/bsv/strategy/PLAN-JIT-PAYMENT-PROXY.md — original JIT proxy plan
- bsv-mpc/INTEGRATION.md — "Hosted Mode: Storage Architecture" section
- bsv-mpc/regulatory/compute-service-position-paper.md — MPC operators as compute providers
- rust-bsv-worm regulatory/executive-brief (Google Doc) — investor claims to validate
- rust-bsv-worm milestone "0. Hosted UX/Security Design" — issues #138-#142
