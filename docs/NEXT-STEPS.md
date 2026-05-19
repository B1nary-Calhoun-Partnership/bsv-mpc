# Next Steps — `bsv-mpc` cosigner deployment

> Living plan, written 2026-05-19 for John's review. With the M1
> deadline constraint dropped and UX + security promoted as primary
> drivers, the honest recommendation flipped from (B) to (A) —
> fully CF-native cosigner as a Cloudflare Worker / Durable Object.
> The three RED audit findings become engineering work, not blockers.

## Why (A) is now the honest god-tier answer

| Axis | (A) CF Worker/DO | (B) Native Rust + CF data | Verdict |
|---|---|---|---|
| **Operator UX** (someone running a cosigner) | `wrangler deploy` zero-touch + dashboard observability + auto-TLS + auto-scale + no host to patch | Manage a host, Dockerfile, volumes, TLS certs, SSH access, OS patches | **(A) wins by a mile** |
| **Developer UX** (someone forking + running a cosigner) | Template repo + `wrangler secret put SERVER_PRIVATE_KEY` + `wrangler deploy`. Done. | Clone repo + install Rust + provision host + configure systemd + manage volumes + arrange TLS termination | **(A) wins** |
| **Security posture** | No SSH surface · no exposed port (MessageBox pull-based) · secrets in CF vault (KMS-backed) · DO storage encrypted-at-rest, replicated, automatic backup · automatic isolation per request · no host OS to patch | Public/private inbound port · secrets on disk (or in vault tool we add) · self-managed encryption-at-rest · self-managed backup · self-managed isolation · OS patching cycle | **(A) wins decisively** |
| **Scale / federation story** (§13, §15 Notary) | Global CF edge fabric · automatic geo-routing · zero-config replication | Single host or hand-managed multi-host | **(A) wins** |
| **Spec alignment** | `profile-edge` — the spec's explicitly-named CF cosigner topology per §16.1.2 | `profile-server` — also spec-compliant | **(A) marginally** (both legal) |
| **Cost** | Free CF Workers + DO + D1 + R2 within free tier; ~$5/mo at moderate volume | $5-15/mo for VPS + storage | **(A) wins on cost too** |
| **Build effort** | ~8-12 weeks of focused work, three novel pieces (SM-async + outbound-WS-DO + storage wiring) | ~3-4 days for M1-shape demo | **(B) wins** — but deadline is gone |

With the deadline removed, every other axis points to (A). **Build (A) properly.**

## The three RED audits become engineering work, not blockers

| RED | What it actually is | Phase that addresses it |
|---|---|---|
| **R1 — no Rust MessageBox CLIENT crate in `~/bsv/`** | The relay's INBOUND `MessageHub` DO at `bsv-messagebox-cloudflare-public/src/message_hub.rs:236-256` is the architectural template — flip it for outbound. ~500 LOC including hibernation re-connect, BRC-31 auth on upgrade, room subscribe + leave + heartbeat. Novel but well-scoped. | **Phase H** |
| **R2 — cggmp24 `std::thread` panics on wasm32** | Rewrite the SM bridge to use `tokio::task::spawn_local` + `LocalSet` (single-threaded async — which is exactly what CF Workers / DOs are). Replace `std::sync::mpsc` with `tokio::sync::mpsc`, blocking `recv()` with async `recv().await`. Same external coordinator API; internal plumbing only. ~1000 LOC across 3 coordinators + `tokio::task::yield_now()` between heavy `sm.proceed()` calls so we don't trip CF's 30s CPU limit. | **Phase G** |
| **R3 — no outbound WS in `workers-rs 0.7`** | Drop to `web_sys::WebSocket` via `wasm-bindgen` — that's the standard Workers-friendly WS API for outbound. DO holds the connection; hibernation handling = reconnect-on-wake + backfill via `/listMessages` (same pattern as Phase C's reconnect path, just hosted differently). | **Phase H** (folds into the client crate) |

Each RED is **well-scoped engineering work** under the "unlimited time" constraint, with concrete patterns we can adopt or invert. None of them are "we don't know if this works"; they're "we know what to build, we just haven't built it yet."

## Workflow discipline — every phase has the same 5-step shape

The earlier swarm-audit-then-decide loop (which surfaced the three REDs
and reversed me from B → A) was high-leverage. Embedding it as the
*standard workflow per phase* makes the discipline structural, not
ad-hoc. Each phase additionally gets a **POC step** between document
and implementation — matching the existing 15-POC pattern in `poc/`
that proved every load-bearing assumption in the original bsv-mpc
build before full implementation. Same discipline, made first-class:

| Step | What happens | Artifact | Commits to main? |
|---|---|---|---|
| **1. Investigate** | Survey the relevant `~/bsv/` reference stack + read the relevant MPC-Spec sections in full + identify risks/unknowns. Targeted (1-3 parallel Explore agents). | Notes in the WIP audit doc | No |
| **2. Document** | Write the phase's audit doc (`docs/PHASE-<X>-AUDIT.md`) summarizing what was learned + concrete design decisions + open questions. User reviews. | `docs/PHASE-<X>-AUDIT.md` | Yes (doc-only) |
| **3. POC** | Build the smallest standalone proof that the unknowns from step 1 actually work as documented in step 2. Lives in `poc/poc<N>-<name>/` per existing convention. Has its own quality gate (the specific unknown is proved). NOT a full implementation — a minimum risk-burn-down. | `poc/poc<N>-<name>/` + commit landing on main | Yes (the POC ships as a discrete commit) |
| **4. Implement** | Full implementation using the audit doc as the design spec + the POC as the validated pattern. Per the established cadence (commit small, hard-gate each commit, never bundle unrelated changes). | Implementation commits | Yes (after each commit passes gate) |
| **5. Quality gate** | Phase-specific live/integration test (described per phase below) proves the implementation works against the real spec, often with a real mainnet artifact. **110% confident no asterisks** — if the merge gate isn't byte-exact / signature-valid / on-chain, the phase stays open. | Test green + ideally an on-chain or other-third-party artifact (mainnet TXID, ARC ack, etc.) | Final phase merge commit |

**Investigation + document + POC are all non-negotiable.** They
prevent "start coding then discover three REDs" outcomes. The audit
doc + the POC commit BOTH land on main BEFORE the full implementation
does — reviewers, peers, and future-us see the reasoning AND the
empirical proof-of-feasibility that drove the implementation.

**110% / no asterisks framing**: a phase's quality gate either
produces a byte-exact / on-chain / verifiable third-party artifact,
or the phase isn't done. No "should work in production" framing. No
"works on my machine" framing. The Phase E mainnet TXID
[`82ccb15c…`](https://whatsonchain.com/tx/82ccb15c49985a32b355a618f417bb7a09ec4ee5cf34e539e9baaebb74dadc29)
is the bar.

**Spec interop framing**: per [`feedback_canonical_ts_immutable`](memory)
and [`feedback_spec_first_then_propose`](memory), we never propose
changing the MPC-Spec to fit our impl. The implementation conforms to
the spec, full stop. If the spec is genuinely wrong, that's a separate
ADR/PR against MPC-Spec — never silent consumer-side drift.

## Phase plan with quality gates per phase

All phases independently shippable + gated. Each commits to `main` only after its gate goes green. Each phase follows the 4-step workflow above.

### Phase G — Coordinator SM inline rewrite + Paillier safe-prime pool in `bsv-mpc-core` — **CLOSED 2026-05-19**

> **Status: merge-gate green.** All five steps landed on main; merge-gate
> closed by `d9b1b27` (citing mainnet TXID
> [`442bd391…`](https://whatsonchain.com/tx/442bd391cf8eda299f82dc1e4aeb1a9cb4f33610365d44c9c1c0e55d32f171b9)).
> See `docs/PHASE-G-AUDIT.md` §7 for the full check-off.
>
> **Direction change vs. original plan**: the audit doc's Step 1
> investigation surfaced that `round_based::StateMachine::proceed()` is
> non-blocking by construction — the prior `std::thread` + `mpsc`
> bridge was incidental complexity, and the originally-anticipated
> `tokio::task::spawn_local` + `LocalSet` rewrite would also have been
> incidental. The actual delivery holds the `StateMachineImpl` inline
> on each coordinator and drives `proceed()` synchronously. No spawn
> at all; no tokio dep added to `bsv-mpc-core`. ~800 LOC simpler than
> the LocalSet path the original plan prescribed.

**Step 1 (investigate)** — Done. Three parallel Explore agents surveyed `round_based`, `cggmp24` async surface, and CF-Worker prior art in `~/bsv/`. Key finding: `proceed()` returns immediately when it needs input; existing thread-and-channel bridge added artificial blocking. Recorded in `docs/PHASE-G-AUDIT.md` §1.

**Step 2 (document)** — Done. `docs/PHASE-G-AUDIT.md` (`c443dd8`) — inline SM rewrite design + Paillier safe-prime pool per MPC-Spec §06.10.1 / ADR-0041. Audit §2 makes the case for inline over LocalSet; audit §3 specs the pool.

**Step 3 (POC)** — Done. `poc/poc16-sm-inline/` (`8a85875`) — 5 hard gates green: inline 2-of-2 keygen with no `thread::spawn`, inline auxinfo with injected primes, pool round-trip preserves primes byte-for-byte, at-rest AES-256-GCM + BRC-42 encryption round-trip, wasm32 cargo-build clean.

**Step 4 (implement)** — Done. Five focused commits:
  - `f1b3947` G-4a: `crates/bsv-mpc-core/src/paillier_pool.rs` (6 unit tests).
  - `bc9c1be` G-4b: dkg.rs inline rewrite (-316 LOC, 12 dkg tests).
  - `cafb4c2` G-4c: signing.rs inline + shared `drive_inline` kernel (-261 LOC, 18 signing tests).
  - `6ab583b` G-4d: presigning.rs inline (-229 LOC, 7 presigning tests).
  - `a9a7e18` G-4e: `unsafe impl Send` shield on the three coordinator types — handles the `Rc<RefCell<_>>`-rooted `!Send` cascade through `bsv-mpc-service` / `bsv-mpc-proxy` / `bsv-mpc-worker` callers. Documented invariant in audit §2.5; structural `SendShield<T>` wrapper tracked as Phase G post-merge / Phase I deployment-audit follow-up.

**Step 5 (gate)** — Done. **Unit:** all 404 native lib tests green across the workspace. **Vector:** byte-locked DKG/sign vectors reproduce via the conformance_02/04/05 integration tests in CI. **E2E:** Phase E mainnet TXID re-run with the inline coordinators produced fresh on-chain artifact
[`442bd391…`](https://whatsonchain.com/tx/442bd391cf8eda299f82dc1e4aeb1a9cb4f33610365d44c9c1c0e55d32f171b9)
(joint pubkey `02aa325a…`, DER 70 bytes byte-identical both parties, pre-flight ECDSA verify PASS, broadcast `SEEN_ON_NETWORK` via gorillapool ARC). **WASM:** `crates/bsv-mpc-core/tests/wasm32_dkg.rs` runs a 2-of-2 DKG end-to-end via `wasm-pack test --node` (150.66s); CI ci.yml `wasm` job green.

---

### Phase H — `bsv-mpc-messagebox-worker` crate (~3-4 wk total)

**Step 1 (investigate)** — Survey: `web_sys::WebSocket` + `wasm-bindgen` patterns for outbound WS in CF Workers, `workers-rs` repo issues + examples, the bsv-messagebox-cloudflare inbound handler at `message_hub.rs:236-256` (invert for outbound), CF DO hibernation contract (state preservation across hibernation/wake; how `WebSocket` behaves during hibernation), Workers' 30s CPU limit vs WS frame processing budget.

**Step 2 (document)** — `docs/PHASE-H-AUDIT.md`: client API surface (mirrors Phase B `MessageBoxClient`), DO topology, BRC-31 upgrade-signing inversion, hibernation reconnect strategy, message_box subscription state location, backfill-on-wake recipe.

**Step 3 (POC)** — `poc/poc17-cf-outbound-ws/`: a minimum DO that opens an outbound WS to the live Calhoun relay via `web_sys::WebSocket`, sends a single canonical envelope to itself, receives it back via WS push, byte-exact. Gate: green round-trip + forced hibernation test (evict DO → wake → reconnect succeeds + replay missed message via `/listMessages`).

**Step 4 (implement)** — New crate `bsv-mpc-messagebox-worker`, WASM cdylib. Use the POC's WS pattern. BRC-31 auth via the inverted middleware pattern. DO host owning the WS + per-room state. Mirror `subscribe_round_messages` + `send_round_message` API from Phase B so consumer code stays portable.

**Step 5 (gate)** — **Unit:** event-envelope parser tests. **WASM build:** wasm32 cdylib compiles + passes clippy. **Live e2e (deployed Worker):** test Worker connects to live Calhoun relay, joins a room, round-trips byte-exact. Forced-hibernation roundtrip works. Backfill-on-wake validated.

---

### Phase I — Integrate G + H into `bsv-mpc-worker` (~3-4 wk total)

**Step 1 (investigate)** — Survey: current `bsv-mpc-worker/` state (HTTP-only, MpcStorage stub), `~/bsv/rust-wallet-infra/` D1 schema patterns (which subset applies to MPC cosigner?), R2 audit log format, Wrangler secret-management for BRC-31 identity priv, CF Worker / DO lifetime + scheduling, the existing `wrangler.toml.example` in the crate.

**Step 2 (document)** — `docs/PHASE-I-AUDIT.md`: D1 schema (tables + columns + indexes), R2 audit blob format, DO topology decision (per-identity vs multi-tenant), Wrangler config skeleton, secrets list, env-var contract for local-dev + production.

**Step 3 (POC)** — `poc/poc18-cf-cosigner-stub/`: minimum deployable Worker that loads `SERVER_PRIVATE_KEY`, opens an outbound WS to the relay (Phase H crate consumed), runs a single SM-async coordinator (Phase G crate consumed), persists one share to D1, returns `/health`. NO full ceremony orchestration. Gate: `wrangler deploy` succeeds; `/health` returns 200 with identity pubkey; the Worker survives across a deploy → restart with the share intact in D1.

**Step 4 (implement)** — Wire Phase G coordinators into bsv-mpc-worker handlers. Replace HTTP-only paths with MessageBox-driven dispatch (DO holds WS, routes inbound canonical envelopes to DkgHandler/SigningHandler — same trait surface as bsv-mpc-service, different transport). Replace `MpcStorage` stub with `D1ShareStorage` + `R2AuditLog`. BRC-31 server identity via Wrangler secret.

**Step 5 (gate)** — **Deployment smoke:** `wrangler deploy` + `/health`. **Within-stack with deployed cosigner:** 2-of-2 DKG + sign + mainnet TX where one party is the deployed CF Worker. **Same shape as Phase E's `82ccb15c…` but with a real CF-deployed cosigner** — this is THE merge gate for (A). No asterisks: a real on-chain TXID with the deployed Worker holding one share, or the phase stays open.

---

### Phase J — CHIP token + `/capabilities` + `health.json` (~2-3 wk total)

**Step 1 (investigate)** — Re-read MPC-Spec §12 (discovery), ADR-0050 (CHIP architecture path A), §16.3 (SLI surface), §16.4 (observability). Survey `bsv-mpc-overlay::chip` (CHIP token construction code from commit `0423aad`) — what's missing for publication + the `/capabilities` endpoint shape? Re-verify §16 MANDATORY items.

**Step 2 (document)** — `docs/PHASE-J-AUDIT.md`: exact `/capabilities` JSON shape, SLI fields in `health.json`, CHIP token publication recipe, BRC-22 SLAP topic registration, retention policy for SLI history (D1? KV? R2 cold storage?), exact §16 MUST-checklist with file:line citations to spec.

**Step 3 (POC)** — `poc/poc19-chip-discovery/`: minimum deployed Worker that serves `/capabilities` + emits `/health.json` + publishes a CHIP token to overlay topic `tm_mpc_signing`. Gate: external service runs `LookupResolver` on `tm_mpc_signing`, finds our cosigner, parses `/capabilities`, opens MessageBox to discovered `inbox_url`, exchanges one envelope byte-exact.

**Step 4 (implement)** — Publish canonical signed SHIP per ADR-0050 (reuse `bsv-mpc-overlay::chip::create_chip_token`). `/capabilities` endpoint per spec. `/health.json` emitting §16.3 SLI set.

**Step 5 (gate)** — **Discovery:** another service finds the deployed cosigner via `LookupResolver` + opens MessageBox to the discovered `inbox_url` + runs a real ceremony end-to-end. **Spec-conformance:** every MUST in §16 ticked via a conformance script that fails if any field is missing.

---

### Phase K — Cross-stack #36 mainnet TX (~1-2 wk Calhoun-side; blocked on Ishaan #8 + #10)

**Step 1 (investigate)** — Coordinate with Quaakee on rust-mpc readiness: relay choice (Calhoun's `rust-message-box.dev-a3e.workers.dev` vs Binary's `<TBD>`), message_box naming, session_id convention, initiation protocol. **Run the byte-locked conformance vectors against rust-mpc's encoder before going live** — `conformance/test-vectors/0{2,4,5}-*.json` MUST reproduce byte-for-byte on rust-mpc's side OR there's a spec drift to resolve first.

**Step 2 (document)** — `docs/PHASE-K-AUDIT.md`: cross-stack handshake convention agreed with Quaakee, runbook for the live test, rollback plan, sat budget, fail-closed assertions on byte-identical joint pubkey + DER signature.

**Step 3 (POC)** — Joint with Quaakee: simplest possible cross-stack envelope round-trip (no ceremony, just send a canonical envelope from one side and decode_strict on the other). Gate: rust-mpc's encoder produces a byte-identical canonical envelope to ours given the same input.

**Step 4 (implement)** — `tests/cross_stack_messagebox_e2e.rs` driving the joint ceremony from a test harness; rust-mpc-side equivalent on Quaakee's side.

**Step 5 (gate)** — **Real joint mainnet TXID** where 1 bsv-mpc + 1 rust-mpc impl each held one share. Both confirm byte-identical joint pubkey + DER signature. Closes MPC-Spec #36. No asterisks.

### Phase ordering / parallelism

- **G can ship independently** — it's an internal refactor of `bsv-mpc-core`, doesn't touch wire or deployment. Could go first while H research happens. Standalone value: makes `bsv-mpc-service` runnable in any single-threaded async context too (cheaper VPS deploys, easier testing).
- **H is independent of G** — could research/prototype in parallel. Doesn't ship until G is done because the deployed thing needs both.
- **I depends on G + H** (wires them together) — serial.
- **J depends on I** (needs a deployed thing to publish CHIP for) — serial.
- **K depends on J + Ishaan** — parallel to Ishaan's work.

Realistic wall-clock: **~6-10 weeks** if G + H are partially parallel, with K landing when Ishaan does.

### What I'm NOT cutting / replacing

- **Within-stack `bsv-mpc-service` Phase D + E e2e tests** stay as the reference oracle. They use native `tokio-tungstenite` (not WASM) and prove the canonical wire works on native Rust. Phase I's merge gate is "the deployed CF Worker reproduces the same wire behavior" — so the native tests are the source of truth.
- **Phase A canonical envelope helpers + byte-locked vectors** stay unchanged; they're target-agnostic.
- **All existing commits on main** — nothing rolled back. (A) is additive engineering work, not a redo.

## Proposed project / issue hierarchy

Two-repo split with one shared org project view:

### Where issues live

**Implementation issues live on `bsv-mpc`** (the code repo), not MPC-Spec. Reasons:

- Co-locate issues with the code they describe — PR ↔ issue ↔ code all in the same repo, single graph.
- Calhoun-side implementation details don't clutter the partnership-shared MPC-Spec.
- bsv-mpc commit history + issue numbers align (commit messages can `closes #N` on bsv-mpc directly).
- Mitch + Quaakee can still see everything via the org-level Partnership Roadmap project (see below).

**Joint deliverables stay on MPC-Spec** — MPC-Spec #36 (the cross-stack TXID) is joint with Quaakee and stays where it is. **An umbrella tracker on MPC-Spec** ("v1.0 CF-native cosigner — Calhoun-side") points at the bsv-mpc work for partnership visibility without duplicating the implementation tracking.

### Hierarchy (lean start: just the milestone + an umbrella placeholder)

The phase issues land **after** each phase's investigation + audit doc lands — not now. We start with just the structural scaffolding so the milestone is visible across all three views (bsv-mpc, MPC-Spec, org project):

```
┌─ bsv-mpc repo ───────────────────────────────────────────────────┐
│  [NEW milestone] v1.0 — CF-native cosigner (Calhoun-side)        │
│  └─ [NEW umbrella issue] v1.0 — CF-native cosigner deployment    │
│      body: NEXT-STEPS.md link + checklist of Phase G/H/I/J/K     │
│            (issues filled in as each phase's audit doc lands)    │
│      added to org project, status: Todo                          │
└──────────────────────────────────────────────────────────────────┘
                            ↑
                  (linked from MPC-Spec #36 via "Related to")
                            ↓
┌─ MPC-Spec repo ──────────────────────────────────────────────────┐
│  [milestone: M1] cross-impl mainnet signing demo (existing)      │
│  └─ #36 cross-stack 2-of-2 MessageBox sign — joint w/ Quaakee   │
│       (a comment will link to the bsv-mpc umbrella for context)  │
└──────────────────────────────────────────────────────────────────┘
                            ↑
                  org project visibility for both repos
                            ↓
┌─ Org project "Partnership Roadmap" ──────────────────────────────┐
│  bsv-mpc umbrella appears as the v1.0-cosigner placeholder       │
│  (later: phase issues join as they're filed)                     │
│  Existing MPC-Spec issues stay where they are                    │
└──────────────────────────────────────────────────────────────────┘
```

**This commit only creates:** (a) the milestone on bsv-mpc, (b) the umbrella placeholder issue on bsv-mpc, (c) adds the umbrella to the org project. Nothing else. Phase G/H/I/J/K issues come LATER — each as Phase X's audit doc lands.

**Labels per bsv-mpc issue:** `phase:G` / `phase:H` / `phase:I` / `phase:J` / `phase:K`, plus one or more of `wire-compat` / `feature` / `security` / `cleanup`. The phase label gives instant filtering.

**Dependencies (visible via "Depends on" in body):** G blocks I · H blocks I · I blocks J · J recommended-before K · K depends on MPC-Spec rust-mpc #8 + #10.

**Project board flow** (existing Partnership Roadmap project): each issue starts in **Todo** → moves to **In Progress** when its investigation begins → moves to **Done** when its quality gate is green. Each phase's 5 internal steps (investigate / document / POC / implement / gate) live as a checklist in the issue body — granular enough to track without inflating to 25 issues.

**Org-project note** — since the existing Partnership Roadmap project (`PVT_kwDOELLQl84BX-W9`) only auto-adds from MPC-Spec, we'd add a workflow that also auto-adds new bsv-mpc issues. Manual one-time addition for the 5 phase issues + 1 milestone tracker is also fine.

### What this gives us

- **Every audit doc is a real commit on bsv-mpc main**, gated by the phase issue's checklist. Doc lands BEFORE implementation begins — reviewers + future-us see the reasoning.
- **Every POC is a `poc/poc<N>-<name>/` directory** following the established 15-POC convention, with its own quality gate. The POC commit lands BEFORE implementation begins — empirically proves the unknown.
- **Every implementation issue has an explicit `110%-no-asterisks` quality gate** (live e2e + on-chain artifact where applicable). No "should work" — either the gate is green or the phase stays open.
- **The bsv-mpc milestone gives the Calhoun-side velocity view**; the MPC-Spec umbrella gives the partnership visibility view; the org project gives the unified cross-repo board.
- **Future readers** (Mitch on architecture review, Quaakee on cross-stack, other operators forking the cosigner template) drop into any single issue and see exactly what was decided, why, what POC proved it, and what artifact made it merge-able.

### Why this hierarchy is god-tier engineering practice

- **One responsibility per issue.** No 12-checkbox umbrellas hiding work.
- **Investigation + POC are first-class quality gates**, not optional polish. Matches the proven 15-POC pattern from the original bsv-mpc build.
- **Issues live where the code lives.** bsv-mpc PRs reference bsv-mpc issues — no cross-repo issue references that decay.
- **Cross-stack and joint work stay on MPC-Spec** — the partnership-shared tracker stays the partnership-shared tracker; the impl-detail tracker is private(-ish) to Calhoun-side velocity.
- **Org project view unifies for stakeholder visibility** — Mitch + Quaakee + you can all see the v1.0 progress on one board without diluting the partnership tracker with impl noise.

## Open questions for you (need answers before Phase G starts)

| | Question | Why it matters | Default if you don't answer |
|---|---|---|---|
| **Q1** | Phase G + H **in parallel** (faster wall-clock, slight double-context) or **strictly serial** (G first, then H — safer, simpler review)? | Parallel = ~6 wk · Serial = ~9 wk | Serial (cleaner) |
| **Q2** | For the WASM SM rewrite (Phase G): **single-threaded `LocalSet` everywhere** (matches CF Worker target, simpler) or **abstract a runtime trait so native multi-threaded tokio works too** (more flexible, ~20% more code)? | Affects Phase G surface area | LocalSet everywhere (KISS) |
| **Q3** | For the deployed Worker (Phase I): **one Worker per cosigner identity** (per-user model) or **one Worker shared across many identities with per-identity DOs** (multi-tenant model)? | Affects the DO topology + secrets model | Per-identity (cleaner; matches MessageBox relay pattern) |
| **Q4** | For Phase J: **fold CHIP+/capabilities+health into Phase I** (full spec-conformant in one ship) or **separate phase** (faster Phase I merge, J later)? | Risk vs ship cadence | Separate (smaller commits) |
| **Q5** | While Phase G+H is being built, do we **interim-deploy a `bsv-mpc-service` somewhere just so we have a deployed thing to point partners at** (the (B) shortcut as a temporary), or **wait for (A)**? | Avoid throwaway interim work | Wait for (A) (avoid throwaway) |
| **Q6** | **Issue hierarchy shape**: (a) 5 phase issues on bsv-mpc only + 1 umbrella tracker on MPC-Spec (= 6 issues) · (b) 5 phase issues on bsv-mpc only, no MPC-Spec tracker (= 5 issues, lean but less partnership visibility) · (c) duplicate on both repos (= 10+ issues, noise) | Visibility vs noise | (a) — recommended above |
| **Q7** | **New milestone "v1.0 — CF-native cosigner"** or **extend M1's scope**? | Milestone clarity vs single-milestone simplicity | New milestone on BOTH bsv-mpc + MPC-Spec for parallel tracking |
| **Q8** | **Auto-add workflow for the org project**: should new bsv-mpc issues auto-flow into the existing Partnership Roadmap project? | Unified org-level visibility vs separate bsv-mpc board | Auto-add (single source of truth across repos) |

## Risks I see going into (A) (with mitigations)

| Risk | Probability | Mitigation |
|---|---|---|
| `sm.proceed()` does long synchronous Paillier work that trips CF's 30s CPU limit | Medium | Phase G inserts `tokio::task::yield_now().await` between proceed-calls + benchmarks Paillier safe-prime gen on the WASM target. If it's >30s wall-clock (likely is), move prime gen to a separate DO with no compute limit OR use a pregenerated-primes pool managed externally. The spec §06.10.1 explicitly RECOMMENDS a primes pool for `profile-mobile` / `profile-edge`; this falls out naturally. |
| `web_sys::WebSocket` in Workers has subtle differences from browser WS that we hit at runtime | Low-Medium | Phase H smoke test is end-to-end against the live relay — any difference surfaces fast. Workers-rs maintainers active; can file issues if blocked. |
| DO hibernation + outbound WS interact badly (e.g., the WS dies during hibernation; reconnect storm on wake) | Medium | Phase H explicitly tests hibernation cycles. Reconnect uses §06.12 backoff (1s→cap 30s) so storms can't form. |
| cggmp24 fork drifts upstream during G's rewrite | Low | The fork is pinned. Rewrite happens in bsv-mpc-core layer ABOVE the cggmp24 SM, not in cggmp24 itself. |

## Status snapshot (live)

Each phase lands as its own issue when its audit doc lands. The umbrella tracker is bsv-mpc issue #2.

| Phase | State | Artifact |
|---|---|---|
| **G** — inline SM + Paillier pool | **CLOSED 2026-05-19** | TXID [`442bd391…`](https://whatsonchain.com/tx/442bd391cf8eda299f82dc1e4aeb1a9cb4f33610365d44c9c1c0e55d32f171b9) + merge-gate commit `d9b1b27` |
| **H** — `bsv-mpc-messagebox` CF Worker client crate | next | audit doc + `poc/poc17-cf-outbound-ws/` pending |
| **I** — wire G + H into `bsv-mpc-worker` | blocked on G + H | audit doc + `poc/poc18-cf-cosigner-stub/` pending |
| **J** — CHIP + `/capabilities` + `health.json` | blocked on I | audit doc + `poc/poc19-chip-discovery/` pending |
| **K** — Cross-stack joint mainnet TX (closes MPC-Spec #36) | blocked on J + Quaakee's rust-mpc | audit doc + joint conformance check pending |

## Reference: audit citations (from pre-Phase-G investigation)

- **Audit 1 (rust-message-box):** `~/bsv/rust-message-box/Cargo.toml:6-7`, `src/message_hub.rs:236-256, 393-445`, `src/lib.rs:329-350`. SERVER only — no client lib exported. **The Phase H CLIENT crate must be built fresh; canonical TS reference is `@bsv/message-box-client` v2.0.7 at `~/bsv/message-box-client/src/MessageBoxClient.ts` (Path A: implementation conforms to the canonical TS, never the inverse — per [`feedback_canonical_ts_immutable`](memory)).**
- **Audit 2 (cggmp24 WASM):** Originally pointed at `bsv-mpc-core/src/dkg.rs:419` (`std::thread::Builder::new().spawn`), `signing.rs:371` (same), `presigning.rs:63` (same). **All three `std::thread::Builder::spawn` sites were removed in Phase G** (`bc9c1be`, `cafb4c2`, `6ab583b` — inline rewrite, no spawn at all). Wasm32 build + runtime test green per `tests/wasm32_dkg.rs`.
- **Audit 3 (outbound WS in CF):** `bsv-messagebox-cloudflare-public/Cargo.lock` pins `worker = "0.7.5"` (no public outbound WS). All `tests/load_gen` clients use native `tokio-tungstenite`. Zero precedent for DO-as-outbound-WS-client anywhere in `~/bsv/`. Still load-bearing for Phase H — the audit doc will need to pick a path: `web_sys::WebSocket` via wasm-bindgen vs. a sub-fetch hijack vs. wait for workers-rs upstream.

---

**Last updated:** 2026-05-19 — Phase G closed; doc adapted from launch-plan to live tracker.
