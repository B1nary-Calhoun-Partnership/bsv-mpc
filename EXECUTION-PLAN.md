# Execution Plan: Parallel Sprint

> **Created:** March 22, 2026
> **Scope:** rust-bsv-worm M2 (33 issues) + bsv-mpc M5 (7 issues) + worm Alpha start
> **Method:** Fire off parallel Claude Code sessions per round, regroup between rounds
> **Goal:** M2 closed by Apr 5, bsv-mpc M5 closed by Apr 14, Alpha well underway

---

## Dependency Graph (what blocks what)

```
ROUND 1 (no deps)                 ROUND 2 (R1 deps)               ROUND 3 (R2 deps)
─────────────────                 ────────────────                 ────────────────
mpc #56 lib export ──────────────▶ mpc #48 StorageClient
mpc #53 deploy KSS                                               ▶ mpc Beta (#54,#50,#51,#52)
worm #23 extract x402 ──────────▶ worm #25+#98 x402 ecosystem
worm #143+#146 CI/CD ───────────▶ worm #82+#100 eval framework
worm docs (#144,#17,#147)         worm #84+#106 skill internals ─▶ worm #105 verification skills
worm #145 Docker                  worm #46+#47 SDK + plugins
decisions (#87,#137,#49,#31,#29)  worm #36+#38 templates
                                  worm #22+#24 fleet start ──────▶ worm #28+#26+#29+#31+#33 fleet
                                                                   worm #97+#53+#54 provider system
                                                                   worm #60+#61 replay
                                                                   worm #62+#51+#64 analytics
                                                                   worm #63+#65 observability
                                                                   worm #107+#35+#48(E.3) remaining
```

---

## Round 1 — Foundation (Day 1-2)

**Fire off 6 sessions + 1 quick decisions batch. Zero dependencies between them.**

### Session A: `[bsv-mpc]` Deploy KSS to Production (PRIVATE — CF details never public)
- **Issues:** mpc #53
- **Touches:** `crates/bsv-mpc-worker/`, wrangler.toml (gitignored), deployment config
- **Size:** Large (8-12h) — deployment + testing + monitoring setup
- **Critical path:** THE blocker for all hosted mode work
- **PRIVATE:** The edge deployment is our cost moat. bsv-mpc-worker crate stays private forever. wrangler.toml stays gitignored. No CF references in public-facing docs. The public KSS story is bsv-mpc-service (standalone binary).
- **Prompt hint:** "Deploy bsv-mpc-worker KSS. Credentials in secrets.md. Reference ~/bsv/agents/ for deployment patterns, ~/bsv/rust-middleware/ for BRC-31 auth. POC 10 validated. wrangler.toml goes in .gitignore. Keep all deployment details out of committed docs."

### Session B: `[bsv-mpc]` Export Proxy as Library
- **Issues:** mpc #56
- **Touches:** `crates/bsv-mpc-proxy/src/lib.rs`, handler function signatures
- **Size:** Medium (4-6h) — structural refactor, no new logic
- **Unblocks:** Round 2 Session G (StorageClient migration)
- **Prompt hint:** "Add lib.rs to bsv-mpc-proxy that exports MpcBridge, FeeInjector, PresignManager, all 28 handler functions. Handlers must accept parsed request types, NOT Axum extractors. Add ProxyBuilder pattern. See issue #56 for full export list. All 130+ existing tests must pass."

### Session C: `[worm]` Extract bsv-x402-server Crate
- **Issues:** worm #23
- **Touches:** `src/x402/`, creates new `bsv-x402-server/` crate
- **Size:** Medium-Large (6-10h) — extraction + re-wiring imports
- **Unblocks:** Round 2 Sessions H (x402 ecosystem)
- **Conflict zone:** `src/x402/` is HIGH conflict — no other session should touch it
- **Prompt hint:** "Extract src/x402/ (payment.rs, schema.rs, discovery.rs, circuit_breaker.rs, rate_limit.rs, cache.rs, refund.rs, registry.rs) into a standalone bsv-x402-server crate (MIT license). The worm re-imports it as a dependency. Tools in src/tools/x402_tools/ stay in the worm but call the extracted crate. All x402 tests must pass."

### Session D: `[worm]` CI/CD + Release Automation
- **Issues:** worm #143, #146
- **Touches:** `.github/workflows/`, `CHANGELOG.md`
- **Size:** Small (3-4h)
- **Prompt hint:** "Create .github/workflows/ci.yml (cargo build, test, clippy, fmt check, matrix stable+nightly) and .github/workflows/release.yml (triggered by v* tags, builds binaries for linux-amd64 + darwin-arm64 + darwin-amd64, creates GitHub Release with auto-changelog). Add CI badge to README."

### Session E: `[worm]` Internal Docs (prep for eventual open-source, NOT publishing yet)
- **Issues:** worm #144 (SECURITY.md), #17 (CLAUDE.md rewrite), #147 (Architecture guide)
- **Touches:** `SECURITY.md`, `CLAUDE.md`, `docs/ARCHITECTURE.md` — all different files
- **Size:** Small-Medium (3-5h)
- **NOTE:** Repos are PRIVATE. No public launch yet. These docs are prep work.
- **Prompt hint:** "Three docs (internal for now, eventual open-source): (1) SECURITY.md with vulnerability disclosure process. (2) Rewrite CLAUDE.md for human contributors. (3) docs/ARCHITECTURE.md with system diagram, crate map, request flow. Do NOT reference CF Workers, deployment infrastructure, or pricing — those are competitive secrets."

### Session F: `[worm]` Docker Image
- **Issues:** worm #145
- **Touches:** `Dockerfile`, `docker-compose.yml`
- **Size:** Small (2-3h)
- **Prompt hint:** "Multi-stage Dockerfile (builder + distroless/alpine runtime). docker-compose.yml with volume mounts for worm.toml and data. Image < 100MB. Add 'Quick Start with Docker' section to README. Publish to ghcr.io via GitHub Actions."

### Session Q: `[both]` Quick Decisions (do yourself, 1-2h total)
- **Issues:** worm #87 (agent naming), worm #137 (bsv-mpc open-source timing), mpc #49 (deployment modes), mpc #31 (decision log), mpc #29 (ecosystem map)
- **These are decisions/docs, not code.** Comment on each issue with the decision, close if resolved.

### Round 1 Regroup Checklist
- [x] KSS responding on production CF URL — `https://bsv-mpc-kss.dev-a3e.workers.dev/health` returns OK
- [x] `bsv-mpc-proxy` has `lib.rs` with all exports, `cargo test` green — 134 tests pass (130 + 4 new)
- [x] `bsv-x402-server` crate exists, worm compiles against it — 48 crate tests, 1500+ worm tests pass
- [x] CI runs on PRs, release workflow exists — ci.yml + release.yml, YAML validated
- [x] SECURITY.md, ARCHITECTURE.md, CLAUDE.md (contributor version) exist — all 3 created and verified
- [x] `docker compose up` starts a working worm — health check passes, all 5 pages render, 174MB image
- [x] Decision issues closed with recorded decisions — 7 issues closed with ADRs

### Round 1 Results (completed 2026-03-22)

**Duration:** ~51 minutes (longest session: C at 51min, shortest: D at 1min)
**All 11 acceptance criteria passed.**

| Session | Issues Closed | Key Metric |
|---------|--------------|------------|
| A (KSS deploy) | mpc #53 | Worker live, 16ms RTT |
| B (proxy lib) | mpc #56 | 134 tests, 28 _impl functions |
| C (x402 extract) | worm x402 | 48 crate tests, E2E verified |
| D (CI/CD) | worm #143, #146 | 2 workflows, YAML valid |
| E (docs) | worm #144, #147 | 3 docs, 755 lines total |
| F (Docker) | worm #145 | 174MB image, health OK |
| Q (decisions) | mpc #49,#31,#29 + worm #87,#137 | 16 ADRs recorded |

**Systemic issue found:** cggmp21-fork sibling path (`../cggmp21-fork`) breaks worktrees and CI. Fix: ADR-017, git submodule (applied in cleanup session).

**Parallel execution note:** Worm sessions C/D/E/F shared a working directory without worktree isolation. All work ended up on one branch (round1-session-F). In Round 2, use worktree isolation for worm sessions too, or accept single-branch merge.

**Archived branch:** `archive/round0-overlay-proofs` (tag on origin) contains 4 unmerged commits from pre-Round-1 work: proof publishing (`publish_proof`, `query_proofs`, `count_proofs_by_node`, `parse_proof_from_script`), settlement tx building (ported from POC 11), CHIP/SLAP overlay merge, and key refresh integration. ~2.6K lines across overlay, core, proxy, service, worker. **19 commits behind main** — will need rework against current `_impl` handler pattern, but the overlay proof logic is directly reusable. Reference this branch when implementing overlay proof publication (mpc M4/M5 scope).

---

## Round 2 — Core Features (Day 3-5)

**Fire off 7 sessions. Some blocked by Round 1 (noted).**

### Session G: `[bsv-mpc]` StorageClient Migration
- **Issues:** mpc #48
- **Touches:** `crates/bsv-mpc-proxy/src/` (utxo_tracker.rs, wallet_api.rs, server.rs)
- **Size:** Large (8-12h) — new trait, two impls, handler updates
- **Blocked by:** R1-B (library export must be done first — both touch proxy crate)
- **Prompt hint:** "Create StorageBackend trait with InMemoryBackend (existing UtxoTracker) and WalletInfraBackend (StorageClient from rust-wallet-toolbox). Update AppState to hold Box<dyn StorageBackend>. Update listOutputs, listActions, createAction, internalizeAction handlers. See issue #48 for full migration plan. Standalone binary keeps InMemoryBackend."

### Session H: `[worm]` x402 Ecosystem
- **Issues:** worm #25 (example x402 service), #98 (LlmProvider bridge crate)
- **Touches:** new crate(s), examples/ directory
- **Size:** Medium (5-8h)
- **Blocked by:** R1-C (x402 extraction must be done)
- **Prompt hint:** "Two things: (1) Example axum x402 service using bsv-x402-server — a minimal paid API that accepts BRC-29 payments. (2) x402 LlmProvider bridge crate — wraps OpenAI/Claude APIs behind x402 payment, so agents in the ecosystem can sell LLM access for BSV."

### Session I: `[worm]` Skill System Internals
- **Issues:** worm #84 (skill hooks/PreToolUse), #106 (skill composition/cross-references)
- **Touches:** `src/skills/mod.rs`, `src/skills/loader.rs`
- **Size:** Medium (5-8h)
- **Conflict zone:** Owns `src/skills/` internals — no other session touches these files
- **Prompt hint:** "Two skill system enhancements: (1) Skill hooks — skills can register PreToolUse handlers that fire before tool execution (e.g., a safety skill that intercepts dangerous commands). (2) Skill composition — skills can reference other skills, loader resolves cross-dependencies."

### Session J: `[worm]` SDK + Plugin Examples
- **Issues:** worm #46 (extract bsv-worm-sdk crate), #47 (3 example plugins)
- **Touches:** new `bsv-worm-sdk/` crate, `examples/plugins/`
- **Size:** Medium (5-8h)
- **Prompt hint:** "Extract the plugin/extension API from bsv-worm into a standalone bsv-worm-sdk crate. Then build 3 example plugins that use it: (1) a custom tool plugin, (2) a skill plugin, (3) a provider plugin. Each with README and tests."

### Session K: `[worm]` Eval + Testing Framework
- **Issues:** worm #82 (agent eval framework), #100 (cold-read prediction test)
- **Touches:** `tests/`, new eval infrastructure
- **Size:** Medium (5-8h)
- **Blocked by:** R1-D (CI must exist so evals run in pipeline)
- **Prompt hint:** "Build an agent evaluation framework: trajectory recording, grading rubrics, regression detection. Then implement a cold-read prediction test — start a fresh session with only memory, predict what the user will ask about, grade accuracy. This validates memory quality."

### Session L: `[worm]` Template System
- **Issues:** worm #36 (agent template format), #38 (10 curated templates)
- **Touches:** `src/config/`, `templates/` directory
- **Size:** Medium (5-8h)
- **Prompt hint:** "Define the agent template format (YAML/TOML with name, description, skills, tools, budget, personality). Then create 10 curated templates: researcher, coder, analyst, trader, content creator, customer support, data pipeline, security auditor, devops, personal assistant. Each with sensible defaults."

### Session M: `[worm]` Fleet Management Start (Alpha)
- **Issues:** worm #22 (Fleet SKILL.md — critical-path), #24 (Fleet status aggregation — critical-path)
- **Touches:** `skills/fleet.md`, `src/tools/fleet_tools/`
- **Size:** Medium (5-8h)
- **Prompt hint:** "Start Alpha fleet work. (1) Create fleet management SKILL.md — defines fleet:spawn, fleet:status, fleet:assign, fleet:recall commands. Uses BRC-52 parent certificates for authorization. (2) Implement fleet status aggregation tool — queries child agents via MessageBox, aggregates health/task status into a dashboard view."

### Round 2 Regroup Checklist
- [ ] bsv-mpc-proxy has StorageBackend trait + two impls, `cargo test` green
- [ ] Example x402 service runs and accepts BRC-29 payments
- [ ] x402 LlmProvider bridge compiles
- [ ] Skill hooks work (PreToolUse fires before tool execution)
- [ ] bsv-worm-sdk crate exists with 3 working example plugins
- [ ] Eval framework runs, cold-read test executes
- [ ] 10 agent templates defined and loadable
- [ ] Fleet SKILL.md works, status aggregation returns data

---

## Round 3 — Polish + Fleet + MPC Beta Prep (Day 5-8)

**Fire off 7 sessions. Finishes M2, advances Alpha, starts bsv-mpc Beta.**

### Session N: `[worm]` Provider System Refactor
- **Issues:** worm #97 (composable decorator chain), worm #53 (cross-model routing), worm #54 (parallel fan-out)
- **Touches:** `src/think.rs` — **SERIAL, one session owns this file**
- **Size:** Large (10-14h) — major refactor of hot path
- **Conflict zone:** ONLY session that touches think.rs. No other session in Round 3 should modify it.
- **Prompt hint:** "Refactor think.rs into a composable provider decorator chain: think() → rate_limit → circuit_breaker → cost_tracking → route → execute. Then add cross-model routing (intelligent selection based on task type) and parallel multi-model fan-out (query multiple providers, return best/fastest). This is the hot path — all 20+ think tests must pass."

### Session O: `[worm]` Replay System
- **Issues:** worm #60 (interactive replay UI), #61 (fork execution from any point)
- **Touches:** new `src/replay/` module, UI components
- **Size:** Medium-Large (6-10h)
- **Prompt hint:** "Build replay infrastructure: (1) Interactive replay UI that visualizes session.jsonl transcripts step-by-step (tool calls, LLM responses, decisions). (2) Fork execution — pick any point in a transcript and re-execute from there with different parameters. Uses existing JSONL transcript format."

### Session P: `[worm]` Cost Analytics
- **Issues:** worm #62 (cost replay/model comparison), #51 (ROI report), #64 (provider benchmarks)
- **Touches:** `src/analytics.rs`, new reporting modules
- **Size:** Medium (5-8h)
- **Prompt hint:** "Three analytics features: (1) Cost replay — re-score a past session with different model pricing to show 'what if you used claude-haiku instead of opus'. (2) Cost vs value ROI report — correlate spending with task completion quality. (3) Provider benchmarks — latency, cost, quality comparisons across providers."

### Session R: `[worm]` Observability
- **Issues:** worm #63 (Prometheus metrics), #65 (telemetry dashboard UI)
- **Touches:** new metrics module, dashboard UI
- **Size:** Medium (5-8h)
- **Prompt hint:** "Observability stack: (1) Prometheus metrics endpoint — expose token usage, latency histograms, error rates, budget utilization as /metrics. (2) Telemetry dashboard UI — real-time view of agent health, spending rate, task throughput. Can be a simple HTML dashboard served by the agent's HTTP server."

### Session S: `[worm]` Remaining M2 Items
- **Issues:** worm #107 (context fork), #35 (auto-escalation), #48/E.3 (plugin marketplace API), #105 (verification skills)
- **Touches:** various (context/, runner/, skills/, server/)
- **Size:** Medium (5-8h) — 4 smaller issues batched
- **Prompt hint:** "Four bounded features: (1) Context fork for memory-intensive skills — clone conversation context so memory-heavy operations don't pollute main context. (2) Auto-escalation to human — detect when agent is stuck or uncertain, pause and notify human. (3) Plugin marketplace listing API — CRUD for plugin metadata so marketplace can display available plugins. (4) Verification skills — skills that double-check other skills' outputs (e.g., code review after code generation)."

### Session T: `[worm]` Fleet Completion (Alpha)
- **Issues:** worm #28 (dashboard UI), #26 (task distribution), #29 (parent cert UI), #31 (health monitoring), #33 (audit view), #103 (adversarial review)
- **Touches:** `src/server/handlers/`, `src/tools/fleet_tools/`
- **Size:** Large (10-14h) — full fleet feature set
- **Blocked by:** R2-M (fleet SKILL.md + status aggregation)
- **Prompt hint:** "Complete Alpha fleet milestone: (1) Fleet dashboard UI — web view showing all child agents, status, tasks, spending. (2) Task distribution tool — assign tasks to children based on capabilities/load. (3) Parent certificate issuance UI — create BRC-52 certs for child agents. (4) Health monitoring — heartbeat checks, auto-restart. (5) Cross-agent audit view — unified audit log across fleet. (6) Adversarial review subagent — spawn a critic agent to review another agent's work."

### Session U: `[bsv-mpc]` Beta Prep
- **Issues:** mpc #51 (threat model), mpc #54 (browser DKG), mpc #50 (WAB onboarding)
- **Touches:** `crates/bsv-mpc-worker/`, `crates/bsv-mpc-core/`, docs
- **Size:** Medium-Large (8-12h)
- **Prompt hint:** "Three bsv-mpc Beta items: (1) Document MPC threat model — what attacks are possible at each phase (Alpha/Beta/GA), what's mitigated, what's accepted risk. (2) Browser-initiated DKG — modify KSS to accept DKG from browser Web Workers, store share_A keyed by joint_key but unbound to a user until binding step. (3) WAB onboarding flow — the binding step: verify BRC-52 certificate, accept encrypted share_B, link to user."

### Round 3 Regroup Checklist
- [ ] think.rs refactored with composable decorator chain, routing, fan-out
- [ ] Replay UI visualizes transcripts, fork execution works
- [ ] Cost analytics: model comparison, ROI report, provider benchmarks
- [ ] Prometheus /metrics endpoint, telemetry dashboard serves
- [ ] All 4 remaining M2 items implemented
- [ ] Fleet complete: dashboard, distribution, certs, monitoring, audit, adversarial review
- [ ] MPC threat model documented, browser DKG + WAB onboarding implemented

---

## Post-Sprint Status (Day 8)

| Milestone | Expected State |
|---|---|
| **worm M2: Open-Source Launch** | **CLOSED** — all 33 issues done |
| **bsv-mpc M5: Integration** | **CLOSED** — KSS deployed, StorageClient, library export |
| **worm Alpha: Fleet** | **CLOSED** — 8/8 fleet issues done |
| **bsv-mpc Beta** | 3/6 done (threat model, browser DKG, WAB) |
| **worm Beta: Hosted Mode** | Ready to start — all bsv-mpc dependencies met |

---

## Conflict Map (which sessions CANNOT run together)

| File/Area | Owner Session | Do NOT run in parallel with |
|---|---|---|
| `bsv-mpc-proxy/src/` | R1-B, then R2-G | Each other (serialize B→G) |
| `worm src/x402/` | R1-C only | Nothing else touches x402 |
| `worm src/think.rs` | R3-N only | Nothing else touches think.rs |
| `worm src/skills/mod.rs, loader.rs` | R2-I only | R2-L creates files but doesn't modify internals |
| `worm .github/workflows/` | R1-D only | Nothing else touches CI |

Everything else creates new files or modifies non-overlapping modules — safe to parallelize.

---

## Session Sizing Quick Reference

| Size | Time | Examples |
|---|---|---|
| **S** (Small) | 1-3h | Docs, decisions, config files, single small feature |
| **M** (Medium) | 3-8h | Crate extraction, new module, multi-file feature |
| **L** (Large) | 8-14h | Major refactor, deployment, full feature with tests |

**Round 1:** 1L + 1M + 1ML + 1S + 1SM + 1S = ~6 sessions, fastest finish ~3h, slowest ~12h
**Round 2:** 1L + 6M = ~7 sessions, fastest finish ~5h, slowest ~12h
**Round 3:** 2L + 4M + 1ML = ~7 sessions, fastest finish ~5h, slowest ~14h
