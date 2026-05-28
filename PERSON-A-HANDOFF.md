# bsv-mpc — Person A Handoff (post-audit, 2026-05-28; updated post-#75-ship)

> For a NEW session to drive **Person A's** lane on the Calhoun-side BSV-MPC partnership.
> Person A owns the **load-bearing 4-of-6 seam + spec-level decisions**.
> Person B has the parallel lane (god-tier security hardening + 100cash Swift wiring +
> they're currently driving the 100cash#15 mainnet TXID that closes #75, and they may
> also be in flight on #69 in their window) — see
> `/Users/johncalhoun/bsv/mpc/100cash/ROADMAP-HANDOFF.md` §"Post-audit work split".
> Repo: `B1nary-Calhoun-Partnership/bsv-mpc` (branch `main`), local at
> `/Users/johncalhoun/bsv/mpc/bsv-mpc/`. Created 2026-05-28; resume-state rewritten
> after #75 shipped + Person B picked up the closing TXID + #69.

---

## 🟢 Resume state — 2026-05-28 PM (READ THIS FIRST, then the checklist below)

### What just shipped from the Person A window

- **bsv-mpc#75 (canonical_render + ffi_canonical_render)** — code + tests + spec amendment
  ALL SHIPPED. **Issue stays OPEN until Person B's mainnet TXID lands** (no asterisks).
  - MPC-Spec PR #48 → merged to main (commit `a140bd7`). ADR-0044 amendment §2.1 (intent
    classifier shape — tagged sum + deny-unknown-fields), §2.2 (pre-resolved string
    fields + punctuation tie-break normative), §2.3 (per-kind required fields — payment
    gains `human_address`). Fixture: payment vector gains `intent.human_address`. Python
    `canonical_render` reference impl in `runner-python/runner.py`.
  - bsv-mpc PR #82 → merged to main (commit `0e90fbe`, squashed). `Intent` enum +
    `canonical_render` in `bsv-mpc-core::approval` + `ffi_canonical_render(intent_cbor)`
    in `bsv-mpc-client::ffi`. 18 new tests (13 unit + 5 FFI) + new conformance test +
    existing `conformance_09_rendered_text.rs` byte-locks preimage/view_hash unchanged.
  - Status comments posted on bsv-mpc#75, Calgooon/100cash#15, bsv-mpc#69 / #73 / #74 /
    #70. No issues closed.
- **`PROGRESS-PERSON-A.md` + `PERSON-A-HANDOFF.md`** committed to bsv-mpc main as
  commit `5481e51` (separate from the #75 PR per "tracker docs go direct to main").

### What the other window is driving right now (per user, 2026-05-28 PM)

- **100cash#15** — Person B is wiring `ffi_canonical_render` into the 100cash send path
  and intends to land the **mainnet TXID that closes bsv-mpc#75 + 100cash#15**.
- **bsv-mpc#69** — Person B is reportedly "almost done" in their window. This was
  originally a Person A item per the audit; appears the other window picked it up.
  **DO NOT touch #69 files** until this is verified — see the checklist below.
- Person B also still owns: bsv-mpc#76/#77/#78 (policy gate RED cluster), #79
  (unbounded HTTP), #80 (Zeroize), #81 (share-metadata auth), 100cash#13/#14/#19/#25.

### File-scope guards — DO NOT TOUCH (other window has uncommitted work)

Last `git status` on local main showed Person B uncommitted in these paths. Re-verify
with `git status` BEFORE editing anything — Person B may have committed or shifted
since this doc was written:

- `bsv-mpc-proxy/src/{bridge,config,server,wallet_api,policy}.rs`
- `bsv-mpc-proxy/tests/*` (most files modified, plus `policy_gate_red_e2e.rs`,
  `policy_loader_red_e2e.rs` untracked)
- `bsv-mpc-core/Cargo.toml`, `bsv-mpc-core/src/policy.rs`
- `bsv-mpc-core/tests/policy_mainnet_strict_red.rs` (untracked)
- `.github/workflows/ci.yml`
- `tests/e2e.rs`
- Anywhere in `/Users/johncalhoun/bsv/mpc/100cash/` (Person B's entire repo)

**If you commit to any file in their working tree, you cause a pull-conflict in
their window.** The cost is real — they have to rebase + resolve. Do not introduce
that friction.

### First-action checklist for the new window (run BEFORE picking up any work)

Execute these in order; the decision tree at the bottom tells you what to do based
on what you find.

1. **Pull latest:** `cd /Users/johncalhoun/bsv/mpc/bsv-mpc && git fetch && git log --oneline origin/main -10`. Note any commits since `5481e51` — that's whether
   Person B has merged anything new (their policy cluster, #69, etc.).
2. **Check the other window's working tree:** `git status --short` (same disk = same
   working tree). The file-scope guard list above is a SNAPSHOT from this doc's write
   time; the LIVE state is what `git status` shows now. Update your file-avoidance
   list accordingly.
3. **Check 100cash progress:**
   - `cd /Users/johncalhoun/bsv/mpc/100cash && git log --oneline -10` (Person B's
     activity)
   - `git status --short` (Person B's in-flight work)
   - `cat PROGRESS-PERSON-B.md` (their live tracker — sibling to ours)
   - `gh issue view 15 --repo Calgooon/100cash` (look for closing comment + mainnet TXID)
4. **Check bsv-mpc#75 closure:** `gh issue view 75 --comments` — if the mainnet TXID
   has been posted, the issue should close. If it's still open without the TXID, the
   send-path hasn't landed yet.
5. **Check bsv-mpc#69 status:** `gh issue view 69 --comments` and `gh pr list --state
   all --search "in:title 69"` — see if Person B opened a PR or commented progress.
   The user said "almost done" — confirm what state it's actually in before treating
   it as taken.
6. **Build + test still green on main:** `cargo build -p bsv-mpc-core && cargo test
   -p bsv-mpc-core --lib approval::` — sanity-check that #75 still works (only takes a
   few seconds; the workspace is cached). If #75 broke, escalate to user before doing
   anything else.

### Decision tree based on what step 1-6 found

- **#75 closed + #69 closed** → both load-bearing items done; pick from #74 (spec PR
  first) or #73 (isolated single file). #73 is the easier same-day ship.
- **#75 closed + #69 OPEN with Person B in flight** → STAY OUT of #69 files
  (`bsv-mpc-client/src/{ffi.rs,native_io/*}`, `bsv-mpc-relay/src/dkg.rs`,
  `bsv-mpc-proxy/src/{bridge,presign_manager,wallet_api}.rs`). Pick up #73 — it's in
  `bsv-mpc-core/src/signing.rs:1028-1047` which has no overlap with the #69 surface.
- **#75 OPEN + Person B working it** → #75 closure is the priority for them, not us.
  Don't touch the FFI / approval surface (`bsv-mpc-core/src/approval.rs`,
  `bsv-mpc-client/src/ffi.rs`'s `ffi_canonical_render` region). Pick up #73 (safe) or
  #70 (deploy ops, no code), or wait if you want to be on call for FFI clarifications.
- **#75 OPEN AND #69 OPEN AND Person B working both** → pick up #73 OR #70. Both are
  zero-collision. If you can't be productive without colliding, the right move is to
  hand back to the user with a status update.
- **#74 spec PR still needed** → can start anytime — needs the user's ADR-0005
  decision (add `"approval"` to enum vs different field) + ADR-0032's `exec_id_prefix`
  rule. Spec PR lands first (per quality-gate-4), then the 2-line code fix in
  `bsv-mpc-proxy/src/relay_approval.rs:132-133`. Note: that file isn't in Person B's
  current touch list, but it IS in the same crate. Confirm via step 2 before editing.

### Quality-gates rule (still applies, no exceptions)

Every issue closed ships with UNIT + VECTOR/GOLDEN + E2E + SPEC PR (if applicable) +
PROOF ARTIFACT (mainnet TXID + WoC URL or test names + CI run link) + CI INTEGRATION +
ZERO-DRIFT all GREEN. "Skipping is lazy." "No asterisks." Open a follow-up issue
instead of asterisking the parent. See the full quality gates section in the
session-opener prompt below.

### After picking up work

Update `PROGRESS-PERSON-A.md` (live tracker — gets committed direct to main as
sibling housekeeping). Use the existing entries for #73 / #74 / #69 / #70 as the
slot for new status. Pattern: status → locked decisions → spec PR (if any) → code
PR → quality gates (one line per gate with GREEN/PENDING + proof link).

---

## Owned scope (5 issues)

All in `B1nary-Calhoun-Partnership/bsv-mpc`. `gh issue view <num>` for full body.

| # | Title | Status | Files |
|---|---|---|---|
| **69** | Client-side multi-share wiring — device holds t−1 shares | open / `step:implement` / audit comment 2026-05-28 | `bsv-mpc-client/src/{ffi.rs,native_io/{provision,ceremony,signer}.rs}` + `bsv-mpc-relay/src/dkg.rs` + `bsv-mpc-proxy/src/{bridge,presign_manager,wallet_api}.rs` |
| **70** | Deploy 2nd cosigner instance (interim) + prod 2-Notary independence | open / `step:investigate` / audit comment 2026-05-28 | CF Worker / container deploy ops, not in-repo code |
| **75** | SPEC LEAK: `canonical_render(intent)` does not exist | open / `step:investigate` / audit-filed 2026-05-28 | `bsv-mpc-core/src/approval.rs` + `bsv-mpc-client/src/ffi.rs` + `MPC-Spec/decisions/0044*.md` |
| **74** | SPEC LEAK: approval envelope phase + exec_id_prefix | open / `step:investigate` / audit-filed 2026-05-28 | `bsv-mpc-proxy/src/relay_approval.rs:132-133` + `MPC-Spec/decisions/0005*.md` + ADR-0032 |
| **73** | SPEC LEAK: `ParticipationProof` placeholders → BRC-18 non-conformant | open / `step:implement` / audit-filed 2026-05-28 | `bsv-mpc-core/src/signing.rs:1023, 1028-1047` |

---

## Reference material (what to read when stuck)

- **MPC-Spec** at `/Users/johncalhoun/bsv/mpc/MPC-Spec/` — the canonical spec. Decisions
  in `decisions/`. Open questions in `OPEN-QUESTIONS.md`.
- **Audit knowledge graph** at `/Users/johncalhoun/bsv/mpc/graphify-out/graph.html`
  (693 nodes / 1136 edges / 70 communities). Open in browser; the graph independently
  surfaced `combine_sign_over_relay (2-party)` ↔ `FfiDeployedSigner` as a similar-pair
  (the exact seam #69 is fixing).
- **bsv-mpc top-level docs** in `/Users/johncalhoun/bsv/mpc/bsv-mpc/`:
  `SPECS.md`, `DECISIONS.md`, `EXECUTION-PLAN.md`, `INTEGRATION.md`, `STATUS.md`, `LESSONS.md`.
- **Partnership direction** at `/Users/johncalhoun/bsv/mpc/{direction.md,direction-audit.md,SWARM-CONVERGENCE.md,GOD-TIER-SWARM-PLAN-2026-05-13.md}`.

---

## Discipline (from auto-memory — partnership rules)

- **No commit/push without user OK.** Show diff, wait for green light.
- **No `cargo fmt` on `lib.rs` or a crate root.** It cascades + reflows pre-existing-unformatted
  files. `main` is CI-red on fmt. Format only edited files. Enforced gate is clippy.
- **Ask user for design decisions.** Don't guess between approach (a) vs (b) on #69.
- **Validate, don't skip.** Negative cases must be asserted (reject for the right reason),
  not skipped. "Skipping is lazy."
- **Verify inputs before escalating.** A "crypto divergence" is usually a wrong-key test
  error; confirm canonical inputs first.
- **Async-only.** No meetings / no scheduled syncs / no handoff calls. Slack + GitHub +
  code + proofs + tests.

---

## Person A focused session-opener prompt

```
You are Person A on the Calhoun-side BSV-MPC partnership. Your scope is the load-bearing
4-of-6 crypto seam + spec-level decisions. You do NOT own god-tier security hardening or
100cash Swift wiring — that's Person B (see 100cash/ROADMAP-HANDOFF.md §"Post-audit work
split"). One repo:
  /Users/johncalhoun/bsv/mpc/bsv-mpc/   (Rust, GitHub B1nary-Calhoun-Partnership/bsv-mpc, branch main)

FIRST read, in order:
  1. bsv-mpc/PROGRESS-PERSON-A.md  (your live status — start by reading this)
  2. bsv-mpc/PERSON-A-HANDOFF.md   (full context)
  3. The audit issue you're about to start (gh issue view <num>)

Your 5 owned issues (rough priority order):
  bsv-mpc#69  — n-party provisioning + sign seam in bsv-mpc-client. LOAD-BEARING for 4-of-6.
                Audit comment on the issue lays out approach (a) new seam vs (b) factor
                proxy's DeviceShareBundle out — ASK USER which before coding. Crypto is
                proven (mainnet TXID febd2877…, PR #46), this is orchestration only.
  bsv-mpc#70  — deploy 2nd Calhoun cosigner. Runs in parallel with #69 (ops not code).
  bsv-mpc#75  — canonical_render(intent) + ffi_canonical_render. UNBLOCKS Person B's
                100cash#15 (every hour you sit on #75, Person B waits).
  bsv-mpc#74  — approval envelope phase + exec_id_prefix. Spec decision needed
                (add "approval" to ADR-0005 enum?). Sibling thinking to #75.
  bsv-mpc#73  — ParticipationProof placeholders in signing.rs:1028-1047. Same file as #69 —
                consider folding into the #69 PR if natural.

QUALITY GATES — every issue you close must be PROVEN, no asterisks:
  Each issue you close must ship with EVERY applicable gate below GREEN before the
  PR can land. "Asterisks" (e.g. "tests pass except for X", "mainnet-deferred",
  "spec-decision pending", "needs Binary to confirm", "should work") are NOT acceptable
  for closing — open a follow-up issue instead of asterisking the parent.

  1. UNIT TESTS — the exact behavior the audit identified must be reproducible in a
     FAILING test against current main, and the fix must turn it green. Include both
     POSITIVE and NEGATIVE cases. The negative case must assert the RIGHT rejection
     reason. Applies to all 5 issues. Memory rule: "Validate, don't skip — negative/
     rejection cases must be asserted, never skipped; skipping is lazy."

  2. VECTOR / GOLDEN TESTS — for any change that touches a wire format, ADR, FFI
     surface, canonical encoding, or cross-impl conformance, add a golden-vector test
     that pins the bytes/behavior. For your scope this is non-negotiable:
       • #69 — 4-of-6 sign produces a signature that verifies against the joint
         pubkey; address derivation matches the proxy-path address (cross-check
         against the febd2877… TXID's address). Mirror the hermetic-test pattern from
         bsv-mpc PR #46.
       • #75 — golden text vectors per intent kind (payment, token_transfer,
         script_spend, brc100_internalize, multi) — BYTE-EXACT. These belong in
         MPC-Spec/conformance/test-vectors/ so Binary's implementation can later
         gate against the same outputs. Also: intent-classifier vectors covering
         edge cases (multi-output payment, derived-key brc100_internalize, etc.).
       • #74 — envelope round-trip vectors per ADR-0037 (canonical CBOR re-encode
         equivalence). Bytes must equal the spec's canonical form on every field.
       • #73 — golden OP_RETURN proof vectors. Parsing a known-good proof verifies;
         parsing a tampered proof rejects with the SPECIFIC reason.

  3. E2E TESTS — for any fix that touches a deployed surface, run an integration
     against real infrastructure. Applies to:
       • #69 — mainnet 4-of-6 TXID via the new client seam. THE audit-closing artifact.
         (Mirror existing pattern: bsv-mpc PRs #46, #57 land mainnet TXIDs in the
         closing comment.)
       • #70 — independence audit: second cosigner has distinct CA / identity key /
         deploy environment; mainnet 4-of-6 TXID signed using BOTH cosigners (not
         the original cosigner twice).
       • #75 — Person B's 100cash#15 closes the loop: 100cash calls
         ffi_canonical_render, viewHash binds, approval flow completes on a real
         mainnet send. Coordinate the closing TXID with Person B.
       • #73 — mainnet sign emits a valid ParticipationProof OP_RETURN; fetch from
         WhatsOnChain, parse-back, verify_participation_proof passes end-to-end.

  4. SPEC PRs (your scope only) — for #74 and #75, the spec decision lands as an
     MPC-Spec PR BEFORE the code PR merges. Don't merge code that silently invents a
     spec answer; open the spec PR first, get the user's OK on the spec direction,
     then build the code to match. Cross-impl conformance is the load-bearing
     property of M1 — drift here means Binary will diverge later.

  5. PROOF ARTIFACT — the closing comment on the GitHub issue MUST include the
     concrete proof: test names, CI run link, mainnet TXID + WoC URL, the actual
     verify_participation_proof output for #73, the actual canonical_render output
     bytes for #75, etc. No "should work" / "tested locally" — only "ran the gate,
     here's the proof, with link."

  6. CI INTEGRATION — every new test (unit + vector) must be part of a CI workflow
     that gates merge. Conformance vectors for #75 + #74 land in MPC-Spec/conformance/
     with a runner that CI invokes. Local-only tests don't count.

  7. ZERO-DRIFT INVARIANT — for any code that emits or consumes envelope bytes /
     OP_RETURN bytes / canonical text (#73, #74, #75): add a "frozen vector" test
     that loads a checked-in byte string and asserts equality. This is the canary
     that future refactors won't silently drift the wire format. Mirror the pattern
     bsv-mpc-core uses for its existing canonical encodings.

Discipline (from auto-memory):
  - No commit/push without user OK (show diff, wait for green light)
  - NO `cargo fmt` on lib.rs or crate roots — cascades + main is CI-red on fmt;
    format edited files only; the enforced gate is clippy
  - Ask user for design decisions; don't guess on (a) vs (b) for #69 or on the
    ADR-0005 "approval" phase value for #74 or on the intent-classifier shape for #75
  - Validate, don't skip — assert negative cases on the right rejection reason
  - Verify inputs before escalating to "crypto divergence" — usually it's the inputs
  - Async-only — no meetings or scheduled syncs

Update PROGRESS-PERSON-A.md after each step (status + last action + blockers +
WHICH QUALITY GATES ARE GREEN). Mark an issue READY FOR PR only when all applicable
gates above are listed green with proof links.

The audit graph is at /Users/johncalhoun/bsv/mpc/graphify-out/graph.html — the graph
independently surfaced `combine_sign_over_relay (2-party)` ↔ `FfiDeployedSigner` as
the load-bearing seam (the exact #69 territory). The 4-agent audit reports live in
the issue bodies (#73, #74, #75) plus the audit-stamped comments on #69 and #70.

Tell me which issue you want to start with and propose the PR shape — including the
specific UNIT + VECTOR + E2E tests you'll write and which SPEC PR (if any) needs to
land first — BEFORE coding.
```
