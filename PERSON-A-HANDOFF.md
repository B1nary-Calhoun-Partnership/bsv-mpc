# bsv-mpc — Person A Handoff (post-audit, 2026-05-28)

> For a NEW session to drive **Person A's** lane on the Calhoun-side BSV-MPC partnership.
> Person A owns the **load-bearing 4-of-6 seam + spec-level decisions**.
> Person B has the parallel lane (god-tier security hardening + 100cash Swift wiring) —
> see `/Users/johncalhoun/bsv/mpc/100cash/ROADMAP-HANDOFF.md` §"Post-audit work split".
> Repo: `B1nary-Calhoun-Partnership/bsv-mpc` (branch `main`), local at
> `/Users/johncalhoun/bsv/mpc/bsv-mpc/`. Created 2026-05-28.

---

## 🟢 Resume state — 2026-05-28 (read this first)

A 4-agent cross-repo coherence audit ran today. Findings:

- **4-of-6 status:** the crypto is proven (mainnet TXID `febd2877…`, PR #46). 100cash already
  threads `(t=4, n=6)` end-to-end. **But** `bsv-mpc-client/src/ffi.rs:756 create_wallet` →
  `provision::provision_wallet` (`native_io/provision.rs:42`) → `run_dkg_over_http_authed`
  (`bsv-mpc-relay/src/dkg.rs:159, 225`) is a **2-party** driver with `ShareIndex(1)`
  hardcoded. `FfiDeployedSigner.sign` calls the 2-party combine. **The n-party
  device-holds-(t-1) machinery lives only in `bsv-mpc-proxy`.** Filed as **bsv-mpc#69**
  (comment + two-approach analysis).
- **Spec drift:** 8 leak items + 6 spec gaps catalogued. Three filed as new issues
  (`#73 ParticipationProof placeholders`, `#74 approval envelope phase + exec_id`,
  `#75 canonical_render missing`).
- **Single load-bearing handoff:** Person A's `#75` → Person B's `100cash#15`. Everything
  else is parallel.

**Next actions** in priority order (your call which first):
1. **bsv-mpc#69** — pick approach (a) new `provision_wallet_nparty` seam in `bsv-mpc-client`
   vs (b) factor proxy's `DeviceShareBundle`/`DevicePresigSetPool` out. Ask user before
   coding — design choice has DRY-vs-complexity trade-off.
2. **bsv-mpc#70** — runs in parallel with #69 (deploy ops, not crypto code).
3. **bsv-mpc#75** — unblocks Person B's `100cash#15`. Spec-level: pick intent classifier
   shape + per-kind formatters from ADR-0044 §2. Then expose as `ffi_canonical_render`.
4. **bsv-mpc#74** — spec decision: add `"approval"` to ADR-0005 enum, or repurpose a
   field? Same neighborhood as #75.
5. **bsv-mpc#73** — `ParticipationProof.agent_identity` + `fee_txid` are placeholders in
   `bsv-mpc-core/src/signing.rs:1028-1047`. Thread caller-supplied identity keys OR patch
   in proxy. Same file as #69 — fold into that PR if natural.

Update **`PROGRESS-PERSON-A.md`** after each step.

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
