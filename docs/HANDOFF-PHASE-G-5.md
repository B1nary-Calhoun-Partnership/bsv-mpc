# Handoff — Phase G Step 5 (merge gate) pickup

> For the next Claude session picking up Phase G at the merge-gate
> step. Read this + `docs/PHASE-G-AUDIT.md` §7 first; then plan the
> Phase E mainnet TXID re-run + wasm32 build verification.

## TL;DR — the next concrete action

**Phase G Step 5 — Quality gate** per `docs/PHASE-G-AUDIT.md` §7. Two
sub-tests + a merge-commit assertion:

1. **WASM build (free)** — `cargo build -p bsv-mpc-core --target
   wasm32-unknown-unknown`. Confirms the inline coordinators compile
   for `wasm32-unknown-unknown` end-to-end (the precondition for Phase
   I CF Worker deployment).

2. **Phase E mainnet TXID re-run (real sats)** — run
   `crates/bsv-mpc-service/tests/sign_mainnet_via_messagebox_e2e.rs`
   with `E2E_MAINNET=1`. Produces a fresh mainnet TXID. The merge gate
   requires: same DER signature shape + joint pubkey as Phase E's
   [`82ccb15c…`](https://whatsonchain.com/tx/82ccb15c49985a32b355a618f417bb7a09ec4ee5cf34e539e9baaebb74dadc29).
   New TXID is cited in the merge-gate commit message.

3. **New wasm32 2-of-2 DKG sim test** — `crates/bsv-mpc-core/tests/wasm32_dkg.rs`
   (new file). Runs a 2-of-2 DKG end-to-end on the wasm32 target via
   `wasm-bindgen-test`. Validates the runtime — not just the build —
   of the inline coordinator on WASM.

After all three pass, Phase G is merge-gate-green and the next phase
(Phase H — CF MessageBox client crate) can start.

## What's done as of this handoff

### Shipped on `bsv-mpc` main

| Commit | What |
|---|---|
| `c443dd8` G-2 | `docs/PHASE-G-AUDIT.md` (754 → 837 lines incl. §2.5 patch) |
| `8a85875` G-3 | `poc/poc16-sm-inline/` — 5 hard gates green, audit-doc G-3.3 correction |
| `f1b3947` G-4a | `crates/bsv-mpc-core/src/paillier_pool.rs` — 6 unit tests green |
| `bc9c1be` G-4b | dkg.rs inline rewrite (-316 LOC) — 12 dkg tests green |
| `cafb4c2` G-4c | signing.rs inline + shared `drive_inline` kernel (-261 LOC) — 18 signing tests green |
| `6ab583b` G-4d | presigning.rs inline (-229 LOC) — 7 presigning tests green |
| `a9a7e18` G-4e | `unsafe impl Send` on three coordinators — fixes downstream Send cascade |
| (this) G-doc | audit-doc §2.5 + handoff doc |

### Workspace status after G-4e

- `cargo clippy --workspace --all-targets -- -D warnings`: GREEN
- `cargo test --workspace --lib`: GREEN (all 161+ bsv-mpc-core + 34+ worker auth/storage tests)
- `cargo build --target wasm32-unknown-unknown -p bsv-mpc-core`: not yet verified post-G-4e (probably green; should test before G-5)
- CI on origin/main: should be GREEN after `a9a7e18` push (verify with `gh run list --branch main --limit 3`)

### Empirical findings recorded in audit doc

- **G-3.3 finding**: `cggmp24::aux_info_gen` is non-deterministic on
  RNG state — pool round-trip preserves *primes byte-for-byte*, not
  AuxInfo bytes. Audit doc §6.2 + §7.2 + §10 corrected in `8a85875`.
- **G-4e finding**: inline coordinators are `!Send`; downstream
  callers required Send. Audit doc §2.5 added in this commit. Resolved
  via `unsafe impl Send` on the three coordinator types.

### Locked decisions (do NOT re-litigate without explicit user redirect)

1. **Inline ownership over LocalSet** — `proceed()` is non-blocking;
   no spawn needed. Audit doc §2.
2. **`unsafe impl Send` over LocalSet topology** — pragmatic shortcut
   in G-4e; documented in audit §2.5. The god-tier alternative
   (LocalSet-per-session) is tracked as a Phase G post-merge cleanup
   or Phase I deployment-audit requirement.
3. **Inline `paillier_pool` with optional `.with_pool()` setter** —
   audit §3.3 + ADR-0041 §06.10.1.

## Q1-Q4 settled (per session 2026-05-19)

- Q1: Serial G → H
- Q2: LocalSet-only N/A (inline supersedes; see audit §2.5 §2)
- Q3: Per-identity Worker (Phase I)
- Q4: Fold Phase J into Phase I (CHIP + /capabilities + health.json)

## Open questions for the next session

| OQ from audit §8 | Default | Resolution |
|---|---|---|
| OQ1 pool optional via `.with_pool()` | yes | Implemented in G-4b |
| OQ2 reuse share.rs BRC-42 pattern | yes | Implemented in G-4a |
| OQ3 `Send + Sync` storage trait | yes | Implemented in G-4a |
| OQ4 eager backfill at startup | yes | Documented; `bsv-mpc-service` doesn't yet eagerly backfill — Phase I work |
| OQ5 path dep on bsv-mpc-core for POC | yes | Implemented in G-3 |

**New OQ6** surfaced in G-4e: replace `unsafe impl Send` with a
structural `SendShield<T>` wrapper? Default: defer to Phase I
deployment audit; `unsafe impl Send` is sound under the documented
invariant and all current callers honor it.

## Critical references in this order

1. **`docs/PHASE-G-AUDIT.md`** — design doc + §2.5 Send-shield finding
2. **`docs/NEXT-STEPS.md`** — phased v1.0 plan
3. **`poc/poc16-sm-inline/README.md`** — what the POC proved
4. **`crates/bsv-mpc-core/src/{dkg,signing,presigning,paillier_pool}.rs`**
   — the inline coordinator + pool source
5. **MPC-Spec `06-transport.md` §06.10.1**, **`decisions/0041-network-profile-latency-budgets.md`**
   — Paillier pool spec source

## Discipline lock (carried forward)

- Each step's commit lands on main BEFORE the next step begins
- `cd ~/bsv/mpc/bsv-mpc/` for commits (NEVER bsv-mpc-old-unscrubbed/)
- 110%-no-asterisks merge gate; mainnet TXID cited in the merge-gate commit
- Spec interop: implementation conforms to MPC-Spec, never the inverse
- god-tier + full-stack awareness — consult `~/bsv/` Rust + TS reference stack before proposing fixes; never recommend pragmatic-today / suppress / defer when a real fix is reachable

## What I am NOT doing in this handoff

- Running the wasm32 build test
- Running the Phase E mainnet TXID test (consumes sats)
- Writing the wasm32_dkg.rs test
- Building the SendShield<T> structural wrapper

Those are all G-5 work for the next session.

---

**Open MessageBox relay (live):** `https://rust-message-box.dev-a3e.workers.dev`
**Local wallet (mainnet sats source):** `http://localhost:3321` with `Origin: http://admin.com`
**Phase E reference TXID:** [`82ccb15c49985a32b355a618f417bb7a09ec4ee5cf34e539e9baaebb74dadc29`](https://whatsonchain.com/tx/82ccb15c49985a32b355a618f417bb7a09ec4ee5cf34e539e9baaebb74dadc29)
**Test command:** see `crates/bsv-mpc-service/tests/sign_mainnet_via_messagebox_e2e.rs` header doc-comment
