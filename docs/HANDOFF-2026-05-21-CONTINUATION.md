# HANDOFF — 2026-05-21 continuation (next-session, Calhoun-solo work)

> Start here next session. Pairs with the authoritative
> [`SESSION-PROGRESS-2026-05-21.md`](SESSION-PROGRESS-2026-05-21.md) (full ledger,
> commits, deployed versions). This doc = **what to do next that does NOT depend
> on Ishaan or Mitch.** `cd ~/bsv/mpc/bsv-mpc/` for all work (NEVER
> `bsv-mpc-old-unscrubbed/` — shell cwd resets there; prefix every cmd with
> `cd ~/bsv/mpc/bsv-mpc/ &&`). `gh auth switch -u Calgooon` to push.

## State (everything below is on `main`, green, deployed-proven)
- **#7 audit CLOSED** (findings 1–4 + concurrency + idempotency-assessed). Replay
  gap (§07.1) folded into #8.
- **#9 fund-safety CLOSED** — KEK-sealed durable share custody; deployed
  (worker `ff080f61`, container `89e52beb`); restart-survival + deployed
  self-stocking-with-custody both BSV-valid.
- **§03 BRC-42 conformance** + canonical MPC-Spec fix (`4891cbe`) + §16.6.4
  custody mandate (`1c7682e`).
- **#8 partial:** deploy smoke-test + round-handler auth DONE; body-binding +
  replay scheduled (see below).
- Closed issues: #4 #6 #7 #9 #12. Repo clean, CI green (fmt/clippy/test/wasm).

## Deployed infra (Calhoun dev-a3e CF account)
- Worker DO `ff080f61`: `https://bsv-mpc-kss.dev-a3e.workers.dev` — authed
  `/sign-relay`, orphan-cleanup, `/custody/{put,get}-share`, presig pool, DO-SQLite.
- Container `89e52beb` (`standard-1`): `https://bsv-mpc-service-container.dev-a3e.workers.dev`
  — BRC-31 ENFORCED + #9 durable custody auto-enabled.
- Relay: `https://rust-message-box.dev-a3e.workers.dev`.
- Deploy: worker → `eval "$(grep '^export CLOUDFLARE' secrets.md)" && cd crates/bsv-mpc-worker && npx wrangler deploy`.
  Container → `CLOUDFLARE_API_TOKEN=$CLOUDFLARE_CONTAINERS_TOKEN`, `cd poc/cf-container-p2 && npx wrangler deploy` (slow Docker rebuild).
  **After ANY deploy: run the smoke-test** `DEPLOY_SMOKE=1 cargo test -p bsv-mpc-proxy --test deploy_smoke_e2e --release` (unauthed→401 guard).
- secrets.md (gitignored): `MPC_SERVER_PRIVATE_KEY` (container secret + KEK root),
  `MPC_PROXY_IDENTITY_KEY` (owner identity for authed DKG e2es), CLOUDFLARE tokens.
  NEVER commit; redact `[a-f0-9]{16,}` + `cfut_…` in output.

## DO NEXT (no Ishaan/Mitch dependency) — priority order

### 0. Hygiene first (quick — clear the decks before building)
Each is a small, low-risk commit; do them up front:
- Refresh `STATUS.md` (stale 2026-05-19, points at Phase-G refs) → supersede
  with this handoff + `SESSION-PROGRESS-2026-05-21.md` as the authoritative
  trackers; list current open issues (#13, #11, #10, #8, #5, #2).
- Add the gated-e2e inventory (see bottom of this doc) to `TESTING.md`.
- Archive superseded docs → `git mv` into `docs/archive/`: HANDOFF-PHASE-{G-5,
  H-3,H-3-3B,H-4-3}, HANDOFF-2026-05-19, H-3-5-*, H-STEP-4-*, PHASE-{G,H}-AUDIT
  (Phase G/H are closed). Keep Phase-I + current docs.
- Confirm + delete stale branch `feat/canonical-wire-mpc-spec-3` (canonical work
  landed on main — `conformance_02/04/05` prove it) — local + `origin`.
- Verify green baseline: `cargo test --workspace` + `cargo clippy --workspace
  --all-targets -- -D warnings` + `cargo build -p bsv-mpc-worker --target
  wasm32-unknown-unknown`.
- (Optional) add a `cargo deny check` job to `.github/workflows/ci.yml`.
- After: re-run `DEPLOY_SMOKE=1 …deploy_smoke_e2e` to confirm deployed infra
  still healthy + enforcing.

### 1. #8 auth-hardening cycle — the one substantive solo build
Body-binding + replay-protection, done as ONE deliberate cycle (both are
auth-substrate changes → one lockstep redeploy + one re-prove). Full plan in
issue **#8** comments. Two sub-items:
- **Body-binding:** sign `SHA-256(nonce ‖ body_bytes)` (client signs the exact
  bytes it sends; both servers hash the exact bytes received — beware the
  body-consumed-once refactor: worker reads body at dispatch, axum service
  switches `Json<T>`→`Bytes`+manual parse).
- **Replay:** track consumed per-request nonces per session (bounded set, TTL
  evict); reject reuse.
- **Strongly consider** migrating the KSS profile to canonical `bsv-rs::auth::Peer`
  (already payload-binds + tracks message state → covers BOTH) instead of
  bolting onto the custom simplified profile. Decide first.
- BREAKING wire change: lockstep redeploy worker+container; re-prove EVERY authed
  e2e (self_stocking, sign_relay_authed, custody_restart, service_owner_authz,
  proxy_enforced, deploy_smoke). Update MPC-Spec §07 to document the hardened
  profile. **Do NOT rush** — silent total-auth-break on any byte mismatch.

### 2. #5 production-hardening items (smaller, solo)
Rate-limiting on the worker; `/poc/*` route retirement (keep what deployed
proofs need — see #13); wrangler.toml version-control; wasm latency benchmark.
Triage in issue **#5**.

### 3. Optional: deny.toml audit job in CI
`.github/workflows/ci.yml` lacks a `cargo deny check` job (low-risk, catches
license/advisory drift). Add with an install step.

## DO NOT pick up (blocked / needs others)
- **#10** distributed key-refresh — fund-critical multi-round PSS + atomic
  commit + **needs a §18 wire spec + Binary coordination** (cross-impl). §18.9
  invalidation primitive + atomic custody overwrite already built; the protocol
  is the work. Spec-first.
- **#11** §06 conformance — blocked on Ishaan byte-locking
  `06-presig-bundle-encryption.json` (MPC-Spec partnership #9).
- **#13** OQ-I1 (retire HTTP sign path) — blocks on relay-mode HD-key support.
- **M1 coordination / MPC-Spec #37 (rust-mpc) / ADR sign-offs** — needs
  Ishaan/Mitch. (M1 is AT RISK on Binary's side; Calhoun's M1 obligations are
  delivered.)

## Discipline (carry forward)
110% no-asterisks: every change gated (fmt --check + clippy --workspace
--all-targets -D warnings + wasm32 worker build + relevant unit/e2e), runtime/
deployed/BSV-verify proof — never "should work". Real-sats e2e via local wallet
`localhost:3321` (Origin `http://admin.com`), `E2E_MAINNET=1`, minimize sats.
Spec-first; MPC-Spec is canonical (conform consumer-side / Path A) — but Mitch
granted authority to FIX the spec where it diverged from the @bsv SDK (used for
§03). Each finding → a regression test. Land each sub-gate before the next.

## Gated e2e harnesses (env var → test)
`E2E_MAINNET` (mainnet createAction) · `DKG_HTTP_E2E` · `SELF_STOCKING_E2E`
(+`DEPLOYED_CONTAINER_URL`,`MPC_PROXY_IDENTITY_KEY` for authed deployed) ·
`SERVICE_AUTHZ_E2E` · `PROXY_ENFORCED_E2E` · `CUSTODY_E2E` · `CONCURRENCY_E2E` ·
`DEPLOY_SMOKE` · `SIGN_RELAY_AUTHED_E2E` · `SIGN_RELAY_E2E` · `RELAY_BENCH_E2E`.
Unit tests + ungated integration run on plain `cargo test`.
(Hygiene punch list = **Step 0** above.)
