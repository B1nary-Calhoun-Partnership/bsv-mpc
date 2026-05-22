# Session progress — Phase I-6 productionization + #4 + audit (2026-05-21)

> Continuity doc (context-loss insurance). Single source of truth for the
> current push. Pairs with `docs/HANDOFF-PHASE-I-STEP4.md` (architecture) and
> GitHub `B1nary-Calhoun-Partnership/bsv-mpc` #6 (productionization), #7 (audit),
> #5 (hardening), #2 (umbrella). `main` is green at each commit below.

## TL;DR state
- **#6 createAction → mainnet gate: MET.** Canonical BRC-100 `CreateActionArgs`
  → proxy `/createAction` (relay mode) → deployed cosigner over authed relay →
  **real-sats TXID `6085f497bead622daac769f73c471f5adc26bb1b2334a22140664feb51f3f23b`**.
- **#4 provisioning automation: COMPLETE + fully deployed.** Self-stocking loop
  (DKG→presig→ship→relay-sign) proven BSV-valid with the **deployed CF Container**
  (share_A) ↔ **deployed DO** (presig pool) ↔ proxy combiner. No trusted dealer.
- **#7 correctness audit: logged**, 5 latent bugs fixed+proven; **finding #1
  (service owner-authz) CLOSED on deployed infra** — enforced CF Container,
  unauthed→401 live, full authed self-stocking BSV-valid (`455fc5c` `5d9a263`
  `afa2939` `55200da`). Residual hardening tracked in #8.
- **MPC-Spec: UNTOUCHED** (Path-A; verified clean tree). No canonical spec
  changes. (Spec-relevant *additions* assessed below.)

## Deployed infra (Calhoun dev-a3e CF account)
- Worker (DO, presig pool + light sign + #9 custody store): `https://bsv-mpc-kss.dev-a3e.workers.dev` (version `ff080f61` — authed `/sign-relay`, orphan-cleanup, `/custody/{put,get}-share`).
- Native cosigner (CF Container, share_A heavy DKG/presig): `https://bsv-mpc-service-container.dev-a3e.workers.dev` (version `89e52beb`, **instance_type `standard-1`**; `MPC_WORKER_URL` baked. **BRC-31 ENFORCED** — `MPC_SERVER_PRIVATE_KEY` via Worker secret → container `envVars`; unauthed→401 live. **#9 durable custody auto-enabled** — persists KEK-sealed share_A to the worker DO).
- Relay: `https://rust-message-box.dev-a3e.workers.dev`.

## Commits this session (all on `main`, all gated)
- `e8aa1df` #6 stable proxy identity (`BridgeAuth::from_share_seed`, §07.4).
- `3727def` authed production `/sign-relay` (owner-authz, pool-consume) — deployed-proven.
- `1b5c7ab` proxy pool holds full `PresignOutput` box (combiner needs public data).
- `dd8383c` createSignature/createAction → relay combiner (`MPC_RELAY_SIGN`).
- `1c3b4de` 🔒 #6 GATE — canonical createAction → mainnet TXID `6085f497…` + pre-flight verify in create_action_impl.
- `c9fe733` #4a `serialize_party_presignature` core helper.
- `c085427` #4b reusable transport-agnostic `bsv_mpc_core::brc31_client::Brc31Client`.
- `f312a23` #4c container ships `Presignature_A` to DO pool (`ProvisionConfig`).
- `9dbfc7e` #4d distributed DKG-over-HTTP driver (`run_dkg_over_http`).
- `b0dc1f3` #4 self-stocking loop (presign_url split + service `from_hex` fix).
- `1cbf4e8` #4e container self-stocking config (ephemeral auth, bake worker URL).
- `32889f7` 🔒 #4e FULLY-DEPLOYED self-stocking loop (joint `03b29053…`, BSV-valid).
- (+ handoff doc commits)

## Bugs found + fixed (the #7 audit seed)
1. DKG execution-id mismatch (proxy must adopt cosigner session id) — `9dbfc7e`.
2. Presig `from_str_hash(hex)` re-hash → eid mismatch; use `from_hex` — `b0dc1f3`.
3. Service DKG share keyed by session-hash not joint key — `b0dc1f3`.
4. ✅ **Relay backlog cross-contamination — FIXED+PROVEN** `b7db361`. Fresh
   per-sign `SessionId` + combiner filters §05 envelopes by
   `from==do_index && session_id==this-sign`, draining stale.
5. ✅ **DO presig pool segregation — FIXED+PROVEN** `b7db361`. Pool keyed by
   joint-key `agent_id` (threaded through proxy `provision_presig_to_do`, service
   `ProvisionConfig::ship_presignature` + presign_session→agent_id map, worker
   `handle_ingest_presig`/`handle_prod_sign_relay`), owner-authz on ingest (§08.1),
   `store_presignature` server-generates a collision-safe row id. **Worker
   redeployed `9f2075e1`.**

### #7 finding #1 — service owner-authz (§07.6 / §08.1) — `455fc5c`
The self-hosted `bsv-mpc-service` exposed `/dkg|/sign|/presign|/ecdh` with NO
auth (any caller could load `share_A`). NOT fund-loss (2-of-2), but a real
§07.6 + DoS + ECDH-partial-leak gap. **Enforcement landed + proven in-process:**
- `bsv-mpc-service/src/auth.rs` (new) — axum port of the worker's BRC-31
  verify + handshake, **wire-identical** to `bsv_mpc_core::brc31_client`
  (`Brc31Client` talks to it unchanged). `AuthState` in `AppState`; dev mode
  (no `MPC_SERVER_PRIVATE_KEY`) = `allow_unauthenticated` (existing flows
  unaffected). Storage gains `store_share_with_owner` / `get_share_owner`
  (empty-preserves). `/dkg/init` captures the caller → DKG-complete records
  `owner_identity`; `/sign|/presign|/ecdh` verify + reject non-owner (403)
  before touching share material. Proxy `run_dkg_over_http_authed` (authed DKG
  driver) for enforced cosigners.
- **Proof:** `service_owner_authz_e2e` (`SERVICE_AUTHZ_E2E=1`) — real
  in-process ENFORCED service, authed DKG binds owner, `/ecdh` unauthed→401 /
  stranger→403 / owner→200, sign+presign stranger→403. PASS (82s). No
  regression: `dkg_over_http_local_e2e` PASS; 17 svc + 149 proxy lib tests.
- **DEPLOYED enforcement = follow-on sub-gate** (NOT yet on the deployed
  container): needs (a) proxy **multi-server BRC-31** — it holds ONE
  `BridgeAuth` session with the DO (`kss_url`); `presign_raw`/`ecdh` hit the
  container (`presign_url`) reusing it → would 401 against an enforced
  container (DKG path already done); (b) redeploy container with
  `MPC_SERVER_PRIVATE_KEY` + re-prove self-stocking. New code w/o the env key
  = behavior-byte-identical (dev mode).

**Regression proof (4+5):** `relay_sign_bench_e2e` (`RELAY_BENCH_E2E=1 BENCH_K=5`)
— **5 SEQUENTIAL relay co-signs, all BSV-valid** (pre-fix, sign #2 died). Plus
`sign_relay_authed_deployed_e2e` green on the segregated pool.

**LATENCY (deployed DO + live relay):** DO issue-partial (wasm online-sign
compute + HTTPS) **median 26ms** (min 22, max 92); end-to-end relay co-sign
**median 2252ms** (per-sign BRC-103 handshake dominates — warm conn → sub-100ms);
authed presig provision median 57ms.

## Deployed versions (current)
Worker DO `9f2075e1` (segregated pool + authed /sign-relay). CF Container
`01e62ab4` (standard instance, self-stocking). Relay `rust-message-box`.

## 2026-05-21 continuation — audit closure + conformance + fund-safety
- **#7 audit: findings #1–#4 all CLOSED + deployed-proven.** #1 service+proxy+deployed
  BRC-31 owner-authz (§07.6/§08.1); #2 `/poc/sign-relay` consume isolation;
  #3 orphaned-coordinator cleanup; #4 `/presign/init` session-id hard-error.
- **§03 BRC-42 conformance harness** (`ddd5b3a`) + **canonical MPC-Spec fix**
  (`MPC-Spec 4891cbe`, Mitch-authorized): the spec's §03.5.2/§03.5.3 stress
  vectors (unicode protocol, empty key_id) were over-permissive vs the canonical
  @bsv SDK `computeInvoiceNumber`; corrected to rejection cases. bsv-mpc conforms
  (10 derivation byte-for-byte + 6 validation vectors). Filed MPC-Spec #37
  (rust-mpc `build_invoice_number` must add the same validation). Issue #8 tracks
  the residual BRC-31-profile asterisks.
- **#9 fund-safety — durable share custody (KEK-wrapped, all-Cloudflare).**
  Deployed cosigner held `share_A` in-memory-only (lost on restart → fund-lock).
  Fix: core `custody.rs` seals (share+owner) under a KEK from
  `MPC_SERVER_PRIVATE_KEY`; worker DO `mpc_custody` table + authed
  `/custody/{put,get}-share`; service persists at DKG-complete (fail-closed) +
  lazily recovers on cold-cache miss before the owner check. **Restart-survival
  PROVEN** against the deployed worker (`custody_restart_survival_e2e`): drop
  service A → fresh B recovers `share_A` → valid partial; stranger→403,
  unauthed→401. **DEPLOYED + CLOSED:** worker `ff080f61` (custody endpoints),
  container `89e52beb` (custody auto-enabled). Deployed self-stocking with
  custody ON → authed DKG completes (DKG-complete custody-put succeeded
  fail-closed) → presig→ship→relay-sign → BSV-valid 2-of-2 (467s).

## Hardening + follow-ons (this segment)
- **#8 hardening:** deploy smoke-test (`b28a856`, live: worker+container healthy +
  unauthed→401 on all funded-boundary/custody routes); round-handler
  defense-in-depth BRC-31 auth on the service (`6ec6890`, proven). **Body-binding
  (`SHA-256(nonce‖body)`) — DESIGNED + fully specced in #8**, scheduled as a
  dedicated cycle (breaking auth-substrate change; §07 permits the nonce profile;
  TLS-covered — not rushed).
- **#9 follow-ons:** MPC-Spec **§16.6.4** mandates durable encrypted custody for
  ephemeral-compute cosigners (`MPC-Spec 1c7682e`); **§18.9 presig-invalidation
  primitive** `delete_presignatures_for_agent` across all pools (`7eb0bc2`,
  unit-proven).
- **#12 audit residual:** concurrency-stress PROVEN (`880eff6` —
  `concurrency_stress_e2e`: 3 parallel ceremonies, distinct keys, owner-gated,
  no corruption/deadlock); replay gap (§07.1 per-request nonce not consumed)
  documented + folded into #8. Closed #12.
- **Issue hygiene:** closed done issues #6/#7/#9/#12; stale auth-TODOs cleared;
  CLAUDE.md version + status table refreshed (`b12c75f`).
- **Open tickets (nothing forgotten):** **#10** distributed-refresh (SCOPE-
  CORRECTED — multi-round PSS + atomic commit + §18 wire spec + Binary coord;
  fund-critical, not rushed); **#11** §06/§09/§18 conformance (§06 deferred on
  Ishaan); **#8** auth-hardening cycle (body-binding + replay-nonce, dedicated);
  **#13** OQ-I1 (blocks on relay HD-key); **#5/#2** umbrellas; **MPC-Spec #37**
  rust-mpc invoice validation. The clean SOLO-buildable high-value backlog is
  now exhausted — remaining work is blocked (Ishaan), cross-impl/spec-first
  (#10), or a dedicated auth-substrate cycle (#8).

## In-flight / next steps (priority order)
0. ✅ **#7 finding #1 DEPLOYED enforcement — DONE.** Proxy multi-server BRC-31
   (`presign_auth` session vs `presign_url`, `MPC_PROXY_IDENTITY_KEY` pre-DKG
   identity) + container redeployed with `MPC_SERVER_PRIVATE_KEY` (Worker
   secret → `envVars`). Live: unauthed→401; full authed self-stocking
   BSV-valid (449s). Residual hardening → #8.
0b. ✅ **#7 finding #3 — orphaned-coordinator cleanup (task #11) DONE** (`ef9db58`).
   Worker + service round handlers remove the live coordinator on a
   mid-ceremony `process_round` error (was: only on completion). Proof:
   `orphan_cleanup_e2e` (500 → retry 404). Worker change deploy-pending.
1. **#7 audit sweep — REMAINING classes** (highest-confidence "no hidden shit"):
   concurrency (two ceremonies on the same DO/pool/relay identity), leftover/
   orphaned state (failed ceremonies → stale presigs/coordinators/sessions; TTL/
   cleanup — task #11), idempotency/replay beyond presig PK. Each finding → a
   regression test reproducing the exposing condition.
2. **Warm relay connection** — the ~2.3s → sub-100ms online-sign win (pool the
   BRC-103 session instead of a fresh handshake per sign).
3. **Background Paillier prime pool** (#5 speed) — `core::paillier_pool` ready;
   wire into `bsv-mpc-service::handle_dkg_init` via `with_pool` + startup backfill
   → fast deployed DKG (presig does NOT use pooled primes).
4. **Retire legacy HTTP sign path (#6, OQ-I1)** — SAFE partial only: relay is
   default; KEEP `bridge.rs::sign` strictly as the HD-derived-key (`hmac_offset`)
   path (relay is base-key only — a full delete would BREAK HD-key createSignature).
   Full retirement blocks on relay-mode HD-key support (offset-baked presigs).
5. **Background Paillier prime pool** (#5 speed) — `core::paillier_pool` is
   production-ready; wire into `bsv-mpc-service` `handle_dkg_init` via `with_pool`
   + a startup backfill task → deployed DKG fast (presig does NOT use pooled
   primes, per audit). Cuts the ~6 min deployed DKG.

## Test harnesses (gated, `cargo test -p bsv-mpc-proxy --test <name> --release`)
- `createaction_relay_mainnet_e2e` (`E2E_MAINNET=1`) — #6 gate, real sats.
- `self_stocking_loop_e2e` (`SELF_STOCKING_E2E=1`, `DEPLOYED_CONTAINER_URL=…` for 4e).
- `provision_via_service_deployed_e2e` (`PROVISION_SVC_E2E=1`) — #4c.
- `dkg_over_http_local_e2e` (`DKG_HTTP_E2E=1`) — #4d distributed DKG.
- `sign_relay_authed_deployed_e2e` (`SIGN_RELAY_AUTHED_E2E=1`) — authed relay.
- `service_owner_authz_e2e` (`SERVICE_AUTHZ_E2E=1`) — #7 finding #1; in-process
  ENFORCED service, authed DKG → owner-gate (unauthed 401 / stranger 403 / owner 200).
- `proxy_enforced_cosigner_e2e` (`PROXY_ENFORCED_E2E=1`) — #7 finding #1 proxy
  side; 2 in-process ENFORCED services, proxy authed-presig vs enforced container.
- `self_stocking_loop_e2e` w/ `MPC_PROXY_IDENTITY_KEY` + `DEPLOYED_CONTAINER_URL`
  — full authed self-stocking vs the ENFORCED deployed container (BSV-valid).
- `relay_sign_bench_e2e` (`RELAY_BENCH_E2E=1`, `BENCH_K=5`) — latency.
- `i5_real_sats_deployed_e2e` / `relay_combine_deployed_e2e` — earlier gates.

## MPC-Spec impact (Path-A)
No changes to `~/bsv/mpc/MPC-Spec/` (verified clean). Spec-relevant *additions*
this work surfaces (propose separately, with Binary review — do NOT mutate
canonical unilaterally): (a) the per-sign **session-id correlation** on relay
sign envelopes (§05/§06 — needed for shared-box isolation); (b) the
**presig-pool-by-joint-key** keying (§ provisioning); (c) the authed
`/sign-relay` + `/ceremony/ingest-presig` routes (§07.5 op table). These are
implementation hardening consistent with the spec's intent, not wire-breaking.

## Discipline (carry forward)
110% no asterisks — runtime/deployed/BSV-verify proof per change. Never assume a
5xx is transient (a transient corruption is worse). Each #7 finding gets a
regression test reproducing the exposing condition. `gh auth switch -u Calgooon`
to push. Worker deploy: `eval "$(grep '^export CLOUDFLARE' secrets.md)"` then
`cd crates/bsv-mpc-worker && wrangler deploy`. Container deploy: use
`CLOUDFLARE_CONTAINERS_TOKEN` as `CLOUDFLARE_API_TOKEN`, `cd poc/cf-container-p2
&& wrangler deploy`. secrets.md gitignored — redact `[a-f0-9]{16,}`.

## 2026-05-21 (cont.) — Step 0 hygiene CLOSED + #8 reframed to canonical convergence + canonical-crate bug FIXED

- **Step 0 hygiene — DONE + pushed (`51b0a42..420adcd`).** Green baseline (482
  tests/50 suites, clippy `-D warnings`, wasm32 worker build); `STATUS.md`
  refreshed; `TESTING.md` gained the live gated-e2e inventory; 12 closed Phase
  G/H docs (+ stale `NEXT-STEPS`) archived to `docs/archive/`; stale branch
  `feat/canonical-wire-mpc-spec-3` deleted (local+origin+pruned); deploy
  smoke-test PASS (worker+container healthy + unauthed→401 enforcing).
- **#8 reframed (decided + recorded):** the auth-hardening is a **convergence
  onto the canonical BSV middleware**, not a patch to the custom "simplified"
  profile (spec §07.2 SHOULD). Layers: clients→`bsv_rs::auth::Peer` (already
  wasm32-proven in `bsv-mpc-messagebox`); worker→`bsv-middleware-cloudflare`
  (canonical-correct, prod-proven); native service→`bsv-middleware-rs`. All
  resolve `bsv-rs 0.3.11`; both middleware crates published on crates.io.
  Earlier "Peer wasm32 = 2-3 wk port" claim was REFUTED by direct verification.
- **🐛 FUND-CRITICAL canonical bug found + fixed.** A §07 interop probe
  (canonical-client signature → `bsv-middleware-rs` verify) PROVED a real
  `bsv_rs::auth::Peer` client could NOT authenticate to a `bsv-middleware-rs`
  server. Root cause (vs `Peer` peer.rs:582-642 + `bsv-middleware-cloudflare`):
  divergent key_id (static session nonces vs `AuthMessage::get_key_id`
  per-message), `SecurityLevel::App` vs `Counterparty`, `for_self: true` vs
  `None`. **Fixed in `Calhooon/bsv-middleware-rs` branch
  `fix/brc31-general-message-canonical-wire` (`61e1f49`)** + regression test
  `canonical_peer_client_general_message_verifies`; 15/15 green, fmt-clean,
  runtime-proven (bsv-rs 0.3.11). Lesson: bsv-rs key derivation base64-decodes
  keyID nonce tokens → nonces MUST be real base64.
- **GATED next action:** publish `bsv-middleware-rs` (bug-fix bump) — outward/
  irreversible, needs maintainer OK. Until then Phase B consumes the fix via a
  git rev on the public Calhooon repo. Then Phase B (service/worker/client
  migration, in-process proof) → C (lockstep redeploy + re-prove all authed e2e
  + real-sats) → D (MPC-Spec §07.10 + THREAT-MODEL scrub + author
  `07-brc31-auth.json` + close #8). Full detail in issue #8 comments.

## 2026-05-21 (cont.) — #8 canonical BRC-31 migration COMPLETE + on-chain proven
Phases A→C done; the whole proxy/service/worker auth stack now speaks the
canonical @bsv BRC-31 wire, deployed, with a real mainnet spend.

- **Phase B (merged `b27ed91`):** proxy→`bsv_rs::auth::Peer` wire; service→
  `bsv-middleware-rs`; worker→`bsv-middleware-cloudflare` (DO-SQLite SessionStorage).
  Owner-authz preserved; §07.1 replay + §07 identity-binding added. In-process gates
  green (service_owner_authz, proxy_enforced, conformance_07).
- **Canonical-crate bugs found+fixed (Calhooon, we maintain):** (1) `bsv-middleware-rs`
  key_id/SecurityLevel/`for_self` (`61e1f49`); (2) `bsv-middleware-rs` BRC-104 payload
  encoding — leading `0x00`, `varint(0)` vs `-1` empties, unsorted headers — now reuses
  canonical `bsv-rs HttpRequest::to_payload` (`57a0b8b`, `bsv-mpc 1ea8d48`); (3)
  `bsv-middleware-cloudflare` pluggable `SessionStorage` (`96efe6f`). Each runtime-proven
  against `bsv-rs` ground truth.
- **Phase C deployed (lockstep):** worker `8573b420`, container `8b11e16f` — CPU fix
  `standard-1`→`standard-4` (½→4 vCPU; Paillier DKG was blowing the timeout) + `sleepAfter`
  30m + observability. proxy `/sign-relay` canonical auth wired (`679940a`; leg-1 had
  deferred it). `deploy_smoke` pass; `self_stocking_loop` full loop → BSV-valid 2-of-2.
- **🔗 REAL-SATS GATE (Phase C end-proof):** `createaction_relay_mainnet_e2e` →
  **mainnet TXID `96c2ebc592c77bab2fc3fba47993bc6638ec248c7f90caf68ba7fddb3cdabcfd`**
  (createAction via the deployed `bsv-mpc-worker` DO over the authed canonical relay;
  joint `1LkbL2a7g679uCGZRQ6ZBysckQxG6MrzBV`; confirmed on WhatsOnChain).
- **Phase D (remaining):** publish `bsv-middleware-rs`/`bsv-middleware-cloudflare` (swap
  git-rev→version); worker invalid-sig→500-not-401 mapping fix; MPC-Spec §07.10/§07.1 +
  THREAT-MODEL A4/A7 scrub + author `07-brc31-auth.json`; then close #8.
