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
- Worker (DO, share_A presig pool + light sign): `https://bsv-mpc-kss.dev-a3e.workers.dev` (version `801f92e6` — has authed `/sign-relay`).
- Native cosigner (CF Container, share_A heavy DKG/presig): `https://bsv-mpc-service-container.dev-a3e.workers.dev` (version `f445893e`, **instance_type `standard-1`**; `MPC_WORKER_URL` baked. **BRC-31 ENFORCED** — `MPC_SERVER_PRIVATE_KEY` wired via Worker secret → container `envVars`; unauthed→401 live).
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

## In-flight / next steps (priority order)
0. ✅ **#7 finding #1 DEPLOYED enforcement — DONE.** Proxy multi-server BRC-31
   (`presign_auth` session vs `presign_url`, `MPC_PROXY_IDENTITY_KEY` pre-DKG
   identity) + container redeployed with `MPC_SERVER_PRIVATE_KEY` (Worker
   secret → `envVars`). Live: unauthed→401; full authed self-stocking
   BSV-valid (449s). Residual hardening → #8.
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
