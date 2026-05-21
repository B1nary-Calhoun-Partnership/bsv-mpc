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
- **#7 correctness audit: logged**, 4 bugs found+fixed, finding #5 (pool
  segregation) in progress.
- **MPC-Spec: UNTOUCHED** (Path-A; verified clean tree). No canonical spec
  changes. (Spec-relevant *additions* assessed below.)

## Deployed infra (Calhoun dev-a3e CF account)
- Worker (DO, share_A presig pool + light sign): `https://bsv-mpc-kss.dev-a3e.workers.dev` (version `801f92e6` — has authed `/sign-relay`).
- Native cosigner (CF Container, share_A heavy DKG/presig): `https://bsv-mpc-service-container.dev-a3e.workers.dev` (image `01e62ab4`, **instance_type `standard`** — lite/dev OOM on inline Paillier prime-gen; `MPC_WORKER_URL` baked, ephemeral auth).
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
4. **Relay backlog cross-contamination** — combiner took first party-0 partial on
   the shared `mpc-sign` box → stale/foreign partial → combine fails. **FIX CODED
   (uncommitted):** `bridge.rs::sign_over_relay` uses a fresh per-sign `SessionId`;
   `relay_sign.rs::combine_sign_over_relay` filters received envelopes by
   `from == do_index && session_id == this-sign` and drains the rest.
5. **DO presig pool not segregated by joint key** (IN PROGRESS) —
   `do_storage.rs` `mpc_presignatures` keyed by DO identity; `consume_presignature`
   pulls oldest across ALL joint keys → cross-key/run contamination. Also
   `store_presignature` uses caller `presig_id` as PK → dup-id INSERT 500s.
   **FIX PLAN:** key ingest + consume by the **joint-key agent_id** (thread it
   through proxy `provision_presig_to_do` + service `ProvisionConfig::ship_presignature`
   + `handle_ingest_presig` request + `handle_prod_sign_relay` consume); make
   `store_presignature` collision-safe. **Worker redeploy required.**

## In-flight / next steps (priority order)
1. **Commit the relay-session-filter fix** (#6 bug 4) — `relay_sign.rs` + `bridge.rs`
   coded; prove no single-sign regression (re-run `sign_relay_authed_deployed_e2e`).
2. **Pool segregation by joint key** (#7 finding 5) — code + worker redeploy.
3. **Re-run the latency benchmark** (`relay_sign_bench_e2e`, `RELAY_BENCH_E2E=1`)
   — needs segregation for clean K-sign runs. Report DO issue-partial RTT + K
   sequential relay co-sign latencies (proves bug-4 fix). First clean single-sign
   was **~2762 ms** end-to-end (dominated by per-sign BRC-103 relay handshake).
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
