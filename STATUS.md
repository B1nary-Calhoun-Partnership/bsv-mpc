# bsv-mpc — Project Status

> What's done, what's open, what's next.
> Updated: 2026-05-23

This file is the short / scannable view. The **authoritative trackers** are:

- [**docs/SESSION-PROGRESS-2026-05-21.md**](docs/SESSION-PROGRESS-2026-05-21.md) — full ledger: commits, deployed versions, bugs found+fixed, latency.
- [**docs/HANDOFF-2026-05-21-CONTINUATION.md**](docs/HANDOFF-2026-05-21-CONTINUATION.md) — next-session plan (Calhoun-solo, non-blocked work).
- [**LESSONS.md**](LESSONS.md) — POC + implementation findings.
- GitHub `B1nary-Calhoun-Partnership/bsv-mpc` issues (see open-issues table below).

Older phase docs (Phase A–H) are archived in [`docs/archive/`](docs/archive/).

---

## Where the project is

The CF-native 2-of-2 cosigner is **built, deployed, and mainnet-proven**. A
canonical BRC-100 `CreateActionArgs` flows proxy → deployed cosigner over an
authed relay and lands a **real-sats mainnet TX**
([`6085f497…`](https://whatsonchain.com/tx/6085f497bead622daac769f73c471f5adc26bb1b2334a22140664feb51f3f23b)).
Self-stocking provisioning (DKG → presig → ship → relay-sign) runs end-to-end
against deployed infra with no trusted dealer, and KEK-sealed durable share
custody survives cosigner restart. MPC-Spec is canonical (Path-A); `main` is
green at every commit (fmt, clippy `-D warnings`, native test, wasm32 build).

### Deployed infra (Calhoun dev-a3e CF account)

| Component | URL | Version | Notes |
|---|---|---|---|
| Worker (DO) | `bsv-mpc-kss.dev-a3e.workers.dev` | `ff080f61` | authed `/sign-relay`, orphan-cleanup, `/custody/{put,get}-share`, presig pool, DO-SQLite |
| Container (cosigner, share_A) | `bsv-mpc-service-container.dev-a3e.workers.dev` | `b804dbfd` (`standard-4`) | BRC-31 ENFORCED + #9 durable custody + #35 cross-(t,n) reshare-relay; **#13: legacy `/sign/{init,round}` removed (relay-only)** |
| Relay | `rust-message-box.dev-a3e.workers.dev` | — | MessageBox / Socket.IO + BRC-103 |

After **any** deploy, run the smoke-test:
`DEPLOY_SMOKE=1 cargo test -p bsv-mpc-proxy --test deploy_smoke_e2e --release`
(asserts deployed health + unauthed→401 on funded-boundary/custody routes).

---

## Issue tracker (B1nary-Calhoun-Partnership/bsv-mpc)

### Closed (delivered + proven)

| # | Scope | Proof |
|---|---|---|
| #4 | Provisioning automation (self-stocking, no dealer) | deployed self-stocking BSV-valid 2-of-2 |
| #6 | createAction → mainnet | real-sats TXID `6085f497…` |
| #7 | Correctness audit (5 latent bugs + findings 1–4) | each finding → regression test, deployed-proven |
| #9 | Fund-safety: KEK-sealed durable share custody | restart-survival proven vs deployed worker |
| #12 | Concurrency-stress | parallel ceremonies, distinct keys, no corruption |
| #35 | Cross-(t,n) address-preserving reshape (2-of-2 → 2-of-3), DEPLOYED + mainnet | spend TXID [`5137b913…`](https://whatsonchain.com/tx/5137b913a80fb4d05d188aa51533f3f0b6c8e3305c22d8b3fe335fb587bd6a0c) under reshared shares; joint pubkey unchanged. Phase-A late-prime ordering fix on container + proxy. |
| #13 | Retire legacy 4-round HTTP sign path (relay-only) | Deleted `bridge.sign` ↔ KSS `/sign/{init,round}` (proxy+service+worker; routes/handlers/wire-types); `createSignature`/`createAction` relay-only, **no 4-round fallback** (provisioning is the mitigation; relay-empty → clear error). NEW multi-input createAction-over-relay TXID [`14c8189f…`](https://whatsonchain.com/tx/14c8189f2b31397101e9a66c36ec34b40ec0a685be7d0c0b82944d4d6fc05722) (≥2 vin, WoC-confirmed). Slimmed container redeployed (`/sign/init`→404) + base-key relay sign re-proven TXID [`793938e3…`](https://whatsonchain.com/tx/793938e3d23a634a865cb8a57fb320818ccec50811f951fccd4a0200723d9073). `SigningCoordinator::sign`/`init_round` retained (still used by `signing_handler` MessageBox sign). conformance_07/07b untouched. |
| #38 | §1 device-holds-(t−1): N-party relay sign (4-of-6, device drives 3 local parties + 1 external cosigner) | God-tier track. Orchestration only — NO new crypto, NO KSS change/redeploy. New `add_local_presig_partial` (core), `combine_sign_over_relay_nparty` (relay), `DeviceShareBundle`/`sign_over_relay_device_holds` (bridge), `DevicePresigSetPool` + device-holds `relay_sign` branch (proxy) → 4-of-6 flows through `/createSignature` + `/createAction`. Real-sats mainnet 4-of-6 spend TXID [`febd2877…`](https://whatsonchain.com/tx/febd287740f603af2cac5e4d73ce7face236fed8e2e3e592f38f7fc6e9552d89) (joint `026b712a…`), WoC-confirmed. Hermetic proof `poc_4of6_device_holds_presig_relay` (base→joint, offset→child, device-alone rejected). |

### Open

| # | Scope | State / blocker |
|---|---|---|
| #8 | Auth-hardening cycle (body-binding + replay-nonce) | **next solo build** — breaking auth-substrate change; lockstep redeploy + re-prove all authed e2e + MPC-Spec §07. Consider migrating KSS profile to `bsv-rs::auth::Peer`. |
| #5 | Production-hardening umbrella | smaller solo items: worker rate-limiting, `/poc/*` retirement, wrangler.toml VC, wasm latency benchmark |
| #2 | v1.0 CF-native cosigner umbrella | tracks the above |
| #10 | Distributed key-refresh | **blocked** — fund-critical multi-round PSS + atomic commit; needs §18 wire spec + Binary coordination |
| #11 | §06 / §09 / §18 conformance | **blocked** — §06 on Ishaan byte-locking `06-presig-bundle-encryption.json` (MPC-Spec #9) |

Related: **MPC-Spec #37** (rust-mpc `build_invoice_number` must add the §03
invoice-number validation the canonical fix introduced).

---

## Conformance status (MPC-Spec, canonical)

| Vector | Test | State |
|---|---|---|
| §02 ExecutionId | `conformance_02_execution_id.rs` | PASS |
| §03 BRC-42 invoice | `conformance_03_brc42_invoice.rs` | PASS (10 derivation + 6 validation; canonical fix `MPC-Spec 4891cbe`) |
| §04 SessionId | `conformance_04_session_id.rs` | PASS |
| §05 MessageEnvelope | `conformance_05_message_envelope.rs` | PASS |
| §06 presig-bundle encryption | — | blocked on Ishaan byte-lock (#11) |

---

## Known follow-ups deferred

| Item | Source | Why deferred |
|---|---|---|
| Replace `unsafe impl Send` with structural `SendShield<T>` | audit §2.5 OQ6 | Sound today under documented serialization invariant; revisit in deployment audit. |
| Eager startup backfill of `paillier_pool` in `bsv-mpc-service` | audit OQ4 | Speed win for deployed DKG; not gate-path. Tracked in #5. |
| SQLite persistence backend for `bsv-mpc-service` | CLAUDE.md | In-memory today; durable custody (#9) covers fund-safety. |
| Overlay proof publication (`publish_proof`, `query_proofs`, `count_proofs_by_node`) | CLAUDE.md | Not on critical path. |
| Warm relay connection (pool BRC-103 session) | SESSION-PROGRESS | ~2.3s → sub-100ms online-sign win; tracked in #5. |
