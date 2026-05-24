# Handoff — god-tier wallet product track (post audit-sweep, 2026-05-24)

> **Read this first in a new session.** It hands off the god-tier consumer-wallet
> product track after the full 4-pillar **de-risking audit sweep is complete**.
> The strategic question ("is it realizable, what's left, can we go solo?") is
> answered: **YES — realizable, no new crypto, no invention, 100% Calhoun-solo.**
> What remains is the **big builds**. This doc tells the next session exactly where
> to start and how.

---

## 0. TL;DR

- The MPC **signing backend** is ~88% and the crypto **primitives all exist**.
- The **god-tier wallet** (north star: `~/bsv/mpc/direction.md`; gap analysis:
  `~/bsv/mpc/direction-audit.md`) is a separate **product** track, umbrella **#37**.
- **All 4 pillars audited + de-risked** this session; every conclusion is backed by
  a green gate or code read (not a spike's "we think"). See §2.
- **Start next with #38 — the N-party relay implement** (§4 of this doc). It's the
  foundation §43/#40/#41 all assume.
- Discipline bar (non-negotiable, set by the user): **110%, no asterisks. Re-run
  every gate yourself; never trust an agent's "passed." Prove done with green gates
  + a deployed mainnet TXID where the work is a signing path.**

---

## 1. How we got here (this session's arc)

1. Shipped **#13** (retire legacy 4-round HTTP sign path → relay-only; merged PR #36;
   mainnet TXIDs `14c8189f` multi-input + `793938e3` container).
2. Built a **strategy knowledge graph** of the whole corpus → `~/bsv/mpc/graphify-out/`
   (`graph.html`, `GRAPH_REPORT.md`, `graph.json`; 234 nodes / 10 communities).
3. Ran a realizability **spike**, then filed the god-tier issues (#37 umbrella, #38–#41),
   each **audit-gated** (`step:investigate` first — confirm conclusions before building).
4. **Completed the audit sweep** on all four pillars (§2). Split the §4 build to #43,
   filed zeroize as #44.

---

## 2. The audit verdict — all 4 pillars de-risked

| Pillar | Issue | Verdict (proof) | Remaining build |
|---|---|---|---|
| **§1** two mandatory sides (4-of-6, device holds t−1) | **#38** | **~200 LOC wiring, NO new crypto.** Hermetic POC merged (PR #42, `crates/bsv-mpc-core/tests/poc_4of6_device_holds_3.rs`, `#[ignore]`): 4-of-6 DKG → 6 shares/one joint key; device {0,1,2}+1 external signs+verifies under joint key; device-alone {0,1,2} (3<4) cryptographically rejected. `SigningCoordinator` already takes `participants: Vec<u16>` of any size. | N-party relay implement — see §4 |
| **§4** what-you-see-is-what-you-sign | **#39** (closed) → build **#43** | binding primitive **DONE + byte-locked** (`bsv-mpc-core/src/approval.rs`, `conformance_09` green; 8-field int-keyed preimage). Spec typo reconciled: **MPC-Spec PR #42** (§09.5.1 → 8-field). The shared conformance vector `conformance/test-vectors/09-rendered-text.json` is byte-identical across MPC-Spec ↔ bsv-mpc → cross-impl byte-identity guaranteed. | policy engine (port from rust-mpc) + approval flow + WebAuthn binding (**#43**) |
| **§3** recovery | **#40** | keystone **CLOSED by #35** — `ResharCoordinator` uses `party_reshare_contribution(&my_old_secret)` (single secret/party; secure multi-round PSS; all-shares `threshold_reshare` is test-only); `/reshare-relay/init` drives it; mainnet TXID `5137b913`. `rotate_on_commit` atomic. §18/Binary is **cross-impl only, NOT a v1 blocker**. | lost-phone ceremony + zeroize (#44) |
| **§2/§6** native client | **#41** | **realizable — implementation, not invention.** KEY: bsv-mpc has **zero dep on `bsv-wallet-toolbox-rs`** → the audit's "biggest lift" (wasm-split toolbox) is moot. wasm substrate mostly HAVE (core/worker/bsv-rs wasm-ready; `rust-wallet-infra` wasm-deployable storage backend; `rust-overlay` PARTIAL — 10-min workspace fix). | enclave wrap-key + WebAuthn-PRF + zeroize + JS/UniFFI bindings + shells |

**The one real product caveat (not a blocker):** cross-ecosystem (iOS↔Android) passkey
sync breaks Layer-1 recovery → falls to Layer-2 trustees. By design (§18 health model);
surface it in UX.

---

## 3. GitHub issue map

- **#37** — umbrella (god-tier product track). Carries the sweep summary + child statuses.
- **#38** — §1 device-holds-(t−1) 4-of-6. **DONE — N-party relay sign implemented +
  mainnet-proven.** Real-sats 4-of-6 `createAction` (proxy drove 3 local device
  parties `{0,1,2}` + 1 deployed cosigner party 3 over the relay), WoC-confirmed:
  spend TXID `febd2877…` (joint `026b712a…`). ZERO KSS change/redeploy. See §7.
- **#39** — §4 binding reconciliation. **Closed** (done; MPC-Spec#42).
- **#43** — §4 policy engine + approval flow + WebAuthn (split from #39). `step:investigate`
- **#40** — §3 recovery ceremony (keystone confirmed; ceremony build open). `step:implement`
- **#41** — §2/§6 native client (realizability confirmed; build open). `step:implement`
- **#44** — zeroize secret scalars (cross-cuts #40/#41/#5). `step:implement`
- Backend (separate track): **#2** v1.0 cosigner umbrella, **#5** production hardening.

---

## 4. ✅ DONE: #38 — relay sign path 2-party → N-party (device-holds-(t−1))

**Shipped + mainnet-proven (2026-05-24).** The foundation everything else assumes
is in place: the proxy drives `t−1` local device parties + one external cosigner
over the relay to produce a single `t`-of-`n` signature. Real-sats 4-of-6
`createAction` spend, WoC-confirmed: TXID `febd2877…`. See §7 for the full record.

> **The remaining god-tier builds now rest on this.** The strong next is **#43**
> (§4 policy engine + approval binding + WebAuthn) — now that the external side
> can co-sign a `t`-of-`n`, it must *enforce policy* before it does ("two
> mandatory sides" only matters if the external side actually checks something).
> Then **#40** (lost-phone recovery ceremony), **#41** (native client), **#44**
> (zeroize). See §8.

**What was built (the lift, from the #38 audit):**
1. **Provision t−1 shares to the device's storage.** DKG today stores one share to
   `share_path` (`crates/bsv-mpc-proxy/src/bridge.rs`, `MpcBridge::new` share-load). The
   device side must hold `{0,1,2}` (3 KeyShares) for 4-of-6.
2. **Generalize relay sign from 2-party → the N-party t-subset.** The t-subset selector
   already exists at `crates/bsv-mpc-proxy/src/bridge.rs:777-790` (the standing
   `TODO: For multi-KSS setups, allow configuring which parties to sign with`). The relay
   entry points run 2-party today and must drive the 4-party subset:
   - `bridge.rs::sign_over_relay` (~L2195), `relay_sign.rs::combine_sign_*_over_relay`,
     KSS `/sign-relay` (`bsv-mpc-service/src/relay_handlers.rs`, `bsv-mpc-worker/src/poc.rs::handle_prod_sign_relay`).
   - `SigningCoordinator` (`signing.rs`) already accepts any-size `participants` — **no core change.**
3. **Gate (110%):** real-sats **mainnet 4-of-6 spend** = proxy drives 3 local parties + 1
   deployed cosigner over the relay, WoC-confirmed. Mirror the #13 gates
   (`createaction_multi_input_relay_mainnet_e2e.rs`) for harness shape.

**Other big builds** (each its own focused session): **#43** policy engine (port rust-mpc's
policy crate → `mpc-policy-shared`; wire RequireApproval→approve()→sign; mainnet gate),
**#40** lost-phone ceremony (new device → reshare onto it → same address), **#41** client
(wasm BRC-100 + wasm-bindgen/UniFFI + enclave wrap + WebAuthn-PRF + shells), **#44** zeroize.

---

## 5. Proven artifacts (don't rebuild)

- **#13:** PR #36 merged; mainnet TXIDs `14c8189f…` (multi-input createAction over relay, ≥2 vin),
  `793938e3…` (slimmed container §06.17.1). All signing relay-only.
- **#38 keystone:** PR #42 merged; `poc_4of6_device_holds_3.rs` (run:
  `cargo test -p bsv-mpc-core --test poc_4of6_device_holds_3 -- --ignored --nocapture`, ~197s).
- **#38 implement:** N-party relay sign + mainnet 4-of-6 spend. Hermetic presigned
  proof `poc_4of6_device_holds_presig_relay.rs` (base→joint, offset→child, device-alone
  rejected). Mainnet gate `createaction_4of6_device_holds_relay_mainnet_e2e.rs`
  (`DEVICE_HOLDS_4OF6_MAINNET=1`). Spend TXID `febd2877…`, joint `026b712a…`.
- **#39:** MPC-Spec PR #42 merged (§09.5.1 8-field reconcile); `conformance_09` green.
- **#35:** reshare keystone, mainnet TXID `5137b913…`.

---

## 6. Resources & gotchas

- **Strategy graph:** `~/bsv/mpc/graphify-out/` (open `graph.html`; `graphify query "…"` for traversal).
  North star `direction.md`; gap analysis `direction-audit.md` (note: parts of it predate
  #13/#35/#39 — this handoff + the issue comments are more current).
- **On-disk repos:** `~/bsv/rust-wallet-infra` (wasm-deployable storage backend, CF Worker
  D1+R2), `~/bsv/rust-overlay` (discovery; workspace `tokio/full` breaks wasm — cherry-pick
  features), `~/bsv/bsv-rs` (wasm-feature-gated), `~/bsv/rust-mpc` (NOT local — source for the
  policy crate port; clone when starting #43).
- **Wallet funding gotcha (solved):** the wallet at `localhost:3321` returns txids but does
  **not** reliably broadcast and chains on unconfirmed change. Fund via: capture its BEEF →
  convert AtomicBEEF→**BEEF V1** (`Transaction::from_atomic_beef(b).to_beef_v1(false)`) →
  self-broadcast to ARC with the **TAAL Bearer token** (`mainnet_9596de07e92300c6287e4393594ae39c`)
  → **retry until `SEEN_ON_NETWORK`** (each retry = fresh coin selection toward a confirmed
  parent). The bare tokenless broadcaster 401s on TAAL. See `createaction_multi_input_relay_mainnet_e2e.rs`.
- **Deploy container:** `cd poc/cf-container-p2 && eval "$(grep '^export CLOUDFLARE' ~/bsv/mpc/bsv-mpc/secrets.md)" && npx wrangler deploy` (needs Docker daemon running; image build ~3min). Verify `GET /reshare-relay/identity` → 200.
- **Gates:** workspace `cargo test`; conformance_* (esp 07/07b/09); `cargo clippy -p bsv-mpc-core -p bsv-mpc-proxy -p bsv-mpc-service -p bsv-mpc-worker --all-targets -- -D warnings`; wasm: `cargo clippy/build -p bsv-mpc-worker --target wasm32-unknown-unknown`. `CARGO_INCREMENTAL=0` to keep the target dir from ballooning (disk filled mid-session once).
- **No commit/push/deploy without showing the diff + approval** on these partnership repos.
- **Memory:** `project_godtier_track`, `project_13_retire_legacy_sign`, `reference_wallet_3321_broadcast`, `project_38_nparty_device_holds` (in `~/.claude/projects/-Users-johncalhoun-bsv-mpc/memory/`).

---

## 7. #38 record — N-party device-holds relay sign (2026-05-24)

**What shipped (orchestration, NO new crypto, NO KSS change/redeploy):**
- **Core primitive** `SigningCoordinator::add_local_presig_partial` — issue an
  additional co-located party's partial in the presigned path (no broadcast;
  shared public data reused; §06.20 offset applied to the secret presig only).
- **N-party combiner** `relay_sign::combine_sign_over_relay_nparty` — primary +
  `t−1` local extras + ONE external cosigner over the relay. The 2-party
  `combine_sign_over_relay` now delegates to it (call sites untouched).
- **Multi-share bridge** — `DeviceShareBundle` share-file format (load `t−1`
  shares); `participants = device parties ∪ externals`; `sign_over_relay_device_holds`;
  `is_device_holds`/`device_party_indices`/`external_cosigner_index`.
- **Device presig-set pool** `DevicePresigSetPool` (FIFO of correlated sets) +
  `relay_sign` device-holds branch → 4-of-6 flows through BOTH `/createSignature`
  and `/createAction` (per-input loop unchanged).
- **KSS is generic** — `handle_prod_sign_relay` issues one party's partial from
  `from_index`, agnostic to party count; `authz_owner_or_reject` allows a fresh
  joint key. No worker change, no redeploy.

**Proof:** hermetic `poc_4of6_device_holds_presig_relay` (base→joint, offset→child,
device-alone {0,1,2} rejected) + mainnet 4-of-6 `createAction` spend TXID
**`febd287740f603af2cac5e4d73ce7face236fed8e2e3e592f38f7fc6e9552d89`** (joint
`026b712af9b6d21143e15588b04be2f4831350709106fabc8f92a0027a3f406222`), proxy drove
device parties `{0,1,2}` + deployed cosigner party 3, WoC-confirmed.

**Follow-on (not blockers):** production device-holds presig REPLENISHMENT (a `t−1`-party
+ cosigner relay presign ceremony to stock `DevicePresigSetPool` automatically) — the
gate seeds the pool from a local ceremony; background replenish stocks only the
single-presig `PresignManager` today. Multi-share refresh hot-swap is also single-share.

---

## 8. What's god-tier next

The §1 "two mandatory sides" signing topology AND the §4 policy/approval gate are
now real on mainnet (#38, #43). **The strong next is #40 (lost-phone recovery
ceremony)** — then #41 (native client) and #44 (zeroize). In dependency order:

1. **#43 — §4 policy engine + approval flow + WebAuthn ✅ DONE + mainnet-proven
   (2026-05-24).** "Two mandatory sides" now has teeth: the external side
   **enforces policy before it signs**. Real-sats `createAction` → policy
   `RequireApproval{k:1}` → approval-request emitted over the LIVE relay →
   approver signed `BRC-77(request_view_hash ‖ "mpc-approval-v1" ‖ session_id)` +
   replied → proxy collected the Allow → THEN signed over the relay with the
   deployed cosigner → broadcast. Spend TXID `7ada3f9d…` (joint `0371bc3f…`),
   WoC-confirmed; the spend could not proceed without the approval. Shipped:
   - ✅ **investigate gate** — `docs/AUDIT-43-policy-engine.md` (port decision:
     bsv-rs only, build-to-spec-CBOR, engine in `bsv-mpc-core`, NOT rust-mpc's
     `bsv-sdk`/JSON; two flagged spec-reconciliation items).
   - ✅ **policy engine** (PR #47) — `bsv-mpc-core/src/policy.rs`: PolicyManifest
     CBOR + `compute_policy_id` + §09.7 matcher + 3-hook eval (presigning ACTUALLY
     gates) + sliding-rate + dry-run. 28 lib + 7 `conformance_09b` tests.
   - ✅ **approval core** (PR #48) — `approval.rs`: BRC-77 `sign_approval`/
     `verify_approval` (79-byte preimage `request_view_hash ‖ "mpc-approval-v1"
     (15B) ‖ session_id`) + `ApprovalCollector` quorum SM (k-Allow/k-Deny/
     deadline, dedup, eligibility).
   - ✅ **approval flow + proxy gate + WebAuthn** (PR #50) — `relay_approval.rs`
     (`collect_approval_over_relay` + `serve_one_approval` = the `mpc.approve()`
     core, on the BOX_APPROVAL MessageBox box); `AppState.policy_engine` +
     `enforce_policy_and_approval` wired into `create_action_impl` BEFORE signing
     material is consumed; `verify_webauthn_approval` (§08.11). + the mainnet gate.
   - **MPC-Spec#43 OPENED** — lock the `policy_id` field-set + nested-key
     convention + the §09-policy CBOR vector before §09.15 cross-impl CI.
   - **Follow-on (not blockers):** production manifest loading from the cosigner
     cert in `server::run` (env path; the library `ProxyBuilder::with_policy_engine`
     is the wired path today).
   This turned 4-of-6 from "math" into a product guarantee.
2. **#40 — §3 lost-phone recovery ceremony.** Keystone proven (#35 reshare,
   mainnet `5137b913…`). Build: new device → reshare the `t−1` device shares onto
   it → same joint address. Plus zeroize (#44).
3. **#41 — §2/§6 native client.** wasm BRC-100 + wasm-bindgen/UniFFI bindings +
   enclave wrap-key + WebAuthn-PRF + iOS/Android shells. Realizability confirmed
   (zero dep on `bsv-wallet-toolbox-rs`).
4. **#44 — zeroize secret scalars** (cross-cuts #40/#41).

**Smaller hardening surfaced by #38:** device-holds presig replenishment (§7
follow-on) and multi-share refresh hot-swap — fold into #5 or a dedicated issue
when device-holds goes to a real deployment.
