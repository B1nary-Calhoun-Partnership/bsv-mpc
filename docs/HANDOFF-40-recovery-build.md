# Handoff — #40 lost-phone recovery BUILD (recovery-sign + mainnet gate)

> **Read this first in the new session, then `docs/AUDIT-40-recovery.md` (the
> investigate gate, already merged).** The reshare keystone is CONFIRMED and
> mainnet-proven (#35); recovery needs **no new crypto**. This handoff hands off
> the remaining BUILD: wire the new-set sign-after-reshare, prove it on mainnet,
> fold in zeroize + health/cooldown. It is scoped so you start at the build, not
> the audit.

Canonical repo: `/Users/johncalhoun/bsv/mpc/bsv-mpc`. Issue: **#40** (`step:implement`),
under umbrella **#37**. Spec: §03/§18 (recovery), `~/bsv/mpc/MPC-Spec`.

---

## 0. TL;DR — what's done, what's left

- ✅ **Reshare keystone confirmed** (`docs/AUDIT-40-recovery.md`, PR #53): secure
  multi-round PSS (`refresh::party_reshare_contribution`), cross-(t,n)
  address-preserving (`refresh::verify_reshare`), atomic rotate-on-commit
  (`bridge::persist_rotated_share` write-then-rename), SOLO (no Binary dep).
- ✅ **Reshare onto a fresh device is mainnet-proven** through the reshare itself:
  `crates/bsv-mpc-proxy/tests/container_reshare_deployed_mainnet_e2e.rs` funds a
  key, reshares 2-of-2 → 2-of-3 onto the deployed container, **address preserved**.
- ❌ **THE GAP:** that test does NOT sign+broadcast with the post-reshare shares —
  its own header says "the 2-of-3 relay-sign path that consumes the new-set shares
  is not yet wired." So recovery is proven up to *"the fresh device holds a valid
  share for the same address"* but NOT *"the recovered device can SPEND."*
- 🎯 **This build closes that** + the product polish. No new crypto — orchestration
  over the proven #35 reshare and the #38 device-holds / #13 relay-sign paths.

---

## 1. The three build steps (in order)

### Step 1 — Recovery-sign primitive (hermetic, no sats)
Wire a **new-set relay sign after a reshare**: after `ResharCoordinator` produces
the new (t′,n′) shares, a new-set subset (the recovered device's share + a
cosigner) signs over the relay and the signature verifies under the **UNCHANGED
joint key**. This is the same presigned 1-round relay-sign the proxy already does
(#38 `combine_sign_over_relay_nparty` / #13 relay sign) — just consuming the
**post-reshare** shares + a presig generated under the new set.

- **Hermetic test first** (mirror `crates/bsv-mpc-core/tests/poc_4of6_device_holds_presig_relay.rs`
  shape): in-process DKG (t,n) → reshare to (t′,n′) via the coordinators (no
  network — drive them in-process like the #38 gate's n-party DKG/presign drivers
  in `createaction_4of6_device_holds_relay_mainnet_e2e.rs`) → 4-party-style presign
  over a new-set subset → that subset signs → **assert the signature verifies under
  the ORIGINAL joint pubkey** (and that an old-set-only subset can't). Base + a
  negative (old share invalidated). `#[ignore]`, run-on-demand.
- The new-set parties need **fresh aux** (party indexing changed) — see
  `refresh::combine_reshared_with_aux` + how `container_reshare_deployed_mainnet_e2e`
  assembles the new KeyShare. The presig is generated under the new set's
  participants (reuse the `gen_presig_set` n-party driver from the #38 gate).

### Step 2 — Mainnet gate (real sats, run + WoC-confirm YOURSELF)
`crates/bsv-mpc-proxy/tests/recovery_spend_deployed_mainnet_e2e.rs` (new,
opt-in env e.g. `RECOVERY_MAINNET=1`). Mirror two proven harnesses:
- **reshare half** ← `container_reshare_deployed_mainnet_e2e.rs` (DKG 2-of-2 →
  fund joint addr → reshare 2-of-2 → 2-of-3 onto a fresh device over the relay /
  deployed container, address preserved).
- **spend half** ← the #38/#13 relay-sign harness (`createaction_relay_mainnet_e2e.rs`
  / `createaction_4of6_device_holds_relay_mainnet_e2e.rs`): the fresh device's
  new-set share + a cosigner sign a real spend **from the SAME joint address**,
  broadcast, WoC-confirm.
- **Assert:** the spend consumes the funded UTXO at the unchanged address; the
  OLD 2-of-2 share can no longer sign (invalidated). Funding fix = handoff §4.
- On success: comment the **mainnet TXID** on #40.

### Step 3 — Fold in #44 zeroize + recovery_health/cooldown
- **#44 zeroize:** add the `zeroize` crate + `Zeroize` on the secret `Scalar`
  share fields (`bridge.rs` `share_scalar`/share material) so the OLD bytes are
  wiped before overwrite on rotate. Mirror the worker pattern at
  `crates/bsv-mpc-worker/src/do_storage.rs` (~L858). Test: post-rotate, old
  scalar memory is zeroed. Close #44.
- **recovery_health (§18.4a) + cooldown:** an indicator + a guard — require a
  survivor quorum (≥ n−t+1) and refuse a second recovery within a cooldown window
  (anti hot-swap). Small state on the bridge/coordinator + a unit test.

---

## 2. Key code (already proven — orchestrate over these)
- `crates/bsv-mpc-core/src/reshar_coordinator.rs` — `ResharCoordinator`,
  `ResharConfig { original_joint_pubkey, contributor_old_indices,
  contributor_new_indices, .. }`, `combine_reshared_with_aux`.
- `crates/bsv-mpc-core/src/refresh.rs` — `party_reshare_contribution`,
  `verify_reshare`, (TEST-ONLY `threshold_reshare` — do NOT use in prod).
- `crates/bsv-mpc-proxy/src/bridge.rs` — `reshare_change_threshold_over_relay`
  (~L1375, deployed-proven), `apply_refreshed_share` (~L1029),
  `persist_rotated_share` (~L2068, atomic write-then-rename),
  `sign_over_relay` / `sign_over_relay_device_holds` (the relay-sign to reuse),
  `relay_identity_priv`.
- `crates/bsv-mpc-proxy/src/relay_reshare.rs` + `crates/bsv-mpc-service/src/reshare_relay_handlers.rs`
  — the deployed `/reshare-relay` path.
- Mirror harnesses: `container_reshare_deployed_mainnet_e2e.rs`,
  `createaction_4of6_device_holds_relay_mainnet_e2e.rs` (n-party in-process DKG +
  presign drivers — `run_dkg`, `gen_presig_set`).

---

## 3. Swarm / orchestrate plan
Parallel **read-only Explore** agents up front (fan out, return conclusions):
1. **Reshare→new-share assembly:** exactly how `container_reshare_deployed_mainnet_e2e`
   builds the post-reshare KeyShare for a new party (aux gen, `combine_reshared_with_aux`,
   what the fresh device ends up holding) + how the new-set participants/indices map.
2. **Relay-sign reuse:** the precise call path to make a new-set subset sign over the
   relay (`sign_over_relay`/`combine_sign_over_relay_nparty`), what a new-set presig
   needs, and how to provision the cosigner's new-set presig.
Then **converge yourself** and build Step 1 (you own the byte/crypto-exact wiring;
don't delegate the integration). A **general-purpose** agent may draft #44 zeroize
+ the health/cooldown unit tests in parallel — but **re-run every gate yourself**.

---

## 4. Env, funding, deploy (gotchas)
- **Wallet** at `http://localhost:3321` (Origin `http://admin.com`) with spendable
  sats. It returns txids but does NOT reliably broadcast → fund via: capture its
  BEEF → `Transaction::from_atomic_beef(b).to_beef_v1(false)` → self-broadcast to
  ARC with the **TAAL Bearer** `mainnet_9596de07e92300c6287e4393594ae39c` → retry
  until `SEEN_ON_NETWORK`. (Copy `broadcast_via_arc` / `fund_joint` from the #38 or
  #43 mainnet gate test.)
- **Deployed cosigner:** CF **Container** `bsv-mpc-service-container.dev-a3e.workers.dev`
  (native, does DKG/presign/reshare) is the heavy-MPC target; CF Worker
  `bsv-mpc-kss.dev-a3e.workers.dev` does light online-sign (`/sign-relay`). Relay
  `https://rust-message-box.dev-a3e.workers.dev`. Verify container live:
  `GET .../reshare-relay/identity` → 200. Redeploy only if needed:
  `cd poc/cf-container-p2 && eval "$(grep '^export CLOUDFLARE' ~/bsv/mpc/bsv-mpc/secrets.md)" && npx wrangler deploy`.
- A fresh locally-generated joint key works against the deployed worker/container
  with no prior owner binding (`authz_owner_or_reject` allows it) — same as #38/#43.

---

## 5. Gates (re-run every one YOURSELF — never trust an agent's "passed")
- `CARGO_INCREMENTAL=0` on every cargo invocation (disk).
- `cargo clippy -p bsv-mpc-core -p bsv-mpc-proxy -p bsv-mpc-service -p bsv-mpc-worker --all-targets -- -D warnings` warning-free.
- wasm: `cargo clippy/build -p bsv-mpc-worker --target wasm32-unknown-unknown`.
- `cargo test` workspace + conformance_* green.
- Hermetic recovery-sign test green (Step 1).
- **Mainnet gate green + WoC-confirmed by you** (Step 2) — the only proof that counts for a signing path.

---

## 6. Discipline (non-negotiable, set by the user)
**110%, no asterisks.** Swarm/orchestrate sub-agents but RE-RUN EVERY GATE
YOURSELF. Branch per change, squash-merge. **NO commit/push/deploy without showing
the diff and getting approval** (the user has given per-issue autopilot before —
ASK; don't assume). On success: comment the mainnet TXID on #40, update the
handoff/STATUS, write a memory note, open an MPC-Spec issue if a §03/§18 ambiguity
surfaces (the #39/#43 reconciliation pattern).

---

## 7. Pointers
- Audit/scope: `docs/AUDIT-40-recovery.md`. Track: `docs/HANDOFF-GODTIER-TRACK.md` §8.
- Memory: `project_40_recovery`, `project_38_nparty_device_holds`,
  `project_43_policy_approval`, `reference_wallet_3321_broadcast`,
  `project_godtier_track`, `project_reshare_deployed_mainnet` (in
  `~/.claude/projects/-Users-johncalhoun-bsv-mpc/memory/`).
- Acceptance (#40): a device-loss recovery demonstrated on mainnet with the
  address preserved + the recovered device spending; old share invalidated.
