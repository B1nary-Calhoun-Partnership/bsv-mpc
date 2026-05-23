# Handoff — #22 (presig invalidation triggers) + #10 (key-refresh §18 endpoint + rotation-on-commit)

> **✅ COMPLETED 2026-05-23.** Both #10 and #22 are landed on `main` + mainnet-proven.
>
> | Layer | PR | Proof |
> |---|---|---|
> | core `RefreshCoordinator` (distributed PSS reshare) | #10b | hermetic: 2-of-2 + 2-of-3 rotate, joint pubkey preserved, refreshed shares sign vs original key; corruption aborts |
> | service `RefreshHandler` + `/refresh-relay/*` | #10c | live-relay e2e: 2 peers refresh over the deployed MessageBox, rotated shares sign |
> | proxy refresh coordinator + hot-swap + persist + §06.18 ShareRefresh invalidation | #10d | hermetic w/ real shares (hot-swap, persist round-trip, malformed-share safety) |
> | §06.17.3 single-use consume + consume-time binding guard | #22a | hermetic incl. 8-thread race (one winner); CVE-2025-66017 mitigation |
> | all 4 §06.18 triggers + metric + §10 audit record | #22b | hermetic per-trigger purge + audit + counters |
> | **DEPLOYED refresh + mainnet sign w/ refreshed shares + invalidation-on-refresh** | #10e + #22c | **mainnet TXID `db865f22e2c10b19b5c4f28696f926aab2bcc21f5247dbd1aa268ae2ef658cae`** — vin spends funding `019525d8…05fbd6`, WoC-confirmed; joint addr `1DJwnQXCR22AzUkDfeixVgXoc6AoZ1jQV` unchanged across refresh |
>
> **Key fact (verified):** cggmp24 has NO native share-refresh SM (only `aux_info_gen`, across 4 revs) — refresh is distributed PSS on `threshold_reshare`. Aux-info kept; secret share rotated. Commit gated on `verify_reshare`. Refresh-capable container image: `217bffda`.
>
> **Follow-ups logged:** #35 (cross-(t,n) reshape 3-of-4→4-of-6, the direction.md endgame — primitives already (t,n)-general); Feldman identifiable-abort + full-proactive aux refresh (on #10); upstream §09/§13.7/§18-rekey firing sites for the 3 non-refresh triggers (on #22); full §10 Merkle/STH anchoring (on #5).
>
> ---
>
> _Original task brief (now complete) follows:_

> Next task for bsv-mpc, written 2026-05-23 after the full ADR-0030 presig lifecycle landed + was mainnet-proven on BOTH deployed cosigner models.
> **Canonical repo:** `/Users/johncalhoun/bsv/mpc/bsv-mpc` (NOT bsv-mpc-DEAD-do-not-use). Spec: `~/bsv/mpc/MPC-Spec`.

## 0. ⚠️ READ THIS FIRST — the CF deployment reality (hard-won; do NOT re-learn it the hard way)

There are **TWO deployed cosigner runtimes**, and which one you target is load-bearing:

| Runtime | What it can do | URL | Status |
|---|---|---|---|
| **CF Worker isolate** (`bsv-mpc-kss`, wasm) | **LIGHT online-sign ONLY** — `issue_partial` field math. CANNOT run cggmp24 DKG / presig generation (blows CF's per-isolate CPU budget: `/dkg/round` 500s, DKG hangs >120s, even with primes pre-seeded). | `bsv-mpc-kss.dev-a3e.workers.dev` | §06.20 at-rest variant mainnet-proven (TXID `cac63ea6…`) |
| **CF Container** (`bsv-mpc-service-container`, **native** bsv-mpc-service, `standard-1`) | **HEAVY MPC — DKG, presign generation, full §06.17.1.** No isolate CPU limit. | `bsv-mpc-service-container.dev-a3e.workers.dev` | full §06.17.1 mainnet-proven (TXID `8b5b954a…`) |

**The mistake to never repeat:** "CF can't run heavy MPC" is FALSE — it's only true for the *worker isolate*. The **container runs native bsv-mpc-service and does everything**, and it is ALREADY DEPLOYED + PROVEN. Anything heavy (DKG, presign, refresh) goes on the **container**, not the worker.

**Deploying the container** (you WILL need this for #10's deployed gate):
- Token: `eval "$(grep '^export CLOUDFLARE' ~/bsv/mpc/bsv-mpc/secrets.md)"` — this token has **`Containers:Edit`** (cfut_… prefix, verified 2026-05-23). The `~/bsv/teragun/SECRETS.md` token is Workers-only — do NOT use it for container deploys.
- Deploy: `cd poc/cf-container-p2 && npx wrangler deploy` (builds the repo-root `Dockerfile` = native bsv-mpc-service release build, ~2min, pushes image, rolls over).
- Verify new code is live: `GET https://bsv-mpc-service-container.dev-a3e.workers.dev/presign-relay/identity` → 200 + `{"cosigner_pub_hex":…}` (NOT 404 — 404 means the deployed image is stale).
- `wrangler containers list` should return the container (not 403) — that's your token-scope smoke test.

## 1. The discipline (non-negotiable — "110% proof, no asterisks")
- Every change gated by **unit/hermetic tests + (for on-chain paths) a real-mainnet e2e with a cited TXID, independently confirmed on WhatsOnChain** (vin must spend the funding UTXO). Never claim a TXID you didn't see on-chain.
- **No green-theater.** A test must fail under the old/wrong code. This session caught: a mis-authored 12-byte conformance IV (canonical is 32 across all 4 BSV SDKs), a non-deterministic two-subscription relay race, a flaky agent "passed" report, and the worker-vs-container target error — ALL via independent re-verification. Re-run agent gates yourself; don't trust the report.
- Mirror proven patterns. Warning-free clippy (native + wasm32). Branch per logical change; squash-merge.
- Wallet for real-sats e2e: `bsv-wallet-cli` at `localhost:3321` (Origin `http://admin.com`). If `createAction` doesn't propagate, self-broadcast the returned signed tx via ARC GorillaPool (TAAL 401s without a key — GorillaPool is the working broadcaster). ARC/secrets in `~/bsv/teragunv2/secrets.md`.

## 2. What's already DONE + on `main` (build on these — do NOT rebuild)
- Full ADR-0030 presig lifecycle (§06.15–06.21): `PresigBundle` + binding triple, BRC-2 share encryption (`presig_encryption.rs`), at-rest sealing (`presig_at_rest.rs`), burn-rate EWMA regen (`burn_rate.rs`), conformance_06 (intermediates byte-locked; ciphertext gated on MPC-Spec #9).
- **§06.18 invalidation CAPABILITY (the heart of #22 is already built — #22 is mostly WIRING):**
  - core `PresigBundle::invalidated_by(&InvalidationTrigger)` — the 4 §06.18 predicates (ShareRefresh / JointPubkeyChange / CosignerSubsetChange / PolicyUpdate), exhaustively unit-tested + pool-level "delete-all-where-any-fires" tested.
  - worker `do_storage.rs`: `invalidate_bundles_for_joint_pubkey` / `_for_subset` / `_with_stale_policy` (overwrite-then-delete zeroize per §06.18).
  - metric `bundles_invalidated_total{reason}` on the burn-rate regulator (`burn_rate.rs::InvalidationReason`).
  - service `SqliteShareStorage::delete_presignatures_for_agent` (purge-on-refresh; has a §18.9 unit test).
- §06.20 sign-time consume (`decrypt_and_issue_partial`), §06.17.1 durable combine (`signing::sign_from_bundle` + `serialize/deserialize_presig_public_data`), `FileBundleStore`.
- Deployed: worker §06.20 (PR #31), container §06.17.1 (PR #34). Both mainnet-proven.
- `PresignHandler` (bsv-mpc-service) = per-party presign-over-MessageBox + bundle assembly (relay-e2e proven 3/3). The container cosigner runs it (`relay_handlers.rs` `/presign-relay/*`); the proxy is the coordinator (`relay_presign.rs`).

## 3. #10 — multi-round key-refresh (§18) endpoint + rotation-on-commit
**What:** the §18 share-refresh ceremony — parties re-randomize their shares (same joint pubkey) so a pre-refresh share leak can't reconstruct. On successful commit, the new shares replace the old; the old shares are zeroized.
- **Read first:** MPC-Spec `18-recovery.md` (refresh §) IN FULL + `crates/bsv-mpc-core/src/refresh.rs` (`RefreshResult`, the cggmp24 refresh SM — already exists in core).
- **Where:** mirror the DKG handler pattern. Native service (`bsv-mpc-service`): add `/refresh/init` + `/refresh/round` (or refresh-over-relay via a `RefreshHandler` mirroring `PresignHandler`/`DkgHandler`). The **container** is the heavy-MPC target (refresh is a full ceremony — NOT the worker isolate). Proxy coordinates (mirror `relay_presign.rs`/`dkg` flow).
- **Rotation-on-commit:** on refresh commit, atomically overwrite the stored share (the service `store_share_with_owner` empty-owner-preserves pattern already supports rotation; the §18.9 test `refresh_rotation_overwrites_share_and_purges_presigs` shows the shape) AND fire #22's invalidation (below).
- **Gate:** hermetic refresh ceremony (in-process, joint pubkey unchanged, new shares sign) + **deployed** refresh against the container + (eventually) a mainnet sign with refreshed shares (TXID). Note §06: refresh latency budget exists.

## 4. #22 — wire §06.18 invalidation into the trigger handlers
**The capability is built (§2 above) — this issue is WIRING the triggers + audit events + single-use.**
- **Read first:** MPC-Spec `06-transport.md` §06.18 + `09-policy.md` (policy-update procedure) + ADR-0030 §13.
- **Wire each trigger to call the (already-built) deletion + record the metric + emit an audit event (§10):**
  - **Share-refresh commit** (in #10's handler) → `invalidate_bundles_for_joint_pubkey(jpk)` + `record_invalidation(Refresh, n)`. **This is why #10 + #22 are a pair — do #10 first or together.**
  - **Policy manifest update** (§09 handler — may need building if no §09 update path exists yet) → `invalidate_bundles_with_stale_policy(current_policy_hex)` + reason=Policy.
  - **Cosigner subset change** (§13.7 operator replacement) → `invalidate_bundles_for_subset(prior_csv)` + reason=Subset.
  - **Joint-pubkey change** (§18 post-recovery rekey) → `invalidate_bundles_for_joint_pubkey` + reason=Rekey.
- **Single-use (§06.17.3):** ensure the bundle store removes a bundle on consume (the worker `consume_presig_bundle` does overwrite-then-delete; verify the proxy/coordinator `FileBundleStore` consume path also enforces single-use — a bundle MUST NOT be consumable twice).
- **Consume-time guard (defense in depth):** before signing from a bundle, re-check `bundle.matches_binding(current)` so a stale bundle that escaped deletion still can't be consumed (predicate already on main).
- **Atomicity:** deletion MUST be atomic with the trigger; a sign request arriving after the trigger MUST get no stale bundle.
- **Gate:** hermetic per-trigger test (bundle present → trigger → pool empty atomically → consume yields nothing) + a deployed test: refresh the container's joint key → its presig bundles purged → next sign falls back to 4-round (or re-presign), never a stale bundle.

## 5. Build order + relationships
1. **#10 refresh endpoint** (on the container) — the heavy lift; unblocks the refresh trigger.
2. **#22 invalidation wiring** — wire all 4 triggers (refresh trigger needs #10; policy/subset/jpk can wire independently) + audit + single-use guard.
3. These complete the §06.18/§18 production story. Related: #13 (retire legacy 4-round path) can follow; #26 (HD offset) is independent; #9/#23 (cross-impl byte-lock) is the Binary-coordination track; #11 (§09/§18 conformance harnesses) pairs naturally with #10+#22.

## 6. Commands
```bash
cd /Users/johncalhoun/bsv/mpc/bsv-mpc
git submodule update --init --recursive
cargo test --workspace                         # gate (warning-free: cargo clippy --workspace --all-targets)
cargo clippy -p bsv-mpc-worker --target wasm32-unknown-unknown   # worker stays wasm-clean
# container hermetic §06.17.1 (no sats): CONTAINER_PRESIG_E2E=1 MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev cargo test -p bsv-mpc-proxy --test container_presign_bundle_sign_e2e -- --nocapture --test-threads=1
# container deploy: cd poc/cf-container-p2 && eval "$(grep '^export CLOUDFLARE' ~/bsv/mpc/bsv-mpc/secrets.md)" && npx wrangler deploy
```

## 7. KICKOFF PROMPT
```
Work on bsv-mpc #10 (key-refresh §18 endpoint + rotation-on-commit) and #22 (wire
§06.18 presig-bundle invalidation triggers), in that order — they're a pair.
Canonical repo: /Users/johncalhoun/bsv/mpc/bsv-mpc. Read
docs/HANDOFF-22-10-INVALIDATION-REFRESH.md FIRST (esp. §0 — the CF deployment
reality: heavy MPC runs on the CONTAINER `bsv-mpc-service-container`, NOT the
worker isolate; both are already deployed + mainnet-proven). Then read MPC-Spec
18-recovery.md (refresh) + 06-transport.md §06.18 in full.

Discipline: 110% proof, no asterisks. Every change gated by hermetic tests +
(for on-chain paths) a real-mainnet TXID independently confirmed on WhatsOnChain.
The §06.18 deletion capability + invalidated_by predicate are ALREADY merged —
#22 is wiring + audit + single-use, not rebuilding. Mirror PresignHandler/DkgHandler.
Re-run any agent gate yourself; don't trust 'passed'. Branch per change; squash-merge.
```
