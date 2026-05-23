# Handoff — finish #35c pt2: deployed cross-(t,n) reshare → MAINNET TXID

> **Mission:** drive the deployed cross-(t,n) key-reshare (2-of-2 → 2-of-3, same address) to a **real mainnet TXID** that spends the original address under the new sharing, independently confirmed on WhatsOnChain. **110% proof, no asterisks, no excuses — green light.** Swarm/orchestrate as needed; **re-run every gate yourself, don't trust "passed."**
> Canonical repo: `/Users/johncalhoun/bsv/mpc/bsv-mpc` (NOT `-DEAD-do-not-use`). Spec: `~/bsv/mpc/MPC-Spec`. Issue: **#35**.

## 0. The ONE thing left

A deployed 2-of-2 → 2-of-3 reshare against the CF container, then **spend K's funded address with the reshared shares** → cited TXID whose `vin[0]` spends the funding UTXO, confirmed on WhatsOnChain. Everything else for #35 is DONE + merged.

## 1. What is ALREADY proven + on `main` (do NOT rebuild)

Cross-(t,n) is proven at THREE levels, all green, merged:
- **#35a** `bsv_mpc_core::refresh::build_reshared_incomplete_shares` + capstone test `capstone_cross_tn_reshare_3of4_to_4of6_signs` (real keygen→reshare→fresh aux→sign vs original key).
- **#35b** `bsv_mpc_core::reshar_coordinator::{ResharCoordinator, ResharConfig, ContributorInputs, ResharCommit, combine_reshared_with_aux}` + distributed in-process test `distributed_reshare_3of4_to_4of6_signs`.
- **#35c pt1+validation** `bsv_mpc_service::ResharHandler` + the **gold reference**: `crates/bsv-mpc-service/tests/reshar_full_2of2_to_2of3_via_messagebox_e2e.rs` — **PASSES on the LIVE relay (~220s)**: 3 in-process agents run phase A (throwaway 2-of-3 DKG, `mpc-dkg`) sequentially, then phase B (PSS reshare of K, `mpc-refresh`), then `combine_reshared_with_aux` → every 2-of-3 subset signs vs the ORIGINAL key, address preserved. **This is the exact deployed mechanism on real transport. Study it — it is the source of truth for sequencing.**

`combine_reshared_with_aux(reshared_incomplete_json, throwaway_dkg_keyshare_json)`: aux is key-independent, so the new set's aux comes from a throwaway new-set DKG (reusing the proven n-party relay `DkgHandler`) and composes with the PSS-reshared secret. Proven.

n-party relay DKG works: `crates/bsv-mpc-service/tests/dkg_2of3_via_messagebox_e2e.rs` (Alice/Bob/Carol, ~90-150s).

## 2. Deployed wiring already BUILT (compiles, clippy-clean, deployed) — needs the phase-A fix

- **Container endpoint:** `crates/bsv-mpc-service/src/reshare_relay_handlers.rs` — `GET /reshare-relay/identity` + `POST /reshare-relay/init`. Sequential: phase A (DkgHandler/`mpc-dkg`) → completion task awaits aux → phase B (ResharHandler/`mpc-refresh`) → `combine_reshared_with_aux` → `store_share_with_owner` + `delete_presignatures_for_agent`. Routed in `crates/bsv-mpc-service/src/lib.rs`.
- **Proxy orchestrator:** `crates/bsv-mpc-proxy/src/relay_reshare.rs` + `MpcBridge::reshare_change_threshold_over_relay` in `bridge.rs`. Proxy plays new parties 1,2 in-process (fresh relay identities); container = party 0. Sequential phases; arms container FIRST (async); awaits proxy parties' aux (phase A) → releases DKG subs → phase B → combine.
- **Mainnet test:** `crates/bsv-mpc-proxy/tests/container_reshare_deployed_mainnet_e2e.rs` (gated `CONTAINER_RESHARE_MAINNET=1`): DKG K → fund → reshare → assert joint pubkey UNCHANGED → sign 2-of-3 with reshared shares `{1,2}` → pre-flight verify under joint pubkey → broadcast (TAAL Bearer token wired). Signing `{1,2}` (proxy-held) is valid + proves the reshared sharing spends K; those shares only exist because of the joint reshare WITH the container.

## 3. THE BUG to fix (the only blocker)

First deployed mainnet run (2026-05-23) FAILED:
```
§18.2 cross-(t,n) reshare over relay: Protocol("reshare: party 1 timed out awaiting throwaway DKG aux")
```
Phase A (throwaway DKG over the relay between deployed container=party0 and proxy parties 1,2) did NOT complete in 300s. The identical mechanism PASSES with all-in-process agents (§1), so this is a **deployed-split timing/ordering bug, NOT a crypto/protocol flaw.**

**Prime hypothesis:** the container generates its Paillier safe-prime set (~60-90s) INSIDE `/reshare-relay/init` BEFORE it subscribes to `mpc-dkg` + initiates + ships round-1 → it joins phase A ~60-90s late → the proxy's round-1 must survive relay backfill, and apparently doesn't (or the lateness breaks it).

## 4. THE PLAN (do this)

### Step 1 — Reproduce HERMETICALLY (no sats, no deploy)
Write `crates/bsv-mpc-service/tests/reshar_phaseA_delayed_party0_e2e.rs` (gated `MESSAGEBOX_RELAY_URL`): mirror the phase-A throwaway DKG of the gold test (3 in-process `DkgHandler` agents, 2-of-3, live relay) BUT delay party 0's subscribe+initiate+ship by `PARTY0_DELAY_SECS` (default 90) AFTER parties 1,2 have subscribed+initiated+shipped. Run it. Does it reproduce the timeout? (If yes → it's the late-join/backfill issue. If it PASSES → the deployed bug is elsewhere: instrument the deployed path, see Step 1b.)
Run: `MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev cargo test -p bsv-mpc-service --test reshar_phaseA_delayed_party0_e2e -- --nocapture --test-threads=1`

### Step 1b — if not reproduced, instrument the deployed container
`cd poc/cf-container-p2 && eval "$(grep '^export CLOUDFLARE' ~/bsv/mpc/bsv-mpc/secrets.md)" && npx wrangler tail` during a run to see the container's phase-A logs (does it ship round-1? receive the proxy's? error?).

### Step 2 — FIX (make Step 1's test pass with the 90s delay)
Candidate fixes (pick the cleanest):
- **(preferred) Subscribe + initiate BEFORE prime gen.** Check `crates/bsv-mpc-core/src/dkg.rs`: does `init()`/keygen need primes, or only the later aux phase? cggmp24 keygen (VSS) does NOT need Paillier primes — only aux does. If so, restructure `DkgHandler` so a party can subscribe + `initiate` (start keygen, register slot, receive backfilled round-1) immediately, and feed primes before the aux phase consumes them. Apply to BOTH `reshare_relay_handlers.rs` (container) and the proxy orchestrator.
- Pre-generate the container's primes off the request hot-path (a small warm pool), so `initiate` is immediate.
- Make the proxy not ship phase-A round-1 until the container has armed (poll/handshake), or re-ship on backfill miss.
Re-run Step 1's delayed test → must PASS. Re-run the gold test (`reshar_full_2of2_to_2of3_via_messagebox_e2e`) → no regression. `cargo clippy -p bsv-mpc-core -p bsv-mpc-service -p bsv-mpc-proxy --all-targets` warning-free.

### Step 3 — Deploy + mainnet run + verify (the 110% TXID)
```bash
# deploy the fixed container (token has Containers:Edit):
cd poc/cf-container-p2 && eval "$(grep '^export CLOUDFLARE' ~/bsv/mpc/bsv-mpc/secrets.md)" && npx wrangler deploy
# wait for rollover, confirm live (200, not 404 = stale image):
curl -s https://bsv-mpc-service-container.dev-a3e.workers.dev/reshare-relay/identity
# run the deployed mainnet reshare (REAL SATS):
CONTAINER_RESHARE_MAINNET=1 cargo test -p bsv-mpc-proxy --test container_reshare_deployed_mainnet_e2e --release -- --nocapture --test-threads=1
```
Then **independently confirm on WhatsOnChain yourself**: `curl -s https://api.whatsonchain.com/v1/bsv/main/tx/hash/<SPEND_TXID>` — assert `vin[0]` spends the funding UTXO. Never claim a TXID you didn't see on-chain.

## 5. Discipline (non-negotiable)
- 110% proof, no asterisks. Every gate re-run by YOU. Branch per logical change; squash-merge. Warning-free clippy (native; worker stays wasm-clean via `cargo clippy -p bsv-mpc-worker --target wasm32-unknown-unknown`).
- Mainnet only. The reshare must PRESERVE the joint pubkey (same address) — assert it.
- On success: comment the TXID on #35, update `STATUS.md`, and write the memory note.

## 6. Environment / secrets
- Container: `https://bsv-mpc-service-container.dev-a3e.workers.dev` (CF Container, native bsv-mpc-service, heavy MPC). Relay: `https://rust-message-box.dev-a3e.workers.dev`.
- CF deploy token (Containers:Edit): `eval "$(grep '^export CLOUDFLARE' ~/bsv/mpc/bsv-mpc/secrets.md)"`.
- Wallet for real sats: `bsv-wallet-cli` at `localhost:3321`, Origin `http://admin.com` (set up + funded for you).
- ARC broadcast: GorillaPool is keyless (often the working one); TAAL needs `Authorization: Bearer mainnet_9596de07e92300c6287e4393594ae39c` (in secrets.md / `~/bsv/teragunv2/secrets.md`) — already wired into the reshare test's `broadcast_via_arc`.
- The proxy identity in the reshare test is `[0x53;32]`; DKG/reshare are minutes (Paillier primes).

## 7. Done = 
`container_reshare_deployed_mainnet_e2e` green with a spending TXID, vin spends the funding UTXO, confirmed on WhatsOnChain, joint address unchanged across the reshare. Then #35 is fully closed (cross-(t,n) deployed + mainnet-proven), and the direction.md endgame's headline (address-preserving quorum reshape) is real on mainnet.
