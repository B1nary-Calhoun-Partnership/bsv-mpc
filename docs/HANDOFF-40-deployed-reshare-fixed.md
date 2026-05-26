# Handoff — #40 recovery: deployed reshare-over-relay FIXED; presign-over-relay under test

> **Read this first.** This session ROOT-CAUSED + FIXED the deployed reshare-over-relay
> hang that blocked #40's on-chain proof, and **proved it on mainnet** (container_reshare
> TXID `6c0f17cc…`). The full #40 recovery gate's reshares now pass reliably; the **last
> step (the `{0,2}` presign over the relay) is under test** — it timed out once and is
> being reproduced. Canonical repo: `/Users/johncalhoun/bsv/mpc/bsv-mpc`. Branch:
> `feat/40-recovery-sign-health-zeroize`. Issue **#40** (umbrella **#37**); infra issue **#58**.

---

## 0. LIVE STATUS — 2026-05-26 (newest first)

### 🎉 #40 LANDED — recovered-device mainnet TXID `f8b514586b8d029f9679c5f0bb8621e91d24d0e88d2b5eaf0500beac2aa21992`
The full true-loss recovery gate `recovery_spend_deployed_mainnet_e2e` **PASSED end-to-end** (`test result: ok`):
DKG → fund K → reshare#1 (2-of-3) → lose phone P2′ → reshare#2 (recovery onto fresh device) → `{0,2}` presign+
sign over the relay → ECDSA verify under K → spend. WoC-confirmed: spends K's UTXO `802afcdb…:0`, signed under
joint key `02613431…` **= K (address UNCHANGED across DKG → 2 reshares)**. Posted to #40 (comment 4544188610).
The fix chain below (OOM → bsv-rs timeout → relay LIMIT + acknowledge-on-consume + backlog drain) is what
unblocked it; the presign/sign code was already correct. **Remaining: commit bsv-mpc working tree (pending
approval); open PRs for Calhooon/bsv-rs `fix/brc104-transport-timeout` + Calhooon/rust-message-box
`fix/listmessages-memory-bound`; close #58 notes.** Gate runs this session: 4 (OOM) → 4/5 (send hang) → 5
(phase A converged, phase B slow) → drain → 7 (PASS).

### ✅ TRUE ROOT CAUSE FOUND + FIXED — relay 128 MB OOM from unbounded `listMessages` (2026-05-26)
The #40 TXID was NOT blocked by OOM (container) or crypto — it was a **relay-side memory regression**.
Full causal chain, each layer instrumented + proven, NOT guessed:
1. **CF Container OOM — FIXED + PROVEN.** `MALLOC_ARENA_MAX=2` (Dockerfile) + process-global safe-prime
   serialization (`paillier_pool::generate_serialized`, wired into `dkg.rs` + `reshare_relay_handlers.rs`)
   + `worker.js` readiness barrier (`startAndWaitForPorts` + `containerFetch` + onStart/onStop/onError).
   Evidence: 3 gate runs, container uptime monotonic to ~1.5 ks, **ZERO `runtime_signal`** (only graceful
   `exitCode=0 reason=exit` from my `max_instances` toggles). The mid-reshare restart class is gone.
2. **bsv-rs BRC-104 no-timeout hang — FIXED.** `SimplifiedFetchTransport::new` built `reqwest::Client::new()`
   (no timeout, no connect-timeout, default keep-alive pool) → CF egress NAT drops the idle pooled socket →
   the BRC-104 General POST (`/sendMessage`) hung forever. Fix: builder with `timeout(30s)` +
   `connect_timeout(10s)` + `pool_max_idle_per_host(0)`. Calhooon/bsv-rs branch `fix/brc104-transport-timeout`
   commit `382282d`, pinned in bsv-mpc root `Cargo.toml` `[patch.crates-io] bsv-rs = { git=…, rev=382282d }`.
   (The container builds published `bsv-rs 0.3.12`, NOT `../bsv-rs` — the path override is host-only.)
3. **THE BLOCKER — relay (`rust-message-box`) Worker OOM (CF error 1102 = "exceeded memory limit").**
   Instrumented with a container `GET /reshare-relay/send-test` probe (self-send, with/without an active
   subscription) + `wrangler tail` on the RELAY. Ground truth: a bare send is OK; a send **while a BRC-103
   subscription is active** 503s. Relay tail = `Error: Worker exceeded memory limit` on `/listMessages` AND
   `/sendMessage`. Cause: `storage.rs::list_messages` did `SELECT … FROM messages WHERE recipient=? AND
   message_box_id=?` **with NO LIMIT**. A long-lived cosigner identity's `mpc-dkg` box accumulated thousands
   of **un-acknowledged** messages (we NEVER called `acknowledge()`); the unbounded SELECT loaded the whole
   box into the **128 MB Worker isolate** → OOM → poisoned the isolate → concurrent `/sendMessage` collateral
   OOM → reshare round-1 ship 503'd (container trail froze at `init:dkg_initiated`, never `round1_shipped`).
   This is why `6c0f17cc` passed early (fresh box) and every later run failed "after a full day of gates"
   (accumulation). **FIX (PROVEN): bound `list_messages` to `LIMIT 100`, NO `ORDER BY`** — an
   `ORDER BY created_at` (uncovered by any index) forced a full scan+sort of the bloated set into the isolate
   *before* the LIMIT, so it STILL OOM'd; un-ordered, the engine stops after LIMIT rows (rowid≈insertion order).
   Calhooon/rust-message-box branch `fix/listmessages-memory-bound`, deployed Version `79ea0061`. After deploy
   the `send-test` probe `send_with_active_subscription` → **ok (1842 ms)** — the 503/1102 is GONE.

**God-tier model (per canonical TS, verified in `~/bsv/message-box-{server,client}`):** the TS server returns
the ENTIRE mailbox (no LIMIT, no TTL, no auto-mark-read); the drain is the client calling `acknowledgeMessage`
(hard DELETE) after processing. It survives only because it's a Node host with GBs of RAM. We never acknowledged
→ unbounded growth. **Fix = canonical acknowledge-on-consume:** `ack_best_effort` wired into
`MessageBoxListener::run_loop` (`bsv-mpc-service/src/messagebox.rs`, main + duplicate paths) so every consumed
message is DELETEd server-side → boxes never accumulate (used by BOTH container and proxy). The relay `LIMIT` is
the CF-Worker platform guard the Node reference doesn't need; together = canonical + platform-safe. Backlog
self-drains ~100/subscribe via the ack wiring — no manual drain needed.

**RIGHT NOW (in flight):** container redeploying with the ack-on-consume wiring (bg `b4cy9ciau`, build
non-stale `Compiling bsv-mpc-service`). NEXT: toggle a fresh instance → warm (`/health` uptime≥12) → re-run
`RECOVERY_MAINNET=1 … recovery_spend_deployed_mainnet_e2e`. With the relay OOM gone (proven), reshare #1's
round-1 ships → DKG converges → reshares pass → reach `(6) presign` → land the recovered-device TXID.
At `(6) presign`: `curl …/presign-relay/debug` → `stored_share_index` MUST==0, `jpk` MUST==K.

**UNCOMMITTED (working trees), pending approval:**
- bsv-mpc (`fix/presign-relay-ws-pump-and-index`): `Dockerfile` (MALLOC_ARENA_MAX), `paillier_pool.rs`,
  `dkg.rs`, `reshare_relay_handlers.rs` (serialize + send-probe endpoint), `messagebox.rs` (ack wiring),
  `lib.rs` (send-test route), root `Cargo.toml` (bsv-rs git patch), `poc/cf-container-p2/{worker.js}`.
- Calhooon/bsv-rs `fix/brc104-transport-timeout` (`382282d`, pushed) — open a PR.
- Calhooon/rust-message-box `fix/listmessages-memory-bound` (deployed, committed) — open a PR; consider
  the same LIMIT on other unbounded reads + a DB index review.

---

## 0b. LIVE STATUS — 2026-05-25 (newest first)

### VALIDATION IN FLIGHT (index fix) + an infra hiccup to know about
- The index fix is deployed (image `06b7bcdf`, fresh instance). First validation run (`recovery_rerun_6`)
  did NOT reach the presign: the **container instance restarted mid-run** (uptime→0, share_count→0, empty
  trail) during the cold reshare#1 safe-prime gen, wiping the funded key's DKG share → reshare#1 hung ~50
  min. Killed it. Container is stable again (uptime climbing, not flapping) — diagnosed as a transient
  instance churn under cold heavy load right after the `max_instances` toggle, NOT the index fix (prior
  cold runs #3-#5 did the same 3 ceremonies and reached presign). **Re-running on the stable container
  (`recovery_rerun_7`, task `btn0v3v95`).** If a restart recurs, pre-warm the Paillier pool before the
  heavy run (or bump instance memory). Watch container `uptime_seconds` — a reset = restart.

### 🛠️ CF CONTAINERS ROOT CAUSE (doc swarm, 2026-05-25) — the infra instability is OOM
A swarm over the Cloudflare Containers docs explained the instability (cite pages):
- **`standard-4` (4 vCPU / 12 GiB) is the LARGEST instance type — there is no bigger box** (custom caps at
  4 vCPU + 12 GiB). On OOM the instance is **killed + restarted** and **there is no swap** (CF Containers
  FAQ). Our back-to-back 2048-bit **Paillier safe-prime generation** (DKG + 2 reshares + presign) spikes
  RSS past 12 GiB → OOM → restart → in-memory MPC coordinator state lost → ceremony hangs/timeouts. **This
  is the mid-run restarts (symptom: uptime→0) AND the day-of "party timed out awaiting throwaway DKG aux"
  — both are OOM, not a code regression.**
- **Cold "container is not running":** we proxy with the plain DO `fetch()` which auto-starts but does NOT
  await port-readiness. FIX: override the Container class `fetch()` to `await this.startAndWaitForPorts(...)`
  then `containerFetch(request)` (readiness barrier), with `requiredPorts`/`portReadyTimeoutMS: 30000`.
  Add `onStart`/`onStop({exitCode,reason})`/`onError` hooks — these fire in the Worker/DO context so they
  DO show in `wrangler tail` and will CONFIRM OOM (`reason: runtime_signal`, non-zero exit).
- **Stop the OOM (highest impact, code not config — we're already at the box ceiling):** serialize
  safe-prime gen behind the existing `paillier_pool.rs` (bounded backfill, NEVER N-parallel) so only ONE
  prime-gen's memory is live at a time; add `MALLOC_ARENA_MAX=2` (glibc arena bloat on num-bigint). And/or
  **persist coordinator round-state to DO-SQLite** (like #9 share custody) so a restart lazily recovers
  instead of hanging.
- **Image rollout:** `wrangler deploy --containers-rollout=immediate` IS the documented force-replace
  (default rollout is gradual `[10,100]` and defers an "active" instance). With `rollout_active_grace_period:0`
  the old instance is SIGTERM'd at once — the `max_instances` 1→0→1 toggle should be unnecessary once this
  is reliable. (Container logs/tracing → Dashboard Logs/Observability tab, NOT `wrangler tail`.)
- **Scale-out option (if needed):** key the DO by ceremony/session id — `getContainer(env.BSV_MPC_SERVICE,
  sessionId)` — so each ceremony pins to its own instance (in-memory state coherent) and load spreads;
  raise `max_instances`. Do the memory fix first. Docs: containers/platform-details/{limits,architecture,
  rollouts,scaling-and-routing}, container-class API, durable-objects/api/container, FAQ.
- **⇒ Apply the readiness barrier + serialize-prime-gen (+`MALLOC_ARENA_MAX=2`) BEFORE the next recovery
  run** — a non-OOMing container should complete the reshares reliably and reach the presign, where the
  `/presign-relay/debug` trail (already deployed) pinpoints the remaining `{0,2}` presign cause. Full CF
  report: see the agent findings (instance_type table, exact `worker.js` `startAndWaitForPorts` pattern).

### ⛔ BLOCKED ON DEPLOYED-INFRA INSTABILITY (2026-05-25 late) — recovery TXID not yet landed
After confirming the index fix is genuinely deployed (clean recompile, `Compiling bsv-mpc-service`, image
`61fc8d16`→`47e4e792`) and STILL hitting the presign timeout, I deployed **container-side presign
instrumentation** — a `/presign-relay/debug` checkpoint trail (`relay_handlers.rs`) that records the
EXACT share the cosigner loads (`stored_share_index`, joint key, ciphertext fingerprint) + the arm's
binding params (`my_party_index`, `coordinator_party`, `parties_at_keygen`). It's live + clippy-clean.
BUT the two instrumented gate runs (#10, #11) **failed at the RESHARE step** (`party 1 timed out awaiting
throwaway DKG aux`) BEFORE reaching the presign, so NO debug data was captured. Earlier runs (#3–#9)
passed the reshares fine; my instrumentation only touched the presign arm — so this is **deployed
container/relay degradation under a full day of ~11 heavy mainnet gates** (cold-start "not running",
mid-run restarts, and now reshare-aux timeouts), NOT a code regression. The demanding recovery gate
(DKG + 2 reshares + presign, all heavy + over the relay) can no longer reliably reach the presign.

**RECOMMENDATION / NEXT SESSION (stable infra):**
1. Start fresh: redeploy the container (clean, `docker builder prune -af`), force a fresh instance
   (`max_instances` 1→0→1), and WARM it (poll `/health` until uptime≥10) before the gate. Possibly bump
   `instance_type` or pre-warm the Paillier pool to stop cold-load restarts/aux-timeouts.
2. Run the gate; the instant it logs `(6) presign`, `curl /presign-relay/debug` → read `stored_share_index`
   (must be 0 = `my_party_index`), `jpk` (must == K), `ct_fp`. If index≠0 or jpk≠K → the container loaded
   a stale/wrong reshared share (fix in reshare store/load); if both correct → instrument the cggmp24 SM
   (the `presign_index_diverge` trace in `presigning.rs`) for the round-by-round divergence.
3. The presign CODE is proven correct for the `{0,2}` reshared scenario over the real relay (3 agent
   repros: `presign_noncontiguous_02_realrelay_e2e.rs`, `presign_noncontiguous_02_reshared_realrelay_e2e.rs`),
   so the remaining bug is container-runtime/state, not crypto/routing.
- **Uncommitted working tree** (all on `feat/40-recovery-sign-health-zeroize`): the 3 proven fixes
  (subscribe re-drain bound, relay_presign reorder, presign_handler index translation) + the settle +
  the `/presign-relay/debug` + `presign_index_diverge` instrumentation + 3 new repro tests. NOT yet
  committed (per no-commit-without-approval). PROVEN mainnet TXIDs: reshare `6c0f17cc`, presign-relay `550d79df`.

### ⭐⭐ DEEP ISOLATION (swarm, 2026-05-25 PM) — code is PROVEN correct; deployed failure = deployment/runtime
After the index fix was deployed the recovery presign STILL timed out. Instrumented logs (proxy debug +
`wrangler tail`) gave ground truth: at the presign the coordinator (party 2) RECEIVES the cosigner's
round-1 + round-2 (from_party=0) but its SM **produces 0 outbound** with NO `dropping` warn → the SM
ingests but never advances. A 3-agent swarm then ISOLATED it with discriminating real-relay tests
(all local, no mainnet):
- `presign_noncontiguous_02_realrelay_e2e.rs`: `{0,2}` coordinator=2 over the REAL relay, in-process
  cosigner, **PASSES** with a correct index; a modeled `share_index`≠`my_party_index` mismatch
  **reproduces the exact symptom** (proves the *mechanism*, but topology says the real container is index 0).
- `presign_noncontiguous_02_reshared_realrelay_e2e.rs`: same but the cosigner uses a **twice-RESHARED
  share** (exact #40 recovery PSS path) — **PASSES** (3×). Trace proves the reshared share is
  byte-identical in topology to a fresh DKG share (internal `i`, VSS `I`, `public_shares`, signing_index,
  `S` all match); cggmp24 `subset(S=[0,2],…)` slices correctly. **So the reshared-share content is NOT the bug.**
- ⇒ The current WORKING-TREE code is PROVEN correct for the exact `{0,2}` reshared scenario over the real
  relay. The deployed timeout is therefore a **deployment/runtime issue**, not a code bug. Leading
  hypothesis: the live container was NOT actually running the index-translation fix (messy deploy history:
  multiple rebuilds + `max_instances` toggles; CLAUDE.md warns Docker can silently reuse a stale build
  layer). Secondary: container dirty runtime state after 2 reshares on its single relay identity.
- **ACTION IN FLIGHT:** clean verified redeploy from the working tree (`docker builder prune -af`,
  confirm `Compiling bsv-mpc-service` in the build = non-stale) + forced fresh instance → re-run the #40
  gate. If it PASSES, the prior deploy was stale. If it still FAILS, it's container runtime state →
  pursue the readiness gate (task #14) / add a container build-stamp + presign index trace.
- New local diagnostic: `presigning.rs` has a silent `presign_index_diverge` trace (enable with
  `RUST_LOG=presign_index_diverge=trace`) dumping cggmp24 internal `i`/`I`/signing_index/`S`.

### ⭐ THE REAL ROOT CAUSE (god-tier, spec-matching) — found via swarm, 2026-05-25
The recovery presign failed deterministically (4/4) at `{0,2}` even after the re-drain + settle fixes,
because those were NOT the cause. **Root cause: a position-vs-absolute party-index bug in the presign
relay routing.** The cggmp24 presigning SM identifies parties by 0-based POSITION within the signing
subset (`[0,t)`); `drive_inline` surfaces that position onto `RoundMessage.{from,to}` (`dkg.rs:861`); but
`wrap_protocol` (`presign_handler.rs`) matched it against `peers` keyed by ABSOLUTE keygen index. For
contiguous `[0,1]` position==index (sec0617 passed); for non-contiguous `[0,2]` party 2 is SM-position 1,
so the cosigner's MtA p2p (to position 1) found no peer with absolute index 1 → dropped → SM stalls →
timeout. The hermetic `{0,2}` test passed because the in-process simulator bypasses `wrap_protocol`. Two
swarm agents confirmed it end-to-end + against MPC-Spec **§05.4.6/§05.5.3** (which require `from_party`/
`to_party` to be the ABSOLUTE keygen index — a BRC-52 cert lookup keys on `from_party`, so a per-ceremony
position is non-conformant). **FIX (spec-matching, relay-layer only, core/DKG untouched):** in
`PresignHandler`, translate position→absolute on SEND (`wrap_protocol`, via `parties_at_keygen[pos]`) and
absolute→position on RECEIVE (`dispatch_one`), so the WIRE carries absolute indices (§05.4.6) and the SM
still sees positions (zero SM behavior change). New unit test `wrap_protocol_routes_noncontiguous_subset_by_absolute_index`
asserts `{0,2}` routes by absolute index. Reshare was the proven template (its hand-rolled PSS already
emits absolute indices). DKG/sign-relay unaffected (DKG always contiguous; sign-relay routes by identity
hex, not index filter). Latent same-class bug in full-4-round `signing.rs` over relay for subsets =
follow-up. MPC-Spec clarification to file: §05.4.6 should state subset-position MUST be translated to
absolute before the wire. Validating now: container rebuilding with the fix → recovery gate.

### SNAPSHOT — fix inventory + where we are
FOUR bugs sat between #40 and its mainnet proof (the 4th above is the real one; the settle was a wrong-
hypothesis band-aid that did NOT fix it):
1. **Deployed reshare-over-relay hang** → bounded best-effort INITIAL backfill (`subscribe.rs:202`).
   PROVEN earlier (container_reshare TXID `6c0f17cc…`). [god-tier]
2. **Presign-over-relay hang** = unbounded POST-JOIN re-drain (`subscribe.rs:569/598`) blocked the WS
   pump on the container → bounded it best-effort + reordered presign to WS live-push
   (`relay_presign.rs`) + ported the `pending_inbound` buffer into `PresignHandler`. PROVEN on mainnet
   (sec0617 TXID `550d79df…`). [god-tier]
3. **Recovery presign timeout** = §06.17 single-identity overlap (reshare#2 listener lingered into the
   presign subscription) → 60 s settle before the presign in the recovery test
   (`recovery_spend_…e2e.rs`). [BAND-AID — god-tier = a container readiness gate; tracked as task #14]

**RIGHT NOW:** full recovery gate re-running with all three fixes (task `bc7lregf1`,
`/tmp/recovery_rerun_5_settle.log`) to land the **recovered-device mainnet TXID** = the #40 acceptance
proof. DKG ✓, funded ✓, reshare #1 running. Tasks: #13 land TXID (in-progress), #14 god-tier readiness
gate (after TXID), #15 update #58 + commit-with-approval. All hermetic gates green; container image
`b3837b4c`/`7928b82b` (re-drain fix) live + fresh.

---

- **THIRD root cause found (recovery-specific) + fixed; #40 gate re-running.** With the re-drain fix
  deployed, the standalone presign (sec0617) PASSED but the **full recovery gate STILL timed out at
  presign `{0,2}`** (run `recovery_rerun_4`, 845 s). Diagnosis: it is the **§06.17 single-identity
  constraint** — the container has ONE relay identity, and its reshare-#2 PSS listener **lingers after
  the `/reshare-relay/init` HTTP response** (shuts down only once the phase-B completion task commits).
  The recovery test settles 60 s between reshare #1 and reshare #2 for exactly this (documented at
  `recovery_spend_…:343-351`) but had **NO settle between reshare #2 and the presign** → reshare #2's
  lingering listener overlapped the presign's `mpc_{sid}` subscription → two-subscription split race →
  presign round messages dropped → 180 s timeout. sec0617 passes because it has NO prior ceremony on
  the identity. **FIX: add the same 60 s single-identity settle after reshare #2, before the presign**
  (`recovery_spend_deployed_mainnet_e2e.rs`, mirrors the reshare-#1 settle). Test-side, no redeploy
  (the container image is proven by sec0617). Gate re-running (`bc7lregf1`). Deeper follow-up: have the
  container release a ceremony's relay listener promptly on commit so back-to-back ceremonies on the
  single identity don't need manual spacing.
- **✅ RE-DRAIN FIX PROVEN ON MAINNET (presign-over-relay).** `container_sec0617_deployed_mainnet_e2e`
  (DKG + presign-over-relay vs the deployed container, the exact path that failed 3×) **PASSED**:
  `✔ PresigBundle assembled` → co-signed via §06.17.1 bundle → ECDSA verifies → spent on mainnet.
  TXID **`550d79dff8395c1f63137e7d30fd3c4912c7ef6ffee01fe99312eded4c56daa6`** (SEEN, joint key
  `023b9925…`), `test result: ok` 196s. **The presign-over-relay hang is FIXED.** Full #40 recovery
  gate (`recovery_spend_deployed_mainnet_e2e`, task `bizzha5c8`) now RUNNING for the recovered-device TXID.
  - NOTE: sec0617's FIRST attempt failed at the *DKG* step (`/dkg/round` transport error) — the known
    cold-instance gotcha (first HTTP DKG round on a just-spawned instance); retried on the warm
    instance → passed. Not related to the presign fix. The fresh instance was forced via the
    `max_instances` 1→0→1 toggle (the `--containers-rollout=immediate` alone left the warm instance
    on the old image — `/reshare-relay/debug` showed the stale trail until the toggle).
- **CORRECTION — the reorder ALONE did NOT fix it; refined root cause found + a SECOND fix applied
  (now PROVEN).** Run #3 (WS-reorder + buffer, fresh image `2c2957b4`) **FAILED at the same presign
  step** (`recovery_rerun_3_wsfix.log`, 944 s, `test result: FAILED`). The reorder put round-1 on WS
  live-push correctly, but the **container's WS PUMP never starts**: the post-join re-drain at
  `subscribe.rs:569` is **unbounded** and runs SEQUENTIALLY before `pump` (line 572); on the container
  its BRC-104 `/listMessages` hangs (#58), so `pump` never runs → the WS-pushed round-1 sits in the
  event buffer, never forwarded to the handler → presign times out. **Reshare survived only because
  its ~360 s/phase budget outlasts the eventual unwind; presign's single 180 s budget did not.**
  Hermetic presign passed because in-process HTTP works (re-drain returns instantly → pump starts).
  **FIX #2 (the missing piece): bound BOTH the post-join re-drain (`subscribe.rs:569`) and the
  reconnect re-drain (`~598`) with `BACKFILL_TIMEOUT`, best-effort — so a dead HTTP `/listMessages`
  can NEVER block the WS pump.** Pump now starts ≤8 s and WS live-push flows immediately. Still 100%
  WS-only (HTTP backfill is recovery-only). Clippy-clean; redeploying the container now; will validate
  fast via `container_sec0617_deployed_mainnet_e2e` (DKG+presign-over-relay vs the container, no
  reshares, ~4 min) BEFORE the full 16-min recovery gate.
- **WS-ONLY PRESIGN FIX (reorder + buffer) — necessary but INSUFFICIENT alone.** User gave full
  green-light (incl. mainnet gate). The presign-over-relay failure is **DETERMINISTIC, root-caused**
  without HTTP dependence (per user: "we must do websocket, http is not an option").
- **DETERMINISTIC REPRODUCTION (NOT transient):** the #40 gate failed at the **presign `{0,2}` step
  TWICE in a row** — run #1 (`b742448tu`) and run #2 (`bt2xaod31`, 870 s) — exact same error
  `Protocol("timed out awaiting PresigBundle assembly over the relay")` (`recovery_spend_…:426`).
  Both runs: DKG ✓, fund ✓, reshare #1 ✓, lose-phone ✓, reshare #2 ✓ (address UNCHANGED), presign ✗.
  **Reshare fix is rock-solid; presign-over-relay was the deterministic gap.**
- **ROOT CAUSE (dual, confirmed by a 2-agent swarm + the deterministic repro):**
  1. **Ordering asymmetry (proximate):** `coordinate_presign_over_relay` shipped the coordinator's
     round-1 to the container *before* the container subscribed (`relay_presign.rs:127-152`; container
     subscribes at `relay_handlers.rs:254`). A pre-subscribe message can NEVER be WS-live-pushed — its
     SOLE delivery path is the single, unbounded, un-retried post-join re-drain at `subscribe.rs:569`,
     i.e. BRC-104 HTTP `/listMessages`. On the container that HTTP path is dead, so the round-1 is
     ALWAYS lost → cosigner never advances → 180 s timeout. **Reshare avoids this by subscribing on
     BOTH sides before any round-1 ship (`bridge.rs:1816-1839`, `reshare_relay_handlers.rs:533→541→552`)
     → round-1 rides WS live-push.** Deterministic failure ⇒ deterministic ordering bug. ✓
  2. **bsv-rs BRC-104 transport (root, → issue #58):** `SimplifiedFetchTransport` builds
     `reqwest::Client::new()` with **no timeout/connect-timeout + default keep-alive pool**
     (`~/bsv/bsv-rs/src/auth/transports/http.rs:497`); the General POST at `peer.rs:390` is un-timeout-
     wrapped; and `identity_key=None` (`messagebox http.rs:117`) forces a fresh handshake every call.
     CF egress NAT drops idle keep-alives → reqwest reuses a half-dead socket → hang. This is WHY the
     HTTP backfill is dead on the container. **Per user, HTTP is not the product path — this is an
     UPSTREAM note for #58, not the fix.**
- **THE FIX (WS-only, §06.17-matching, no new crypto) — DONE in the working tree:**
  1. **Reorder `crates/bsv-mpc-proxy/src/relay_presign.rs` (`coordinate_presign_over_relay`):** ship
     the coordinator's round-1 **AFTER** arming the cosigner (steps renumbered 4→initiate, 5→arm,
     6→ship). Now the cosigner has joined its box before round-1 is sent → **WS live-push**, never the
     HTTP backfill. Matches the §06.17 ordering invariant reshare already follows.
  2. **Port the `DkgHandler` early-inbound/out-of-order buffer into `PresignHandler`**
     (`crates/bsv-mpc-service/src/presign_handler.rs`): new `pending_inbound` field; `drive_protocol`
     is now a work-queue loop that BUFFERS (not drops) a protocol msg for an unregistered/checked-out
     session and replays it on `initiate` + after each round advances. Absorbs the round-2-before-
     round-1 race the reorder can create. The cggmp24 presigning SM also buffers out-of-order rounds
     internally (`presigning.rs` `wire_buffer`), so replay order is safe.
  3. bsv-rs HTTP fix held back as a separate #58 item (HTTP path, not the product fix).
- **Gates GREEN so far:** `cargo build` (service+proxy) ✓; clippy 4-native `--all-targets` -D warnings
  ✓; wasm worker clippy ✓; `presign_handler` unit tests (14) ✓; **hermetic `container_presign_bundle_sign_e2e`
  PASSED** (reordered flow + buffer, sig verifies under joint key). core/proxy/service lib suites RUNNING.
- **NEXT:** clean rebuild + deploy container (`docker builder prune -af`; force fresh instance) → re-run
  `recovery_spend_deployed_mainnet_e2e` for the recovered-device TXID → WoC-confirm → comment on #40.

---

## 1. TL;DR

- **#40 CODE is done + proven** (Steps 1+3, committed in PR #57, commit `5ed26bc`):
  - Hermetic **recovery-sign** (true device-loss): `crates/bsv-mpc-core/tests/recovery_sign_after_reshare.rs` — PASS.
  - **recovery_health (§18.4a)** + survivor-quorum (`max(t, n−t+1)`) + cooldown: `crates/bsv-mpc-core/src/recovery_health.rs` — 15 unit tests.
  - **#44 zeroize**: `crates/bsv-mpc-proxy/src/bridge.rs` (wipe old KeyShare+scalar before overwrite + Drop) — observable test.
  - Gates: clippy (4 native `--all-targets` + wasm worker), core lib 262, proxy lib 157.
- **THE BREAKTHROUGH** (uncommitted, in the working tree): the deployed reshare-over-relay
  was hanging EVERY run all session. Root-caused + fixed; **`container_reshare_deployed_mainnet_e2e`
  PASSED on mainnet** — TXID **`6c0f17cc5ea0cd5a1d1ef08d69958ddcd5e906394bafdacba50db3655fec6aa6`**
  (reshared 2-of-3 spend, WoC SEEN, joint key UNCHANGED).
- **RUNNING NOW:** the full #40 gate `recovery_spend_deployed_mainnet_e2e` (background task
  `b742448tu`, log `/tmp/recovery_mainnet_run_final.log`). It does DKG → fund → reshare#1 →
  lose phone → reshare#2 → recovered-device `{0,2}` spend over relay → WoC. **CHECK ITS RESULT FIRST.**

---

## 2. Root cause (definitive) + the fix

**Symptom (all session):** the deployed CF Container's reshare arm (`/reshare-relay/init`)
froze; proxy timed out "party 1 timed out awaiting throwaway DKG aux".

**Root cause (proven via the `/reshare-relay/debug` + `/reshare-relay/egress-test` endpoints
I added to the container):**
- Container→relay **connectivity is FINE**: HTTP `/socket.io` handshake 200 in ~118ms; TCP
  connects on **both IPv4 and IPv6** in ~1ms. **NOT** IPv6, **NOT** TLS, **NOT** egress, **NOT** my code.
- The hang is in `subscribe_round_messages` → `subscribe()` → **`drain_backfill`'s authed
  `POST /listMessages`**, which uses **BRC-104 `SimplifiedFetchTransport`** (`bsv_rs` auth `Peer`).
  That Peer's **BRC-104 handshake LOGIC hangs** from the container (the `/.well-known/auth`
  endpoint itself responds in **79ms** — so it's the Peer's multi-step handshake await, not HTTP).
- The **BRC-103 WS subscribe** path (`connect_and_join`) works fine from the container.

**THE FIX (the one that made it pass)** — `crates/bsv-mpc-messagebox/src/subscribe.rs`:
made `drain_backfill` **bounded (`BACKFILL_TIMEOUT = 8s`) + best-effort (non-fatal)** so a
stalled BRC-104 backfill can no longer block the live BRC-103 WS subscribe. `subscribe()`
now succeeds in ~8.5s (8s backfill cap → falls through to the working WS path), and the
reshare ceremony converges. Messages still flow via WS live-push + the bounded post-join re-drain.

**The TRUE god-tier root-cause fix (NOT done — follow-up):** fix the `bsv_rs` auth `Peer`
BRC-104 handshake hang. Note `~/bsv/bsv-rs/src/auth/transports/http.rs:497` builds
`reqwest::Client::new()` with **NO timeout** (every broadcaster in bsv-rs sets `.timeout(...)`);
that's a real bug, but the hang is in the handshake await, not just the HTTP. File a bsv_rs issue.

---

## 3. Working-tree changes (UNCOMMITTED) — keep vs reconsider

`git status` (branch `feat/40-recovery-sign-health-zeroize`):
- **`crates/bsv-mpc-messagebox/src/subscribe.rs`** —
  - ✅ **KEEP (THE FIX):** bounded best-effort `drain_backfill` (`BACKFILL_TIMEOUT`).
  - 🟡 reconsider: WS connect timeout/retry (`CONNECT_TIMEOUT`, `CONNECT_ATTEMPTS`, retry loop) — defensive, fine.
  - 🟡 reconsider: HTTP-polling fallback (`run_loop_polling`, `POLL_INTERVAL`) — **dead for this failure** (it also needs the authed `/listMessages` that hangs); only justified for a different failure. Likely revert.
  - ✅ keep: post-join re-drain moved to background `run_loop_with_conn` (off the subscribe critical path).
- **`crates/bsv-mpc-messagebox/src/transport_native.rs`** —
  - 🔴 **SPECULATIVE (revert candidate):** `connect_tcp_prefer_ipv4` + `ws_host_port` + `client_async_tls`. Built on an IPv6 theory the egress probe **disproved** (both families connect in 1ms). Adds complexity for a non-issue.
- **`crates/bsv-mpc-service/src/messagebox.rs`** — ✅ **KEEP:** `message_id` dedup in `run_loop` (correct; enables safe re-drain).
- **`crates/bsv-mpc-service/src/reshar_handler.rs`** — ✅ **KEEP:** early-inbound buffer (`pending_inbound`) mirroring `DkgHandler` (hermetic-proven; took hermetic reshare flaky→6/6).
- **`crates/bsv-mpc-service/src/reshare_relay_handlers.rs`** — 🟡 DIAGNOSTIC: `checkpoint`/`RESHARE_CHECKPOINTS` + `handle_reshare_relay_debug` (`GET /reshare-relay/debug`) + `handle_reshare_relay_egress_test` (`GET /reshare-relay/egress-test`). Hugely useful; decide keep (gate behind a flag?) vs strip for prod.
- **`crates/bsv-mpc-service/src/lib.rs`** — routes for the two debug endpoints.
- **`poc/cf-container-p2/wrangler.jsonc`** — `rollout_active_grace_period: 0` (so `--containers-rollout=immediate` actually replaces the warm instance). KEEP.

Hermetic validation already done: `reshar_full_2of2_to_2of3_via_messagebox_e2e` 6/6 PASS with these changes.

---

## 4. Deployed-infra gotchas (learned the hard way)

- **Docker build caches the cargo layer.** A normal `npx wrangler deploy` often reuses a
  stale binary (no `Compiling bsv-mpc-messagebox` in the output → your change isn't in the image).
  To force a clean rebuild: `docker builder prune -af` **then** `npx wrangler deploy --containers-rollout=immediate`. Confirm the build log shows `Compiling bsv-mpc-messagebox` + `Pushed`.
- **Rollout won't replace a warm instance** by default. With `rollout_active_grace_period: 0`
  (now set) + `--containers-rollout=immediate` it does. If not, **toggle `max_instances` 1→0 (deploy) → 0→1 (deploy)** to force a fresh instance.
- **Confirm the NEW image is live:** `GET /reshare-relay/debug` returns `{"count":0,...}` on a
  fresh process (the in-memory checkpoint trail resets on restart). A persisting trail = old process.
- **Cold-start:** the first DKG after a fresh instance is slow (safe-prime gen). `/health` 200 fast ≠ instance warm for heavy MPC; the first `/dkg/round` can transport-error on a cold instance — warm it or just retry.
- Deploy cmd: `cd poc/cf-container-p2 && eval "$(grep '^export CLOUDFLARE' ~/bsv/mpc/bsv-mpc/secrets.md)" && npx wrangler deploy`.
- Relay `https://rust-message-box.dev-a3e.workers.dev` is healthy (handshake 200 in 0.17s from a normal host). Wallet `http://localhost:3321` (Origin `http://admin.com`).

---

## 5. NEXT STEPS (in order)

1. **Check the #40 gate result FIRST:** `cat /tmp/recovery_mainnet_run_final.log` (bg task `b742448tu`).
   - If **PASS**: grab the `recovery_spend` TXID + `view:` line → **WoC-confirm it yourself**
     (`curl https://api.whatsonchain.com/v1/bsv/main/tx/hash/<txid>`) → comment the TXID on **#40**
     (this is the acceptance proof: true-loss recovery, address preserved, recovered device spends).
   - If **FAIL** (a reshare/sign timeout): the fix is proven on `container_reshare`; the #40 gate is
     more demanding (2 reshares + presign + sign `{0,2}` over relay). Read `/reshare-relay/debug`,
     ensure the warm WS-fixed image is live (trail count:0), and **re-run** (each run burns ~2000 sats
     ≈ fractions of a cent; OK per project norms):
     `RECOVERY_MAINNET=1 CARGO_INCREMENTAL=0 cargo test -p bsv-mpc-proxy --test recovery_spend_deployed_mainnet_e2e --release -- --nocapture --test-threads=1`
2. **Clean up the relay-reliability changes** (god-tier discipline — don't ship speculative cruft):
   keep bounded-backfill + dedup + ResharHandler buffer + post-join re-drain; **revert the IPv4-prefer
   connect (transport_native.rs) and likely the polling fallback** (disproven/dead-here). Re-run the
   hermetic loop after cleanup.
3. **Decide the debug endpoints** (`/reshare-relay/debug`, `/reshare-relay/egress-test`): keep
   (gate behind an env flag) or strip before committing.
4. **Re-run all gates yourself:** clippy `-p bsv-mpc-core -p bsv-mpc-proxy -p bsv-mpc-service -p bsv-mpc-worker --all-targets -- -D warnings` (+ wasm worker), core/proxy/messagebox/service lib tests, hermetic recovery-sign + reshar_full loop. `CARGO_INCREMENTAL=0`.
5. **Commit** the relay-reliability fix to the branch (SHOW THE DIFF + GET APPROVAL first). Update **#58**
   with the root cause + the bounded-backfill fix. **File a `bsv_rs` issue** for the auth `Peer` BRC-104
   handshake hang (+ the no-timeout `reqwest::Client::new()` at `transports/http.rs:497`).
6. On the #40 TXID landing: update `docs/HANDOFF-GODTIER-TRACK.md` §8 + write a memory note.

---

## 6. Key context / decisions

- **God-tier #40 = TRUE device-loss** (not 2-of-2 re-provision). Start 2-of-3, lose the phone P2,
  survivors `{0,1}` reshare onto a fresh device, recovered device + container cosign `{0,2}` over
  relay → spend → old share dead. Makes `recovery_health` non-vacuous. See memory
  `project_40_recovery_godtier`. The existing hardcoded `reshare_change_threshold_over_relay`
  already does a survivors-{0,1} 2-of-3→2-of-3 reshare with ZERO code change (point the bridge at
  the surviving P1 share); a fresh bridge on the recovered P2 share auto-derives signing participants `[0,2]`.
- **User discipline (non-negotiable):** 110% no asterisks; **NO commit/push/deploy without showing the
  diff + approval**; re-run every gate yourself (never trust an agent's "passed"); don't ship speculative
  code; keep tooling simple.
- **Decisions log:** the polling-fallback and IPv4-prefer were workarounds added under wrong hypotheses;
  the user explicitly called the workaround stack out as non-god-tier and chose to root-cause the auth
  hang — which we did. The bounded-backfill is the correct design fix (backfill must be best-effort).
- Memory dir: `~/.claude/projects/-Users-johncalhoun-bsv-mpc/memory/` — `project_40_recovery`,
  `project_40_recovery_godtier`, `project_38_nparty_device_holds`, `reference_wallet_3321_broadcast`,
  `project_godtier_track`.

---

## 7. Mainnet TXIDs this session

- `container_reshare` (single reshare 2-of-2→2-of-3 on deployed container + in-process {1,2} sign + broadcast): **`6c0f17cc5ea0cd5a1d1ef08d69958ddcd5e906394bafdacba50db3655fec6aa6`** (WoC SEEN). **First time the deployed reshare worked** — proves the fix.
- #40 recovered-device spend TXID: **PENDING** — run #1 (`b742448tu`) failed at the presign step;
  re-run #2 (`bt2xaod31`, log `/tmp/recovery_rerun_2.log`) in flight. See §0 LIVE STATUS.

---

## 8. Prompt to continue (paste into a new session)

```
Continue #40 (lost-phone recovery) in /Users/johncalhoun/bsv/mpc/bsv-mpc on branch
feat/40-recovery-sign-health-zeroize. READ docs/HANDOFF-40-deployed-reshare-fixed.md IN FULL first.

This session ROOT-CAUSED + FIXED the deployed reshare-over-relay hang (CF container's BRC-104
auth Peer handshake hangs; BRC-103 WS path works) via a bounded best-effort drain_backfill in
crates/bsv-mpc-messagebox/src/subscribe.rs — and PROVED it on mainnet: container_reshare passed
(TXID 6c0f17cc…). The full #40 gate (recovery_spend_deployed_mainnet_e2e) was running.

DO, in order: (1) check /tmp/recovery_mainnet_run_final.log for the #40 recovery_spend TXID; if PASS,
WoC-confirm it and comment on #40; if FAIL, ensure the warm WS-fixed container image is live
(GET /reshare-relay/debug → count:0) and re-run the gate. (2) Clean up the relay-reliability changes:
keep bounded-backfill + message_id dedup + ResharHandler early-inbound buffer + background post-join
re-drain; REVERT the speculative IPv4-prefer connect (transport_native.rs) and likely the polling
fallback. (3) Re-run all gates yourself (clippy 4 native --all-targets + wasm worker, lib tests,
hermetic recovery-sign + reshar_full loop; CARGO_INCREMENTAL=0). (4) Show me the diff, get approval,
commit to the branch; update #58 with the root cause; file a bsv_rs issue for the auth Peer BRC-104
handshake hang (+ no-timeout reqwest client at bsv-rs transports/http.rs:497).

Discipline: 110% no asterisks; NO commit/push/deploy without showing the diff and getting approval;
re-run every gate yourself; don't ship speculative cruft.
```
