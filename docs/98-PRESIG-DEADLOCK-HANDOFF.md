# Handoff — on-device 4-of-6 presig deadlock (#98 / 100cash#31)

**Status: OPEN. Root cause NOT yet found.** A real bug was found + fixed (`5fa31d5`) but it is
**not** the deployed bug — drive 9 (with the fix, both sides rebuilt) is **byte-identical** to
drive 8 (pre-fix). Do not assume the fix helped the live ceremony; it did not.

North star: ship the on-device 4-of-6 mainnet send (100cash#31). The ONLY remaining blocker is
this presig deadlock. Person A owns `~/bsv/mpc/bsv-mpc` (Rust/MPC/FFI/relay). Person B owns
`~/bsv/mpc/100cash` (iOS app, XCFramework build, device runs). Person A does NOT touch 100cash.

---

## THE DEPLOYED BUG (precise, from the dual-instrumented drives 8 & 9)

A 4-of-6 presign-over-relay: the **device hosts w=t−1=3 local parties {0,1,2}**; **one notary
container is the external cosigner at index 3** (4-party signing subset `{0,1,2,3}`, contiguous).
It **deadlocks**, device `coord.assembly_wait` pins at the 600s budget, times out (~637s).

What the instrumentation shows (identical across drive 8 pre-fix and drive 9 with `5fa31d5`):
- device `presig.timing` → `sends: r6=[0,1,3] r7=[0,1,2,3]` (+ `r1` via the `ship_round1` stage),
  `dropped:` **EMPTY**.
- cosigner `/presign-relay/debug` `timing` → `sends: r7=[0,1,2]`, `dropped:` empty.
- rounds that reach party 3 (cosigner): **`[1, 6, 7]`** only.
- **Middle wire-rounds 2,3,4,5 are NEVER EMITTED by either side** (absent from both `sends` AND
  `dropped` → the SM never produced them; it is not a routing/wrap_protocol drop, and delivery of
  what IS sent is perfect — the cosigner receives exactly r1,r6,r7).
- Both sides execute ~9–10 handler rounds (`handler.round.exec`) but only **3 distinct wire-rounds
  (1,6,7) ever cross.**
- DKG healthy (261–358s), custody fine (`task:share_durably_custodied`), no 404, no scale-to-zero.

**Interpretation:** the stall is UPSTREAM of completion. Something gates the emission of the
middle rounds; both SMs reach the same wall and neither advances → mutual deadlock at (Person B's
phrase) the "1→2 boundary." The "1→6/7 jump skipping 2-5" smells like a **round-index mapping
mismatch** (the SM's internal round vs the relay/transport message tag) OR the **handler's
`pending_inbound` slot-checkout replay** losing/mis-sequencing buffered inbounds under reordered
delivery. NOTE the wire `round` field is the SENDER's `current_round` call-counter, NOT the cggmp24
SM round (the SM routes by message *type*, not round number — `WireMessage` carries no round). So
the 1/6/7 labels are cosmetic; gaps = receive-only handler calls. Don't over-index on the labels.

---

## WHAT `5fa31d5` FIXED (real bug, WRONG bug for this)

`PresigningManager::process_generate_round` discarded the SM's final-round `outgoing` when the
protocol completed in the same drive (the `Some(presig_output)` arm returned a payload-less
`Complete`). Under reordered delivery a party's final SEND and its COMPLETION can coincide in one
drive → the final message was thrown away → peers waiting on it stall. **This is genuinely a bug**
and is now fixed: `PresigningRoundResult::Complete(Vec<RoundMessage>)` carries the final messages;
`presign_handler` ships them. Guarded by `nparty_presign_survives_reordered_delivery`
(crates/bsv-mpc-core/src/presigning.rs — RED without the fix, GREEN with it, ~60s).

**Why it did NOT fix the deployed deadlock:** the live ceremony deadlocks BEFORE completion
(rounds 2-5 never emitted, never reaches the ship-on-completion path). The repro test drives an
*adversarial highest-round-first* reorder that happens to trigger the completion-coincidence; the
DEPLOYED reorder triggers a DIFFERENT failure (middle-round gating, no completion). So the repro is
a valid regression guard for a real bug, but it does NOT reproduce the deployed pattern. **The next
repro must reproduce drive-8's signature: rounds 1,6,7 cross, 2-5 never emitted, NO party
completes.** Keep `5fa31d5` — it's correct.

---

## ELIMINATION LEDGER (ruled out with hard evidence — do NOT re-chase)

- **Apple HTTP = rustls / TLS (#96):** FALSE. bsv-rs forces reqwest `default-tls` → native-tls
  (Security.framework) already on iOS device+sim. cargo-tree proof. TLS is not the lever.
- **Device CPU / #98 runtime (multi-thread):** device does its real work in ~2s; `await≈exec`
  (no blocking-pool starvation). The 623a447 multi-thread runtime is healthy.
- **Live MessageBox relay:** healthy — macOS in-process cosigner does the same presign in ~56s.
- **Notary cold-start / scale-to-zero:** refuted (in-memory `/debug` trail survived 105 min;
  uptime monotonic across probes).
- **Notary durable-custody / #102 / share-404:** fixed + healthy; DKG custody lands every run.
- **WS-push lossy delivery (the egress-NAT drop):** REAL and FIXED — the reliability drain
  (scoped to presign boxes, per-poller dedup) recovered a WsPush-dropped round on-the-wire. But
  it is NOT this deadlock (you can't recover from the box what was never sent).
- **wrap_protocol routing / index drop:** NOT it — `dropped:` is empty; the SM never emits 2-5.
- **Final-message-discard-on-completion:** REAL, FIXED (`5fa31d5`), but NOT the deployed bug.
- **Stale build / didn't rebuild:** ruled out — Person B verified the linked `.a`
  (size 70343008, mtime Jun 1 11:27 sim slice) is the `5fa31d5` rebuild.

---

## INSTRUMENTATION (already deployed + in the binary — use it)

- Device timeout error string carries `presig.timing` with `... | sends: r{n}=[parties] |
  dropped: r{n}=[abs]`. `sends` = what `run_loop` posted (per round→recipient). `dropped` = what
  `wrap_protocol` discarded (round→bad target abs; `?` = untranslatable position). Code:
  `crates/bsv-mpc-core/src/presig_timing.rs` (`record_send`, `record_dropped`, `summary`).
- Cosigner: `GET https://bsv-mpc-service-container.dev-a3e.workers.dev/presign-relay/debug` →
  `steps` (arm:share_loaded → round1_shipped → hdl:rx round=N from=P → round3_done → return_built)
  + a `timing` field (the cosigner's own sends/dropped — `presig_timing` is armed in
  `handle_presign_relay_init`). `/dkg-relay/debug` similarly.
- The presign-handler background checkpoints (`hdl:rx`, `hdl:round3_done`, `hdl:return_built`) live
  in `crates/bsv-mpc-service/src/presign_handler.rs` (`dispatch_one`, `on_presign_complete`).

---

## NEXT STEPS (for the next session — in order)

1. **Build a repro that matches drive-8's signature** (rounds 1,6,7 cross, 2-5 NEVER emitted, no
   completion). The existing repro reaches completion, so it's the wrong scenario. Likely needs
   to drive through the **handler** (`presign_handler` + its `pending_inbound` slot-checkout
   replay), OR to replay the EXACT deployed delivery order, not an arbitrary adversarial one. The
   handler layer (concurrent dispatch + buffering) is the prime suspect that the direct-manager
   repro skips.
2. **Investigate the round-2 emission gate:** what input does each party's SM block round-2 (the
   first MtA/echo batch) on? Is that input (a) produced by peers, (b) delivered, (c) consumed by
   the SM? Check cggmp24 presigning's RELIABLE-BROADCAST echo: if the round-1 broadcast isn't
   echo-verified, the protocol won't advance to round 2. Trace `drive_inline`
   (crates/bsv-mpc-core/src/dkg.rs:861) feeding the rounds_router
   (~/.cargo/.../round-based-0.4.1/src/rounds_router/) — confirm out-of-order broadcast+echo are
   actually buffered, not silently parked.
3. **Add handler-side `pending_inbound` instrumentation** (buffered/replayed counts per round) to
   the cosigner, redeploy, re-run — see whether the cosigner BUFFERS the device's middle-round
   inputs and never replays them.
4. Once reproduced locally + fixed, ONE final both-sides rebuild + re-run → presig should complete
   → fund + send → mainnet TXID → close #31.

Person B's open question answered: **HOLD** (don't clean-room rebuild — binary evidence is
conclusive; the fix simply doesn't address this deadlock). Wait for the next image.

---

## ARTIFACTS / STATE

- Repo: `~/bsv/mpc/bsv-mpc`, branch `main`, HEAD `5fa31d5` (pushed). Working tree: only the two
  uncommitted audit docs (`docs/67-WEB-CUSTODY-AUDIT.md`, `docs/CONVERGENCE-AUDIT-2026-05-27.md`)
  — NEVER commit those. (This handoff doc is new; commit it if you want it tracked.)
- Key commits this saga: `eaa3729` (presig_timing) → `c6b7363` (scoped reliability drain + DKG-safe
  + send-routing diag) → `5b521c6` (wrap_protocol drop log + cosigner-side timing) → `5fa31d5`
  (final-message-discard fix + reorder repro test).
- Deployed cosigners (both on `5fa31d5`, confirmed fresh uptime=0):
  - Notary A: `bsv-mpc-service-container.dev-a3e.workers.dev` (image 25c2728e).
  - Notary B: `bsv-mpc-service-container-b.dev-a3e.workers.dev` (image cde4619e).
- Deploy: `cd poc/cf-container-p2[ -notaryb] && eval "$(grep '^export CLOUDFLARE' ~/bsv/mpc/bsv-mpc/secrets.md)" && npx wrangler deploy --containers-rollout=immediate`.
  Rollover gotcha: the old instance keeps serving until traffic stops — go quiet ~110s, then
  `/health` `uptime_seconds:0` confirms the new image is live (the `--containers-rollout=immediate`
  + your own probes fight each other). Docker build ~15-20 min, builds the workspace from the root
  Dockerfile (picks up the working tree).
- Gates (CI = clippy + fmt): `cargo clippy --workspace --all-targets -- -D warnings`;
  `cargo clippy -p bsv-mpc-client --features native --all-targets -- -D warnings`;
  `cargo clippy --target wasm32-unknown-unknown -- -D warnings`; `cargo fmt --all -- --check`
  (format only edited MODULE files, not crate roots). NO commit/push without explicit user OK.
  Mainnet only, never testnet; no mainnet TXs in CI.
- Local repro to extend: `cargo test -p bsv-mpc-core --lib nparty_presign_survives_reordered_delivery -- --nocapture` (~60s; uses a real 3-of-3 DKG sim via Blum test primes — see `run_dkg(n,t)` helper in the presigning test module).

---

## SESSION UPDATE — 2026-06-01 (Person A, working tree; NOT yet committed/deployed)

### Re-read of drive-8: the stall is a SWALLOWED SM ERROR at the reliability gate

Mapped cggmp24 presigning's true round structure (`cggmp24/src/signing.rs:832-837`):
`round1a`(bcast,round **0**) → `round1b`(p2p,**1**) → **`round1a_sync`** = the reliability echo
(bcast, ProtocolMessage round **5**) → `round2`(MtA p2p,**2**) → `round3`(bcast,**3**). A party
emits round2 the INSTANT its reliability check passes. drive-8's "~9–10 handler rounds then NO
round2" = it consumed round1a(×3)+round1b(×3)+round1a_sync(×3) and then **either** the reliability
check ABORTED the SM (`SigningAborted::Round1aNotReliable`, a round1a-set/hash disagreement, or
`AttemptToOverwriteReceivedMsg` from a dup) **or** it is still missing one `round1a_sync`. Both
manifest identically today: `drive_inline` returns `Err` → `dispatch_one` returns `Err` →
`messagebox::run_loop` swallows it with a `warn!` the **stdout-less device can't show** → the
coordinator just times out 600s "awaiting PresigBundle assembly". **The real cause was invisible.**

Hermetic logic is SOUND (macOS capstone + `nparty_presign_survives_reordered_delivery` both pass;
rounds_router buffers out-of-order; handler `pending_inbound`/dedup/contiguous-index translation all
verified correct), so the stall is device-transport/timing specific and needs device data to pin.

### Shipped this session (working tree, gates green, NOT committed)

1. **Diagnostics that crack drive-8 on the NEXT image** (the actual unblock):
   - `presig_timing::record_recv(round,from)` → surfaces `recv: r0=[…] r1=[…] r5=[…] r2=[…]` by
     **TRUE cggmp24 round** in the device timeout summary AND cosigner `/presign-relay/debug`. Fed
     from `drive_inline` (`dkg.rs`, gated `not(wasm32)`; `M: ProtocolMessage` bound added). A peer
     missing from `r5` (no `r2`/`r3`) = a never-arriving reliability echo. Full `r0/r1/r5` + no
     `r2` = a reliability ABORT.
   - `presig_timing::record_error(reason)` + `presign_checkpoint("hdl:SM_ABORT …")` in
     `presign_handler::drive_protocol` (and the initiate-replay swallow) → the EXACT cggmp24 abort
     string (`Round1aNotReliable(parties [..])` / overwrite / …) folds into the device timeout
     summary + cosigner `/debug`, instead of an opaque 600s timeout.
2. **Fixed a REAL, reproducible bug (`early-return-share loss`)** — NOT drive-8 (it needs the
   presign to COMPLETE), but it would bite the moment drive-8 is fixed, and it ALSO produces the
   exact "awaiting PresigBundle assembly" timeout: `collect_return_share` returned `Ok(())` when a
   cosigner's return ciphertext reached the coordinator BEFORE the coordinator's own round-3 opened
   the collection slot — the "leave un-acked for redelivery" comment was FALSE (`run_loop` acks
   every inbound regardless of outcome → it was deleted from the relay forever → bundle never
   assembled). Fix: BUFFER early return shares (`pending_return_shares`), replay them when
   `on_presign_complete` opens the slot. Guarded RED→GREEN by
   `crates/bsv-mpc-service/tests/presign_early_return_share_repro.rs` (hermetic 2-party in-memory
   bus, deliver-exactly-once like the acking listener; deterministically forces the early-return
   ordering; **verified RED with the fix reverted**, GREEN with it).

Gates all green (workspace+client-native+wasm clippy `-D warnings`, fmt on edited modules,
`presig_timing`/`presign_handler` unit tests, the `5fa31d5` reorder guard).

### NEXT STEP (recommended) — needs user OK to deploy/commit

ONE both-sides image (rebuild XCFramework for the device + redeploy BOTH notary containers off this
working tree) then re-run the on-device 4-of-6 presign. The timeout error string (and each notary's
`/presign-relay/debug`) will now name the precise failure:
  - `errors: [… Round1aNotReliable(parties [k])]` → a round1a-set disagreement; chase WHY party k's
    round1a view differs (dup/corruption/serialization on the device WS path).
  - `recv: … r5=[a,b]` missing a peer (no `r2`) → that peer's reliability echo never arrived; chase
    the egress-NAT delivery of THAT broadcast leg (reliability-drain gap for one recipient).
  - bundle-assembly stall with all rounds present → the early-return-share fix (now in) resolves it.
Then fund + send → #31 TXID. (Mainnet only; no mainnet TXs in CI.)
