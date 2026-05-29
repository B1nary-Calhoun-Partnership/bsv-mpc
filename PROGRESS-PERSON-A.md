# Person A — Progress (bsv-mpc, crypto + spec lane)

> Live status. Update after each step. Sibling file:
> `100cash/PROGRESS-PERSON-B.md`. Full context: `PERSON-A-HANDOFF.md`
> (read its "🎯 Overarching goal" block first — it is the shared truth with Person B).

**🎯 Overarching goal (shared with Person B):** ship **4-of-6 PRODUCTION** god-tier
self-custody on 100cash — t=4, n=6, device-held shares + **two independent Notary
cosigners**, plumbing over the audited `bsv-mpc-core` (**no new MPC protocol**),
**mpc-spec-conformant**. We are at 2-of-2 today only because client multi-share isn't
wired. **#69 is THE critical path** (client `my_indices: Vec<ShareIndex>`); **#70** makes
the two network-side cosigners genuinely independent. Once #69 lands, Person B flips
`NativeBackendConfig` to real 4-of-6 → capstone 100cash#31.

**Started:** 2026-05-28 (4-agent audit; issues #73-#81 filed + comments on #69/#70).

---

## Status legend

- ☐ `NOT STARTED` — not yet picked up
- ☐ `DESIGNING` — thinking through approach; user-decision pending
- ☐ `IN PROGRESS` — code being written
- ☐ `BLOCKED` — needs user input / external dep / cross-stack
- ☐ `READY FOR PR` — branch up, awaiting user OK to push
- ☐ `SHIPPED` — merged to main

---

## Issues (priority order)

### ☐ `IN PROGRESS` — bsv-mpc#69 — n-party provisioning + sign seam — ★ THE CRITICAL PATH to 4-of-6 production

**Locked decisions (2026-05-28, user):** (a) NEW seam in `bsv-mpc-client` (the n-party
SIGNING machinery is already shared in `bsv-mpc-relay`, so (b)'s extraction is redundant);
provisioning = **genuine 6-party DKG over relay** (device drives 3 logical parties,
cosigner(s) drive the other 3) — bigger than reshare + not yet mainnet-proven, chosen for
the strongest entropy/topology story. Phased to keep each PR independently green
(no asterisks). Quality bar (user): **prove 110% at each step, zero caveats.**

**PR-1a — device-holds combine kernel — ✅ SHIPPED + MERGED (bsv-mpc PR #83, commit `8c8c7bb`):**
- `bsv-mpc-core/src/signing.rs`: extracted `device_holds_combine` — the relay-free
  device-holds-(t−1) combine. `bsv-mpc-relay`'s `combine_sign_over_relay_nparty` now CALLS
  it (zero-drift: deployed relay path + tests run byte-identical code).
- Gates ALL GREEN: 3-of-3 device-holds-2 verifies under joint pubkey + BRC-42-offset under
  child key (CI-gated); NEGATIVE sub-threshold → "did not complete"; 4-of-6 real-topology
  `#[ignore]` proof RAN green (joint_pubkey `03e8d7d7…`, 212s). CI: fmt+clippy + native
  (31m30s) + wasm32 (4m19s) all PASS. Merged to main.

**SPEC — ✅ MERGED (MPC-Spec PRs #49 + #50):**
- **ADR-0052** (`#49`) — device-holds-(t−1) multishare + genuine n-party DKG over relay,
  **Model B** (one ceremony identity per held index → wire unchanged, ADR-0051-consistent);
  + §06.22 (DKG over relay), §06.17.1 note, §15.2.4 (device-holds vs any-t tiers),
  `15-device-holds-quorum.json` vector + Python runner gate (24 checks pass). Both stewards
  signed off (Binary OK relayed by user).
- **§13.7.1 / §18.2** (`#50`) — cross-implementation Notary swap: a Notary MAY be replaced
  ACROSS impls (bsv-mpc ↔ rust-mpc) via address-preserving `reshare_replace_party`,
  vector-gated. (Answers "swap 2nd Calhoun cosigner for rust-mpc?" → yes, normatively.)

**PR-2 — `IN PROGRESS` (branch `person-a/69-pr2-nparty-dkg-relay`)** — the big code build,
absorbs the old PR-1b. KEY DE-RISK (workflow `wl5ju8hj2`): it MIRRORS the mainnet-proven
reshare-over-relay path — `provision_wallet_nparty` ≈ `coordinate_reshare_over_relay`
(already runs `Vec<DkgHandler>` per index), `/dkg-relay/init` ≈ `/reshare-relay/init` minus
PSS/throwaway-combine, KEEPING the shares. User-approved 8-step TDD ladder + 5 fork-defaults
(agent_id re-key at completion · once-per-index container arming · DEFER p2p short-circuit ·
reject-unless-owner re-provision · ADD new mainnet test). Top risks tracked: storage-key
collision (step 1 ✓), persistence-before-funding (gate fundable address on post-DKG re-load
verify), CF-container 6-party-DKG feasibility (MEASURE early, container is standard-4),
one-DkgHandler-per-index discipline.

**SERVICE SIDE COMPLETE + PROVEN (branch `person-a/69-pr2-nparty-dkg-relay`, 6 commits):**
- ✅ **Step 1** — composite `(agent_id, share_index)` storage keying. GREEN; `f7075f3`.
- ✅ **Step 2** — DkgHandler composite-persist override + re-provision protection
  (reject-unless-owner). Hermetic GREEN; `e76a430`.
- ✅ **Step 3** — `POST /dkg-relay/{identity,init}` route (mirrors `/reshare-relay/init`,
  DKG-only; `deny_unknown_fields`; `AppState.storage`→`Arc<RwLock>`). Route-unit GREEN
  (shape contract + 412/400 gates); `daad0c7`.
- ✅ **Step 4 — PROVEN ON LIVE RELAY** — genuine 6-party 4-of-6 DKG agreed a
  **byte-identical joint key** over the deployed MessageBox relay: joint_pubkey
  `029b846a…`, address `15naugTY2FycKX5BtpndLkVfGkou5jFaVP`, all 6 shares persisted,
  ~6min. `771600e`. This validates the chosen path on real infra AND resolves the
  CF-container concern (standard-4 + the reshare relay-DKG patterns scale to 6 parties).
- ✅ **Diagnostics** — `/dkg-relay/debug` checkpoint trail (reuse reshare #58
  observability); egress reuses `/reshare-relay/egress-test`. `2b8bd0c`.

**➡️ NEW WINDOW: read `PERSON-A-HANDOFF.md` "🟢🟢 RESUME — 2026-05-29" block FIRST** — it has
the full locked design + exact remaining steps (the design workflow output lives only in ephemeral
`/tmp`, so the handoff is the durable record).

**🔴 TRACKED GATE — bsv-mpc#85** (security, HIGH, pre-existing): cosigner identity fetched over
UNAUTH HTTP → MITM can steer DKG to an attacker co-party. MUST close before god-tier-production
4-of-6 funding (pin master identity out-of-band + sign the fetch + signed co-party challenge).

**🔒 Per-index relay identity = ONE-WAY HMAC, NOT additive** (adversary killed additive: it leaks
`server_priv`, which is also the BRC-31 auth + BRC-2 sealing key). Topology = **2 cosigners, one
holds 2 indices**. See handoff for the exact derivation fn + driver spec.

**CLIENT SIDE — IN PROGRESS (branch `person-a/69-pr2-client-multishare`, off main):**
- ✅ **Step 5a-i** — `bsv_mpc_core::hd::derive_relay_index_privkey(server_priv, session, index)`:
  `reduce_mod_n(HMAC-SHA256(key=server_priv, b"bsv-mpc dkg-relay identity v1" ‖ session(32) ‖
  index_be_u16))`. ONE-WAY (server_priv is the HMAC key — no derived key inverts it). 8 hermetic
  unit tests (determinism, per-index/per-session distinctness, one-way ≠ server_priv,
  keys-on-server_priv, valid key) + **frozen golden vector**
  (`f698e3016303f85f5358e07dbe9b23ae798182cf5d1c5bac93163f6afa40d72d`). 38 hd tests GREEN.
- ✅ **Step 5a-ii** — `handle_dkg_relay_init` now derives a per-index relay identity (distinct relay
  room per held index) + new read-only `GET /dkg-relay/peer-identity?session&index` →
  `relay_pub_hex`. Route-unit tests: route↔core golden cross-check + per-index distinctness + 400
  (bad session) + the 412-no-identity case still GREEN. Container-internal ⇒ NO new cross-impl wire
  ⇒ no gate-4 spec PR.
- ✅ **Step 5b** — `bsv_mpc_relay::coordinate_dkg_over_relay` (NEW, sibling to
  `coordinate_reshare_over_relay`; user-approved relay placement) + thin
  `bsv_mpc_client::native_io::provision_wallet_nparty` wrapper (handshake → coordinate →
  composite-seal `{agent_id}#{index}`). `CosignerEndpoint { init_url, indices, arm_signer }`
  natively supports the 2-cosigner / one-holds-two topology. Hermetic: 2 client unit tests
  (validate-don't-skip topology + fail-closed) + 1 coordinator guard (no-network reject). **Live
  E2E PROVEN GREEN** `tests/dkg_4of6_multiindex_relay_e2e.rs` (device {0,1,2} + ONE in-process
  container holding {3,4,5} via 3 one-way-derived identities, over the deployed relay):
  **joint_pubkey `027545996f0074c9c3eaf9835c8a53052c4581ed084e3b1222e2d6f72eb9c13798`, addr
  `1DbuHHwfUVFZxgSfhsNaBM7hQ12EDoFbiG`, 365s** — device 3 distinct signable shares at {0,1,2} +
  ONE container persisted 3 distinct composite shares at {joint}#{3,4,5}. fmt + clippy
  `-D warnings` workspace-wide GREEN; hd 38 / messagebox 27 / route-unit 4 / client-unit 3 GREEN.
  - **DEBUG (2 god-tier fixes from the live run, both production-correct):**
    (1) **pre-seed device primes** (was late-seed) — a device backing `w=t−1` parties must
    pre-generate safe primes, else it inline-generates *inside* auxinfo `proceed()`, blocking the
    thread for minutes (would freeze a phone). (2) **idempotent transport retry** — added
    `MessageBoxClient::send_round_message_reliable` (stable message_id → relay no-ops re-sends →
    exactly-once) + the `MessageBoxListener` now retries sends 4× w/ backoff. A transient
    `/sendMessage` blip previously DROPPED a round message → ceremony stall; this hardens
    **every** ceremony (DKG/sign/presign/reshare) on the deployed cosigner. ⚠️ touches shared
    `bsv-mpc-messagebox` + `bsv-mpc-service` (deployed path) — additive + safe (idempotency
    guaranteed by the relay's existing (recipient,box,message_id) dedup); all existing tests green.
- ✅ **Step 6** — `my_indices: Vec<u16>` added to `WalletMeta` + `FfiSignerConfig` (+ back-compat
  mapping in `connect`: empty → `[device_share_index]`); `create_wallet`/`recover_wallet` set
  `my_indices=[device_share_index]`; new `create_wallet_nparty` + `FfiNpartyCosigner` FFI
  (validates topology fail-closed via `provision_wallet_nparty`; sign quorum = my_indices + ONE
  trigger cosigner). 2-of-2 back-compat GREEN (client lib 41 + hermetic_sign 3); clippy clean
  default **and** `--features native`. Full deployed proof of `create_wallet_nparty` = step 8
  (mirrors how `create_wallet`/`recover_wallet` are proven by their deployed e2e).
- ⏳ **Step 7 (IN PROGRESS) — SCOPE FINDING confirmed + filed as [bsv-mpc#86].** The combine/sign
  CONSUME side EXISTS + is proven (`combine_sign_over_relay_nparty` + the #83 `device_holds_combine`
  kernel + the proxy's `sign_over_relay_device_holds`). **The multi-index presig GENERATION over the
  relay did NOT exist** — the proxy's `DevicePresigSetPool::add_set` is fed ONLY by the test-only
  `gen_presig_set` (holds all 6 shares). Filed #86 (affects client + proxy); user said file-first.
  - **🔒 LOCKED design (Arch 2 — "PresignHandler-everywhere + reconstruct-from-bundle"):** keeps the
    deployed cosigner's presign RUNTIME byte-identical (only `/presign-relay/init` gains a `peers`
    list). Device runs `w` PresignHandlers (primary=coordinator, others=cosigner) + ONE external
    cosigner over the relay → the proven `PresigBundle`; device RECONSTRUCTS its `w` raw boxes from
    the bundle (unseal own + BRC-2-decrypt co-located, paired with shared `commitments`) + keeps the
    external ct for the sign-time trigger. Rejected the "local-raw PresignHandler role" alt (mutates
    the mainnet-proven completion path → asterisk).
  - **✅ Step 7a sub-steps 1–3 GREEN (branch `person-a/69-pr2-client-multishare`):**
    (1) core `deserialize_party_presig_with_public_data` inverse + round-trip gate (reconstructed box
    drives a BSV-valid 2-of-2 sig; byte-stable; negative) — `bsv-mpc-core` presigning 10/10.
    (2) `/presign-relay/init` n-party `peers` list (mirror `/dkg-relay/init`, back-compat fallback to
    single coordinator, fail-fast if coordinator absent) + composite share load at `my_party_index`
    (`load_share_or_recover_at_index_pub`) — `bsv-mpc-service` 55/55 (4 new `resolve_presign_peers`).
    (3) `bsv_mpc_relay::coordinate_presign_over_relay_nparty` (new `provision_presign.rs`, mirrors
    `coordinate_dkg_over_relay`) + `DoTrigger.presig_id` shipped by `combine_sign_over_relay_nparty`
    (additive; 12 existing literals get `None`) — `bsv-mpc-relay` 6/6 (4 hermetic topology guards).
    fmt+workspace clippy + `-p bsv-mpc-client --features native` clippy all GREEN.
  - **✅ Step 7a sub-step 4 (keystone E2E) PROVEN GREEN ON THE LIVE RELAY:**
    `presign_sign_4of6_multiindex_relay_e2e.rs` — device {0,1,2} + ONE in-process container cosigner
    {3} over the deployed relay: genuine 4-of-6 DKG (joint
    `02c709186cbe1ac811a2f7eb39e17dfeeca4ce7465f009592d300494df981cc32f`, addr
    `1nec9An3paL7P4S19MPzjNntMd5Vk2r1a`, 464s) → genuine n-party presign (3 correlated device presigs +
    438-byte cosigner ct, 521s) → device-holds combine → **BSV-valid signature under the joint key**
    (`1 passed`, 524s). The cosigner generated its OWN presig as a genuine protocol party — no process
    ever held > t−1 shares. This validates the generation half (#86) feeding the proven #83 combine.
  - **🛡 Two production-correct service-side fixes the E2E forced out (n-party path only; 2-party
    deployed runtime byte-identical):** (1) **composite owner-authz** on `/presign-relay/init`
    (`authz_owner_at_index_pub`) — a multi-index wallet records its owner at `{joint}#{idx}`, so the
    old bare-key check was a §08.1 BYPASS; now enforced (composite owner preferred, bare fallback),
    positive+negative unit-tested. (2) **race-closing retry** on the composite share load
    (`load_share_or_recover_at_index_pub`) — a presign armed immediately after provisioning could 404
    before the cosigner's DKG persist landed; bounded retry closes it (genuine miss still 404s).
  - **✅ Step 7b/7c BUILT + GREEN** (unit + both clippy gates + fmt; underlying crypto live-proven by 7a):
    `DeviceMultiPresig` + durable `MultiPresigStore` (atomic single-use consume = CVE-2025-66017
    mitigation; persist/rehydrate/single-use unit-tested) in `native_io/multipresig.rs`;
    `DeployedCosigner::{coordinate_presig_nparty, sign_nparty}` (wrap the proven relay fns with the
    session arm/request signer); `DeployedSigner` multi-index branch — `is_multi()` gate,
    `unseal_device_shares_multi` (composite `{agent_id}#{idx}`), pool + on-demand fallback, reconstruct
    → `sign_nparty` → fail-closed pre-flight. 2-of-2 back-compat intact (client lib 26 default / 43
    native). DECISION: `coordinate_presign_over_relay_nparty` returns raw boxes (proven); the client
    re-serializes to the durable `DeviceMultiPresig` + reconstructs at sign time via the proven core
    inverse (no E2E re-prove needed; the FFI sign auto-routes n-party via the `is_multi()` branch).
  - **⏳ Step 8 — deployed mainnet 4-of-6. BLOCKED on external gates:** (1) DEPLOY the updated
    `bsv-mpc-service` to the CF Container (it runs pre-#86 code — no `peers` list / composite load /
    composite authz); (2) #70 for two INDEPENDENT cosigners (one container holding 3 indices is an
    interim); (3) #85 (MITM) blocks real-sats FUNDING. A deployed NO-SATS 4-of-6 sign (real BRC-31,
    dummy hash) proves the full client wrapper without #70/#85; the real spend → WoC TXID is gated.
- ☐ **Step 8** — mainnet 4-of-6 genuine-DKG E2E (with #70). `provision_wallet_nparty` +
  `create_wallet_nparty` full deployed proof (real BRC-31 + seal) lands here (in-process service
  auth is a dev stub), mirroring how `recover_wallet`'s full proof is its deployed E2E.

**PR-3/#70 — 2nd cosigner + mainnet 4-of-6 E2E** (the audit-closing artifact; pairs with PR-2).

**Why this is THE critical path (2026-05-28 PM):** it is the *only* thing between us and
the overarching goal (4-of-6 production self-custody on 100cash). The 100cash app config
is **4-of-6**, but provisioning 4-of-6 over the deployed cosigner **FAILS** ("no outgoing
messages to bundle") because client multi-share (device holds **t−1 shares**,
`my_indices: Vec<ShareIndex>`) isn't wired in `bsv-mpc-client` — the client FFI
(`FfiSigningSession::new`, `ffi.rs:473`) takes a **single** `share_index: u16`. The
send-path mainnet drive (#75 / 100cash#15) therefore **fell back to 2-of-2**
(deployed-proven). The two closing TXIDs prove the render/sign/broadcast machinery
end-to-end but NOT the real 4-of-6 topology. **#69 unblocks true app-parity (4-of-6)
signing → Person B flips `NativeBackendConfig` to 4-of-6 → capstone 100cash#31.** Pairs
with **#70** (2nd cosigner = two independent Notaries). The other window did NOT pick it
up — it remains un-started Person A work.

**mpc-spec conformance (cite these — keep #69 spec-conformant):** the canonical
§-numbered spec lives at `/Users/johncalhoun/bsv/mpc/MPC-Spec/` (NOT in this repo; no
single `mpc-spec.md`). Governing sections for 4-of-6 / multi-share / share indexing:
- **§00 Quorum profile** (`(threshold, n, party_kinds)`; party≡cosigner; joint pubkey
  invariant across signing subset).
- **§18.3 quorum profiles + §18.2 cross-(t,n) resharing** (address-preserving `(t,n)`
  transitions, 0 sats on-chain).
- **§15 multi-share tiers + direction.md §1.1** — the model #69 implements: `t = w + 1`,
  `w` = device-held share count, `#second-factors ≤ w`; for 4-of-6 the device holds
  `w = t−1 = 3` (`my_indices`), the two Notaries supply the rest.
- **§08.8 threshold-subject** + `ShareIndex` type (`bsv-mpc-core/src/types.rs:103`;
  `ThresholdConfig::new` enforces `2 ≤ t ≤ n`).

**Crypto already proven — orchestration only, no new protocol — at two levels:** mainnet
TXID `febd2877…` (PR #46) AND the in-core POC
`crates/bsv-mpc-core/tests/poc_4of6_device_holds_presig_relay.rs` (keystone
`poc_4of6_device_holds_3.rs`): 4-of-6 DKG → 6 shares, device holds `{0,1,2}` (t−1=3) and
folds parties 1 & 2's partials **locally** (never on the wire) into a valid signature;
NEGATIVE case asserted (device-alone 3<t=4 cannot sign). #69 wires that exact combine
through the **client crate FFI**.

**File:line evidence (from audit):**
- 2-party today at `bsv-mpc-client/src/ffi.rs:756` → `provision/provision.rs:42` → `bsv-mpc-relay/src/dkg.rs:159, 225` (`ShareIndex(1)` hardcoded).
- `FfiDeployedSigner.sign` at `native_io/signer.rs:220` calls `combine_sign_from_bundle_over_relay` (2-party).
- n-party machinery lives only in `bsv-mpc-proxy/src/{bridge,presign_manager,wallet_api,server}.rs` + `bsv-mpc-relay/src/lib.rs:226`.
- ⚠️ `bsv-mpc-client/src/ffi.rs` was edited by the other window's commit `1da783c`
  (added `ffi_p2pkh_unlocking_script_hex` + `ffi_beef_subject_raw_tx_hex`). **Re-diff
  this file before starting** — line numbers above may have shifted.

**Design choice (ask user first):**
- (a) New `provision_wallet_nparty` + n-party `FfiDeployedSigner` variant in `bsv-mpc-client`. Greenfield seam.
- (b) Factor `DeviceShareBundle` / `DevicePresigSetPool` / `device_holds` out of `bsv-mpc-proxy` into a shared crate. DRY but non-trivial extraction (pool behind `Arc<RwLock<...>>` keyed off proxy state).

**Last action:** —

**Blockers:** user design decision (a) vs (b). Pairs with #70 (2nd cosigner) for a real
4-of-6 mainnet closing artifact.

---

### ☐ `NOT STARTED` — bsv-mpc#70 — deploy 2nd Calhoun cosigner (2-Notary independence)

**Pairs with #69** on the critical path. Without two **independent** cosigners live, a
4-of-6 mainnet demo would just use one cosigner twice — not the real topology. #70 makes
the two network-side parties genuinely independent (distinct CA / identity key / deploy
env) per **mpc-spec §13 federation** + **direction.md §1** ("two mandatory sides"). Ops,
not code. **Last action:** — **Blockers:** none — parallel with #69.

---

### ✅ `SHIPPED + CLOSED` — bsv-mpc#75 — canonical_render(intent) + ffi_canonical_render

**WYSIWYS load-bearing. UNBLOCKED Person B's 100cash#15. CLOSED 2026-05-28T19:07Z.**

**🎉 CLOSED 2026-05-28 PM.** The E2E gate is now GREEN: co-closed with
**100cash#13/#14/#15** via TWO real audit-closing **MAINNET TXIDs** (both spend the MPC
joint-key UTXO; ARC `SEEN_ON_NETWORK`; verify on `whatsonchain.com/tx/<id>`):
- `5e527f275ffa796f9a0997b6b0897ec09570a3860a128bd3c69c416b6551abee`
- `d3515c50ed494a656ef25f7bf10d8760159f3ec61562c7625ce289e521c395cb`

The other window's commit `1da783c` ("native-tls MessageBox WS on Apple + send-path
assembly FFIs") landed the simulator TLS fix + two additive FFIs that let the genuine
Swift send chain close the loop. NOTE: the sends used **2-of-2** (the 4-of-6 client
multi-share path is #69, still open). **Do not re-open #75.**

ADR-0044 §2 specifies per-kind formats; no intent classifier existed.
`bsv-mpc-core/src/approval.rs:37-41` literally said rendered_text NOT derivable.

**Locked decisions (2026-05-28):**
- Spec PR for #75 only; #74's spec gets its own PR right after.
- Intent classifier: Rust typed enum, `#[serde(tag = "kind", rename_all = "snake_case")] enum Intent { Payment, TokenTransfer, ScriptSpend, Brc100Internalize, Multi }`. `#[serde(deny_unknown_fields)]` on each variant.
- `<human_address_or_alias>` resolution: pre-resolved by caller — `Intent::Payment` gains required `human_address: String`. `canonical_render` is pure substitution; only in-renderer derivation is the counterparty truncation (`cert_name OR "anonymous" + 0x + pubkey_hex[0..8] + "..."`).
- Conformance runner language: Python alongside existing `runner-python/`.

**Spec PR (DRAFTED, awaiting commit OK):**
- `MPC-Spec/decisions/0044-wallet-renderer-canonicalization.md` — added §2.1 (classifier shape), §2.2 (pre-resolved fields), §2.3 (per-kind required fields, payment gains `human_address`), amendment log.
- `MPC-Spec/conformance/test-vectors/09-rendered-text.json` — payment intent gains `"human_address": "1A1zP1...EQK..."`. Locked preimage CBOR + view_hash bytes UNCHANGED (human_address is upstream of preimage).
- `bsv-mpc/crates/bsv-mpc-core/tests/fixtures/09-rendered-text.json` — vendored fixture kept in sync.

**Code PR (IN FLIGHT — agents spawned):**
- `crates/bsv-mpc-core/src/approval.rs` — Intent enum + `canonical_render` + unit tests
- `crates/bsv-mpc-client/src/ffi.rs` — `ffi_canonical_render(intent_cbor)`
- `crates/bsv-mpc-core/tests/conformance_09_canonical_render.rs` — new conformance gate
- `MPC-Spec/conformance/runner-python/runner.py` — extended with canonical-render gate (Python reference impl)

**Quality gates (status):**
1. UNIT — **GREEN.** 13 new tests in `approval.rs` (5 per-kind positive, cert_name fallback, 0x-prefix strip, unknown-kind reject, missing-field reject, extra-field reject, wrong-type reject, nested-multi extra-field reject, serde round-trip). `cargo test -p bsv-mpc-core --lib approval::` → 29 pass.
2. VECTOR — **GREEN.** New `conformance_09_canonical_render.rs` drives all 5 fixture vectors. `cargo test -p bsv-mpc-core --test conformance_09_canonical_render` → 1 pass (loops 5 vectors). Existing `conformance_09_rendered_text.rs` still GREEN (zero drift on CBOR/view_hash bytes).
3. FFI — **GREEN.** 5 new tests in `bsv-mpc-client/src/ffi.rs` (golden vectors for payment + multi, negative for malformed CBOR, unknown kind, missing required field). All pass under `--features native`.
4. E2E — **🟢 GREEN.** Person B's 100cash#15 landed the mainnet send chain that binds the rendered text → TXIDs `5e527f27…51abee` + `d3515c50…c395cb`. Audit-closing artifact on-chain.
5. SPEC PR — **DRAFTED.** ADR-0044 §2.1/§2.2/§2.3 + amendment log + punctuation tie-break (in §2.2) + fixture payment-vector addition. NEEDS MPC-Spec PR open + merge BEFORE bsv-mpc PR merges.
6. CI — **GREEN.** Python runner is already auto-invoked by `.github/workflows/conformance.yml`; new `canonical_render` gate fires inline. `python3 conformance/runner-python/runner.py` → exit 0, 20 checks pass, 5 canonical_render vectors green, both negative self-tests pass.
7. ZERO-DRIFT — **GREEN.** Existing `conformance_09_rendered_text.rs` continues to byte-lock the preimage + view_hash (unchanged). Python runner's existing CBOR round-trip on 09-rendered-text.json still fires (5 CBOR fields, all pass).

**Last action (2026-05-28):**
- MPC-Spec PR #48 → MERGED to main (commit `a140bd7`). ADR-0044 §2.1/§2.2/§2.3 amendment + Python `canonical_render` reference impl + fixture diff. Branch deleted.
- bsv-mpc PR #82 → MERGED to main (commit `0e90fbe`, squashed). All 3 CI gates green: fmt+clippy (1m02s), wasm32 (5m08s), native (32m15s). Branch deleted.
- GitHub hygiene: status comments on bsv-mpc#75, Calgooon/100cash#15 (Person B), bsv-mpc#69 / #73 / #74 / #70 (queue markers).
- Local main synced; this PROGRESS commit is the final closing housekeeping.

**Blockers:** NONE — all gates green, mainnet artifacts on-chain.

**Issue state:** GitHub bsv-mpc#75 **CLOSED 2026-05-28T19:07Z**, co-closed with
100cash#13/#14/#15. PRs #48 + #82 merged; commit `1da783c` landed the closing send-path
FFIs + simulator TLS fix.

---

### ☐ `NOT STARTED` — bsv-mpc#74 — approval envelope phase + exec_id_prefix

`bsv-mpc-proxy/src/relay_approval.rs:132-133` ships `phase="sign"` (invalid per
ADR-0005 closed enum) + `execution_id_prefix=[0u8;8]` (invalid per ADR-0005 field 10).
**Decision needed:** add `"approval"` to ADR-0005 enum, or repurpose a different
envelope field? Spec PR + code fix paired.

**Last action:** — **Blockers:** spec decision.

---

### ☐ `NOT STARTED` — bsv-mpc#73 — ParticipationProof placeholders

`bsv-mpc-core/src/signing.rs:1028-1047`: `agent_identity = vec![0x02; 33]`,
`participating_nodes` index-stuffed, `fee_txid: None`. Every BRC-18 OP_RETURN
audit proof emitted today is non-conformant. Fix: thread caller-supplied identity
keys + fee_txid, OR patch in proxy. Same file as #69 — consider folding.

**Last action:** — **Blockers:** none.

---

### ☐ `NOT STARTED` — bsv-mpc#71 — post-recovery cooldown / velocity window (post-critical-path)

Velocity window for high-value spends after a recovery (direction.md §3). Policy/security
hardening. Pick up after the 4-of-6 critical path (#69/#70). **Last action:** —
**Blockers:** none — sequence after critical path.

---

### ☐ `NOT STARTED` — bsv-mpc#67 — web client custody & threat model (DESIGN, post-critical-path)

No-enclave browser signing (WebAuthn-PRF seal + below-threshold). Sets up the **web lane**
(same Rust core → wasm) the goal block calls out — natural follow-on once 4-of-6 is real.
⚠️ An untracked draft `docs/67-WEB-CUSTODY-AUDIT.md` exists; **never commit it**.
**Last action:** — **Blockers:** none — sequence after critical path.

---

### ☐ `NOT STARTED` — bsv-mpc#56 — concurrent multi-device sessions (DESIGN, post-critical-path)

Mirror + coordinated presig checkout — the **multi-device lane** in the goal block.
Design-only for now; after 4-of-6. **Last action:** — **Blockers:** none.

---

## Open decisions (waiting on user)

- [ ] **bsv-mpc#69 approach: (a) new seam vs (b) factor proxy out** — ★ the gating
      decision for the next big item (unblocks 4-of-6 app parity).
- [x] ~~bsv-mpc#75 intent-classifier shape~~ — RESOLVED: typed enum (`#[serde(tag="kind")]`
      + `deny_unknown_fields`). #75 shipped + CLOSED.
- [ ] bsv-mpc#74 phase tag value: add `"approval"` to ADR-0005, or different field?

---

## Coordination notes

- **The #75 → 100cash#15 handoff is DONE** — send-path cluster closed via mainnet TXIDs.
  The new single load-bearing handoff is **#69 → 100cash 4-of-6 parity**: until #69 lands
  the app cannot provision/sign at its real threshold (it falls back to 2-of-2).
- **⚠️ native-tls MessageBox WS fix (`1da783c`):** `bsv-mpc-messagebox` now target-splits
  `tokio-tungstenite` TLS — native-tls (Security.framework) on Apple, rustls on Linux —
  to dodge a rustls+ring `EXC_BAD_ACCESS` on the arm64 iOS simulator. **Linux / container
  behavior is UNCHANGED (still rustls, no OpenSSL).** Heads-up if your work touches
  messagebox or any WS path (#69's sign seam uses `coordinate_presign_over_relay`).
- **Person B owns** policy gate RED (#76/#77/#78 — shipped), unbounded HTTP (#79),
  Zeroize (#80), share-metadata auth (#81), 100cash recover (#25) / SE-wrap (#19).
  100cash#13/#14/#15 are CLOSED.
- **Stay out of `bsv-mpc-proxy/src/wallet_api.rs` + `server.rs`** if Person B picks up
  #79/#80/#81 (they re-touch the proxy/policy surface). Re-verify with `git status`.

---

## Daily log

_(append session-by-session notes here)_

### 2026-05-29 LATE PM — #69 step 7 PROVEN + #85 MITM gate built (branch `person-a/69-pr2-client-multishare`, NOT pushed)
- **#69 step 7a LIVE-PROVEN** — genuine n-party presign generation over the relay
  (`coordinate_presign_over_relay_nparty`, new `provision_presign.rs`) feeding the proven #83
  combine → BSV-valid 4-of-6 sig (joint `02c70918…`). Filed [#86] for the gap (file-first, user call).
- **#69 step 7b/7c BUILT+GREEN** — client `DeviceMultiPresig` + durable `MultiPresigStore`
  (atomic single-use) + `DeployedCosigner::{coordinate_presig_nparty, sign_nparty}` + `DeployedSigner`
  multi-index branch (composite unseal + pool + reconstruct → sign). 2-of-2 back-compat intact.
- **2 production-correct service fixes (n-party only; 2-party byte-identical):** composite owner-authz
  (`authz_owner_at_index_pub`, closed a §08.1 BYPASS) + race-closing composite-load retry with a
  fast-path bare read (no 2-party latency regression). Both unit-tested (incl. negatives).
- **#85 MITM gate BUILT+PROVEN (DKG funding path + presign path):** core attestation + funding-challenge
  sign/verify (`hd.rs`, frozen RFC-6979 golden vectors + 5 negatives each); service signs
  `/dkg-relay/peer-identity` (master attestation) + new `POST /identity-challenge`; client
  `coordinate_dkg_over_relay` verifies every per-index attestation vs the PINNED master + runs a
  post-DKG liveness challenge before returning a fundable wallet; presign pins the cosigner master;
  pin threaded through `NpartyCosigner`/`CosignerEndpoint`/`PresignCosignerArm`/`WalletMeta`/FFI.
  Fast HTTP proof `mitm_gate_85_signed_identity` (in-process container; signed responses + MITM
  negatives). Live e2e now PIN the master (proves verify+challenge end-to-end).
- **All gates GREEN** workspace-wide: fmt + `clippy --workspace -D warnings` + `clippy -p bsv-mpc-client
  --features native -D warnings`; unit: core 41 (incl. #85) / relay 6 / service 59 / client-native 43 /
  mitm_gate_85 2 / multipresig store 2.
- **REMAINING #85 surface (recovery flow, not 4-of-6 funding):** reshare-relay + refresh-relay identity
  fetches still unsigned — harden for full closure. **REMAINING capstone:** deploy hardened container(s)
  → #70 (2nd independent Notary) → deployed no-sats 4-of-6 → funded mainnet → WoC TXID.

### 2026-05-28
- Audit landed. 5 issues assigned to Person A (#69, #70, #73, #74, #75). Awaiting first
  session pickup.

### 2026-05-28 PM
- **#75 SHIPPED + CLOSED** (PRs #48 + #82 merged; closed 19:07Z). Co-closed with
  100cash#13/#14/#15 via two real mainnet TXIDs (`5e527f27…51abee`, `d3515c50…c395cb`)
  driven by the other window. E2E gate now green; all 7 quality gates green.
- Other window also shipped commit `1da783c`: native-tls MessageBox WS fix on Apple
  (Linux unchanged) + two additive FFIs in `bsv-mpc-client` (touches `ffi.rs` — re-diff
  before #69). The mainnet sends used 2-of-2 fallback, not the app's real 4-of-6.
- **#69 (4-of-6 client multi-share) elevated to NEXT BIG ITEM.** It's what unblocks true
  app-parity signing; provisioning 4-of-6 currently fails ("no outgoing messages to
  bundle"). Still un-started Person A work; gated on the (a)/(b) design decision.
- Remaining Person A queue: #69 (next), #70 (pairs with #69, ops), #73 (easy filler,
  zero #69 overlap), #74 (needs ADR-0005 spec decision).

### 2026-05-28 (goal-alignment doc refresh)
- Embedded the shared **🎯 Overarching goal** block (byte-identical to Person B's
  handoff) at the top of `PERSON-A-HANDOFF.md`; added a goal frame to this tracker.
- Reframed **#69 as THE critical path** to 4-of-6 production (was "next big item") and
  cited the governing mpc-spec sections: §00 (Quorum profile), §18.3/§18.2 (quorum
  profiles + address-preserving cross-(t,n) resharing), §15 + direction.md §1.1 (`t=w+1`
  multi-share), §08.8 (threshold-subject). The §-numbered spec lives **outside this repo**
  at `/Users/johncalhoun/bsv/mpc/MPC-Spec/` (no single `mpc-spec.md`).
- Noted the in-core POC `poc_4of6_device_holds_presig_relay.rs` already proves the
  device-holds-(t−1) combine — #69 is wiring it through the client FFI.
- Expanded the owned-scope queue to the full open set (added #71 policy, #67 web design,
  #56 multi-device — all post-critical-path). Docs-only; no code/issue changes.
