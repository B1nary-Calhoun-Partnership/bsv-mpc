# Person A — Progress (bsv-mpc, crypto + spec lane)

> Live status. Update after each step. Sibling file:
> `100cash/PROGRESS-PERSON-B.md`. Full context: `PERSON-A-HANDOFF.md`.

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

### ☐ `NOT STARTED` — bsv-mpc#69 — n-party provisioning + sign seam (LOAD-BEARING) — ★ NEXT BIG ITEM

**Why this is now the priority (2026-05-28 PM):** the 100cash app config is **4-of-6**,
but provisioning 4-of-6 over the deployed cosigner **FAILS** ("no outgoing messages to
bundle") because client multi-share (device holds **t−1 shares**,
`my_indices: Vec<ShareIndex>`) isn't wired in `bsv-mpc-client`. The send-path mainnet
drive (#75 / 100cash#15) therefore **fell back to 2-of-2** (deployed-proven). The two
closing TXIDs prove the render/sign/broadcast machinery end-to-end but NOT the real
4-of-6 topology. **#69 is what unblocks true app-parity (4-of-6) signing.** The other
window did NOT pick it up — it remains un-started Person A work.

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

### ☐ `NOT STARTED` — bsv-mpc#70 — deploy 2nd Calhoun cosigner

**Co-blocker** with #69. Without two cosigners live, no real 4-of-6 mainnet demo.
**Last action:** — **Blockers:** none — parallel with #69, ops not code.

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
