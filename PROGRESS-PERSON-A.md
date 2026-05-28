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

### ☐ `NOT STARTED` — bsv-mpc#69 — n-party provisioning + sign seam (LOAD-BEARING)

**File:line evidence (from audit):**
- 2-party today at `bsv-mpc-client/src/ffi.rs:756` → `provision/provision.rs:42` → `bsv-mpc-relay/src/dkg.rs:159, 225` (`ShareIndex(1)` hardcoded).
- `FfiDeployedSigner.sign` at `native_io/signer.rs:220` calls `combine_sign_from_bundle_over_relay` (2-party).
- n-party machinery lives only in `bsv-mpc-proxy/src/{bridge,presign_manager,wallet_api,server}.rs` + `bsv-mpc-relay/src/lib.rs:226`.

**Design choice (ask user first):**
- (a) New `provision_wallet_nparty` + n-party `FfiDeployedSigner` variant in `bsv-mpc-client`. Greenfield seam.
- (b) Factor `DeviceShareBundle` / `DevicePresigSetPool` / `device_holds` out of `bsv-mpc-proxy` into a shared crate. DRY but non-trivial extraction (pool behind `Arc<RwLock<...>>` keyed off proxy state).

**Last action:** —

**Blockers:** user design decision (a) vs (b).

---

### ☐ `NOT STARTED` — bsv-mpc#70 — deploy 2nd Calhoun cosigner

**Co-blocker** with #69. Without two cosigners live, no real 4-of-6 mainnet demo.
**Last action:** — **Blockers:** none — parallel with #69, ops not code.

---

### ☑ `SHIPPED (code) + OPEN (E2E)` — bsv-mpc#75 — canonical_render(intent) + ffi_canonical_render

**WYSIWYS load-bearing. UNBLOCKS Person B's 100cash#15.**

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
4. E2E — **PENDING.** Closes when Person B's 100cash#15 lands a mainnet send TXID that binds the rendered text. The closing TXID is the audit-closing artifact.
5. SPEC PR — **DRAFTED.** ADR-0044 §2.1/§2.2/§2.3 + amendment log + punctuation tie-break (in §2.2) + fixture payment-vector addition. NEEDS MPC-Spec PR open + merge BEFORE bsv-mpc PR merges.
6. CI — **GREEN.** Python runner is already auto-invoked by `.github/workflows/conformance.yml`; new `canonical_render` gate fires inline. `python3 conformance/runner-python/runner.py` → exit 0, 20 checks pass, 5 canonical_render vectors green, both negative self-tests pass.
7. ZERO-DRIFT — **GREEN.** Existing `conformance_09_rendered_text.rs` continues to byte-lock the preimage + view_hash (unchanged). Python runner's existing CBOR round-trip on 09-rendered-text.json still fires (5 CBOR fields, all pass).

**Last action (2026-05-28):**
- MPC-Spec PR #48 → MERGED to main (commit `a140bd7`). ADR-0044 §2.1/§2.2/§2.3 amendment + Python `canonical_render` reference impl + fixture diff. Branch deleted.
- bsv-mpc PR #82 → MERGED to main (commit `0e90fbe`, squashed). All 3 CI gates green: fmt+clippy (1m02s), wasm32 (5m08s), native (32m15s). Branch deleted.
- GitHub hygiene: status comments on bsv-mpc#75, Calgooon/100cash#15 (Person B), bsv-mpc#69 / #73 / #74 / #70 (queue markers).
- Local main synced; this PROGRESS commit is the final closing housekeeping.

**Blockers:** **E2E gate ONLY** — 100cash#15 (Person B) lands a mainnet send TXID via `ffi_canonical_render`. When that TXID lands and gets posted to both threads, #75 + 100cash#15 co-close. Per the quality-gates rule, the issue stays OPEN until the mainnet artifact is on-chain (no asterisks).

**Issue state:** GitHub bsv-mpc#75 stays OPEN with the audit-closing E2E gate. PRs #48 + #82 are closed-merged.

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

- [ ] bsv-mpc#69 approach: (a) new seam vs (b) factor proxy out
- [ ] bsv-mpc#75 intent-classifier shape (discriminant tag? CBOR-tag prefix? typed enum?)
- [ ] bsv-mpc#74 phase tag value: add `"approval"` to ADR-0005, or different field?

---

## Coordination notes

- **Single load-bearing handoff:** #75 → Person B's 100cash#15. Ship #75 first if priority
  is to unblock Person B.
- **Person B is unblocked on 10/11 of their items.** Person B does NOT wait on you for
  policy gate RED (#76/#77/#78), unbounded HTTP (#79), Zeroize (#80), share-metadata
  auth (#81), 100cash send-path wiring (#13/#14), recover wiring (#25), or SE-wrap (#19).
- **Stay out of `bsv-mpc-proxy/src/wallet_api.rs` + `server.rs`** while Person B is on
  the RED cluster (#76/#77/#78). After that lands you can fold #73 into a separate PR.

---

## Daily log

_(append session-by-session notes here)_

### 2026-05-28
- Audit landed. 5 issues assigned to Person A (#69, #70, #73, #74, #75). Awaiting first
  session pickup.
