# Audit — #43 policy engine + approval flow + WebAuthn (step:investigate)

> **Verdict: realizable as a from-scratch build in `bsv-mpc-core`. NO new crypto.
> NO rust-mpc code ported verbatim. NO `bsv-sdk` dependency.** rust-mpc's
> `crates/policy/` is a *reference for decision logic only*; the canonical wire
> (PolicyManifest CBOR, Verdict, ApprovalQuorum, approval signing) is built to
> MPC-Spec §09 on our existing `bsv-rs`-based primitives.

## 1. What exists (foundation — do NOT rebuild)
- `bsv-mpc-core/src/types.rs::PolicyId` — 32-byte manifest hash; CBOR `bstr32`
  wire shape (byte-locked, used as the presig-binding label in #30/#38).
- `bsv-mpc-core/src/approval.rs::request_view_hash` — the §09.5.1 8-field
  canonical-CBOR binding, byte-locked (`conformance_09` green, shared vector
  identical to MPC-Spec). **The approval signing preimage's `request_view_hash`
  component is done.**
- BRC-31 auth (`brc31_client`), BRC-78 envelope (`envelope.rs`), MessageBox §06
  transport (`bsv-mpc-messagebox`) — all deployed, all on `bsv-rs`.
- **No policy engine / Verdict / PolicyManifest / approval flow exists.** Confirmed
  by full grep. #43 is net-new.

## 2. rust-mpc `crates/policy/` — reference value + why we don't port verbatim
- **Reusable decision-logic patterns:** the 4-variant verdict (Allow / Deny /
  RequireApproval / RateLimited), first-match-wins rule eval, `max_amount_sats` +
  `max_per_hour` sliding-window (1-hour) rate limiting, the glob pattern matcher.
- **NOT reusable as-is:**
  - Serializes policy as **JSON**, not the canonical **CBOR** the spec mandates
    (§09.2). Wire would not be cross-impl byte-equivalent.
  - `RequireApproval(Vec<PartyId>)` ≠ spec's `RequireApproval(ApprovalQuorum{k,
    eligible})`. No k-of-m.
  - `tokio::sync::RwLock` in the engine (audit-log + rate counters) → **not
    wasm32**. Our engine must be sync + wasm-portable (bsv-mpc-core is wasm-built).
  - Pulls `bsv-sdk = "0.2"` transitively via `mpc-core` types — **forbidden** (we
    use `bsv-rs`). The policy crate itself is BSV-SDK-free, but its `mpc-core`
    type deps are not; porting the *types* would drag it in. So we define our own.
  - Spec §09.13 itself lists deltas rust-mpc is MISSING: `min_fee_sats`,
    `RequireAttestation`, `cumulative_daily_cap_sats`, `allowed_window`,
    counterparty allow/deny, `jurisdiction`, k-of-m `ApprovalSpec`.

**Decision: build the engine in `bsv-mpc-core` (wasm-portable; already hosts
`approval.rs`, `canonical.rs`, `PolicyId`).** A separate `mpc-policy-shared` crate
(spec §09.13 suggestion) buys nothing here — rust-mpc can't link it (different SDK
+ JSON), and cross-impl conformance is achieved by the **shared test vector**
(`conformance/test-vectors/09-policy.json`), not shared code.

## 3. Canonical shapes to build (MPC-Spec §09.2 / §09.5)
- `PolicyManifest` — 12-field canonical-CBOR map (version, policy_id,
  cosigner_identity, group_key, rules, default_action, effective_after_ms,
  expires_after_ms?, prev_policy_id?, approver_keys, approver_sigs, dry_run).
- `Rule` — 11-field map (protocol_pattern, max_amount_sats?, max_per_hour?,
  cumulative_daily_cap_sats?, allowed_window?, counterparty_allowlist?,
  counterparty_denylist?, min_fee_sats?, jurisdiction?, approval_spec?,
  attestation_spec?).
- `DefaultAction = "Deny" / {"RequireApproval":[bstr33]} / "EscalateToHuman"`.
- `Verdict = "Allow" / {"Deny":tstr} / {"RequireApproval":ApprovalQuorum} /
  {"RateLimited":{retry_after_secs:u64}}`.
- **3 hooks** (§09.3): `check_derivation`, `check_presigning`, `check_signing` —
  the §09.3 fix is that presigning MUST be gated (rust-mpc allows it
  unconditionally). Each hook returns a `Verdict`.
- Pattern matcher (§09.7): `*`, `prefix/*`, `prefix/middle/*`, exact. No regex, no
  leading `*`, no multi-segment wildcards; reject invalid patterns at load.

### v1 enforcement scope (gate-relevant subset; rest parsed-but-deferred)
ENFORCE in v1 (covers the §09.14 vectors + the mainnet gate): pattern match,
`max_amount_sats`, `min_fee_sats`, `max_per_hour` (sliding window),
counterparty allow/deny, `approval_spec` (→ RequireApproval), `default_action`,
`dry_run`. PARSE-but-DEFER (round-trip in CBOR, not yet enforced — they need geo /
TEE / wall-clock context not present in v1; documented in code): `jurisdiction`,
`attestation_spec`, `allowed_window`, `cumulative_daily_cap_sats`. This is
honest: the manifest is fully canonical/round-trippable; enforcement of the
deferred fields is a tracked follow-on, not a silent gap.

## 4. ⚠️ SPEC AMBIGUITY to reconcile (cross-impl-critical) — flagged, not guessed
**`policy_id` hash domain.** §09.2 line 28 comment: `policy_id = SHA-256(canonical
CBOR of fields 3+)`. §09.8: signatures are "over the canonical CBOR encoding of
fields **1-10**." These disagree on whether `version` (field 1) is in the
policy_id preimage. Cross-impl byte-equivalence REQUIRES one answer.

**Proposed (pending MPC-Spec reconciliation, mirroring the #39 / MPC-Spec#42
8-field reconcile):** `policy_id = SHA-256(canonical_CBOR(map of fields
{1,3,4,5,6,7,8,9,10}))` — i.e. all of 1–10 EXCEPT the self-referential field 2;
exclude 11 (sigs) and 12 (dry_run, operational not identity). Rationale: §09.8's
"signatures over fields 1-10" is the explicit normative statement, and the sig
must cover `version` (downgrade protection, §09.9). `bstr` field 2 is obviously
self-excluded. **Implemented with this choice in `policy.rs::compute_policy_id`,
clearly marked in code.**

**SECOND reconciliation item (nested key convention):** §09.2's CDDL NAMES the
nested sub-shapes with TEXT keys (`{"RequireApproval":…}`, `ApprovalSpec = {k,
eligible}`, `TimeWindow`, `Jurisdiction`, `AttestationSpec`) but numbers the
top-level `PolicyManifest`/`Rule` with INTEGER keys. The engine uses integer keys
throughout (one internally-consistent canonical form). **There is NO locked §09
CBOR vector yet** (`09-policy.json` is referenced but unverified; rust-mpc uses
JSON), so neither convention is byte-verifiable today. Both items (field-set +
nested-key) must be settled by an MPC-Spec vector + rust-mpc cross-check before
the §09.15 CI conformance gate. Until then `policy_id` is a deterministic in-impl
binding label (sufficient for the #43 mainnet gate); it is NOT yet a cross-impl
byte anchor. **Open an MPC-Spec issue to lock both before cross-impl CI.**

## 5. Approval flow (§09.5.1) — all on bsv-rs primitives we already have
1. On `RequireApproval`, compute `request_view_hash` (✅ `approval.rs`, done).
2. Emit approval-request envelope to each `eligible` approver over the relay
   (reuse `bsv-mpc-messagebox` + `envelope.rs` BRC-78 + BRC-31 — the SAME
   substrate the #38 device-holds relay sign uses; default TTL 300s).
3. Approver `approve()` signs `BRC-77(request_view_hash ‖ "mpc-approval-v1" ‖
   session_id)` — 80-byte preimage (32 ‖ 16 ‖ 32), binary concat, no separators.
   Signing uses `bsv-rs` ECDSA (same as BRC-31).
4. Coordinator collects until k-Allow (proceed) / k-Deny (abort) / deadline.
5. Then sign via the existing device-holds relay path (#38).
- SDK `mpc.approve()` (ADR-0035) + requester status surface
  (`{collected,total,deadline_ms_remaining,eligible_responded,status}`).

## 6. WebAuthn (§08.11)
`clientDataJSON.challenge == request_view_hash`, `userVerification=required`. A
verification primitive in core (parse clientDataJSON, assert challenge ==
request_view_hash); full passkey ceremony wiring lands with the #41 client shells.

## 7. Build order (tasks #8–#11)
1. **#8 engine** (this increment): manifest CBOR round-trip + `compute_policy_id`
   + Verdict + 3-hook eval + pattern matcher + §09.14 conformance vector + clippy/
   wasm/tests. Self-contained, gateable by green tests (no TXID — not a signing path).
2. **#9 approval flow** + SDK `mpc.approve()` — emit/collect over relay, BRC-77
   approve, quorum; wire `check_signing == RequireApproval` → collect → device-holds sign.
3. **#10 WebAuthn** binding verifier.
4. **#11 mainnet GATE**: real-sats spend that hit RequireApproval, collected a
   k-Allow approval over the relay, then signed (device-holds path) + WoC-confirmed.

## 8. Discipline
110%, no asterisks. Engine proven by byte-equivalent conformance vectors (the
spec's §09.15 CI requirement); the deployed mainnet TXID proof comes with #11.
clippy (4 native + wasm worker) warning-free; CARGO_INCREMENTAL=0.
