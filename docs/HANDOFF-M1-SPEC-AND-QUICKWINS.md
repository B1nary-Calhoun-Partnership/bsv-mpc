# Handoff — M1 Spec Lock (#2) + Quick Wins (#3): #55, #17, #14

> **Purpose.** Implementation-ready handoff for the two next-best-step buckets after #40 landed
> on mainnet (TXID `f8b51458…`). Produced by a 3-agent audit swarm (2026-05-26). Every item below
> has: current state (quoted), the exact change (file:line), the test, dependencies, and an
> M1-blocking verdict. A fresh session should be able to execute each item from this doc alone.
>
> **Context.** Repos: spec `~/bsv/mpc/MPC-Spec/` (GitHub `B1nary-Calhoun-Partnership/MPC-Spec`),
> impl `/Users/johncalhoun/bsv/mpc/bsv-mpc`. **Today: 2026-05-26.** **M1 cross-impl demo: 2026-05-29
> (3 days).** **Phase 0 spec-lock: 2026-06-12.** Cross-impl partner: rust-mpc (Binary / Mitch steward,
> Ishaan implementor). Partnership is **async-only** (Slack + GitHub + proofs); **no commit/push/PR
> without showing the diff + approval.**
>
> **Overall read (from the graphify pass `docs/STATE-2026-05-26.md`):** crypto + infra are proven and
> settled; the only dated/imminent gate is the **cross-impl/rust-mpc joint leg for M1**, and #2 below
> is the bsv-mpc-side spec work that gate needs. #3 are cheap, independent robustness wins.

---

## PRIORITIZED EXECUTION ORDER (across both buckets)

1. **#2 §05.4.6 absolute-index clarification** — HARDEST M1 blocker, pure wire-compat, no ADR exists yet. Do first.
2. **#2 ADR-0037 (CBOR re-encode)** — spec text + 8 vectors already done; just flip status + drop "proposed". Parallel with (1).
3. **#2 ADR-0044 (renderer canonicalization)** — flip status; gates 0032.
4. **#2 ADR-0032 (approval view_hash)** — flip status + reconcile preimage to numeric keys; **must land AFTER 0044**.
5. **#17 signing.rs non-contiguous index** — cheap (~30 LOC, mirror PR #59); closes a latent same-class bug. Optionally a shared `pos↔abs` helper.
6. **#55 keygen-only pubkey accessor** — tiny additive accessor; do whenever instant-signup UX is prioritized.
7. **#14 container readiness gate** — POST-M1 robustness; replaces the recovery settle band-aid. Pull forward only if a product flow runs back-to-back reshares on one identity.

All of #2's *spec-text* is small; the *code conformance* for 0037/0044/0032/§05.4.6 is **on rust-mpc's side** (Ishaan) — see "What's needed from Binary/rust-mpc" at the end of Part 1. Every ADR also needs **Binary sign-off** (the `[ ] Binary` checkbox) — async ping Mitch.

---

# PART 1 — #2: Lock the M1-critical MPC-Spec

**Where ADRs live:** `~/bsv/mpc/MPC-Spec/decisions/` (NOT `adr/`). **"Lock" = flip the ADR header
`Status: Proposed → Accepted` + check BOTH `## Sign-off` boxes (`[x] Calhoun`, `[x] Binary`).**
`CHANGES-PROPOSED.md`'s "locked" column means "position decided," not the header flip — don't be
fooled, every ADR header still says `Proposed`. **NOTE: there is NO §05.5.3** (the earlier reference
was wrong — §05.5 has no subsections); all `from_party`/`to_party` content is **§05.4.6** + the §05.6
BRC-52 cert-lookup sentence. Conformance vectors live in `~/bsv/mpc/MPC-Spec/conformance/test-vectors/`.

### 1.1 §05.4.6 — from_party/to_party = ABSOLUTE keygen index  ·  **M1-BLOCKING: YES (hardest)**

**Current text** (`05-message-envelope.md` §05.4.6, lines 79-83): defines `from_party`/`to_party` as
"the 0-based party_index" but **never says which index space** — absolute keygen index vs the
per-ceremony subset position that cggmp24 renumbers a t-subset into (`0..t`). For a non-contiguous
subset (e.g. `{0,2}`, where keygen-party 2 = subset-position 1) two impls can silently disagree →
mis-routed p2p → deadlock. The §05.6 BRC-52 cert lookup keys on `from_party`, which only works if it's
the **absolute** keygen index.

**This is exactly what bsv-mpc PR #59 implemented** (`crates/bsv-mpc-service/src/presign_handler.rs`):
`wrap_protocol` (lines 989-1048) translates SM-position→absolute on send (emits `wire_msg.from/to` as
absolute, lines 1028-1030); `dispatch_one` (lines 581-604) translates absolute→position on receive;
regression test `wrap_protocol_routes_noncontiguous_subset_by_absolute_index` (lines 1216-1252). The
impl is already conformant to the *intended* rule — the **spec text just hasn't caught up.**

**Exact change** — add this normative paragraph to `~/bsv/mpc/MPC-Spec/05-message-envelope.md` §05.4.6
(as the new lead sentence):
> **`from_party` and `to_party` are ABSOLUTE keygen party indices** — entries of `parties_at_keygen`
> (the canonical ascending cosigner set fixed at DKG, the same index a BRC-52 cert-chain lookup keys on
> per §05.6). They are NOT protocol-library subset positions. A library that renumbers a t-of-n signing
> subset to contiguous positions `0..t` (as cggmp24 does) MUST translate each subset-position to its
> absolute keygen index before populating `from_party`/`to_party` on the wire, and MUST translate
> absolute→position on receipt before feeding the protocol state machine. For a contiguous subset
> (`{0,1}`) position == absolute and the translation is a no-op; for a non-contiguous subset (`{0,2}`,
> keygen-party 2 = subset-position 1) it is mandatory — omitting it mis-addresses every p2p message and
> deadlocks the ceremony.

Optionally update the §05.3 inline comments (lines 38-39) to say "ABSOLUTE keygen party_index."

**Conformance vector to ADD:** a non-contiguous `{0,2}` envelope round-trip under
`conformance/test-vectors/` (none exists — the current `05-message-envelope.json` is `from=0,to=1`,
contiguous, can't catch this). New vector: envelope from absolute party 0 to absolute party 2 within
subset `{0,2}`, asserting `to_party == 2` (not `1`). bsv-mpc has the in-crate test already; rust-mpc
needs the equivalent.

**How to file:** either a new short ADR (next free number, **ADR-0051**) OR fold into the §05 LOCKED
status note. Needs Binary concurrence (touches both wires). **No ADR exists yet — this is net-new spec text.**

### 1.2 ADR-0037 — CBOR re-encode byte-equivalence (§05.9)  ·  **M1-BLOCKING: YES (hard)**

**Current state:** `decisions/0037-cbor-re-encode-equivalence.md` `Status: Proposed`, both sign-off
boxes unchecked (lines 93-94). Spec text **already merged** as §05.9.1 (`05-message-envelope.md` lines
177-195, labeled "Normative (per ADR-0037, proposed)"). Decision: recipient MUST re-encode parsed
fields as canonical CBOR + verify byte-equivalence vs the signed bytes; 8 enumerated reject classes.

**bsv-mpc is ALREADY FULLY CONFORMANT** (`crates/bsv-mpc-core/src/envelope.rs`): `encode_canonical`
(159-205), `decode_strict` (463-671) rejects all 8 classes, and the byte-equivalent re-encode itself at
lines 655-668 (`let re = env.encode_canonical(); if re != bytes { … "reencode-mismatch" }` →
`MpcError::EnvelopeReencodeMismatch`). Vector **exists + is rich**: `05-message-envelope-diff.json`
(+ `.cbor.hex`) = 1 ACCEPT + 8 REJECT vectors, one per class. `STATUS.md:40` tracks this as
"bsv-mpc half complete; held pending rust-mpc half (Ishaan)."

**Exact change** — `decisions/0037-…md`: flip line 3 → `Accepted`; check both sign-off boxes; in
§05.9.1 (envelope.md:179) drop the "(per ADR-0037, **proposed**)" qualifier. **No body change.**
**Dependency: none.** Only external gate = rust-mpc passing the 8 reject vectors.

### 1.3 ADR-0044 — wallet-renderer canonicalization  ·  **M1-BLOCKING: YES (payment slice only)**

**Current state:** `decisions/0044-wallet-renderer-canonicalization.md` `Status: Proposed`, boxes
unchecked. Specifies the canonical `rendered_text` algorithm via intent-kind dispatch (payment /
token_transfer / script_spend / brc100_internalize / multi), NFC UTF-8, locale-aware ISO-4217/BCP-47.
**Gates ADR-0032** because `rendered_text` is preimage field 8 — two wallets must render an intent to
byte-identical text or `request_view_hash` diverges.

**Exact change** — flip line 3 → `Accepted`; check both boxes; confirm `09-policy.md` §09.5.1
references it. Vector **already exists**: `conformance/test-vectors/09-rendered-text.json` byte-locks
`expected_rendered_text` per intent + the resulting `request_view_hash`. **For M1, only the
`payment-en-US-USD` vector is mandatory**; full intent coverage is Phase-0 (2026-06-12). Real remaining
work is CODE (`canonical_render(intent)`, ~400-600 LOC) on both impls — bsv-mpc near `approval.rs`/policy
(verify it emits byte-exact `expected_rendered_text`); rust-mpc from scratch.

### 1.4 ADR-0032 — approval request_view_hash (8-field preimage)  ·  **M1-BLOCKING: YES (format), soft (flow)**

**Current state:** `decisions/0032-approval-quorum-request-view-hash.md` `Status: Proposed`, boxes
unchecked. **ADR body still shows the OLD named-key preimage (lines 24-34)** — the PR-#42 reconciliation
to numeric keys 1-8 landed in the conformance vector but NOT in the ADR file. Authoritative layout is
`conformance/test-vectors/09-rendered-text.json` lines 7-15: keys `1 amount_satoshis, 2 recipient_outputs,
3 sighash, 4 ExecutionId, 5 policy_id, 6 manifest_ack, 7 human_locale, 8 rendered_text`, byte-locked
preimage + hash for payment/token/script. Mainnet-proven in bsv-mpc #43 (TXID `7ada3f9d`).

**Exact change** — `decisions/0032-…md`: flip line 3 → `Accepted`; check both boxes; **reconcile the
preimage block (lines 24-34) to the numeric-key 1-8 layout** the vector already byte-locks (this is the
PR-#42 reconciliation that never made it into the ADR file — without it the ADR and vector describe two
different preimages). **Dependency: HARD-gated on ADR-0044** (field 8 = `rendered_text`, undefined until
0044 locks the renderer) → **land LAST.** Flow can run Allow-by-default for M1; only the format must lock.

### Land order (dependency-sequenced)
```
1. §05.4.6 absolute-index   ┐ independent, parallel — the two pure wire-compat M1 blockers
2. ADR-0037 re-encode       ┘ (envelope byte agreement)
3. ADR-0044 renderer        → must precede 0032
4. ADR-0032 view_hash       → depends on 0044; land last
```

### What's needed from Binary / rust-mpc (the actual M1 gate)
1. **Binary sign-off (Mitch):** every ADR has an unchecked `[ ] Binary` box; CHANGES-PROPOSED marks all
   "Mitch sign-off required: Yes." §05.4.6 also needs Binary concurrence. Async ping.
2. **rust-mpc code conformance (Ishaan):**
   - **§05.4.6:** implement position↔absolute translation in rust-mpc send+receive; pass the new `{0,2}`
     envelope vector (mirror of bsv-mpc presign_handler.rs `wrap_protocol`/`dispatch_one`).
   - **ADR-0037:** byte-equivalent re-encode; pass all 9 vectors in `05-message-envelope-diff.json`
     (bsv-mpc already green — `STATUS.md:40` is waiting on this half).
   - **ADR-0044:** `canonical_render(intent)` (payment intent for M1); reproduce `09-rendered-text.json`.
   - **ADR-0032:** shift approval binding from `policy_id`-only to the 8-field `request_view_hash`.
3. Shared adversarial CBOR fuzz corpus (ADR-0037 / OPEN-Q26) — ownership + CI cadence open; nice-to-have.

### Spec-author cleanups to flag (block a clean lock)
- ADR-0032 preimage block out of sync with the vector (named vs numeric keys) — reconcile (PR-#42 work).
- Drop any "§05.5.3" reference — it doesn't exist; the content is §05.4.6.

---

# PART 2 — #3: Quick wins

## 2.1 #55 — export joint pubkey/address from a keygen-only share  ·  **M1-BLOCKING: NO (low-risk, high-value)**

**The field already exists + is populated.** cggmp24's `IncompleteKeyShare.shared_public_key` is the
full group key; the DKG code already captures it at keygen-complete into
`DkgCoordinator.keygen_joint_pubkey: Option<[u8;33]>` (`crates/bsv-mpc-core/src/dkg.rs:266`), set at
`dkg.rs:657-667` (`handle_keygen_complete`), populated for the entire aux-info phase. **No public
accessor exists** — it's only read internally for the auxinfo ExecutionId.

**Aux-info does NOT change the pubkey (confirmed):** `assemble_dkg_result` (`dkg.rs:742-747`) reads
`shared_public_key` from the same stashed `IncompleteKeyShare`; `KeyShare::from_parts((incomplete,
aux_info))` (`dkg.rs:750-752`) only attaches Paillier/ring-Pedersen params. Test `full_2of3_dkg_via_sim`
(`dkg.rs:1360-1362`) already shows `share.core.shared_public_key == joint_pubkey`. So the keygen-phase
pubkey is byte-identical to `DkgResult.joint_key.compressed`.

**Exact change** — add to `DkgCoordinator` (after `phase()` ~`dkg.rs:558`):
```rust
/// Joint/group public key, available the instant KEYGEN completes — BEFORE the slow
/// aux-info phase. `None` while in keygen/not_started; `Some(_)` in aux_info + complete.
/// DISPLAY-ONLY: a keygen-only share CANNOT sign (aux-info Paillier params required).
/// Byte-identical to the eventual DkgResult.joint_key.compressed (aux-info never changes it).
pub fn keygen_joint_pubkey(&self) -> Option<[u8; 33]> { self.keygen_joint_pubkey }

/// Convenience: keygen-phase joint key as JointPublicKey (compressed + BSV address),
/// address derived by the SAME derive_p2pkh_address used in assemble_dkg_result.
pub fn keygen_joint_key(&self) -> Option<crate::types::JointPublicKey> {
    self.keygen_joint_pubkey.map(|jpk| crate::types::JointPublicKey {
        compressed: jpk.to_vec(),
        address: derive_p2pkh_address(&jpk),   // dkg.rs:897-911 (same fn assemble_dkg_result uses)
    })
}
```
No new field, no crypto, no protocol change. `JointPublicKey` is `types.rs:147-153`.

**Test** (extend `two_coordinators_keygen_message_exchange`, `dkg.rs:1369`): drive a 2-of-2 with fast
primes; capture `keygen_joint_pubkey()` the first round `phase()=="aux_info"`; on `Complete`, assert it
`== res0.joint_key.compressed` AND `derive_p2pkh_address(&kp) == res0.joint_key.address`. Assert it's
`None` before keygen completes.

**Caveats:** display-only — a keygen-only artifact is an `IncompleteKeyShare`, not a `KeyShare`, so
loading it into `SigningCoordinator` fails at `signing.rs:619`. Proxy `getPublicKey` fast-path wiring
(hold the live coordinator / persist the keygen pubkey between keygen-complete and aux-complete) is the
natural follow-on, out of scope for the accessor.

## 2.2 #17 — signing.rs full-4-round over relay: non-contiguous index fix  ·  **M1-BLOCKING: NO (latent, not reached in prod)**

**The bug is REAL but LATENT.** `SigningCoordinator` renumbers the subset to SM positions
(`signing.rs:599-608` `my_signing_index = participants.position(share_index)`; drives
`cggmp24::signing(eid, my_signing_index, …)` at `:640`; `drive_inline` writes `RoundMessage.from/to` in
position space, `dkg.rs:858-863`). But `signing_handler.rs` (the interactive 4-round relay handler)
routes by ABSOLUTE index and **never translates**: `wrap_outgoing` (`:295-326`) sets
`params.to_party=peer_party_index` (absolute) and ships `rm.clone()` with position-space from/to (no
send translation); `dispatch_one` (`:208-290`) feeds `inbound.round_msg` straight to
`coord.process_round` (no receive translation). Same class as PR #59's presign bug. Works for `{0,1}`
(position==absolute), breaks for `{0,2}`.

**NOT reached in production:** the deployed sign path is the **1-round presigned/bundle combine**
(`crates/bsv-mpc-proxy/src/relay_sign.rs` + `crates/bsv-mpc-service/src/sign_relay_handler.rs`
`cosign_over_relay`), routed via `/sign-relay`. That path is **{0,2}-SAFE** — it routes by explicit
recipient identity hex (`sign_relay_handler.rs:145`), not an index→peer filter, and uses from/to only as
`BTreeMap` ordering keys for `PartialSignature::combine` (`signing.rs:699-740`). The interactive
`SigningHandler` is referenced ONLY in `lib.rs:31` (re-export) + `tests/sign_mainnet_via_messagebox_e2e.rs`
(2-of-2); **no production crate constructs it.** A `{0,2}` full-4-round relay sign only happens if a
future feature wires `SigningHandler` for a non-contiguous quorum.

**Exact fix** — mirror PR #59 into `SigningHandler`:
- **Send** — `wrap_outgoing` (`signing_handler.rs:295-326`): add `participants: &[u16]` param;
  `pos_to_abs = |pos| participants.get(pos as usize).copied()`; translate `rm.from`/`rm.to`
  position→absolute; emit only messages for the single peer (broadcast → always; p2p → only when
  `to_abs == peer_party_index`). Update call sites `:176-182` (initiate) + `:262-268` (dispatch) to
  pass `&self.inner.participants`.
- **Receive** — `dispatch_one` (`:208-290`), before building `inbound_round_msg` (~`:232`): translate
  `inbound.round_msg.from` absolute→position via `participants.position(...)` (drop with warn if not in
  subset); translate `to` likewise. Mirror `presign_handler.rs:589-604`.
- **Best (anti-drift):** extract a shared `pub(crate)` `pos_to_abs`/`abs_to_pos` helper used by BOTH
  `presign_handler.rs` and `signing_handler.rs` (they share `drive_inline` + the same position
  convention). Land it alongside the §05.4.6 spec clarification (1.1).

**Test** — add `wrap_outgoing_routes_noncontiguous_subset_by_absolute_index` (mirror
`presign_handler.rs:1216-1252`): subset `[0,2]`, p2p from position 0 to position 1, assert
`params.to_party==2`, `round_msg.from==ShareIndex(0)`, `round_msg.to==Some(ShareIndex(2))`. `{0,1}` still
proven by `sign_mainnet_via_messagebox_e2e` (translation is identity) + update
`wrap_outgoing_uses_real_joint_pubkey_and_sign_phase` (`:361`) to pass `&[0,1]`.

## 2.3 #14 — container readiness gate (replace the recovery settle band-aid)  ·  **M1-BLOCKING: NO (post-M1)**

**The band-aid:** two `tokio::time::sleep(Duration::from_secs(60))` settles in
`crates/bsv-mpc-proxy/tests/recovery_spend_deployed_mainnet_e2e.rs` — reshare#1→lose-phone (`:343-351`)
and reshare#2→presign (`:396-407`).

**Why (the real issue):** the container uses ONE relay identity. Its reshare `mpc-refresh` listener
LINGERS — the completion task spawns at `reshare_relay_handlers.rs:615`, the HTTP 200 returns at `:694`,
but the `pss_listener` lives from `:630` until `pss_listener.shutdown()` at `:672` (after the full PSS
ceremony). So a follow-on ceremony's subscription on the same identity overlaps the lingering one. The
relay routes per-identity to one DO (`~/bsv/rust-message-box/src/lib.rs:347-348`) and fans out per-room
filtered by `joined_rooms` (`message_hub.rs:483-517`); a `leaveRoom` on the shared `mpc-refresh` room
(both reshares use the FIXED `BOX_REFRESH`) during reshare#2's join drops reshare#2's PSS messages →
timeout. (Presign uses session-scoped boxes, so settle #2 is the teardown-churn window, not a pure room
collision — same cure.) The settle approximates "at most one live listener on the identity, prior
`leaveRoom` flushed before the next subscribes." Presign listeners in `RELAY_CEREMONIES`
(`relay_handlers.rs:57-62`, inserted `:364`) have **no removal on completion** — they linger until a
same-sid replacement (never) or restart.

**God-tier fix — Hybrid A (readiness gate) + B (prompt synchronous release):**
- **(B) Real "free" signal:** add `static ACTIVE_LISTENERS: LazyLock<Mutex<HashSet<String>>>` (keyed by
  box / `"reshare:{sid}"` / `"presign:{sid}"`). Insert when a listener starts (reshare `:533` dkg, `:630`
  pss; presign `relay_handlers.rs:364`); REMOVE **strictly AFTER** `shutdown().await` returns
  (`:672` + every early-return/error path `:544,:563,:648,:658,:666`) — so an empty set is a TRUE
  "room released + leaveRoom flushed" signal. (Critical: remove post-shutdown, and clean on the
  `Drop`-only-abort path `messagebox.rs:175` which does NOT leaveRoom — use a guard.) Add explicit
  presign removal on round-3/return-ship completion.
- **(A) Readiness endpoint:** `GET /relay-ceremonies/active` (read-only, no auth — exposes only box
  names/counts; mirror `/presign-relay/debug` + `/reshare-relay/debug`):
  `{"active_listeners":[{kind,box,session,age_ms}], "count":N, "identity_busy":N>0}`.
- **Proxy wait helper:** `wait_until_container_free(presign_url, auth, timeout)` — poll every ~1-2s
  until `count==0`, bounded ~90s (returns the instant free; ceiling, not cost). Call at the TOP of
  `MpcBridge::reshare_change_threshold_over_relay` (`bridge.rs:1623`, before identity fetch `:1727`) and
  `coordinate_presign_over_relay` (`relay_presign.rs:68`, before `fetch_cosigner_identity` `:119`).
- **Remove** the two test settles (`:343-351`, `:396-407`) — the gate now lives in the bridge/coordinator.
- Reject **(C) one shared multiplexed subscription** (big lifecycle rewrite; the gate solves it cheaply).

**Test:** (1) hermetic unit on the registry (insert 2 → `count==2,identity_busy`; shutdown 1 → 1;
poller returns on `count==0`, **asserts the timeout path rejects for the right reason** per
validate-don't-skip); (2) hermetic e2e back-to-back reshare→reshare→presign with NO sleep against local
service+relay, instrument poll counts >0; (3) deployed re-run of `recovery_spend_deployed_mainnet_e2e`
with settles removed → same mainnet recovery TXID flow passes.

**Urgency:** POST-M1. Recovery is already mainnet-proven WITH the settle; this is robustness/cleanliness.
**Pull forward ONLY if** a product flow runs back-to-back reshares on one container identity (e.g.
automated rotation) — then the `mpc-refresh` room collision (settle #1's case) is a live prod risk.

---

## Risks / discipline (applies to all of the above)
- **No commit/push/PR without showing the diff + approval** (partnership rule).
- **Spec changes need Binary sign-off** — async ping Mitch; don't flip a `[ ] Binary` box unilaterally.
- **#17 anti-drift:** prefer the shared `pos↔abs` helper so presign + sign can't diverge again.
- **#14 ordering hazard:** registry removal MUST be post-`shutdown().await` (leaveRoom flushed) and on
  every early-return/Drop path, or the gate reintroduces the race.
- **Gates:** warning-free clippy (4 native `--all-targets` + wasm worker), `CARGO_INCREMENTAL=0`;
  re-run lib suites (core 262 / proxy 157 / service 40); the deployed #14 re-run burns real sats (gated).
- Source audits (full detail): the 3 swarm agent reports of 2026-05-26; state graph
  `docs/STATE-2026-05-26.md` + `graphify-out/GRAPH_REPORT.md`.
