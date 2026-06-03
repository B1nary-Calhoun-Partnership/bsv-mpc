# Aux-info REUSE — build spec (bsv-mpc #104)

> Verdict from a 7-agent adversarial security review + design swarm (2026-06-02): **GO-WITH-CONDITIONS.**
> Aux-info reuse across wallets for a fixed (device, Notary-set) group is cryptographically sound for our
> 4-of-6 threshold topology (the crate's reuse note `cggmp24/src/lib.rs:131-137` applies verbatim — see
> threat notes), **but only if every must-do below is met.** This is the authoritative spec; build to it.

## The win
With the prime pool warm, 4-of-6 provision is still ~250–513s because the **aux-info protocol** (ring-Pedersen
+ 3× ZK proofs) runs every signup. Aux-info is **independent of the key** (`AuxInfo` = Paillier moduli + Pedersen
params only; no curve/secret/eid binding; `from_parts` checks only `n` + `N[i]==p*q`). So: run aux **once** per
fixed group (persisted, sealed, pinned), then **per-wallet = keygen (EC seconds) + `from_parts(reused aux)` +
presig**. Per-wallet aux → **0**. The single biggest time-to-sendable cut.

## THE decisive risk (why the gates exist)
The crate's ZK proofs (Π_mod/Π_fac/Π_prm, verified by every party incl. the device) prove a modulus is
**well-formed** but **NOT that the contributor doesn't know its factorization**. A one-time relay-MITM during
aux-setup can stand in as a "Notary", contribute perfectly well-formed but **attacker-factored** moduli, and —
because aux is reused forever — **permanently backdoor every future wallet, invisibly (no abort, no error)**.
`validate_consistency` is the ONLY automatic guard and is weak by design (`pedersen.len()==n` + `N[i]==p*q`); it
binds no identity, no `(t,n)`, no epoch, and **never inspects any peer slot `N[j]`**. Every scoping guarantee is
**ours** to enforce out-of-band.

## Security MUST-DOs (hard gates — nothing funded reuses aux until all pass)
1. **Aux-setup identity pin** — run the one-time ceremony under the #85 per-index relay-identity attestation
   VERBATIM (`hd.rs:324-339` `relay_identity_attestation_msg/verify`, wallet-independent → reused unchanged).
   Fail closed on missing/invalid attestation. This binds WHO contributed `N[3..5]`.
2. **Aux-bound liveness challenge** — the funding gate (`cosigner_challenge_msg` binds `joint_pubkey`, `hd.rs:382-395`)
   is structurally inapplicable (no joint key at setup). Add a new challenge: each pinned Notary master signs a
   fresh-nonce `H(master ‖ aux_session ‖ index ‖ N_i ‖ hat_N_i ‖ s_i ‖ t_i)`, verified under the pinned master
   BEFORE persisting. The aux analogue of `challenge_cosigner`.
3. **Group-scoped aux ExecutionId** — new `PhaseTag::AuxSetup` whose preimage binds the FROZEN tuple (device master,
   both Notary masters, the index→master map {0,1,2→dev, 3,4→A, 5→B}, n=6, t=4, security level) — NOT a joint key.
   All 6 derive byte-identical `sid`; Fiat-Shamir then makes aux proofs non-replayable across any other group AND
   across the per-wallet keygen sid. **Reuse aux, NEVER reuse sid.**
4. **Seal at rest as key-grade secret** — aux holds the Paillier secret `p,q` + CRT (crate-flagged "extremely
   sensitive", `key_share.rs:82-84,299`); reused across ALL wallets ⇒ blast radius = all wallets. DEVICE: the
   Secure-Enclave ECIES path (`EnclaveKeyStore.swift`, WhenUnlockedThisDeviceOnly) — at-least-equal to a share,
   NEVER a weaker keychain/UserDefaults store. NOTARY: KEK-sealed custody (the #9 durable-custody pattern),
   owner-bound to its BRC-31 DKG-time identity, gated by §07/§08.1 owner-authz. No plaintext aux rows.
5. **Tamper-evident binding envelope + re-verify at EVERY load** — store alongside the sealed aux a signed/MAC'd
   canonical record `{sid, 3 masters, index→master map, n, t, per-index N digests, full-N hash, aux-epoch}`. Verify
   BEFORE `from_parts`; REJECT on any mismatch. Catches both a coherently-tampered own modulus (`from_parts`
   passes it) AND a swapped/stale peer `N[j]` (`from_parts` never checks it — otherwise a late opaque
   `EncProofOfK` sign-time abort).
6. **Per-index modulus distinctness + bit-length floor at persist** — assert the 6 `N` (and 6 `hat_N`) are pairwise
   distinct and each ≥ `RSA_PUBKEY_BITLEN` (a Notary can't reuse one Paillier key across [3,4]). The crate verifies
   the floor + per-party proofs in-ceremony but NOT cross-index distinctness across the persisted vector.
7. **Explicit app-level `from_parts` assertions** — before fuse: `aux.N.len()==6`, `pedersen.len()==6`, `i==expected`,
   per-slot params hash matches the group descriptor, curve/L matches keygen. Don't treat `from_parts` success as proof.
8. **One n=6 co-generated aux vector — NEVER stitch** — run the ceremony across the full n=6; device seals 3 DISTINCT
   `(p,q)` and loads the index-correct primes per share. Stitching independent auxes is UNSAFE (a wrong PEER slot is
   not caught at fuse time).
9. **Fresh ExecutionId per keygen + per signing; NEVER reuse a presignature** (`signing.rs:1511`) — orthogonal hard
   key-leak vectors, unaffected by aux reuse; the fast path must not collapse this discipline. Keep
   `reliable_broadcast_enforced=true` for aux-setup (`key_refresh.rs:116`).
10. **Invalidate-and-regenerate (fail-closed)** on ANY frozen-tuple change: Notary master rotation, any reshare,
    n/party/index change, security-level change, OR SE biometric re-enrollment (`.biometryCurrentSet` invalidates →
    treat as regenerate, not error). Tie validity to an explicit **aux-epoch**; refuse a per-wallet provision whose
    aux-epoch ≠ the current pinned-Notary epoch. Zeroize the deserialized `AuxInfo` after `from_parts` (per #41).

## Build stages (ordered, smallest-diff-first)
1. **Core: group-scoped aux ExecutionId** — `canonical.rs` `PhaseTag::AuxSetup` + group-id hash; `dkg.rs` derives a
   jpk-free sid for the standalone aux ceremony (today `dkg.rs:709-714` binds the per-wallet jpk). *(no redeploy)*
2. **Core: reuse + capture seams on `DkgCoordinator`** — `loaded_aux_info` field + `set_loaded_aux_info[_from_json]`
   + a reuse fork in `handle_keygen_complete` (~:706: stash incomplete, set phase=Complete, skip the auxinfo SM) +
   a Complete-arm that calls `assemble_dkg_result(loaded_aux)` UNCHANGED; plus `capture_aux_info` flag +
   `captured_aux_info_json` + `take_captured_aux_info_json` (serialize at the auxinfo-complete arm before fuse). *(no redeploy)*
3. **Core: binding-envelope + load-time validation** — the tamper-evident record + sign/verify (mirror
   `relay_identity_attestation_msg`) + the aux-bound liveness challenge msg + the `from_parts` pre-assertions in
   `dkg.rs`/`hd.rs`. The gate that rejects a swapped/stale/tampered aux at LOAD, not at sign. *(no redeploy)*
4. **Service: aux-setup routes + sealed aux custody + load branch** — `aux_relay_handlers` (`POST /aux-setup/{init,
   peer-identity}`, `GET /aux-setup/identity` smoke), owner-authz; an aux-only handler with an aux-out oneshot
   (mirror #101 `keygen_done_tx`); `aux_blobs` custody `{group_id}#{index}` KEK-sealed; a load branch in
   `handle_dkg_relay_init` that loads the sealed aux + `set_loaded_aux_info` + SKIPS `seed_primes_late`. **NEEDS NOTARY REDEPLOY.**
5. **Relay: aux-setup orchestration + device_aux on DKG** — `provision_aux.rs::coordinate_aux_setup_over_relay`
   (n-only, no joint-key gate, arms `/aux-setup/init`, reuses `fetch_dkg_peer_identity` + the #85 attestation + the
   new aux-bound challenge, returns each local index's serialized `AuxInfo`); `DkgOverRelay` gains
   `device_aux: Option<...>` + `group_id` → when present, `set_loaded_aux` per device index + SKIP the device
   prime-pre-seed; prime_pool stays as the no-aux fallback. *(no redeploy)*
6. **Client FFI: `setup_group_aux` export + `FfiAuxStore` + create_wallet_nparty params** — run-once export returning
   `group_id`; `FfiAuxStore` (seal_aux/unseal_aux/has_aux, Rust seals via BRC-42-from-at_rest_root → opaque to host);
   optional `aux_store`+`group_id_hex` on `create_wallet_nparty` (unseal the device's w=3 blobs, thread `device_aux`),
   inline-aux fallback (Pareto). Regen XCFramework. *(no redeploy)*
7. **100cash: `AuxBlobStore` + `setupGroupAux` + createWallet pass-through** — `setupGroupAux()` next to
   `prewarmPrimePool` (background, overlapping OAuth) runs the one-time n=6 ceremony + seals the 3 device blobs via
   the **Secure-Enclave** path (key-grade, NOT the prime-pool store); persist `group_id`; pass `auxStore`+`groupId`
   into `createWalletNparty`. Inline-aux fallback until setup finishes. *(no redeploy)*

## Test plan (must pass before any funded reuse)
- **POS:** 2nd-wallet provision drops to keygen+`from_parts`+presig — assert NO auxinfo SM + NO prime gen (device or
  Notary), `from_parts` succeeds, signs + broadcasts mainnet → SEEN_ON_NETWORK, time-to-sendable materially below
  the with-aux baseline.
- **POS:** two wallets reuse the SAME aux → DISTINCT joint keys, each signs, DIFFERENT keygen+signing sids.
- **NEG (validate-don't-skip — reject for the RIGHT reason):** swapped/stale aux (different group / rotated master /
  reassigned index) rejected at LOAD by the envelope (specific reason), NOT a late sign abort; coherently-tampered
  own modulus (N==p*q still holds) rejected by the envelope (prove `from_parts` alone would accept it);
  missing/invalid attestation aborts aux-setup; duplicate modulus across a Notary's two indices rejected at persist;
  cross-phase sid replay fails; n-mismatch rejected at the app assertion.
- **DEPLOY SMOKE:** `GET /aux-setup/identity` → 200 on the redeployed container (404 = stale image); the FULL
  adversarial set rejects before any funded reuse.
- **REGRESSION:** aux_store/group_id absent or blob missing → falls back to per-ceremony aux gen, still signs mainnet
  (strictly Pareto).

## Threat-model notes (for the §10 threat doc)
- Reuse is ORTHOGONAL to and relaxes NEITHER classic leak vector: presig single-use (`signing.rs:1511`) + sid
  freshness (`lib.rs:93-98`). The long-term share is never Paillier-encrypted (only ephemeral nonces) — two keys
  sharing one `N` reveal nothing extra about `x`.
- Threshold (t-of-n, device w=3) changes nothing vs n-of-n for aux safety: the Lagrange rescale is fresh per signing
  (EC-only); the Paillier/Pedersen layer sees the rescaled `x_i` as a plaintext input to MtA, and the aux reduction
  quantifies over ALL plaintexts. The crate's reuse note applies verbatim to 4-of-6.
- A stale/swapped COUNTERPARTY aux fails CLOSED but LATE/opaquely (sign-time `EncProofOfK` abort) — hence the
  load-time binding check. The DANGEROUS case is the COHERENT swap (attacker knows the substituted modulus's
  factorization): self-consistency `N==p*q` is NOT integrity; only the signed envelope (MAC over full-N hash) defeats it.

Full review JSON: see the session workflow `aux-reuse-104-design-review` (run `wf_b07344d3-9eb`).
