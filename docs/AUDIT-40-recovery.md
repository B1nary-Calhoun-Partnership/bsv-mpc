# Audit — #40 lost-phone recovery ceremony (step:investigate)

> **Verdict: the resharing keystone is CONFIRMED — secure multi-round PSS,
> cross-(t,n), address-preserving, atomically committed, solo (no Binary dep),
> mainnet-proven through the reshare itself (#35). The ONE remaining gap to the
> #40 acceptance is signing-with-the-recovered-share + broadcast.**

## 1. Keystone confirmed (no new crypto needed)
- **Secure multi-round PSS.** `refresh::party_reshare_contribution` (refresh.rs
  ~L200) — each survivor `k` builds a fresh degree-(t′−1) polynomial with
  `f_k(0) = λ_k · my_secret`; each recipient `j` learns exactly ONE evaluation
  `f_k(e′_j)` over a BRC-78 p2p envelope. Recovering a survivor's old share needs
  `t′` evaluations → ≤t′−1 colluders learn nothing. The coordinator NEVER sees
  all shares. The all-shares-at-once `refresh::threshold_reshare` is **test-only**
  — `ResharCoordinator` (the production/relay path) does NOT call it.
- **Cross-(t,n) + address-preserving.** `ResharConfig::original_joint_pubkey` is
  the contract; `refresh::verify_reshare` confirms the new public shares
  Lagrange-reconstruct the UNCHANGED joint key over any new-t subset. Proven:
  `distributed_reshare_3of4_to_4of6_signs`, `capstone_cross_tn_reshare_*`, and the
  deployed `container_reshare_deployed_mainnet_e2e` (2-of-2 → 2-of-3, address
  preserved, against the live CF container).
- **Atomic rotate-on-commit.** `bridge::apply_refreshed_share` hot-swaps the
  in-memory share under a write-lock; `bridge::persist_rotated_share` writes
  `{share_path}.tmp` then `rename()`s — POSIX-atomic, crash-safe (crash before
  rename → old share intact; after → new share intact). Presigs are purged on
  reshare (stale-pool guard). **Gap:** old in-memory share bytes are not
  cryptographically zeroized (overwritten, not wiped) — **low risk** (transient
  proxy; rotated old bytes are useless on the new polynomial) and is exactly
  **#44**, not a #40 blocker.
- **Solo / no Binary dep.** `party_reshare_contribution` is a local computation;
  the two-phase ceremony (Phase A fresh aux DKG + Phase B PSS reshare) runs over
  the proven MessageBox relay with NO second implementation. §18 cross-impl
  portability is a future extensibility feature, not a recovery blocker.

## 2. The gap (what #40 must build)
`container_reshare_deployed_mainnet_e2e` funds a key on mainnet and reshares it
2-of-2 → 2-of-3 onto the deployed container (a "fresh party"), address preserved —
but its own header notes the **new-set relay-sign is not yet wired** (it does not
sign+broadcast with the post-reshare shares). So the recovery story is proven up
to "the new device holds a valid share for the same address" but NOT yet "the
recovered device can SPEND."

**#40 build = close that:**
1. **Recovery-sign:** after a reshare onto a fresh device, drive a new-set
   relay sign (recovered device's new-set share + a cosigner, the proven
   device-holds/#38 + relay-sign/#13 path) and broadcast — same joint address.
   This is orchestration over proven primitives, not new crypto.
2. **Ceremony orchestration (product polish):** a recovery flow that calls
   `bridge::reshare_change_threshold_over_relay` (bridge.rs ~L1375, already
   deployed-proven) with recovery params (survivor quorum ≥ n−t+1, the fresh
   device's identity), + new-device onboarding (BRC-31 owner auth, relay identity,
   share receipt + signing-ready KeyShare assembly via
   `combine_reshared_with_aux`).
3. **`recovery_health` (§18.4a) + post-recovery cooldown** — prevent a
   hot-swap attack (no second recovery within a cooldown window; require a
   survivor quorum).
4. **#44 zeroize** — fold in (Zeroize on the Scalar share fields before overwrite;
   mirror the worker `do_storage` pattern).

## 3. Mainnet gate (the #40 acceptance)
Real-sats: DKG 2-of-2 → fund joint address → reshare 2-of-2 → 2-of-3 onto a fresh
device over the relay (proven) → **the fresh device's new-set share + a cosigner
sign a spend over the relay from the SAME address → broadcast → WoC-confirm**, old
2-of-2 share invalidated. Mirror `container_reshare_deployed_mainnet_e2e` for the
reshare half + the #38/#13 relay-sign harness for the spend half.

## 4. Build order (tasks #13–#14)
1. **#13 recovery-sign + ceremony** — wire the new-set relay sign after reshare;
   the recovery coordinator + health/cooldown; #44 zeroize. Hermetic test first
   (reshare → new-set subset signs → verifies under the unchanged joint key).
2. **#14 mainnet GATE** — the real-sats recovered-device spend, WoC-confirmed.

## 5. Discipline
110%, no asterisks. The recovery-sign primitive proven by a hermetic test (a
new-set subset signs + verifies under the original joint key); the deployed TXID
proof at #14. clippy (4 native + wasm worker) warning-free; CARGO_INCREMENTAL=0.
