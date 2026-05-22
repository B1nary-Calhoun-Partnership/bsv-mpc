# Handoff — MPC-Spec #4: presig lifecycle (ADR-0030, §06.15–§06.21)

> Next task for bsv-mpc. Written 2026-05-22 after the M1 2-of-3 ceremony landed.
> **Canonical repo:** `/Users/johncalhoun/bsv/mpc/bsv-mpc` — NOT `bsv-mpc-DEAD-do-not-use`.

## 0. The discipline (non-negotiable — "110% proof, no asterisks")
- Every change gated by **unit tests + conformance vectors + a real-mainnet e2e with a cited TXID**. No "should work."
- **Mirror proven patterns** in the repo; consult `~/bsv/` reference stack before inventing.
- **No green-theater.** A test must fail under the old/wrong code and pass under the new. Never claim done / close an issue without load-bearing proof. (This session caught two would-be-fake-greens — a relay TXID that wouldn't exercise the fix, and a silent-skip masking a real 500.)
- Crypto is sensitive: **spec-first, design + plan before code**, then implement incrementally, each step gated.
- Branch off `main`; PR per logical change; squash-merge. Impl-only bsv-mpc PRs need no peer sign-off (conformance vectors are the gate).

## 1. What #4 is — ADR-0030 presig lifecycle
Spec: `~/bsv/mpc/MPC-Spec/06-transport.md` §06.15–§06.21 + `~/bsv/mpc/MPC-Spec/decisions/0030-presig-coordinator-storage.md`. **Read both in full first.**

The lifecycle layer that turns raw presig generation into a production pool:
- **§06.16 Generation + encryption.** After the 3-round presign, each cosigner **BRC-2 self-encrypts** its presig share via the wallet primitive (ProtoWallet `encrypt`): `protocol_id.protocol = "mpcpresig"` (BRC-43, lowercase, no hyphens), `security_level = 2`, `counterparty = Self_`, `key_id = presig_id`. Invoice is `2-mpcpresig-{presig_id}` (§03). **MUST NOT hand-roll AES** — use the wallet primitive so both impls derive the same key. Cosigner zeroizes plaintext after coordinator ack.
- **§06.17.1 PresigBundle** (the coordinator's stored unit): `presig_id, presig_bytes, cosigner_encrypted_share, gamma_hex, commitments, policy_id, joint_pubkey, parties_at_keygen, generated_at`. **Binding triple = `(policy_id, joint_pubkey, parties_at_keygen)`** — a presig is consumable only when all three match the current ceremony.
- **§06.17.2 Mailboxes.** `presig_return_{session_id}` — one-way return channel for the cosigner-encrypted ciphertexts. Delete after ack / timeout.
- **§06.17.1 at-rest.** Coordinator stores `presig_bytes` encrypted at rest (same level as the DKG key share).
- **§06.17.3 single-use.** Consume = remove from pool atomically; no replay.
- **§06.18 invalidation (mandatory).** Atomically delete all bundles on: share refresh commit / cosigner-subset change / policy update / joint-pubkey change. Emit audit events.
- **§06.19 burn-rate regen.** EWMA over 60s; `target = max(8, ceil(burn_rate × 30))`; `low_water = 0.5 × target`; `cap = 2 × target`. Regen in parallel when `available < low_water`. (Recommended baseline, not MUST — alternatives allowed within the water bounds.)
- **§06.20 consumption.** At sign-time the coordinator sends the cosigner its encrypted ciphertext + message; cosigner decrypts + applies the BRC-42 offset, returns its partial. Fall back to the 4-round path if the pool is empty and the cosigner is online.
- Metrics: `pool_size, burn_rate, regen_in_flight, bundles_consumed, bundles_invalidated{reason}`.

## 2. Current bsv-mpc state — HAVE vs NEED
**HAVE (working):**
- 3-round presign generation: `crates/bsv-mpc-core/src/presigning.rs` (`PresigningManager`, real CGGMP'24 SM).
- FIFO pool + burn-aware replenish: `crates/bsv-mpc-proxy/src/presign_manager.rs`.
- Worker provisioning: `/ceremony/ingest-presig` in `crates/bsv-mpc-worker/src/poc.rs` (stores plaintext presig in DO SQLite).
- Relay consume: `crates/bsv-mpc-proxy/src/relay_sign.rs` (`/sign-relay` consumes a pooled presig + combines).

**NEED (the ADR-0030 layer — none of this exists yet):**
1. `PresigBundle` struct + binding triple (likely `crates/bsv-mpc-core/src/types.rs`), serde/CBOR-stable. **(S)**
2. BRC-2 self-encryption of the presig share via ProtoWallet (`mpcpresig`, Self_, key_id=presig_id) — `presigning.rs` post-round-3. **(M)**
3. Return mailbox `presig_return_{session_id}` + return path (proxy/service orchestrator). **(M)**
4. Persistent `PresigBundle` storage, encrypted at rest, `policy_id`-indexed (pattern from worker `do_storage.rs`). **(M)**
5. Burn-rate EWMA regen loop + metrics (§06.19). **(M)**
6. Invalidation triggers (§06.18) wired into policy-update + refresh-commit handlers. **(S)**
7. Sign-time consumption + cosigner decrypt of the encrypted share (§06.20) — `relay_sign.rs` / signing path. **(M)**
8. Conformance test `conformance_06_presig_bundle_encryption.rs` (see blocker). **(S)**

## 3. Blocker (partial — ~80% buildable NOW)
- The cross-impl ciphertext conformance vector `~/bsv/mpc/MPC-Spec/conformance/test-vectors/06-presig-bundle-encryption.json` has **3 `__TBD__` ciphertexts** waiting on Binary's **MPC-Spec #9** (rust-mpc byte-locks them via a ref run). Until then the final byte-match test can't be locked.
- **But the intermediate values are already locked** (wallet pub, BRC-42 invoice, shared_secret, HMAC offset) — so items 1–7 above are fully buildable now, and the bsv-mpc encrypt path can be unit-tested against the locked intermediates. Only the final ciphertext byte-equality assertion waits on #9.

## 4. Key refs
- Spec: `MPC-Spec/06-transport.md` §06.15–21; `MPC-Spec/decisions/0030-presig-coordinator-storage.md`; `MPC-Spec/conformance/test-vectors/06-presig-bundle-encryption.json`; `MPC-Spec/03-brc42-invoice.md` (invoice format).
- Code: `presigning.rs`, `presign_manager.rs`, `relay_sign.rs`, worker `poc.rs` + `do_storage.rs`, `crates/bsv-mpc-core/src/types.rs`.
- BRC-2 primitive: bsv-rs `ProtoWallet::encrypt` (`~/bsv/bsv-rs`; already used for DKG share encryption — find that call site and mirror it).
- Proven gating patterns this session: real-mainnet e2e funds the joint addr from the wallet at **localhost:3321** (`Origin: http://admin.com`, `acceptDelayedBroadcast:false`), broadcasts via **GorillaPool ARC** with **full-ancestry BEEF** (never WoC-fetch ancestry — see `crates/bsv-mpc-proxy/src/wallet_api.rs` `build_beef_from_ancestry`). ARC key at `~/bsv/teragunv2/secrets.md` (TAAL `mainnet_…`).
- MessageBox ceremony e2e patterns: `crates/bsv-mpc-service/tests/{dkg_2of3,sign_mainnet}_via_messagebox_e2e.rs` (gated on `MESSAGEBOX_RELAY_URL`; relay `https://rust-message-box.dev-a3e.workers.dev`).

## 5. Proven context (this session — don't redo)
- bsv-mpc **#18** n-party MessageBox routing; **#19** 2-of-3 DKG over relay; **#20** 2-of-3 mainnet sign → TXID `c8f3201a545dcdcc3c6d8e2ee8bab887e61b74a306c473410f14294823c816dd` (SEEN_ON_NETWORK).
- bsv-mpc **#14** (worker SessionId) + MPC-Spec **#18** (THREAT-MODEL + e2e silent-skip) closed; signing SessionId `from_hex` fix mainnet-proven (`66385b55…`); full-ancestry BEEF broadcast (`803a4ae2…`); CI wasm32 fix.
- M1 capability is DONE (Calhoun-run 2-of-3). #4 is M2-critical + unblocks #13 (HD-key-over-relay).

## 6. Commands
```bash
cd /Users/johncalhoun/bsv/mpc/bsv-mpc
git submodule update --init --recursive   # if cggmp21-fork is empty
cargo test --workspace                     # unit + conformance (warning-free clippy: cargo clippy --workspace --all-targets)
# MessageBox e2e (no sats):   MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev cargo test -p bsv-mpc-service --test dkg_2of3_via_messagebox_e2e -- --nocapture --test-threads=1
# Real-sats mainnet (wallet :3321 must be up + funded):
#   MESSAGEBOX_RELAY_URL=… E2E_MAINNET=1 cargo test -p bsv-mpc-service --test sign_mainnet_via_messagebox_e2e within_stack_2of3 -- --nocapture --test-threads=1
```

## 7. KICKOFF PROMPT (paste into the new session)

```
Work on MPC-Spec #4 — implement the presig lifecycle per ADR-0030 (§06.15–§06.21) in bsv-mpc.
Canonical repo: /Users/johncalhoun/bsv/mpc/bsv-mpc (ignore bsv-mpc-DEAD-do-not-use).
Read docs/HANDOFF-PRESIG-LIFECYCLE-ADR0030.md first, then read MPC-Spec/06-transport.md §06.15–21
and MPC-Spec/decisions/0030-presig-coordinator-storage.md IN FULL before any code (spec-first).

Discipline: 110% proof, no asterisks. Every change gated by unit tests + conformance vectors +
(for the on-chain path) a real-mainnet e2e with a cited TXID. Mirror proven patterns. No green-theater;
never claim done without a load-bearing test that fails under the old code. Use the BRC-2 wallet
primitive for share encryption (no hand-rolled AES).

First deliverable: a design/plan for the 8 work items in the handoff (PresigBundle + binding triple,
BRC-2 share encryption, return mailbox, at-rest storage, burn-rate regen, invalidation, sign-time
decrypt, conformance test) — with the exact gate for each — and STOP for my approval before writing
crypto code. Note the only blocker: the final ciphertext byte-match conformance test waits on Binary's
MPC-Spec #9 (3 TBD ciphertexts); ~80% is buildable now against the already-locked intermediate values.
```
