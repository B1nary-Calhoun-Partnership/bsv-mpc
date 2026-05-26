# Handoff — #41 native-client foundation: Step 1 audit (+ the proof plan)

> **Read this first, in full.** This starts **issue #41** (part of umbrella #37): the greenfield
> **native client** that wraps the already-proven MPC primitives — the biggest net-new surface,
> **100% Calhoun-solo**, no Binary dependency. Begin with the **Step 1 audit** (`step:investigate`),
> whose deliverable is a *realizability findings doc + dep/split plan + a per-item proof plan*.
> Canonical repo: `/Users/johncalhoun/bsv/mpc/bsv-mpc`. Work on a fresh branch off `main`.

---

## 0. State / timing (as of 2026-05-26)
- **#40 true-loss recovery LANDED on mainnet** (TXID `f8b51458…`); **#50, #58** done/closed.
- **M1 cross-impl demo = 2026-05-29 (Fri, imminent)**; **Phase 0 spec-lock = 2026-06-12**. Cross-impl
  partner = **rust-mpc** (Binary / Mitch + Ishaan). Partnership is **async-only** (Slack + GitHub).
- **The M1 *code* quick-wins already merged** (PR **#61**, commit `04337ba`):
  - **#55** — `dkg.rs:574` `keygen_joint_pubkey()` + `:584` `keygen_joint_key()` accessors.
  - **#17** — shared `pub(crate)` index helper extracted to **`crates/bsv-mpc-service/src/index.rs`**
    (`pos_to_abs`/`abs_to_pos`), wired through **both** `signing_handler.rs` (now carries `participants`)
    **and** `presign_handler.rs`. (GitHub issue **#55 is still OPEN** — PR #61 didn't auto-close it;
    minor hygiene to close.)
- **The other window's *remaining* M1 work is the spec-lock (#2)** in **`~/bsv/mpc/MPC-Spec/`** (ADRs
  0051/0037/0044/0032 + conformance vectors) — a **separate tree**.

## 1. Why #41 is clear to start NOW, in parallel
File-overlap analysis (the only thing that gates parallel work):

| Other window (remaining M1) | Where | Overlap with #41 |
|---|---|---|
| Spec-lock #2 (ADRs + vectors) | `~/bsv/mpc/MPC-Spec/` (separate dir) | **none** |
| Code #55/#17 | bsv-mpc | **already merged** (#61) — not concurrent |

⇒ The dkg.rs collision risk I'd flagged earlier (zeroize vs #55) is **gone** — #55 is on `main`.
**#41 has zero file overlap with the other window.** Branch off the current `main` (`04337ba`+) and go.
Only caution: it's **demo week** — keep #41 PRs from competing for M1 *review* bandwidth (the audit is a
doc; zeroize is a solo PR that can wait for review).

## 2. What #41 is (issue #41, label step:implement/security)
Native CLIENT that wraps the primitives. All net-new but understood:
- **zeroize** — secret scalars are **not** zeroized today (no `zeroize` dep in core). Small core change.
- **wasm-split wallet-toolbox** — toolbox not wasm-buildable (hard-pinned tokio/sqlx/reqwest); **core
  already builds wasm32 in CI** (`.github/workflows/ci.yml:58/66/70`) — that asymmetry is the lever.
- **UniFFI** bindings; **enclave wrap-key** (Secure Enclave/StrongBox can't run secp256k1 → seal/unseal
  the share, biometric-gated, no silent signing); **WebAuthn-PRF** passkey backup; **3 shells** (iOS/Android/web).

## 3. Sequence (do in this order — each a reviewable diff, show before PR)
1. **Step 1 audit** (this handoff's job) → findings doc + dep/split plan + per-item proof plan.
2. **zeroize** (first impl; pure core, no Binary dep) — off new `main`, no two-window collision now.
3. **wasm-split toolbox + UniFFI** — per the audit's dep/split plan.
4. **enclave wrap-key + WebAuthn-PRF + shells** — capstone is the mainnet TXID (see §5).

## 4. Step 1 audit — concrete checklist (the deliverable)
Produce `docs/41-AUDIT-FINDINGS.md` with falsifiable artifacts, not vibes:
- [ ] **`cargo tree -e features`** on `~/bsv/rust-wallet-toolbox`: enumerate the **exact** wasm-hostile
  deps (tokio/sqlx/reqwest/…) + the **split boundary** (what moves behind a trait / feature-gate). Paste
  the tree excerpt.
- [ ] **Confirm secp256k1 cannot run inside Secure Enclave / StrongBox** (cite Apple/Android docs) → the
  **wrap-key** (seal/unseal the share, biometric-gated) is the correct pattern. **Document the in-memory
  exposure window** (what's protected, what isn't) — this is the asterisk we disclose up front.
- [ ] **Confirm WebAuthn-PRF cross-platform reality** (iOS↔Android passkey sync stability; what breaks
  Layer-1 recovery → falls to trustees).
- [ ] **Confirm + scope the zeroize gap.** Confirmed: **no `zeroize` dep in core** (only comment-mentions
  in `presig_encryption.rs`/`presig_at_rest.rs`). Secret-bearing paths to wrap in `Zeroizing<T>` /
  `ZeroizeOnDrop`:
  - `ecdh.rs:78` `parse_share_scalar()` → returns a raw `[u8;32]` secret scalar (prime target).
  - `share.rs:115` `decrypt_share()` → returns plaintext share `Vec<u8>`; `:68` `encrypt_share` input;
    `:157` `derive_share_encryption_key` → `[u8;32]`.
  - `dkg.rs` key_share construction (~`:750-768`) + the `EncryptedShare` ciphertext.
  - also: `signing.rs`, `presigning.rs`, `refresh.rs`, `refresh_coordinator.rs`, `reshar_coordinator.rs`
    (secret scalars / shares).
- [ ] **Bake the per-item proof plan (§5) into the findings doc** so "done + proven" is agreed before any
  impl PR.

## 5. THE PROOF PLAN — "110% no asterisks" for #41
#41 is **not** pure-Rust crypto (it's client + platform), so the proof has two halves and we state the
boundary explicitly — *that explicitness is the no-asterisk discipline*. Same gold standard as every prior
god-tier deliverable: **the capstone is a WoC-confirmed mainnet TXID.**

**Tier 1 — unit tests (CI, `CARGO_INCREMENTAL=0`, clippy-clean 4 native + wasm worker):**
- zeroize: `ZeroizeOnDrop`/`Zeroizing<T>` wired on every secret (compiler-enforced) + an observable-Drop
  test (hold the buffer, assert zeroed after drop) + assert no plaintext scalar persists in serialized structs.
- wrap-key crypto: KAT seal→unseal round-trip; **wrong wrap-key unseal MUST reject for the right reason**
  (validate-don't-skip).
- PRF→unwrap-key derivation: known-PRF-output → known key vector; tampered input rejects.

**Tier 2 — conformance vectors (`conformance/test-vectors/`, byte-locked):** wrap-key envelope layout +
WebAuthn-PRF→key derivation. (Self-consistency / future-impl locks — the native client is Calhoun-solo,
so these are **not** rust-mpc parity vectors; say so, don't imply cross-impl coverage we don't have.)

**Tier 3 — build + binding gates (CI):**
- `cargo build --target wasm32-unknown-unknown` green = split worked.
- **wasm-bindgen-test** headless: wasm core derives a key / signs **byte-identical to native**.
- **UniFFI**: generated Swift + Kotlin bindings compile + a round-trip test matches expected bytes.

**Tier 4 — god-tier integration capstone:**
- A **Rust-level full-software integration test** (zeroize + wrapped-share + sign, minus device biometric)
  as a CI gate, **then**
- **first shell signs a real mainnet tx with a biometric-gated, enclave-wrapped share → WoC-confirmed TXID.**
  The chain doesn't lie. That's the no-asterisk end-to-end proof.

**The honest boundaries (kill the hidden asterisks by naming them):**
1. zeroize wipes **our** heap buffers (volatile-write + fence via the `zeroize` crate); it **cannot** prove
   the OS/allocator/page-file/JS-GC never copied the secret. The no-asterisk claim is the *scoped* one +
   the documented exposure window.
2. enclave + biometric + passkey **cannot** be faked in Rust CI: CI proves crypto vectors + build/binding
   gates; the platform layer is proven **on-device + the mainnet TXID**. Two proofs, no hand-wave bridge.
3. **secp256k1-not-in-enclave** is a documented platform reality (cite), not a bug — the wrap-key pattern
   is the honest design around it.

## 6. Discipline / gates (non-negotiable)
- **NO commit/push/PR without showing the diff + getting approval.**
- Warning-free **clippy: 4 native crates `--all-targets` + the wasm worker target**, `-D warnings`,
  `CARGO_INCREMENTAL=0`.
- **Validate, don't skip** — assert rejection paths (reject for the *right reason*).
- **Never rustfmt a crate root** (`lib.rs`) — it cascades + reflows pre-existing-unformatted files (main is
  CI-red on fmt). **Format only the files you edited.** The enforced gate is clippy, not fmt.
- Spec ADRs live in `~/bsv/mpc/MPC-Spec/decisions/` (don't touch — that's the other window's M1 lane).
- This handoff is **uncommitted** until approved.

## 7. Key refs
- Issue **#41** (umbrella **#37**); related closed: #40, #58, #50.
- Repos: `~/bsv/mpc/bsv-mpc` (this), `~/bsv/rust-wallet-toolbox` (to wasm-split), `~/bsv/mpc/MPC-Spec`
  (spec, other window), `~/bsv/rust-message-box` (relay), `~/bsv/bsv-rs` (SDK, crate `bsv-rs 0.3.13`).
- Landed M1 code: `dkg.rs:574/584` (#55 accessors), `bsv-mpc-service/src/index.rs` (#17 `pos_to_abs`/
  `abs_to_pos`), wired through `signing_handler.rs` + `presign_handler.rs`.
