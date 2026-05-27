# #41 native-client foundation — Step 1 audit findings

> **Scope:** `step:investigate` only (issue #41, umbrella #37). This is the realizability
> findings doc + dep/split plan + per-item proof plan. **No implementation in this deliverable.**
> Produced 2026-05-26 on branch `41-audit` off `main` (`04337ba`). 100% Calhoun-solo, zero file
> overlap with the other window's M1 spec-lock (`~/bsv/mpc/MPC-Spec/`).
>
> Every claim below is backed by a **falsifiable artifact** — a pasted dep tree, a cited vendor
> doc, or a `file:line`. Where the truth is "this is unprovable in Rust CI," that boundary is named
> explicitly (§6) rather than papered over. That explicitness *is* the no-asterisk discipline.

---

## Finding 1 — wasm-split of `rust-wallet-toolbox`: exact hostile deps + split boundary

**Artifact:** `cargo tree --depth 1` on `~/bsv/rust-wallet-toolbox` (`bsv-wallet-toolbox-rs v0.3.38`),
default `["sqlite"]` feature:

```
bsv-wallet-toolbox-rs v0.3.38
├── anyhow v1.0.100
├── async-trait v0.1.89
├── base64 v0.22.1
├── bsv-rs v0.3.4                 ← NOTE: toolbox pins 0.3.4; bsv-mpc is on 0.3.13 (version skew, see below)
├── chrono v0.4.43
├── futures v0.3.31
├── futures-util v0.3.31
├── hex v0.4.3
├── once_cell v1.21.3
├── rand v0.8.5
├── reqwest v0.12.28              ← WASM-HOSTILE (hyper + native-tls + tokio net)
├── ring v0.17.14                 ← WASM-HOSTILE in this config (C/asm; wasm needs special handling)
├── ripemd v0.1.3
├── serde v1.0.228
├── serde_json v1.0.149
├── sha2 v0.10.9
├── sqlx v0.8.6                   ← WASM-HOSTILE (libsqlite3-sys = C library)
├── thiserror v1.0.69
├── tokio v1.49.0                 ← WASM-HOSTILE (full features → mio + socket2 = OS sockets)
├── tokio-tungstenite v0.24.0     ← WASM-HOSTILE (native-tls + tokio net)
├── tracing v0.1.44
├── url v2.5.8
├── uuid v1.20.0
└── zeroize v1.8.2                ← already a top-level dep here; reuse this exact version in core (Finding 4)
```

**Exact wasm-hostile crates (from `cargo tree -e features | grep`):** every one of these resolves to a
native-only leaf — they cannot compile to `wasm32-unknown-unknown`:

| Crate | Why it's wasm-hostile (the C / OS-socket leaf) |
|---|---|
| `tokio v1.49.0` (full) | pulls `mio v1.1.1` + `socket2 v0.6.2` → epoll/kqueue OS sockets |
| `sqlx v0.8.6` (sqlite) | pulls `libsqlite3-sys v0.30.1` → links the SQLite **C** library |
| `reqwest v0.12.28` | pulls `hyper v1.8.1` + `native-tls v0.2.14` + `tokio-native-tls` → OS TLS + sockets |
| `tokio-tungstenite v0.24.0` | `native-tls` + tokio net |
| `native-tls` / `tokio-native-tls` | bind OpenSSL/SecureTransport (C) |
| `ring v0.17.14` | C/asm; wasm builds require non-default plumbing — treat as native-only here |

**The asymmetry that is the lever:** `bsv-mpc-core` **already builds `wasm32-unknown-unknown` in CI**
(`.github/workflows/ci.yml:67` `cargo build -p bsv-mpc-core --target wasm32-unknown-unknown`, and `:69`
for `bsv-mpc-worker`). Core is wasm-clean today; the toolbox is not. So the native client does **not**
need the whole toolbox — it needs the toolbox's *pure-Rust tx-assembly knowledge*, not its storage/HTTP
runtime.

**Split boundary (what moves behind a trait / feature-gate):**

```
┌─ WASM-SAFE (pure Rust, no I/O) ───────────────┐   ┌─ NATIVE-ONLY (behind a trait + feature-gate) ─┐
│ • tx construction / input selection logic      │   │ • Storage          → sqlx / libsqlite3-sys    │
│ • fee / change math                             │   │ • Services/broadcast → reqwest / hyper / TLS  │
│ • BEEF assembly, sighash, script building       │   │ • Async runtime I/O → tokio(net) / mio        │
│ • BRC-42 derivation (already in core: hd.rs)    │   │ • WS subscribe      → tokio-tungstenite        │
│   ↓ provided by bsv-mpc-core + bsv-rs (wasm-OK) │   │   ↓ injected by the host shell (Swift/Kotlin/  │
│                                                 │   │     JS) over UniFFI / wasm-bindgen imports     │
└─────────────────────────────────────────────────┘   └────────────────────────────────────────────────┘
```

Concretely: define `trait WalletStorage` and `trait ChainServices` (broadcast/UTXO lookup) in a wasm-safe
crate; the **native** impl uses `sqlx`+`reqwest` (today's toolbox), the **wasm/UniFFI** impl delegates to
host-provided callbacks (the device's own networking/storage). The signing path itself is already wasm-safe
in core. This is the POC-6 finding (toolbox reuse = "~30-line fork") generalized to a feature-gate.

**Open risk to resolve before the wasm-split PR:** **bsv-rs version skew** — toolbox pins `bsv-rs 0.3.4`,
bsv-mpc is on `0.3.13`. The split crate must converge both on one wasm-buildable `bsv-rs` (`0.3.13`, which
core already builds to wasm). This is a dependency-unification task, not a code rewrite.

> **RESOLVED 2026-05-26 (empirical):** pointed the toolbox at local bsv-rs `0.3.13`
> (`features = ["full","http"]`, the exact features it already used) and ran `cargo check` →
> **clean, zero errors / zero warnings, 25s.** So the skew is a **one-line `0.3.4 → 0.3.13` bump
> with no code changes**, not a risk. 0.3.13 keeps `full`/`http` *and* adds a dedicated `wasm`
> feature for the wasm side of the split; bsv-mpc-core already builds wasm32 against 0.3.13. The
> wasm-split PR is unblocked on the dependency axis.

---

## Finding 2 — secp256k1 CANNOT run in Secure Enclave / StrongBox → wrap-key is correct

**Claim:** Apple Secure Enclave and Android StrongBox are hardware key stores that perform ECDSA/ECDH
**only on the NIST P-256 curve (secp256r1)** — never on **secp256k1**, the BSV/Bitcoin curve. Therefore the
MPC share scalar (a secp256k1 secret) **cannot be generated or held as a non-extractable enclave key**.

**Citations (falsifiable):**
- **Apple Secure Enclave** — Apple CryptoKit exposes exactly one curve namespace under `SecureEnclave`:
  `SecureEnclave.P256` (with `.Signing` / `.KeyAgreement`). There is **no** `SecureEnclave.P384`,
  `SecureEnclave.P521`, or any secp256k1 type. P-384/P-521 exist only as **software** CryptoKit types
  (`P384`/`P521`), not Secure-Enclave-backed.
  → https://developer.apple.com/documentation/cryptokit/secureenclave (only `P256` nested type)
- **Android StrongBox** — StrongBox KeyMint (API 28+) documents a deliberately minimal algorithm set:
  *"A subset of algorithms and key sizes are supported … **ECDSA, ECDH P-256**."* secp256k1 is not listed;
  Android additionally deprecated/removed secp256k1 from the Keystore long ago.
  → https://developer.android.com/privacy-and-security/keystore

**Conclusion:** the correct pattern is **wrap-key (seal/unseal)** — the enclave holds a **P-256 wrapping
key** (non-extractable, biometric/`kSecAccessControlBiometryCurrentSet`-gated); the secp256k1 MPC share
lives **encrypted at rest**, sealed under that wrapping key, and is unsealed into host memory only for the
duration of a signing ceremony. The enclave never sees secp256k1; it only gates the unwrap. This delivers
"no silent signing" (every unseal requires a fresh biometric / user presence).

### The asterisk we disclose up front — the in-memory exposure window

| Protected | NOT protected (the named window) |
|---|---|
| Share at rest (sealed; unusable without a biometric-gated enclave unwrap) | The **unsealed secp256k1 scalar lives in host RAM** during the ceremony |
| "No silent signing" — every unseal needs user presence | We **cannot** prove the OS/allocator/swap/JS-GC never copied that plaintext (see Finding 4 + §6.1) |
| Wrapping key is non-extractable hardware-bound | A device already compromised at the OS/root level during the window can read it |

This window is *inherent* to "the hardware can't do our curve" — it is the honest design around a platform
limitation (§6.3), not a defect. We minimize it (zeroize on drop — Finding 4 — bounds the lifetime) and we
**state it**. The threshold property is the real backstop: even a fully-read single share is **one of t+1** —
it cannot sign alone.

---

## Finding 3 — WebAuthn-PRF cross-platform reality → Layer-1 recovery breaks cross-ecosystem, falls to trustees

**Claim:** WebAuthn-PRF (the `prf` extension over CTAP2 `hmac-secret`) can derive a stable, reproducible
key **within a single passkey ecosystem**, but it is **not** a cross-ecosystem backup primitive. A passkey
created in Apple's iCloud Keychain does not exist in Google Password Manager (and vice-versa); there is no
iOS↔Android passkey sync bridge.

**Citations (falsifiable):**
- PRF output is deterministic & reproducible *within an ecosystem*: *"the identical PRF output"* can be
  re-derived on later logins with the same passkey (Corbado, *Passkeys & WebAuthn PRF for E2E Encryption*).
- Loss semantics are absolute: *"PRF-derived keys are bound exclusively to the specific passkey used during
  authentication. If that passkey is lost, the encrypted data becomes permanently inaccessible."* (ibid.)
  → https://www.corbado.com/blog/passkeys-prf-webauthn
- Platform support is **per-ecosystem**: Android PRF via Google Password Manager; iOS/iPadOS PRF via iCloud
  Keychain — two separate sync domains, no interop. Plus live caveats: an **early-iOS-18 data-loss bug**,
  and open **Safari/WebKit CTAP2 `hmac-secret` bugs** (macOS/iPadOS 26.4) that break security-key PRF interop.
  → https://www.w3.org/TR/webauthn-3/#prf-extension (spec), Yubico PRF developer guide, ChromeStatus 5138422207348736

**What this means for the recovery architecture (the layered fallback):**

| Layer | Mechanism | Breaks when … | Falls back to … |
|---|---|---|---|
| **L1** | WebAuthn-PRF passkey unwrap (same ecosystem) | user crosses ecosystems (iOS→Android), loses the only passkey, or hits the iOS-18 / WebKit PRF bugs | **L2** |
| **L2** | Trustee-assisted **reshare** (the #40 true-loss path, already mainnet-proven, TXID `f8b51458…`) | survivor quorum < t | — (true loss; threshold floor) |

⇒ PRF is a **convenience unwrap** layer, **never the sole custody of recoverability**. The durable backstop
is the already-proven trustee reshare (#40). We must **not** ship a design where losing one passkey =
losing funds — the Corbado "permanently inaccessible" warning is exactly the trap, and #40 is the escape.

---

## Finding 4 — zeroize gap: CONFIRMED, with scoped targets

**Confirmed gap:** `bsv-mpc-core` has **no direct `zeroize` dependency.** Evidence:
- `crates/bsv-mpc-core/Cargo.toml` `[dependencies]` — no `zeroize` (only `cggmp24`, `generic-ec`, `bsv`, …).
- `grep -rn zeroize crates/bsv-mpc-core/` → **only comment-mentions**, no code:
  - `presig_at_rest.rs:22-23` (doc comment about rotation "effectively zeroizes")
  - `presig_encryption.rs:62` (doc comment "caller MUST zeroize")
- `zeroize v1.8.2` *is* present transitively (via `aes-gcm → cipher → zeroize`) and is a **direct** dep of
  `rust-wallet-toolbox` — so **adopt that exact version** (`zeroize = "1.8"`, `features = ["zeroize_derive"]`)
  for consistency; no new version enters the lockfile.

**Secret-bearing paths to wrap (confirmed `file:line`, prime targets first):**

| # | Location | Secret material | Wrap |
|---|---|---|---|
| 1 | `ecdh.rs:78` `parse_share_scalar()` | returns raw `[u8; 32]` big-endian secret scalar (`scalar.to_be_bytes()` → `arr`) | `Zeroizing<[u8;32]>` return; zeroize `arr` + `encoded` |
| 2 | `share.rs:115` `decrypt_share()` | returns plaintext share `Vec<u8>` | `Zeroizing<Vec<u8>>` return |
| 3 | `share.rs:68` `encrypt_share(share_bytes)` | plaintext share **input** borrowed | document caller-owns; ensure no internal copy lingers |
| 4 | `share.rs:157` `derive_share_encryption_key()` | returns `[u8; 32]` AES key (+ local `key`/`result` buffers) | `Zeroizing<[u8;32]>` return |
| 5 | `dkg.rs` `assemble_dkg_result()` (~`:759-775`) | deserializes `IncompleteKeyShare` from `incomplete_share_json` (holds `x`) + the stashed JSON + `EncryptedShare` ct | zeroize the stashed `incomplete_share_json` buffer after use |
| 6 | `signing.rs:902` `presig.tilde_chi = SecretScalar::new(&mut shifted)` | the BRC-42 additive-**shifted** secret scalar (`shifted`) | zeroize `shifted` after move |
| 7 | `refresh.rs:343,409,722` `SecretScalar::new(&mut share_scalar / my_secret)` | reshare secret scalars | zeroize the `&mut` byte buffers after construction |
| 8 | `refresh_coordinator.rs:189,377,646` + `reshar_coordinator.rs:569` | `SecretScalar` AsRef + `new(&mut new_share)` | zeroize source buffers post-construction |

**Scope of the zeroize PR (Finding 4 → next step, NOT in this deliverable):**
- Add `zeroize = { version = "1.8", features = ["zeroize_derive"] }` to `bsv-mpc-core`.
- Change the **return types** of the four leaf accessors (#1, #2, #4) to `Zeroizing<T>` (compiler-enforced
  propagation — callers must keep them in `Zeroizing` or explicitly extract).
- For the in-place `&mut [u8;32]` / `Vec<u8>` buffers fed to `SecretScalar::new` (#6,#7,#8), call
  `.zeroize()` (or hold in `Zeroizing`) once the scalar is constructed.
- `#[derive(ZeroizeOnDrop)]` on any owned struct field holding a raw secret (audit `EncryptedShare`/
  key-share structs for plaintext-holding fields; the *ciphertext* is fine, only **plaintext** needs it).
- **No public API behavior change** beyond return-type wrapping (`Zeroizing<T>: Deref<Target=T>`), so
  call sites mostly compile unchanged.

---

## Finding 5 — THE PROOF PLAN ("110% no asterisks" for #41), agreed before any impl PR

#41 is **client + platform**, not pure-Rust crypto, so the proof has two halves and we state the boundary
explicitly. Gold standard, same as every prior god-tier deliverable: **the capstone is a WoC-confirmed
mainnet TXID.**

**Tier 1 — unit tests** (CI, `CARGO_INCREMENTAL=0`, clippy-clean: 4 native crates `--all-targets` + the
wasm worker target, `-D warnings`):
- **zeroize:** `ZeroizeOnDrop`/`Zeroizing<T>` on every secret (compiler-enforced) **+** an observable-Drop
  test (own a buffer via raw ptr, drop, assert bytes are zero) **+** assert no plaintext scalar persists in
  any serialized struct.
- **wrap-key crypto:** KAT seal→unseal round-trip; **wrong wrap-key unseal MUST reject for the right reason**
  (GCM/auth-tag failure — *validate-don't-skip*, assert the specific error, not just `is_err()`).
- **PRF→unwrap-key derivation:** known-PRF-output → known-key vector; tampered PRF input rejects.

**Tier 2 — conformance vectors** (`conformance/test-vectors/`, byte-locked): wrap-key envelope layout +
WebAuthn-PRF→key derivation. These are **self-consistency / future-impl locks** — the native client is
Calhoun-solo, so they are **NOT** rust-mpc parity vectors. We say so; we do not imply cross-impl coverage
we don't have.

**Tier 3 — build + binding gates** (CI):
- `cargo build --target wasm32-unknown-unknown` green on the split crate = the split worked.
- **wasm-bindgen-test** headless: wasm core derives a key / signs **byte-identical to native**.
- **UniFFI:** generated Swift + Kotlin bindings compile + a round-trip test matches expected bytes.

**Tier 4 — god-tier integration capstone:**
1. A **Rust-level full-software integration test** (zeroize + wrapped-share + sign, minus the device
   biometric) as a CI gate, **then**
2. **the first shell signs a real mainnet tx with a biometric-gated, enclave-wrapped share → WoC-confirmed
   TXID.** The chain doesn't lie. That is the no-asterisk end-to-end proof.

---

## §6 — The honest boundaries (hidden asterisks, named)

1. **zeroize is scoped.** It wipes **our** heap buffers (volatile write + fence via the `zeroize` crate). It
   **cannot** prove the OS allocator, swap/page-file, or a JS GC never copied the secret first. The
   no-asterisk claim is the *scoped* one + the documented exposure window (Finding 2). Threshold is the
   real backstop: a leaked single share is one of t+1, useless alone.
2. **Enclave + biometric + passkey cannot be faked in Rust CI.** CI proves crypto vectors + build/binding
   gates (Tiers 1–3); the platform layer is proven **on-device + the mainnet TXID** (Tier 4). Two proofs,
   no hand-wave bridge between them.
3. **secp256k1-not-in-enclave is a documented platform reality** (Finding 2 citations), not a bug. The
   wrap-key pattern is the honest design around it; the in-memory window is its irreducible cost, disclosed.

---

## §7 — Discipline gates carried into every #41 impl PR (non-negotiable)
- **NO commit/push/PR without showing the diff + approval.**
- clippy: **4 native crates `--all-targets` + wasm worker target**, `-D warnings`, `CARGO_INCREMENTAL=0`.
- **Validate, don't skip** — assert rejection paths reject *for the right reason*.
- **Never rustfmt a crate root** (`lib.rs`) — format only edited files; enforced gate is clippy, not fmt.
- Do **not** touch `~/bsv/mpc/MPC-Spec/` (the other window's M1 lane).

## §8 — Recommended sequence after this audit
1. ✅ **Step 1 audit** (this doc).
2. **zeroize PR** (Finding 4) — pure core, no Binary dep, off `main`. *Propose first; STOP for approval
   before writing.* (Demo week: this is a solo PR that can wait for review bandwidth.)
3. **wasm-split toolbox + UniFFI** (Finding 1) — resolve the bsv-rs 0.3.4↔0.3.13 skew first.
4. **enclave wrap-key + WebAuthn-PRF + shells** (Findings 2–3) — capstone = the mainnet TXID (Tier 4).
