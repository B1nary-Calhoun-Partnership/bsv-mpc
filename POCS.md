# bsv-mpc — POCs, MVPs, and Risk Reduction

> Ordered list of proof-of-concept experiments to de-risk the project.
> Each POC validates one assumption. If a POC fails, we know early and can pivot.
> Do these BEFORE writing production code.

---

## Risk Map

| # | Risk | Severity | Likelihood | POC to validate |
|---|------|----------|-----------|----------------|
| 1 | cggmp24 API is too complex / undocumented | HIGH | Medium | POC 1 |
| 2 | cggmp24 doesn't compile to WASM | **CRITICAL** | Low | POC 2 |
| 3 | CF Worker can't run MPC crypto (memory, entropy) | HIGH | Low | POC 2 |
| 4 | Key derivation produces different keys than normal wallet | **CRITICAL** | Medium | POC 3 |
| 5 | Transaction signing produces invalid signatures | **CRITICAL** | Low | POC 4 |
| 6 | MPC signing too slow over HTTP (>500ms) | Medium | Low | POC 5 |
| 7 | rust-wallet-toolbox can't be used as dependency (API changes) | HIGH | Medium | POC 6 |
| 8 | Fee injection breaks transaction validity | Medium | Low | POC 7 |
| 9 | UTXO selection doesn't work with MPC addresses | Medium | Medium | POC 6 |
| 10 | Overlay network infrastructure doesn't exist | Low | High | Defer |

---

## POC 1: cggmp24 Compiles and Signs (2-3 days)

### What we're validating
Can we use cggmp24 to do 2-of-2 DKG and signing on secp256k1?

### What to build
A single Rust binary (not even a library — just `main.rs` with tests):

```rust
// tests/poc_cggmp24.rs

#[tokio::test]
async fn test_two_party_dkg_and_sign() {
    // 1. Create two DKG parties (threshold=2, n=2)
    // 2. Run DKG rounds between them (in-process, no network)
    // 3. Both parties get their shares
    // 4. Compute the joint public key
    // 5. Verify: joint pubkey is a valid secp256k1 point

    // 6. Create a message to sign (32-byte hash)
    // 7. Both parties run signing protocol (in-process)
    // 8. Get the ECDSA signature
    // 9. Verify: bsv::PublicKey::verify(&joint_pubkey, &message, &signature) == true

    // 10. Try presigning:
    //     a. Run 3 presigning rounds
    //     b. Get presignature
    //     c. Run 1 online signing round with presignature
    //     d. Verify signature is valid
}
```

### Pass criteria
- DKG completes without panic
- Signing produces a valid ECDSA signature
- `bsv::PublicKey::verify()` returns true
- Presigning + 1-round signing works

### Fail response
- If cggmp24 API is unusable: try cggmp21 v0.6.3 (older, more stable API)
- If secp256k1 curve not supported: check curve configuration
- If build fails: check Rust version compatibility

### Files to create
```
poc/
  poc1-cggmp24-signing/
    Cargo.toml    # depends on cggmp24, bsv
    src/main.rs   # empty
    tests/poc.rs  # the actual test
```

### Dependencies
```toml
[dependencies]
cggmp24 = { git = "https://github.com/LFDT-Lockness/cggmp21", features = ["num-bigint"] }
cggmp24-keygen = { git = "https://github.com/LFDT-Lockness/cggmp21", features = ["num-bigint"] }
bsv = { path = "../../rust-sdk", features = ["transaction"] }
tokio = { version = "1", features = ["full"] }
rand = "0.8"
```

---

## POC 2: WASM Compilation + CF Worker (1-2 days)

### What we're validating
Does cggmp24 compile to wasm32-unknown-unknown and run in a CF Worker?

### What to build
1. Take POC 1's signing logic
2. Compile to `wasm32-unknown-unknown`
3. Run in Node.js via `wasm-pack test --node`
4. Deploy a minimal CF Worker that runs DKG round 1

### Specific concerns
- `getrandom` needs `js` feature for WASM entropy
- `num-bigint` backend (avoiding GMP/rug) — may be slower
- CF Worker memory limit: 128MB
- CF Worker CPU time: is DKG (~230ms) within limits?

### Pass criteria
- `cargo build --target wasm32-unknown-unknown` succeeds
- WASM module size < 50MB (ideally < 10MB)
- Signing test passes in WASM
- DKG round completes within CF Worker CPU limits

### Fail response
- If WASM won't compile: identify blocking dependency, find alternative
- If module too large: check if tree-shaking helps, consider feature flags
- If memory exceeds 128MB: profile, reduce allocations
- If entropy fails: test alternative `getrandom` backends
- **If CF Worker completely fails: fall back to CF Container or standalone binary (bsv-mpc-service)**. This is a deployment change, not an architecture change.

### Files to create
```
poc/
  poc2-wasm/
    Cargo.toml
    src/lib.rs        # WASM entry point
    tests/wasm.rs     # wasm-pack test
```

---

## POC 3: BRC-42 Key Derivation Compatibility (1 day)

### What we're validating
Can the MPC system derive the SAME public keys as a normal wallet for the same protocol/key/counterparty tuple?

### Why this is critical
If the MPC proxy returns a different public key for `getPublicKey([2, "3241645161d8"], "prefix suffix", server_key)`, then:
- BRC-31 auth fails (server derives a different key → signature mismatch)
- x402 payments fail (server can't verify the payment was for them)
- Memory encryption fails (different key → can't decrypt)

### What to build
```rust
#[test]
fn test_key_derivation_matches_normal_wallet() {
    // 1. Create a normal ProtoWallet with a known root key
    let root_key = PrivateKey::from_hex("known-test-key");
    let proto_wallet = ProtoWallet::new(root_key);

    // 2. Derive a public key the normal way
    let normal_pubkey = proto_wallet.key_deriver().derive_public_key(
        &Protocol::new(SecurityLevel::Counterparty, "3241645161d8"),
        "test-prefix test-suffix",
        &Counterparty::Other(server_pubkey),
    );

    // 3. Now simulate: if the MPC system holds the same root key (as shares),
    //    and we reconstruct the derivation, do we get the same pubkey?

    // BRC-42 derivation:
    //   invoice = "2-3241645161d8-test-prefix test-suffix"
    //   scalar = HMAC-SHA256(root_key, invoice) mod n
    //   child_pubkey = root_pubkey + scalar*G

    let invoice = format!("2-3241645161d8-test-prefix test-suffix");
    let scalar = hmac_sha256(root_key.to_bytes(), invoice.as_bytes());
    let scalar_mod_n = scalar_from_bytes(&scalar); // mod secp256k1 order
    let child_pubkey = root_pubkey + scalar_mod_n * G;

    // 4. Verify they match
    assert_eq!(normal_pubkey, child_pubkey);
}
```

### The critical question
With MPC, the root key is split into shares. Can we compute `root_pubkey + scalar*G` without knowing `root_private_key`?

**Answer: YES.** Public key derivation only needs the root PUBLIC key (not private key). The scalar is derived from the invoice string + the root public key (for the counterparty derivation, it uses ECDH which can also be done via MPC). For `counterparty: "self"`, the derivation is simpler — it only uses the root key's public component.

**But for signing**, we need `root_private_key + scalar` as the signing key. With MPC:
- Each party locally adds `scalar` to their share
- `share_A' = share_A + scalar`, `share_B' = share_B + scalar`
- `share_A' + share_B' = (share_A + share_B) + 2*scalar` ← WRONG!

**Wait — this is the HD derivation problem.** cggmp24 supports SLIP-10/BIP-32 HD derivation, which handles this correctly. The shares are adjusted so that additive key derivation works with threshold signing.

### Pass criteria
- Derived public keys match between normal wallet and MPC-derived computation
- Signing with MPC-derived child key produces verifiable signatures

### Fail response
- If derivation differs: check BRC-42 vs BIP-32 differences (BRC-42 uses HMAC for scalar, BIP-32 uses hash chain)
- This is a design issue, not an implementation issue — if BRC-42 derivation is incompatible with MPC, we need a different approach (e.g., derive keys locally in the proxy using a local key, only use MPC for the root signing operations)

---

## POC 4: Sign a Real BSV Transaction (2-3 days)

### What we're validating
Can the MPC signing produce a transaction that the BSV network accepts?

### What to build
```rust
#[tokio::test]
async fn test_mpc_signed_transaction_is_valid() {
    // 1. Two-party DKG → joint public key
    // 2. Fund the MPC address (send 10,000 sats — mainnet, never testnet)
    // 3. Build a P2PKH transaction spending from the MPC address
    // 4. Compute sighash (BIP-143)
    // 5. MPC sign the sighash → ECDSA signature
    // 6. Build unlocking script (sig + pubkey)
    // 7. Verify transaction locally (script evaluation)
    // 8. Broadcast to mainnet
}
```

### Pass criteria
- Transaction passes local script evaluation
- Transaction is accepted by BSV mainnet
- Signature is standard DER format
- Unlocking script is standard P2PKH

### Fail response
- Signature format wrong: check DER encoding, low-S normalization
- Sighash wrong: compare against a normal wallet's sighash for same transaction
- Script evaluation fails: debug the unlocking script bytes

---

## POC 5: HTTP Round-Trip Signing Latency (1 day)

### What we're validating
Is MPC signing fast enough over HTTP between proxy and Key Share Service?

### What to build
- Start bsv-mpc-service on port 4322
- Start bsv-mpc-proxy on port 3322
- Proxy sends signing requests to service
- Measure end-to-end latency

### Target
- <200ms for full 4-round signing (no presig)
- <50ms for 1-round signing (with presig)
- <500ms worst case

### Pass criteria
- P50 latency < 100ms (4-round, localhost)
- P99 latency < 300ms
- Presigned path < 30ms

### Fail response
- If too slow: profile where time is spent (crypto vs network vs serialization)
- Consider batching rounds (send all rounds in one message)
- Consider WebSocket instead of HTTP for lower overhead

---

## POC 6: rust-wallet-toolbox as Dependency (1-2 days)

### What we're validating
Can bsv-mpc-proxy depend on rust-wallet-toolbox and swap the signer?

### Why this matters
The wallet investigation revealed rust-wallet-toolbox has a clean architecture:
```
Wallet<StorageSqlx, Services>
  ├── ProtoWallet (signing) ← swap this
  ├── StorageSqlx (UTXO mgmt) ← keep this
  └── WalletSigner ← replace this
```

If we can use the toolbox as a dependency, we save 4+ weeks of reimplementation.

### What to build
```rust
// In bsv-mpc-proxy/Cargo.toml:
[dependencies]
rust-wallet-toolbox = { path = "../../rust-wallet-toolbox" }

// In bsv-mpc-proxy/src/mpc_signer.rs:
pub struct MpcSigner {
    bridge: MpcBridge,
}

impl MpcSigner {
    /// Replace WalletSigner::sign_transaction
    pub async fn sign_transaction(
        &self,
        unsigned_tx: &[u8],
        inputs: &[SignerInput],
    ) -> Result<Vec<u8>> {
        for input in inputs {
            let sighash = compute_sighash(unsigned_tx, input);  // reuse from toolbox
            let signature = self.bridge.sign(&sighash).await?;  // MPC signing
            // build unlocking script, insert into tx
        }
    }
}
```

### Pass criteria
- `cargo build -p bsv-mpc-proxy` succeeds with toolbox dependency
- Can construct a `Wallet<StorageSqlx, Services>` instance
- Can intercept the signing layer
- UTXO selection + fee calculation works unchanged

### Fail response
- If toolbox API is too tightly coupled to ProtoWallet: fork and refactor
- If storage layer has version conflicts: pin compatible versions
- Worst case: extract just the sighash computation and UTXO selection logic

---

## POC 7: Fee Injection (1 day)

### What we're validating
Can we add a fee output to a transaction without breaking its validity?

### What to build
```rust
#[test]
fn test_fee_injection() {
    // 1. Build a normal transaction (1 input, 1 output, 1 change)
    // 2. Inject a fee output (1000 sats to a P2PKH address)
    // 3. Adjust change output to account for fee
    // 4. Verify: total inputs = total outputs + mining fee
    // 5. Sign and verify the transaction is valid
}
```

### Pass criteria
- Transaction with injected fee output passes script evaluation
- Change output correctly adjusted
- Mining fee correctly calculated with extra output

### Fail response
- If fee injection changes txid before signing: ensure injection happens before sighash computation (it should, since injection modifies outputs which affect hashOutputs in the sighash)

---

## POC Execution Order

```
Week 1:
  Day 1-2: POC 1 (cggmp24 signs)           ← GO/NO-GO for the whole project
  Day 3:   POC 2 (WASM compilation)         ← GO/NO-GO for CF Worker deployment
  Day 4:   POC 3 (key derivation compat)    ← GO/NO-GO for wallet replacement

Week 2:
  Day 1-2: POC 6 (toolbox as dependency)    ← determines build approach
  Day 3:   POC 4 (real BSV transaction)     ← validates end-to-end signing
  Day 4:   POC 5 (HTTP latency)             ← validates deployment topology
  Day 5:   POC 7 (fee injection)            ← validates economics

Total: ~2 weeks to validate all assumptions before writing production code.
```

### Decision Gates

| After POC | Decision |
|-----------|----------|
| POC 1 fails | **STOP.** Evaluate alternative MPC libraries (cb-mpc via FFI, tss-lib via Go FFI). |
| POC 2 fails | CF Worker path is dead. Use CF Container or standalone binary for KSS. Core architecture unchanged. |
| POC 3 fails | Key derivation approach needs rethinking. May need to do derivation locally and only MPC-sign at root level. |
| POC 6 fails | Fork bsv-wallet-cli instead of depending on toolbox. More work but still viable. |
| All POCs pass | **GREEN LIGHT.** Proceed to production implementation with confidence. |

---

## MVP After POCs: "MPC-Signed LLM Call"

The minimum viable product after POCs:

1. Start `bsv-mpc-service` (Key Share Service) on port 4322
2. Start `bsv-mpc-proxy` (signing proxy) on port 3322
3. Start `bsv-worm serve` pointing at proxy
4. Send a chat message: "What is 2+2?"
5. bsv-worm calls the LLM via x402
6. Payment transaction is MPC-signed (proxy + KSS cooperate)
7. LLM responds "4"
8. On-chain proof shows the MPC-signed transaction

**That's the demo.** An AI agent that pays for its own inference, where the signing key never exists on any single machine.
