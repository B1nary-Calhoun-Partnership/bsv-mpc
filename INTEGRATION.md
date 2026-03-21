# bsv-mpc ↔ bsv-worm Integration Guide

> How bsv-worm talks to its wallet, and exactly what the MPC signing proxy must implement to replace it.
> Based on source analysis of ~/bsv/rust-bsv-worm/ (90 .rs files, ~2350 lines in runner alone).

---

## The Contract: bsv-worm expects a wallet at localhost:3322

bsv-worm's `src/wallet.rs` is a thin HTTP client that sends JSON POST requests to a BRC-100 wallet. The wallet URL comes from config (`WalletConfig.url`, default `http://localhost:3322`). One known bug: `src/tools/wallet_tools.rs:13` hardcodes `localhost:3322` — must be fixed before any non-local wallet works.

**The MPC proxy sits at localhost:3322 and responds to the same HTTP endpoints.** bsv-worm requires zero code changes (except the wallet_tools.rs hardcoded URL fix).

---

## Endpoints by Priority

### TIER 1: Called Every Agent Iteration (MUST implement)

These are in the critical hot path — every think/act/record cycle uses them.

#### `getPublicKey`
**Called by:** auth/client.rs (BRC-31 handshake), x402/payment.rs (derive payment key), tools/wallet_tools.rs (wallet_identity tool), messagebox/ (signing), runner/ (identity)

**Request:**
```json
{
  "protocolID": [2, "3241645161d8"],
  "keyID": "some-derivation-suffix",
  "counterparty": "02abc...def",
  "forSelf": false
}
```

**Response:**
```json
{
  "publicKey": "02abc...def"
}
```

**MPC proxy behavior:** Derive child public key from the joint MPC public key using BRC-42 HMAC-SHA256 scalar multiplication. The derivation MUST produce the exact same key as a normal wallet with the same root key — otherwise BRC-31 auth and x402 payments will fail (the server derives the matching key independently).

**Critical detail:** When `forSelf: true`, derive from own identity key. When `counterparty` is specified, derive using ECDH shared secret. This is BRC-42's bilateral key derivation.

#### `createSignature`
**Called by:** auth/client.rs (sign auth messages), x402/payment.rs (sign payment data for some auth flows), messagebox/ (BRC-77 message signing)

**Request:**
```json
{
  "data": [1, 2, 3, ...],
  "protocolID": [2, "auth message signature"],
  "keyID": "nonce-value",
  "counterparty": "02server..."
}
```

**Response:**
```json
{
  "signature": [48, 69, 2, ...]
}
```

**MPC proxy behavior:** This is THE MPC signing operation.
1. Derive the signing key using BRC-42 (same derivation as getPublicKey)
2. Run MPC threshold signing protocol with Key Share Service
3. With presignature: 1 round (~7-15ms). Without: 4 rounds (~28-180ms)
4. Return standard DER-encoded ECDSA signature

**Critical detail:** Response is a byte array, NOT hex string. The `data` field is raw bytes to sign (typically a SHA-256 hash). The signature must be verifiable against the public key returned by `getPublicKey` with the same derivation params.

#### `createAction`
**Called by:** x402/payment.rs (construct payment tx), onchain/proofs.rs (create BRC-18 proofs), onchain/state.rs (create BRC-48 tokens), session/conversation.rs (wallet sync)

**Request:**
```json
{
  "description": "x402 payment to openai-chat.x402agency.com",
  "outputs": [
    {
      "satoshis": 50000,
      "lockingScript": "76a914...88ac",
      "basket": "default",
      "description": "LLM payment"
    }
  ],
  "options": {
    "acceptDelayedBroadcast": false,
    "randomizeOutputs": false
  }
}
```

**Response:**
```json
{
  "txid": "abc123...",
  "tx": [1, 2, 3, ...],
  "rawTx": "optional hex"
}
```

**MPC proxy behavior:** This is the HARDEST endpoint. It must:
1. Select UTXOs from the wallet's tracked outputs (enough to cover outputs + mining fee)
2. Construct the transaction (inputs, outputs, change output)
3. **Inject the MPC fee output** (additional output to multisig address)
4. Calculate the mining fee
5. Run MPC signing for each input
6. Serialize to the appropriate format (raw tx, BEEF, or AtomicBEEF)
7. Broadcast to the BSV network
8. Return txid + tx bytes

**Critical detail:** The `tx` response may be raw bytes, BEEF, or AtomicBEEF depending on wallet version. bsv-worm's `x402/payment.rs` auto-detects the format. The proxy should return AtomicBEEF for best compatibility.

#### `listOutputs`
**Called by:** wallet.rs `get_balance()` (paginates and sums), onchain/state.rs (list state tokens), certificates.rs (check revocation UTXOs)

**Request:**
```json
{
  "basket": "default",
  "include": "locking scripts",
  "limit": 100,
  "offset": 0
}
```

**Response:**
```json
{
  "outputs": [
    {
      "txid": "abc...",
      "vout": 0,
      "satoshis": 50000,
      "lockingScript": "76a914...88ac",
      "spendable": true,
      "outputDescription": "..."
    }
  ]
}
```

**MPC proxy behavior:** Must maintain a UTXO set. Options:
- **Full UTXO tracker:** Parse every tx the proxy creates, track outputs. This is what bsv-wallet-cli does (SQLite).
- **Chain sync:** Query a block explorer (WhatsOnChain) for UTXOs at the joint MPC address. Simpler but depends on external service.
- **Hybrid:** Track locally-created UTXOs + periodic chain sync for incoming funds.

**Critical detail:** `get_balance()` paginates with limit=100, offset=0,100,200... until it gets fewer than 100 results. The proxy must support this pagination correctly.

#### `encrypt` / `decrypt`
**Called by:** memory/encrypt.rs (memory files), onchain/state.rs (state token data), session/conversation.rs (conversation sync)

**Request:**
```json
{
  "plaintext": [1, 2, 3, ...],
  "protocolID": [2, "worm memory"],
  "keyID": "knowledge",
  "counterparty": "self"
}
```

**Response:**
```json
{
  "ciphertext": [1, 2, 3, ...]
}
```

**MPC proxy behavior:** Does NOT need MPC — encryption is symmetric. Derive an AES-256 key from the MPC-derived encryption key using BRC-42 (HMAC-SHA256 of protocol + key_id + counterparty), then AES-256-GCM encrypt/decrypt.

**Critical detail:** Must be compatible with data already encrypted by a normal wallet. If the proxy uses a different root key (MPC joint key ≠ original root key), old encrypted data is unreadable. For fresh agents this is fine. For migration, need a re-encryption step.

---

### TIER 2: Called During Task Lifecycle (SHOULD implement)

#### `internalizeAction`
**Called by:** x402/payment.rs (process refunds from x402 services), x402/refund.rs (parse excess refund outputs), wallet.rs `fund_from_woc()` (internalize external funding)

**What it does:** Takes an external transaction and adds its outputs to the wallet's UTXO set. The wallet verifies the transaction is valid and the outputs are spendable by derived keys.

**MPC proxy behavior:** Parse the tx, verify output scripts match derivable keys, add to UTXO tracker. No MPC signing needed.

#### `relinquishOutput`
**Called by:** onchain/state.rs (spend and recreate state tokens), certificates.rs (revoke/relinquish certs)

**What it does:** Removes a UTXO from the wallet's tracking (marks it as spent or abandoned).

**MPC proxy behavior:** Remove from UTXO tracker. No signing needed.

#### `verifySignature`
**Called by:** server/auth.rs (verify incoming BRC-31 auth from clients), messagebox/ (verify BRC-77 message signatures)

**What it does:** Verify an ECDSA signature using BRC-42 derived key.

**MPC proxy behavior:** Derive the public key via BRC-42, standard ECDSA verify. No MPC needed — verification is a local operation.

---

### TIER 3: Optional (CAN stub or defer)

| Endpoint | What bsv-worm uses it for | Stub behavior |
|----------|--------------------------|---------------|
| `listCertificates` | BRC-52 certificate management | Return empty array |
| `acquireCertificate` | Parent cert acquisition | Return error (no parent cert support) |
| `proveCertificate` | Prove identity to message recipients | Return error (degrade to unsigned) |
| `relinquishCertificate` | Clean up revoked certs | Return success (no-op) |
| `discoverByIdentityKey` | BRC-56 peer discovery | Return empty array (no discovery) |
| `discoverByAttributes` | BRC-56 peer discovery | Return empty array |
| `revealCounterpartyKeyLinkage` | Audit compliance (BRC-42) | Return error (compliance unavailable) |
| `revealSpecificKeyLinkage` | Audit compliance (BRC-42) | Return error |
| `isAuthenticated` | Startup check | Return `true` |
| `getNetwork` | Network check | Return `"main"` |
| `getVersion` | Version check | Return `"mpc-proxy-0.1.0"` |
| `waitForAuthentication` | Startup wait | Return immediately |
| `getHeight` | Block height | Return 0 (not tracked) |
| `createHmac` / `verifyHmac` | Only via wallet_call tool | Return error |
| `listActions` | Only via wallet_call tool | Return empty array |

---

## Protocol IDs That Must Match Exactly

The MPC proxy must derive identical keys for these protocol IDs. If any derivation is wrong, the corresponding feature breaks silently (signatures won't verify, encryption won't decrypt).

| Protocol ID | Key ID Pattern | Counterparty | Used For | Breaks If Wrong |
|------------|---------------|--------------|----------|----------------|
| `[2, "3241645161d8"]` | `"{prefix} {suffix}"` | Server identity key | **x402 payments** | Payment rejected by server |
| `[2, "auth message signature"]` | Nonce string | Server identity key | **BRC-31 auth** | Auth handshake fails (401) |
| `[2, "worm memory"]` | Category name | `"self"` | Memory encryption | Memory unreadable |
| `[2, "worm state"]` | `"tokens"` | `"self"` | State token encryption | Tokens unreadable |
| `[2, "worm conversation"]` | Conversation ID | `"self"` | Conversation sync | Conversation data lost |
| `[2, "worm message signature"]` | `"message"` | `"self"` or sender key | MessageBox signing | Messages rejected |
| `[2, "worm message encryption"]` | `"message"` | Recipient key | MessageBox encryption | Messages unreadable |
| `[2, "CHIP"]` | Topic name | `"anyone"` (1*G) | Overlay CHIP tokens | Tokens invalid |

**Key derivation algorithm (BRC-42):**
```
invoice_number = "{security_level}-{protocol_id_hex}-{key_id}"
scalar = HMAC-SHA256(root_key, invoice_number) mod n
child_key = root_key + scalar  (for private key)
child_pubkey = root_pubkey + scalar*G  (for public key)
```

The MPC proxy must implement this derivation. For encryption (counterparty = "self"), the ECDH shared secret is derived between the child private key and the child public key of the same root — effectively a deterministic symmetric key.

---

## Transaction Construction Deep Dive

The x402 payment flow in `src/x402/payment.rs` is the most complex wallet interaction:

```
create_payment(wallet, requirements, server_identity_key)
│
├── 1. Generate random 32-byte derivation_suffix
│
├── 2. Derive payment pubkey via BRC-42:
│      wallet.get_public_key(
│        protocol_id: [2, "3241645161d8"],
│        key_id: "{derivation_prefix} {derivation_suffix}",
│        counterparty: server_identity_key
│      )
│
├── 3. Build P2PKH locking script from derived pubkey
│
├── 4. Call wallet.create_action(outputs: [{
│        satoshis: required_sats,
│        lockingScript: p2pkh_script,
│        basket: "default"
│      }])
│
│      ╔══════════════════════════════════════╗
│      ║  THIS IS WHERE THE MPC PROXY MUST:  ║
│      ║  a. Select UTXOs                    ║
│      ║  b. Build transaction               ║
│      ║  c. INJECT FEE OUTPUT               ║
│      ║  d. Calculate mining fee            ║
│      ║  e. MPC-sign each input             ║
│      ║  f. Broadcast                       ║
│      ╚══════════════════════════════════════╝
│
├── 5. Get back tx bytes (raw/BEEF/AtomicBEEF)
│
├── 6. Detect format:
│      - Starts with [1,0,0xBE,0xEF] → BEEF
│      - Starts with [1,1,0,0xBE,0xEF] → AtomicBEEF
│      - Otherwise → raw tx
│
├── 7. Base64-encode for x-bsv-payment header
│
├── 8. If payment > 8KB (MULTIPART_THRESHOLD in payment.rs):
│      Switch to multipart/form-data body transport (BRC-105)
│
└── 9. Send to server, get response
```

**For fee injection:** The proxy intercepts step 4. Before signing, it adds:
```
Output N+1: {
  satoshis: 1000,  // MPC fee
  lockingScript: <multisig_script_of_mpc_nodes>
}
```
Then adjusts the change output to account for the additional fee.

---

## What Needs to Happen in bsv-worm (the 1-line fix + nice-to-haves)

### Must Fix
- `src/tools/wallet_tools.rs:13` — Change hardcoded `localhost:3322` to use config wallet URL

### Nice to Have
- Add `WORM_WALLET_MODE` env var: `"native"` (bsv-wallet-cli), `"mpc"` (bsv-mpc-proxy), `"remote"` (any URL)
- Log which wallet mode is in use at startup
- Health check the wallet on startup with a timeout (already does this in `status` subcommand)

### Do NOT Change
- `src/wallet.rs` — The HTTP client is wallet-agnostic. It sends JSON, gets JSON. Leave it alone.
- `src/x402/payment.rs` — The payment flow is proxy-agnostic. It calls wallet methods. Leave it alone.
- `src/auth/client.rs` — The auth flow calls wallet.createSignature(). Works with any signer.

---

## POC / MVP Milestones for Risk Reduction

### POC 1: cggmp24 compiles and signs (HIGHEST RISK)
**Risk:** cggmp24 API is complex, poorly documented.
**Test:** Two-party DKG → sign → verify. All in-process, no network.
**Pass criteria:** Valid secp256k1 signature verified by bsv SDK's `PublicKey::verify()`.
**Time:** 2-3 days.

### POC 2: cggmp24 compiles to WASM (HIGH RISK)
**Risk:** WASM + crypto entropy + CF Worker constraints.
**Test:** Same as POC 1 but compiled to wasm32-unknown-unknown, run in Node.js.
**Pass criteria:** Same signature verification passes in WASM.
**Time:** 1-2 days.

### POC 3: MPC proxy passes bsv-worm's startup health check
**Risk:** Response format mismatch.
**Test:** Start the proxy, point bsv-worm at it, run `bsv-worm status`.
**Pass criteria:** Status command shows balance, identity key.
**Time:** 1-2 days (after Tier 1 endpoints are stubbed).

### POC 4: MPC proxy handles a real x402 payment
**Risk:** Transaction construction, UTXO selection, fee calculation.
**Test:** bsv-worm calls `think "hello"` through the proxy.
**Pass criteria:** LLM responds, payment confirmed on-chain, agent has valid proof.
**Time:** 3-5 days (the hardest POC — requires full createAction implementation).

### POC 5: Two-party signing over HTTP
**Risk:** Network latency, round-trip serialization.
**Test:** Proxy at localhost:3322 talks to bsv-mpc-service at localhost:4322.
**Pass criteria:** Signing completes in <200ms over HTTP.
**Time:** 1-2 days (after POC 1 + POC 3).

---

## Reference Code

| What | Where | Useful for |
|------|-------|-----------|
| BRC-100 wallet HTTP client | `~/bsv/rust-bsv-worm/src/wallet.rs` | Understanding request/response formats |
| BRC-31 auth client | `~/bsv/rust-bsv-worm/src/auth/client.rs` | Key derivation protocol IDs |
| x402 payment construction | `~/bsv/rust-bsv-worm/src/x402/payment.rs` | Transaction construction flow |
| BRC-42 key derivation spec | `~/bsv/BRCs/key-derivation/0042.md` | Derivation algorithm |
| BRC-100 wallet API spec | `~/bsv/BRCs/wallet/0100.md` | All 28 endpoint definitions |
| **bsv-wallet-cli** | `~/bsv/bsv-wallet-cli/` | **The binary being replaced** (Rust + Axum + SQLite) |
| **rust-wallet-toolbox** | `~/bsv/rust-wallet-toolbox/` | **The wallet engine — reuse everything except signing** |
| **rust-sdk (bsv)** | `~/bsv/rust-sdk/` | ProtoWallet, WalletInterface trait, crypto primitives |
| rust-wallet-infra (CF Worker wallet) | `~/bsv/rust-wallet-infra/` | R2/D1 patterns, 14 endpoint implementations |
| wallet-toolbox (TypeScript) | `~/bsv/wallet-toolbox/` | Key reconstruction, profile system |

---

## CRITICAL FINDING: bsv-wallet-cli Architecture

### The wallet stack has a clean separation

```
bsv-wallet-cli (HTTP layer — Axum, port 3321/3322)
    ↓
rust-wallet-toolbox (Wallet<StorageSqlx, Services>)
    ├── ProtoWallet (key derivation + signing)  ← INTERCEPT HERE
    ├── StorageSqlx (UTXO management, tx tracking, SQLite)
    ├── WalletSigner (tx signing orchestration)  ← REPLACE THIS
    └── Services (broadcasting, chain height)
    ↓
bsv-sdk (WalletInterface trait, crypto primitives)
```

### The Shortcut: Don't Reimplement — Intercept

**Instead of reimplementing UTXO selection, fee calculation, and transaction construction from scratch, the MPC proxy can use `rust-wallet-toolbox` as a Cargo dependency and only replace the signing layer.**

The wallet engine (`Wallet<S, V>`) is parameterized by storage and services. The signing happens in `WalletSigner.sign_transaction()` which calls `ProtoWallet.key_deriver().derive_private_key()`. The MPC proxy intercepts at this boundary:

```
Normal flow:
  createAction → storage.select_utxos → build_unsigned_tx →
  signer.sign_transaction(proto_wallet) → broadcast

MPC flow:
  createAction → storage.select_utxos → build_unsigned_tx →
  mpc_signer.sign_transaction(mpc_bridge) → broadcast
                 ↑ ONLY THIS CHANGES ↑
```

### What this means for build time

| Without toolbox reuse | With toolbox reuse |
|---|---|
| Reimplement UTXO selection (~4000 lines) | Reuse as-is |
| Reimplement fee calculation | Reuse as-is |
| Reimplement tx construction | Reuse as-is |
| Reimplement all 28 HTTP handlers | Reuse 24, modify 4 signing-related |
| Reimplement SQLite schema | Reuse as-is |
| **~8-10 weeks** | **~4-6 weeks** |

### Key files in the wallet stack

| File | Lines | What it does | MPC action |
|------|-------|-------------|------------|
| `bsv-wallet-cli/src/server/handlers.rs` | 800 | All 28 endpoint handlers | Modify 4 signing handlers |
| `bsv-wallet-cli/src/server/types.rs` | 264 | JSON request/response types | Keep as-is |
| `rust-wallet-toolbox/src/wallet/wallet.rs` | 3618 | Wallet orchestration | Reuse, intercept signing |
| `rust-wallet-toolbox/src/wallet/signer.rs` | 1029 | Transaction signing | **Replace with MPC signer** |
| `rust-wallet-toolbox/src/wallet/signer.rs:108-218` | 110 | `sign_transaction()` | **The exact function to replace** |
| `rust-wallet-toolbox/src/wallet/signer.rs:431-480` | 50 | Sighash computation (BIP-143) | Keep — compute locally, send hash to MPC |
| `rust-wallet-toolbox/src/storage/sqlx/create_action.rs` | 3937 | UTXO selection + fee calc | Keep entirely |
| `rust-sdk/src/wallet/proto_wallet.rs` | ~400 | Key derivation (ProtoWallet) | Intercept — ask MPC instead |

### Signing flow in detail

```rust
// In rust-wallet-toolbox/src/wallet/signer.rs:
pub fn sign_transaction(
    unsigned_tx: &[u8],
    inputs: &[SignerInput],
    proto_wallet: &ProtoWallet
) -> Result<Vec<u8>> {
    for input in inputs {
        // 1. Derive signing key (BRC-29)
        let key = proto_wallet.key_deriver().derive_private_key(
            &Protocol::new(SecurityLevel::Counterparty, "3241645161d8"),
            &format!("{} {}", input.derivation_prefix, input.derivation_suffix),
            &counterparty,
        )?;

        // 2. Compute sighash (BIP-143, deterministic)
        let sighash = compute_sighash(unsigned_tx, input.vin, &input.locking_script, input.satoshis);

        // 3. Sign the sighash ← THIS IS WHAT MPC REPLACES
        let signature = key.sign(&sighash)?;

        // 4. Build unlocking script
        let unlock = build_p2pkh_unlock(&signature, &key.to_public_key());

        // 5. Insert into transaction
        insert_unlock_script(tx, input.vin, unlock);
    }
}
```

**The MPC replacement:**
```rust
pub fn mpc_sign_transaction(
    unsigned_tx: &[u8],
    inputs: &[SignerInput],
    mpc_bridge: &MpcBridge,
) -> Result<Vec<u8>> {
    for input in inputs {
        // 1. Get public key from MPC (BRC-29 derivation happens on both sides)
        let pubkey = mpc_bridge.get_derived_public_key(
            &input.derivation_prefix, &input.derivation_suffix, &input.counterparty
        ).await?;

        // 2. Compute sighash LOCALLY (no key needed)
        let sighash = compute_sighash(unsigned_tx, input.vin, &input.locking_script, input.satoshis);

        // 3. Send sighash to MPC for signing ← THE MPC OPERATION
        let signature = mpc_bridge.sign(&sighash).await?;

        // 4. Build unlocking script (same as before)
        let unlock = build_p2pkh_unlock(&signature, &pubkey);

        // 5. Insert into transaction (same as before)
        insert_unlock_script(tx, input.vin, unlock);
    }
}
```

**Only step 3 changes.** Everything else is identical. The sighash computation is deterministic and doesn't need any key. The unlocking script construction is deterministic given the signature and pubkey.

### Implications for bsv-mpc-proxy crate

The proxy doesn't need its own UTXO tracker, fee calculator, or transaction builder. It can:

1. **Depend on `rust-wallet-toolbox`** as a Cargo path dependency
2. **Create a custom signer** that implements the same interface but calls MPC
3. **Reuse the existing HTTP handlers** (from bsv-wallet-cli) with the signing swap
4. **Reuse the existing SQLite storage** for UTXO management

This changes the proxy from "reimplement a wallet from scratch" to "fork bsv-wallet-cli and swap the signer." Dramatically simpler.
