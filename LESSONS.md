# bsv-mpc — Lessons Learned from 15 POCs

> Every technical finding from POC validation, organized by topic.
> 15/15 POCs passed. ~12,300 lines of POC code. $0.05 total mainnet cost.
> Updated: 2026-03-21

---

## 1. cggmp24 API Patterns

### What works
- `round_based::sim::run(n, |i, party| ...)` for in-process DKG simulation
- `round_based::sim::run_with_setup(shares, |i, party, share| ...)` for signing/presigning
- `cggmp24::KeyShare::from_parts((incomplete_share, aux_info))` to combine DKG result with Paillier params
- `sig.write_to_slice(&mut [u8; 64])` outputs compact r||s → `bsv::Signature::from_compact()` accepts
- Signature is automatically low-S normalized (BIP-62 compliant) — no manual normalization needed
- `PregeneratedPrimes::generate(&mut OsRng)` for aux info — expensive (~30s per party) but one-time
- `trusted_dealer` (cggmp24 `spof` feature) correctly splits a known private key into threshold shares
- `reconstruct_secret_key` round-trips perfectly from shares back to original key

### What's tricky
- **Must pin `glass_pumpkin = "=1.9.0"`** to avoid rand_core 0.6/0.10 version conflict with fast-paillier
- **Must use `buffer_outgoing()` wrapper** (from cggmp24 test infra) to ensure messages are properly flushed between protocol rounds — without it, simulation hangs
- **State machine is `!Send`** — can't move across tokio tasks. Run in `std::thread`, bridge with channels
- **Paillier prime generation dominates all timing** — 30s per party for aux_info_gen. This is one-time per DKG but must be planned for
- **4-round signing is ~1.2s in dev mode** (debug + num-bigint). Release mode + rug would be ~100-200ms, but rug is LGPL/no-WASM. Presigning is the answer

### Dependencies
```toml
cggmp24 = { git = "https://github.com/LFDT-Lockness/cggmp21", features = ["num-bigint"] }
cggmp24-keygen = { git = "https://github.com/LFDT-Lockness/cggmp21", features = ["num-bigint"] }
round-based = { git = "https://github.com/LFDT-Lockness/round-based", features = ["sim"] }
generic-ec = { version = "0.4", features = ["curve-secp256k1"] }
glass_pumpkin = "=1.9.0"  # MUST pin
```

### State machine over HTTP (POC 5 pattern)
```
round_based::state_machine::wrap_protocol → manual round stepping
Each SendMsg → HTTP POST to /send
Each NeedsOneMoreMessage → HTTP POST to /recv
Protocol messages serialize cleanly with serde_json
```

### Scaling (POC 12: 3-of-5)
- 5-party DKG: 138ms (vs ~80ms for 2-party)
- Aux info is the bottleneck: 130s for 5 sets of Paillier primes (one-time)
- Any 3-of-5 subset produces valid signatures for the same joint pubkey
- Below-threshold (2-of-5) correctly returns `MismatchedAmountOfParties`
- Presigning combine: 4.4ms regardless of threshold — presigning absorbs the cost
- **3x cost ratio** (3-of-5 vs 2-of-2) for on-demand signing; 0x difference with presigning

---

## 2. Key Derivation (BRC-42 + MPC)

### Three counterparty types, three derivation paths

| Counterparty | ECDH shared secret | MPC approach | KSS round-trips |
|---|---|---|---|
| `Anyone` (privkey=1) | `G * root_priv = root_pubkey` | Derive locally from joint pubkey | **0** |
| `Self_` | `root_pubkey * root_priv` | Partial ECDH with Lagrange interpolation | **1** |
| `Other(key)` | `key * root_priv` | Partial ECDH with Lagrange interpolation | **1** |

### Partial ECDH protocol
1. Proxy computes: `partial_B = counterparty_pub * share_B`
2. KSS computes: `partial_A = counterparty_pub * share_A`
3. Proxy combines with Lagrange: `shared_secret = λ_0 * partial_A + λ_1 * partial_B`
4. Proxy derives: `child_pub = root_pub + G * HMAC(shared_secret, invoice)`

**Critical**: Shamir (VSS) shares require **Lagrange interpolation**, not simple addition. `shared_secret ≠ partial_A + partial_B`. Must use Lagrange basis polynomials evaluated at x=0 using VSS evaluation points.

### KSS endpoint needed
`POST /ecdh` — takes counterparty pubkey, returns `counterparty_pub * share_A`. Does NOT reveal share_A (ECDL is hard).

### Signing with derived keys
Naive `share_i' = share_i + scalar` doesn't work for VSS threshold shares. Use additive share offset with proper Lagrange handling. POC 8 confirmed: `reconstruct(shares) + hmac = child_priv` via additive homomorphism.

### BRC-42 formula verified against spec vectors
```
shared_secret = ECDH(counterparty_pub, root_priv)
hmac = HMAC-SHA256(key=compressed(shared_secret), data=invoice_bytes)
child_pubkey = root_pubkey + G * hmac
```

---

## 3. Transaction Construction

### BIP-143 sighash
- Use BSV SDK's `compute_sighash_for_signing()` — internal byte order, not reversed
- **Internal byte order txid ≠ display order** — BIP-143 uses internal (reversed from what block explorers show)
- Sighash type: `0x41` = `SIGHASH_ALL | SIGHASH_FORKID`

### MPC signing integration
- Use `PrehashedDataToSign::from_scalar()` for cggmp24 signing (not raw bytes)
- cggmp24 auto-normalizes to low-S (BIP-62 compliant)
- `TransactionSignature::to_checksig_format()` = DER + sighash byte
- Standard P2PKH unlocking script: `<DER_sig + 0x41> <compressed_pubkey>`

### BEEF construction (the hard part)
- Wallet's `internalizeAction` requires **AtomicBEEF** with complete merkle proof ancestry
- **Must use BSV SDK's `Beef` struct** — don't build manually
- Build 3-tx BEEF V2: `confirmed_parent(+BUMP) → unconfirmed_funding → unconfirmed_spending`
- `beef.merge_bump(merkle_path)` → `beef.merge_raw_tx(funding_tx, Some(bump_idx))` → `beef.merge_raw_tx(spending_tx, None)`
- `beef.to_binary_atomic(spend_txid)` for final output

### Merkle proofs
- WoC TSC endpoint: `GET /tx/{txid}/proof/tsc` — this works
- WoC regular `/proof` endpoint returns 404 — don't use it
- TSC gives `{index, nodes[]}`, needs conversion to `MerklePath` with `MerklePathLeaf` tree structure
- Block height from target: WoC TSC proof gives block hash as `target`, need `/block/hash/{hash}` call for height

### Broadcasting
- **ARC GorillaPool** (`https://arc.gorillapool.io`) works without API key
- TAAL ARC requires Bearer token
- Fee rate: 100 sats/kb works on mainnet
- 191-byte tx = 100 sat fee; 250-byte tx (3 outputs) = 150 sat fee

### Fee injection (POC 7)
- Fee output MUST be added BEFORE sighash computation — it's part of `hashOutputs` in BIP-143
- Injection is simple: append output + reduce change
- Split fee among N operators handles remainder correctly (integer division, remainder to first)
- Graceful failure when change < fee — outputs not modified
- 3-output tx works on mainnet: recipient + change + fee

### DKG key persistence
- **ALWAYS persist DKG keys before funding the MPC address**
- Ephemeral keys = lost funds. POC 4 lost 3,000 sats ($0.0015) from ephemeral keys in failed runs
- **Never use ephemeral DKG keys in production**

---

## 4. CF Worker Deployment

### WASM compilation
- `cargo build --target wasm32-unknown-unknown` succeeds first try
- **Module size: 636KB** (release, LTO + strip). Well under 10MB CF Worker limit
- **Memory: 79.5MB RSS** (128MB limit). Comfortable headroom
- `getrandom` with `js` feature works perfectly for WASM entropy
- `cggmp24` with `no_std` + `backend-num-bigint` + `state-machine` features compiles clean
- Must pin `glass_pumpkin = "=1.9.0"` (same as native)

### CF Worker specifics (POC 10)
- **worker crate 0.7 required** — v0.4 rejected by worker-build v0.7.5
- DO API changed: `impl DurableObject` no longer needs `#[durable_object]` macro
- `fetch(&self)` not `fetch(&mut self)` in new DO API
- **WASM module: 1069KB** (with CF Worker runtime), gzip 393KB
- **Startup: 1ms** (V8 isolate, not container boot)
- **No CORS, header size, or cold start issues**

### Latency over real HTTPS (POC 10)
- **HTTPS RTT: ~16ms p50** (US West ↔ CF edge), 15-25ms range
- Payload size doesn't affect latency
- DO storage: 58ms first access (instance creation), 24ms subsequent
- DKG keygen over HTTPS: 52ms (2 requests) — deterministic replay works
- **Estimated presigned signing: ~16ms** (1 HTTPS RTT) — 12x under 200ms target
- **Estimated full signing: ~33ms** (2 RTTs) — 60x under 2s target

### Production architecture decision
- **DKG**: Deterministic replay is fine (52ms, no Paillier primes)
- **Signing**: Store key share in DO, load per request, run signing SM with fresh RNG. Each request = 1 RTT (~16ms)
- **Alternative**: DO WebSocket for persistent SM connection — eliminates replay
- **Do NOT replay signing** — 28s due to Paillier prime re-generation

### KeyShare serialization
- serde_json works: KeyShare serializes to ~10KB JSON
- DO put/get confirmed for both small (10B) and large (10KB) values

---

## 5. Wallet Integration

### Origin header quirk
- **Wallet uses `Origin: http://admin.com` header** for default basket access
- MPC proxy MUST send this header when making requests that use the default basket

### UTXO vout
- **UTXO vout is NOT always 0** — wallet puts its own change outputs first
- Don't hardcode vout=0 when looking for funded outputs
- Parse the actual transaction to find the correct output index

### WoC indexing delay
- **9-18 seconds** before a tx appears on WhatsOnChain after wallet broadcast
- Retry logic needed when querying UTXOs after funding

### rust-wallet-toolbox reuse (POC 6)
**Verdict: GO** — reuse toolbox with minimal fork (~30 lines)

| Component | Signer Coupling | Reusable? |
|---|---|---|
| StorageSqlx (UTXO, ~4000 LOC) | ZERO | As-is |
| StorageSqlx (fee calculation) | ZERO | As-is |
| Services (broadcasting) | ZERO | As-is |
| handlers.rs (HTTP endpoints) | Via WalletInterface trait only | As-is |
| types.rs (JSON types) | ZERO | As-is |
| ProtoWallet (encrypt/decrypt) | Local key derivation | As-is |
| **WalletSigner (~420 LOC)** | **Hardcoded concrete struct** | **Replace** |

**Resolution**: Add `WalletSignerApi` trait (~30 lines), make `Wallet` generic over it, implement `MpcSigner`.

**Alternative (no-fork)**: `create_action(sign_and_process: false)` → sign externally → `sign_action` with pre-computed unlocking scripts.

### BRC-100 endpoint priorities
- **TIER 1** (every iteration): `getPublicKey`, `createSignature`, `createAction`, `listOutputs`, `encrypt`/`decrypt`
- **TIER 2** (task lifecycle): `internalizeAction`, `relinquishOutput`, `verifySignature`
- **TIER 3** (stub/defer): certificates, discovery, key linkage, HMAC, `listActions`

### Protocol IDs that must match exactly
| Protocol ID | Used for | Breaks if wrong |
|---|---|---|
| `[2, "3241645161d8"]` | x402 payments | Payment rejected |
| `[2, "auth message signature"]` | BRC-31 auth | Handshake fails (401) |
| `[2, "worm memory"]` | Memory encryption | Memory unreadable |
| `[2, "worm state"]` | State token encryption | Tokens unreadable |
| `[2, "worm conversation"]` | Conversation sync | Data lost |

---

## 6. BRC-31 Authentication (POC 8)

### Production MPC auth flow
1. Proxy + KSS do partial ECDH (1 round-trip, ~135us) → `shared_secret`
2. Both compute HMAC offset from `shared_secret + invoice`
3. Both add offset to their share locally (**0 extra round-trips**)
4. Threshold sign auth data (standard signing rounds)
5. **Total overhead: 1 extra KSS round-trip**

### Validations
- Partial ECDH (Other counterparty): Lagrange interpolation on VSS shares → correct shared secret
- Additive offset: `share_i + hmac` reconstructs correct child key (Shamir's additive homomorphism)
- ECDH commutativity: server derives same child pubkey using `ECDH(client_pub, server_priv)`
- DER encoding: compact r||s → DER roundtrip works for BRC-31 wire format
- BRC-42 match: protocol `[2, "auth message signature"]` with `key_id = "{nonce} {peer_nonce}"` matches wallet `KeyDeriver` exactly

---

## 7. Encrypt/Decrypt Compatibility (POC 9)

### Result: byte-identical symmetric keys
- **Zero data loss** during wallet → MPC proxy transition
- Existing wallet-encrypted agent memory is readable by MPC shares
- MPC-encrypted data is readable by normal wallet

### Algorithm: 2 partial ECDH rounds
1. **Round 1**: `base_ecdh = counterparty_key * root_priv` via partial ECDH with Lagrange
2. **Local**: `hmac = HMAC-SHA256(compressed(base_ecdh), invoice)`, `child_pub = counterparty_key + G * hmac`
3. **Round 2**: `root_priv * child_pub` via partial ECDH
4. **Local**: `symmetric_point = (root_priv * child_pub) + (hmac * child_pub)`, `key = symmetric_point.x()`

### All protocols validated
- `[2, "worm memory"]` with key_ids: `knowledge`, `episodic`, `procedural`
- `[2, "worm state"]` with key_id: `tokens`
- `[2, "worm conversation"]` with conversation ID key_id

---

## 8. Overlay Network (POC 14)

### Production overlay is LIVE
- 4 mainnet SLAP trackers: 3 BSV Association (US/EU/AP bsvb.tech) + 1 Babbage (bapp.dev)
- **No fallback needed** — infrastructure exists and works

### Service discovery
- `LookupResolver` query works for `ls_ship` and `ls_slap`
- `tm_mpc_signing` query returns 0 outputs (correct — nobody registered yet)
- Live SHIP host found: `backend.<REDACTED-CF-ID>.projects.babbage.systems`

### Registration pattern
- SHIP admin tokens use PushDrop format: 4 fields (`"SHIP"`, identity key, domain, topic)
- `create_overlay_admin_token(Protocol::Ship, identity_key, domain, "tm_mpc_signing")` → broadcast via `TopicBroadcaster`
- Deregistration = spending the UTXO (identity key is the locking key)
- rust-sdk has complete overlay client: `LookupResolver`, `TopicBroadcaster`, `create_overlay_admin_token`

---

## 9. Key Refresh / Threshold Resharing (POC 13)

### cggmp24 v0.7 has NO native key refresh
- `key_refresh` module only contains `aux_info_gen()` (Paillier params)
- cggmp21 v0.6 had non-threshold-only refresh using `rug` (LGPL/no WASM) — incompatible

### Our implementation: ~50 LOC threshold resharing
Built from scratch using cggmp24's existing primitives:
- `generic_ec_zkp::polynomial::Polynomial` for VSS
- `lagrange_coefficient_at_zero` for interpolation
- `round_based` for messaging

**Protocol (Proactive Secret Sharing):**
1. Each surviving party generates random degree-t polynomial with zero constant term
2. Distribute evaluations to all parties (including replacement)
3. Each party adds received evaluations to current share
4. Result: new shares, same joint secret, same public key

### Resharing vs Re-DKG

| | Resharing | Re-DKG |
|--|---|---|
| Joint key | SAME | Different |
| BSV address | SAME | Different |
| Fund transfer | Not needed | Required (~188 sats) |
| On-chain cost | 0 sats | ~188 sats |
| Indexing delay | None | 9-18s |

### Production hardening needed
- Add Schnorr proofs for refresh polynomial commitments
- Consider contributing upstream as cggmp24 PR

---

## 10. Fee Settlement (POC 11)

### Nodes' DKG is independent from agent's DKG
Same CGGMP'24 protocol, different participants, different joint key. The settlement address is controlled by the MPC node group, not the agent.

### 2-of-3 threshold for node settlement
- Any 2 nodes can trigger settlement, no single node can steal
- Proportional distribution with integer division; remainder to first node
- Matches `calculate_settlement()` in `bsv-mpc-overlay/src/proofs.rs`

### Mainnet validated
- Settlement tx: 1 input (3000 sats) → 3 outputs (1283/997/570 = 45%/35%/20%) + 150 sat fee
- All 3 subsets (A+B, A+C, B+C) produce valid signatures
- Below-threshold (single node) correctly rejected
- [TXID: afbb7ecd...](https://whatsonchain.com/tx/afbb7ecd746bf75c346303e863e9e6a4bd17184d8149ac68f0bdcc1003e485d7)

---

## 11. HTTP Latency (POC 5)

### Results (100 iterations, localhost)

| Metric | p50 | p95 |
|---|---|---|
| Raw HTTP RTT | 135us | 184us |
| Presigned online signing | **359us** | 362us |
| 4-round signing | 1.23s | 1.25s |
| Presig generation (3 rounds) | 1.24s | 1.25s |

- HTTP overhead is negligible (~135us per round)
- HTTP signing is actually **faster** than sim (1.23s vs 2.39s) because parties run in parallel
- 4-round timing dominated by Paillier ZK proofs, not HTTP

---

## 12. POC Shortcuts vs Production Requirements

### What the capstone (POC 15) did correctly (real MPC)
- DKG (2-of-2): full CGGMP'24 DKG via `round_based::sim`
- Transaction signing: 4-round threshold ECDSA over HTTP
- All 28 BRC-100 endpoints routed (8 functional, rest stubbed)

### What the capstone used shortcuts for (must fix in production)

| Component | POC shortcut | Production requirement |
|---|---|---|
| BRC-31 auth signing | Reconstructed derived key | Share offsets (partial ECDH + additive offset per POC 8) |
| Encrypt/decrypt | Reconstructed key via ProtoWallet | Partial ECDH (2 KSS round-trips per POC 9) |
| UTXO management | WhatsOnChain query per request | Local UTXO tracker (reuse StorageSqlx from toolbox) |
| Key persistence | Ephemeral (DKG on startup) | Persistent DO/SQLite storage |
| Fee injection | Not implemented | Fee output per POC 7 pattern |
| Presigning | Not used | Background presig pool (sub-ms signing) |

### Total capstone cost
- DKG: 0 sats (in-memory)
- Funding: 80,000 sats
- x402 payment: 72,247 sats (327 effective, 71,920 refunded)
- Total: ~80,500 sats (~$0.04)

---

## 13. Performance Budget

| Operation | Measured | Target | Status |
|---|---|---|---|
| Presigned signing (1 RTT) | 359us local, ~16ms HTTPS | <50ms | 3x-140x under |
| Full 4-round signing | 1.23s local, ~33ms HTTPS est | <200ms (HTTPS) | Under (HTTPS) |
| DKG (2-of-2) | 4ms WASM, ~80ms native | One-time | N/A |
| DKG (3-of-5) | 138ms native | One-time | N/A |
| HTTP RTT | 135us local, 16ms HTTPS | <50ms | 3x under |
| WASM module | 636KB core, 1069KB worker | <10MB | 10x under |
| Memory (WASM) | 79.5MB RSS | <128MB | 1.6x under |
| Presig combine | 1ms WASM, 4.4ms 3-of-5 | <50ms | 10x under |

---

## 14. POC Code Reuse Map

Which POC code to port into production crates:

| POC | Port to | Key files | LOC |
|---|---|---|---|
| POC 1 | `bsv-mpc-core` (dkg.rs, signing.rs) | `poc1/tests/poc.rs` | 375 |
| POC 2 | `bsv-mpc-worker` (WASM config) | `poc2/src/lib.rs`, `Cargo.toml` | 296 |
| POC 3 | `bsv-mpc-core` (hd.rs), `bsv-mpc-proxy` (bridge.rs) | `poc3/tests/poc.rs` | 584 |
| POC 4 | `bsv-mpc-proxy` (wallet_api.rs createAction) | `poc4/tests/poc.rs`, `full_loop.rs` | 1119 |
| POC 5 | `bsv-mpc-proxy` (bridge.rs HTTP SM) | `poc5/tests/poc.rs` | 845 |
| POC 6 | `bsv-mpc-proxy` (toolbox integration) | `poc6/tests/poc.rs` | 886 |
| POC 7 | `bsv-mpc-proxy` (fee_injector.rs) | `poc7/src/lib.rs`, `tests/poc.rs` | 1081 |
| POC 8 | `bsv-mpc-proxy` (BRC-31 auth) | `poc8/tests/poc.rs` | 786 |
| POC 9 | `bsv-mpc-proxy` (encrypt/decrypt) | `poc9/tests/poc.rs` | 744 |
| POC 10 | `bsv-mpc-worker` (CF Worker impl) | `poc10/worker/src/lib.rs`, `tests/poc.rs` | 1191 |
| POC 11 | `bsv-mpc-overlay` (proofs.rs settlement) | `poc11/tests/poc.rs` | 982 |
| POC 12 | `bsv-mpc-core` (3-of-5 config) | `poc12/tests/poc.rs` | 573 |
| POC 13 | `bsv-mpc-core` (key refresh) | `poc13/tests/poc.rs` | 686 |
| POC 14 | `bsv-mpc-overlay` (discovery.rs, chip.rs) | `poc14/tests/poc.rs` | 684 |
| POC 15 | `bsv-mpc-proxy` (full integration) | `poc15/src/main.rs` | 1441 |

**Total POC code: ~12,300 lines. ~60% is directly portable to production crates.**

---

## 15. Dependency Gotchas

| Dependency | Gotcha | Fix |
|---|---|---|
| `glass_pumpkin` | rand_core version conflict with fast-paillier | Pin `= "1.9.0"` |
| `worker` crate | v0.4 rejected by worker-build v0.7.5 | Use v0.7 |
| `cggmp24` state machine | `!Send` — can't span tokio tasks | Run in `std::thread`, bridge with channels |
| `rug` (GMP) | LGPL + no WASM | Use `num-bigint` backend always |
| `getrandom` | No entropy source in WASM by default | Enable `js` feature |
| `bsv` SDK | `features = ["transaction"]` required for tx building | Always include |
| WoC API | `/proof` returns 404, must use `/proof/tsc` | Use TSC endpoint specifically |
| `glass_pumpkin` workspace pin | POCs each pin individually, but workspace `Cargo.toml` was missing it | Add `glass_pumpkin = "=1.9.0"` to `[workspace.dependencies]` |
| `hmac` crate | Not in workspace deps despite being a transitive dep of cggmp24 | Add `hmac = "0.12"` to workspace and bsv-mpc-core for HMAC-SHA256 key derivation |

---

## 16. Production Implementation Notes (M1)

### Share encryption (share.rs)
- `aes-gcm 0.10` API: `Aes256Gcm::new(Key::from_slice(bytes))`, `cipher.encrypt(nonce, plaintext)`, `cipher.decrypt(nonce, ciphertext)`
- GCM auth tag (16 bytes) is automatically appended to ciphertext by `encrypt()` and verified by `decrypt()`
- `rand::rngs::OsRng.fill_bytes()` for 12-byte nonce generation; compiles to WASM via getrandom/js
- `hmac::Hmac::<Sha256>::new_from_slice(key)` accepts any key length (no padding issue for 32 bytes)
- `validate_encrypted_share()` should be called before `decrypt_share()` to catch structural issues before hitting crypto

### HD key derivation (hd.rs)
- **BIP-32 chain codes are required** for HD derivation but `JointPublicKey` originally lacked a `chain_code` field. Added `Option<Vec<u8>>` with `#[serde(default, skip_serializing_if = "Option::is_none")]` for backward compatibility with existing serialized values.
- **Chain code bootstrapping**: When `chain_code` is `None` (legacy keys, pre-DKG-upgrade), the code derives a deterministic chain code from `SHA-256(compressed_pubkey)`. This is safe for non-hardened (public) derivation because chain codes add domain separation but are not secret material. For production DKG, the chain code SHOULD be set from the DKG transcript hash.
- **Non-hardened derivation is pure public-key math**: `HMAC-SHA512(chain_code, pubkey || index)` → left 32 bytes = tweak scalar, right 32 bytes = child chain code → `child_pub = parent_pub + tweak * G`. No MPC communication needed. Each party can independently derive the child public key AND update their share by adding the same tweak scalar.
- **Hardened derivation is impossible without MPC protocol**: It requires the private key in the HMAC input (`0x00 || privkey || index`). A 2-party HMAC protocol would be needed. The current implementation returns `MpcError::Protocol` for hardened paths.
- **Scalar validity check required by BIP-32**: The left 32 bytes of the HMAC output must be < secp256k1 curve order `n`. This is astronomically unlikely to fail (~1 in 2^128) but must be checked for correctness.
- **BSV SDK provides all needed primitives**: `PublicKey::from_scalar_mul_generator()` for `G * scalar`, `PublicKey::add()` for point addition, `sha512_hmac()` for HMAC-SHA512, `Address::new_from_public_key()` for P2PKH address derivation. No additional crypto dependencies needed.
- **`derive_tweak()` enables share updates**: The exported `derive_tweak()` function returns the scalar tweak and child chain code separately, so the proxy and KSS can each add the tweak to their share independently (for non-hardened derivation) without any communication.
- **Incremental vs single-call derivation**: `derive_child_key(key, "m/0/1")` produces identical results to `derive_child_key(derive_child_key(key, "m/0"), "m/1")` because chain codes propagate correctly through each level.

### Participation proofs (proof.rs)
- Bitcoin PUSHDATA encoding: 0 bytes = OP_0 (0x00), 1-75 = direct length byte, 76-255 = OP_PUSHDATA1 + 1-byte len, 256-65535 = OP_PUSHDATA2 + 2-byte LE len
- The BRC draft specifies `"mpc-signing-proof"` as protocol ID, but the proof.rs code uses `"bsv-mpc-participation"` (matching the existing stub doc comments and proof struct). These will be reconciled when finalizing the BRC spec
- Compressed pubkey validation: check `len == 33` and `prefix in {0x02, 0x03}` — format check only, not on-curve verification (no secp256k1 dependency needed)
- `chrono::Utc::now()` works in both native and WASM (chrono's `wasmbind` feature)
- `timestamp_millis()` returns `i64`; cast to `u64` for big-endian serialization in OP_RETURN
