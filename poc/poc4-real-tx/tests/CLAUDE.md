# POC 4 Tests — Real BSV Mainnet Transactions via MPC
> Integration tests proving MPC threshold signing produces valid, broadcastable BSV transactions.

## Overview

Two end-to-end mainnet tests that exercise the full MPC signing pipeline: DKG key generation, wallet funding, UTXO lookup, BIP-143 sighash computation, 2-of-2 threshold ECDSA signing, transaction serialization, ARC broadcast, and WhatsOnChain verification. These are **mainnet tests** — they spend real sats (1000-1500 sats per run, ~$0.001).

## Prerequisites

- **bsv-wallet running at localhost:3321** — used to fund MPC addresses and receive returned funds. Must have a balance of at least 2000 sats.
- **Internet access** — tests call WhatsOnChain API and ARC broadcast endpoints.
- **No mocking** — all MPC ceremonies run via `round_based::sim` (in-memory simulation of the multi-party protocol), but funding, broadcasting, and verification hit real mainnet infrastructure.

## Files

| File | Purpose |
|------|---------|
| `poc.rs` | Core POC: 9-step DKG → fund → sign → broadcast → verify pipeline |
| `full_loop.rs` | Extended test: adds BEEF construction, `internalizeAction`, and balance accounting |

## Test Details

### `poc.rs` — `test_mpc_signed_mainnet_transaction`

The foundational proof that MPC produces valid BSV transactions. 9 steps:

1. **DKG** — 2-of-2 `cggmp24::keygen` via `round_based::sim::run`, produces joint public key
2. **Aux info** — `cggmp24::aux_info_gen` with pregenerated Blum primes (`SecurityLevel128`), combined into complete `KeyShare`s
3. **Fund** — Sends 1500 sats to the MPC P2PKH address via `POST localhost:3321/createAction`
4. **Find UTXO** — Polls WhatsOnChain (`/v1/bsv/main/tx/hash/{txid}`) with retry loop (up to 6 attempts, 3s×attempt backoff) to find the vout matching the MPC locking script
5. **Build tx** — Constructs a P2PKH spending tx sending funds back to the wallet's identity key (minus 100 sat fee)
6. **MPC sign** — Converts BIP-143 sighash to `PrehashedDataToSign::from_scalar`, runs `cggmp24::signing` via `round_based::sim::run_with_setup`, verifies low-S and BSV SDK verification
7. **Serialize** — Builds unlocking script (`DER sig + sighash byte + compressed pubkey`), serializes full transaction
8. **Broadcast** — Tries ARC endpoints (TAAL then GorillaPool) via `POST /v1/tx`
9. **Verify** — Checks WhatsOnChain for the txid

Logs all transactions to `tx_log.txt` for recovery.

### `full_loop.rs` — `test_full_loop`

Extends the core test with wallet round-trip verification:

- **Balance before/after** — Calls `POST localhost:3321/listOutputs` to measure wallet balance before and after
- **Smaller funding** — Uses 1000 sats with 20 sat fee
- **BEEF construction** — Builds AtomicBEEF with merkle proof ancestry:
  - If spending tx is mined: uses its merkle proof directly (with fallback to also prove the funding tx)
  - If not yet mined: traverses funding tx → parent tx, gets TSC merkle proof from WoC, builds 3-tx BEEF chain
- **Internalization** — Calls `POST localhost:3321/internalizeAction` with the AtomicBEEF to insert the return output into the wallet's `default` basket (tagged `poc4-full-loop`)
- **Balance delta** — Reports the difference (expected: ~30 sats for createAction fee + MPC tx fee)

Uses `Origin: http://admin.com` header for wallet access (required for default basket operations).

## Shared Infrastructure

Both tests duplicate several helpers (not shared as a module):

| Helper | Purpose |
|--------|---------|
| `BufferedSink` / `buffer_outgoing` | Wraps `round_based::MpcParty` delivery to buffer outgoing messages (from POC 1 pattern) |
| `generate_blum_prime` / `generate_pregenerated_primes` | Creates RSA primes (mod 4 ≡ 3) for `cggmp24::aux_info_gen` |
| `p2pkh_locking_script` / `p2pkh_script` | Builds standard P2PKH locking script from pubkey hash160 |
| `p2pkh_unlocking_script` | Builds P2PKH unlocking script from checksig-format signature + compressed pubkey |
| `serialize_transaction` / `serialize_tx` | Manual transaction serialization using `bsv::primitives::encoding::Writer` |
| `log_transaction` / `log_tx` | Appends transaction details to `tx_log.txt` for recovery |

`full_loop.rs` additionally has:
- `tsc_to_merkle_path` — Converts WoC TSC proof format (`{index, target, nodes}`) to BSV SDK `MerklePath`
- `get_wallet_balance` — Sums satoshis from `listOutputs` response

## Key Patterns

**Sighash computation**: Uses `bsv::primitives::bsv::sighash::compute_sighash_for_signing` with `SIGHASH_ALL | SIGHASH_FORKID` (0x41). The sighash feeds into cggmp24 via `Scalar::from_be_bytes` → `PrehashedDataToSign::from_scalar`.

**Txid byte order**: WoC returns display-order txids (big-endian). BIP-143 sighash uses internal byte order (little-endian). The tests reverse bytes when converting: `prev_txid.reverse()`.

**WoC value conversion**: WoC returns satoshi values as BSV floats. Tests convert via `(value_bsv * 1e8 + 0.5) as u64` to avoid floating point truncation.

**BEEF ancestry** (full_loop only): Wallet's `internalizeAction` requires AtomicBEEF with merkle proofs. For unconfirmed transactions, the test walks the input chain back to a confirmed ancestor and builds a multi-tx BEEF.

## Running

```bash
cd poc/poc4-real-tx

# Run the core test (costs ~1500 sats ≈ $0.001)
cargo test test_mpc_signed_mainnet_transaction -- --nocapture

# Run the full loop test (costs ~1000 sats ≈ $0.0005)
cargo test test_full_loop -- --nocapture
```

`--nocapture` is recommended — the tests print step-by-step progress and the final txid/WhatsOnChain link.

The `[profile.dev.package]` section in `Cargo.toml` optimizes big integer operations (`num-bigint`, `glass_pumpkin`) at opt-level 3 even in debug builds, since DKG prime generation is otherwise very slow.

## Related

- [Root CLAUDE.md](../../../CLAUDE.md) — Project architecture and POC validation results
- `poc/poc1-cggmp24-signing/` — The simpler DKG + signing POC (no real transactions) that established the `BufferedSink` pattern
- `poc/poc3-key-derivation/` — HD key derivation from MPC shares
