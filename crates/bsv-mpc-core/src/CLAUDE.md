# bsv-mpc-core/src
> Core MPC threshold ECDSA protocol layer wrapping cggmp24 for secp256k1.

## Overview

This is the cryptographic heart of the bsv-mpc system. It implements the CGGMP'24 threshold ECDSA protocol for BSV's secp256k1 curve — distributed key generation, threshold signing with presignature optimization, HD key derivation from MPC shares, share encryption, and on-chain participation proofs. No networking or transport — this crate is pure protocol logic consumed by `bsv-mpc-proxy`, `bsv-mpc-worker`, and `bsv-mpc-service`.

## Implementation Status

Most modules contain well-documented `todo!()` stubs describing the exact cggmp24 integration steps. Working code exists for:
- All types and error handling (`types.rs`, `error.rs`) — **complete**
- `ThresholdConfig::new()` validation — **complete**
- `PresigningManager` pool management (`new`, `take`, `should_replenish`, `pool_size`) — **complete**
- `validate_encrypted_share()` — **complete**
- `DkgCoordinator::new()` and accessor methods — **complete**
- `SigningCoordinator::new()` and accessor methods — **complete**

Everything else (`todo!()`) awaits cggmp24 wiring.

## Files

| File | Purpose | Status |
|------|---------|--------|
| `lib.rs` | Module declarations + re-exports of all 10 key public types | Complete |
| `types.rs` | 10 core data types: `SessionId`, `ShareIndex`, `ThresholdConfig`, `JointPublicKey`, `EncryptedShare`, `Presignature`, `ParticipationProof`, `RoundMessage`, `DkgResult`, `SigningResult` | Complete |
| `error.rs` | `MpcError` enum (9 variants) + `Result<T>` alias + `From<serde_json::Error>` | Complete |
| `dkg.rs` | `DkgCoordinator` — 4-round DKG ceremony producing a joint secp256k1 key | Stub |
| `signing.rs` | `SigningCoordinator` — threshold signing (1-round with presig, 4-round without) | Stub |
| `presigning.rs` | `PresigningManager` — FIFO pool of presignatures for low-latency signing | Partial (pool logic works, `generate()` is stub) |
| `share.rs` | AES-256-GCM share encryption/decryption + BRC-42 key derivation | Partial (`validate_encrypted_share` works, rest stub) |
| `hd.rs` | BIP-32/SLIP-10 HD derivation from MPC joint keys | Stub |
| `proof.rs` | BRC-18 participation proofs — create, serialize to OP_RETURN, verify | Stub |

## Key Exports

All re-exported from `lib.rs` for ergonomic `use bsv_mpc_core::X` imports:

```rust
pub use error::{MpcError, Result};
pub use types::{
    DkgResult, EncryptedShare, JointPublicKey, ParticipationProof,
    Presignature, RoundMessage, SessionId, ShareIndex, SigningResult,
    ThresholdConfig,
};
```

### Types (`types.rs`)

| Type | Description |
|------|-------------|
| `SessionId(String)` | SHA-256 hash of DKG transcript, identifies an MPC group |
| `ShareIndex(u16)` | Party index in `[0, n)`, determines polynomial evaluation point |
| `ThresholdConfig { threshold, parties }` | t-of-n config, validated `2 <= t <= n` |
| `JointPublicKey { compressed, address }` | 33-byte compressed secp256k1 pubkey + Base58Check P2PKH address |
| `EncryptedShare { nonce, ciphertext, session_id, share_index, config }` | AES-256-GCM encrypted share with all metadata |
| `Presignature { id, session_id, data, created_at }` | Opaque serialized cggmp24 presigning state |
| `ParticipationProof { session_hash, agent_identity, participating_nodes, signing_hash, fee_txid, timestamp }` | BRC-18 proof for fee distribution |
| `RoundMessage { session_id, round, from, to, payload }` | Protocol message; `to=None` means broadcast |
| `DkgResult { joint_key, share, session_id }` | Complete DKG output |
| `SigningResult { signature, r, s, recovery_id, proof }` | DER sig + raw (r,s) + recovery ID + participation proof |

### Errors (`error.rs`)

`MpcError` has 9 variants: `Dkg`, `Signing`, `ShareStorage`, `InvalidThreshold { t, n }`, `InvalidShare`, `PresigningExhausted`, `Encryption`, `Serialization`, `Protocol`. Converts from `serde_json::Error`.

### Coordinators

| Struct | Module | Purpose |
|--------|--------|---------|
| `DkgCoordinator` | `dkg.rs` | Drives one party through 4-round DKG. `init()` -> `process_round()` loop -> `DkgRoundResult::Complete` |
| `SigningCoordinator` | `signing.rs` | Drives one party through signing. Fast path: `sign(hash, Some(presig))`. Slow path: `init_round(hash)` -> `process_round()` loop -> `SigningRoundResult::Complete` |
| `PresigningManager` | `presigning.rs` | FIFO pool of presignatures. `generate()` runs 3-round offline protocol. `take()` consumes oldest. `should_replenish()` triggers at < 50% capacity. |

### Share Functions (`share.rs`)

| Function | Status | Description |
|----------|--------|-------------|
| `encrypt_share(bytes, key) -> EncryptedShare` | Stub | AES-256-GCM encrypt with random 12-byte nonce |
| `decrypt_share(encrypted, key) -> Vec<u8>` | Stub | AES-256-GCM decrypt, verifies auth tag |
| `derive_share_encryption_key(root_key, session_id) -> [u8; 32]` | Stub | `HMAC-SHA256(root_key, "bsv-mpc-share" \|\| session_id)` |
| `validate_encrypted_share(share) -> Result<()>` | **Working** | Checks nonce=12 bytes, ciphertext non-empty, index < parties, threshold valid |

### HD Functions (`hd.rs`)

| Function | Status | Description |
|----------|--------|-------------|
| `derive_child_key(joint_key, path) -> JointPublicKey` | Stub | BIP-32/SLIP-10 derivation; non-hardened only (hardened needs MPC rounds) |
| `parse_derivation_path(path) -> Vec<(u32, bool)>` | Stub | Parses `"m/44'/236'/0'/0/0"` into index+hardened tuples |

### Proof Functions (`proof.rs`)

| Function | Status | Description |
|----------|--------|-------------|
| `create_participation_proof(session_id, agent_key, nodes, signing_hash, fee_txid) -> ParticipationProof` | Stub | Constructs proof with SHA-256 session hash |
| `proof_to_op_return(proof) -> Vec<u8>` | Stub | Serializes to `OP_FALSE OP_RETURN` with Bitcoin PUSHDATA opcodes |
| `verify_participation_proof(proof) -> bool` | Stub | Structural validation: field lengths, compressed pubkey prefixes, no duplicates, agent in participants |

## Protocol Round Counts

| Operation | Rounds | Notes |
|-----------|--------|-------|
| DKG | 4 | Commitment -> decommitment -> share distribution -> verification |
| Signing with presignature | 1 | Partial sig broadcast + combine |
| Signing without presignature | 4 | Nonce commit -> decommit -> partial sig -> combine |
| Presigning (offline) | 3 | Nonce commit -> MtA sub-protocol -> delta broadcast |

## Round Result Enums

Both DKG and signing use the same pattern — a round result enum that is either `NextRound(Vec<RoundMessage>)` or `Complete(result)`:

- `DkgRoundResult::NextRound(msgs)` / `DkgRoundResult::Complete(DkgResult)`
- `SigningRoundResult::NextRound(msgs)` / `SigningRoundResult::Complete(SigningResult)`

The caller (transport layer in proxy/worker/service) is responsible for delivering `RoundMessage`s between parties.

## Encryption Scheme

Share encryption follows BRC-42 pattern:
1. **Key derivation**: `HMAC-SHA256(root_key, "bsv-mpc-share" || session_id)` produces a 32-byte AES key
2. **Encryption**: AES-256-GCM with random 12-byte nonce; ciphertext includes 16-byte auth tag
3. **Storage**: `EncryptedShare` struct contains nonce + ciphertext + metadata (no key)
4. **Restore**: Same root_key + session_id re-derives the encryption key deterministically

## Dependencies

| Crate | Purpose |
|-------|---------|
| `cggmp24` | CGGMP'24 threshold ECDSA (with `num-bigint` feature, NOT `rug`) |
| `cggmp24-keygen` | DKG protocol |
| `bsv` | BSV primitives (`features = ["transaction"]`) |
| `aes-gcm` | AES-256-GCM share encryption |
| `sha2` | SHA-256 for session IDs, BRC-42 derivation |
| `serde` / `serde_json` | Serialization for all types |
| `chrono` | Timestamps on `Presignature` and `ParticipationProof` |
| `rand` | `OsRng` for nonce generation |
| `thiserror` | `MpcError` derive |
| `tracing` | Structured logging |

**Critical constraint**: cggmp24 MUST use `num-bigint` (not `rug`) — `rug` depends on GMP (LGPL, blocked by `deny.toml`) and doesn't compile to `wasm32-unknown-unknown`.

## Usage Patterns

### DKG Ceremony (from proxy/worker)

```rust
use bsv_mpc_core::dkg::{DkgCoordinator, DkgRoundResult};
use bsv_mpc_core::{ThresholdConfig, ShareIndex};

let config = ThresholdConfig::new(2, 3)?; // 2-of-3
let mut coord = DkgCoordinator::new(config, ShareIndex(0));

let msg = coord.init().await?;
transport.broadcast(msg).await;

loop {
    let incoming = transport.receive_round().await;
    match coord.process_round(incoming).await? {
        DkgRoundResult::NextRound(msgs) => transport.send_all(msgs).await,
        DkgRoundResult::Complete(result) => {
            // result.joint_key — the agent's BSV public key
            // result.share — encrypted key share to store
            // result.session_id — identifies this MPC group
            break;
        }
    }
}
```

### Threshold Signing (fast path)

```rust
use bsv_mpc_core::signing::SigningCoordinator;

let coord = SigningCoordinator::new(session_id, share, config);
let result = coord.sign(&sighash, Some(presig)).await?;
// result.signature — DER-encoded, ready for BSV Script OP_CHECKSIG
// result.proof — participation proof for fee distribution
```

### Presignature Pool

```rust
use bsv_mpc_core::presigning::PresigningManager;

let mut mgr = PresigningManager::new(session_id, 20);

// Background loop (run during idle time)
while mgr.should_replenish() {
    mgr.generate().await?; // 3-round protocol with KSS
}

// At signing time
if let Some(presig) = mgr.take() {
    coordinator.sign(&hash, Some(presig)).await?; // 1 round
} else {
    coordinator.sign(&hash, None).await?; // 4 rounds (fallback)
}
```

### Share Validation

```rust
use bsv_mpc_core::share::validate_encrypted_share;

// This is the only share function that works today
validate_encrypted_share(&encrypted_share)?;
// Checks: nonce=12 bytes, ciphertext non-empty, index < parties, 2 <= t <= n
```

## Implementation Notes

- All async methods (`init`, `process_round`, `sign`, `init_round`, `generate`) use `async fn` but currently hit `todo!()`. The async boundary exists because cggmp24 protocol steps will need RNG and potentially I/O.
- `PresigningManager::take()` uses `Vec::remove(0)` for FIFO. Consider `VecDeque` when implementing for better O(1) pop performance.
- `SigningCoordinator` stores the `EncryptedShare` and decrypts it in memory only during signing. The `todo!()` notes mention using `zeroize::Zeroizing<Vec<u8>>` for the decrypted share.
- BIP-62 low-s normalization is required by BSV consensus: if `s > n/2`, replace with `n - s`.
- HD derivation (`hd.rs`) only supports non-hardened paths without MPC communication. Hardened derivation requires a 2-party HMAC protocol (future work).

## Related

- [Root CLAUDE.md](../../../CLAUDE.md) — project architecture, deployment modes, fee economics
- `bsv-mpc-proxy` — BRC-100 signing proxy that consumes this crate via `MpcBridge`
- `bsv-mpc-worker` — CF Worker KSS that uses `DkgCoordinator`/`SigningCoordinator` server-side
- `bsv-mpc-service` — Standalone KSS binary (same API as worker, different storage backend)
