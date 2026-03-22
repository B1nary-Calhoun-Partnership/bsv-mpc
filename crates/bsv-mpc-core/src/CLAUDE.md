# bsv-mpc-core/src
> Core MPC threshold ECDSA protocol layer wrapping cggmp24 for secp256k1.

## Overview

This is the cryptographic heart of the bsv-mpc system. It implements the CGGMP'24 threshold ECDSA protocol for BSV's secp256k1 curve — distributed key generation, threshold signing with presignature optimization, partial ECDH for BRC-42 key derivation, key refresh via threshold resharing, share encryption, and on-chain participation proofs. No networking or transport — this crate is pure protocol logic consumed by `bsv-mpc-proxy`, `bsv-mpc-worker`, and `bsv-mpc-service`.

## Implementation Status

**All protocol modules are fully implemented — zero `todo!()` stubs remain.** 109 unit tests across 8 files.

| Module | Tests | Status |
|--------|-------|--------|
| `dkg.rs` | 10 | Implemented — 4-round DKG with thread-based SM bridge |
| `signing.rs` | 9 | Implemented — full protocol with SM bridge, BRC-42 offset support |
| `presigning.rs` | 5 | Implemented — 3-round protocol with SM bridge + FIFO pool |
| `ecdh.rs` | 8 | Implemented — partial ECDH + Lagrange interpolation + symmetric key derivation |
| `hd.rs` | 21 | Implemented — BRC-42 derivation, validates against BSV SDK + spec vectors |
| `proof.rs` | 33 | Implemented — create/serialize/verify participation proofs |
| `share.rs` | 22 | Implemented — AES-256-GCM encrypt/decrypt + key derivation |
| `refresh.rs` | 1 | Implemented — threshold resharing (Proactive Secret Sharing) |

## Files

| File | LOC | Purpose |
|------|-----|---------|
| `lib.rs` | 65 | Module declarations + re-exports of 11 key public types |
| `types.rs` | 194 | 10 core data types with serde support |
| `error.rs` | 79 | `MpcError` enum (9 variants) + `Result<T>` alias |
| `dkg.rs` | 1563 | `DkgCoordinator` — 4-round DKG via thread-based SM bridge |
| `signing.rs` | 1562 | `SigningCoordinator` — threshold signing with BRC-42 additive offset |
| `presigning.rs` | 1200 | `PresigningManager` — 3-round presig generation + FIFO pool |
| `ecdh.rs` | 583 | Partial ECDH, Lagrange interpolation, symmetric key derivation |
| `hd.rs` | 585 | BRC-42 key derivation (NOT BIP-32), invoice computation |
| `proof.rs` | 811 | BRC-18 participation proofs — create, OP_RETURN serialize, verify |
| `refresh.rs` | 816 | Key refresh via threshold resharing (ported from POC 13) |
| `share.rs` | 549 | AES-256-GCM share encryption + HMAC-SHA256 key derivation |

## Key Exports

Re-exported from `lib.rs` for ergonomic `use bsv_mpc_core::X` imports:

```rust
pub use error::{MpcError, Result};
pub use refresh::RefreshResult;
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

## State Machine Architecture

DKG, signing, and presigning all use the same architecture:

1. The cggmp24 state machine (`StateMachine`) is `!Send` — cannot cross tokio task boundaries.
2. Each coordinator spawns a dedicated `std::thread` for the SM.
3. Communication between coordinator and SM thread uses `std::sync::mpsc` channels (`SmInbound`/`SmOutbound` enums).
4. The caller drives the protocol via synchronous `init()` → `process_round()` loop.
5. Wire messages are serialized to JSON via `WireMessage` struct (sender, is_broadcast, msg payload).

Helper functions in `dkg.rs` (used by all coordinators):
- `outgoing_to_wire<M>()` — converts cggmp24 `Outgoing<M>` to `WireMessage`
- `wire_to_incoming<M>()` — converts `WireMessage` back to cggmp24 `Incoming<M>`

## Coordinators

### `DkgCoordinator` (`dkg.rs`)

Drives one party through the CGGMP'24 DKG ceremony (keygen + aux info generation).

| Method | Description |
|--------|-------------|
| `new(session_id, config, my_index)` | Create coordinator for a party |
| `set_pregenerated_primes(p, q)` | Inject pre-computed safe primes (skips expensive generation) |
| `init()` | Start DKG, returns initial `Vec<RoundMessage>` |
| `process_round(messages)` | Feed incoming messages, returns `DkgRoundResult` |
| `current_round()` | Current round number |
| `config()` | Threshold config |
| `my_index()` | This party's share index |
| `phase()` | Current phase: `"not_started"`, `"keygen"`, `"aux_info"`, `"complete"` |

Returns `DkgRoundResult::NextRound(msgs)` or `DkgRoundResult::Complete(DkgResult)`.

### `SigningCoordinator` (`signing.rs`)

Drives one party through threshold signing. Supports BRC-42 derived key signing via `hmac_offset`.

| Method | Description |
|--------|-------------|
| `new(session_id, share, config, participants)` | Create coordinator |
| `sign(hash, presig, hmac_offset)` | Start signing (delegates to `init_round`) |
| `init_round(hash, hmac_offset)` | Start full 4-round protocol |
| `process_round(messages)` | Feed incoming messages, returns `SigningRoundResult` |
| `current_round()` | Current round number |
| `config()` | Threshold config |

The `hmac_offset` parameter is used for BRC-42 derived key signing — the cggmp24 fork's `set_additive_shift()` applies this HMAC scalar to the signing key share without reconstructing the private key.

Returns `SigningRoundResult::NextRound(msgs)` or `SigningRoundResult::Complete(SigningResult)`.

### `PresigningManager` (`presigning.rs`)

FIFO pool of presignatures with SM-based generation protocol.

| Method | Description |
|--------|-------------|
| `new(session_id, share, participants, max_pool)` | Create manager |
| `init_generate()` | Start 3-round presig generation protocol |
| `process_generate_round(messages)` | Feed messages, returns `PresigningRoundResult` |
| `take()` | Consume oldest presignature (serialized `Presignature`) |
| `take_raw()` | Consume oldest with raw cggmp24 data (`Box<dyn Any + Send>`) |
| `add(presig)` | Manually add a presignature |
| `pool_size()` | Current pool count |
| `should_replenish()` | True when pool < 50% capacity |
| `max_pool_size()` | Configured capacity |
| `is_generating()` | True if generation protocol is in progress |

Returns `PresigningRoundResult::NextRound(msgs)` or `PresigningRoundResult::Complete`.

## Partial ECDH (`ecdh.rs`)

Distributed ECDH for BRC-42 key derivation when the private key is split across MPC shares. Proven in POC 3, 8, 9.

| Function | Description |
|----------|-------------|
| `parse_share_scalar(raw_json) -> [u8; 32]` | Extract secret scalar from serialized cggmp24 key share (handles both `KeyShare` and `IncompleteKeyShare` formats) |
| `parse_share_vss_points(raw_json) -> Vec<[u8; 32]>` | Extract VSS evaluation points for Lagrange computation |
| `compute_partial_ecdh_point(pub, scalar) -> PublicKey` | EC scalar multiplication: `pub * scalar` |
| `point_add(a, b) -> PublicKey` | EC point addition |
| `combine_partials_lagrange(partials) -> PublicKey` | Lagrange interpolation at x=0: `Σ λ_i * partial_i = pub * secret` |
| `derive_symmetric_key_anyone(root_pub, level, proto, key_id) -> [u8; 32]` | Full BRC-42 symmetric key for "anyone" counterparty (0 MPC rounds) |
| `derive_symmetric_key_from_partials(counter_pub, shared_secret, root_times_child, invoice) -> [u8; 32]` | Final symmetric key computation for "self"/"other" after 2-round partial ECDH |

### Counterparty round-trip costs

| Counterparty | MPC Rounds | Symmetric Key Function |
|-------------|------------|----------------------|
| Anyone | 0 (local) | `derive_symmetric_key_anyone()` |
| Self_ | 2 (partial ECDH) | `derive_symmetric_key_from_partials()` |
| Other(key) | 2 (partial ECDH) | `derive_symmetric_key_from_partials()` |

## BRC-42 Key Derivation (`hd.rs`)

Uses BRC-42 (NOT BIP-32). Proven in POC 3, 8, 9. Validates against BSV SDK `KeyDeriver` and BRC-42 spec test vectors.

| Function | Description |
|----------|-------------|
| `derive_child_pubkey(root_pub, shared_secret, invoice) -> PublicKey` | Core BRC-42: `root_pub + G * HMAC-SHA256(shared_secret, invoice)` |
| `compute_brc42_hmac(shared_secret, invoice) -> [u8; 32]` | HMAC scalar for MPC share offset addition |
| `compute_invoice(security_level, protocol_name, key_id) -> String` | Builds `"{level}-{protocol}-{key_id}"` |
| `derive_anyone_pubkey(root_pub, protocol, key_id, level) -> PublicKey` | Anyone counterparty (0 MPC round-trips) |
| `derive_anyone_joint_key(joint_key, protocol, key_id, level) -> JointPublicKey` | Convenience wrapper with BSV address |
| `derive_joint_key_with_secret(joint_key, secret, protocol, key_id, level) -> JointPublicKey` | For Self_/Other after MPC partial ECDH |

## Proof Functions (`proof.rs`)

| Function | Description |
|----------|-------------|
| `create_participation_proof(session_id, agent_key, nodes, signing_hash, fee_txid) -> ParticipationProof` | Constructs proof with SHA-256 session hash, validates all inputs |
| `proof_to_op_return(proof) -> Vec<u8>` | Serializes to `OP_FALSE OP_RETURN` with Bitcoin PUSHDATA opcodes |
| `verify_participation_proof(proof) -> bool` | Structural validation: hash lengths, pubkey prefixes, no duplicates, agent in participants, valid fee_txid hex, non-zero timestamp |

## Key Refresh (`refresh.rs`)

Threshold resharing (Proactive Secret Sharing) — ported from POC 13. Same joint key, 0 on-chain cost, old shares cryptographically invalidated.

| Item | Description |
|------|-------------|
| `RefreshResult` | Struct with `new_secret_shares`, `new_public_shares`, `new_eval_points`, `original_joint_key`, `new_threshold`, `new_parties` |
| `threshold_reshare(surviving_points, surviving_shares, new_points, new_t, rng) -> (secrets, publics)` | Generate new shares via weighted Lagrange + random polynomials |
| `verify_reshare(original_pubkey, new_publics, new_points, new_t) -> bool` | Verify reconstructed key matches original |

Supports arbitrary `(t, n) → (t', n')` resharing.

## Share Functions (`share.rs`)

| Function | Description |
|----------|-------------|
| `encrypt_share(bytes, key) -> EncryptedShare` | AES-256-GCM encrypt with random 12-byte nonce |
| `decrypt_share(encrypted, key) -> Vec<u8>` | AES-256-GCM decrypt, verifies auth tag |
| `derive_share_encryption_key(root_key, session_id) -> [u8; 32]` | `HMAC-SHA256(root_key, "bsv-mpc-share" \|\| session_id)` |
| `validate_encrypted_share(share) -> Result<()>` | Checks nonce=12 bytes, ciphertext non-empty, index < parties, threshold valid |

## Protocol Round Counts

| Operation | Rounds | Notes |
|-----------|--------|-------|
| DKG | Multi-round | Keygen phase + aux info phase (safe prime generation) |
| Signing with presignature | 1 | Not yet wired (requires cggmp24 `insecure-assume-preimage-known` feature) |
| Signing without presignature | 4 | Full interactive protocol via SM bridge |
| Presigning (offline) | 3 | Nonce commit → MtA sub-protocol → delta broadcast |

## Round Result Enums

All three coordinators use the same pattern — a round result enum that is either `NextRound(Vec<RoundMessage>)` or `Complete(result)`:

- `DkgRoundResult::NextRound(msgs)` / `DkgRoundResult::Complete(DkgResult)`
- `SigningRoundResult::NextRound(msgs)` / `SigningRoundResult::Complete(SigningResult)`
- `PresigningRoundResult::NextRound(msgs)` / `PresigningRoundResult::Complete`

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
| `generic-ec` / `generic-ec-zkp` | EC scalar/point operations, Lagrange interpolation, polynomials |
| `round-based` | State machine driver for cggmp24 protocols |
| `aes-gcm` | AES-256-GCM share encryption |
| `hmac` / `sha2` | HMAC-SHA256 for BRC-42 derivation, SHA-256 for session IDs |
| `serde` / `serde_json` | Serialization for all types |
| `chrono` | Timestamps on `Presignature` and `ParticipationProof` |
| `rand` | `OsRng` for nonce generation and random polynomial coefficients |
| `thiserror` | `MpcError` derive |
| `tracing` | Structured logging |

**Critical constraint**: cggmp24 MUST use `num-bigint` (not `rug`) — `rug` depends on GMP (LGPL, blocked by `deny.toml`) and doesn't compile to `wasm32-unknown-unknown`.

## Implementation Notes

- All coordinator methods are synchronous (`fn`, not `async fn`). The SM runs in a dedicated `std::thread` with `mpsc` channel bridge.
- `SigningCoordinator::sign()` currently ignores the presignature parameter and always uses the full 4-round protocol. The presigned 1-round path requires the `insecure-assume-preimage-known` feature on cggmp24.
- `SigningCoordinator` accepts an optional `hmac_offset: Option<[u8; 32]>` for BRC-42 derived key signing — passed through to cggmp24's `set_additive_shift()`.
- BIP-62 low-s normalization is handled automatically by cggmp24.
- `PresigningManager` stores raw cggmp24 presignature data via `Box<dyn Any + Send>` because the concrete type doesn't implement `Serialize`. Use `take_raw()` to access the underlying cggmp24 data.
- `ecdh.rs` handles both full `KeyShare` and raw `IncompleteKeyShare` JSON formats when parsing share scalars.
- `DkgCoordinator::set_pregenerated_primes()` allows injecting safe primes to skip expensive generation in tests.

## Related

- [Root CLAUDE.md](../../../CLAUDE.md) — project architecture, deployment modes, fee economics
- `bsv-mpc-proxy` — BRC-100 signing proxy that consumes this crate via `MpcBridge`
- `bsv-mpc-worker` — CF Worker KSS that uses `DkgCoordinator`/`SigningCoordinator` server-side
- `bsv-mpc-service` — Standalone KSS binary (same API as worker, different storage backend)
