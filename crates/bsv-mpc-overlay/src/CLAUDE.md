# bsv-mpc-overlay/src
> BSV overlay network integration for MPC node discovery and participation proof publication.

## Overview

This crate handles the overlay-facing aspects of the MPC signing network: advertising Key Share Services as discoverable CHIP tokens (BRC-23), querying the overlay to find signing partners via SLAP/CLAP lookup (BRC-24/25), and publishing BRC-18 participation proofs for on-chain fee distribution. All communication targets the `tm_mpc_signing` overlay topic.

## Implementation Status

Most functions contain detailed `todo!()` stubs describing the intended implementation. The only implemented logic is `calculate_settlement()` in `proofs.rs`, which performs proportional fee distribution from proof counts. All other functions will panic at runtime.

## Files

| File | Purpose |
|------|---------|
| `lib.rs` | Module declarations and re-exports (`OverlayError`, `DiscoveryQuery`, `MpcNodeInfo`, `OverlayProof`, `MPC_TOPIC`) |
| `types.rs` | Shared data structures: `MpcNodeInfo`, `DiscoveryQuery`, `OverlayProof`, `FeeSettlement`, `NodeFeeShare`, and the `MPC_TOPIC` constant |
| `error.rs` | `OverlayError` enum with 8 variants covering overlay communication, CHIP parsing, and proof errors |
| `chip.rs` | CHIP token (BRC-23/BRC-48 PushDrop) creation, parsing, publishing, and revocation |
| `discovery.rs` | SLAP/CLAP overlay lookup to find MPC nodes, health checking, reputation scoring |
| `proofs.rs` | BRC-18 participation proof publication, querying, counting, parsing, and fee settlement calculation |

## Key Exports

### Types (`types.rs`)

| Export | Description |
|--------|-------------|
| `MPC_TOPIC` | Constant `"tm_mpc_signing"` — the overlay topic for all MPC data |
| `MpcNodeInfo` | Node advertisement data: identity key, domain, curves, threshold configs, fee, version, optional limits |
| `DiscoveryQuery` | Query filters: curve, threshold config, max fee, result limit (all optional) |
| `OverlayProof` | Wraps a `bsv_mpc_core::types::ParticipationProof` with on-chain txid, vout, and optional block height |
| `FeeSettlement` | Epoch-bounded fee distribution: total fees + per-node `NodeFeeShare` breakdown |
| `NodeFeeShare` | Single node's share: identity key, proof count, and proportional fee in sats |

### Error (`error.rs`)

`OverlayError` variants:

| Variant | When |
|---------|------|
| `Unreachable(String)` | Overlay node cannot be reached (DNS, TLS, timeout) |
| `InvalidChipToken(String)` | CHIP token script parsing or signature verification fails |
| `SubmissionRejected(String)` | BRC-22 `/submit` returns 400/409/422 |
| `LookupFailed(String)` | BRC-24 SLAP or BRC-25 CLAP query fails |
| `NoNodesFound` | Discovery query matched zero nodes |
| `InvalidProof(String)` | Participation proof script cannot be parsed |
| `Http(reqwest::Error)` | HTTP transport error (auto-converted via `From`) |
| `Serialization(serde_json::Error)` | JSON ser/de error (auto-converted via `From`) |

### CHIP Token Functions (`chip.rs`)

| Function | Signature | Status |
|----------|-----------|--------|
| `create_chip_token` | `(identity_key: &[u8; 33], domain: &str, node_info: &MpcNodeInfo) -> Result<Vec<u8>, OverlayError>` | Stub |
| `parse_chip_token` | `(script: &[u8]) -> Result<MpcNodeInfo, OverlayError>` | Stub |
| `publish_chip_token` | `async (overlay_url: &str, token_tx: &[u8]) -> Result<(), OverlayError>` | Stub |
| `revoke_chip_token` | `async (overlay_url: &str, token_txid: &str, token_vout: u32) -> Result<String, OverlayError>` | Stub |

`ChipCapabilities` struct holds the JSON blob embedded in the PushDrop script: curves, threshold_configs, fee_sats, version, and optional limits.

### Discovery Functions (`discovery.rs`)

| Function | Signature | Status |
|----------|-----------|--------|
| `discover_nodes` | `async (overlay_url: &str, query: &DiscoveryQuery) -> Result<Vec<MpcNodeInfo>, OverlayError>` | Stub |
| `node_reputation` | `async (overlay_url: &str, identity_key: &str) -> Result<u64, OverlayError>` | Stub |
| `verify_node_health` | `async (node: &MpcNodeInfo) -> Result<bool, OverlayError>` | Stub |
| `discover_healthy_nodes` | `async (overlay_url: &str, query: &DiscoveryQuery, max_concurrent_checks: Option<usize>) -> Result<Vec<MpcNodeInfo>, OverlayError>` | Stub |

Default result limit is 20. Default max concurrent health checks is 5.

### Proof Functions (`proofs.rs`)

| Function | Signature | Status |
|----------|-----------|--------|
| `publish_proof` | `async (overlay_url: &str, proof: &ParticipationProof) -> Result<OverlayProof, OverlayError>` | Stub |
| `query_proofs` | `async (overlay_url: &str, node_identity: &str, since: Option<DateTime<Utc>>) -> Result<Vec<OverlayProof>, OverlayError>` | Stub |
| `count_proofs_by_node` | `async (overlay_url: &str, node_identities: &[String], epoch_start: DateTime<Utc>, epoch_end: DateTime<Utc>) -> Result<Vec<(String, u64)>, OverlayError>` | Stub |
| `calculate_settlement` | `(proof_counts: &[(String, u64)], total_fees_sats: u64, epoch_start: DateTime<Utc>, epoch_end: DateTime<Utc>) -> FeeSettlement` | **Implemented** |
| `parse_proof_from_script` | `(script: &[u8]) -> Result<ParticipationProof, OverlayError>` | Stub |

Constants: `PROOF_VERSION = 1`, `PROOF_PREFIX = b"mpc-proof"`.

## Overlay Protocol Stack

```
Agent needs MPC signing:
  1. CLAP (BRC-25): Find overlay nodes hosting CHIP lookups for tm_mpc_signing
  2. SLAP (BRC-24): Query those nodes for CHIP tokens (node advertisements)
  3. Parse CHIP tokens into MpcNodeInfo via chip::parse_chip_token()
  4. Filter by curve, threshold config, max fee
  5. Health-check candidates via GET https://{domain}/health
  6. Initiate DKG/signing with selected node(s)
```

## CHIP Token PushDrop Layout

```
OP_PUSH <signing_pubkey>       # BRC-42 derived: protocol [2,"CHIP"], key "tm_mpc_signing", counterparty "anyone"
OP_PUSH "CHIP"                 # Protocol identifier
OP_PUSH <identity_key>         # 33-byte compressed secp256k1
OP_PUSH <domain>               # HTTPS domain (e.g., "mpc.example.com")
OP_PUSH "tm_mpc_signing"       # Topic name
OP_PUSH <capabilities_json>   # ChipCapabilities JSON
OP_5 OP_DROP                   # Clean stack
OP_CHECKSIG                    # Verify BRC-42 signature
```

## Participation Proof OP_RETURN Format

```
OP_FALSE OP_RETURN
  "mpc-proof"                  # Protocol prefix (9 bytes)
  0x01                         # Version byte
  <session_hash>               # 32 bytes (SHA-256 of session transcript)
  <agent_identity>             # 33 bytes (compressed pubkey)
  <participating_count>        # varint
  <signing_hash>               # 32 bytes (sighash that was signed)
  <timestamp>                  # 8 bytes (Unix, big-endian)
  <signature>                  # ~72 bytes (DER ECDSA over preceding fields)
```

## Fee Settlement Logic

`calculate_settlement()` is the only fully implemented function. It performs proportional integer distribution:

```
node_fee = (total_fees * node_proof_count) / total_proof_count
```

Integer division rounds down. If total proofs is zero, all nodes receive 0 sats. Rounding remainder is not explicitly redistributed (lost to truncation, typically < n sats total).

## Dependencies

| Crate | Purpose |
|-------|---------|
| `bsv-mpc-core` | `ParticipationProof` type from `types.rs` |
| `bsv` | BSV primitives (transactions, scripts) |
| `reqwest` | HTTP client for overlay communication |
| `serde` / `serde_json` | Serialization for all types and API payloads |
| `sha2` | Hashing (session transcripts) |
| `chrono` | UTC timestamps on `MpcNodeInfo`, `OverlayProof`, `FeeSettlement` |
| `thiserror` | `OverlayError` derive macro |
| `tracing` | Logging |

## Related

- [Root CLAUDE.md](../../../CLAUDE.md) — project architecture, conventions, overlay network design
- `crates/bsv-mpc-core/src/proof.rs` — `ParticipationProof` creation and OP_RETURN serialization (BRC-18)
- `crates/bsv-mpc-core/src/types.rs` — `ParticipationProof` struct definition
- `crates/bsv-mpc-proxy/src/wallet_api.rs` — `discoverByIdentityKey` / `discoverByAttributes` handlers forward to this crate
