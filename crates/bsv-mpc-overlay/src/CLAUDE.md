# bsv-mpc-overlay/src
> BSV overlay network integration for MPC node discovery and participation proof publication.

## Overview

This crate handles the overlay-facing aspects of the MPC signing network: advertising Key Share Services as discoverable CHIP tokens (BRC-23), querying the overlay to find signing partners via SLAP/CLAP lookup (BRC-24/25), and publishing BRC-18 participation proofs for on-chain fee distribution. All communication targets the `tm_mpc_signing` overlay topic.

## Implementation Status

CHIP token creation/parsing and node discovery are **fully implemented** with comprehensive test coverage. Overlay publication (`publish_chip_token`) works but lacks BRC-31 auth headers. Proof publication and parsing remain `todo!()` stubs. Fee settlement calculation is implemented.

| Area | Status |
|------|--------|
| CHIP token create/parse | **Implemented** — 5-field PushDrop with capabilities JSON, 14 tests |
| CHIP token publish | **Implemented** — HTTP POST to `/submit`, missing BRC-31 auth |
| CHIP token revoke | **Stub** — returns error explaining what's needed |
| SDK admin token wrappers | **Implemented** — `create_ship_admin_token`, `parse_ship_admin_token` |
| Node discovery | **Implemented** — `LookupResolver` + SLAP, filter, dedup, sort. 9 tests |
| Node health checking | **Implemented** — HTTP GET `/health` with 5s timeout |
| Node reputation | **Implemented** — proof count lookup via overlay |
| Client-side filtering | **Implemented** — pure `filter_and_rank_nodes()` |
| Proof publication | **Stub** — `todo!()` with detailed pseudocode |
| Proof querying/counting | **Stub** — `todo!()` with detailed pseudocode |
| Proof script parsing | **Stub** — `todo!()` with detailed pseudocode |
| Fee settlement | **Implemented** — proportional integer distribution |

## Files

| File | Purpose |
|------|---------|
| `lib.rs` | Module declarations and re-exports (`OverlayError`, `DiscoveryQuery`, `MpcNodeInfo`, `OverlayProof`, `MPC_TOPIC`) |
| `types.rs` | Shared data structures: `MpcNodeInfo`, `DiscoveryQuery`, `OverlayProof`, `FeeSettlement`, `NodeFeeShare`, and the `MPC_TOPIC` constant |
| `error.rs` | `OverlayError` enum with 8 variants covering overlay communication, CHIP parsing, and proof errors |
| `chip.rs` | CHIP token (BRC-23/BRC-48 PushDrop) creation, parsing, publishing, revocation, and SDK wrappers. 14 tests |
| `discovery.rs` | SLAP overlay lookup to find MPC nodes, health checking, reputation scoring, client-side filtering. 9 tests |
| `proofs.rs` | BRC-18 participation proof publication, querying, counting, parsing, and fee settlement calculation |

## Key Exports

### Types (`types.rs`)

| Export | Description |
|--------|-------------|
| `MPC_TOPIC` | Constant `"tm_mpc_signing"` — the overlay topic for all MPC data |
| `MpcNodeInfo` | Node advertisement data: identity key, domain, curves, threshold configs, fee, version, published_at, optional limits |
| `DiscoveryQuery` | Query filters: curve, threshold config, max fee, result limit (all optional, `Default` derived) |
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
| `create_chip_token` | `(identity_key: &[u8; 33], domain: &str, node_info: &MpcNodeInfo) -> Result<Vec<u8>, OverlayError>` | **Implemented** |
| `parse_chip_token` | `(script_bytes: &[u8]) -> Result<MpcNodeInfo, OverlayError>` | **Implemented** |
| `create_ship_admin_token` | `(identity_key: &[u8; 33], domain: &str) -> Result<Vec<u8>, OverlayError>` | **Implemented** |
| `parse_ship_admin_token` | `(script_bytes: &[u8]) -> Result<OverlayAdminTokenData, OverlayError>` | **Implemented** |
| `publish_chip_token` | `async (overlay_url: &str, token_tx: &[u8]) -> Result<(), OverlayError>` | **Implemented** |
| `revoke_chip_token` | `async (overlay_url: &str, token_txid: &str, token_vout: u32) -> Result<String, OverlayError>` | Stub |

`ChipCapabilities` struct holds the JSON blob embedded in the PushDrop script: curves, threshold_configs, fee_sats, version, and optional max_presignatures/min_balance_sats (skipped in JSON when None).

`create_chip_token` validates that domain is non-empty and fee_sats > 0. `parse_chip_token` accepts both 5-field MPC tokens (with capabilities JSON) and 4-field standard SHIP tokens (with defaults: secp256k1, 2-of-2, 100 sats, version "0.0.0").

`create_ship_admin_token` / `parse_ship_admin_token` are SDK wrappers around `bsv::overlay::create_overlay_admin_token` / `decode_overlay_admin_token` that enforce the `tm_mpc_signing` topic.

### Discovery Functions (`discovery.rs`)

| Function | Signature | Status |
|----------|-----------|--------|
| `discover_nodes` | `async (overlay_url: &str, query: &DiscoveryQuery) -> Result<Vec<MpcNodeInfo>, OverlayError>` | **Implemented** |
| `node_reputation` | `async (overlay_url: &str, identity_key: &str) -> Result<u64, OverlayError>` | **Implemented** |
| `verify_node_health` | `async (node: &MpcNodeInfo) -> Result<bool, OverlayError>` | **Implemented** |
| `discover_healthy_nodes` | `async (overlay_url: &str, query: &DiscoveryQuery, max_concurrent_checks: Option<usize>) -> Result<Vec<MpcNodeInfo>, OverlayError>` | **Implemented** |
| `filter_and_rank_nodes` | `(nodes: Vec<MpcNodeInfo>, query: &DiscoveryQuery) -> Vec<MpcNodeInfo>` | **Implemented** |

Constants: `MPC_LOOKUP_SERVICE = "ls_mpc_signing"`.

Default result limit is 20. Default max concurrent health checks is 5.

`discover_nodes` uses the BSV SDK's `LookupResolver` with mainnet preset. If `overlay_url` is non-empty, it's added as an additional SHIP host. The flow: build `LookupQuestion` for `ls_ship` with topic `tm_mpc_signing`, parse returned BEEF outputs as CHIP tokens, filter/dedup/sort, truncate to limit.

`filter_and_rank_nodes` is a pure (no-network) function for client-side filtering of cached or locally-registered nodes. Same filter/dedup/sort logic as `discover_nodes`.

`verify_node_health` sends GET to `https://{domain}/health` with 5-second timeout. Returns `false` (not error) on connection failure.

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
  1. LookupResolver queries SLAP trackers for SHIP hosts serving tm_mpc_signing
  2. SHIP hosts return BEEF outputs containing CHIP token PushDrop scripts
  3. Parse CHIP tokens into MpcNodeInfo via chip::parse_chip_token()
  4. Filter by curve, threshold config, max fee; dedup by identity_key
  5. Sort by fee_sats ascending (cheapest first)
  6. Health-check candidates via GET https://{domain}/health
  7. Initiate DKG/signing with selected node(s)
```

## CHIP Token PushDrop Layout

```
<signing_pubkey> OP_CHECKSIG
OP_PUSH "SHIP"                 # Protocol identifier (field 0)
OP_PUSH <identity_key>         # 33-byte compressed secp256k1 (field 1)
OP_PUSH <domain>               # HTTPS domain, e.g. "mpc.example.com" (field 2)
OP_PUSH "tm_mpc_signing"       # Topic name (field 3)
OP_PUSH <capabilities_json>    # ChipCapabilities JSON (field 4, optional)
OP_2DROP OP_2DROP OP_DROP      # Clean stack (5 fields)
```

The signing/locking key is the identity key itself. Standard 4-field SHIP tokens (without field 4) are accepted with default capabilities.

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

`calculate_settlement()` performs proportional integer distribution:

```
node_fee = (total_fees * node_proof_count) / total_proof_count
```

Integer division rounds down. If total proofs is zero, all nodes receive 0 sats. Rounding remainder is not explicitly redistributed (lost to truncation, typically < n sats total).

## Tests

**chip.rs** — 14 tests covering:
- Create/parse roundtrip (full capabilities, minimal config, various thresholds, various fees)
- Validation errors (empty domain, zero fee, invalid identity key, invalid script)
- Protocol/topic validation (wrong topic, wrong protocol)
- 4-field standard SHIP token parsing with defaults
- SDK `create_ship_admin_token` / `parse_ship_admin_token` roundtrip
- PushDrop field count verification
- `ChipCapabilities` JSON roundtrip
- Multiple nodes produce distinct tokens

**discovery.rs** — 9 tests covering:
- Filter by curve, threshold, max fee, and combined filters
- Sort by fee ascending
- Deduplication by identity_key (keeps most recent `published_at`)
- Result limit truncation
- Empty input and no-filter cases
- `MPC_LOOKUP_SERVICE` constant value

## Dependencies

| Crate | Purpose |
|-------|---------|
| `bsv-mpc-core` | `ParticipationProof` type from `types.rs` |
| `bsv` | BSV primitives, scripts, `PushDrop`, `LockingScript`, overlay SDK (`LookupResolver`, `create_overlay_admin_token`, `decode_overlay_admin_token`, `Protocol`, `Transaction`) |
| `reqwest` | HTTP client for overlay communication and health checks |
| `serde` / `serde_json` | Serialization for all types, API payloads, and `ChipCapabilities` |
| `hex` | Encoding transaction bytes for overlay submission |
| `chrono` | UTC timestamps on `MpcNodeInfo`, `OverlayProof`, `FeeSettlement` |
| `futures` | `future::join_all` for concurrent health checks |
| `thiserror` | `OverlayError` derive macro |
| `tracing` | Structured logging in discovery and publication |

## Related

- [Root CLAUDE.md](../../../CLAUDE.md) — project architecture, conventions, overlay network design
- `crates/bsv-mpc-core/src/proof.rs` — `ParticipationProof` creation and OP_RETURN serialization (BRC-18)
- `crates/bsv-mpc-core/src/types.rs` — `ParticipationProof` struct definition
- `crates/bsv-mpc-proxy/src/wallet_api.rs` — `discoverByIdentityKey` / `discoverByAttributes` handlers forward to this crate
