# BRC-XXX: MPC Overlay Service Discovery

| Field      | Value                                                   |
|------------|---------------------------------------------------------|
| Title      | MPC Overlay Service Discovery                           |
| Author     | John Calhoun                                            |
| Status     | Draft                                                   |
| Created    | 2026-03-21                                              |
| Type       | Standards Track                                         |
| Layer      | Overlay / Discovery                                     |
| Requires   | BRC-22, BRC-23, BRC-24, BRC-25, BRC-31, BRC-48         |

## Abstract

This BRC defines how MPC threshold signing nodes advertise their services on the BSV overlay network and how agents discover available nodes that meet their requirements. It introduces a new overlay topic `tm_mpc_signing` and specifies CHIP token fields, registration flows, discovery queries, reputation scoring, and deregistration. The protocol extends the existing BSV overlay infrastructure (BRC-22 SHIP, BRC-23 CHIP, BRC-24 SLAP, BRC-25 overlay lookup) to enable permissionless, decentralized MPC node discovery without any central registry.

## Motivation

### Decentralized Node Discovery

A threshold signing network is only useful if agents can find signing nodes. A centralized registry (e.g., a hardcoded list of node URLs) introduces a single point of failure, censorship risk, and a trust dependency that undermines the security properties of threshold signing. If the registry operator can control which nodes appear, they can effectively control which parties hold key shares.

The BSV overlay network provides existing infrastructure for decentralized service advertisement and discovery. Nodes register by creating on-chain tokens; anyone can discover nodes by querying the overlay. No single party controls the registry.

### Capability Matching

Not all MPC nodes are identical. Agents need to filter nodes by:

- **Supported curves.** Currently secp256k1, but future extensions may include Ed25519.
- **Supported thresholds.** A node may support 2-of-2 and 2-of-3 but not 5-of-9.
- **Pricing.** Nodes set their own fee per signing operation.
- **Protocol version.** Ensures compatibility between agent and node.
- **Reputation.** Agents prefer nodes with a proven track record of honest participation.

The overlay topic and CHIP token format defined here capture all of these dimensions.

### Permissionless Participation

Anyone can run an MPC signing node. Registration requires only creating a CHIP token (a small on-chain transaction). There is no approval process, no KYC requirement, and no minimum stake. Market dynamics -- pricing and reputation -- naturally select for reliable operators.

## Specification

### 1. Topic Definition

A new overlay topic is introduced:

| Property           | Value                                                       |
|--------------------|-------------------------------------------------------------|
| Topic name         | `tm_mpc_signing`                                            |
| Topic manager type | CHIP validation (BRC-23 compliant)                          |
| Admission rule     | Valid BRC-48 PushDrop token with correct CHIP field layout   |

The topic manager MUST validate:
1. The token is a valid BRC-48 PushDrop script.
2. Field 1 is the literal string `"CHIP"`.
3. Field 2 is a valid 33-byte compressed secp256k1 public key.
4. Field 3 is a valid HTTPS URL.
5. Field 4 is the literal string `"tm_mpc_signing"`.
6. The token is signed by the key in Field 2 via BRC-48 PushDrop signature.

### 2. CHIP Token Format

Each MPC node creates a CHIP token (BRC-23) to advertise its services. The token is a BRC-48 PushDrop script with the following fields:

**Core CHIP fields (in the PushDrop script):**

| Field Index | Name              | Type     | Description                                |
|-------------|-------------------|----------|--------------------------------------------|
| 0           | marker            | string   | `"CHIP"` (literal)                         |
| 1           | identity_key      | bytes    | Node's BRC-31 identity key (33 bytes)      |
| 2           | service_url       | string   | HTTPS domain of the Key Share Service      |
| 3           | topic             | string   | `"tm_mpc_signing"` (literal)               |

**Extended capability fields (JSON in OP_RETURN data push):**

```json
{
  "curves": ["secp256k1"],
  "thresholds": ["2-of-2", "2-of-3", "3-of-5"],
  "fee_sats": 333,
  "version": "0.1.0",
  "protocols": ["cggmp24"],
  "min_presign_pool": 10,
  "max_concurrent_sessions": 50,
  "uptime_commitment": 0.99,
  "jurisdiction": "US",
  "contact": "operator@example.com"
}
```

| Field                    | Type       | Required | Description                                         |
|--------------------------|------------|----------|-----------------------------------------------------|
| curves                   | string[]   | Yes      | Supported elliptic curves                            |
| thresholds               | string[]   | Yes      | Supported threshold configurations                   |
| fee_sats                 | uint64     | Yes      | Fee in satoshis per signing operation                |
| version                  | string     | Yes      | Node software version (semver)                       |
| protocols                | string[]   | Yes      | Supported MPC protocols                              |
| min_presign_pool         | uint32     | No       | Minimum presignatures maintained per session         |
| max_concurrent_sessions  | uint32     | No       | Maximum concurrent signing sessions                  |
| uptime_commitment        | float      | No       | Advertised uptime SLA (0.0 to 1.0)                  |
| jurisdiction             | string     | No       | Legal jurisdiction of the node operator              |
| contact                  | string     | No       | Operator contact information                         |

### 3. Registration Flow

To register as an MPC signing node:

**Step 1: Generate identity.**

The node operator generates a BRC-31 identity keypair. This key is used for all authentication with agents and other nodes.

**Step 2: Create CHIP token.**

Construct a BRC-48 PushDrop script containing the CHIP fields:

```
OP_0 OP_RETURN
  PUSH "CHIP"
  PUSH <identity_key_33_bytes>
  PUSH <service_url_string>
  PUSH "tm_mpc_signing"
  PUSH <extended_capabilities_json>
  <BRC-48 PushDrop signature>
```

The PushDrop signature is computed using a BRC-42 derived key:

| Parameter    | Value                     |
|--------------|---------------------------|
| Protocol ID  | `[2, "CHIP"]`             |
| Key ID       | `"tm_mpc_signing"`        |
| Counterparty | `"anyone"` (1*G)          |

**Step 3: Submit to overlay.**

Submit the transaction containing the CHIP token to the overlay network via BRC-22:

```
POST https://overlay-node.example.com/submit
Content-Type: application/json

{
  "beef": "<AtomicBEEF-encoded-transaction>",
  "topics": ["tm_mpc_signing"]
}
```

The overlay node validates the CHIP token against the topic manager's admission rules and indexes it.

**Step 4: Verify registration.**

Query the overlay to confirm the token appears:

```
POST https://overlay-node.example.com/lookup
Content-Type: application/json

{
  "provider": "CHIP",
  "query": {
    "topic": "tm_mpc_signing",
    "identity_key": "<node-identity-key-hex>"
  }
}
```

### 4. Discovery Flow

Agents discover MPC nodes through the overlay network:

**Step 1: Query the overlay.**

```
POST https://overlay-node.example.com/lookup
Content-Type: application/json

{
  "provider": "CHIP",
  "query": {
    "topic": "tm_mpc_signing"
  }
}
```

The overlay returns BRC-36 UTXO objects containing matching CHIP tokens.

**Step 2: Parse tokens.**

For each returned UTXO, extract:
- The CHIP fields from the PushDrop script.
- The extended capabilities from the JSON data push.

**Step 3: Filter by requirements.**

Apply agent-specific filters:

```python
# Pseudocode
candidates = []
for token in discovered_tokens:
    caps = token.extended_capabilities
    if "secp256k1" not in caps.curves:
        continue
    if desired_threshold not in caps.thresholds:
        continue
    if caps.fee_sats > max_acceptable_fee:
        continue
    if caps.version < minimum_version:
        continue
    candidates.append(token)
```

**Step 4: Rank by reputation.**

Sort candidates by reputation score (see Section 6). Prefer nodes with:
- Higher participation proof count.
- Lower abort rate.
- Longer registration age.

**Step 5: Select nodes.**

For a t-of-n configuration, select n nodes from the ranked candidates. Nodes SHOULD be on independent infrastructure (inferred from different service URLs, IP ranges, or stated jurisdictions).

**Step 6: Initiate contact.**

Contact each selected node via BRC-31 authenticated HTTPS:

```
POST https://mpc-node.example.com/api/session/propose
Authorization: <BRC-31 Authrite headers>
Content-Type: application/json

{
  "threshold": 1,
  "party_count": 3,
  "agent_identity": "<agent-identity-key-hex>",
  "proposed_parties": [
    "<agent-identity-key-hex>",
    "<node1-identity-key-hex>",
    "<node2-identity-key-hex>"
  ]
}
```

### 5. Node Service API

Each MPC node exposes an HTTPS API for session management:

| Method | Path                         | Auth    | Description                                 |
|--------|------------------------------|---------|---------------------------------------------|
| GET    | /health                      | None    | Node health and version                     |
| GET    | /capabilities                | None    | Extended capabilities (same as CHIP token)  |
| POST   | /api/session/propose         | BRC-31  | Propose a new MPC session                   |
| POST   | /api/session/{id}/accept     | BRC-31  | Accept session proposal                     |
| POST   | /api/session/{id}/reject     | BRC-31  | Reject session proposal                     |
| POST   | /api/session/{id}/message    | BRC-31  | Send a protocol message                     |
| GET    | /api/session/{id}/messages   | BRC-31  | Poll for incoming protocol messages         |
| GET    | /api/session/{id}/status     | BRC-31  | Session status and presignature count       |
| POST   | /api/session/{id}/sign       | BRC-31  | Request a signing operation                 |
| DELETE | /api/session/{id}            | BRC-31  | Terminate session                           |

All endpoints marked BRC-31 require mutual Authrite authentication. The node MUST verify that the requesting party is a member of the specified session.

### 6. Reputation System

Node reputation is derived entirely from on-chain data -- no trusted third party.

**Reputation inputs:**

| Factor                | Weight | Source                                           |
|-----------------------|--------|--------------------------------------------------|
| Participation proofs  | 0.40   | BRC-XXX: MPC Participation Proofs on overlay     |
| Registration age      | 0.20   | Block height of CHIP token creation              |
| Abort rate            | 0.25   | Abort proofs vs. participation proofs ratio       |
| Fee competitiveness   | 0.15   | Percentile rank of fee_sats among active nodes   |

**Reputation score calculation:**

```
proof_score = min(1.0, participation_count / 1000)
age_score = min(1.0, registration_age_days / 365)
abort_score = 1.0 - (abort_count / max(1, participation_count))
fee_score = 1.0 - fee_percentile

reputation = (0.40 * proof_score) +
             (0.20 * age_score) +
             (0.25 * abort_score) +
             (0.15 * fee_score)
```

Score range: 0.0 to 1.0. New nodes start with a score of approximately 0.15 (fee competitiveness only).

**Reputation queries:**

Agents compute reputation locally by:
1. Querying participation proofs from the overlay (BRC-24 lookup by node identity).
2. Querying the CHIP token for registration age and fee.
3. Computing the score using the formula above.

No trust in any reputation oracle is required. All inputs are publicly verifiable on-chain data.

### 7. Node Health and Liveness

**Health endpoint:**

```
GET https://mpc-node.example.com/health

Response:
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime_seconds": 864000,
  "active_sessions": 12,
  "presignatures_available": 156,
  "identity_key": "02abc...hex"
}
```

**Liveness monitoring:**

Agents SHOULD periodically check the health of nodes they have active sessions with. If a node fails to respond to health checks for a configurable period (default: 5 minutes), the agent SHOULD:

1. Attempt to reach the node via BRC-33 MessageBox as a fallback.
2. If still unreachable after 15 minutes, mark the node as potentially down.
3. If in a t-of-n configuration with n > t+1, signing can continue with remaining nodes.
4. If exactly t+1 nodes remain, issue an alert and prepare for re-keying.

### 8. Deregistration

A node deregisters by spending its CHIP token UTXO:

1. Create a transaction that spends the CHIP token output.
2. The output can be spent to any address (the node operator's own address is typical).
3. Submit the spending transaction to the BSV network.
4. The overlay node detects the spent output and removes it from the `tm_mpc_signing` index.

Deregistration is final. To re-register, the node must create a new CHIP token.

**Graceful shutdown:**

Before deregistering, a node SHOULD:
1. Stop accepting new session proposals.
2. Complete all active signing requests.
3. Notify active session partners of planned shutdown via BRC-33 message.
4. Allow a grace period (e.g., 24 hours) for session migration.
5. Then spend the CHIP token to deregister.

### 9. CHIP Token Update

To update advertised capabilities (e.g., change fee, add threshold support):

1. Create a new CHIP token with updated fields.
2. Submit the new token to the overlay.
3. Spend the old CHIP token to deregister it.

Both transactions can be included in the same block. The overlay will process the registration before the deregistration (new token first, then old token spent).

### 10. Privacy Considerations

**What is public:**

- Node identity key (BRC-31 public key).
- Service URL.
- Supported capabilities and pricing.
- Participation proof count (reputation).

**What is NOT public:**

- Which agents use which nodes (session proposals are BRC-31 encrypted).
- Key share values (encrypted at rest and in transit).
- Signing request content (transaction details are not in participation proofs).

Agents who require additional privacy SHOULD:
- Contact nodes via Tor or VPN.
- Use different identity keys for different MPC sessions.
- Avoid including jurisdiction or contact fields in their own CHIP tokens (if the agent itself is also a node).

## Implementation

### Reference Overlay Node Configuration

The overlay node runs a topic manager for `tm_mpc_signing`:

```typescript
// Topic manager validation (TypeScript pseudocode)
class MpcSigningTopicManager implements TopicManager {
  async admitTransaction(tx: Transaction, topic: string): Promise<AdmitResult> {
    if (topic !== 'tm_mpc_signing') return { admitted: false };

    for (const output of tx.outputs) {
      const fields = parsePushDrop(output.script);
      if (!fields) continue;

      // Validate CHIP fields
      if (fields[0] !== 'CHIP') continue;
      if (!isValidCompressedPubkey(fields[1])) continue;
      if (!isValidHttpsUrl(fields[2])) continue;
      if (fields[3] !== 'tm_mpc_signing') continue;

      // Validate PushDrop signature
      if (!verifyPushDropSignature(output.script, fields[1])) continue;

      // Validate extended capabilities JSON
      const caps = JSON.parse(fields[4]);
      if (!Array.isArray(caps.curves) || !caps.curves.includes('secp256k1')) continue;
      if (!Array.isArray(caps.thresholds) || caps.thresholds.length === 0) continue;
      if (typeof caps.fee_sats !== 'number' || caps.fee_sats < 0) continue;

      return { admitted: true, outputIndex: output.index };
    }

    return { admitted: false };
  }
}
```

### Agent Discovery Client

```rust
// Rust pseudocode for agent-side discovery
pub struct MpcNodeDiscovery {
    overlay_url: String,
}

impl MpcNodeDiscovery {
    pub async fn discover_nodes(&self, requirements: &NodeRequirements) -> Vec<MpcNode> {
        // Step 1: Query overlay
        let response = reqwest::Client::new()
            .post(&format!("{}/lookup", self.overlay_url))
            .json(&serde_json::json!({
                "provider": "CHIP",
                "query": { "topic": "tm_mpc_signing" }
            }))
            .send()
            .await?;

        let utxos: Vec<OverlayUtxo> = response.json().await?;

        // Step 2: Parse and filter
        let mut candidates: Vec<MpcNode> = Vec::new();
        for utxo in utxos {
            if let Some(node) = MpcNode::from_chip_token(&utxo) {
                if node.matches(requirements) {
                    candidates.push(node);
                }
            }
        }

        // Step 3: Rank by reputation
        for node in &mut candidates {
            node.reputation = self.compute_reputation(&node.identity_key).await;
        }
        candidates.sort_by(|a, b| b.reputation.partial_cmp(&a.reputation).unwrap());

        candidates
    }
}
```

### Integration with bsv-worm

The discovery flow integrates with the existing `discovery.rs` module in bsv-worm:

1. Agent calls `discover_mpc_nodes()` during setup or when establishing a new MPC session.
2. Discovery results are cached for 5 minutes (same TTL as x402 service discovery).
3. Node selection is logged to the session transcript for audit.
4. Selected nodes are stored in the session configuration for the MPC signing proxy.

### Bootstrap Nodes

For initial network bootstrap (when the overlay has few or no registered nodes), the following fallback is available:

- A hardcoded list of bootstrap node URLs MAY be included in client implementations.
- Bootstrap nodes MUST also register on the overlay.
- Clients SHOULD prefer overlay-discovered nodes over hardcoded bootstrap nodes.
- The bootstrap list SHOULD be empty or removed once the overlay has sufficient nodes.

## References

- BRC-22: SHIP (Simplified Hosting of Internet Peers).
- BRC-23: CHIP (Confederacy Host Interconnect Protocol).
- BRC-24: SLAP (Simplified Lookup and Advertising Protocol).
- BRC-25: Overlay Network Lookup.
- BRC-31: Authrite Mutual Authentication.
- BRC-36: UTXO Format.
- BRC-42: Key Derivation via HMAC.
- BRC-46: Output Baskets.
- BRC-48: PushDrop Tokens.
- BRC-XXX: Threshold ECDSA Signing Protocol for BSV (this series).
- BRC-XXX: MPC Participation Proofs (this series).
