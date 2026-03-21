# BRC-XXX: MPC Participation Proofs

| Field      | Value                                                   |
|------------|---------------------------------------------------------|
| Title      | MPC Participation Proofs                                |
| Author     | John Calhoun                                            |
| Status     | Draft                                                   |
| Created    | 2026-03-21                                              |
| Type       | Standards Track                                         |
| Layer      | Proofs / Overlay                                        |
| Requires   | BRC-18, BRC-22, BRC-24, BRC-31, BRC-77                 |

## Abstract

This BRC defines the on-chain proof format for MPC threshold signing participation. Each proof attests that a set of identified nodes cooperated to produce a threshold signature for a specific agent. Proofs are stored as BRC-18 OP_RETURN outputs, indexed on the BSV overlay network under the `tm_mpc_signing` topic, and queryable via BRC-24 lookup. They serve three purposes: verifiable fee distribution to node operators (see BRC-XXX: MPC Fee Distribution), reputation scoring for node discovery (see BRC-XXX: MPC Overlay Service Discovery), and an auditable record of all MPC signing operations.

## Motivation

### Verifiable Work Attribution

In a decentralized MPC signing network, fee distribution must be proportional to actual work performed. Without on-chain proofs, a coordinator could claim that nodes participated when they did not (inflating fees) or deny that nodes participated when they did (withholding payment). On-chain proofs eliminate both failure modes by creating a publicly verifiable record of participation.

### Reputation as Public Good

Node reputation in the discovery system (BRC-XXX: MPC Overlay Service Discovery) is derived from participation proof count. For this to work, proofs must be:

1. **Publicly queryable.** Anyone can count proofs for any node.
2. **Unforgeable.** A proof cannot be created without actual participation.
3. **Non-repudiable.** Once created, a proof cannot be denied or deleted.
4. **Attributable.** Each proof clearly identifies which nodes participated.

On-chain BRC-18 proofs indexed on the overlay satisfy all four properties.

### Audit Trail

For regulated environments, agents may need to prove that their transactions were signed through a proper MPC ceremony with the required threshold of parties. Participation proofs provide this evidence without revealing the key shares or the details of the signed transaction.

## Specification

### 1. Proof Format

An MPC participation proof is a BRC-18 OP_RETURN output with the following field layout:

```
OP_FALSE OP_RETURN
  [0]  protocol_id:       "mpc-signing-proof"  (UTF-8 string, 18 bytes)
  [1]  version:           0x01                  (uint8, 1 byte)
  [2]  session_hash:      <32 bytes>            (SHA-256 of signing session transcript)
  [3]  agent_identity:    <33 bytes>            (agent's BRC-31 identity key, compressed)
  [4]  node_count:        <uint8>               (number of participating nodes, 1 byte)
  [5]  node_identity_0:   <33 bytes>            (first node's BRC-31 identity key)
  [6]  node_identity_1:   <33 bytes>            (second node's BRC-31 identity key)
  ...  (repeat for each participating node)
  [5+n]   signing_hash:   <32 bytes>            (SHA-256d of the signed BSV transaction)
  [5+n+1] fee_txid:       <32 bytes>            (txid containing the fee output, or 32 zero bytes if none)
  [5+n+2] timestamp:      <8 bytes>             (Unix epoch seconds, uint64 big-endian)
  [5+n+3] proof_signature: <variable>           (BRC-77 signature from the agent)
```

**Total size for a 2-of-3 signing (3 nodes):**
18 + 1 + 32 + 33 + 1 + (3 * 33) + 32 + 32 + 8 + ~72 = ~328 bytes

This fits comfortably within a single OP_RETURN output.

### 2. Field Definitions

#### 2.1 protocol_id

The literal UTF-8 string `"mpc-signing-proof"`. Identifies this output as an MPC participation proof. Topic managers and indexers use this field to filter relevant outputs.

#### 2.2 version

Protocol version as a single unsigned byte. Current version is `0x01`. Future versions may extend the field layout. Parsers MUST reject proofs with unknown versions.

#### 2.3 session_hash

SHA-256 hash of the signing session transcript. The transcript is the concatenation of all protocol messages exchanged during the signing ceremony, ordered by (round, from, to):

```
session_hash = SHA-256(
  msg_0_broadcast ||
  msg_1_p2p_0_to_1 ||
  msg_1_p2p_0_to_2 ||
  msg_1_p2p_1_to_0 ||
  ...
)
```

This hash binds the proof to a specific signing session. Participants can independently verify the hash by replaying their session transcript. The session_hash also serves as a deduplication key -- the topic manager rejects proofs with duplicate session_hash values.

#### 2.4 agent_identity

The 33-byte compressed secp256k1 public key of the agent that requested the signing operation. This is the agent's BRC-31 identity key.

#### 2.5 node_count

The number of nodes that participated in the signing ceremony. This is the number of node_identity fields that follow.

For a t-of-n threshold configuration, node_count = t+1 (the number of parties that actually participated, not the total number of share holders).

#### 2.6 node_identity_i

The 33-byte compressed secp256k1 public key of each participating node, in ascending lexicographic order of the raw key bytes. Ordering ensures deterministic proof construction -- all parties will produce the same proof bytes.

#### 2.7 signing_hash

The SHA-256d (double SHA-256) hash of the BSV transaction that was signed. This is the same hash that was input to the ECDSA signing algorithm.

Note: This reveals which transaction was MPC-signed, but does not reveal the transaction contents (only the hash). For additional privacy, agents MAY use a commitment scheme (e.g., hash of the signing_hash with a blinding factor) and reveal the preimage only to auditors.

#### 2.8 fee_txid

The transaction ID of the transaction containing the fee output(s) for this signing operation. This links the proof to the fee payment, enabling fee distribution verification.

If no fee was collected (e.g., during a free trial or testing), this field is 32 zero bytes.

#### 2.9 timestamp

Unix epoch seconds as an 8-byte big-endian unsigned integer. This is the wall-clock time at which the signing operation completed, as reported by the proof creator.

Note: This timestamp is self-reported and not consensus-enforced. For ordering disputes, the block timestamp of the proof transaction is authoritative.

#### 2.10 proof_signature

A BRC-77 ECDSA signature over the concatenation of all preceding fields (protocol_id through timestamp), signed by the agent's BRC-31 identity key.

```
signature_preimage = protocol_id || version || session_hash || agent_identity ||
                     node_count || node_identity_0 || ... || node_identity_n ||
                     signing_hash || fee_txid || timestamp

proof_signature = BRC-77-Sign(agent_private_key, SHA-256(signature_preimage))
```

This signature proves that the agent (not a third party) created the proof. Nodes can verify the signature using the agent's public identity key.

### 3. Proof Creation

The proof is created by the agent (or the MPC signing proxy acting on the agent's behalf) immediately after a successful signing operation:

**Step 1: Collect session data.**

After the signing protocol completes successfully:
- Record the session transcript (all protocol messages).
- Compute the session_hash.
- Collect the identity keys of all participating nodes.

**Step 2: Construct the proof.**

Assemble the OP_RETURN fields in the specified order. Sort node identity keys lexicographically.

**Step 3: Sign the proof.**

Compute the BRC-77 signature over the proof fields using the agent's identity key.

**Step 4: Create the transaction.**

Construct a BSV transaction with:
- Input: a small UTXO from the agent's wallet (for the transaction fee).
- Output 0: the OP_RETURN proof output (0 satoshis).
- Output 1: change output (if needed).

The transaction fee is standard (1 sat/byte).

**Step 5: Broadcast and submit.**

1. Broadcast the transaction to the BSV network.
2. Submit the transaction to the overlay via BRC-22:

```
POST https://overlay-node.example.com/submit
Content-Type: application/json

{
  "beef": "<AtomicBEEF-encoded-transaction>",
  "topics": ["tm_mpc_signing"]
}
```

### 4. Overlay Admission

The topic manager for `tm_mpc_signing` validates participation proofs for admission to the overlay index:

**Validation rules:**

1. **Format check.** The OP_RETURN output matches the specified field layout. Field 0 is `"mpc-signing-proof"`. Version is `0x01`.

2. **Identity key validity.** The agent_identity and all node_identity fields are valid compressed secp256k1 public keys (on the curve).

3. **Signature verification.** The proof_signature is a valid BRC-77 ECDSA signature under the agent_identity key.

4. **Node ordering.** Node identity keys are in ascending lexicographic order.

5. **Deduplication.** No existing proof in the index has the same session_hash. Duplicate proofs are rejected.

6. **Node count consistency.** The node_count field matches the actual number of node_identity fields present.

The topic manager does NOT verify:
- Whether the signing session actually occurred (this would require the session transcript, which is private).
- Whether the fee_txid refers to a real transaction (fee verification is the responsibility of BRC-XXX: MPC Fee Distribution).
- Whether the timestamp is accurate (self-reported).

### 5. Querying Proofs

Proofs are queried via BRC-24 overlay lookup:

**Query by node identity (for reputation):**

```json
{
  "provider": "mpc-proofs",
  "query": {
    "node_identity": "02abc...hex",
    "since": 1711036800,
    "until": 1711123200
  }
}
```

Returns all proofs where the specified node_identity appears in the node list, within the optional time range.

**Query by agent identity (for audit):**

```json
{
  "provider": "mpc-proofs",
  "query": {
    "agent_identity": "03def...hex",
    "since": 1711036800
  }
}
```

Returns all proofs created by the specified agent.

**Query by fee_txid (for fee verification):**

```json
{
  "provider": "mpc-proofs",
  "query": {
    "fee_txid": "aabb...hex"
  }
}
```

Returns the proof(s) associated with a specific fee transaction.

**Query all recent proofs (for global statistics):**

```json
{
  "provider": "mpc-proofs",
  "query": {
    "since": 1711036800,
    "limit": 100
  }
}
```

### 6. Verification

Anyone can verify a participation proof:

**Step 1: Fetch the proof.**

Query the overlay or fetch the proof transaction directly from the BSV network.

**Step 2: Parse the OP_RETURN.**

Extract all fields according to the specified layout.

**Step 3: Verify the signature.**

Recompute the signature preimage from the parsed fields and verify the BRC-77 signature against the agent_identity key.

**Step 4: Verify on-chain existence.**

Confirm the proof transaction is included in a block (or in the mempool for recent proofs).

**Step 5: Cross-reference (optional).**

- Verify the fee_txid refers to a real transaction with appropriate fee outputs.
- Check the signing_hash against known agent transactions.
- Verify node identities against registered CHIP tokens on the overlay.

### 7. Abort Proofs

When a signing ceremony fails due to identifiable abort (a party misbehaved), an abort proof MAY be created:

```
OP_FALSE OP_RETURN
  [0]  protocol_id:       "mpc-abort-proof"    (UTF-8 string)
  [1]  version:           0x01                  (uint8)
  [2]  session_hash:      <32 bytes>            (SHA-256 of partial session transcript)
  [3]  agent_identity:    <33 bytes>            (agent's BRC-31 identity key)
  [4]  faulty_party:      <33 bytes>            (identity key of the misbehaving party)
  [5]  reason:            <variable>            (UTF-8 string: reason for abort)
  [6]  honest_count:      <uint8>               (number of honest parties)
  [7..] honest_parties:   <33 bytes each>       (identity keys of honest parties)
  [last] proof_signature: <variable>            (BRC-77 signature from the agent)
```

Abort proofs are submitted to the same `tm_mpc_signing` topic. They contribute negatively to the faulty party's reputation score and positively (marginally) to the honest parties' scores, since they demonstrated availability even though the session failed.

**Abort reasons (standardized strings):**

| Reason                   | Description                                          |
|--------------------------|------------------------------------------------------|
| `timeout`                | Party failed to respond within the round timeout     |
| `invalid_commitment`     | Commitment did not match decommitment                |
| `invalid_share`          | VSS share failed Feldman verification                |
| `invalid_range_proof`    | Zero-knowledge range proof was invalid               |
| `invalid_mta_proof`      | MtA (multiplicative-to-additive) proof was invalid   |
| `invalid_signature_share`| Partial signature did not verify                     |
| `protocol_violation`     | Generic protocol violation                           |

### 8. Proof Aggregation

For efficiency, multiple signing proofs MAY be aggregated into a single transaction:

```
Transaction:
  Input 0: funding UTXO
  Output 0: OP_RETURN proof_1 (signing operation 1)
  Output 1: OP_RETURN proof_2 (signing operation 2)
  ...
  Output N: OP_RETURN proof_N (signing operation N)
  Output N+1: change
```

Each proof is a separate OP_RETURN output in the same transaction. The topic manager indexes each output independently.

Aggregation is RECOMMENDED for agents that perform many signing operations in rapid succession (e.g., batch payments). It reduces the number of transactions and total fees.

**Aggregation limits:**

- Maximum 20 proofs per transaction (to stay within standard transaction size limits).
- All proofs in an aggregated transaction MUST be from the same agent (same agent_identity).

### 9. Proof Expiry

Proofs do not expire. They remain on-chain and in the overlay index indefinitely. However, for reputation calculations, implementations SHOULD apply a time decay:

```
recency_weight = exp(-age_days / 365)
weighted_count = sum(recency_weight for each proof)
```

This ensures that recent activity weighs more heavily than historical activity, preventing nodes that were active a year ago but are now dormant from maintaining inflated reputation scores.

### 10. Privacy Considerations

**Information revealed by proofs:**

- Which agent used MPC signing (agent_identity is public).
- Which nodes participated (node identities are public).
- When the signing occurred (timestamp).
- Which transaction was signed (signing_hash -- the hash, not the content).
- The fee transaction (fee_txid).

**Information NOT revealed:**

- Transaction contents (only the hash is in the proof).
- Key share values.
- Protocol message contents (only the session_hash is in the proof).
- The threshold configuration (node_count reveals how many participated, but not the total n or the threshold t).

**Privacy-enhanced mode:**

For agents requiring stronger privacy, a blinded proof format MAY be used in future versions:
- Replace agent_identity with a Pedersen commitment.
- Replace node_identity with ring signatures over the set of registered nodes.
- This is left for a future BRC extension.

## Implementation

### Proof Builder (Rust)

```rust
use bsv::script::Script;

pub struct MpcProofBuilder {
    session_hash: [u8; 32],
    agent_identity: [u8; 33],
    node_identities: Vec<[u8; 33]>,
    signing_hash: [u8; 32],
    fee_txid: [u8; 32],
    timestamp: u64,
}

impl MpcProofBuilder {
    pub fn build_op_return(&self) -> Script {
        let mut data = Vec::new();

        // Field 0: protocol_id
        data.extend_from_slice(b"mpc-signing-proof");
        // Field 1: version
        data.push(0x01);
        // Field 2: session_hash
        data.extend_from_slice(&self.session_hash);
        // Field 3: agent_identity
        data.extend_from_slice(&self.agent_identity);
        // Field 4: node_count
        data.push(self.node_identities.len() as u8);
        // Fields 5..5+n: node identities (sorted)
        let mut sorted_nodes = self.node_identities.clone();
        sorted_nodes.sort();
        for node in &sorted_nodes {
            data.extend_from_slice(node);
        }
        // signing_hash
        data.extend_from_slice(&self.signing_hash);
        // fee_txid
        data.extend_from_slice(&self.fee_txid);
        // timestamp
        data.extend_from_slice(&self.timestamp.to_be_bytes());

        Script::from_op_return(&data)
    }
}
```

### Overlay Indexer

The overlay indexer for `mpc-proofs` provider maintains two indexes:

1. **By node identity.** Maps `node_identity_key -> Vec<ProofRef>` for reputation queries.
2. **By agent identity.** Maps `agent_identity_key -> Vec<ProofRef>` for audit queries.

Both indexes support time-range filtering via the proof timestamp.

### Integration with Fee Distribution

The fee distribution system (BRC-XXX: MPC Fee Distribution) uses participation proofs as the source of truth for settlement calculations:

1. Query all proofs for an epoch (time range).
2. Tally participation count per node.
3. Compute proportional fee split.
4. Verify against fee_txid references.

See BRC-XXX: MPC Fee Distribution for the complete settlement flow.

## References

- BRC-18: OP_RETURN Proofs.
- BRC-22: SHIP (Simplified Hosting of Internet Peers).
- BRC-24: SLAP (Simplified Lookup and Advertising Protocol).
- BRC-31: Authrite Mutual Authentication.
- BRC-77: Message Signing.
- BRC-XXX: Threshold ECDSA Signing Protocol for BSV (this series).
- BRC-XXX: MPC Overlay Service Discovery (this series).
- BRC-XXX: MPC Fee Distribution (this series).
