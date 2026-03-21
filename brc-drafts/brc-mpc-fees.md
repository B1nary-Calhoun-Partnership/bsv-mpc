# BRC-XXX: MPC Fee Distribution

| Field      | Value                                                   |
|------------|---------------------------------------------------------|
| Title      | MPC Fee Distribution                                    |
| Author     | John Calhoun                                            |
| Status     | Draft                                                   |
| Created    | 2026-03-21                                              |
| Type       | Standards Track                                         |
| Layer      | Economic / Settlement                                   |
| Requires   | BRC-18, BRC-22, BRC-24, BRC-48                          |

## Abstract

This BRC defines how MPC threshold signing fees are collected from agent transactions and distributed to node operators proportionally based on participation. It specifies the fee output format injected into every MPC-signed transaction, three progressively trustless settlement levels (trusted accumulator, multisig self-settlement, and sCrypt covenant), and the economic model for sustainable MPC node operation. Fees are small relative to the agent's operational costs (~2% overhead), collected transparently, and distributed verifiably using on-chain participation proofs (BRC-XXX: MPC Participation Proofs).

## Motivation

### Economic Sustainability

MPC signing nodes require economic incentive to operate. Without fees, the network depends on altruism or platform subsidies -- neither of which scales. A well-designed fee mechanism ensures:

1. **Node operator profitability.** Revenue exceeds operating costs at reasonable network scale.
2. **Market-driven pricing.** Nodes set their own fees; agents choose based on price and reputation.
3. **Proportional compensation.** Nodes are paid for actual work performed, not merely for existing.

### Trustless Distribution

In a decentralized network, fee distribution should not depend on any single trusted party. Three settlement levels provide a progression from simple (with trust assumptions) to fully trustless:

- **Level 1** is suitable for single-operator deployments or testing.
- **Level 2** is the recommended production configuration -- it requires only an honest majority of the MPC nodes themselves (which is already assumed for signing security).
- **Level 3** eliminates all trust requirements using on-chain enforcement.

### Transparency

Every fee is visible on-chain. Every distribution is linked to participation proofs. Agents can audit exactly where their fees went. Node operators can verify they received their fair share. No off-chain accounting is required.

## Specification

### 1. Fee Output Format

Every MPC-signed BSV transaction includes an additional output for the signing fee:

```
Transaction (MPC-signed):
  Input 0: agent's UTXO
  ...
  Output 0: payment to recipient (agent's intended output)
  Output 1: change back to agent
  ...
  Output N-1: fee output → [fee_sats] satoshis → [fee_locking_script]
  Output N: (optional) OP_RETURN participation proof
```

The fee output is the second-to-last non-OP_RETURN output. Its position is deterministic so that nodes and auditors can identify it programmatically.

**Fee output fields:**

| Field              | Description                                                  |
|--------------------|--------------------------------------------------------------|
| fee_sats           | Fee amount in satoshis (from node CHIP token)                |
| fee_locking_script | Locking script determined by the settlement level            |

### 2. Fee Injection

The MPC Signing Proxy (BRC-XXX: Threshold ECDSA Signing Protocol, Section 9) injects the fee output into the transaction:

**Injection point:** After the BRC-100 client constructs the transaction but before signing.

**Injection flow:**

1. Agent calls `createAction` on the MPC Signing Proxy.
2. Proxy constructs the transaction using the underlying wallet (UTXO selection, outputs).
3. Proxy adds the fee output to the transaction.
4. Proxy adjusts the change output to account for the fee (reduces change by `fee_sats`).
5. Proxy computes SIGHASH for all inputs (including the new fee output in hashOutputs).
6. Proxy initiates threshold signing with participating nodes.
7. Proxy returns the fully signed transaction to the agent.

**The agent is aware of the fee** through the proxy's fee disclosure endpoint (see Section 7), but does not construct the fee output itself. This ensures the fee is always correctly formatted and cannot be omitted.

**Fee sufficiency check:** Before constructing the transaction, the proxy verifies that the agent's selected UTXOs have sufficient value to cover: intended outputs + miner fee + MPC fee. If insufficient, the proxy returns an error (not a partial transaction).

### 3. Fee Calculation

The fee for a signing operation is determined by the participating nodes' advertised rates:

```
fee_sats = max(node_0.fee_sats, node_1.fee_sats, ..., node_t.fee_sats)
```

The maximum fee among participating nodes is used. This ensures every participating node receives at least their advertised rate (after proportional split). Agents who want lower fees should select lower-cost nodes during discovery.

**Fee bounds:**

| Parameter      | Value        | Description                              |
|----------------|--------------|------------------------------------------|
| Minimum fee    | 100 sats     | Protocol-enforced floor (~$0.00002)      |
| Default fee    | 1,000 sats   | Recommended starting fee (~$0.0002)      |
| Maximum fee    | 100,000 sats | Protocol-enforced ceiling (~$0.02)       |

The minimum fee prevents nodes from advertising zero fees to gain reputation without contributing to network economics. The maximum fee protects agents from accidentally selecting excessively priced nodes.

### 4. Settlement Level 1: Trusted Accumulator

The simplest settlement model. Suitable for single-operator deployments, testing, and low-trust environments where the accumulator is the agent operator themselves.

**Fee locking script:** Standard P2PKH to a designated settlement address.

```
OP_DUP OP_HASH160 <settlement_address_hash> OP_EQUALVERIFY OP_CHECKSIG
```

**Settlement flow:**

1. Fee outputs accumulate at the settlement address.
2. Periodically (daily, weekly, or on threshold), the accumulator:
   a. Queries participation proofs from the overlay for the settlement period.
   b. Tallies participation count per node.
   c. Computes proportional split: `node_share = (node_proofs / total_proofs) * total_fees`.
   d. Constructs a multi-output transaction:
      ```
      Input: accumulated fee UTXOs
      Output 0: node_0_share → node_0_address
      Output 1: node_1_share → node_1_address
      ...
      Output N: change (rounding dust) → settlement_address
      ```
   e. Signs and broadcasts the settlement transaction.

**Trust assumption:** The accumulator honestly reports participation and distributes fees proportionally. Nodes can verify by checking on-chain proofs against their expected share, but cannot force distribution.

**Dispute resolution:** If a node believes they were underpaid:
1. Query participation proofs for the period.
2. Compute expected share.
3. Compare against received payment.
4. If discrepancy exists, submit dispute to other nodes / community.

### 5. Settlement Level 2: Multisig Self-Settlement (Recommended)

Fee outputs are locked in a t-of-n multisig controlled by the participating MPC nodes themselves. Since these nodes already cooperate for threshold signing, they can cooperate for fee settlement using the same threshold.

**Fee locking script:** t-of-n bare multisig of participating node public keys.

```
OP_<t+1> <node_pubkey_0> <node_pubkey_1> ... <node_pubkey_n> OP_<n> OP_CHECKMULTISIG
```

Note: The threshold for the fee multisig is the same as the signing threshold (t+1 of n). This ensures the same security assumption: if t+1 honest nodes are required for signing, then t+1 honest nodes can settle fees.

For configurations where n > 3 and bare multisig becomes unwieldy, P2SH can be used:

```
OP_HASH160 <hash_of_redeem_script> OP_EQUAL

Redeem script:
OP_<t+1> <node_pubkey_0> ... <node_pubkey_n> OP_<n> OP_CHECKMULTISIG
```

**Settlement flow:**

**Step 1: Epoch boundary.**

Settlement occurs at epoch boundaries. An epoch is a configurable time period:

| Epoch Type | Duration | Use Case                            |
|------------|----------|-------------------------------------|
| Daily      | 24 hours | High-volume networks                |
| Weekly     | 7 days   | Standard (recommended)              |
| On-demand  | Variable | Triggered by accumulated fee amount |

The epoch boundary is defined as midnight UTC of the epoch end day.

**Step 2: Proof tallying.**

At epoch end, any node can initiate settlement by:

1. Querying all participation proofs for the epoch from the overlay:
   ```json
   {
     "provider": "mpc-proofs",
     "query": {
       "since": <epoch_start_unix>,
       "until": <epoch_end_unix>
     }
   }
   ```

2. Tallying participation count per node:
   ```
   node_0_count = count of proofs containing node_0_identity
   node_1_count = count of proofs containing node_1_identity
   ...
   total_participations = sum of all node counts
   ```

   Note: A single proof may list multiple nodes. Each listed node gets credit for that proof.

3. Computing proportional shares:
   ```
   node_i_share = floor(total_fee_sats * node_i_count / total_participations)
   remainder = total_fee_sats - sum(all node_i_share)
   ```
   The remainder (due to integer division) goes to the node that initiated settlement.

**Step 3: Settlement proposal.**

The initiating node constructs a settlement transaction and proposes it to the other nodes:

```json
{
  "epoch": {
    "start": 1711036800,
    "end": 1711123200
  },
  "fee_utxos": [
    { "txid": "aabb...", "vout": 2, "sats": 1000 },
    { "txid": "ccdd...", "vout": 3, "sats": 1000 }
  ],
  "total_sats": 2000,
  "distribution": [
    { "node": "02abc...", "proofs": 15, "sats": 800, "address": "1Node0..." },
    { "node": "03def...", "proofs": 10, "sats": 533, "address": "1Node1..." },
    { "node": "04ghi...", "proofs": 12, "sats": 667, "address": "1Node2..." }
  ],
  "unsigned_tx": "<hex-encoded-unsigned-settlement-tx>"
}
```

**Step 4: Verification and co-signing.**

Each node that receives the proposal:

1. Independently queries participation proofs for the epoch.
2. Independently computes the proportional split.
3. Verifies the proposed distribution matches their computation (within 1 sat rounding tolerance).
4. If verified, signs the settlement transaction.
5. Returns their signature to the initiator.

**Step 5: Broadcast.**

Once t+1 signatures are collected, the initiator:
1. Assembles the fully signed transaction.
2. Broadcasts to the BSV network.
3. Submits a settlement proof to the overlay.

**Trust assumption:** Honest majority of MPC nodes (same assumption as signing security). If t+1 nodes agree on the distribution, it is correct.

**Failure mode:** If settlement fails (not enough signatures), any node can re-initiate with a corrected proposal. Fee UTXOs remain locked until settlement succeeds.

### 6. Settlement Level 3: sCrypt Covenant (Trustless)

Fee outputs are locked by an sCrypt covenant that enforces proportional distribution on-chain. No trust in any party is required -- the BSV script interpreter enforces correctness.

**Covenant design:**

The fee covenant uses BRC-21 OP_PUSH_TX introspection to verify that the spending transaction distributes fees proportionally.

**State model:**

Two UTXOs work together:

1. **Fee UTXO:** Accumulated fees locked by the covenant script.
2. **Weights UTXO:** A BRC-48 PushDrop token storing the current per-node weights (participation counts).

**Covenant script (conceptual sCrypt):**

```typescript
class MpcFeeDistribution extends SmartContract {
    @prop()
    nodeCount: bigint;

    @prop()
    nodeAddresses: FixedArray<PubKeyHash, 5>; // max 5 nodes

    @method()
    public settle(
        weights: FixedArray<bigint, 5>,
        weightsSig: Sig,        // BRC-48 signature on weights UTXO
        weightsUtxo: ByteString // serialized weights UTXO for introspection
    ) {
        // 1. Verify weights UTXO is spent in this transaction
        assert(this.ctx.hashPrevouts.includes(hash256(weightsUtxo)));

        // 2. Compute total weight
        let totalWeight = 0n;
        for (let i = 0; i < this.nodeCount; i++) {
            totalWeight += weights[i];
        }
        assert(totalWeight > 0n);

        // 3. Verify outputs match proportional distribution
        const totalSats = this.ctx.utxo.value;
        let distributed = 0n;
        for (let i = 0; i < this.nodeCount; i++) {
            const share = (totalSats * weights[i]) / totalWeight;
            assert(
                this.ctx.hashOutputs.includes(
                    buildP2PKHOutput(this.nodeAddresses[i], share)
                )
            );
            distributed += share;
        }

        // 4. Remainder goes to first node (rounding)
        assert(totalSats - distributed < this.nodeCount);
    }
}
```

**Weights UTXO:**

The weights UTXO is a BRC-48 PushDrop token in the `mpc-fee-weights` basket:

```
Fields:
  [0] "mpc-fee-weights"
  [1] epoch_start (uint64)
  [2] epoch_end (uint64)
  [3] node_0_identity (33 bytes)
  [4] node_0_weight (uint64)
  [5] node_1_identity (33 bytes)
  [6] node_1_weight (uint64)
  ...
```

The weights UTXO is created by querying participation proofs and is signed by t+1 nodes (the same MPC threshold). It is consumed in the settlement transaction alongside the fee UTXO.

**Trust assumption:** None. The sCrypt covenant enforces correct distribution. The only input that requires agreement is the weights UTXO, which is verifiable against on-chain participation proofs.

**Limitations:**
- Maximum ~5 nodes per covenant (script size constraints).
- More complex to implement and debug than Level 2.
- Requires sCrypt compilation and deployment.

### 7. Fee Disclosure

The MPC Signing Proxy MUST provide fee transparency to agents:

**Fee disclosure endpoint:**

```
GET /api/fee-schedule

Response:
{
  "fee_sats": 1000,
  "fee_breakdown": {
    "node_0": { "identity": "02abc...", "advertised_fee": 333 },
    "node_1": { "identity": "03def...", "advertised_fee": 250 },
    "node_2": { "identity": "04ghi...", "advertised_fee": 300 }
  },
  "settlement_level": 2,
  "settlement_epoch": "weekly"
}
```

**Per-transaction fee disclosure:**

The `createAction` response from the proxy includes:

```json
{
  "txid": "aabb...",
  "rawTx": "...",
  "mpc_fee": {
    "sats": 1000,
    "output_index": 3,
    "settlement_level": 2,
    "participating_nodes": ["02abc...", "03def..."]
  }
}
```

This allows agents to track MPC fees in their budget accounting (e.g., bsv-worm's per-task budget tracker).

### 8. Economics

#### 8.1 Fee Economics per Signing Operation

| Metric                        | Value          |
|-------------------------------|----------------|
| Default fee per signing       | 1,000 sats     |
| Average x402 LLM call cost   | ~50,000 sats   |
| MPC overhead as % of LLM     | ~2%            |
| MPC overhead in USD (at $50/BSV) | ~$0.005    |

The 2% overhead is negligible relative to the agent's primary operating costs (LLM inference, image generation, etc.).

#### 8.2 Node Operator Economics

**Revenue per node in a 2-of-3 configuration:**

```
fee_per_signing = 1,000 sats
node_share = 1,000 / 3 = 333 sats per signing
```

**Scaling projections:**

| Network Scale    | Agents | Signings/Day | Revenue/Node/Day | Revenue/Node/Month |
|------------------|--------|--------------|-------------------|--------------------|
| Early (launch)   | 10     | 100          | 33,300 sats       | ~$5                |
| Growth           | 100    | 1,000        | 333,000 sats      | ~$50               |
| Scale            | 1,000  | 10,000       | 3,330,000 sats    | ~$500              |
| Mature           | 10,000 | 100,000      | 33,300,000 sats   | ~$5,000            |

Assumes 10 signings per agent per day (reasonable for an active AI agent making x402 calls).

**Operating costs:**

| Deployment         | Cost/Month | Break-Even Scale |
|--------------------|------------|------------------|
| Cloudflare Worker  | $5-19      | ~30 agents       |
| Small VPS          | $10-25     | ~50 agents       |
| Dedicated server   | $50-100    | ~200 agents      |

**Margin analysis:**

At 1,000 agents: $500/mo revenue vs. $5-25/mo cost = 95%+ margins.

The economics are compelling even at modest scale, which is critical for bootstrapping a decentralized network.

#### 8.3 Agent Cost Impact

For an agent spending 1,000,000 sats/day on LLM calls (~20 calls at 50K sats each):

| Metric                 | Value              |
|------------------------|--------------------|
| LLM costs/day          | 1,000,000 sats     |
| MPC signing fees/day   | ~20,000 sats       |
| MPC overhead           | 2%                 |
| MPC overhead in USD    | ~$0.10             |

The MPC fee is a rounding error in the agent's operating budget.

### 9. Fee Adjustment Mechanism

Fees are market-driven, not protocol-mandated:

**Node-side:**
- Each node advertises its fee in its CHIP token (BRC-XXX: MPC Overlay Service Discovery).
- Nodes can update their fee by re-registering with a new CHIP token.
- Nodes SHOULD adjust fees based on their operating costs and desired margin.

**Agent-side:**
- Agents discover available nodes and their fees during node selection.
- Agents SHOULD select nodes that provide the best combination of reputation, reliability, and price.
- Agents MAY set a maximum acceptable fee and reject nodes above this threshold.

**Market dynamics:**
- If too few nodes exist, fees will be high (scarcity premium).
- High fees attract new node operators (profit opportunity).
- More nodes increase competition, driving fees toward marginal cost.
- Equilibrium: fees stabilize at a level that covers operating costs plus a reasonable margin.

**Protocol floor and ceiling:**

The protocol enforces:
- Minimum fee: 100 sats (prevents race-to-zero that could destabilize the network).
- Maximum fee: 100,000 sats (prevents accidental or malicious overcharging).

These bounds are protocol parameters that can be adjusted via network-wide consensus (a new BRC version).

### 10. Fee Accounting and Audit

**On-chain audit trail:**

Every MPC fee is fully auditable on-chain:

1. **Fee output.** Visible in the signed transaction (deterministic output index).
2. **Participation proof.** Links the signing session to the fee via `fee_txid` field (BRC-XXX: MPC Participation Proofs).
3. **Settlement transaction.** Links the fee UTXO to individual node payments.

**Audit query flow:**

To audit MPC fees for a specific agent:

```
1. Query participation proofs by agent_identity → list of (session_hash, fee_txid)
2. For each fee_txid, fetch the transaction → extract fee output (amount, locking script)
3. Track fee UTXOs → settlement transactions → individual node payments
4. Verify: sum(node_payments) == sum(fee_outputs) - miner fees
5. Verify: node_payment proportions match participation proof tallies
```

This audit can be performed by anyone -- the agent, a node operator, or a third-party auditor.

**Integration with bsv-worm:**

The MPC fee is recorded in bsv-worm's budget tracker (`onchain/budget.rs`) as a separate line item:

```jsonl
{"ts":1711036800,"service":"mpc-signing","sats":1000,"session":"abc...","nodes":3}
```

The budget detail endpoint (`/budget/detail`) includes MPC fees as a distinct category.

### 11. Edge Cases

**Agent has insufficient funds for fee:**

The proxy returns an error before initiating signing. The agent must fund its wallet or reduce the transaction amount.

**Node goes offline during settlement:**

For Level 2, settlement requires t+1 signatures. If one node is offline but t+1 others are available, settlement proceeds. The offline node's share is included in the settlement transaction (sent to their address).

**Disputed participation count:**

All participation data is on-chain and publicly verifiable. If a node disagrees with the tally, they can independently query the overlay and present their evidence. The on-chain proofs are the source of truth.

**Fee UTXO dust:**

If the fee amount is below the dust threshold (currently 1 satoshi output is valid on BSV), the output is still valid. However, nodes SHOULD set fees above 100 sats to ensure the output is economically spendable.

**Multiple signing operations in one transaction:**

If a transaction requires multiple inputs to be signed (e.g., consolidating UTXOs), a single fee output covers all signings. The participation proof lists all signing sessions.

## Implementation

### Fee Output Injection (Rust)

```rust
pub struct FeeInjector {
    fee_sats: u64,
    fee_script: Script,
}

impl FeeInjector {
    /// Create fee injector for Level 2 (multisig) settlement
    pub fn new_multisig(
        threshold: usize,
        node_pubkeys: &[PublicKey],
        fee_sats: u64,
    ) -> Self {
        let fee_script = Script::multisig(threshold, node_pubkeys);
        Self { fee_sats, fee_script }
    }

    /// Inject fee output into a transaction before signing
    pub fn inject(&self, tx: &mut Transaction) -> Result<(), FeeError> {
        // Verify sufficient inputs
        let total_input: u64 = tx.inputs.iter().map(|i| i.value).sum();
        let total_output: u64 = tx.outputs.iter().map(|o| o.value).sum();
        let miner_fee = estimate_miner_fee(tx);

        if total_input < total_output + miner_fee + self.fee_sats {
            return Err(FeeError::InsufficientFunds {
                needed: total_output + miner_fee + self.fee_sats,
                available: total_input,
            });
        }

        // Reduce change output by fee amount
        let change_idx = find_change_output(tx)?;
        tx.outputs[change_idx].value -= self.fee_sats;

        // Insert fee output before any OP_RETURN outputs
        let insert_idx = tx.outputs.iter()
            .position(|o| o.script.is_op_return())
            .unwrap_or(tx.outputs.len());

        tx.outputs.insert(insert_idx, TxOutput {
            value: self.fee_sats,
            script: self.fee_script.clone(),
        });

        Ok(())
    }
}
```

### Settlement Coordinator (Level 2)

```rust
pub struct SettlementCoordinator {
    session: MpcSession,
    overlay_client: OverlayClient,
}

impl SettlementCoordinator {
    pub async fn settle_epoch(&self, epoch: Epoch) -> Result<Txid, SettlementError> {
        // Step 1: Query participation proofs
        let proofs = self.overlay_client.query_proofs(
            epoch.start, epoch.end
        ).await?;

        // Step 2: Tally participation
        let tally = self.tally_participation(&proofs);

        // Step 3: Collect fee UTXOs
        let fee_utxos = self.collect_fee_utxos(&epoch).await?;
        let total_sats: u64 = fee_utxos.iter().map(|u| u.sats).sum();

        // Step 4: Compute proportional distribution
        let distribution = self.compute_distribution(&tally, total_sats);

        // Step 5: Build settlement transaction
        let unsigned_tx = self.build_settlement_tx(&fee_utxos, &distribution)?;

        // Step 6: Collect threshold signatures from nodes
        let signed_tx = self.collect_signatures(unsigned_tx).await?;

        // Step 7: Broadcast
        let txid = broadcast(signed_tx).await?;

        Ok(txid)
    }

    fn compute_distribution(
        &self,
        tally: &HashMap<IdentityKey, u64>,
        total_sats: u64,
    ) -> Vec<(IdentityKey, u64)> {
        let total_participations: u64 = tally.values().sum();
        tally.iter().map(|(node, count)| {
            let share = (total_sats * count) / total_participations;
            (node.clone(), share)
        }).collect()
    }
}
```

### Integration with bsv-worm

The MPC fee system integrates with bsv-worm through the BRC-100 signing proxy:

1. **Configuration:** `worm.toml` specifies the proxy URL instead of the direct wallet URL.
2. **Budget tracking:** The proxy's fee disclosure is parsed and logged to `budget.jsonl`.
3. **UI display:** The budget panel (`ui/src/pages/budget/budget-panel.ts`) shows MPC fees as a separate cost category.
4. **No code changes:** The agent's `wallet.rs` module talks to the proxy using the same BRC-100 API. Fee injection is transparent.

```toml
# worm.toml
[wallet]
url = "http://localhost:3323"  # MPC proxy, not direct wallet

[mpc]
fee_budget_per_task = 50000    # Max MPC fees per task (sats)
fee_budget_per_day = 500000    # Max MPC fees per day (sats)
```

## References

- BRC-18: OP_RETURN Proofs.
- BRC-21: OP_PUSH_TX / Transaction Introspection.
- BRC-22: SHIP (Simplified Hosting of Internet Peers).
- BRC-24: SLAP (Simplified Lookup and Advertising Protocol).
- BRC-48: PushDrop Tokens.
- BRC-XXX: Threshold ECDSA Signing Protocol for BSV (this series).
- BRC-XXX: MPC Overlay Service Discovery (this series).
- BRC-XXX: MPC Participation Proofs (this series).
