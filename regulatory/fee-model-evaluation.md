# MPC Fee Model Evaluation: Regulatory and Economic Analysis

**Date:** March 22, 2026
**Scope:** Evaluate fee model alternatives for MPC node operators
**Decision timeline:** Analysis by Aug 2026, implementation before GA (Oct+ 2026)
**Current model:** Per-transaction (~1,000 sats/signature)
**Related:** [MPC regulatory analysis](./mpc-fee-network-analysis.md), [Compute service position paper](./compute-service-position-paper.md)

---

## 1. The Regulatory Problem with Per-Transaction Fees

The compute service position paper establishes a strong legal foundation: MPC key share holders are not money transmitters under FinCEN's "total independent control" test (FIN-2019-G001, Section 4.2). That analysis is sound. But it addresses the *capability* question -- can the operator unilaterally move funds? The fee model raises a separate question about *economic substance*.

Regulators look at both capability and revenue profile when classifying businesses. An entity that earns revenue proportional to the volume and frequency of financial transactions has a financial-services revenue signature, regardless of the technical mechanism generating that revenue. Per-transaction pricing is the dominant model for payment processors (Stripe: 2.9% + $0.30), money transmitters (Western Union: per-transfer fees), and clearinghouses (ACH: per-transaction).

At current pricing (~1,000 sats/signature, roughly $0.005 at $100/BSV), the revenue per operator is negligible. But the architecture is designed to scale. An operator servicing 1,000 agents making 1,000 transactions/day generates approximately $1.8M/year in per-signature revenue. At that scale, the "we're a compute service" narrative starts to strain under the weight of a revenue model that looks indistinguishable from financial intermediation.

The concern is not that per-transaction pricing is illegal. It is that per-transaction pricing *undermines the strongest legal arguments* in the position paper by creating economic signals that contradict the "compute service" framing. A FinCEN examiner reviewing an operator's financials would see revenue that rises and falls with transaction volume -- the exact pattern they associate with money services businesses.

This matters most at GA, when permissionless operators join the network without vetting. A single operator attracting regulatory scrutiny under an unfavorable fee model could trigger enforcement actions that set precedent for the entire network.

## 2. Fee Model Options

### 2a. Per-Transaction (Current)

**Mechanism:** Proxy injects a fee output of ~1,000 sats into each transaction before MPC signing. The KSS operator receives payment on-chain as part of the signed transaction.

**Revenue projection (per operator, 10 agents, 100 txs/day/agent):**
- 10 agents x 100 txs/day x 1,000 sats x 30 days = 30M sats/month (~$150/month at $100/BSV)

**Regulatory profile:** Financial services. Revenue scales linearly with transaction volume. Indistinguishable from per-transaction processing fees charged by payment processors. The compute-service framing is defensible but weakened.

**Operator incentives:** Well-aligned. Operators earn more when they provide more value (more signatures). Natural market for uptime and reliability -- agents migrate to operators with better availability.

**Pros:** Simple to implement (already built), incentive-aligned, familiar to operators, no billing infrastructure needed.
**Cons:** Worst regulatory profile. Revenue-volume correlation is exactly what MSB analysis looks for. Difficult to defend at scale.

### 2b. Monthly Subscription

**Mechanism:** Agents pay a flat monthly fee per KSS slot (e.g., $5/agent/month). Fee is collected off-chain via payment invoice or on-chain via a monthly recurring transaction. No per-signature fee.

**Revenue projection (per operator, 10 agents):**
- 10 agents x $5/month = $50/month

**Regulatory profile:** SaaS -- the cleanest available. Monthly subscriptions are the standard pricing model for cloud compute, API access, and software services. No per-transaction revenue component means no financial-services revenue signature. A regulator examining the operator's books would see flat recurring revenue, identical to any other infrastructure subscription.

**Operator incentives:** Misaligned. Operators earn the same whether they process 10 signatures or 10,000. No incentive for uptime optimization. High-volume agents subsidize low-volume agents. Operators may oversubscribe capacity.

**Pros:** Cleanest regulatory profile. Clearly a service subscription, not a per-transaction fee. Simplest for operator compliance.
**Cons:** Incentive misalignment. Revenue does not scale with costs (more signatures = more compute but no additional revenue). Requires off-chain billing infrastructure or a subscription smart contract. Lower total revenue at moderate scale.

### 2c. Hybrid (Base + Per-TX)

**Mechanism:** Low monthly base fee (e.g., $2/agent/month) plus a reduced per-signature fee (e.g., 200 sats/sig). The base fee covers infrastructure costs; the per-signature component compensates for incremental compute.

**Revenue projection (per operator, 10 agents, 100 txs/day/agent):**
- Base: 10 agents x $2/month = $20/month
- Per-sig: 10 agents x 100 txs/day x 200 sats x 30 days = 6M sats/month (~$30/month)
- Total: ~$50/month

**Regulatory profile:** Mixed. The base fee component looks like SaaS. The per-transaction component still creates transaction-volume-correlated revenue, but at a much lower rate (~$0.001/sig instead of ~$0.005/sig). Whether this is sufficiently distinct from a financial-services profile depends on the ratio. If the base fee is 60%+ of total revenue, the SaaS characterization is more defensible.

**Operator incentives:** Partially aligned. The per-sig component rewards uptime and volume. The base fee provides revenue floor during low-activity periods.

**Pros:** Balances regulatory defensibility with operator incentives. Covers fixed costs (base) and variable costs (per-sig). More revenue than pure subscription at moderate volume.
**Cons:** More complex to implement. Regulatory profile is ambiguous -- neither cleanly SaaS nor cleanly financial services. Requires both subscription billing and fee injection.

### 2d. Tiered / Freemium

**Mechanism:** Free tier with a limited number of signatures per month (e.g., 100 sigs/month). Paid tiers at fixed monthly prices with higher or unlimited signature allowances (e.g., $5/month for 5,000 sigs, $20/month for unlimited).

**Revenue projection (per operator, 10 agents, mix of tiers):**
- 3 free-tier agents + 5 agents at $5/month + 2 agents at $20/month = $65/month

**Regulatory profile:** SaaS -- clean. Revenue is subscription-based with usage tiers, identical to how AWS, Twilio, or any metered API prices. The free tier strengthens the "developer tooling" narrative. The structure is unmistakably a software service, not a financial intermediary.

**Operator incentives:** Moderate alignment. Operators benefit from upgrading agents to higher tiers. Overage charges (if any) create some per-transaction correlation. Free tier creates onboarding funnel but also freeloading risk.

**Pros:** Clean regulatory profile. Familiar SaaS pricing. Free tier lowers barrier to entry. Operator can differentiate on tier features (SLA, throughput, priority signing).
**Cons:** Complex billing. Free-tier abuse potential. Requires usage tracking and enforcement. More engineering than flat subscription.

### 2e. Stake-Based

**Mechanism:** Operators stake BSV to join the network. Signing fees are distributed proportionally to stake. Higher stake = more signing requests routed to operator = more revenue. Unstaking has a cooldown period.

**Revenue projection:** Highly variable. Depends on total network volume, operator's stake fraction, and staking rewards curve.

**Regulatory profile:** Most complex. Staking mechanisms have attracted regulatory attention in the context of proof-of-stake networks. The SEC has taken enforcement action against staking-as-a-service providers (Kraken, 2023). While MPC staking differs from PoS consensus staking, the optics are problematic. A regulator might characterize staked BSV as an investment contract (Howey test) or the staking mechanism as a securities offering.

**Operator incentives:** Strongly aligned with network security -- operators have skin in the game. Discourages malicious behavior (stake slashing). However, creates a capital barrier to entry that conflicts with the permissionless network goal.

**Pros:** Strong security incentives. Sybil resistance. Aligns operator interests with network health.
**Cons:** Worst regulatory complexity (potential securities implications, staking enforcement precedent). Capital barrier contradicts permissionless design. Most complex to implement. Introduces DeFi-adjacent mechanics that could attract additional scrutiny.

## 3. Comparison Matrix

| Model | Revenue Profile | Regulatory Classification | Operator Incentive | Implementation Complexity | Best For Phase |
|-------|----------------|--------------------------|-------------------|--------------------------|---------------|
| Per-Transaction | Financial services | MSB risk at scale | Strongly aligned | Low (built) | Alpha, Beta |
| Subscription | SaaS | Clean | Misaligned | Medium | GA |
| Hybrid | Mixed | Ambiguous | Partially aligned | High | GA (if sub insufficient) |
| Tiered | SaaS | Clean | Moderate | High | GA |
| Stake-Based | DeFi/validator | Most complex | Strong (security) | Very high | Not recommended |

## 4. Regulatory Analysis by Model

### Financial Services vs. SaaS: Why the Distinction Matters

The distinction between a financial-services and a SaaS revenue profile has concrete regulatory consequences:

**FinCEN MSB registration.** An entity qualifies as a money services business if it engages in money transmission exceeding $1,000/day in aggregate. Per-transaction revenue that scales with payment volume strengthens the argument that the entity is facilitating financial transactions for profit. Flat subscription revenue does not.

**State Money Transmitter Licenses (MTLs).** At least 48 states and territories require MTLs for money transmission. Application costs range from $5,000 to $500,000+, with ongoing compliance costs (audits, bonding, reporting). A per-transaction revenue model is a red flag in MTL applications because it demonstrates that the applicant's business is economically dependent on facilitating transactions.

**SaaS subscriptions are categorically excluded.** No state or federal regulator has classified a subscription-based software service as money transmission. The business model is fundamentally different: you pay for access to a service, not per-transaction facilitation. AWS charges monthly for compute capacity regardless of whether that compute processes financial transactions. The same logic applies to a KSS subscription.

### Which Model Best Supports the "Compute Service" Narrative?

The position paper argues that KSS operators provide "elliptic curve computation, not money movement." The fee model should reinforce this narrative, not undermine it.

**Subscription** is the strongest match. Cloud compute is priced by subscription (reserved instances), by time (per-hour), or by capacity (per-vCPU-month). It is not priced per-financial-transaction-processed. A subscription-based KSS is indistinguishable from any other compute API subscription.

**Per-transaction** is the weakest match. Charging per signature, where each signature enables a financial transaction, creates a direct economic link between operator revenue and payment facilitation. This is precisely the revenue pattern the position paper argues operators should not have.

**Hybrid** occupies a middle ground. If the subscription base represents the majority of revenue (60%+), the per-transaction component can be characterized as a metered compute surcharge (similar to AWS data transfer fees on top of instance pricing). If the per-transaction component dominates, the subscription becomes a fig leaf.

## 5. Economic Modeling

Revenue projections for a single operator at three scale points (assuming $100/BSV, 100 txs/day/agent):

| Model | 10 Agents | 100 Agents | 1,000 Agents |
|-------|-----------|------------|--------------|
| Per-TX (1,000 sats/sig) | $150/mo | $1,500/mo | $15,000/mo |
| Subscription ($5/agent/mo) | $50/mo | $500/mo | $5,000/mo |
| Hybrid ($2 + 200 sats/sig) | $50/mo | $500/mo | $5,000/mo |
| Tiered (avg $4/agent/mo) | $40/mo | $400/mo | $4,000/mo |

**Operator cost estimates:** A KSS node requires a cloud VM ($20-50/month), bandwidth (~$5-10/month), and monitoring/maintenance time. Break-even under subscription at $5/agent requires approximately 6-10 agents. Under per-transaction at current rates, break-even requires approximately 4-6 agents.

**Key observation:** Subscription generates roughly one-third the revenue of per-transaction at equivalent scale. This is a real trade-off. Operators will earn less under subscription, which could reduce supply of KSS operators and slow network growth. However, the regulatory cost of per-transaction pricing at GA scale (potential MSB registration, state licensing, compliance overhead) could easily exceed the revenue difference. An operator earning $15,000/month in per-transaction fees but facing $50,000+ in annual compliance costs is worse off than one earning $5,000/month with no compliance burden.

**Pricing flexibility:** $5/agent/month is illustrative. Operators in a permissionless network will compete on price. Market dynamics may push subscription prices higher or lower. The important thing is the *structure* (flat recurring) not the specific price point.

## 6. Phase-Appropriate Recommendations

**Alpha (single operator, Apr-Jun 2026):** Per-transaction is fine. John operates both shares on his own infrastructure. The fee system is internal accounting between his own services. No MSB concern, no independent operator classification question. Changing the fee model now would add unnecessary engineering work.

**Beta (2-3 known operators, Jul-Sep 2026):** Per-transaction remains acceptable. Known operators can sign operator agreements that include compliance representations. The small number of vetted operators limits regulatory surface area. This is also the period to implement and test the subscription billing infrastructure, so it is ready for GA.

**GA (permissionless network, Oct+ 2026):** Switch to subscription or tiered model. At GA, unknown operators join without vetting. Per-transaction fees at scale create MSB classification risk for every operator in the network. A subscription model ensures that the "compute service" framing in the position paper is supported -- not contradicted -- by the economic reality.

## 7. Recommendation

**Primary recommendation:** Implement monthly subscription billing for GA. Per-transaction pricing is acceptable through Beta.

**Rationale:**

1. **Regulatory alignment.** Subscription cleanly positions KSS operators as SaaS infrastructure providers. It eliminates the revenue-volume correlation that is the single weakest point in the compute-service legal argument.

2. **Operator compliance simplification.** Operators under a subscription model have a straightforward answer to "what does your business do?" -- they sell compute subscriptions. No explanation of per-transaction fee mechanics, no MSB analysis, no MTL inquiry.

3. **Revenue decoupling.** Subscription decouples operator revenue from transaction volume. An operator processing 10 transactions or 10,000 earns the same amount. This is how compute services work.

4. **Position paper consistency.** The position paper argues operators provide "cryptographic computation, not money movement." The fee model should look like computation pricing (subscription/capacity), not money-movement pricing (per-transaction).

**Secondary recommendation:** If subscription creates unacceptable incentive misalignment (operators neglecting uptime because revenue is flat), a hybrid model with a dominant subscription base and a small per-signature surcharge (e.g., 100-200 sats) is acceptable. The subscription component must represent the majority of expected operator revenue (60%+) for the SaaS characterization to hold.

**Not recommended:** Stake-based pricing introduces securities-law complexity that is disproportionate to any benefit. The MPC network is not a blockchain consensus mechanism and should not import staking mechanics from that domain.

## 8. Implementation Notes

The fee model change affects the following components:

**Proxy fee injection (bsv-mpc-proxy).** Currently injects a fixed per-transaction fee output. Under subscription, the proxy would not inject fee outputs at all (or would inject a negligible "dust" output for protocol continuity). Under hybrid, the per-sig amount would decrease from ~1,000 to ~200 sats.

**Subscription management.** New infrastructure needed: subscription creation, renewal, expiration, and enforcement. Options include (a) on-chain subscription tokens (BRC-48 style, time-locked UTXOs), (b) off-chain billing with payment invoices, or (c) prepaid credit balances. On-chain tokens are most consistent with the existing architecture but add complexity.

**KSS authentication.** The KSS currently signs for any properly authenticated MPC session. Under subscription, the KSS must verify that the requesting agent has an active subscription before participating in signing. This requires a subscription registry or token verification step in the MPC handshake.

**Operator discovery.** Operators in the permissionless network (SHIP/SLAP) will need to advertise their pricing model. The service manifest (currently fee-per-sig) needs to support subscription pricing metadata.

**Migration path.** Alpha and Beta operators continue with per-transaction. Subscription infrastructure is built and tested during Beta. At GA launch, new operators default to subscription. Existing operators have a 90-day migration window.

**Note:** This analysis concerns the fee *model* for the open network. It does not propose changing Alpha or Beta behavior. The current per-transaction mechanism remains in place until GA implementation begins.

---

## Appendix: Revenue Projections

Assumes $100/BSV, 100 transactions/day/agent, 30-day month.

### Per-Transaction (1,000 sats/sig)

| Agents | Sigs/Month | Revenue (sats) | Revenue (USD) |
|--------|-----------|----------------|---------------|
| 10 | 30,000 | 30,000,000 | $150 |
| 100 | 300,000 | 300,000,000 | $1,500 |
| 1,000 | 3,000,000 | 3,000,000,000 | $15,000 |

### Subscription ($5/agent/month)

| Agents | Revenue (USD) | vs. Per-TX |
|--------|---------------|------------|
| 10 | $50 | 33% |
| 100 | $500 | 33% |
| 1,000 | $5,000 | 33% |

### Hybrid ($2/month + 200 sats/sig)

| Agents | Base (USD) | Per-Sig (USD) | Total (USD) | vs. Per-TX |
|--------|-----------|---------------|-------------|------------|
| 10 | $20 | $30 | $50 | 33% |
| 100 | $200 | $300 | $500 | 33% |
| 1,000 | $2,000 | $3,000 | $5,000 | 33% |

### Tiered (Free: 100 sigs, $5: 5K sigs, $20: unlimited)

| Agents | Free | $5 Tier | $20 Tier | Revenue (USD) |
|--------|------|---------|----------|---------------|
| 10 | 3 | 5 | 2 | $65 |
| 100 | 20 | 60 | 20 | $700 |
| 1,000 | 100 | 600 | 300 | $9,000 |

### Break-Even Analysis (operator costs ~$50/month)

| Model | Agents to Break Even |
|-------|---------------------|
| Per-TX (1,000 sats/sig) | ~4 |
| Subscription ($5/agent) | ~10 |
| Hybrid ($2 + 200 sats) | ~10 |
| Tiered (avg ~$4.50) | ~12 |

The higher break-even point under subscription is a real trade-off. It means fewer operators will be profitable at small scale, which could slow initial network growth. This is offset by the elimination of compliance costs that per-transaction operators at meaningful scale would face.
