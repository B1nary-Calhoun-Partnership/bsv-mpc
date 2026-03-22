# MPC Fee Network: Regulatory Analysis

**Date:** 2026-03-22
**Status:** Draft — needs integration with bsv-worm full-stack assessment
**Related:** [bsv-worm regulatory assessment](https://github.com/Calgooon/rust-bsv-worm/tree/main/regulatory/assessment.md)

---

## 1. Architecture (Regulatory Lens)

The MPC signing network has a unique structure that doesn't map cleanly to existing regulatory categories:

| Component | Role | Revenue |
|-----------|------|---------|
| **bsv-mpc-proxy** | BRC-100 compatible signing proxy at localhost:3322. Intercepts wallet API calls, coordinates MPC protocol, injects fee outputs. | None (open-source, runs in user's container) |
| **Key Share Service (KSS)** | Holds one share of the agent's signing key. Participates in threshold signing protocol. | Earns ~1,000 sats per signature (~2% of avg x402 payment) |
| **Agent (bsv-worm)** | Signs transactions via the proxy. Unaware that MPC is happening. | Pays fees implicitly (included in transaction) |

### Fee Flow

```
Agent requests createAction() via proxy
  -> Proxy builds transaction + injects fee output (1,000 sats to KSS operator)
  -> Proxy initiates 2-of-2 MPC signing with KSS
  -> Both parties contribute partial signatures
  -> Complete ECDSA signature assembled
  -> Transaction broadcast includes fee payment to KSS
```

The agent signs the complete transaction (including the fee output) — it consents to the total transaction. But the fee output was added by the proxy, not requested by the agent.

## 2. Are MPC Node Operators Money Services Businesses?

### Arguments That They Are NOT MSBs

1. **No custody of user funds.** KSS holds a key share, not funds. The share alone cannot sign anything — it's mathematically useless without the other share(s). This is analogous to holding one half of a torn check.

2. **Signing service, not transmission.** The KSS provides a cryptographic computation (partial ECDSA signature), not a money movement service. The analogy is a notary who witnesses a signature — the notary doesn't transmit funds.

3. **FinCEN's "Total Independent Control" test.** A party is a money transmitter only if it has "total independent control" over user funds at some point. With 2-of-2 MPC, the KSS never has total independent control — it literally cannot move funds unilaterally.

4. **The fee is for compute, not for transmission.** KSS operators are paid for performing elliptic curve computation (MPC protocol rounds), not for moving money. Similar to how a cloud provider charges for CPU time used during a financial transaction.

5. **Infrastructure provider exemption.** FinCEN's FIN-2019-G001 exempts providers of "the delivery, communication, or network access services used by a money transmitter to support money transmission services." MPC node operators provide signing infrastructure.

### Arguments That They COULD Be MSBs

1. **Per-transaction revenue model.** Earning fees proportional to transaction volume looks like a financial services revenue model, not a software services model.

2. **Essential for transaction completion.** Without the KSS's cooperation, no transaction can be signed. The KSS is not optional infrastructure — it's a required counterparty to every payment.

3. **Substance over form.** A regulator could argue that regardless of the cryptographic mechanism, the KSS is functionally enabling money movement and profiting from it per-transaction.

4. **Scale changes character.** One developer running both shares is clearly not an MSB. A network of independent operators each earning $50K+/year from facilitating financial transactions starts to look different.

### Assessment

**For alpha (single operator, both shares):** Almost certainly NOT an MSB. Single operator running both shares on their own infrastructure. The fee system is internal accounting.

**For beta (independent operators, 2-of-3):** Ambiguous. Independent parties earning per-transaction revenue for cryptographic participation in financial transactions. **Needs counsel opinion.** The strongest defense is the "no total independent control" + "compute service" framing, but this is novel territory.

**For GA (permissionless network):** Most risk. Open network of operators earning fees is structurally similar to mining pools or validator networks. Regulatory treatment of these varies by jurisdiction and is evolving.

## 3. Fee Injection: Who Is the "Transmitter"?

The proxy adds fee outputs to transactions before the agent signs them. This creates an interesting question:

| Party | Adds the fee? | Signs the tx? | Receives the fee? |
|-------|--------------|---------------|-------------------|
| Agent (bsv-worm) | No (proxy adds it) | Yes (MPC signing) | No |
| Proxy (bsv-mpc-proxy) | Yes (injects output) | Yes (MPC signing) | No (passes to KSS) |
| KSS operator | No | Yes (MPC signing) | Yes |

The agent signs the complete transaction including the fee output, so it technically consents. The proxy is open-source code running in the agent's container — it's the agent's own software, not a third party. The KSS receives payment for a service (signing computation).

**Most defensible framing:** The fee is a service charge for cryptographic computation, embedded in the transaction by the agent's own software (proxy), paid to the service provider (KSS). No different from a cloud API that charges per-request.

**Risk:** If a regulator views the proxy as a third party that unilaterally diverts funds from the agent's transaction to a separate payee, it could be characterized as unauthorized fund diversion.

**Mitigation:** Make the fee visible and configurable. The proxy should:
- Log the fee amount in every transaction
- Allow agents to query fee rates before signing
- Allow operators to set maximum acceptable fee caps
- Include fee disclosure in the MPC protocol handshake

## 4. Independent Operator Transition Timeline

| Phase | Operators | Threshold | Fee Settlement | Regulatory Profile |
|-------|-----------|-----------|---------------|-------------------|
| **Alpha** (Apr-Jun 2026) | Single operator (John), 2 CF accounts | 2-of-2 | Level 1 (trusted) | **Clean** — internal operation |
| **Beta** (Jul-Sep 2026) | 2-3 known operators | 2-of-3 | Level 2 (multisig) | **Amber** — independent parties earning fees |
| **GA** (Oct+ 2026) | Permissionless via SHIP/SLAP | 3-of-5+ | Level 2-3 | **Needs counsel** — open network |

The transition from Alpha to Beta is the regulatory inflection point. Before onboarding independent operators, the following should be resolved:

1. Whether KSS operators need MSB registration (federal + key states)
2. Whether KSS operators need KYC/AML procedures
3. Whether the fee model needs restructuring (e.g., subscription instead of per-tx)
4. Whether operator agreements need regulatory compliance clauses

## 5. Jurisdictional Considerations

| Jurisdiction | Key Question | Notes |
|-------------|-------------|-------|
| **US (Federal/FinCEN)** | Does "total independent control" test definitively exclude MPC share holders? | Likely yes, but no ruling on MPC specifically |
| **US (State)** | Do state MTL regimes treat MPC operators differently? | NY, CA most restrictive. WY most favorable (DAO LLC framework). |
| **EU** | MiCA treatment of MPC infrastructure providers? | MiCA focuses on CASPs (crypto-asset service providers). MPC infra likely exempt. |
| **Hong Kong** | MSO Ordinance — does signing computation qualify as money service? | Likely no — no remittance, no money changing. |

## 6. Recommendations

### Before Beta Launch (Jul 2026)

1. **Get counsel opinion on KSS operator classification** — specifically: "Is a party that holds one share of a 2-of-3 MPC key and earns per-signature fees an MSB under FinCEN rules?" This can be bundled with the bsv-worm agent-to-agent counsel memo.

2. **Make fees transparent and configurable** — agent must be able to see and cap fees. Removes "unauthorized diversion" risk.

3. **Document the "compute service" framing** — position paper: MPC operators provide elliptic curve computation, not money movement.

### Before GA Launch (Oct+ 2026)

4. **Operator compliance requirements** — what (if anything) independent operators need to do before joining the network.

5. **Fee model alternatives** — evaluate subscription-based pricing (monthly flat fee per agent) vs per-tx fees. Subscription model has cleaner regulatory profile (SaaS, not financial services).

6. **Regulatory monitoring** — FinCEN has not ruled on MPC specifically. Watch for guidance.
