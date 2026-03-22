# Position Paper: MPC Node Operators as Compute Service Providers

**Prepared by:** LobsterFarm
**Date:** March 22, 2026
**Purpose:** For counsel reference and regulator conversations
**Related:** "Integral Part" position paper (bsv-worm regulatory milestone)

---

## Executive Summary

Operators of Multi-Party Computation (MPC) key share services provide a cryptographic computation service: partial ECDSA signature generation via elliptic curve arithmetic. A key share holder in a 2-of-2 threshold signing scheme cannot independently access, move, or control digital assets. Under FinCEN's "total independent control" test (FIN-2019-G001, Section 4.2, pp.15-16), MPC node operators are not money transmitters.

## 1. What MPC Operators Do

The bsv-mpc system uses a 2-of-2 threshold signing protocol (CGGMP24). Two parties each hold one *share* of a private key:

- The **MPC Signing Proxy** holds one share and runs in the user's own container.
- The **Key Share Service (KSS)** holds the other share and runs as a remote service.

When a transaction requires signing, both parties participate in a multi-round cryptographic protocol to produce a valid ECDSA signature. The complete private key is never reconstructed -- not in memory, not on disk, not in transit. Each share is a partial mathematical input to an elliptic curve computation. A single share alone cannot produce a signature, derive the full private key, or move funds.

The KSS earns approximately 1,000 satoshis per signature (roughly 2% of the average x402 payment). This fee compensates for CPU cycles consumed during the MPC protocol rounds -- specifically, modular exponentiation, Paillier encryption, zero-knowledge proof generation, and partial signature assembly. The entire codebase is MIT-licensed and fully auditable.

## 2. The "Total Independent Control" Test

FinCEN's 2019 guidance establishes a four-factor framework for classifying intermediaries (FIN-2019-G001, Section 4.2, pp.15-16):

> "The regulatory treatment of such intermediaries depends on four criteria: (a) who owns the value; (b) where the value is stored; (c) whether the owner interacts directly with the payment system where the CVC runs; and, (d) whether the person acting as intermediary has total independent control over the value."

Applied to a KSS operator:

| Factor | Analysis |
|--------|----------|
| **(a) Ownership** | The agent (user) owns the value. The KSS operator has no claim to or interest in the funds. |
| **(b) Storage** | Value is stored on-chain in UTXOs controlled by the threshold key. No single party stores or custodies value. |
| **(c) Direct interaction** | The agent interacts with the BSV payment system directly through its proxy. The KSS does not interact with the blockchain on the agent's behalf. |
| **(d) Total independent control** | The KSS definitively does not have total independent control. Its key share alone cannot sign any transaction, cannot move any funds, and cannot access any value. This is provable and auditable from the source code. |

Factor (d) is dispositive. A 2-of-2 key share holder fails the total independent control test by mathematical necessity.

## 3. MPC vs. Multi-Signature: Why the Safe Harbor Applies

FinCEN directly addresses multi-signature wallets (FIN-2019-G001, Section 4.2.2, pp.16-17):

> "If the multiple-signature wallet provider restricts its role to creating un-hosted wallets that require adding a second authorization key to the wallet owner's private key in order to validate and complete transactions, the provider is not a money transmitter because it does not accept and transmit value."

The critical finding:

> "(c) the person participating in the transaction to provide additional validation at the request of the owner does not have total independent control over the value."

MPC threshold signing is the mathematical evolution of multi-signature. In traditional multi-sig, each party holds an independent private key and produces an independent signature; the protocol requires *n* of *m* signatures. In MPC threshold signing, each party holds a *share* of a single key and contributes a *partial* computation; the protocol produces a single valid signature. The security model is identical: no single party can authorize a transaction unilaterally. The regulatory principle -- that a party providing additional validation without total independent control is not a money transmitter -- applies with equal force.

If anything, MPC provides a stronger case than multi-sig: in multi-sig, each party holds a complete private key capable of producing a valid signature for their portion. In MPC, each party holds a value that is cryptographically meaningless in isolation.

## 4. The Service: Cryptographic Computation, Not Money Movement

Five independent arguments support classifying KSS operation as a compute service:

1. **Mathematical inertness.** A single key share cannot sign a transaction, derive the full private key, or move funds. This is not a policy assertion but a mathematical fact, verifiable from the open-source protocol implementation.

2. **Service definition.** The KSS performs partial ECDSA signature generation -- modular arithmetic on elliptic curve points. This is computation, not fund transfer.

3. **Analogical reasoning.** The KSS is analogous to: a notary who witnesses but does not execute a transaction; a cloud provider billing for CPU cycles consumed during a financial computation; a co-signer on a safe deposit box who holds one of two required keys.

4. **Fee characterization.** The approximately 1,000 satoshis per signature compensates for compute resources (CPU, memory, network bandwidth for MPC protocol rounds), not for financial intermediation. The fee is fixed regardless of the transaction amount -- a hallmark of compute pricing, not financial services pricing.

5. **Auditability.** The MIT-licensed source code is publicly verifiable. There is no hidden logic that could grant the KSS operator additional capabilities beyond partial signature generation.

## 5. The Infrastructure Provider Exemption

31 CFR 1010.100(ff)(5)(ii)(A) exempts providers of "the delivery, communication, or network access services used by a money transmitter to support money transmission services."

FinCEN elaborates (FIN-2019-G001, Section 4.5.1(b), p.20):

> "Suppliers of tools (communications, hardware, or software) that may be utilized in money transmission, like anonymizing software, are engaged in trade and not money transmission."

MPC signing is infrastructure that enables secure transaction authorization. The KSS provides a cryptographic computation service consumed by the agent's signing process. It does not itself accept value from one party and transmit it to another. The fee is for the computation, not for the movement of funds.

This exemption is further reinforced by FIN-2014-R002, which held that "the production and distribution of software, in and of itself, does not constitute acceptance and transmission of value, even if the purpose of the software is to facilitate the sale of virtual currency."

## 6. Scale Considerations

At scale -- a permissionless network of independent operators each earning substantial revenue from per-signature fees -- the regulatory character of the activity could receive closer scrutiny. A regulator might argue that the aggregate effect of the network is to facilitate money movement for profit.

However, the cryptographic analysis does not change with scale. A key share cannot become "total independent control" regardless of how many signatures the operator processes or how much revenue the operator earns. FinCEN's four-factor test is capability-based, not revenue-based. The question is whether the intermediary *can* unilaterally control the value, not how much the intermediary earns.

That said, prudent operators should monitor FinCEN guidance and consult counsel before operating at significant scale, as no MPC-specific ruling exists.

## 7. The MTMA "Prevent Indefinitely" Concern

The CSBS Money Transmission Modernization Act (adopted in approximately 31 states) defines "control" more broadly than FinCEN: **"the power to execute unilaterally, or prevent indefinitely, a virtual currency transaction."**

Under this definition, a 2-of-2 key share holder can refuse to sign, effectively vetoing any transaction. This "prevent indefinitely" capability could bring MPC operators within scope of state money transmission laws, even where FinCEN's federal test would exclude them.

Two mitigations address this concern:

**(a) Threshold upgrade to 2-of-3 or higher.** In a 2-of-3 threshold scheme, no single operator can prevent a transaction -- the remaining two shares can complete the signature without the refusing party. This eliminates the veto power that triggers the MTMA definition.

**(b) User key migration.** The proxy runs in the user's own container. The user can always generate a new key pair, migrate funds to the new key, and select a different KSS operator. The veto power is therefore temporary, not indefinite.

It bears noting that no state or federal regulator has issued MPC-specific guidance, and the application of the MTMA "prevent indefinitely" prong to threshold cryptography has not been tested.

## 8. Conclusion

MPC key share operators satisfy all three applicable regulatory frameworks:

- **Total independent control test (FinCEN):** A key share cannot unilaterally access, move, or control value. Factor (d) of the four-factor test is not met.
- **Multi-signature safe harbor principle (FinCEN):** The operator "participat[es] in the transaction to provide additional validation at the request of the owner" and "does not have total independent control over the value." MPC is the mathematical successor to multi-sig; the regulatory principle applies.
- **Infrastructure provider exemption (31 CFR 1010.100(ff)(5)(ii)(A)):** The operator provides cryptographic computation consumed by a signing process. It is a supplier of tools, engaged in trade, not money transmission.

The service is elliptic curve arithmetic. The fee is for compute. The code is open-source and auditable. As the network scales beyond 2-of-2 to 2-of-3 or higher thresholds, even the theoretical "prevent indefinitely" concern under state MTMA definitions is eliminated.

This paper should be reviewed by counsel and updated as FinCEN or state regulators issue MPC-specific guidance.

---

## Appendix: Citable References

| Reference | Topic | Application |
|-----------|-------|-------------|
| FIN-2019-G001, Section 4.2, pp.15-16 | Four-factor test, "total independent control" | Key share holder fails factor (d) |
| FIN-2019-G001, Section 4.2.2, pp.16-17 | Multi-signature wallet safe harbor | Closest analog to MPC threshold signing |
| FIN-2019-G001, Section 4.5.1(b), p.20 | Software/tools provider exemption | "Suppliers of tools... are engaged in trade and not money transmission" |
| 31 CFR 1010.100(ff)(5)(ii)(A) | Statutory infrastructure provider exclusion | Delivery, communication, or network access services |
| FIN-2014-R002 | Software production not money transmission | "Production and distribution of software... does not constitute acceptance and transmission of value" |
| CSBS MTMA, Art. XIII | State-level "control" definition | "Power to execute unilaterally, or prevent indefinitely" |
| FIN-2019-G001, Section 4.2.1, pp.15-16 | Hosted vs. unhosted wallet distinction | KSS does not custody funds |
