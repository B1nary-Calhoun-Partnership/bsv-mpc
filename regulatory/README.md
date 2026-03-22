# Regulatory & Licensing — bsv-mpc

MPC-specific regulatory analysis for the threshold signing network.

## Documents

| File | Scope | Status |
|------|-------|--------|
| [mpc-fee-network-analysis.md](mpc-fee-network-analysis.md) | Are MPC node operators MSBs? Fee injection character. Operator transition timeline. | Draft |
| [action-items.md](action-items.md) | MPC-specific regulatory work items. | Living document |
| [compute-service-position-paper.md](compute-service-position-paper.md) | Position paper: MPC operators as compute service providers, not MSBs. FinCEN total independent control analysis. | Complete |
| [fee-model-evaluation.md](fee-model-evaluation.md) | Per-tx vs subscription vs hybrid fee model evaluation. Regulatory and economic trade-offs. | Complete |

## The Core Question

MPC node operators earn per-signature fees (~1,000 sats/tx) for facilitating BSV transactions. At scale, this is meaningful revenue ($50K+/year/node). Three open questions:

1. **Are node operators Money Services Businesses?** They receive compensation for facilitating financial transactions.
2. **Who is the "transmitter" when the proxy injects fee outputs?** The agent signs the transaction but didn't request the fee. The proxy added it silently.
3. **When does the independent operator transition change the regulatory profile?** Alpha (single operator, both shares) vs Beta (independent operators, 2-of-3).

## Cross-Repo

See also: [bsv-worm/regulatory/](https://github.com/Calgooon/rust-bsv-worm/tree/main/regulatory) for the full-stack regulatory assessment covering sovereign mode, hosted/JIT, and agent-to-agent flows.

## GitHub Tracking

- **Milestone:** "Regulatory & Licensing" in this repo
- **Label:** `regulatory`
