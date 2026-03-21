# bsv-mpc

Decentralized MPC threshold signing for BSV. The agent's private key never exists.

## What is this?

A Rust library and service for threshold ECDSA signing on BSV's secp256k1 curve. Two or more parties each hold one share of a signing key. Valid signatures require t+1 parties to cooperate. Neither party alone can produce a signature or reconstruct the key.

Built for autonomous AI agents (like [bsv-worm](https://github.com/anthropics/bsv-worm)) that hold BSV wallets and make x402 micropayments for AI inference.

## Architecture

```
Agent                          MPC Signing Proxy              Key Share Service
(bsv-worm)                    (localhost:3322)               (CF Worker / self-hosted)

Calls BRC-100        <->       Translates to MPC      <2PC>   Holds share_A
wallet API                    protocol. Holds share_B.        (~15ms signing)
(unchanged)                   Injects fee output.
```

Five crates:

| Crate | Description |
|-------|-------------|
| `bsv-mpc-core` | Core MPC protocol wrapping cggmp24 (CGGMP'24 threshold ECDSA) |
| `bsv-mpc-proxy` | BRC-100 signing proxy — drop-in replacement for bsv-wallet-cli |
| `bsv-mpc-worker` | Cloudflare Worker Key Share Service (Rust -> WASM) |
| `bsv-mpc-service` | Standalone Key Share Service binary (self-hosted) |
| `bsv-mpc-overlay` | BSV overlay network integration (SHIP/SLAP node discovery) |

## Quick Start

```bash
# Build
cargo build

# Start signing proxy (connects to Key Share Service)
MPC_KSS_URL=https://kss.example.com cargo run -p bsv-mpc-proxy

# Start standalone Key Share Service
cargo run -p bsv-mpc-service -- --port 4322

# Build WASM for Cloudflare Worker
cargo build -p bsv-mpc-worker --target wasm32-unknown-unknown
```

## Performance

| Operation | Latency |
|-----------|---------|
| ECDSA signing (with presignature) | **~7-15ms** |
| ECDSA signing (without presignature) | ~28-180ms |
| Key generation (DKG) | ~230ms |
| Agent overhead on 10s LLM call | **0.1%** |

## Economics

Every MPC-signed transaction includes a small fee output (~1,000 sats, ~2% of average x402 payment). Fees are distributed to MPC node operators proportionally based on participation.

| Scale | Node Revenue | Node Cost (CF Worker) | Margin |
|-------|-------------|----------------------|--------|
| 1,000 agents | $50/mo | $5/mo | 90% |
| 10,000 agents | $500/mo | $5/mo | 99% |

## BRC Standards

This project proposes four new BSV Request for Comments:

- **Threshold ECDSA Signing Protocol for BSV** — MPC signing protocol
- **MPC Overlay Service Discovery** — Node advertisement via SHIP/SLAP
- **MPC Participation Proofs** — On-chain proof of signing participation
- **MPC Fee Distribution** — Fee collection and proportional settlement

See `brc-drafts/` for full specifications.

## Why?

> "Not even we can sign your transactions."

AI agents need wallets. Wallets need signing keys. If the platform holds the key, the platform can steal the funds. MPC threshold signing means the key never exists — it's split into shares held by independent parties. The agent signs transactions through a cryptographic protocol where no party ever sees the complete key.

## License

MIT OR Apache-2.0
