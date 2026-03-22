# MPC Signing Network Analysis

> Full analysis is at `~/bsv/strategy/MPC-SIGNING-NETWORK-ANALYSIS.md`
>
> This file contains a summary. See the source document for complete details.

## Key Findings

- **MPC Library**: cggmp24 (LFDT/Dfns) — pure Rust, MIT, WASM, audited, TSSHOCK-patched
- **Deployment**: CF Workers for Key Share Service ($5/mo, 0ms cold start)
- **Signing**: 7-15ms with presigning, 180ms without (cross-region)
- **Economics**: $50-5,000/mo node revenue at 1K-100K agents; $5-19/mo cost
- **Overlay**: SHIP/SLAP (BRC-22/23/24/25) for node discovery
- **Fees**: sCrypt covenant or multisig self-settlement

## Rejected Alternatives

| Library | Reason |
|---------|--------|
| cb-mpc (Coinbase) | C++, no WASM, needs FFI |
| multi-party-ecdsa (ZenGo) | GPL, abandoned, TSSHOCK won't fix |
| synedrion (entropyxyz) | AGPL, unaudited, company shut down |
| Fireblocks mpc-lib | GPL |
| Fireblocks (managed) | Holds 2/3 shares (backwards trust), $2,400/yr min, 2-6s latency |

## Platform Cost Comparison

| Platform | 10K signs/day | 100K signs/day | 1M signs/day | Cold Start |
|----------|--------------|----------------|--------------|-----------|
| CF Workers | $5.00 | $5.30 | $19.40 | ~0ms |
| AWS Lambda | $0.00 | $0.17 | $4.57 | ~15ms |
| Fly.io | $0-$2 | $2.02 | $2-$7 | 300-500ms |
| Cloud Run | $0.00 | $0.52 | ~$80 | 200-500ms |
| Modal | $0.00 | $0.00 | ~$43 | 1-2s |

CF Workers win on cold start (critical for signing latency) and WASM support.

## Source

Full 1,276-line analysis: `~/bsv/strategy/MPC-SIGNING-NETWORK-ANALYSIS.md`
