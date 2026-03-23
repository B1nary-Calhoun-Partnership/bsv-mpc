# bsv-mpc Threshold Configuration Roadmap

> Migration path from 2-of-2 (Alpha) to 2-of-3 (Beta) to 3-of-5 (GA).
> All performance numbers from validated POC measurements.
> Key refresh enables threshold upgrades with zero on-chain cost.

---

## 1. Current State: 2-of-2 (Alpha)

The simplest threshold configuration: two parties, both required to sign.

### Participants

| Party | Role | Share Location | Infrastructure |
|-------|------|---------------|----------------|
| **Proxy (share_B)** | MPC Signing Proxy at localhost:3322. Initiates all protocol sessions. Holds the agent's encrypted share on local disk (`share.enc`). | Agent container | Same container as bsv-worm |
| **KSS (share_A)** | Key Share Service. Participates in MPC protocols when requested by the proxy. Holds the other encrypted share. | Remote service | Separate infrastructure |

### Properties

| Property | Value |
|----------|-------|
| Threshold | t=1 (both parties required, since signing needs t+1=2) |
| Fault tolerance | **None.** If either party is unavailable, no signatures can be produced. |
| Compromise tolerance | **None.** If both shares are obtained, the full private key is reconstructable. |
| DKG time | ~80ms native (POC 1), ~4ms WASM (POC 2), plus ~30s one-time aux info generation per party |
| Signing (presigned) | ~359us localhost (POC 5), ~16ms over HTTPS (POC 10) |
| Signing (4-round) | ~1.23s localhost (POC 5), ~33ms estimated over HTTPS (POC 10) |
| Protocol rounds (signing) | 4 without presignature, 1 with presignature |
| Protocol rounds (presigning) | 3 |
| WASM module size | 636KB core (POC 2), 1069KB with CF Worker runtime (POC 10) |
| WASM memory | 79.5MB RSS of 128MB limit (POC 2) |

### Rationale for Alpha

2-of-2 is the right starting point:

1. **Minimal complexity.** Two parties, one HTTP channel, no quorum selection logic.
2. **Fastest iteration.** No discovery, no node selection, no liveness management.
3. **Proven in POCs.** All 15 POCs use 2-of-2 (except POC 12 which validated 3-of-5).
4. **Sufficient for initial deployment.** The agent container and KSS run on separate infrastructure with separate credentials. An attacker must compromise both to steal funds.

### Limitations

- **Single point of failure.** KSS downtime = no signing capability.
- **Single point of compromise.** Compromising both the container and KSS is sufficient. No defense-in-depth beyond infrastructure isolation.
- **No recovery path.** If either share is lost (disk failure, accidental deletion), funds are permanently locked unless both shares were backed up.

---

## 2. Phase 1 -- Alpha: Stay 2-of-2

**Timeline:** Through Alpha milestone (current).

No threshold changes. Focus on:

- Completing BRC-31 authentication on all KSS endpoints.
- Hardening presignature pool management (atomic consumption, audit logging).
- Implementing remaining BRC-100 wallet API handlers (10 stubs).
- Deploying persistent storage (DO SQLite on worker, SQLite on service).

### Why Not Move to 2-of-3 Yet

- BRC-31 auth is incomplete -- adding a third party multiplies unauthenticated surface.
- Browser DKG (WAB onboarding) is not implemented -- the third share has nowhere to live.
- Recovery service infrastructure does not exist yet.
- The 2-of-2 trust model is acceptable for controlled Alpha deployment where both parties are operated by the same entity.

---

## 3. Phase 2 -- Beta: Move to 2-of-3

**Timeline:** Beta milestone.

### New Configuration

| Party | Role | Share Location | Infrastructure |
|-------|------|---------------|----------------|
| **Proxy (share_B)** | Same as Alpha. Initiates signing. | Agent container | Same container as bsv-worm |
| **KSS (share_A)** | Same as Alpha. Primary signing partner. | Remote service | Separate infrastructure |
| **Recovery Service (share_C)** | Backup share holder. Only participates in signing during recovery scenarios (KSS unavailable, share_B lost). | Independent service | Different provider/jurisdiction |

### Properties

| Property | Value |
|----------|-------|
| Threshold | t=1 (any 2 of 3 can sign) |
| Fault tolerance | **1 party.** Any single party can go offline without losing signing capability. |
| Compromise tolerance | **1 party.** An attacker must compromise 2 of 3 independent systems. |
| DKG time | ~80-100ms native (linear scaling from POC 1). Plus ~30s aux info per party (one-time). |
| Signing (presigned) | Same as 2-of-2 (~16ms HTTPS). Only 2 of 3 parties participate in each signing. |
| Signing (4-round) | Same as 2-of-2 (~33ms HTTPS est). Threshold signing selects any 2 parties. |
| Protocol rounds | Same as 2-of-2 (threshold determines round count, not total parties). |

### Why 2-of-3

1. **Eliminates single-KSS-compromise** as a critical risk. Even if the KSS is fully compromised, the attacker only has 1 of 3 shares.
2. **Enables recovery.** If share_B is lost (container failure), the recovery service + KSS can co-sign a fund transfer to a new MPC address.
3. **Same performance.** Threshold signing only involves t+1 parties. A 2-of-3 signing session is the same speed as 2-of-2 -- only 2 parties participate.
4. **Validated in POC 11.** Fee settlement used 2-of-3 on mainnet. All three 2-party subsets produced valid signatures.

### Share Holder Selection

The three share holders should satisfy:

| Requirement | Rationale |
|------------|-----------|
| **Independent infrastructure** | Different cloud providers, different physical locations. Correlated failures (same data center) defeat the purpose. |
| **Independent credentials** | Compromising one account's API keys must not grant access to the other accounts. |
| **Different jurisdictions** (recommended) | Reduces risk of coordinated legal seizure. |
| **Recovery service restricted access** | The recovery share should require additional authentication (user passphrase, hardware token) before participating in signing. It is not for routine use. |

### DKG for 2-of-3

The DKG ceremony runs once with all 3 parties. CGGMP'24 DKG natively supports any (t, n) configuration. The `DkgCoordinator` is parameterized by `ThresholdConfig { threshold: 2, parties: 3 }`.

```
Party 0 (KSS)           Party 1 (Proxy)          Party 2 (Recovery)
     |                        |                        |
     |<------ Keygen (4 rounds, all 3 parties) ------->|
     |                        |                        |
     |  share_A               |  share_B               |  share_C
     |  (encrypted, stored    |  (encrypted, stored    |  (encrypted, stored
     |   in DO SQLite)        |   in share.enc)        |   in recovery svc)
     |                        |                        |
     |<------ Aux Info (multi-round, all 3) ---------->|
     |                        |                        |
     |  aux_A                 |  aux_B                 |  aux_C
     |                        |                        |
     |  KeyShare::from_parts  |  KeyShare::from_parts  |  KeyShare::from_parts
     |  (share_A, aux_A)      |  (share_B, aux_B)      |  (share_C, aux_C)
```

### Signing Participant Selection

For routine operations, the proxy selects KSS as its signing partner (parties 0 and 1). The recovery service is not contacted unless:

1. KSS is unreachable (health check fails).
2. The agent explicitly requests a different signing set.
3. A recovery operation requires the recovery service.

This keeps the common path identical to 2-of-2 in latency and complexity.

### Migration Path: 2-of-2 to 2-of-3

Key refresh (threshold resharing) enables migration without on-chain cost:

1. **Current state:** 2-of-2 with shares `(share_A, share_B)` on polynomial `F(x)` where `F(0) = secret`.
2. **Reshare:** Both surviving parties (A and B) participate. New polynomial `G(x)` with degree 1 (for threshold 2), same constant term `G(0) = F(0) = secret`. Produce 3 new shares `(share_A', share_B', share_C')`.
3. **Distribute:** share_A' to KSS, share_B' to proxy, share_C' to recovery service.
4. **Verify:** `verify_reshare()` confirms the joint public key is unchanged.
5. **Invalidate:** Old shares `(share_A, share_B)` are cryptographically useless against the new polynomial.

**Properties** (validated in POC 13):
- Joint public key unchanged (same BSV address).
- 0 on-chain cost (no fund transfer needed).
- Supports arbitrary (t, n) to (t', n') transitions.
- Old shares are rotated -- they cannot sign with the new share set.

---

## 4. Phase 3 -- GA: Support 3-of-5

**Timeline:** GA milestone, for high-value wallets.

### New Configuration

| Party | Role | Infrastructure |
|-------|------|----------------|
| **Party 0** | KSS (primary) | Operator A infrastructure |
| **Party 1** | Proxy (agent-side) | Agent container |
| **Party 2** | KSS (secondary) | Operator B infrastructure |
| **Party 3** | Recovery service | Operator C infrastructure |
| **Party 4** | Cold storage backup | Offline / air-gapped |

### Properties

| Property | Value | Source |
|----------|-------|--------|
| Threshold | t=2 (any 3 of 5 can sign) | POC 12 |
| Fault tolerance | **2 parties.** Any 2 can go offline. | POC 12 |
| Compromise tolerance | **2 parties.** Attacker must breach 3 of 5 independent systems. | POC 12 |
| DKG time | 138ms (5-party, native) | POC 12 |
| Aux info time | ~130s for 5 sets of Paillier primes (one-time) | POC 12 |
| Presigning combine | 4.4ms (regardless of threshold) | POC 12 |
| On-demand signing cost ratio | ~3x vs 2-of-2 | POC 12 |
| Presigned signing cost ratio | ~1x vs 2-of-2 (presigning absorbs the cost) | POC 12 |

### Performance Details from POC 12

POC 12 validated 3-of-5 with concrete measurements:

- **5-party DKG:** 138ms (vs ~80ms for 2-party). Linear scaling.
- **Aux info generation:** 130 seconds total for 5 parties. This is a one-time cost at DKG. Paillier prime generation is the bottleneck -- it can be parallelized or pre-computed in background jobs.
- **Presigning combine:** 4.4ms regardless of threshold. Presigning absorbs the multi-round cost into offline preparation.
- **Below-threshold rejection:** Attempting to sign with only 2 of 5 parties (when t=2, requiring 3) correctly returns `MismatchedAmountOfParties`. The protocol enforces the threshold.
- **All subsets valid:** Any 3-of-5 subset produces valid signatures for the same joint public key.

### When to Use 3-of-5

3-of-5 is recommended for:

| Scenario | Rationale |
|----------|-----------|
| **High-value wallets** (>100,000 sats balance) | Higher compromise tolerance justifies additional operational complexity. |
| **Multi-operator deployments** | When the agent wants signing distributed across multiple independent MPC operators discovered via overlay. |
| **Regulatory requirements** | Some jurisdictions may require multi-party custody above certain thresholds. |

3-of-5 is NOT recommended for:

| Scenario | Rationale |
|----------|-----------|
| **Low-value agent wallets** | Operational overhead outweighs security benefit for wallets holding <10,000 sats. |
| **Latency-sensitive applications** | On-demand (non-presigned) 3-of-5 is ~3x slower than 2-of-2. Use presigning to eliminate this penalty. |
| **Single-operator deployments** | If one entity runs all 5 parties, the security benefit is illusory. |

### Migration Path: 2-of-3 to 3-of-5

Same key refresh mechanism as the 2-of-3 migration:

1. Any 2 of the 3 existing parties participate in resharing (threshold requirement met).
2. New polynomial of degree 2 (for threshold 3), same constant term.
3. Produce 5 new shares, distribute to all parties.
4. Joint public key unchanged, 0 on-chain cost.

POC 13 validated this exact transition pattern (`test_different_threshold_reshare`: 2-of-3 to 3-of-5).

---

## 5. Key Refresh: The Universal Migration Mechanism

Key refresh (threshold resharing) is the mechanism that makes threshold upgrades seamless. It is implemented in `bsv-mpc-core/src/refresh.rs`, ported from POC 13.

### How It Works

Given `t` surviving parties with shares on polynomial `F(x)` where `F(0) = secret`:

1. Each surviving party `k` computes their Lagrange coefficient `lambda_k` for interpolation at x=0.
2. Each party computes their weighted share: `w_k = lambda_k * x_k`.
3. Each party generates a random polynomial `f_k(x)` of degree `(t'-1)` with `f_k(0) = w_k`.
4. Each party evaluates their polynomial at each new party's evaluation point and sends the result.
5. Each new party sums the received evaluations: `x'_i = sum_k f_k(eval_point_i)`.

The composite polynomial has the same constant term (the secret) but different coefficients, producing new shares that reconstruct the same secret.

### Properties

| Property | Detail |
|----------|--------|
| **Joint key unchanged** | Same BSV address, no fund transfer, no re-indexing. |
| **On-chain cost** | 0 sats (vs ~188 sats for full re-DKG + fund transfer + 9-18s WoC indexing delay). |
| **Old shares invalidated** | New shares lie on a different polynomial. Old shares are mathematically useless for signing with the new share set. |
| **Arbitrary (t,n) to (t',n')** | Supports changing both threshold and party count in one operation. |
| **Verification** | `verify_reshare()` confirms the reconstructed key matches the original joint public key using Lagrange interpolation on the new public shares. |

### Validated Transitions (POC 13 + refresh.rs tests)

| From | To | Test |
|------|----|------|
| 2-of-3 | 2-of-3 (share rotation) | `test_threshold_reshare_preserves_key` |
| 2-of-3 | 2-of-3 (party replacement) | `test_sign_with_new_shares` (party 2 replaced) |
| 2-of-3 | 3-of-5 (threshold upgrade) | `test_different_threshold_reshare` |

### Production Hardening Needed

- **Schnorr proofs for refresh polynomial commitments.** Each party should prove their polynomial has the correct degree and constant term without revealing the polynomial itself. This prevents a malicious party from biasing the reshared result. Currently not implemented.
- **Round-based protocol integration.** The current implementation (`threshold_reshare()`) runs locally with all shares available. Production deployment requires a multi-round protocol where each party only provides evaluations at remote parties' points, never their raw share.

---

## 6. Performance Comparison

All measurements from POC code on the same hardware. "HTTPS" column estimated from POC 10 RTT measurements.

### DKG (One-Time)

| Config | Native | HTTPS (est) | Notes |
|--------|--------|-------------|-------|
| 2-of-2 | ~80ms keygen + ~30s aux/party | ~52ms keygen (POC 10) + aux | Aux info is bottleneck |
| 2-of-3 | ~100ms keygen + ~30s aux/party | ~70ms keygen (est) + aux | Linear scaling |
| 3-of-5 | 138ms keygen + ~26s aux/party | ~100ms keygen (est) + aux | 130s total aux for 5 parties |

Aux info generation (Paillier safe primes) is a one-time cost and can be pre-computed in a background job before DKG begins (`DkgCoordinator::set_pregenerated_primes()`).

### Signing (Per Transaction)

| Config | Presigned (1 RTT) | 4-Round | Notes |
|--------|-------------------|---------|-------|
| 2-of-2 | ~16ms HTTPS | ~33ms HTTPS (est) | Only 2 parties participate |
| 2-of-3 | ~16ms HTTPS | ~33ms HTTPS (est) | Same -- only 2 of 3 participate |
| 3-of-5 | ~16ms HTTPS | ~100ms HTTPS (est) | 3 parties participate, ~3x on-demand cost |

**Key insight:** Presigned signing is ~16ms regardless of threshold configuration. The multi-round cost is absorbed during offline presignature generation. This is why presigning is the recommended production path.

### Presigning (Offline, Background)

| Config | Time per Presig | Pool Replenishment |
|--------|----------------|-------------------|
| 2-of-2 | ~1.24s localhost | Background task, 5s check interval |
| 2-of-3 | ~1.24s (est, same 2-party presigning) | Same |
| 3-of-5 | ~3.7s (est, 3x) | Longer cycle, higher pool target recommended |

---

## 7. Operational Considerations

### 7.1 Node Discovery (GA)

In 3-of-5, the agent must discover and select 4 remote parties (the proxy is always one party). The overlay network (BRC-22/23/24/25) provides this:

1. **Registration:** Each MPC node creates a CHIP token on the `tm_mpc_signing` overlay topic.
2. **Discovery:** The agent queries SLAP trackers for nodes matching its requirements (supported thresholds, pricing, reputation).
3. **Selection:** Client-side filtering and ranking by health check latency, participation proof history, and fee.
4. **DKG:** The agent initiates DKG with the selected nodes.

POC 14 validated that 4 of 4 mainnet SLAP trackers are alive and responsive. The `discovery.rs` module implements health checking and reputation scoring.

### 7.2 Fee Distribution

Fee distribution scales with the number of parties:

| Config | Fee Split | Settlement |
|--------|----------|------------|
| 2-of-2 | 50/50 or operator-defined | Level 1 (trusted) or Level 2 (multisig) |
| 2-of-3 | Proportional to participation proofs | Level 2 (2-of-3 multisig self-settlement) |
| 3-of-5 | Proportional to participation proofs | Level 2 (3-of-5 multisig) or Level 3 (covenant) |

`calculate_settlement()` in `proofs.rs` handles proportional distribution with integer division and remainder allocation. POC 11 validated 2-of-3 settlement on mainnet with proportional splits (45%/35%/20%).

### 7.3 Liveness and Failover

| Config | Liveness Guarantee | Failover Behavior |
|--------|-------------------|-------------------|
| 2-of-2 | Both parties must be online | No failover. KSS downtime = signing outage. |
| 2-of-3 | Any 2 of 3 online | Proxy tries KSS first. If KSS unreachable, falls back to recovery service. Transparent to the agent. |
| 3-of-5 | Any 3 of 5 online | Proxy selects the 2 fastest-responding remote parties. Automatic failover to alternates. |

The proxy's signing participant selection logic should implement:

1. **Health check** before signing (lightweight GET to `/health`).
2. **Timeout-based failover** (if primary KSS does not respond within 2 seconds, try the next).
3. **Sticky sessions** (prefer the same signing set for consecutive operations to reuse presignatures).

### 7.4 Presignature Pool Sizing

Higher thresholds should maintain larger presignature pools because presigning takes longer:

| Config | Recommended Pool Size | Replenishment Rate | Rationale |
|--------|----------------------|-------------------|-----------|
| 2-of-2 | 20 (default) | ~1 per 1.3s | Pool refills in ~26s. Agent typically idle 5-30s between tasks. |
| 2-of-3 | 20 | ~1 per 1.3s | Same as 2-of-2 (only 2 parties presign). |
| 3-of-5 | 50 | ~1 per 4s (est) | 3-party presigning is ~3x slower. Larger pool absorbs burst demand. |

The `PresignManager` supports configurable pool size via `MPC_MAX_PRESIGS` env var. The `should_replenish()` trigger fires at 50% capacity.

---

## 8. Summary

| Phase | Config | Fault Tolerance | Compromise Tolerance | Migration Mechanism | On-Chain Cost |
|-------|--------|----------------|---------------------|--------------------|----|
| Alpha | 2-of-2 | 0 | 0 | -- | -- |
| Beta | 2-of-3 | 1 party | 1 party | Key refresh (resharing) | 0 sats |
| GA | 3-of-5 | 2 parties | 2 parties | Key refresh (resharing) | 0 sats |

The migration path is smooth: key refresh preserves the joint public key (same BSV address), costs 0 sats on-chain, and cryptographically invalidates old shares. Each threshold upgrade strictly increases security without disrupting existing agent operations or requiring fund transfers.
