# bsv-mpc — Plain English Specifications

> What each piece does, how it works, and why it exists.
> No code jargon — just the concepts.

---

## The Big Picture

**Problem:** AI agents hold BSV wallets to pay for things (LLM inference, image generation, etc.). The wallet has a private key. Whoever has that key controls the money. If you host the agent on a cloud platform, the platform has the key. The platform could steal the funds.

**Solution:** Split the key into pieces (called "shares"). No single piece is useful on its own. To sign a transaction (spend money), multiple parties must cooperate using a cryptographic protocol. The full key literally never exists — not in memory, not on disk, not in transit.

**Result:** "Not even the platform can sign your transactions."

---

## Component 1: bsv-mpc-core — The Crypto Engine

### What it does
Wraps the cggmp24 library (built by Dfns, audited by Kudelski) to perform threshold ECDSA signing on Bitcoin's secp256k1 curve.

### How it works

**Key Generation (DKG — Distributed Key Generation):**
- Multiple parties (say 3) run a multi-round protocol over the network
- At the end, each party has one "share" of a signing key
- A joint public key is computed — this is the agent's BSV address
- The full private key was never computed or assembled anywhere
- Takes ~230ms, done once when an agent is created

**Signing (making a payment):**
- When the agent needs to sign a transaction, any t+1 parties (e.g., 2 of 3) run the signing protocol
- With presigning (prepared in advance): 1 network round, ~7-15ms
- Without presigning: 4 network rounds, ~28-180ms depending on distance
- Output: a standard ECDSA signature, indistinguishable from a normal Bitcoin signature

**Presigning (background preparation):**
- Between tasks, the parties run 3 rounds to prepare a "presignature"
- Presignatures are stockpiled (like pre-loaded bullets)
- When a real signing request comes in, consume one presignature — single round trip
- The agent never waits for the full 4-round protocol

**Share Storage:**
- Each party's share is encrypted with AES-256-GCM
- Encryption key derived from BSV's key derivation system (BRC-42)
- Encrypted shares can be stored anywhere (Cloudflare, database, disk)
- Without the encryption key, the share is useless ciphertext

### Why it exists separately
The crypto is the same regardless of how you deploy it. A Cloudflare Worker, a standalone server, or a local binary all use the same core protocol. Separating it means one audited crypto library shared by all deployment options.

---

## Component 2: bsv-mpc-proxy — The Wallet Impersonator

### What it does
Pretends to be a normal BSV wallet (bsv-wallet-cli) at localhost:3322. The agent (bsv-worm) talks to it using the standard wallet API (BRC-100, 28 endpoints). Behind the scenes, it translates every signing request into an MPC protocol exchange with the Key Share Service.

### How it works

**Drop-in replacement:**
- bsv-worm calls `localhost:3322/createSignature` thinking it's talking to a normal wallet
- The proxy intercepts the request
- Instead of signing with a local key, it runs the MPC protocol with the Key Share Service
- Returns a valid signature — bsv-worm never knows the difference
- **Zero code changes to bsv-worm**

**Fee injection:**
- Before signing a transaction, the proxy adds an extra output: a small fee (default 1,000 sats) to pay the MPC node operators
- The agent doesn't know about this fee — it's transparent
- The fee goes to a multisig address controlled by the MPC nodes
- ~2% overhead on a typical LLM payment — negligible

**Presignature management:**
- A background task runs continuously
- When the presignature pool drops below half-full, it generates more
- Generation happens during idle time (between LLM calls — there's 5-30s of dead time)
- When a signing request arrives, it grabs a presignature from the pool
- If the pool is empty, falls back to the full 4-round protocol (slower but still works)

**What it proxies (the important ones):**
| Wallet API Call | What the proxy does |
|---|---|
| `getPublicKey` | Returns the joint MPC public key (computed during DKG) |
| `createSignature` | Runs MPC signing protocol with Key Share Service |
| `createAction` | Builds transaction + injects fee output + MPC signs + broadcasts |
| `encrypt` / `decrypt` | Uses a locally-derived key (no MPC needed for encryption) |
| `listOutputs` | Tracks UTXOs locally (no MPC needed) |

### Why it exists
The whole point is that bsv-worm doesn't change. Any BRC-100 wallet client works. The MPC complexity is hidden behind a standard interface. If you want to switch from MPC back to a normal wallet, just swap the binary at localhost:3322.

---

## Component 3: bsv-mpc-worker — The Cloud Key Keeper

### What it does
A Cloudflare Worker (runs as WASM at the network edge) that holds one share of the signing key. When the proxy needs to sign, it talks to this worker. The worker participates in the MPC protocol using its share, then forgets about the request.

### How it works

**Deployment:**
- Rust code compiled to WebAssembly (WASM)
- Runs on Cloudflare's global network (300+ locations)
- No server to manage, no containers, no VMs
- Starts in <5ms (V8 isolate, not a container boot)
- Costs ~$5/month for the first 10 million requests

**Share storage:**
- Each agent's encrypted share is stored in Durable Object SQLite
- Durable Objects provide strongly consistent, transactional storage
- The share is encrypted — even Cloudflare can't read it
- 5GB free tier = millions of agent shares

**Protocol flow:**
1. Proxy sends POST to `/sign/init` with the message hash to sign
2. Worker loads the agent's share from storage
3. Worker runs round 1 of CGGMP'24, returns its protocol message
4. Proxy processes the message, sends the next round to `/sign/round`
5. After 1-4 rounds, a valid signature is produced
6. Worker has already forgotten everything (stateless request handling)

**Authentication:**
- BRC-31 Authrite mutual authentication on every request
- Only the corresponding agent's proxy can request signatures for that agent's share
- A rogue request from a different agent gets rejected

### Why it exists
Cloudflare Workers are the cheapest, fastest way to run the Key Share Service. Zero cold start means signing isn't delayed by container boot. WASM means the same Rust crypto code runs in the browser, on a server, or at the edge. Global distribution means the worker is physically close to the agent container, keeping network latency low.

---

## Component 4: bsv-mpc-service — The DIY Key Keeper

### What it does
The same thing as bsv-mpc-worker, but as a standalone Rust binary you run yourself. For people who don't want Cloudflare involved, or for independent MPC node operators running on their own hardware.

### How it works
- Same API endpoints as the CF Worker version
- Backed by local SQLite instead of Durable Object SQLite
- Run it on a VPS, a home server, a Raspberry Pi, Docker, whatever
- `bsv-mpc-service --port 4322 --data-dir ./shares`

### Why it exists
Not everyone wants to use Cloudflare. Independent MPC node operators need a self-hosted option. This is also the development/testing binary — easier to debug locally than on a CF Worker.

---

## Component 5: bsv-mpc-overlay — The Yellow Pages

### What it does
Handles MPC node discovery on the BSV overlay network. Think of it as the yellow pages: MPC nodes register their services, and agents look them up when they need signing partners.

### How it works

**Node registration (CHIP tokens):**
- An MPC node wants to be discoverable
- It creates a special on-chain token (CHIP, BRC-23) that says: "I'm an MPC node at this domain, I support these capabilities, I charge this much per signing"
- This token is published to the BSV overlay network under the `tm_mpc_signing` topic
- Now anyone can find this node by querying the overlay

**Agent discovery (SLAP lookup):**
- An agent needs MPC signing nodes
- It queries the overlay: "Give me all MPC nodes that support secp256k1, 2-of-3 threshold, and charge less than 500 sats"
- Gets back a list of nodes with their domains, capabilities, and prices
- Picks the best ones and initiates DKG

**Participation proofs:**
- After every signing, a BRC-18 proof is published to the overlay
- The proof says: "These nodes participated in this signing session"
- These proofs are the basis for fee distribution — more work = more pay
- Anyone can verify the proofs (they're on-chain)

### Why it exists
A decentralized network needs decentralized discovery. Without this, agents would need a hardcoded list of MPC nodes. With overlay discovery, anyone can run a node, register on the network, and start earning fees — permissionlessly.

---

## The Fee System — How Node Operators Get Paid

### The flow

1. **Agent makes an x402 payment** (e.g., 50,000 sats to an LLM provider)
2. **Proxy injects fee output** — adds 1,000 sats to the transaction going to the MPC nodes
3. **Transaction is MPC-signed** — the fee output is part of the transaction
4. **Fee accumulates** — many small fee UTXOs pile up over time
5. **Settlement** — periodically, the MPC nodes co-sign a settlement transaction that splits the accumulated fees proportionally

### Settlement levels

**Level 1 — Trusted (simplest, ships first):**
Someone counts up the proofs and sends each node their share. You trust that person to count honestly.

**Level 2 — Multisig (recommended):**
The fee outputs are locked in a multisig that requires the MPC nodes themselves to co-sign. The nodes settle themselves — they have to agree on the split. No one can take more than their share because the others won't co-sign. Elegant: the MPC nodes use their own threshold signing to settle their own fees.

**Level 3 — Smart Contract (trustless, ambitious):**
An sCrypt covenant on BSV that enforces the proportional split in Script. Nobody can spend the fee pool without creating outputs in the correct proportions. The blockchain itself enforces fairness.

### The math

At 1,000 agents, each making 10 x402 calls/day:
- 10,000 signings/day × 1,000 sats = 10M sats/day in fees
- Split 3 ways (2-of-3 setup): ~3.3M sats/node/day = ~$50/node/month
- Node cost on CF Workers: $5/month
- **90% margin**

At 100,000 agents: $5,000/node/month. The margins scale because the compute cost barely changes — 15ms of WASM doesn't cost more at 10x volume.

---

## The Overlay Network — How It All Connects

### What's an overlay?

BSV has a layer on top of the blockchain called the overlay network (BRC-22/23/24/25). It's like topic-based pub/sub for transactions. Services register under topics, and clients discover them by querying the topic.

### Our topic: `tm_mpc_signing`

MPC nodes publish CHIP tokens to this topic. Agents query this topic to find nodes. Participation proofs are published to this topic. Fee settlements reference this topic.

### The bootstrap problem

Initially, we run all the overlay nodes and all the MPC nodes. That's fine — Bitcoin started with one miner. The architecture supports permissionless joining from day one. When economic incentives kick in (~10K agents, $500/month per node), independent operators will join.

---

## The BRC Standards — Making It Official

Four new BSV Request for Comments (BRCs) formalize this network:

| BRC | What it standardizes | Why it matters |
|---|---|---|
| **Threshold ECDSA Signing** | The MPC protocol messages, DKG flow, signing flow | Any wallet implementer can build compatible MPC |
| **MPC Overlay Discovery** | How nodes register and agents find them | Permissionless network — anyone can join |
| **Participation Proofs** | On-chain proof format for signing | Verifiable fee distribution — no trust needed |
| **Fee Distribution** | How fees are collected and settled | Economic incentive layer — nodes get paid |

These standards mean this isn't just "our MPC for our platform." It's infrastructure anyone in the BSV ecosystem can use.

---

## How It Fits With bsv-worm

```
bsv-worm (unchanged)
    |
    | Calls wallet API at localhost:3322
    | (thinks it's talking to bsv-wallet-cli)
    |
    v
bsv-mpc-proxy (new)
    |
    | Translates to MPC protocol
    | Injects fee output
    | Manages presignature pool
    |
    v
bsv-mpc-worker or bsv-mpc-service (new)
    |
    | Holds the other share
    | Participates in threshold signing
    | Returns partial signatures
    |
    v
BSV Overlay Network (existing infra, new topic)
    |
    | Node discovery (CHIP tokens)
    | Participation proofs (BRC-18)
    | Fee settlement (multisig/covenant)
```

The agent's private key never exists. The platform can't sign. The user's master key (rootPrimaryKey) is only in the browser for 120 seconds during setup, then destroyed. The MPC fee system creates a sustainable business model for node operators. And the BRC standards make it all interoperable.
