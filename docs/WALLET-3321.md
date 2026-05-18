# How to call the wallet at `localhost:3321`

> Living reference for any bsv-mpc test or harness that needs to fund
> an MPC joint address, query history, or build a sighash from a real
> BSV UTXO. Every claim here is grounded in a line citation in one of
> our local cousin repos under `~/bsv/`, verified empirically against
> the running wallet on `2026-05-17`.
>
> If something here drifts (BSV Desktop updates, etc.), update the
> doc — don't paper over with a workaround. Truth > shorthand.

## TL;DR

| Need | Header | Notes |
|---|---|---|
| Spend from default basket (createAction, etc.) | `Origin: http://admin.com` | Required — see §1 |
| List outputs in `default` basket | `Origin: http://admin.com` | Same admin gate |
| Crypto ops (encrypt, createSignature, etc.) | Any non-empty `Origin` | Just needs to be present |
| Read-only GETs (getVersion, getNetwork) | None | No originator required |

Without admin Origin, default basket returns `{"name":"Error","message":"Basket "default" is admin-only."}`. Empirically confirmed 2026-05-17 against a running BSV Desktop instance.

## §1 What's actually running on port 3321

Either of two implementations exposes the same BRC-100 surface on this port:

- **BSV Desktop** (`~/bsv/bsv-desktop`) — Electron app, React renderer with `WalletPermissionsManager`. The relevant entry points:
  - `electron/httpServer.ts:173` — `app.listen(3321, '127.0.0.1', ...)` — every request gets forwarded over IPC to the renderer
  - `src/onWalletReady.ts:76` — renderer wires `window.electronAPI.onHttpRequest` to dispatch by `req.path` to the wallet
  - `src/lib/WalletContext.tsx:1250` — `new WalletPermissionsManager(wallet, adminOriginator, ...)` — the permissions wrapper that enforces admin-only baskets

- **bsv-wallet-cli** (`~/bsv/bsv-wallet-cli`) — Rust daemon, axum server. The relevant entry points:
  - `src/server/mod.rs:86` — `.route("/createAction", post(handlers::create_action))`
  - `src/server/handlers.rs:77-89` — `extract_originator` from `Origin` or `Originator` header (returns 400 if neither)
  - `src/context.rs:56` — instantiates `bsv_wallet_toolbox::Wallet::new(...)` directly; **does not** wrap with `WalletPermissionsManager`, so the admin-only restrictions do NOT apply when bsv-wallet-cli is the one serving 3321

**Implication:** the "admin-only" gate is a BSV Desktop / PermissionsManager feature. If you hit the gate at all, you're talking to BSV Desktop. If you're talking to bsv-wallet-cli serve mode, any non-empty Origin works.

For mainnet ceremony tests, assume BSV Desktop and use the admin Origin to stay safe under both.

## §2 The admin originator string is `"admin.com"`

Defined in `bsv-desktop/src/lib/config.ts:3`:

```ts
export const ADMIN_ORIGINATOR = 'admin.com';
```

Used at `bsv-desktop/src/lib/WalletContext.tsx:1250` when constructing the permissions manager:

```ts
const permissionsManager = new WalletPermissionsManager(wallet, adminOriginator, ...)
```

The matching check in the toolbox at `bsv-wallet-toolbox-rs/src/managers/permissions_manager.rs:559-561`:

```rust
fn is_admin(&self, originator: &str) -> bool {
    originator == self.admin_originator
}
```

**Exact-string match.** The wallet stores the originator as `"admin.com"` (the constant value), and `is_admin` compares the request's originator against that exact string.

## §3 How Origin maps to originator

The renderer pulls the originator from the `Origin` HTTP header via `parseOrigin` at `bsv-desktop/src/onWalletReady.ts:45-72`:

```ts
function parseOrigin(headers: Record<string, string>): string | null {
  const rawOrigin = headers['origin'];
  const rawOriginator = headers['originator'];

  // 1) Browser case
  if (rawOrigin) {
    try {
      return new URL(rawOrigin).host;
    } catch { return null; }
  }
  // 2) Node-injected fallback
  if (rawOriginator) {
    const candidate = rawOriginator.includes('://') ? rawOriginator : `http://${rawOriginator}`;
    return new URL(candidate).host;
  }
  return null;
}
```

**Key transform:** `new URL(rawOrigin).host` extracts ONLY the host portion. So:

| Header value | `parseOrigin` returns |
|---|---|
| `Origin: http://admin.com` | `"admin.com"` ✓ matches `ADMIN_ORIGINATOR` |
| `Origin: https://admin.com` | `"admin.com"` ✓ matches |
| `Origin: http://admin.com:8080` | `"admin.com:8080"` ✗ no match |
| `Origin: http://localhost` | `"localhost"` ✗ no match |
| `Origin: admin.com` | `null` (URL parse fails) → falls to legacy `Originator` |
| `Originator: admin.com` | `"admin.com"` ✓ matches (via the fallback branch) |

The scheme is parsed off; the **port matters** (don't include one); the **host alone** is what the renderer compares against `ADMIN_ORIGINATOR`.

The bsv-wallet-cli serve path is a different story — it uses `extract_originator` at `bsv-wallet-cli/src/server/handlers.rs:77-89` which returns the raw header value, not the URL host. Since bsv-wallet-cli's serve doesn't enforce the admin gate at all (no permissions wrapper, see §1), this distinction doesn't matter there.

## §4 Empirically verified 2026-05-17

```bash
# WITH admin Origin — default basket query works, 574 outputs visible:
$ curl -sS -X POST -H 'Origin: http://admin.com' -H 'Content-Type: application/json' \
       http://localhost:3321/listOutputs \
       -d '{"basket":"default","limit":3,"includeBEEF":false}'
{"totalOutputs":574,"outputs":[{"satoshis":5,...},{"satoshis":16,...},{"satoshis":16,...}], ...}

# WITHOUT admin Origin — explicit admin-only error:
$ curl -sS -X POST -H 'Origin: http://localhost' -H 'Content-Type: application/json' \
       http://localhost:3321/listOutputs \
       -d '{"basket":"default","limit":3}'
{"name":"Error","message":"Basket "default" is admin-only.","isError":true}

# listActions with admin Origin — full history visible (3,395 actions seen):
$ curl -sS -X POST -H 'Origin: http://admin.com' -H 'Content-Type: application/json' \
       http://localhost:3321/listActions \
       -d '{"labels":[],"limit":3,"includeOutputs":false,"includeInputs":false,"includeLabels":false}'
{"totalActions":3395,"actions":[{"txid":"35a475de...","satoshis":150000,"status":"completed"},...]}
```

## §5 Common request shapes

### Fund an arbitrary P2PKH address (e.g., an MPC joint address)

```http
POST /createAction
Origin: http://admin.com
Content-Type: application/json

{
  "description": "MPC joint address funding",
  "outputs": [{
    "satoshis": 1500,
    "lockingScript": "<hex of P2PKH script>",
    "outputDescription": "MPC joint P2PKH"
  }]
}
```

Response shape (proven by POC 4):

```json
{ "txid": "...", "tx": "<atomic BEEF hex>", "noSendChange": [...] }
```

The wallet auto-selects UTXOs from `default`, builds + signs the tx, broadcasts via its configured `Services.arc` (TAAL by default), and returns the TXID + atomic BEEF. Spending happens immediately — `noSend: true` in `options` would build without broadcasting if needed.

### Get the wallet's identity public key (for change outputs)

```http
POST /getPublicKey
Origin: http://admin.com
Content-Type: application/json

{ "identityKey": true }
```

Response: `{ "publicKey": "<33-byte hex>" }`. Use this to derive a P2PKH script for returning unused funds.

### Query default basket (after a test run, for debugging)

```http
POST /listOutputs
Origin: http://admin.com
Content-Type: application/json

{ "basket": "default", "limit": 100, "includeBEEF": false }
```

### Query recent action history (for post-mortem)

```http
POST /listActions
Origin: http://admin.com
Content-Type: application/json

{ "labels": [], "limit": 10, "includeOutputs": false, "includeInputs": false, "includeLabels": false }
```

Returns `{"totalActions", "actions": [{"txid","satoshis","status","description"}, ...]}`. `satoshis` is positive for incoming, negative for outgoing (net of fees).

## §6 What NOT to do

- ❌ `Origin: http://localhost` — falls into the per-origin permission flow; default basket is denied
- ❌ `Origin: admin.com` (no scheme) — `URL` parse fails in the renderer; gets denied as if missing
- ❌ Omit Origin entirely — 400 "Origin header is required"
- ❌ Wrap or re-encode body — the wallet expects raw BRC-100 JSON shapes, not envelopes

## §7 Local files this doc cites (all under `~/bsv/`)

| Claim | File:line |
|---|---|
| Port + listener | `bsv-desktop/electron/httpServer.ts:173` |
| Renderer http dispatch | `bsv-desktop/src/onWalletReady.ts:76` |
| Permissions manager wiring | `bsv-desktop/src/lib/WalletContext.tsx:1250` |
| `ADMIN_ORIGINATOR = 'admin.com'` constant | `bsv-desktop/src/lib/config.ts:3` |
| `parseOrigin` (Origin → host extraction) | `bsv-desktop/src/onWalletReady.ts:45-72` |
| `is_admin` exact-string check | `bsv-wallet-toolbox-rs/src/managers/permissions_manager.rs:559-561` |
| Admin-only basket error string | `bsv-wallet-toolbox-rs/src/managers/permissions_manager.rs:842-848` |
| bsv-wallet-cli serve (no perms wrapper) | `bsv-wallet-cli/src/server/mod.rs:86`, `src/context.rs:56` |
| bsv-wallet-cli originator extraction | `bsv-wallet-cli/src/server/handlers.rs:77-89` |
| POC 4 reference flow (canonical fund→sign→broadcast) | `bsv-mpc/poc/poc4-real-tx/tests/poc.rs:307-666` |
