//! # bsv-mpc-worker
//!
//! Cloudflare Worker Key Share Service for MPC threshold signing.
//!
//! This Worker holds **share_A** — one half of a 2-of-2 threshold signing setup.
//! The MPC Signing Proxy (running in the agent's container) holds **share_B**.
//! Together, the two parties can produce a valid ECDSA signature over a BSV
//! sighash. Neither party alone can reconstruct the private key or forge a
//! signature.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────┐        ┌──────────────────────┐
//! │  Agent Container    │  HTTP  │  CF Worker (this)     │
//! │  ┌───────────────┐  │◄──────►│  ┌────────────────┐  │
//! │  │ MPC Proxy     │  │ BRC-31 │  │ Key Share Svc  │  │
//! │  │ (share_B)     │  │  auth  │  │ (share_A)      │  │
//! │  └───────────────┘  │        │  └────────────────┘  │
//! └─────────────────────┘        │  ┌────────────────┐  │
//!                                │  │ DO SQLite      │  │
//!                                │  │ (encrypted     │  │
//!                                │  │  shares)       │  │
//!                                │  └────────────────┘  │
//!                                └──────────────────────┘
//! ```
//!
//! ## Endpoints
//!
//! | Method  | Path              | Auth   | Description                          |
//! |---------|-------------------|--------|--------------------------------------|
//! | POST    | `/.well-known/auth` | none | BRC-31 Authrite handshake            |
//! | OPTIONS | `*`               | none   | CORS preflight                       |
//! | POST    | `/dkg/init`       | BRC-31 | Start DKG ceremony                   |
//! | POST    | `/dkg/round`      | BRC-31 | Process DKG round                    |
//! | POST    | `/sign/init`      | BRC-31 | Start signing                        |
//! | POST    | `/sign/round`     | BRC-31 | Process signing round                |
//! | POST    | `/presign/init`   | BRC-31 | Start presigning protocol            |
//! | POST    | `/presign/round`  | BRC-31 | Process presigning round             |
//! | GET     | `/health`         | none   | Liveness check + share count         |
//! | GET     | `/shares/:agent`  | BRC-31 | Share metadata (no secrets exposed)  |
//!
//! ## Security Model
//!
//! - All mutation endpoints require BRC-31 Authrite mutual authentication.
//! - Only the agent that owns a share can request signing with that share.
//! - Shares are encrypted with AES-256-GCM (BRC-42 derived keys) at rest.
//! - The Worker never sees the full private key — only its share.
//! - Durable Object SQLite provides per-agent isolation.

mod api;
pub mod auth;
mod poc;
mod storage;

use worker::*;

// ── Durable Object: MpcStorage ──────────────────────────────────────────────
//
// Stores key shares and protocol state in DO storage.
// Required by wrangler for the MPC_STORAGE binding declared in wrangler.toml.
// Currently a stub — protocol state is held in-memory (static HashMap/Mutex).
// Future: migrate to DO SQLite for persistence across Worker restarts.

#[durable_object]
pub struct MpcStorage {
    #[allow(dead_code)]
    state: State,
    #[allow(dead_code)]
    env: Env,
}

impl DurableObject for MpcStorage {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, _req: Request) -> Result<Response> {
        Response::from_json(&serde_json::json!({
            "status": "ok",
            "message": "MpcStorage Durable Object"
        }))
    }
}

/// CF Worker fetch event handler.
///
/// Routes incoming HTTP requests to the appropriate MPC protocol handler.
/// All mutation endpoints (DKG, signing, presigning) require BRC-31 auth.
/// The handshake endpoint and health check are open.
#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // Handle CORS preflight for any path
    if req.method() == Method::Options {
        return auth::handle_cors_preflight();
    }

    let router = Router::new();

    router
        // ── BRC-31 Authrite handshake ────────────────────────────────
        .post_async("/.well-known/auth", |req, ctx| async move {
            let config = auth::AuthConfig::from_env(&ctx.env)?;
            auth::handle_initial_request(req, &config).await
        })
        // ── DKG protocol endpoints (BRC-31 protected) ───────────────
        .post_async("/dkg/init", |req, ctx| async move {
            let config = auth::AuthConfig::from_env(&ctx.env)?;
            if let Err(resp) = auth::verify_or_allow(&req, &config) {
                return Ok(resp);
            }
            api::handle_dkg_init(req, &ctx).await
        })
        .post_async("/dkg/round", |req, ctx| async move {
            let config = auth::AuthConfig::from_env(&ctx.env)?;
            if let Err(resp) = auth::verify_or_allow(&req, &config) {
                return Ok(resp);
            }
            api::handle_dkg_round(req, &ctx).await
        })
        // ── Signing protocol endpoints (BRC-31 protected) ───────────
        .post_async("/sign/init", |req, ctx| async move {
            let config = auth::AuthConfig::from_env(&ctx.env)?;
            if let Err(resp) = auth::verify_or_allow(&req, &config) {
                return Ok(resp);
            }
            api::handle_sign_init(req, &ctx).await
        })
        .post_async("/sign/round", |req, ctx| async move {
            let config = auth::AuthConfig::from_env(&ctx.env)?;
            if let Err(resp) = auth::verify_or_allow(&req, &config) {
                return Ok(resp);
            }
            api::handle_sign_round(req, &ctx).await
        })
        // ── Presigning protocol endpoints (BRC-31 protected) ────────
        .post_async("/presign/init", |req, ctx| async move {
            let config = auth::AuthConfig::from_env(&ctx.env)?;
            if let Err(resp) = auth::verify_or_allow(&req, &config) {
                return Ok(resp);
            }
            api::handle_presign_init(req, &ctx).await
        })
        .post_async("/presign/round", |req, ctx| async move {
            let config = auth::AuthConfig::from_env(&ctx.env)?;
            if let Err(resp) = auth::verify_or_allow(&req, &config) {
                return Ok(resp);
            }
            api::handle_presign_round(req, &ctx).await
        })
        // ── Partial ECDH endpoint (BRC-31 protected) ───────────────
        .post_async("/ecdh", |req, ctx| async move {
            let config = auth::AuthConfig::from_env(&ctx.env)?;
            if let Err(resp) = auth::verify_or_allow(&req, &config) {
                return Ok(resp);
            }
            api::handle_ecdh(req, &ctx).await
        })
        // ── Read-only endpoints (no auth required) ──────────────────
        .get_async("/health", |_req, ctx| async move {
            api::handle_health(&ctx).await
        })
        .get_async("/shares/:agent_id", |req, ctx| async move {
            // Share metadata requires auth in production
            let config = auth::AuthConfig::from_env(&ctx.env)?;
            if let Err(resp) = auth::verify_or_allow(&req, &config) {
                return Ok(resp);
            }
            let agent_id = ctx.param("agent_id").unwrap();
            api::handle_get_share_metadata(agent_id, &ctx).await
        })
        // ── Phase I-3b POC: DO SQLite persistence + hibernation ─────
        // Forwarded to the per-identity CosignerSessionDo (DO SQLite +
        // stable identity from SERVER_PRIVATE_KEY). Proves the fund-safety
        // persistence primitive on the deployed Worker (gated at runtime by
        // the I-3c deploy + forced-hibernation harness).
        .get_async("/poc/identity", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        .post_async("/poc/persist", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        // I-3b2: relay-handshake-from-DO — outbound Socket.IO + BRC-103 +
        // envelope round-trip against the live MessageBox relay, driven from
        // inside the per-identity CosignerSessionDo (wasm32 transport).
        .get_async("/poc/handshake", |req, ctx| async move {
            poc::forward_to_cosigner_do(req, &ctx.env).await
        })
        .run(req, env)
        .await
}
