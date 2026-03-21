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
//! | Method | Path              | Description                                  |
//! |--------|-------------------|----------------------------------------------|
//! | POST   | `/dkg/init`       | Start DKG ceremony, return round 1 message   |
//! | POST   | `/dkg/round`      | Process DKG round, return next or complete    |
//! | POST   | `/sign/init`      | Start signing, return round 1 message         |
//! | POST   | `/sign/round`     | Process signing round, return sig or next     |
//! | POST   | `/presign/init`   | Start presigning protocol                     |
//! | POST   | `/presign/round`  | Process presigning round                      |
//! | GET    | `/health`         | Liveness check + share count                  |
//! | GET    | `/shares/:agent`  | Share metadata (no secrets exposed)            |
//!
//! ## Security Model
//!
//! - All endpoints require BRC-31 Authrite mutual authentication.
//! - Only the agent that owns a share can request signing with that share.
//! - Shares are encrypted with AES-256-GCM (BRC-42 derived keys) at rest.
//! - The Worker never sees the full private key — only its share.
//! - Durable Object SQLite provides per-agent isolation.

mod api;
mod auth;
mod storage;

use worker::*;

/// CF Worker fetch event handler.
///
/// Routes incoming HTTP requests to the appropriate MPC protocol handler.
/// All mutation endpoints (DKG, signing, presigning) require BRC-31 auth.
#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();

    router
        // DKG protocol endpoints
        .post_async("/dkg/init", |req, ctx| async move {
            api::handle_dkg_init(req, &ctx).await
        })
        .post_async("/dkg/round", |req, ctx| async move {
            api::handle_dkg_round(req, &ctx).await
        })
        // Signing protocol endpoints
        .post_async("/sign/init", |req, ctx| async move {
            api::handle_sign_init(req, &ctx).await
        })
        .post_async("/sign/round", |req, ctx| async move {
            api::handle_sign_round(req, &ctx).await
        })
        // Presigning protocol endpoints
        .post_async("/presign/init", |req, ctx| async move {
            api::handle_presign_init(req, &ctx).await
        })
        .post_async("/presign/round", |req, ctx| async move {
            api::handle_presign_round(req, &ctx).await
        })
        // Read-only endpoints
        .get_async("/health", |_req, ctx| async move {
            api::handle_health(&ctx).await
        })
        .get_async("/shares/:agent_id", |_req, ctx| async move {
            let agent_id = ctx.param("agent_id").unwrap();
            api::handle_get_share_metadata(agent_id, &ctx).await
        })
        .run(req, env)
        .await
}
