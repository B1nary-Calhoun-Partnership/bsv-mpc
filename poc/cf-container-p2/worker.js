// #17 CF Container P2 — Worker proxy for the full native bsv-mpc-service.
// The Container DO class (from @cloudflare/containers) runs the native Rust
// bsv-mpc-service image; the Worker routes every request to a singleton
// instance. defaultPort must match the service's bind port (MPC_SERVICE_PORT,
// set to 8080 in the Dockerfile).
import { Container, getContainer } from "@cloudflare/containers";

export class BsvMpcServiceContainer extends Container {
  defaultPort = 8080;
  sleepAfter = "5m";

  constructor(ctx, env, options) {
    super(ctx, env, options);
    // §07.6: inject the cosigner's BRC-31 server identity from a Worker SECRET
    // (`wrangler secret put MPC_SERVER_PRIVATE_KEY`) into the container at start —
    // NOT baked into the committed image. When set, the native service enforces
    // BRC-31 owner-authz on /dkg, /sign, /presign, /ecdh; when absent it stays
    // in dev mode (unenforced).
    //
    // This MUST be an instance assignment AFTER super(): the base `Container`
    // defines `envVars = {}` as an instance field, which would shadow a subclass
    // *getter* (own data property beats a prototype accessor). Assigning here
    // (after the base field initializes) overrides it with the live value.
    const key = env?.MPC_SERVER_PRIVATE_KEY;
    this.envVars = key ? { MPC_SERVER_PRIVATE_KEY: key } : {};
  }
}

export default {
  async fetch(request, env) {
    return getContainer(env.BSV_MPC_SERVICE, "singleton").fetch(request);
  },
};
