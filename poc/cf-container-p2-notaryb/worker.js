// #17 CF Container P2 — Worker proxy for the full native bsv-mpc-service.
// The Container DO class (from @cloudflare/containers) runs the native Rust
// bsv-mpc-service image; the Worker routes every request to a singleton
// instance. defaultPort must match the service's bind port (MPC_SERVICE_PORT,
// set to 8080 in the Dockerfile).
import { Container, getContainer } from "@cloudflare/containers";

export class BsvMpcServiceContainer extends Container {
  defaultPort = 8080;
  // Longer than a full DKG/presig ceremony so a mid-sequence gap can't sleep the
  // container and drop the in-memory COORDINATOR_STORE session state. (CF default
  // is 10m; a multi-round Paillier DKG can exceed that on a busy/slow instance.)
  sleepAfter = "30m";

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

  // Readiness barrier (#40/#58). The base Container.fetch() auto-STARTS the
  // instance but does NOT await port-readiness, so the first request after a
  // cold start — OR after an OOM restart — races the native process coming up
  // and fails with "container is not running". Block on startAndWaitForPorts
  // before forwarding so every request lands on a process that is actually
  // listening. portReadyTimeoutMS:30000 covers the slow native cold start
  // (release binary + glibc init); the heavy MPC work happens AFTER this.
  async fetch(request) {
    await this.startAndWaitForPorts({
      ports: [this.defaultPort],
      cancellationOptions: { portReadyTimeoutMS: 30000 },
    });
    return this.containerFetch(request, this.defaultPort);
  }

  // Lifecycle hooks run in the Worker/DO context (NOT container stdout), so
  // they DO surface in `wrangler tail`. onStop with a non-zero exitCode and
  // reason "runtime_signal" is the signature of an OOM kill — this is how we
  // CONFIRM (vs. merely suspect) the #40/#58 instability is memory, not code.
  onStart() {
    console.log("[container] onStart: bsv-mpc-service instance started");
  }

  onStop({ exitCode, reason }) {
    console.log(`[container] onStop: exitCode=${exitCode} reason=${reason}`);
  }

  onError(error) {
    console.error(`[container] onError: ${error}`);
  }
}

export default {
  async fetch(request, env) {
    return getContainer(env.BSV_MPC_SERVICE, "singleton").fetch(request);
  },
};
