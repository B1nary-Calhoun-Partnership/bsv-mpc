// #17 CF Container P2 — Worker proxy for the full native bsv-mpc-service.
// The Container DO class (from @cloudflare/containers) runs the native Rust
// bsv-mpc-service image; the Worker routes every request to a singleton
// instance. defaultPort must match the service's bind port (MPC_SERVICE_PORT,
// set to 8080 in the Dockerfile).
import { Container, getContainer } from "@cloudflare/containers";

export class BsvMpcServiceContainer extends Container {
  defaultPort = 8080;
  sleepAfter = "5m";
}

export default {
  async fetch(request, env) {
    return getContainer(env.BSV_MPC_SERVICE, "singleton").fetch(request);
  },
};
