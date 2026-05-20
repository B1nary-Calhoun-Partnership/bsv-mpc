// Minimal Worker proxy for the CF Containers platform probe (P1).
// The Container DO class (from @cloudflare/containers) runs the native Rust
// image; the Worker routes every request to a singleton container instance.
import { Container, getContainer } from "@cloudflare/containers";

export class BsvMpcContainer extends Container {
  defaultPort = 8080; // must match the container's listen port
  sleepAfter = "5m";
}

export default {
  async fetch(request, env) {
    // Single shared container instance for the probe.
    return getContainer(env.BSV_MPC_CONTAINER, "singleton").fetch(request);
  },
};
