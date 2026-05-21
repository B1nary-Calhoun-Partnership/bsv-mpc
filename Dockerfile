# CF Container P2 (#17) — full native bsv-mpc-service image.
#
# Build context = workspace root (cargo must see every workspace member's
# manifest to resolve). cggmp24 / bsv-rs are git+crates.io deps (no submodule),
# so the BUILD stage needs network + git; the cggmp21 patch rev is pinned in
# Cargo.lock (--locked). Heavy ~5-15min release compile (Paillier + num-bigint).
#
# Runtime: pure-Rust crypto (backend-num-bigint, no GMP), so a slim glibc base
# suffices. The service binds 0.0.0.0:$MPC_SERVICE_PORT and is the CF Container
# `defaultPort` target (8080).

# bsv-rs / reqwest pull native-tls (default-tls) → openssl-sys, so the build
# needs libssl-dev + pkg-config (feature unification means the workspace can't
# turn this off; the host build links system OpenSSL too). The runtime stage
# then needs the matching libssl3 shared lib.
FROM rust:1.85-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# --locked pins the cggmp21 patch rev from Cargo.lock; fall back if the lockfile
# is momentarily out of sync with a manifest edit.
RUN cargo build --release -p bsv-mpc-service --locked \
 || cargo build --release -p bsv-mpc-service

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m app \
 && mkdir -p /data \
 && chown app /data
COPY --from=build /src/target/release/bsv-mpc-service /usr/local/bin/bsv-mpc-service
USER app
EXPOSE 8080
ENV MPC_SERVICE_PORT=8080
ENV MPC_DATA_DIR=/data
# #4 self-stocking: ship each generated Presignature_A to the cosigner DO pool.
# MPC_WORKER_URL is the (public) DO worker base URL — not a secret. The BRC-31
# auth identity is ephemeral (generated at startup) unless MPC_SERVICE_AUTH_KEY
# is provided, so no key is committed to the image.
ENV MPC_WORKER_URL=https://bsv-mpc-kss.dev-a3e.workers.dev
CMD ["bsv-mpc-service"]
