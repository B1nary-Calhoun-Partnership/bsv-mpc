# Multi-stage: build the tiny Rust axum binary, run it on a slim Debian base.
FROM rust:1.85-slim AS build
WORKDIR /app
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release --locked || cargo build --release

FROM debian:bookworm-slim
RUN useradd -m app
COPY --from=build /app/target/release/poc-cf-container /usr/local/bin/poc-cf-container
USER app
EXPOSE 8080
ENV PORT=8080
CMD ["poc-cf-container"]
