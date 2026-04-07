FROM rust:1.94-bookworm AS builder
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build --locked --release -p swarm-runtime --bin swarm_detect --bin swarmctl \
    && strip target/release/swarm_detect \
    && strip target/release/swarmctl

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r swarm \
    && useradd -r -g swarm -d /app swarm

WORKDIR /app

COPY --from=builder /src/target/release/swarm_detect /usr/local/bin/swarm_detect
COPY --from=builder /src/target/release/swarmctl /usr/local/bin/swarmctl
COPY rulesets/ /app/rulesets/

USER swarm

EXPOSE 9090

ENTRYPOINT ["/usr/local/bin/swarm_detect"]
CMD ["--config", "/app/rulesets/default.yaml", "--serve", "--bind", "0.0.0.0:9090"]
