FROM rust:1.94-bookworm

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY rulesets/ rulesets/
COPY deploy/integration-proof/ deploy/integration-proof/
COPY deploy/integration-proof/runtime.yaml integration-proof/runtime.yaml

RUN cargo build -p swarm-runtime --bin swarm_detect --bin swarmctl --bin swarm_debug_attest \
    && cargo run -p swarm-runtime --bin swarm_debug_attest -- \
        --binary /app/target/debug/swarm_detect \
        --config /app/integration-proof/runtime.yaml

EXPOSE 9090

ENTRYPOINT ["/app/target/debug/swarm_detect"]
CMD ["--config", "/app/integration-proof/runtime.yaml", "--serve", "--bind", "0.0.0.0:9090"]
