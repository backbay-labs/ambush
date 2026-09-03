# syntax=docker/dockerfile:1.7
#
# Public Ambush relay image — published as ghcr.io/backbay-labs/ambush:<tag>.
#
# Builds the `ambush-relay` binary (Rust 1.95) and the `ambush-web` static bundle
# (pnpm + vite), then assembles them into a small debian-slim runtime with
# `git` available (the relay shells out to git for repo hydrate / receive-pack
# / upload-pack — see crates/ambush-relay/src/api/git).
#
# Multi-arch is handled by running this same Dockerfile on native amd64 and
# native arm64 runners (see .github/workflows/docker.yml). The Dockerfile
# itself is platform-agnostic; do not add --platform pins.

ARG RUST_VERSION=1.95
ARG NODE_VERSION=24
ARG DEBIAN_VERSION=bookworm

# Optional extra CA bundle for builds behind a TLS-intercepting corporate proxy
# (e.g. a Cloudflare/Zscaler gateway that re-signs TLS). Empty by default, so
# public CI builds are unaffected. Point it at a PEM file in the build context:
#   docker build --build-arg EXTRA_CA_CERTS=path/to/proxy-ca.pem ...
# Consumed by the network-touching stages below (cargo + pnpm).
ARG EXTRA_CA_CERTS=

# Optional npm registry for builds where the public registry is unreachable or
# policy-blocked (e.g. a corporate mirror / Artifactory). Empty default = public
# npmjs, so public CI builds are unaffected. Consumed by the web-builder stage.
ARG NPM_REGISTRY=

# ─── Stage 1: cargo-chef base ───────────────────────────────────────────────
FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS chef
# Trust an optional corporate-proxy CA before any network fetch (no-op if unset).
ARG EXTRA_CA_CERTS
COPY --chmod=0644 ${EXTRA_CA_CERTS:-Dockerfile} /tmp/extra-ca/src
RUN if [ -n "${EXTRA_CA_CERTS}" ]; then \
        cp /tmp/extra-ca/src /usr/local/share/ca-certificates/extra-proxy-ca.crt \
        && update-ca-certificates \
        && echo "CARGO_HTTP_CAINFO=/etc/ssl/certs/ca-certificates.crt" >> /etc/environment; \
    fi
ENV CARGO_HTTP_CAINFO=/etc/ssl/certs/ca-certificates.crt
RUN cargo install cargo-chef --locked --version 0.1.71
WORKDIR /build

# ─── Stage 2: plan dependency graph ─────────────────────────────────────────
# Only the manifests are needed to compute the recipe; this layer rebuilds
# only when Cargo.{toml,lock} or crate manifests change, not on every source
# edit.
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ─── Stage 3: cook dependencies, then build the binary ──────────────────────
FROM chef AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libssl-dev \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*
# Keep enough DWARF for native profilers to resolve optimized code to source
# locations. The normal runtime strips it below; runtime-debug retains it.
ENV CARGO_PROFILE_RELEASE_DEBUG=line-tables-only
COPY --from=planner /build/recipe.json recipe.json
# Cook the full workspace recipe — relay deps include workspace siblings, so
# scoping to -p ambush-relay misses transitive deps and re-builds them later.
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
# Compile immutable artifact identity into the relay. Defaults preserve local
# and third-party builds that do not run in provenance-aware CI.
ARG AMBUSH_SOURCE_SHA=unknown
ARG AMBUSH_BUILD_ID=local
ARG AMBUSH_BUILD_URL=unknown
ENV AMBUSH_SOURCE_SHA=${AMBUSH_SOURCE_SHA} \
    AMBUSH_BUILD_ID=${AMBUSH_BUILD_ID} \
    AMBUSH_BUILD_URL=${AMBUSH_BUILD_URL}
RUN cargo build --release --locked -p ambush-relay --bin ambush-relay \
                                   -p ambush-admin --bin ambush-admin \
                                   -p ambush-pair-relay --bin ambush-pair-relay

# Derive the normal release binaries from the same optimized ELF files as the
# debug image so the two variants cannot drift at code-generation time.
FROM builder AS stripped-binaries
RUN strip target/release/ambush-relay \
    && strip target/release/ambush-admin \
    && strip target/release/ambush-pair-relay

# ─── Stage 4: web bundle (pnpm + vite) ──────────────────────────────────────
# Independent of the Rust layers so a CSS change doesn't bust Rust cache and
# vice versa.
FROM node:${NODE_VERSION}-${DEBIAN_VERSION}-slim AS web-builder
WORKDIR /build
# Trust an optional corporate-proxy CA so corepack + pnpm can fetch over an
# intercepting TLS gateway (no-op if EXTRA_CA_CERTS is unset).
ARG EXTRA_CA_CERTS
COPY --chmod=0644 ${EXTRA_CA_CERTS:-Dockerfile} /tmp/extra-ca/src
RUN if [ -n "${EXTRA_CA_CERTS}" ]; then \
        apt-get update && apt-get install -y --no-install-recommends ca-certificates \
        && cp /tmp/extra-ca/src /usr/local/share/ca-certificates/extra-proxy-ca.crt \
        && update-ca-certificates \
        && rm -rf /var/lib/apt/lists/*; \
    fi
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
# Point npm + corepack at an optional mirror (no-op when NPM_REGISTRY is unset).
# corepack reads COREPACK_NPM_REGISTRY to fetch the pinned pnpm; pnpm/npm read
# the .npmrc registry for dependency installs.
ARG NPM_REGISTRY
ENV COREPACK_NPM_REGISTRY=${NPM_REGISTRY}
# When using a mirror, disable corepack's npmjs signature check: the mirror
# republishes tarballs without the public registry's provenance signatures, so
# strict verification fails ("No compatible signature found"). Only relaxed on
# the mirror path — public builds (NPM_REGISTRY unset) keep strict verification.
RUN if [ -n "${NPM_REGISTRY}" ]; then \
        echo "registry=${NPM_REGISTRY}" > /build/.npmrc \
        && echo "COREPACK_INTEGRITY_KEYS=0" >> /etc/environment; \
    fi
ENV COREPACK_INTEGRITY_KEYS=${NPM_REGISTRY:+0}
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY patches/ patches/
COPY web/package.json web/
COPY admin-web/package.json admin-web/
RUN pnpm install --frozen-lockfile --filter ambush-web --filter ambush-admin-web
COPY web/ web/
COPY admin-web/ admin-web/
RUN pnpm -C web build && pnpm -C admin-web build

# ─── Stage 5: shared runtime ────────────────────────────────────────────────
FROM debian:${DEBIAN_VERSION}-slim AS runtime-base

# OCI annotations: required for GHCR to auto-link the image to this repo and
# inherit its visibility. org.opencontainers.image.source is the load-bearing
# one — without it GHCR keeps the image private even when the repo is public.
LABEL org.opencontainers.image.title="Ambush" \
      org.opencontainers.image.description="WebSocket relay server for the Ambush communications platform" \
      org.opencontainers.image.source="https://github.com/backbay-labs/ambush" \
      org.opencontainers.image.url="https://github.com/backbay-labs/ambush" \
      org.opencontainers.image.documentation="https://github.com/backbay-labs/ambush#readme" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        openssl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1000 ambush \
    && useradd  --system --uid 1000 --gid 1000 --home-dir /var/lib/ambush \
                --create-home --shell /usr/sbin/nologin ambush

COPY --from=web-builder /build/web/dist                 /srv/ambush/web
COPY --from=web-builder /build/admin-web/dist           /srv/ambush/admin-web

# The invite landing page is always served from the bundled web UI. Repository
# browser routes require the separate AMBUSH_SERVE_GIT_WEB_GUI=true opt-in. The
# admin bundle is inert until AMBUSH_ADMIN_HOST is configured.
ENV AMBUSH_WEB_DIR=/srv/ambush/web \
    AMBUSH_ADMIN_WEB_DIR=/srv/ambush/admin-web

# 3000: app (WS + REST)  ·  8080: /_liveness, /_readiness  ·  9102: /metrics
EXPOSE 3000 8080 9102

# deploy/compose mounts a volume here; pre-created so it inherits ambush:ambush.
RUN mkdir -p /data/git && chown ambush:ambush /data/git

USER ambush:ambush
WORKDIR /var/lib/ambush

ENTRYPOINT ["/usr/local/bin/ambush-relay"]

# Optimized binaries with line-table debug information for native profiling.
# Published under debug-* tags; runtime behavior otherwise matches the normal
# image exactly.
FROM runtime-base AS runtime-debug
COPY --from=builder /build/target/release/ambush-relay /usr/local/bin/ambush-relay
COPY --from=builder /build/target/release/ambush-admin /usr/local/bin/ambush-admin
COPY --from=builder /build/target/release/ambush-pair-relay /usr/local/bin/ambush-pair-relay

# Keep the stripped runtime as the final/default Dockerfile target so existing
# `docker build .` callers and release tags retain their current behavior.
FROM runtime-base AS runtime
COPY --from=stripped-binaries /build/target/release/ambush-relay /usr/local/bin/ambush-relay
COPY --from=stripped-binaries /build/target/release/ambush-admin /usr/local/bin/ambush-admin
COPY --from=stripped-binaries /build/target/release/ambush-pair-relay /usr/local/bin/ambush-pair-relay
