# syntax=docker/dockerfile:1.7

FROM rust:1.90-bullseye AS builder

ARG PROFILE=release
ARG GIT_REVISION=unknown
ARG WORKDIR=/opt
ARG NO_DEFAULT_FEATURES=false

ENV CARGO_HOME=/usr/local/cargo
ENV GIT_REVISION=$GIT_REVISION

WORKDIR ${WORKDIR}/ika

# --------------------------
# SSH key for private git (secure)
# --------------------------
# GH_DEPLOY_KEY is provided as a BuildKit secret
RUN --mount=type=secret,id=GH_DEPLOY_KEY \
    mkdir -p ~/.ssh && \
    cp /run/secrets/GH_DEPLOY_KEY ~/.ssh/id_ed25519 && \
    chmod 600 ~/.ssh/id_ed25519 && \
    ssh-keyscan github.com >> ~/.ssh/known_hosts

# Rewrite GitHub HTTPS to SSH
RUN git config --global \
    url."git@github.com:dwallet-labs/cryptography-private".insteadOf \
    "https://github.com/dwallet-labs/cryptography-private"

# Build dependencies
RUN apt-get update && apt-get install -y \
    cmake clang pkg-config libssl-dev

# Cargo workspace manifests
COPY Cargo.toml Cargo.lock ./
COPY crates/*/Cargo.toml crates/*/Cargo.toml
COPY contracts/*/Cargo.toml contracts/*/Cargo.toml
COPY deployed_contracts/*/Cargo.toml deployed_contracts/*/Cargo.toml

RUN cargo fetch --locked

# Cache-heavy dependency compilation layer
RUN if [ "$NO_DEFAULT_FEATURES" = "true" ]; then \
      cargo build --profile ${PROFILE} --locked --bin ika-node --no-default-features || true; \
    else \
      cargo build --profile ${PROFILE} --locked --bin ika-node || true; \
    fi

# Full source
COPY . .

RUN if [ "$NO_DEFAULT_FEATURES" = "true" ]; then \
      cargo build --profile ${PROFILE} --locked --bin ika-node --no-default-features; \
    else \
      cargo build --profile ${PROFILE} --locked --bin ika-node; \
    fi

# ==========================
# Runtime
# ==========================
FROM debian:stable-slim AS runtime

ARG WORKDIR=/opt
ARG BUILD_DATE
ARG GIT_REVISION
ARG PROFILE=release
ARG TARGETARCH

RUN apt-get update && apt-get install -y \
    libjemalloc-dev \
    ca-certificates \
    curl \
    jq

WORKDIR ${WORKDIR}/ika

COPY --from=builder /opt/ika/target/${PROFILE}/ika-node /usr/local/bin/ika-node

LABEL build-date=$BUILD_DATE
LABEL git-revision=$GIT_REVISION