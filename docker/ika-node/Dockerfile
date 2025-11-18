# syntax=docker/dockerfile:1.7

# ==========================
# Build stage
# ==========================
FROM rust:1.90-bullseye AS builder

# Arguments
ARG PROFILE=release
ARG GIT_REVISION=unknown
ARG WORKDIR=/opt
ARG NO_DEFAULT_FEATURES=false

# Environment
ENV CARGO_HOME=/usr/local/cargo
ENV GIT_REVISION=$GIT_REVISION
# Avoid rustup trying to self-update and download extra toolchains
ENV RUSTUP_NO_SELF_UPDATE=1

# Set working directory
WORKDIR ${WORKDIR}/ika

# --------------------------
# SSH key for private git (via BuildKit secret)
# --------------------------
# Secret is provided by docker/build-push-action:
#   secrets:
#     GH_DEPLOY_KEY=${{ secrets.GH_DEPLOY_KEY }}
RUN --mount=type=secret,id=GH_DEPLOY_KEY \
    mkdir -p ~/.ssh && \
    cp /run/secrets/GH_DEPLOY_KEY ~/.ssh/id_ed25519 && \
    chmod 600 ~/.ssh/id_ed25519 && \
    ssh-keyscan github.com >> ~/.ssh/known_hosts

# Rewrite GitHub HTTPS to SSH for private dependency
RUN git config --global \
    url."git@github.com:dwallet-labs/cryptography-private".insteadOf \
    "https://github.com/dwallet-labs/cryptography-private"

# Install build dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    clang \
    pkg-config \
    libssl-dev

# --------------------------
# Workspace + dependencies
# --------------------------

# Root manifests
COPY Cargo.toml Cargo.lock ./

# Copy the full workspace directories so all members are present
COPY crates crates
COPY contracts contracts
COPY deployed_contracts deployed_contracts

# Fetch dependencies according to Cargo.lock
RUN cargo fetch --locked

# Copy the rest of the repo (configs, scripts, etc.)
COPY . .

# Single actual build
RUN if [ "$NO_DEFAULT_FEATURES" = "true" ]; then \
      cargo build --profile ${PROFILE} --locked --bin ika-node --no-default-features; \
    else \
      cargo build --profile ${PROFILE} --locked --bin ika-node; \
    fi

# ==========================
# Runtime stage
# ==========================
FROM debian:stable-slim AS runtime

ARG WORKDIR=/opt
ARG BUILD_DATE
ARG GIT_REVISION
ARG PROFILE=release
ARG TARGETARCH

# Install runtime dependencies and jemalloc
RUN apt-get update && apt-get install -y \
    libjemalloc-dev \
    ca-certificates \
    curl \
    jq

# Set working directory
WORKDIR ${WORKDIR}/ika

# Copy the built binary from the builder stage
COPY --from=builder /opt/ika/target/${PROFILE}/ika-node /usr/local/bin/ika-node

# Build metadata
LABEL build-date=$BUILD_DATE
LABEL git-revision=$GIT_REVISION