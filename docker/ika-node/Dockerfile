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

# Set working directory
WORKDIR ${WORKDIR}/ika

# --------------------------
# SSH key for private git (secure via BuildKit secret)
# --------------------------
# secret is injected at build time by docker/build-push-action:
#   secrets: |
#     GH_DEPLOY_KEY=${{ secrets.GH_DEPLOY_KEY }}
RUN --mount=type=secret,id=GH_DEPLOY_KEY \
    mkdir -p ~/.ssh && \
    cp /run/secrets/GH_DEPLOY_KEY ~/.ssh/id_ed25519 && \
    chmod 600 ~/.ssh/id_ed25519 && \
    ssh-keyscan github.com >> ~/.ssh/known_hosts

# Rewrite GitHub HTTPS to SSH for the private dependency
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
# Workspace + deps
# --------------------------

# Root manifests
COPY Cargo.toml Cargo.lock ./

# Copy the full workspace directories so all members exist.
# (This fixes the `dwallet-mpc-centralized-party` missing manifest error.)
COPY crates crates
COPY contracts contracts
COPY deployed_contracts deployed_contracts

# Fetch dependencies according to Cargo.lock
RUN cargo fetch --locked

# Optional "warm-up" build to cache dependencies; we allow failure
# because code might not be fully present/valid yet, but deps get compiled.
RUN if [ "$NO_DEFAULT_FEATURES" = "true" ]; then \
      cargo build --profile ${PROFILE} --locked --bin ika-node --no-default-features || true; \
    else \
      cargo build --profile ${PROFILE} --locked --bin ika-node || true; \
    fi

# Now copy the rest of the repo (config, scripts, etc.)
COPY . .

# Final build
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

# Install runtime dependencies and jemalloc.
RUN apt-get update && apt-get install -y \
    libjemalloc-dev \
    ca-certificates \
    curl \
    jq

# If you really want jemalloc by default, you might prefer:
# ENV LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so
ENV LD_PRELOAD=""
RUN if [ "$TARGETARCH" = "amd64" ]; then \
      echo "/usr/lib/x86_64-linux-gnu/libjemalloc.so" > /etc/ld.so.preload; \
    fi

# Set working directory.
WORKDIR ${WORKDIR}/ika

# Copy the built binary from the builder stage.
COPY --from=builder /opt/ika/target/${PROFILE}/ika-node /usr/local/bin/ika-node

# Add build metadata.
LABEL build-date=$BUILD_DATE
LABEL git-revision=$GIT_REVISION