# ==========================
# Build stage
# ==========================
FROM rust:1.90-bullseye AS builder

# Arguments
ARG PROFILE=release
ARG GIT_REVISION=unknown
ARG GH_DEPLOY_KEY
ARG WORKDIR=/opt

# Environment
ENV CARGO_HOME=/usr/local/cargo
ENV GIT_REVISION=$GIT_REVISION

# Setup SSH for manual git
RUN mkdir -p ~/.ssh
RUN printf "%s" "${GH_DEPLOY_KEY}" > ~/.ssh/id_ed25519
RUN chmod 600 ~/.ssh/id_ed25519
RUN ssh-keyscan github.com >> ~/.ssh/known_hosts

# Globally rewrite any GitHub HTTPS to SSH
RUN git config --global url."git@github.com:dwallet-labs/cryptography-private".insteadOf "https://github.com/dwallet-labs/cryptography-private"

# Install build dependencies
RUN apt-get update && apt-get install -y cmake clang pkg-config libssl-dev
# Set working directory
WORKDIR ${WORKDIR}/ika

# Copy Cargo manifests and crate folders for dependency resolution
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY contracts contracts
COPY deployed_contracts deployed_contracts

# Build dependencies first for better layer caching
# --locked ensures you never accidentally change dependencies during a build.
# Build dependencies first for better layer caching
RUN cargo fetch --locked

# Conditionally compile with the network DKG feature
RUN cargo build --profile ${PROFILE} --locked --bin ika-proxy
# ==========================
# Runtime stage
# ==========================
FROM debian:bookworm-slim AS runtime

# CA certificates and other dependencies for debug.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl


ARG PROFILE=release


# Copy the built binary from the builder stage.
COPY --from=builder --chmod=755 /opt/ika/target/${PROFILE}/ika-proxy /opt/ika/bin/ika-proxy
