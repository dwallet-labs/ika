# ==========================
# Build stage
# ==========================
FROM rust:1.85-bullseye AS builder

# Arguments
ARG PROFILE=release
ARG GIT_REVISION=unknown
ARG GITHUB_TOKEN
ARG WORKDIR=/opt

# Environment
ENV CARGO_HOME=/usr/local/cargo
ENV GIT_REVISION=$GIT_REVISION

# Setup GitHub token for private repos
RUN git config --global url."https://${GITHUB_TOKEN}:x-oauth-basic@github.com/".insteadOf "https://github.com/"

# Install build dependencies
RUN apt-get update && apt-get install -y cmake clang pkg-config libssl-dev
# Set working directory
WORKDIR ${WORKDIR}/ika

# Copy Cargo manifests and crate folders for dependency resolution
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY class-groups-keys-mock-files class-groups-keys-mock-files

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

ARG PROFILE=release


# Copy the built binary from the builder stage.
COPY --from=builder --chmod=755 /opt/ika/target/${PROFILE}/ika-proxy /opt/ika/bin/ika-proxy
