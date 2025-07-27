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
RUN cargo build --profile ${PROFILE} --locked --bin ika-node

# ==========================
# Runtime stage
# ==========================
FROM debian:bullseye-slim AS runtime

ARG WORKDIR=/opt
ARG BUILD_DATE
ARG GIT_REVISION
ARG PROFILE=release
ARG TARGETARCH

# Install runtime dependencies and jemalloc.
RUN apt-get update && apt-get install -y libjemalloc-dev ca-certificates curl jq

# Use jemalloc as memory allocator.
ENV LD_PRELOAD=""
RUN if [ "$TARGETARCH" = "amd64" ]; then \
      LD_PRELOAD="/usr/lib/x86_64-linux-gnu/libjemalloc.so"; \
    fi

# Set working directory.
WORKDIR ${WORKDIR}/ika

# Copy the built binary from the builder stage.
COPY --from=builder /opt/ika/target/${PROFILE}/ika-node /opt/ika/bin/ika-node
COPY --from=builder /opt/ika/target/${PROFILE}/ika-node /usr/local/bin/ika-node

# Add build metadata.
LABEL build-date=$BUILD_DATE
LABEL git-revision=$GIT_REVISION

