# ==========================
# Build stage for current version (v2)
# ==========================
FROM rust:1.88-bullseye AS builder-v2

ARG GIT_REVISION=unknown
ARG WORKDIR=/opt
ARG CARGO_BUILD_FLAGS
ARG GITHUB_TOKEN

# Environment
ENV CARGO_HOME=/usr/local/cargo
ENV GIT_REVISION=$GIT_REVISION
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
# Install build dependencies
RUN apt-get update && apt-get install -y cmake clang pkg-config libssl-dev git
# Set working directory
WORKDIR ${WORKDIR}/ika

# Copy Cargo manifests and crate folders for dependency resolution
# Note: The build context is now the parent directory, so we need to copy from dwallet-network-original
COPY dwallet-network-original/Cargo.toml dwallet-network-original/Cargo.lock ./
COPY dwallet-network-original/crates crates
COPY dwallet-network-original/contracts contracts
COPY dwallet-network-original/deployed_contracts deployed_contracts
RUN git config --global url."https://x-access-token:$GITHUB_TOKEN@github.com/".insteadOf "https://github.com/"
RUN cargo build ${CARGO_BUILD_FLAGS} --profile release --bin ika-node

# ==========================
# Build stage for old version (v1)
# ==========================
FROM rust:1.88-bullseye AS builder-v1

ARG GIT_REVISION=unknown
ARG WORKDIR=/opt
ARG CARGO_BUILD_FLAGS
ARG GITHUB_TOKEN

# Environment
ENV CARGO_HOME=/usr/local/cargo
ENV GIT_REVISION=$GIT_REVISION
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
# Install build dependencies
RUN apt-get update && apt-get install -y cmake clang pkg-config libssl-dev git
# Set working directory
WORKDIR ${WORKDIR}/dwallet-network

# Copy Cargo manifests and crate folders for dependency resolution from old version
# Note: The build context is now the parent directory, so we can access both dwallet-network and dwallet-network-original
COPY dwallet-network/Cargo.toml dwallet-network/Cargo.lock ./
COPY dwallet-network/crates crates
COPY dwallet-network/contracts contracts
COPY dwallet-network/deployed_contracts deployed_contracts
RUN git config --global url."https://x-access-token:$GITHUB_TOKEN@github.com/".insteadOf "https://github.com/"
RUN cargo build ${CARGO_BUILD_FLAGS} --profile release --bin ika-node

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

# Create bin directory
RUN mkdir -p /opt/ika/bin

# Copy the built binaries from both builder stages with version naming
# Current version (v2)
COPY --from=builder-v2 /opt/ika/target/${PROFILE}/ika-node /opt/ika/bin/ika-node-v2
COPY --from=builder-v2 /opt/ika/target/${PROFILE}/ika-node /usr/local/bin/ika-node-v22

# Old version (v1)
COPY --from=builder-v1 /opt/dwallet-network/target/${PROFILE}/ika-node /opt/ika/bin/ika-node-v1
COPY --from=builder-v1 /opt/dwallet-network/target/${PROFILE}/ika-node /usr/local/bin/ika-node-v1

# Create symlinks for backward compatibility (default to v2)
RUN ln -s /usr/local/bin/ika-node-v2 /usr/local/bin/ika-node

# Add build metadata.
LABEL build-date=$BUILD_DATE
LABEL git-revision=$GIT_REVISION
