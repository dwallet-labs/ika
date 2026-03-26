# ==========================
# Build stage
# ==========================
FROM rust:1.94-bookworm AS builder

# Arguments
ARG PROFILE=release
ARG GIT_REVISION=unknown
ARG GH_DEPLOY_KEY
ARG WORKDIR=/opt
ARG BIN=ika-validator

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
RUN cargo fetch --locked

RUN cargo build --profile ${PROFILE} --locked --bin ${BIN}

# ==========================
# Runtime stage
# ==========================
FROM debian:stable-slim AS runtime

ARG WORKDIR=/opt
ARG BUILD_DATE
ARG GIT_REVISION
ARG PROFILE=release
ARG BIN=ika-validator
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
COPY --from=builder /opt/ika/target/${PROFILE}/${BIN} /opt/ika/bin/${BIN}
COPY --from=builder /opt/ika/target/${PROFILE}/${BIN} /usr/local/bin/${BIN}

# Add build metadata.
LABEL build-date=$BUILD_DATE
LABEL git-revision=$GIT_REVISION
