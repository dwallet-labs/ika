# ==========================
# Unified builder — compiles all release binaries for a given target
# ==========================
# Usage:
#   Linux x64 (default):  docker build --output type=local,dest=out .
#   Linux arm64:          docker build --build-arg TARGET=aarch64-unknown-linux-gnu --output type=local,dest=out .
FROM rust:1.90-bullseye AS builder

ARG PROFILE=release
ARG GIT_REVISION=unknown
ARG GH_DEPLOY_KEY
ARG TARGET=x86_64-unknown-linux-gnu
ARG WORKDIR=/opt

# Which binaries to build. Infrastructure bins are Linux-only;
# desktop targets only need the CLI.
ARG BINS="ika ika-validator ika-fullnode ika-notifier ika-proxy"

ENV CARGO_HOME=/usr/local/cargo
ENV GIT_REVISION=$GIT_REVISION

# Setup SSH for private git dependencies
RUN mkdir -p ~/.ssh && \
    printf "%s" "${GH_DEPLOY_KEY}" > ~/.ssh/id_ed25519 && \
    chmod 600 ~/.ssh/id_ed25519 && \
    ssh-keyscan github.com >> ~/.ssh/known_hosts && \
    git config --global url."git@github.com:dwallet-labs/cryptography-private".insteadOf "https://github.com/dwallet-labs/cryptography-private"

# Install build dependencies
RUN apt-get update && apt-get install -y cmake clang pkg-config libssl-dev

# Install cross-compilation toolchain for arm64 if needed
RUN if [ "$TARGET" = "aarch64-unknown-linux-gnu" ]; then \
      apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross && \
      rustup target add aarch64-unknown-linux-gnu && \
      mkdir -p /root/.cargo && \
      printf '[target.aarch64-unknown-linux-gnu]\nlinker = "aarch64-linux-gnu-gcc"\n' >> /root/.cargo/config.toml; \
    fi

ENV CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
ENV CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++
ENV AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc

WORKDIR ${WORKDIR}/ika

# Copy source for dependency resolution and build
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY contracts contracts
COPY deployed_contracts deployed_contracts

RUN cargo fetch --locked

# Build all requested binaries in one pass (shares dependency artifacts)
RUN set -e; \
    BIN_FLAGS=""; \
    for bin in ${BINS}; do BIN_FLAGS="${BIN_FLAGS} --bin ${bin}"; done; \
    cargo build --profile ${PROFILE} --locked --target ${TARGET} ${BIN_FLAGS}

# Stage all binaries in a known location for extraction
RUN set -e; \
    mkdir -p /out; \
    for bin in ${BINS}; do \
      cp "target/${TARGET}/${PROFILE}/${bin}" "/out/${bin}"; \
    done; \
    chmod +x /out/*

FROM scratch AS export
COPY --from=builder /out/ /
