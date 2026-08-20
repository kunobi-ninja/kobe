# =============================================================================
# Builder — compile both release binaries
# Used as a named context by operator and kobe-sync Dockerfiles via Bake.
# =============================================================================
FROM rust:1-slim-bookworm AS deps

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install 1.95.0 && \
    rustup default 1.95.0

WORKDIR /app

# Cache dependencies only — compile a lib stub, never a binary.
# This populates the cargo registry + dep artifacts without creating
# any kobe binaries that could be confused with real ones.
#
# kobe is now a Cargo workspace: the `crates/kobectl` member manifest must be
# present for cargo to load the workspace, so copy it (+ a stub bin source). We
# still only cache the ROOT (operator) deps via the lib stub; the CLI member's
# unique deps aren't compiled here — the operator images never include the CLI.
COPY Cargo.toml Cargo.lock ./
COPY crates/kobectl/Cargo.toml crates/kobectl/Cargo.toml
# The runner member is a real dependency of the operator (it owns the wire
# contract in `src/protocol.rs`), so its manifest AND a lib stub have to exist
# or the root package cannot resolve during dependency caching.
COPY crates/kobe-runner/Cargo.toml crates/kobe-runner/Cargo.toml
RUN mkdir -p src crates/kobectl/src crates/kobe-runner/src && \
    echo "pub fn stub() {}" > src/lib.rs && \
    echo "fn main() {}" > crates/kobectl/src/main.rs && \
    echo "fn main() {}" > crates/kobe-runner/src/main.rs && \
    echo "pub fn stub() {}" > crates/kobe-runner/src/lib.rs && \
    cargo build --release --lib 2>/dev/null || true && \
    rm -rf src crates/kobectl/src crates/kobe-runner/src

# Build the real binaries — clean slate for kobe crates
FROM deps AS build

ARG BUILD_VERSION=dev
ENV BUILD_VERSION=${BUILD_VERSION}
# Read by build.rs and baked into the binaries, so a running process can state
# which commit it was built from. Set here in the `build` stage rather than in
# `deps`: the layer below is invalidated by `COPY . .` on every commit anyway,
# so a per-commit ENV costs no extra cache — while putting it in `deps` would
# rebuild every dependency on each commit.
ARG BUILD_COMMIT=unknown
ENV BUILD_COMMIT=${BUILD_COMMIT}

COPY . .
# Operator-side binaries only (the `kobe` CLI lives in the kobectl member and is
# released as a signed standalone binary, not bundled in the operator image).
# The dependency layer compiled stub sources for both workspace packages.
# Their mtimes can be newer than the real files copied above, so Cargo may
# otherwise reuse a stub `kobe-runner` library with no `protocol` module.
RUN cargo clean --release -p kobe-operator -p kobe-runner && \
    cargo build --release --bin kobe-operator --bin kobe-sync --bin kubeconfig-publisher --bin kobe-host-reaper && \
    ls -la target/release/kobe-operator target/release/kobe-sync target/release/kubeconfig-publisher target/release/kobe-host-reaper
