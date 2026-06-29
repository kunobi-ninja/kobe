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
RUN mkdir -p src crates/kobectl/src && \
    echo "pub fn stub() {}" > src/lib.rs && \
    echo "fn main() {}" > crates/kobectl/src/main.rs && \
    cargo build --release --lib 2>/dev/null || true && \
    rm -rf src crates/kobectl/src

# Build the real binaries — clean slate for kobe crates
FROM deps AS build

ARG BUILD_VERSION=dev
ENV BUILD_VERSION=${BUILD_VERSION}

COPY . .
# Operator-side binaries only (the `kobe` CLI lives in the kobectl member and is
# released as a signed standalone binary, not bundled in the operator image).
RUN cargo build --release --bin kobe-operator --bin kobe-sync --bin kubeconfig-publisher --bin kobe-host-reaper && \
    ls -la target/release/kobe-operator target/release/kobe-sync target/release/kubeconfig-publisher target/release/kobe-host-reaper
