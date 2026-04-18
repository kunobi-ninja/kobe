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
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/cli/commands && \
    echo "pub fn stub() {}" > src/lib.rs && \
    echo "fn main() {}" > src/cli/main.rs && \
    cargo build --release --lib 2>/dev/null || true && \
    rm -rf src

# Build the real binaries — clean slate for kobe crates
FROM deps AS build

ARG BUILD_VERSION=dev
ENV BUILD_VERSION=${BUILD_VERSION}

COPY . .
RUN cargo build --release --bin kobe-operator --bin kobe-sync --bin kobe --bin kubeconfig-publisher && \
    ls -la target/release/kobe-operator target/release/kobe-sync target/release/kobe target/release/kubeconfig-publisher
