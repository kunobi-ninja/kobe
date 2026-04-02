# =============================================================================
# Builder — compile both release binaries
# Used as a named context by operator and kobe-sync Dockerfiles via Bake.
# =============================================================================
FROM rust:1.93-slim-bookworm AS deps

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependencies: copy manifests first, build a dummy to populate cargo cache
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src

# Build the real binaries
FROM deps AS build

COPY . .
RUN rm -rf target/release/kobe-operator target/release/kobe-sync \
           target/release/deps/kobe_operator* \
           target/release/deps/kobe_sync* \
           target/release/.fingerprint/kobe-operator* \
           target/release/.fingerprint/kobe-sync* \
           target/release/incremental/kobe_operator* \
           target/release/incremental/kobe_sync* && \
    cargo build --release --bin kobe-operator --bin kobe-sync && \
    ls -la target/release/kobe-operator target/release/kobe-sync
