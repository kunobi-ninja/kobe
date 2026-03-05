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
RUN cargo build --release --bin kunobi-pool-operator --bin kobe-sync
