# --- Stage 1: dependency cache layer ---
ARG RUST_VERSION=1.93
FROM rust:${RUST_VERSION}-bookworm AS deps

WORKDIR /app
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs so cargo can resolve and cache dependencies.
# This layer is only rebuilt when Cargo.toml or Cargo.lock change.
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release && rm -rf src target/release/deps/kunobi_pool_operator*

# --- Stage 2: build the actual binary ---
FROM deps AS builder

COPY src/ src/
RUN cargo build --release

# --- Stage 3: runtime ---
FROM debian:bookworm-slim

ARG BUILD_VERSION=dev
ARG BUILD_COMMIT=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.source="https://github.com/kunobi-ninja/wagyu"
LABEL org.opencontainers.image.version="${BUILD_VERSION}"
LABEL org.opencontainers.image.revision="${BUILD_COMMIT}"

# Minimal runtime — all cluster lifecycle goes through kube-rs (no CLI tools needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/kunobi-pool-operator /usr/local/bin/

RUN groupadd -rf operator && useradd -r -g operator -d /home/operator -m operator || true
USER operator

ENV BUILD_VERSION=${BUILD_VERSION}
ENV BUILD_COMMIT=${BUILD_COMMIT}

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO /dev/null http://localhost:8080/healthz || exit 1

ENTRYPOINT ["kunobi-pool-operator"]
