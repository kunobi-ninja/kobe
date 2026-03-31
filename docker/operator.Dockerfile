# =============================================================================
# kobe-operator — minimal runtime image
# =============================================================================
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r operator && useradd -r -g operator operator

USER operator

ARG BUILD_VERSION=dev
ARG BUILD_COMMIT=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="waygu-operator"
LABEL org.opencontainers.image.description="Kunobi cluster pool operator"
LABEL org.opencontainers.image.version="${BUILD_VERSION}"
LABEL org.opencontainers.image.revision="${BUILD_COMMIT}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.source="https://github.com/kunobi-ninja/kobe"

COPY --from=builder /app/target/release/kobe-operator /kobe-operator

EXPOSE 8080

ENTRYPOINT ["/kobe-operator"]
