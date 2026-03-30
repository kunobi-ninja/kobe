# =============================================================================
# kobe-operator — minimal runtime image
# =============================================================================
FROM gcr.io/distroless/cc-debian12

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
