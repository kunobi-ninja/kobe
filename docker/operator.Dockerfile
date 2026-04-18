# =============================================================================
# kobe-operator — minimal runtime image
# =============================================================================
FROM gcr.io/distroless/cc-debian12

ARG BUILD_VERSION=dev
ARG BUILD_COMMIT=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.version="${BUILD_VERSION}"
LABEL org.opencontainers.image.revision="${BUILD_COMMIT}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.title="kobe-operator"
LABEL org.opencontainers.image.description="Kubernetes cluster pool operator"
LABEL org.opencontainers.image.source="https://github.com/kunobi-ninja/kobe"

ENV BUILD_VERSION=${BUILD_VERSION}

COPY --from=builder /app/target/release/kobe-operator /kobe-operator
COPY --from=builder /app/target/release/kubeconfig-publisher /kubeconfig-publisher

EXPOSE 8080

ENTRYPOINT ["/kobe-operator"]
