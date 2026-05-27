# =============================================================================
# Helm fetch — download and verify the helm CLI binary used by the
# vcluster backend (`src/backend/vcluster.rs`) to install / uninstall
# vcluster instances. Multi-arch via BuildKit's TARGETARCH.
# =============================================================================
FROM alpine:3.21 AS helm-fetch

# Pin the helm version explicitly. Bumping this is a deliberate,
# review-worthy change — the vcluster backend's compatibility window
# is documented in `docs/architecture/virtual-cluster-strategy.md`.
ARG HELM_VERSION=3.20.2
# BuildKit injects this automatically for multi-arch builds; default
# matches the operator's primary CI architecture.
ARG TARGETARCH=amd64

RUN apk add --no-cache curl tar \
    && curl -fsSL "https://get.helm.sh/helm-v${HELM_VERSION}-linux-${TARGETARCH}.tar.gz" \
        -o /tmp/helm.tgz \
    && curl -fsSL "https://get.helm.sh/helm-v${HELM_VERSION}-linux-${TARGETARCH}.tar.gz.sha256sum" \
        -o /tmp/helm.tgz.sha256sum \
    # The checksum file is `<sha256>  helm-v...-linux-...tar.gz`.
    # `sha256sum -c` requires the named file to exist in cwd, so we
    # rename the download to match.
    && cp /tmp/helm.tgz "/tmp/helm-v${HELM_VERSION}-linux-${TARGETARCH}.tar.gz" \
    && cd /tmp && sha256sum -c "helm.tgz.sha256sum" \
    && tar -xzf helm.tgz -C /tmp \
    && mv "/tmp/linux-${TARGETARCH}/helm" /usr/local/bin/helm \
    && chmod +x /usr/local/bin/helm \
    && /usr/local/bin/helm version --short

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
# kobe-host-reaper is invoked by the same-image kobe-host-reaper DaemonSet
# (privileged, hostPID). The chart selects it via `command: [kobe-host-reaper]`.
COPY --from=builder /app/target/release/kobe-host-reaper /kobe-host-reaper

# helm CLI is invoked as a subprocess by the `vcluster` backend to
# install/uninstall vcluster instances per ClusterInstance.
# /usr/local/bin is on the default distroless PATH, so
# `Command::new("helm")` from Rust resolves it transparently.
COPY --from=helm-fetch /usr/local/bin/helm /usr/local/bin/helm

EXPOSE 8080

ENTRYPOINT ["/kobe-operator"]
