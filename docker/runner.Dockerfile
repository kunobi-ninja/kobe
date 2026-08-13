# =============================================================================
# kobe-runner — the supervisor that runs INSIDE a Sandbox container (#82).
#
# Two things make this image unlike the operator images:
#
#  1. It is built statically against musl. The binary is meant to be copied
#     into an administrator's own agent image, whose libc, distro and glibc
#     version Kobe does not control and must not depend on. A dynamically
#     linked runner would work on the images we happened to test and fail on
#     somebody else's.
#
#  2. It does NOT reuse the shared `builder` stage. That stage compiles the
#     operator's entire dependency tree — kube, aws-sdk, sqlx — none of which
#     this binary uses. Building the runner alone takes seconds, and keeping
#     the trees apart means the thing that ships inside a tenant's container
#     cannot silently acquire one of the operator's dependencies.
#
# Administrators consume it either way round:
#
#     COPY --from=zondax/kobe-runner:latest /kobe-runner /kobe-runner
#
# and then set `spec.template.runnerPath: /kobe-runner` on the SandboxPool.
# =============================================================================
FROM rust:1-slim-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools \
    && rm -rf /var/lib/apt/lists/*

# Built for the architecture of the stage itself, so a cross-platform bake
# resolves the target from the emulated build environment rather than from a
# guess made on the host.
RUN rustup target add "$(uname -m)-unknown-linux-musl"

WORKDIR /app

# The whole workspace manifest set is needed for cargo to load the workspace at
# all, even though only one member is built.
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY src src
COPY build.rs ./

ARG BUILD_VERSION=dev
ENV BUILD_VERSION=${BUILD_VERSION}

RUN cargo build --release --locked \
        --target "$(uname -m)-unknown-linux-musl" \
        -p kobe-runner --bin kobe-runner \
    && cp "target/$(uname -m)-unknown-linux-musl/release/kobe-runner" /kobe-runner \
    # A dynamic dependency here would defeat the point of the musl build, and
    # would only show up on somebody else's base image.
    && ! ldd /kobe-runner 2>/dev/null | grep -q "=>"

# =============================================================================
# Nothing but the binary. There is no shell in this image on purpose: the
# runner contract has no shell anywhere in it, and an image that shipped one
# would invite a Dockerfile that used it.
# =============================================================================
FROM scratch

ARG BUILD_VERSION=dev
ARG BUILD_COMMIT=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.version="${BUILD_VERSION}"
LABEL org.opencontainers.image.revision="${BUILD_COMMIT}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.title="kobe-runner"
LABEL org.opencontainers.image.description="Kobe Sandbox execution supervisor, for copying into a Sandbox image"
LABEL org.opencontainers.image.source="https://github.com/kunobi-ninja/kobe"

COPY --from=build /kobe-runner /kobe-runner

ENTRYPOINT ["/kobe-runner"]
