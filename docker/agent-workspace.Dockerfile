# syntax=docker/dockerfile:1

# =============================================================================
# kobe-agent-workspace — a general-purpose Sandbox image for agent sessions.
#
# Unlike `sandbox-e2e` (a conformance fixture) this image is meant to be run by
# real callers: an agent leases a Sandbox, clones a project into it, installs
# that project's own toolchain, builds, tests, and pushes commits.
#
# The design rule is that the image is NOT project-specific. It carries only
# what a project cannot install for itself, and defers every language toolchain
# to `mise`, which reads the cloned repo's own `mise.toml`. That keeps one image
# serving every project instead of one image per project.
#
# What a project cannot install for itself, and therefore lives here:
#
#   1. System shared libraries and a C toolchain. Kobe runs Sandbox containers
#      as an unprivileged UID with no capabilities, so there is no root and no
#      `apt-get` at runtime. `mise` installs language runtimes; it cannot
#      install `libssl-dev`. Rust `-sys` crates need the headers and a linker
#      present up front — kobe's own `docker/builder.Dockerfile` needs exactly
#      `pkg-config` + `libssl-dev`, which is the floor encoded below.
#
#   2. `mise` itself, and `tmux` for `attachCommand`.
#
#   3. `kobe-runner`, so the pool can offer detached execution.
# =============================================================================
FROM debian:bookworm-slim

# --- System layer -----------------------------------------------------------
#
# Installed as root at BUILD time, because there is no root at RUN time. Keep
# this list at the floor a compiled language needs to link and fetch:
# a C toolchain, TLS roots, git, and the OpenSSL headers that `-sys` crates
# probe through pkg-config. Anything project-shaped belongs in that project's
# `mise.toml`, not here.
#
# `tmux` backs the pool's `attachCommand`. Without a multiplexer, `kobe attach`
# joins the container's own idle process and a dropped connection loses the
# session — the exact failure an 8h agent lease must not have.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        libssl-dev \
        pkg-config \
        tmux \
        unzip \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

# --- Workload identity ------------------------------------------------------
#
# A real passwd entry for the UID Kobe runs as. Without one, git refuses some
# operations and several toolchains fail to resolve a home directory, which
# surfaces as confusing errors deep inside a build rather than at startup.
ARG WORKLOAD_UID=65532
ARG WORKLOAD_GID=65532
RUN groupadd --gid "${WORKLOAD_GID}" nonroot \
    && useradd --uid "${WORKLOAD_UID}" --gid "${WORKLOAD_GID}" \
        --create-home --home-dir /home/agent --shell /bin/bash nonroot \
    && install -d -o "${WORKLOAD_UID}" -g "${WORKLOAD_GID}" -m 0755 /home/agent/work

# --- mise -------------------------------------------------------------------
#
# Installed to a root-owned path so the workload cannot modify the installer
# it depends on. Tool INSTALLS still land under $HOME and need no privileges.
#
# PINNED, not floating, for the reason the repo's own `mise.toml` records: an
# unpinned tool release broke the conformance matrix overnight and invisibly
# (#34). This image is in the `default` bake group, so an unpinned `mise.run`
# would put that same floating dependency in front of every CI build. Bump it
# deliberately, with a green build as the gate.
ARG MISE_VERSION=v2026.9.3
RUN curl -fsSL https://mise.run \
      | MISE_VERSION="${MISE_VERSION}" MISE_INSTALL_PATH=/usr/local/bin/mise sh \
    && /usr/local/bin/mise --version | grep -q "${MISE_VERSION#v}"

COPY --from=runner /kobe-runner /kobe-runner

RUN test -x /kobe-runner \
    && install -d -o "${WORKLOAD_UID}" -g "${WORKLOAD_GID}" -m 0700 /var/run/kobe/executions

USER 65532:65532

ENV HOME=/home/agent

# `mise activate` is a SHELL hook, and Kobe's runner executes argv directly with
# no implicit shell — so a shell-activated PATH would never apply to
# `kobe exec -- cargo build`. Shims are the mechanism that works without a
# shell: they are real executables on PATH that dispatch to the version the
# project's `mise.toml` pins. Putting them first is what makes a bare `cargo`
# resolve at all in this image.
ENV PATH=/home/agent/.local/share/mise/shims:/home/agent/.local/bin:$PATH

# mise refuses to read a config file it has not been told to trust, which in a
# freshly cloned repo means `mise install` stops and waits for a human that a
# detached agent execution does not have. Trusting the workspace root (and only
# that) keeps clones usable while leaving configs elsewhere untrusted.
ENV MISE_TRUSTED_CONFIG_PATHS=/home/agent/work
ENV MISE_YES=1

WORKDIR /home/agent/work

# --- Build-time proof -------------------------------------------------------
#
# Both halves of the contract are exercised here rather than discovered on a
# leased Sandbox: the runner spool must be usable under the workload UID, and
# a mise-installed tool must resolve through the shims with no shell involved.
# An image that fails either is not worth publishing.
RUN printf '%s\n' '{"protocol":1,"id":"agentws-image-smoke","argv":["/bin/true"],"timeoutSeconds":30,"maxOutputBytes":1024}' \
      | /kobe-runner start \
    && attempts=0 \
    && until /kobe-runner status --id agentws-image-smoke | grep -q '"state":"succeeded"'; do \
         attempts=$((attempts + 1)); \
         test "$attempts" -lt 100; \
         sleep 0.05; \
       done \
    && rm -rf /var/run/kobe/executions/agentws-image-smoke

# `jq` is small, has no runtime deps, and stands in for "any mise-managed tool".
# Resolving it by bare name proves the shim PATH works for a non-shell exec.
RUN mise use --global jq@1.7.1 \
    && command -v jq \
    && jq --version \
    && mise unuse --global jq \
    && rm -rf /home/agent/.cache/mise

ARG BUILD_VERSION=dev
ARG BUILD_COMMIT=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.version="${BUILD_VERSION}"
LABEL org.opencontainers.image.revision="${BUILD_COMMIT}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.title="kobe-agent-workspace"
LABEL org.opencontainers.image.description="Project-agnostic Kobe Sandbox workspace: mise, a C toolchain, and kobe-runner"
LABEL org.opencontainers.image.source="https://github.com/kunobi-ninja/kobe"

# Idle until the lease drives it. TERM is trapped so a released lease tears the
# container down promptly instead of waiting out the grace period.
CMD ["/bin/sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600; done"]
