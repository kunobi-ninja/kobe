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
#
# `rsync` completes the file-transfer story the SSH path already tells. `scp`
# and `sftp` work today and are proven at build time below, but rsync needs the
# binary at BOTH ends: a caller has it on their machine and the sandbox did
# not, so syncing a source tree incrementally — the workload in #259 that
# started this — was the one transfer shape still unavailable.
#
# `openssh-server` is for `kobe ssh-proxy`: an SSH client on the caller's
# machine reaches this sandbox through `kobe attach`, which runs `kobe-sshd`
# (below) as the workload user in inetd mode. No port is opened.
RUN apt-get update && apt-get install -y --no-install-recommends \
        autocutsel \
        build-essential \
        ca-certificates \
        curl \
        dbus \
        file \
        firefox-esr \
        fontconfig \
        fonts-dejavu-core \
        fonts-liberation2 \
        fonts-noto-cjk \
        fonts-noto-color-emoji \
        fonts-noto-core \
        gh \
        git \
# `iputils-ping` for first-hop network diagnostics: without it, "is it DNS
# or is it the network" is unanswerable from inside the sandbox.
        iproute2 \
        iputils-ping \
        jq \
        less \
        libayatana-appindicator3-dev \
        libgl1-mesa-dri \
        librsvg2-dev \
        libssl-dev \
        libwebkit2gtk-4.1-dev \
        novnc \
        openbox \
        openssh-client \
        openssh-server \
        pkg-config \
        procps \
        ripgrep \
        rsync \
        tmux \
        unzip \
        websockify \
        wget \
        x11-utils \
        x11-xserver-utils \
        x11vnc \
        xauth \
        xdg-utils \
        xterm \
        xvfb \
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
    && install -d -o "${WORKLOAD_UID}" -g "${WORKLOAD_GID}" -m 0755 /home/agent/work \
    && usermod -p '*' nonroot

# --- SSH over the attach stream ---------------------------------------------
#
# `useradd` leaves the password field as `!`, which sshd reads as a locked
# account and refuses even for public-key logins when PAM is not in use. `*`
# above means "no password", which is what an image with only key auth wants.
#
# `kobe-sshd` serves one session on stdin/stdout; `kobe ssh-proxy` on the
# caller's side hands that stream to the local `ssh`. The configuration is
# root-owned so the workload cannot loosen it; the host key is generated per
# sandbox under $HOME on first use, so the image ships no key material.
COPY --chmod=0755 docker/scripts/kobe-desktop docker/scripts/kobe-desktop-up /usr/local/bin/
COPY --chown=65532:65532 docker/scripts/kobe-openbox-menu.xml /home/agent/.config/openbox/menu.xml
COPY --chown=65532:65532 docker/scripts/kobe-mimeapps.list /home/agent/.config/mimeapps.list

COPY docker/scripts/kobe-sshd_config /etc/kobe/sshd_config
COPY docker/scripts/kobe-sshd /usr/local/bin/kobe-sshd
RUN chmod 0644 /etc/kobe/sshd_config && chmod 0755 /usr/local/bin/kobe-sshd

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
# Fetched to a file rather than piped into `sh`. In `curl ... | sh` the
# pipeline's exit status is SH's, not curl's, so a download that dies partway
# leaves sh reading a truncated script, installing nothing, and STILL exiting 0.
# That is not hypothetical: a publish run failed here with
#
#   curl: (18) HTTP/2 stream 1 was not closed cleanly before end of the
#         underlying stream
#   /bin/sh: 1: /usr/local/bin/mise: not found
#
# Only the version assertion below caught it. Retries absorb the transient
# case, `test -s` refuses an empty download, and the assertion stays as the
# backstop that proves the pinned binary is actually on disk.
RUN curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 \
        https://mise.run -o /tmp/mise-install.sh \
    && test -s /tmp/mise-install.sh \
    && MISE_VERSION="${MISE_VERSION}" MISE_INSTALL_PATH=/usr/local/bin/mise \
        sh /tmp/mise-install.sh \
    && rm -f /tmp/mise-install.sh \
    && /usr/local/bin/mise --version | grep -q "${MISE_VERSION#v}"

# AI coding CLIs are part of the workspace baseline: a project cannot install
# them before an agent starts, so an agent that arrives to an empty box spends
# its first minutes installing its own tooling. Credentials are deliberately
# NOT baked in; each lease authenticates its own user at runtime. Node comes
# from the same pinned tool manager the workspace already uses, then sits at a
# stable root-owned path so `kobe exec` reaches it without a login shell.
# Node is pinned to a MAJOR, not to a patch. The major is what can break the
# CLIs that sit on it, and a break there would be indistinguishable from the
# CLIs breaking by themselves; patches within the major are security fixes we
# want the nightly rebuild to pick up, and an exact pin would have quietly
# kept reinstalling known CVEs. `lts` is deliberately not used: it moves to 26
# in October, and that jump would arrive on a night nobody is watching.
ARG NODE_VERSION=24
# The CLIs are NOT pinned. They ship often, a pinned version starts rotting the
# day it is written, and the nightly rebuild exists precisely so the baseline
# keeps up. The blast radius is small: this is developer tooling inside a
# sandbox, and a bad release is one re-lease away from gone, not a production
# dependency. What a pin really bought was the ability to answer "which version
# is in this image?", so that is recorded below instead of frozen.
# Layer-cache buster. `@latest` resolves at build time, but the RUN string
# never changes, so BuildKit would reuse this layer forever and "latest" would
# quietly mean "whatever shipped the day the cache was written". The build uses
# a local cache and CI sets no BUILD_DATE, while BUILD_COMMIT only moves when
# main does — so on a quiet night nothing here would be reinstalled at all.
# CI passes the date; a local build keeps the default and stays cacheable.
ARG CLI_REFRESH=pinned-by-default
# npm locates its bundled JavaScript relative to its executable. Keeping the
# whole Node distribution together avoids a broken /usr/local symlink. npm's
# cache is dropped at the end: it is written as root, never read at runtime,
# and worth tens of megabytes in the published layer.
RUN echo "cli refresh: ${CLI_REFRESH}" \
    && MISE_DATA_DIR=/opt/kobe/mise mise install "node@${NODE_VERSION}" \
    && node_dir="$(MISE_DATA_DIR=/opt/kobe/mise mise where "node@${NODE_VERSION}")" \
    && PATH="$node_dir/bin:$PATH" \
    && export PATH \
    && npm install --global --prefix "$node_dir" --no-audit --no-fund \
        "@openai/codex@latest" \
        "@anthropic-ai/claude-code@latest" \
        "opencode-ai@latest" \
    && codex --version \
    && claude --version \
    && opencode --version \
    && printf 'node %s\ncodex %s\nclaude-code %s\nopencode %s\n' \
        "$(node --version)" "$(codex --version)" "$(claude --version)" "$(opencode --version)" \
        > /etc/kobe-workspace-versions \
    && chmod 0644 /etc/kobe-workspace-versions \
    && npm cache clean --force \
    && rm -rf /root/.npm \
    && ln -sfn "$node_dir" /opt/kobe/node

# Interactive SSH starts a login shell, whose Debian profile resets PATH. Keep
# the pinned tools visible there as well as to Kobe's direct-exec environment.
# A Debian login shell resets PATH, so ENV PATH alone does not survive an
# interactive SSH session. This covers that case; ENV PATH below covers the
# shell-less one. Both point at the stable symlink rather than the versioned
# directory, so neither has to know which patch release mise resolved.
RUN printf '%s\n' 'export PATH=/opt/kobe/node/bin:$PATH' \
      > /etc/profile.d/kobe-node-tools.sh \
    && chmod 0644 /etc/profile.d/kobe-node-tools.sh

# Login banner: one branded line on an interactive shell (a tty), silent for
# `kobe exec` and friends (#319). Background: `nproc` inside this container
# reports the HOST's CPU count, not the cgroup quota Kubernetes actually
# enforces on it — commonly a fraction of the host's (#272). `kobe-runner`
# (below) computes the real number at runtime from `/sys/fs/cgroup/cpu.max`
# and exports it as
# `KOBE_CPUS` on every process it spawns — see its `cpu` module for why that
# has to happen in the runner itself rather than here: a shell-less `kobe
# exec` never sources this file, so this script cannot be the source of the
# value, only an announcement of it. Colors stay off under `NO_COLOR` or on a
# `dumb` terminal. The `nproc` caveat and the `CARGO_BUILD_JOBS` /
# `RUST_TEST_THREADS` detail live in the runner's docs, not in front of every
# prompt.
RUN printf '%s\n' \
      'if [ -n "$KOBE_CPUS" ] && [ -t 1 ]; then' \
      '  if [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != "dumb" ]; then' \
      '    _kobe_b=$(printf "\033[1;36m"); _kobe_r=$(printf "\033[0m")' \
      '  else' \
      "    _kobe_b=''; _kobe_r=''" \
      '  fi' \
      '  printf "%b\n" "${_kobe_b}kobe${_kobe_r} · agent-workspace · ${KOBE_CPUS} CPUs (cgroup quota)" >&2' \
      '  unset _kobe_b _kobe_r' \
      'fi' \
      > /etc/profile.d/kobe-cpu-quota.sh \
    && chmod 0644 /etc/profile.d/kobe-cpu-quota.sh

COPY --from=runner /kobe-runner /kobe-runner

RUN test -x /kobe-runner \
    && install -d -o "${WORKLOAD_UID}" -g "${WORKLOAD_GID}" -m 0700 \
        /var/run/kobe/executions /var/run/kobe/sessions

USER 65532:65532

ENV HOME=/home/agent

# `mise activate` is a SHELL hook, and Kobe's runner executes argv directly with
# no implicit shell — so a shell-activated PATH would never apply to
# `kobe exec -- cargo build`. Shims are the mechanism that works without a
# shell: they are real executables on PATH that dispatch to the version the
# project's `mise.toml` pins. Putting them first is what makes a bare `cargo`
# resolve at all in this image.
# `/opt/kobe/node/bin` is on PATH because Kobe's runner executes argv with NO
# shell: `kobe exec -- claude ...` never reads /etc/profile.d, so a profile
# line alone left the CLIs installed and unreachable, which is exactly what
# shipped in v0.48.0. The symlink keeps this stable across Node patch bumps.
ENV PATH=/home/agent/.local/share/mise/shims:/home/agent/.local/bin:/opt/kobe/node/bin:$PATH

# mise refuses to read a config file it has not been told to trust, which in a
# freshly cloned repo means `mise install` stops and waits for a human that a
# detached agent execution does not have. Trusting the workspace root (and only
# that) keeps clones usable while leaving configs elsewhere untrusted.
ENV MISE_TRUSTED_CONFIG_PATHS=/home/agent/work
ENV MISE_YES=1

# Fixed desktop paths so independent runner executions join the SAME desktop:
# a second `kobe exec` has no shell and no way to discover a random one. All of
# it is writable by the workload, with no /run and no root. Setting these does
# not start anything — `kobe-desktop-up` does, as an explicit foreground
# execution — so a headless lease pays nothing for them being here.
ENV DISPLAY=:99 \
    XDG_RUNTIME_DIR=/home/agent/.cache/kobe-desktop \
    XAUTHORITY=/home/agent/.cache/kobe-desktop/Xauthority \
    DBUS_SESSION_BUS_ADDRESS=unix:path=/home/agent/.cache/kobe-desktop/bus \
    LIBGL_ALWAYS_SOFTWARE=1 \
    WEBKIT_DISABLE_DMABUF_RENDERER=1

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

# The SSH path is proven end to end as the workload user: `kobe-sshd --check`
# generates the host key and validates the configuration, then a real `ssh`
# logs in through `kobe-sshd` as its ProxyCommand, exactly as `kobe ssh-proxy`
# will drive it. Every key this produces is removed afterwards so no sandbox
# inherits one. The `--session` path is proven the same way: a command and
# sftp pass through unchanged, and an interactive login runs in a session.
RUN kobe-sshd --check \
    && ssh-keygen -q -t ed25519 -N '' -f /tmp/proof-client \
    && cat /tmp/proof-client.pub >> "$HOME/.ssh/authorized_keys" \
    && ssh -q \
        -o ProxyCommand=/usr/local/bin/kobe-sshd \
        -o IdentityFile=/tmp/proof-client \
        -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes \
        nonroot@kobe-proof 'test "$(id -u)" = 65532 && test -x /usr/lib/openssh/sftp-server && command -v ping' \
    && session_ssh='-o IdentityFile=/tmp/proof-client -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes' \
    && session_proxy='ProxyCommand=/usr/local/bin/kobe-sshd --session proof' \
    && ssh -q ${session_ssh} -o "${session_proxy}" nonroot@kobe-proof 'echo passed-through' \
        | grep -qx passed-through \
    && printf 'ls /\n' > /tmp/proof-batch \
    && sftp -q ${session_ssh} -o "${session_proxy}" -b /tmp/proof-batch nonroot@kobe-proof >/dev/null \
    && printf 'echo in-session-$((6 * 7))\nexit\n' \
        | ssh -q -tt ${session_ssh} -o "${session_proxy}" nonroot@kobe-proof \
        | grep -q in-session-42 \
    && rm -rf "$HOME/.ssh" /tmp/proof-client /tmp/proof-client.pub /tmp/proof-batch \
        /var/run/kobe/sessions/proof.*

# The AI CLIs must resolve with NO shell, the way `kobe exec` invokes argv.
# `env -i` strips the environment down to the image's own PATH, which is the
# only thing a runner execution inherits: a profile.d line would not survive
# this, and in v0.48.0 that is exactly how the CLIs shipped unreachable.
RUN env -i PATH="$PATH" claude --version >/dev/null \
    && env -i PATH="$PATH" codex --version >/dev/null \
    && env -i PATH="$PATH" opencode --version >/dev/null

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
LABEL org.opencontainers.image.description="Project-agnostic Kobe Sandbox workspace: mise, a C toolchain, kobe-runner, and an opt-in loopback-only desktop"
LABEL org.opencontainers.image.source="https://github.com/kunobi-ninja/kobe"

# Idle until the lease drives it. TERM is trapped so a released lease tears the
# container down promptly instead of waiting out the grace period.
CMD ["/bin/sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600; done"]
