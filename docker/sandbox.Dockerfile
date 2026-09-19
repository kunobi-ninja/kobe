# syntax=docker/dockerfile:1

# =============================================================================
# kobe-sandbox — a general-purpose Sandbox image for agent sessions.
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
#   3. A `/nix` the workload owns, with Nix in it. Creating `/nix` takes root,
#      so a project cannot do it; with it in place, a project fetches its own
#      system libraries instead of asking for them to be added to (1).
#
#   4. `kobe-runner`, so the pool can offer detached execution.
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
        bc \
        build-essential \
        ca-certificates \
        clang \
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
# X11 keyboard and XCB libraries that GPUI-based apps (gpui-kit) link against.
# `xkbcommon-x11.pc` requires `xcb-xkb`, so pkg-config needs both -dev packages;
# the pkg-config check after the install fails the build if either goes missing.
        libx11-xcb-dev \
        libxcb-xkb-dev \
        libxcb-xkb1 \
        libxkbcommon-x11-0 \
        libxkbcommon-x11-dev \
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
    && pkg-config --exists xkbcommon-x11 x11-xcb xcb-xkb \
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
        > /etc/kobe-sandbox-versions \
    && chmod 0644 /etc/kobe-sandbox-versions \
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
#
# The second line is the one hint worth the space: a person who lands here
# reaches for `sudo apt-get` first, and there is no root. Nix (below) is the
# answer, and nothing else in the session would tell them so.
RUN printf '%s\n' \
      'if [ -n "$KOBE_CPUS" ] && [ -t 1 ]; then' \
      '  if [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != "dumb" ]; then' \
      '    _kobe_b=$(printf "\033[1;36m"); _kobe_r=$(printf "\033[0m")' \
      '  else' \
      "    _kobe_b=''; _kobe_r=''" \
      '  fi' \
      '  printf "%b\n" "${_kobe_b}kobe${_kobe_r} · sandbox · ${KOBE_CPUS} CPUs (cgroup quota)" >&2' \
      '  printf "%s\n" "no root here · system packages: nix shell nixpkgs#<pkg>" >&2' \
      '  unset _kobe_b _kobe_r' \
      'fi' \
      > /etc/profile.d/kobe-cpu-quota.sh \
    && chmod 0644 /etc/profile.d/kobe-cpu-quota.sh

# --- Nix store ---------------------------------------------------------------
#
# `/nix` is the one part of Nix a project cannot provide for itself: creating it
# takes root, and there is none at runtime. Owning it by the workload UID makes
# this a single-user install, with no daemon, no setuid helper and no build
# users, so Nix adds no privilege the lease did not already have. What it adds
# is reach: a project pulls the system libraries it needs with `nix shell` or
# its own flake instead of waiting for them to land in the apt list above.
#
# `sandbox = false` because Kobe's Sandbox containers cannot create user
# namespaces, which is what the Nix build sandbox is made of. Builds are
# therefore not isolated from one another inside a lease; the lease itself is
# the isolation boundary. The store lives in the container's writable layer and
# counts against the pool's ephemeral-storage limit.
RUN install -d -o "${WORKLOAD_UID}" -g "${WORKLOAD_GID}" -m 0755 /nix \
    && install -d -m 0755 /etc/nix \
    && printf '%s\n' \
        'sandbox = false' \
        'build-users-group =' \
        'experimental-features = nix-command flakes' \
        > /etc/nix/nix.conf \
    && chmod 0644 /etc/nix/nix.conf \
    && printf '%s\n' 'export PATH=$PATH:/home/agent/.nix-profile/bin' \
        > /etc/profile.d/kobe-nix.sh \
    && chmod 0644 /etc/profile.d/kobe-nix.sh

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
# The Nix profile comes LAST: a tool a project pins through mise, and anything
# the image ships, wins over whatever a lease later adds with `nix profile`.
ENV PATH=/home/agent/.local/share/mise/shims:/home/agent/.local/bin:/opt/kobe/node/bin:$PATH:/home/agent/.nix-profile/bin

# mise refuses to read a config file it has not been told to trust, which in a
# freshly cloned repo means `mise install` stops and waits for a human that a
# detached agent execution does not have. Trusting the workspace root (and only
# that) keeps clones usable while leaving configs elsewhere untrusted.
ENV MISE_TRUSTED_CONFIG_PATHS=/home/agent/work
ENV MISE_YES=1

# Without a locale every process runs in C/POSIX, so the desktop's xterm reads
# UTF-8 as Latin-1 and the login banner's `·` renders as `Â·`. C.UTF-8 ships
# with libc; no locales package is needed.
ENV LANG=C.UTF-8

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

# --- Nix ---------------------------------------------------------------------
#
# Installed as the workload user into the `/nix` prepared above. Pinned for the
# same reason mise is; the versioned installer carries the SHA-256 of the
# tarball it fetches, so the pin covers the binaries and not just the script.
# Fetched to a file, not piped, for the reason recorded at the mise install.
# `--no-modify-profile` because PATH is already handled: ENV above for a
# shell-less `kobe exec`, /etc/profile.d for a login shell.
ARG NIX_VERSION=2.35.2
RUN curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 \
        "https://releases.nixos.org/nix/nix-${NIX_VERSION}/install" -o /tmp/nix-install.sh \
    && test -s /tmp/nix-install.sh \
    && USER=nonroot sh /tmp/nix-install.sh --no-daemon --no-modify-profile --no-channel-add \
    && rm -f /tmp/nix-install.sh \
    && env -i HOME="$HOME" PATH="$PATH" nix --version | grep -q "${NIX_VERSION}"

# --- Build-time proof -------------------------------------------------------
#
# Both halves of the contract are exercised here rather than discovered on a
# leased Sandbox: the runner spool must be usable under the workload UID, and
# a mise-installed tool must resolve through the shims with no shell involved.
# An image that fails either is not worth publishing.
RUN printf '%s\n' '{"protocol":1,"id":"sandbox-image-smoke","argv":["/bin/true"],"timeoutSeconds":30,"maxOutputBytes":1024}' \
      | /kobe-runner start \
    && attempts=0 \
    && until /kobe-runner status --id sandbox-image-smoke | grep -q '"state":"succeeded"'; do \
         attempts=$((attempts + 1)); \
         test "$attempts" -lt 100; \
         sleep 0.05; \
       done \
    && rm -rf /var/run/kobe/executions/sandbox-image-smoke

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

# Nix must BUILD, not just start, under the constraints a lease has: no root,
# no user namespaces, no shell. A trivial derivation proves the store is
# writable and the unsandboxed builder runs; the result is collected again so
# the proof leaves nothing in the published store.
RUN out="$(env -i HOME="$HOME" PATH="$PATH" nix build --impure --no-link --print-out-paths --expr \
        'derivation { name = "kobe-nix-proof"; system = builtins.currentSystem; builder = "/bin/sh"; args = [ "-c" "echo ok > $out" ]; }')" \
    && grep -qx ok "$out" \
    && nix store delete "$out" \
    && rm -rf /home/agent/.cache/nix

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
LABEL org.opencontainers.image.title="kobe-sandbox"
LABEL org.opencontainers.image.description="Project-agnostic Kobe Sandbox workspace: mise, Nix, a C toolchain, kobe-runner, and an opt-in loopback-only desktop"
LABEL org.opencontainers.image.source="https://github.com/kunobi-ninja/kobe"

# Idle until the lease drives it. TERM is trapped so a released lease tears the
# container down promptly instead of waiting out the grace period. The shell
# runs a trap only once its foreground child returns, so `sleep` must run in the
# background: `wait` returns on the signal, while a foreground `sleep 3600`
# held TERM until the kubelet's SIGKILL.
CMD ["/bin/sh", "-c", "trap 'exit 0' TERM INT; sleep infinity & wait"]
