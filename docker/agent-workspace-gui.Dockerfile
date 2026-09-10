# syntax=docker/dockerfile:1

# Reuse the headless workspace and its exact runner through Docker Bake.
FROM workspace

USER root

# Tauri 2 Linux prerequisites plus an unprivileged software-rendered desktop.
# Language runtimes and project tools still come from the project's mise.toml.
RUN apt-get update && apt-get install -y --no-install-recommends \
        dbus \
        file \
        fonts-dejavu-core \
        libayatana-appindicator3-dev \
        libgl1-mesa-dri \
        librsvg2-dev \
        libwebkit2gtk-4.1-dev \
        novnc \
        openbox \
        procps \
        websockify \
        wget \
        x11-utils \
        x11vnc \
        xauth \
        xvfb \
    && rm -rf /var/lib/apt/lists/*

COPY --chmod=0755 docker/kobe-desktop-up /usr/local/bin/kobe-desktop-up

USER 65532:65532

# Fixed paths let independent runner executions join the same desktop/session.
# All desktop state is writable by the workload, without /run or root access.
ENV DISPLAY=:99 \
    XDG_RUNTIME_DIR=/home/agent/.cache/kobe-desktop \
    XAUTHORITY=/home/agent/.cache/kobe-desktop/Xauthority \
    DBUS_SESSION_BUS_ADDRESS=unix:path=/home/agent/.cache/kobe-desktop/bus \
    LIBGL_ALWAYS_SOFTWARE=1 \
    WEBKIT_DISABLE_DMABUF_RENDERER=1

LABEL org.opencontainers.image.title="kobe-agent-workspace-gui"
LABEL org.opencontainers.image.description="Kobe agent workspace with Tauri Linux libraries and an opt-in loopback-only noVNC desktop"

# Inherit the idle command. The lease explicitly starts kobe-desktop-up as a
# foreground managed execution; building or leasing does not start a desktop.
