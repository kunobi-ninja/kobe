# syntax=docker/dockerfile:1

# CI-only workload for the dual-placement Sandbox conformance gate. The
# production runner image is intentionally scratch; this image adds the small
# POSIX userspace the public API scenarios exercise without changing what Kobe
# publishes.
FROM alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1

COPY --from=runner /kobe-runner /kobe-runner

RUN test -x /kobe-runner

CMD ["/bin/sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600; done"]
