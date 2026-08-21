# syntax=docker/dockerfile:1

# CI-only workload for the dual-placement Sandbox conformance gate. The
# production runner image is intentionally scratch; this image adds the small
# POSIX userspace the public API scenarios exercise without changing what Kobe
# publishes.
FROM alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1

COPY --from=runner /kobe-runner /kobe-runner

RUN test -x /kobe-runner \
    && install -d -o 65532 -g 65532 -m 0700 /var/run/kobe/executions

USER 65532:65532

# Exercise the runner exactly as Kobe does: no --state-dir override, under the
# workload UID. Keep the image clean after proving the default spool is usable.
RUN printf '%s\n' '{"protocol":1,"id":"sbxe-image-smoke","argv":["/bin/true"],"timeoutSeconds":30,"maxOutputBytes":1024}' \
      | /kobe-runner start \
    && attempts=0 \
    && until /kobe-runner status --id sbxe-image-smoke | grep -q '"state":"succeeded"'; do \
         attempts=$((attempts + 1)); \
         test "$attempts" -lt 100; \
         sleep 0.05; \
       done \
    && rm -rf /var/run/kobe/executions/sbxe-image-smoke

CMD ["/bin/sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600; done"]
