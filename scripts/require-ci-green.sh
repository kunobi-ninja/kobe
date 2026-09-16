#!/usr/bin/env bash
# Require that the named CI jobs concluded `success` for a given commit before
# proceeding. Used to gate irreversible publishes (crates.io, container image)
# on the CI suite, regardless of how the release/tag/push was created — e.g. a
# release drafted by hand in the UI fires `release: published` immediately and
# would otherwise publish in parallel with (or ahead of) CI.
#
# Usage: require-ci-green.sh <commit-sha> <job-name>...
# Env:   GH_TOKEN, GITHUB_REPOSITORY (both set automatically in Actions).
#
# Exit: 0 when every named job is completed+success; 1 if any failed or on
# timeout; 2 on usage error. Fails closed on purpose — a publish must not
# proceed on an indeterminate CI state.
set -euo pipefail

sha="${1:-}"
[ -n "$sha" ] || { echo "usage: require-ci-green.sh <sha> <job>..." >&2; exit 2; }
shift
[ "$#" -ge 1 ] || { echo "at least one required job name needed" >&2; exit 2; }
required=("$@")
: "${GH_TOKEN:?GH_TOKEN required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY required}"
repo="$GITHUB_REPOSITORY"

interval="${CI_GREEN_INTERVAL:-30}"
max_attempts="${CI_GREEN_MAX_ATTEMPTS:-80}" # ~40 min ceiling; `Check` is ~15 min

echo "Gating on CI for $sha — required jobs: ${required[*]}"

# One commit can carry several CI runs: the tag push, the branch push it was
# tagged from, and any manual dispatch. Only the tag run contains the
# release-cli jobs, so picking the newest run and waiting on it is a coin toss
# that a single dispatch can lose. v0.47.0 lost it — a nightly dispatched 21
# seconds after the tag run became `.[0]`, its release-cli jobs never existed,
# and both crates.io and every package lane timed out on a release whose
# artefacts were already built and green. Look across every run for the commit
# instead: a required job counts as green when ANY run for this exact commit
# concluded it successfully, which is the question the gate is really asking.
for attempt in $(seq 1 "$max_attempts"); do
  run_ids="$(gh run list --repo "$repo" --commit "$sha" --workflow CI \
              --json databaseId --jq '.[].databaseId' 2>/dev/null || true)"
  if [ -z "${run_ids:-}" ]; then
    echo "[$attempt/$max_attempts] no CI run for $sha yet; waiting ${interval}s"
    sleep "$interval"; continue
  fi

  jobs='{"jobs":[]}'
  for run_id in $run_ids; do
    run_jobs="$(gh api "repos/$repo/actions/runs/$run_id/jobs?per_page=100")"
    jobs="$(jq -s '{jobs: (.[0].jobs + .[1].jobs)}' <<<"$jobs $run_jobs")"
  done

  failed=(); pending=(); ok=()
  for name in "${required[@]}"; do
    # Prefer a completed success over any other copy of the same job name:
    # a skipped release-cli in the branch run must not mask the real one.
    obj="$(jq -c --arg n "$name" '
      [.jobs[] | select(.name == $n)]
      | (map(select(.status == "completed" and .conclusion == "success")) + .)
      | first // empty' <<<"$jobs")"
    if [ -z "$obj" ]; then pending+=("$name (not started)"); continue; fi
    status="$(jq -r '.status' <<<"$obj")"
    concl="$(jq -r '.conclusion' <<<"$obj")"
    if [ "$status" != "completed" ]; then pending+=("$name ($status)"); continue; fi
    if [ "$concl" = "success" ]; then ok+=("$name"); else failed+=("$name ($concl)"); fi
  done

  if [ "${#failed[@]}" -gt 0 ]; then
    echo "required CI job(s) did not pass for $sha: ${failed[*]}" >&2
    exit 1
  fi
  if [ "${#pending[@]}" -eq 0 ]; then
    echo "all required CI jobs green for $sha: ${ok[*]}"
    exit 0
  fi
  echo "[$attempt/$max_attempts] waiting on: ${pending[*]}"
  sleep "$interval"
done

echo "timed out after $((max_attempts * interval))s waiting for CI green on $sha" >&2
exit 1
