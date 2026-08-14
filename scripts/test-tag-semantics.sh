#!/usr/bin/env bash
# Pin what each published image tag MEANS.
#
# `latest` was once emitted unconditionally, which quietly made it a second
# name for `dev`: every publish moved it, so it tracked whichever run went
# last — a main push, the nightly, or a `workflow_dispatch` on an unmerged
# branch — rather than the newest release. The comment in docker-bake.hcl now
# says otherwise; this asserts it, because a comment cannot fail CI.
#
# Resolves tags via `docker buildx bake --print` (no build, no push) under the
# three ways this repo publishes, and compares against the exact expected set.
set -euo pipefail

cd "$(dirname "$0")/.."

failures=0
SHA=59af83006568890a6417fd3b0a4ab83823e94c0e

# Resolve the tag list for one target under the given environment.
resolve() {
  docker buildx bake -f docker-bake.hcl operator --print 2>/dev/null \
    | jq -r '.target.operator.tags[]' | sort
}

expect() {
  local scenario="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo "PASS: $scenario"
  else
    echo "FAIL: $scenario"
    echo "  expected:"; echo "$expected" | sed 's/^/    /'
    echo "  actual:"; echo "$actual" | sed 's/^/    /'
    failures=$((failures + 1))
  fi
}

# 1. A local build (and the e2e harness, which sets IMAGE_TAG itself) names
#    only its own tag. It must NOT claim `latest`.
actual="$(IMAGE_TAG=dev VERSION=0.0.0 BUILD_COMMIT=unknown resolve)"
expect "local build tags only IMAGE_TAG" \
  "zondax/kobe-operator:dev" "$actual"

# 2. A push to main moves `dev` and stamps the immutable commit tag. `latest`
#    must stay where the last RELEASE left it.
actual="$(IMAGE_TAG=dev VERSION=0.0.0 BUILD_COMMIT=$SHA resolve)"
expect "main push moves dev + sha, never latest" \
  "$(printf 'zondax/kobe-operator:dev\nzondax/kobe-operator:sha-59af830' | sort)" "$actual"

# 3. A release tag claims `latest` and the rolling semver tags — and leaves
#    `dev` alone, since a release does not advance the head of main.
actual="$(IMAGE_TAG= VERSION=0.40.0 BUILD_COMMIT=$SHA resolve)"
expect "release tags latest + semver, never dev" \
  "$(printf 'zondax/kobe-operator:latest\nzondax/kobe-operator:sha-59af830\nzondax/kobe-operator:v0\nzondax/kobe-operator:v0.40\nzondax/kobe-operator:v0.40.0' | sort)" "$actual"

if [[ $failures -gt 0 ]]; then
  echo ""
  echo "$failures tag-semantics assertion(s) failed."
  exit 1
fi

echo ""
echo "All tag-semantics assertions passed."
