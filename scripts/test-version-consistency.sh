#!/usr/bin/env bash
# Executable tests for check-version-consistency.sh.
#
# That script is the last gate before irreversible release steps, and it has
# grown real parsing logic (the artifacthub.io/images block). Manual "I tried
# breaking it once" checks do not survive the next edit — these do.
#
# Each case builds a throwaway repo root (Cargo.toml + charts/kobe/Chart.yaml +
# a copy of the checker, which resolves its root from its own location) and
# asserts the checker's exit status, plus a substring of the failure it should
# report. A test that expects failure but does not say WHY would pass on the
# wrong error.
#
# Usage: scripts/test-version-consistency.sh    (exit 0 = all cases pass)
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
checker="$here/check-version-consistency.sh"
pass=0
fail=0

# Build a repo root whose Chart.yaml images block is exactly $2.
make_root() {
  local version="$1" images="$2" prerelease="${3:-false}" root
  root="$(mktemp -d)"
  mkdir -p "$root/scripts" "$root/charts/kobe"
  cp "$checker" "$root/scripts/"
  cat >"$root/Cargo.toml" <<EOF
[workspace]
members = []

[workspace.package]
version = "$version"
EOF
  {
    echo "apiVersion: v2"
    echo "name: kobe"
    echo "version: $version"
    echo "appVersion: \"$version\""
    echo "annotations:"
    echo "  artifacthub.io/prerelease: \"$prerelease\""
    # The literal NO_KEY drops the annotation entirely, to exercise the
    # "someone deleted the block" path rather than "the block is empty".
    if [ "$images" != "NO_KEY" ]; then
      echo "  artifacthub.io/images: |"
      printf '%s\n' "$images"
    fi
  } >"$root/charts/kobe/Chart.yaml"
  echo "$root"
}

# expect <name> <expected-rc> <substring-of-output> <root>
expect() {
  local name="$1" want_rc="$2" want_sub="$3" root="$4" out rc
  out="$("$root/scripts/check-version-consistency.sh" 2>&1)"
  rc=$?
  if [ "$rc" -ne "$want_rc" ]; then
    echo "FAIL: $name — expected rc=$want_rc, got rc=$rc"
    echo "      output: $out"
    fail=$((fail + 1))
  # Match in memory: with pipefail, `grep -q` can close the pipe after a match
  # and turn printf's resulting SIGPIPE into a false test failure.
  elif [ -n "$want_sub" ] && [[ "$out" != *"$want_sub"* ]]; then
    echo "FAIL: $name — output did not mention: $want_sub"
    echo "      output: $out"
    fail=$((fail + 1))
  else
    echo "ok: $name"
    pass=$((pass + 1))
  fi
  rm -rf "$root"
}

GOOD='    - name: kobe-operator
      image: docker.io/zondax/kobe-operator:v9.9.9
    - name: kobe-sync
      image: docker.io/zondax/kobe-sync:v9.9.9
    - name: kine
      image: docker.io/rancher/kine:v0.13.2
      whitelisted: true'

expect "a well-formed chart passes" 0 "version consistency OK" \
  "$(make_root 9.9.9 "$GOOD")"

# The images the operator actually ships must be listed, or Artifact Hub has
# nothing to scan for them.
expect "a missing first-party image fails" 1 "missing the first-party image 'kobe-sync'" \
  "$(make_root 9.9.9 '    - name: kobe-operator
      image: docker.io/zondax/kobe-operator:v9.9.9')"

# A commented-out entry is not a field Artifact Hub can read, so it must not
# count towards the required set.
expect "a commented-out entry does not count" 1 "missing the first-party image 'kobe-sync'" \
  "$(make_root 9.9.9 '    - name: kobe-operator
      image: docker.io/zondax/kobe-operator:v9.9.9
    # image: docker.io/zondax/kobe-sync:v9.9.9')"

# Collapsing duplicates would let a stale ref hide behind a correct one.
expect "a stale duplicate is rejected" 1 "lists 'kobe-sync' 2 times" \
  "$(make_root 9.9.9 '    - name: kobe-operator
      image: docker.io/zondax/kobe-operator:v9.9.9
    - name: kobe-sync
      image: docker.io/zondax/kobe-sync:v9.0.0
    - name: kobe-sync
      image: docker.io/zondax/kobe-sync:v9.9.9')"

expect "a stale tag is rejected" 1 "!= expected 'v9.9.9'" \
  "$(make_root 9.9.9 '    - name: kobe-operator
      image: docker.io/zondax/kobe-operator:v9.9.9
    - name: kobe-sync
      image: docker.io/zondax/kobe-sync:v9.0.0')"

# The images are published v-prefixed; the CHART's own OCI tag is bare semver.
# Conflating them is the mistake this check exists to catch.
expect "a bare-semver image tag is rejected" 1 "published tags are v-prefixed" \
  "$(make_root 9.9.9 '    - name: kobe-operator
      image: docker.io/zondax/kobe-operator:9.9.9
    - name: kobe-sync
      image: docker.io/zondax/kobe-sync:9.9.9')"

expect "deleting the annotation fails closed" 1 "no \`artifacthub.io/images: |\` block" \
  "$(make_root 9.9.9 NO_KEY)"

expect "emptying the block fails closed" 1 "missing the first-party image" \
  "$(make_root 9.9.9 '')"

# Prereleases must not advertise themselves as stable releases.
expect "an rc version with prerelease=true passes" 0 "version consistency OK" \
  "$(make_root 9.9.9-rc.1 '    - name: kobe-operator
      image: docker.io/zondax/kobe-operator:v9.9.9-rc.1
    - name: kobe-sync
      image: docker.io/zondax/kobe-sync:v9.9.9-rc.1' true)"

expect "an rc version with prerelease=false fails" 1 "artifacthub.io/prerelease 'false' != 'true'" \
  "$(make_root 9.9.9-rc.1 '    - name: kobe-operator
      image: docker.io/zondax/kobe-operator:v9.9.9-rc.1
    - name: kobe-sync
      image: docker.io/zondax/kobe-sync:v9.9.9-rc.1' false)"

expect "a stable version with prerelease=true fails" 1 "artifacthub.io/prerelease 'true' != 'false'" \
  "$(make_root 9.9.9 "$GOOD" true)"

echo
echo "version-consistency tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
