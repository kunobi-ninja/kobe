#!/usr/bin/env bash
# Assert kobe's release version is internally consistent across all the places
# that must agree, and — when given a release tag — that the tag matches them,
# BEFORE anything irreversible happens (binary build, signing, GitHub Release,
# crates.io publish, container image).
#
# Single source of truth = the workspace version in the root Cargo.toml
# (`[workspace.package].version`), inherited by both `kobe-operator` and the
# published `kobectl` crate. The places that must mirror it:
#   - charts/kobe/Chart.yaml  `appVersion`  (the app/operator release version)
#   - nix/package.nix         `version`     (only if the file exists)
#
# NOTE: the chart's own `version:` is INTENTIONALLY decoupled — kobe versions the
# Helm chart on its own track (e.g. chart 0.21.x while appVersion is 0.31.x), so
# it is deliberately NOT gated here.
# The binary's --version comes from BUILD_VERSION=<tag> at build time; the tag is
# a checked mirror of the manifest.
#
# Release-candidates publish to crates.io with the prerelease in the manifest
# (e.g. 0.32.0-rc.1 ↔ tag v0.32.0-rc.1). The FULL version must match — no suffix
# stripping. Cargo serves prereleases only on an explicit request, so this never
# affects a normal `cargo install`.
#
# Hermetic: pure file reads via python — no cargo, no nix, no network.
#
# Usage:
#   check-version-consistency.sh                # internal mode: the values agree
#   check-version-consistency.sh v0.32.0        # tag mode: the values == 0.32.0
#   check-version-consistency.sh v0.32.0-rc.1   # tag mode: the values == 0.32.0-rc.1
#
# Exit: 0 consistent; 1 on a mismatch / malformed tag; fail-closed.
set -euo pipefail

tag="${1:-}"

tag_version=""
if [ -n "$tag" ]; then
  case "$tag" in
    v*) : ;;
    *) echo "release tag must look like vX.Y.Z[-rc.N], got: $tag" >&2; exit 1 ;;
  esac
  tag_version="${tag#v}"
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TAG_VERSION="$tag_version" ROOT="$root" python3 - <<'PY'
import os, re, sys, tomllib, pathlib

tag_version = os.environ["TAG_VERSION"]
root = pathlib.Path(os.environ["ROOT"])

errors = []

# --- workspace version (the source of truth) ---
with open(root / "Cargo.toml", "rb") as f:
    cargo = tomllib.load(f)
try:
    ws_version = cargo["workspace"]["package"]["version"]
except KeyError:
    print("root Cargo.toml has no [workspace.package].version", file=sys.stderr)
    sys.exit(1)

# Reject a no-dot prerelease identifier (e.g. 0.32.0-rc1): crates.io is permanent
# and semver orders the no-dot form lexically (rc.2 would sort after rc.10).
m = re.search(r"-(rc|alpha|beta)[0-9]", ws_version)
if m:
    errors.append(
        f"version {ws_version!r} uses a no-dot prerelease ({m.group(0)[1:]}…); "
        "use the dotted form (e.g. -rc.4) — the no-dot form sorts lexically on crates.io"
    )

# --- Chart.yaml version + appVersion (plain line reads; avoid a yaml dep) ---
chart = (root / "charts" / "kobe" / "Chart.yaml").read_text()
def chart_field(name):
    mm = re.search(rf'(?m)^{name}:\s*"?([^"\s]+)"?\s*$', chart)
    return mm.group(1) if mm else None

# Only appVersion is gated; the chart's own `version:` is decoupled on purpose.
chart_appversion = chart_field("appVersion")
if chart_appversion is None:
    errors.append("charts/kobe/Chart.yaml has no `appVersion:`")
elif chart_appversion != ws_version:
    errors.append(f"Chart.yaml appVersion {chart_appversion!r} != workspace version {ws_version!r}")

# --- nix/package.nix version (optional) ---
nix_pkg = root / "nix" / "package.nix"
if nix_pkg.exists():
    nm = re.search(r'version\s*=\s*"([^"]+)"', nix_pkg.read_text())
    if nm and nm.group(1) != ws_version:
        errors.append(f"nix/package.nix version {nm.group(1)!r} != workspace version {ws_version!r}")

# --- tag agreement (only when a tag is supplied) ---
if tag_version and ws_version != tag_version:
    errors.append(f"workspace version {ws_version!r} != tag version {tag_version!r}")

if errors:
    scope = f"tag {tag_version}" if tag_version else "the workspace manifests"
    print(f"version consistency FAILED for {scope}:", file=sys.stderr)
    for e in errors:
        print("  - " + e, file=sys.stderr)
    fix = tag_version or ws_version
    print(f"Fix: run `just bump {fix}` so Cargo.toml + Chart.yaml agree, then re-tag if needed.", file=sys.stderr)
    sys.exit(1)

if tag_version:
    print(f"version consistency OK: tag {tag_version} == workspace == Chart.yaml appVersion")
else:
    print(f"version consistency OK: workspace == Chart.yaml appVersion == {ws_version}")
PY
