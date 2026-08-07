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
#   - charts/kobe/Chart.yaml  `version`     (the chart ships on the same tag)
#   - nix/package.nix         `version`     (only if the file exists)
#
# NOTE: the chart's own `version:` used to be on its own track (chart 0.21.x while
# appVersion was 0.31.x). As of 0.36.0 the chart is published from the same `v*`
# release tag as the image, so it is gated here too and `just bump` moves both.
# A chart-only fix is therefore a patch release of the whole thing — NOT a
# `X.Y.Z-1` suffix, which semver reads as a PRERELEASE of X.Y.Z (it sorts below
# the release it means to fix, and helm hides it from search / dependency
# resolution without --devel).
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

chart_appversion = chart_field("appVersion")
if chart_appversion is None:
    errors.append("charts/kobe/Chart.yaml has no `appVersion:`")
elif chart_appversion != ws_version:
    errors.append(f"Chart.yaml appVersion {chart_appversion!r} != workspace version {ws_version!r}")

# The chart is published from the same release tag, so its own `version:` tracks
# the operator version too.
chart_version = chart_field("version")
if chart_version is None:
    errors.append("charts/kobe/Chart.yaml has no `version:`")
elif chart_version != ws_version:
    errors.append(f"Chart.yaml version {chart_version!r} != workspace version {ws_version!r}")

# --- Chart.yaml artifacthub.io/images tags ---
# The Artifact Hub annotation pins fully-qualified image refs so the security
# report scans the right tags. They are first-party images, so they move with
# the release and would otherwise silently advertise a stale version forever
# (`just bump` rewrites them; this is what stops that from being optional).
# Third-party images (kine, flux-cli, kubectl) are deliberately not checked.
#
# The expected tag is `v<version>`, NOT the bare version: docker-bake.hcl
# publishes `v${VERSION}` and the templates default to
# `printf "v%s" .Chart.AppVersion`, so a bare `0.37.0` image does not exist.
# (The CHART's own OCI tag is bare semver — a different artifact. Conflating
# the two is exactly the mistake this check now catches.)
expected_image_tag = f"v{ws_version}"

# Every first-party image the chart deploys. Asserting the SET, not just the
# tags of whatever happens to be present: a check that only validated the refs
# it found would pass just as happily after someone deleted the kobe-sync
# entry, while still advertising that it protects the image listing.
REQUIRED_FIRST_PARTY = {"kobe-operator", "kobe-sync"}

# Read the annotation's own block scalar rather than scanning the whole file,
# so an image-shaped string in a comment or a different annotation cannot
# satisfy this. The block is the run of more-indented lines after the key.
images_block = []
lines = chart.splitlines()
for i, line in enumerate(lines):
    m = re.match(r"^(\s*)artifacthub\.io/images:\s*\|", line)
    if not m:
        continue
    key_indent = len(m.group(1))
    for follow in lines[i + 1 :]:
        if follow.strip() and (len(follow) - len(follow.lstrip())) <= key_indent:
            break
        images_block.append(follow)
    break

if not images_block:
    errors.append(
        "charts/kobe/Chart.yaml has no `artifacthub.io/images: |` block — the "
        "annotation was removed or restructured; update this check or restore it"
    )
else:
    # Strip YAML comments before matching. A commented-out entry is not an
    # image field Artifact Hub can scan, so counting one would let the block
    # look complete while the listing was actually missing that image.
    def strip_comment(line):
        cut = re.search(r"(^|\s)#", line)
        return line[: cut.start()] if cut else line

    live = [strip_comment(l) for l in images_block]

    # Collect every occurrence, not a name->tag dict: collapsing duplicates
    # would let a stale ref pass as long as a correct one appeared later.
    occurrences = []
    for line in live:
        occurrences += re.findall(r"docker\.io/zondax/([\w.-]+):(\S+)", line)

    seen = {}
    for image_name, image_tag in occurrences:
        seen.setdefault(image_name, []).append(image_tag)

    for missing in sorted(REQUIRED_FIRST_PARTY - seen.keys()):
        errors.append(
            f"Chart.yaml artifacthub.io/images is missing the first-party image "
            f"{missing!r} — Artifact Hub would not scan it"
        )
    for image_name, tags in sorted(seen.items()):
        if len(tags) > 1:
            errors.append(
                f"Chart.yaml artifacthub.io/images lists {image_name!r} "
                f"{len(tags)} times ({', '.join(sorted(tags))}) — one entry per image"
            )
        for image_tag in tags:
            if image_tag != expected_image_tag:
                errors.append(
                    f"Chart.yaml artifacthub.io/images {image_name} tag {image_tag!r} "
                    f"!= expected {expected_image_tag!r} (published tags are v-prefixed)"
                )

# --- Chart.yaml artifacthub.io/prerelease matches the version ---
# Artifact Hub surfaces prereleases differently, and rc publishing is a
# supported flow (`just bump 0.38.0-rc.1`), so a static value would advertise
# every release candidate as stable. `just bump` derives it; this enforces it.
expected_prerelease = "true" if "-" in ws_version else "false"
pm = re.search(r'(?m)^\s*artifacthub\.io/prerelease:\s*"?([^"\s]+)"?\s*$', chart)
if pm is None:
    errors.append("charts/kobe/Chart.yaml has no `artifacthub.io/prerelease:` annotation")
elif pm.group(1) != expected_prerelease:
    errors.append(
        f"Chart.yaml artifacthub.io/prerelease {pm.group(1)!r} != {expected_prerelease!r} "
        f"for version {ws_version!r}"
    )

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
    print(f"version consistency OK: tag {tag_version} == workspace == Chart.yaml version + appVersion")
else:
    print(f"version consistency OK: workspace == Chart.yaml version + appVersion == {ws_version}")
PY
