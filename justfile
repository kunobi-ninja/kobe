native_platform := "linux/" + if arch() == "x86_64" { "amd64" } else { "arm64" }

# Show available recipes
default:
    @just --list

# Run all checks (format, lint, test)
[group('dev')]
check: fmt-check lint test

# Format code
[group('dev')]
fmt:
    cargo fmt

# Check formatting (CI)
[group('dev')]
fmt-check:
    cargo fmt -- --check

# Run clippy with deny warnings
[group('dev')]
lint:
    cargo clippy -- -D warnings

# Run all tests
[group('dev')]
test:
    cargo test

# Build all binaries (operator + kobe-sync + cli)
[group('build')]
build:
    cargo build --release --workspace

# Build just the CLI (`kobe` binary lives in the crates/kobectl member)
[group('build')]
build-cli:
    cargo build --release -p kobectl --bin kobe

# Build and install the CLI into ~/.cargo/bin (honors $CARGO_INSTALL_ROOT)
[group('build')]
install:
    cargo install --path crates/kobectl --bin kobe --force

# Run the CLI (pass args after --)
[group('dev')]
run *args:
    cargo run --bin kobe -- {{ args }}

# Lease a real warm cluster, verify kubectl can reach it, then release it
[group('dev')]
test-smoke pool='ci-small' ttl='2m' *args:
    @mise exec -- bun run ./hack/test-smoke.ts {{ pool }} {{ ttl }} {{ args }}

# Lease a local vkobe warm cluster, verify kubectl can reach it, then release it
[group('dev')]
test-smoke-vkobe ttl='2m' *args:
    @mise exec -- bun run ./hack/test-smoke.ts e2e-vkobe-etcd {{ ttl }} {{ args }}

# Lease a local vkobe+kine-sqlite warm cluster, verify API discovery, then release it
[group('dev')]
test-smoke-vkobe-kine ttl='2m' *args:
    @mise exec -- bun run ./hack/test-smoke.ts e2e-vkobe-kine-sqlite {{ ttl }} {{ args }}

# Lease a local bootstrap-enabled vkobe cluster and verify bootstrap resources exist
[group('dev')]
test-smoke-bootstrap-vkobe ttl='2m' *args:
    @env POOL_WARMUP_TIMEOUT_SECONDS=90 mise exec -- bun run ./hack/test-smoke-bootstrap.ts e2e-vkobe-etcd-bootstrap default configmap bootstrap-marker {{ ttl }} {{ args }}

# Lease a local vkobe+kine-sqlite cluster with Flux bootstrap and verify Flux namespace exists
[group('dev')]
test-smoke-bootstrap-vkobe-kine ttl='2m' *args:
    @env POOL_WARMUP_TIMEOUT_SECONDS=120 mise exec -- bun run ./hack/test-smoke-bootstrap.ts e2e-vkobe-kine-sqlite-bootstrap flux-system deployment source-controller {{ ttl }} {{ args }}

# Lease one warm cluster and verify the pool refills back to the warm target
[group('dev')]
test-smoke-pool pool='ci-small' ttl='2m' *args:
    @mise exec -- bun run ./hack/test-smoke-pool.ts {{ pool }} {{ ttl }} {{ args }}

# Provision a real single-server k3s instance, assert it reaches Ready, then
# recycle it and assert clean teardown (RBAC + readiness-probe regression gate).
# Talks directly to the host kind cluster; set E2E_CLUSTER to match the harness.
[group('dev')]
test-smoke-k3s cluster='e2e-kobe' *args:
    @env E2E_CLUSTER={{ cluster }} mise exec -- bun run ./hack/test-e2e-k3s.ts {{ args }}

# Local e2e environment entrypoint
[group('dev')]
e2e *args:
    @mise exec -- bun run ./hack/e2e.ts {{ args }}

# Create or refresh the local e2e cluster
[group('dev')]
e2e-up *args:
    @mise exec -- bun run ./hack/e2e.ts up {{ args }}

# Delete the local e2e cluster
[group('dev')]
e2e-down *args:
    @mise exec -- bun run ./hack/e2e.ts down {{ args }}

# Regenerate CRD YAML files from Rust types
[group('build')]
build-crdgen:
    cargo run --bin crdgen -- clusterpools > charts/kobe/crds/clusterpools.yaml
    cargo run --bin crdgen -- clusterleases > charts/kobe/crds/clusterleases.yaml
    cargo run --bin crdgen -- clusterinstances > charts/kobe/crds/clusterinstances.yaml
    cargo run --bin crdgen -- bootstrapconfigs > charts/kobe/crds/bootstrapconfigs.yaml
    cargo run --bin crdgen -- accesspolicies > charts/kobe/crds/accesspolicies.yaml
    cargo run --bin crdgen -- kobestores > charts/kobe/crds/kobestores.yaml
    cargo run --bin crdgen -- cidrpools > charts/kobe/crds/cidrpools.yaml

# Build Docker images locally (operator + kobe-sync)
[group('docker')]
docker:
    PLATFORM={{ native_platform }} docker buildx bake -f docker-bake.hcl --load

# Show Docker bake plan (dry run)
[group('docker')]
docker-print:
    docker buildx bake -f docker-bake.hcl --print

# Build and push Docker images
[group('docker')]
docker-push:
    docker buildx bake -f docker-bake.hcl push

# Remove Docker build cache
[group('docker')]
docker-clean:
    docker builder prune -f

# Run tests with tarpaulin coverage (JSON output)
[group('coverage')]
coverage:
    cargo tarpaulin --engine llvm --all-features --workspace --out Json

# Run coverage and open HTML report
[group('coverage')]
coverage-open:
    cargo tarpaulin --engine llvm --all-features --workspace --out Html
    open tarpaulin-report.html || xdg-open tarpaulin-report.html || true

# Remove build artifacts
clean:
    cargo clean

# Bump the release version across the workspace + Chart.yaml appVersion in
# lockstep, then verify consistency. Usage: just bump 0.32.0  (or 0.32.0-rc.1)
[group('release')]
bump VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    # Reject the no-dot prerelease form (-rc4): semver sorts it lexically on
    # crates.io, which is permanent. Require -rc.4 / -alpha.2 / -beta.1.
    case "{{ VERSION }}" in
      *-rc[0-9]*|*-alpha[0-9]*|*-beta[0-9]*)
        echo "use a dotted prerelease (e.g. 0.32.0-rc.4), not the no-dot form" >&2
        exit 1 ;;
    esac
    if ! command -v cargo-set-version >/dev/null 2>&1; then
      echo "cargo-edit (cargo set-version) not found — install with: cargo binstall cargo-edit" >&2
      exit 1
    fi
    # Sets [workspace.package].version; both kobe-operator and kobectl inherit.
    cargo set-version --workspace "{{ VERSION }}"
    # Mirror into the chart's appVersion (the chart's own `version:` is decoupled
    # and bumped separately when the chart itself changes).
    perl -i -pe 's/^appVersion:.*$/appVersion: "{{ VERSION }}"/' charts/kobe/Chart.yaml
    cargo update -p kobe-operator -p kobectl --precise "{{ VERSION }}" 2>/dev/null || true
    ./scripts/check-version-consistency.sh
    echo "Bumped to {{ VERSION }}. Review the diff, commit, then \`just release\`."

# Cut a release: validate clean tree / on main / in sync, run the version gate,
# and push the tag. The tag push fires CI (build+sign), package-publish, and the
# crates.io publish.
[group('release')]
release:
    #!/usr/bin/env bash
    set -euo pipefail
    [ -z "$(git status --porcelain)" ] || { echo "working tree is dirty — commit or stash first" >&2; exit 1; }
    branch="$(git rev-parse --abbrev-ref HEAD)"
    [ "$branch" = "main" ] || { echo "not on main (on '$branch') — releases are cut from main" >&2; exit 1; }
    git fetch --quiet origin main
    [ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || { echo "local main is not in sync with origin/main — pull/push first" >&2; exit 1; }
    version="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"]=="kobectl"))')"
    tag="v${version}"
    ./scripts/check-version-consistency.sh "$tag"
    git rev-parse -q --verify "refs/tags/$tag" >/dev/null && { echo "tag $tag already exists" >&2; exit 1; } || true
    git tag -s "$tag" -m "$tag"
    git push origin "$tag"
    echo "Pushed $tag. Create the GitHub Release from this tag to fire the signed-release + package-publish + crates.io pipelines."
