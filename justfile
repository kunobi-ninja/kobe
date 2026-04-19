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
    cargo build --release

# Build just the CLI
[group('build')]
build-cli:
    cargo build --release --bin kobe

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

# Lease one warm cluster and verify the pool refills back to the warm target
[group('dev')]
test-smoke-pool pool='ci-small' ttl='2m' *args:
    @mise exec -- bun run ./hack/test-smoke-pool.ts {{ pool }} {{ ttl }} {{ args }}

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
    cargo run --bin crdgen -- accesspolicies > charts/kobe/crds/accesspolicies.yaml
    cargo run --bin crdgen -- kobestores > charts/kobe/crds/kobestores.yaml

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
