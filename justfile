native_platform := arch() + if arch() == "x86_64" { "/amd64" } else { "/arm64" }

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
cli:
    cargo build --release --bin kobe

# Run the CLI (pass args after --)
[group('dev')]
run *args:
    cargo run --bin kobe -- {{ args }}

# Lease a real warm cluster, verify kubectl can reach it, then release it
[group('dev')]
test-smoke pool='ci-small' ttl='15m' *args:
    bash ./hack/lease-smoke.sh {{ pool }} {{ ttl }} {{ args }}

# Regenerate CRD YAML files from Rust types
[group('build')]
crdgen:
    cargo run --bin crdgen -- clusterpools > charts/kobe/crds/clusterpools.yaml
    cargo run --bin crdgen -- clusterleases > charts/kobe/crds/clusterleases.yaml
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
