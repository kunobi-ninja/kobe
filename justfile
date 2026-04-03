native_platform := arch() + if arch() == "x86_64" { "/amd64" } else { "/arm64" }

# Show available recipes
default:
    @just --list

# Run all checks (format, lint, test)
check: fmt-check lint test

# Build release binary
build:
    cargo build --release

# Run all tests
test:
    cargo test

# Run clippy with deny warnings
lint:
    cargo clippy -- -D warnings

# Format code
fmt:
    cargo fmt

# Check formatting (CI)
fmt-check:
    cargo fmt -- --check

# Run tests with tarpaulin coverage (JSON output)
coverage:
    cargo tarpaulin --engine llvm --all-features --workspace --out Json

# Run coverage and open HTML report
coverage-open:
    cargo tarpaulin --engine llvm --all-features --workspace --out Html
    open tarpaulin-report.html || xdg-open tarpaulin-report.html || true

# Build Docker images locally (both operator + kobe-sync)
docker:
    PLATFORM={{ native_platform }} docker buildx bake -f docker-bake.hcl --load

# Show Docker bake plan (dry run)
docker-print:
    docker buildx bake -f docker-bake.hcl --print

# Build and push both Docker images
docker-push:
    docker buildx bake -f docker-bake.hcl push

# Remove Docker build cache
docker-clean:
    docker builder prune -f

# Build the CLI
cli:
    cargo build --release --bin kobe

# Remove build artifacts
clean:
    cargo clean

# Regenerate CRD YAML files from Rust types
crdgen:
    cargo run --bin crdgen -- clusterpools > charts/kobe/crds/clusterpools.yaml
    cargo run --bin crdgen -- clusterleases > charts/kobe/crds/clusterleases.yaml
    cargo run --bin crdgen -- accesspolicies > charts/kobe/crds/accesspolicies.yaml
    cargo run --bin crdgen -- kobestores > charts/kobe/crds/kobestores.yaml
