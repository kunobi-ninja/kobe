.PHONY: build test check lint fmt fmt-check coverage coverage-open docker clean help

IMAGE_NAME ?= zondax/wagyu
IMAGE_TAG  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

check: fmt-check lint test ## Run all checks (format, lint, test)

build: ## Build release binary
	cargo build --release

test: ## Run all tests
	cargo test

lint: ## Run clippy with deny warnings
	cargo clippy -- -D warnings

fmt: ## Format code
	cargo fmt

fmt-check: ## Check formatting (CI)
	cargo fmt -- --check

coverage: ## Run tests with tarpaulin coverage (JSON output)
	cargo tarpaulin --engine llvm --all-features --workspace --out Json

coverage-open: ## Run coverage and open HTML report
	cargo tarpaulin --engine llvm --all-features --workspace --out Html && \
		(open tarpaulin-report.html || xdg-open tarpaulin-report.html || true)

docker: ## Build Docker image
	docker build \
		--build-arg BUILD_VERSION=$(IMAGE_TAG) \
		--build-arg BUILD_COMMIT=$(shell git rev-parse HEAD 2>/dev/null || echo unknown) \
		--build-arg BUILD_DATE=$(shell date -u +%Y-%m-%dT%H:%M:%SZ) \
		-t $(IMAGE_NAME):$(IMAGE_TAG) .

clean: ## Remove build artifacts
	cargo clean
