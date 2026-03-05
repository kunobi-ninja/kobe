.PHONY: build test check lint fmt fmt-check coverage coverage-open docker docker-print docker-push docker-clean clean help

NATIVE_PLATFORM := linux/$(shell uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')

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

docker: ## Build Docker images locally (both operator + kobe-sync)
	PLATFORM=$(NATIVE_PLATFORM) docker buildx bake -f docker-bake.hcl --load

docker-print: ## Show Docker bake plan (dry run)
	docker buildx bake -f docker-bake.hcl --print

docker-push: ## Build and push both Docker images
	docker buildx bake -f docker-bake.hcl push

docker-clean: ## Remove Docker build cache
	docker builder prune -f

clean: ## Remove build artifacts
	cargo clean
