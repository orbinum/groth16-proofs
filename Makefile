.PHONY: help fmt check test build build-wasm clean lint all install-tools

# Default target
.DEFAULT_GOAL := help

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(BLUE)orbinum-groth16-proofs - Development Commands$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)Common workflows:$(NC)"
	@echo "  make all       - Run all checks (fmt, lint, test)"
	@echo "  make build     - Build native + WASM"
	@echo "  make dev       - Quick dev cycle (fmt, check, test)"

# Format code
fmt: ## Format code with rustfmt
	@echo "$(BLUE)Formatting code...$(NC)"
	cargo fmt --all

# Check formatting without changes
fmt-check: ## Check formatting (dry-run)
	@echo "$(BLUE)Checking formatting...$(NC)"
	cargo fmt --all -- --check

# Clippy linting
lint: ## Run clippy linter
	@echo "$(BLUE)Running clippy...$(NC)"
	cargo clippy --all-targets --all-features -- -D warnings

# Run tests
test: ## Run all tests
	@echo "$(BLUE)Running tests...$(NC)"
	cargo test --lib --all-features

test-all: ## Run all tests including doc tests
	@echo "$(BLUE)Running all tests (including docs)...$(NC)"
	cargo test --all-features

test-release: ## Run tests in release mode
	@echo "$(BLUE)Running tests (release mode)...$(NC)"
	cargo test --lib --release --all-features

# Check (fmt + clippy)
check: fmt-check lint ## Check code quality (fmt + clippy)
	@echo "$(GREEN)✓ Code quality checks passed$(NC)"

# Build native binary
build: ## Build native binary (release)
	@echo "$(BLUE)Building native binary...$(NC)"
	cargo build --release
	@echo "$(GREEN)✓ Binary: ./target/release/generate-proof-from-witness$(NC)"

build-debug: ## Build native binary (debug)
	@echo "$(BLUE)Building native binary (debug)...$(NC)"
	cargo build

# Build WASM module
build-wasm: ## Build WASM module (release)
	@echo "$(BLUE)Building WASM module...$(NC)"
	@command -v wasm-pack >/dev/null 2>&1 || { echo "$(YELLOW)Installing wasm-pack...$(NC)"; curl https://rustwasm.org/wasm-pack/installer/init.sh -sSf | sh; }
	wasm-pack build --target web --out-dir ./pkg --release --features wasm
	@echo "$(GREEN)✓ WASM: ./pkg/orbinum_groth16_proofs.wasm$(NC)"

build-wasm-dev: ## Build WASM module (dev/unoptimized)
	@echo "$(BLUE)Building WASM module (dev)...$(NC)"
	@command -v wasm-pack >/dev/null 2>&1 || { echo "$(YELLOW)Installing wasm-pack...$(NC)"; curl https://rustwasm.org/wasm-pack/installer/init.sh -sSf | sh; }
	wasm-pack build --target web --out-dir ./pkg --dev --features wasm
	@echo "$(GREEN)✓ WASM (dev): ./pkg/orbinum_groth16_proofs.wasm$(NC)"

# Build everything
build-all: build build-wasm ## Build both native and WASM
	@echo "$(GREEN)✓ All builds complete$(NC)"

# Clean build artifacts
clean: ## Clean build artifacts
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	cargo clean
	rm -rf pkg/
	@echo "$(GREEN)✓ Clean complete$(NC)"

# Development workflow
dev: fmt lint test ## Quick dev cycle (format → lint → test)
	@echo "$(GREEN)✓ Dev cycle complete$(NC)"

# Full validation (used in CI)
all: fmt lint test build build-wasm ## Full validation pipeline
	@echo "$(GREEN)✓ All checks passed$(NC)"

# Install development tools
install-tools: ## Install required dev tools
	@echo "$(BLUE)Installing development tools...$(NC)"
	rustup component add rustfmt clippy
	@command -v wasm-pack >/dev/null 2>&1 || curl https://rustwasm.org/wasm-pack/installer/init.sh -sSf | sh
	@command -v cargo-release >/dev/null 2>&1 || cargo install cargo-release
	@echo "$(GREEN)✓ Tools installed$(NC)"

# Run specific examples
run-example: ## Run example binary (usage: make run-example)
	@echo "$(BLUE)Ensure witness.json and proving_key.ark are in current directory$(NC)"
	./target/release/generate-proof-from-witness witness.json proving_key.ark

# Check dependencies
deps: ## List project dependencies
	@echo "$(BLUE)Cargo dependencies:$(NC)"
	cargo tree

# Security audit
audit: ## Run security audit
	@echo "$(BLUE)Running security audit...$(NC)"
	@command -v cargo-audit >/dev/null 2>&1 || { echo "$(YELLOW)Installing cargo-audit...$(NC)"; cargo install cargo-audit; }
	cargo audit

# Update dependencies
update: ## Update dependencies
	@echo "$(BLUE)Updating dependencies...$(NC)"
	cargo update

# Version information
version: ## Show version and toolchain info
	@echo "$(BLUE)Rust Toolchain:$(NC)"
	@rustc --version
	@cargo --version
	@rustup show active-toolchain

# Documentation
doc: ## Generate and open documentation
	@echo "$(BLUE)Generating documentation...$(NC)"
	cargo doc --no-deps --open
