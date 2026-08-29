# groth16-proofs — development commands. `make` on its own lists them.
#
# Two things here are load-bearing rather than convenience:
#
#   * `test` never passes `--lib`. That flag skips tests/, which holds every
#     test that proves and then verifies — and a suite that ran only the unit
#     tests is how a prover producing unverifiable proofs passed CI for two
#     major versions.
#
#   * `test-strict` sets GROTH16_REQUIRE_ARTIFACTS. Integration tests skip
#     themselves when ../circuits is absent, so a suite that skips everything
#     looks exactly like one that passes everything. That variable turns
#     absence into a failure, which is what CI runs.

.DEFAULT_GOAL := help

BLUE  := \033[0;34m
GREEN := \033[0;32m
DIM   := \033[2m
NC    := \033[0m

# Where the integration tests look for proving keys and fixtures.
CIRCUITS ?= ../circuits

CARGO_FEATURES := --all-features

.PHONY: help
help: ## List available commands
	@echo "$(BLUE)groth16-proofs$(NC)"
	@echo ""
	@grep -hE '^[a-z][a-z0-9-]*:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-14s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(DIM)  dev            fmt → lint → test$(NC)"
	@echo "$(DIM)  test-publish   everything that must pass before releasing$(NC)"

# ─── Checks ──────────────────────────────────────────────────────────────────

.PHONY: fmt
fmt: ## Format with rustfmt
	cargo fmt --all

.PHONY: fmt-check
fmt-check: ## Check formatting without writing
	cargo fmt --all -- --check

.PHONY: lint
lint: ## Run clippy, warnings as errors
	cargo clippy --all-targets $(CARGO_FEATURES) -- -D warnings

.PHONY: check
check: fmt-check lint test build ## Formatting + clippy

# ─── Tests ───────────────────────────────────────────────────────────────────

.PHONY: test
test: ## Unit + integration tests
	cargo test $(CARGO_FEATURES)

.PHONY: test-lib
test-lib: ## Unit tests only — fast, but no prove/verify coverage
	cargo test --lib $(CARGO_FEATURES)

.PHONY: test-release
test-release: ## All tests in release mode (proving is impractically slow in debug)
	cargo test --release $(CARGO_FEATURES)

.PHONY: test-strict
test-strict: ## All tests, failing if circuit artifacts are missing
	GROTH16_REQUIRE_ARTIFACTS=1 cargo test --release $(CARGO_FEATURES)

.PHONY: e2e
e2e: build build-wasm ## End-to-end: the shipped artifacts, cross-verified
	@node tests/e2e/wasm-all-circuits.mjs
	@node tests/e2e/full-chain.mjs
	@node tests/e2e/negative.mjs
	@node tests/e2e/proof-generator.mjs

.PHONY: test-publish
test-publish: test-release e2e ## Full pre-publish verification
	@echo "$(GREEN)✓ ready to publish$(NC)"

# ─── Builds ──────────────────────────────────────────────────────────────────

.PHONY: build
build: ## Build the four binaries (release)
	cargo build --release
	@echo "$(GREEN)✓$(NC) target/release/{pack-proving-key,pack-verifying-key,verify-proof,bench-circom}"

.PHONY: build-debug
build-debug: ## Build the binaries (debug)
	cargo build

# The npm package.json is rendered from a template so its version cannot drift
# from Cargo.toml — one source of truth, checked by parsing the result.
define package-wasm
@node -e "\
	const fs = require('fs');\
	const v = fs.readFileSync('Cargo.toml', 'utf8').match(/^version\s*=\s*\"(.+)\"/m);\
	if (!v) throw new Error('no version in Cargo.toml');\
	const out = fs.readFileSync('npm/package.json.template', 'utf8').replace(/__VERSION__/g, v[1]);\
	JSON.parse(out);\
	fs.writeFileSync('pkg/package.json', out);\
"
@cp npm/README.md pkg/README.md
@echo "$(GREEN)✓$(NC) pkg/ — @orbinum/groth16-proofs"
endef

.PHONY: build-wasm
build-wasm: ## Build the wasm package (release)
	@command -v wasm-pack >/dev/null || { echo "wasm-pack not found — run 'make install-tools'"; exit 1; }
	wasm-pack build --target web --out-dir ./pkg --release --features wasm
	$(package-wasm)

.PHONY: build-wasm-dev
build-wasm-dev: ## Build the wasm package (unoptimized)
	@command -v wasm-pack >/dev/null || { echo "wasm-pack not found — run 'make install-tools'"; exit 1; }
	wasm-pack build --target web --out-dir ./pkg --dev --features wasm
	$(package-wasm)

.PHONY: build-all
build-all: build build-wasm ## Native + wasm

# ─── Workflows ───────────────────────────────────────────────────────────────

.PHONY: dev
dev: fmt lint test ## Format, lint, test

.PHONY: bench
bench: build ## Benchmark proving against the unshield fixture
	@test -f $(CIRCUITS)/keys/unshield_pk.zkey \
		|| { echo "needs $(CIRCUITS) with built keys"; exit 1; }
	./target/release/bench-circom unshield \
		$(CIRCUITS)/fixtures/unshield.witness.json \
		$(CIRCUITS)/keys/unshield_pk.zkey 3

.PHONY: doc
doc: ## Build and open the API docs
	cargo doc --no-deps --open

.PHONY: audit
audit: ## Check dependencies for advisories
	@command -v cargo-audit >/dev/null || cargo install cargo-audit --locked
	cargo audit

.PHONY: clean
clean: ## Remove build artifacts
	cargo clean
	rm -rf pkg/

.PHONY: install-tools
install-tools: ## Install rustfmt, clippy and wasm-pack
	rustup component add rustfmt clippy
	@command -v wasm-pack >/dev/null \
		|| curl https://rustwasm.org/wasm-pack/installer/init.sh -sSf | sh
