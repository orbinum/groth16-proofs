# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0](https://github.com/orbinum/groth16-proofs/releases/tag/v2.1.0) - 2026-04-07

### Added
- `convert-vk` binary: converts a snarkjs `verification_key_*.json` to a
  ~424-byte arkworks compressed binary (via `CanonicalSerialize::serialize_compressed`).
  Required for on-chain VK registration — the runtime `ArkVK::deserialize_compressed()`
  expects binary format, not raw JSON bytes.

### Changed
- `Makefile` `build` target now builds both `generate-proof-from-witness` and `convert-vk`.
- Docs updated (`installation.md`, `usage.md`, `witness-formats.md`) to document the
  current proof flows: CDN WASM init, snarkjs → `compress_snarkjs_proof_wasm` primary
  path, and `convert-vk` VK registration workflow.
- CHANGELOG is now maintained manually; removed `cargo-release` from the release workflow.

## [2.0.0](https://github.com/orbinum/groth16-proofs/releases/tag/v2.0.0) - 2026-02-16

### Added
- `compress_snarkjs_proof_wasm()` WASM API for snarkjs proof (`pi_a`, `pi_b`, `pi_c`) to arkworks canonical compressed bytes conversion.
- Internal `src/wasm/snarkjs_proof.rs` module to separate snarkjs parsing/validation/compression responsibilities.
- `npm/package.json.template` as source of truth for npm package metadata (rendered with release version in CI/local builds).

### Changed
- **BREAKING**: WASM proof generation is now decimal-only via `generate_proof_from_decimal_wasm()`.
- Documentation updated to reflect decimal-only WASM proof flow and snarkjs interoperability path.
- Release workflow now generates `pkg/package.json` from template (circuits-style), builds release asset (`orb-groth16-proof.tar.gz`), and publishes the rendered `pkg` package to npm.
- Release workflow trigger paths now include `npm/**` to ensure packaging metadata/template changes run through release automation.
- `Makefile` (`build-wasm`, `build-wasm-dev`) now renders `pkg/package.json` from template using `Cargo.toml` version for local parity with CI.
- `cargo-release` responsibility narrowed to version/changelog/tag preparation; WASM build is handled in CI release job to avoid duplicate builds.

### Removed
- **BREAKING**: Removed legacy WASM API `generate_proof_wasm()` (hex little-endian witness input).

## [1.0.0](https://github.com/orbinum/groth16-proofs/releases/tag/v1.0.0) - 2026-02-12

### Added
- **NEW**: `decimal_to_field()` function for converting snarkjs decimal strings to field elements
- **NEW**: `generate_proof_from_decimal_wasm()` WASM function accepting decimal witness format (snarkjs native)
- Support for decimal witness format (no conversion needed from snarkjs output)
- `num-bigint` dependency for decimal string parsing
- Validation for `num_public_signals` parameter (must be > 0 and < witness length)
- Automatic CHANGELOG updates via cargo-release in CI/CD

### Changed
- **BREAKING**: `generate_proof_wasm()` now accepts `num_public_signals: usize` instead of `circuit_type: &str`
  - Makes the library truly generic and usable with any Groth16 circuit
  - No need to modify source code for custom circuits
- Documentation updated to explain witness formats (decimal vs hex little-endian)
- Release workflow now uses cargo-release to automatically update CHANGELOG

### Removed
- Hardcoded circuit type mappings ("unshield", "transfer", "disclosure")

## [0.1.0](https://github.com/orbinum/groth16-proofs/releases/tag/v0.1.0) - 2026-02-12

### Added
- Initial public release of groth16-proofs
- Native Rust library for Groth16 proof generation
- WebAssembly (WASM) module for browser compatibility
- Support for BN254 curve
- Circuit types: unshield, transfer, disclosure
- Comprehensive test suite (21+ tests)
- CI/CD pipeline with cargo-release and GitHub Actions
- Automated publication to crates.io and npm
- Documentation: Installation, Usage, Development, and Release guides
- Makefile with development commands
- CHANGELOG following Keep a Changelog format

[Unreleased]: https://github.com/orbinum/groth16-proofs/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/orbinum/groth16-proofs/releases/tag/v2.0.0
[1.0.0]: https://github.com/orbinum/groth16-proofs/releases/tag/v1.0.0
[0.1.0]: https://github.com/orbinum/groth16-proofs/releases/tag/v0.1.0
