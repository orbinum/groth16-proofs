# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

[1.0.0]: https://github.com/orbinum/groth16-proofs/releases/tag/v1.0.0

### Changed
- **BREAKING**: `generate_proof_wasm()` now accepts `num_public_signals: usize` instead of `circuit_type: &str`
  - Makes the library truly generic and usable with any Groth16 circuit
  - No need to modify source code for custom circuits

### Added
- Validation for `num_public_signals` parameter (must be > 0 and < witness length)

### Removed
- Hardcoded circuit type mappings ("unshield", "transfer", "disclosure")

## [0.1.0] - 2026-02-12

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

[0.1.0]: https://github.com/orbinum/groth16-proofs/releases/tag/v0.1.0
