# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0](https://github.com/orbinum/groth16-proofs/releases/tag/v3.0.0) - 2026-04-08

### Added

- `ProofError` — unified error enum replacing `String` errors throughout the crate.
  Variants: `WitnessEmpty`, `WitnessConversion`, `ProvingKeyIo`, `ProvingKeyParse`,
  `ProveGeneration`, `ProofSerialization`, `NumPublicSignals`, `WitnessJsonParse`,
  `SnarkjsProofParse`.
- `from_decimal_str::<F>()` — generic `PrimeField` parser for decimal strings,
  replaces the `Bn254Fr`-only `decimal_to_field()` with a type-parameterized version
  usable for any field (`Fr`, `Fq`, etc.).
- `from_hex_le::<F>()` — generic `PrimeField` parser for little-endian hex strings,
  replaces the `Bn254Fr`-only `hex_to_field()`.
- `prove_from_witness()` — core prover function shared by the native and WASM paths.
  Accepts already-loaded `pk_bytes` and a converted witness; eliminates code duplication
  that existed between `proof.rs` and `wasm.rs`.
- `compress_snarkjs_proof()` — native (non-WASM) snarkjs proof compression, available
  for server-side Rust code (previously only exposed as `compress_snarkjs_proof_wasm`).
- New `src/codec.rs` module: snarkjs JSON → arkworks compressed bytes, decoupled from
  the `wasm` feature.
- New `src/prover.rs` module: core Groth16 prove logic with input validation.
- New `src/field.rs` module: generic field element parsers.
- New `src/error.rs` module: `ProofError` type.
- `decimal_to_field()` and `hex_to_field()` remain as backward-compat shims in
  `src/utils.rs` (thin wrappers over the new generic functions).

### Changed

- **BREAKING**: `generate_proof_from_witness()` signature changed — now requires an
  explicit `num_public_signals: usize` third argument.
  ```rust
  // Before (2.x)
  generate_proof_from_witness(&witness_hex, "key.ark")
  // After (3.0)
  generate_proof_from_witness(&witness_hex, "key.ark", 5)
  ```
- **BREAKING**: `generate_proof_from_witness()` now returns `Result<Vec<u8>, ProofError>`
  instead of `Result<Vec<u8>, String>`.
- **BREAKING**: `prove_from_witness()` (new public function) also returns `ProofError`;
  callers that previously matched on `String` errors must switch to `ProofError` variants.
- `WitnessCircuit` struct: `num_public_signals` is now an explicit field instead of
  being computed from a heuristic `(witness.len() / 100).clamp(1, 10)` — which produced
  wrong public signal counts for `disclosure` (got 1, expected 4) and `transfer`
  (got 10, expected 5).
- `src/wasm.rs` rewritten as a thin wrapper using `prove_from_witness()`; no duplicated
  prove logic.
- `src/wasm/snarkjs_proof.rs` rewritten as a 9-line WASM binding delegating to
  `codec::compress_snarkjs_proof()`.
- `bench-groth16` binary: accepts optional `[num_public=5]` sixth argument.
- `generate-proof-from-witness` binary: `num_public_signals` derived from CLI arg,
  JSON field, or default — no longer heuristic.
- Removed stale `#!/usr/bin/env rust` shebang from `generate-proof-from-witness` source.
- Removed trivial tautological test (`assert_eq!(128, 128)`) in `proof.rs`.
- Docs updated: `installation.md`, `usage.md`, `witness-formats.md` reflect new API,
  `ProofError` variants, generic `from_decimal_str`/`from_hex_le`, and correct
  `num_public_signals` semantics.

### Fixed

- **Bug**: `WitnessCircuit::generate_constraints` used `(witness.len() / 100).clamp(1,10)`
  as a heuristic for `num_public_signals`. For `disclosure` (4 public signals, ~1171
  witness elements) this produced 1; for `transfer` (5 public signals, ~11,808 elements)
  this produced 10. Fixed by requiring callers to pass the exact value.

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

[Unreleased]: https://github.com/orbinum/groth16-proofs/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/orbinum/groth16-proofs/releases/tag/v3.0.0
[2.1.0]: https://github.com/orbinum/groth16-proofs/releases/tag/v2.1.0
[2.0.0]: https://github.com/orbinum/groth16-proofs/releases/tag/v2.0.0
[1.0.0]: https://github.com/orbinum/groth16-proofs/releases/tag/v1.0.0
[0.1.0]: https://github.com/orbinum/groth16-proofs/releases/tag/v0.1.0
