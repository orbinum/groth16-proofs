# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.0](https://github.com/orbinum/groth16-proofs/releases/tag/v4.0.0) - 2026-08-27

There is no 3.1.0. This release was prepared under that number and became a major
when `from_hex_le` was removed rather than left deprecated: dropping a `pub use` is
a breaking change, and 3.0.0 shipped that function without a deprecation notice. The
attribute it later carried said `will be removed in 4.0`, so this is that release.

### Security

An adversarial audit before publishing — three parallel code reviews plus real
proofs generated with all three published circuits and then attacked. Eight
findings, all fixed. Nothing found accepted a forged proof; every finding is a
denial of service or a canonicality break, and most are reachable from
`generate_proof_wasm`, which is the path the wallet runs.

- **A hostile `.ark` aborted the process with 250 KB.** The guard bounded
  `num_constraints` against the remaining bytes, but that is not the number the
  allocation comes from: `MatrixRows` is a `Vec`, and ark-serialize reads _its own_
  `u64` length prefix and calls `Vec::with_capacity` before reading any element.
  Two independent fields, one checked. The prefix is now read and reconciled with
  the header before anything is sized from it.

- **Column indices truncated silently on wasm32.** ark-serialize deserializes them
  as `<u64>::from_le_bytes(bytes) as usize` (impls.rs:148), which drops the high 32
  bits on the wallet's own target — two different files decoded to one matrix. The
  matrix section is now re-serialized and required to reproduce the bytes it was
  read from.

- **A witness of the wrong length panicked rather than erroring.** `prove_circom`
  checked the witness against `num_instance_variables` (5 for value_proof) instead
  of the circuit's real width (1157), and arkworks indexes with the matrices'
  columns unchecked (`r1cs_to_qap.rs:29`). Measured: lengths 5, 6, 578 and 1155 all
  aborted, and wasm has no unwinding, so each one took the module down. An overlong
  witness was quieter and also wrong — `msm_bigint` truncates it silently, so the
  caller got a well-formed proof that could never verify. Both ends are now
  rejected.

- **`vk_hash` was not injective.** `from_decimal_str` used
  `from_le_bytes_mod_order`, which reduces rather than rejects, and
  `BigUint::parse_bytes` accepts a leading `+` and skips `_`. Measured on a real
  verifying key: `x`, `x + p`, `"000…x"` and `"2_049…"` all packed to identical
  bytes and the same hash. That is not a forgery — they are one field element, and
  both keys verify the same proofs — but the JSON someone audits and the JSON
  someone registers could differ textually and be indistinguishable afterwards.
  Canonical decimal is now required. Verified against every published artifact
  first: 0 of 51,814 witness elements and 0 verifying-key coordinates are
  non-canonical, so nothing real is refused.

- **`read_zkey` aborted on malformed input.** Five inherited panic sites — a missing
  section, non-UTF8 magic, two unchecked subtractions, an unvalidated `u32`
  indexing a two-element vec — plus the worse one: the point constructors used
  `Affine::new`, which asserts `is_on_curve()` **in release builds**. Flipping one
  byte at 30 positions in a real `.zkey` aborted 27 times. All now return `Err`;
  250 hostile inputs produce zero panics. Each divergence from upstream is marked
  in place.

- **The `.ark` parser accepted trailing bytes.** A real artifact with a megabyte of
  padding appended parsed as valid. `proof-generator` verifies the manifest sha256
  fail-closed, so it was not exploitable there — but a format that accepts padding
  is not the canonical format the manifest claims to pin.

- **`verify_proof` accepted more than 128 bytes.** `deserialize_compressed` reads
  from the front of a slice and ignores the rest, so a 129-byte input with a valid
  proof in its first 128 bytes verified. Two encodings of one proof.

- **The G2 subgroup check had no test.** It is the line that stops the small-subgroup
  attack on pairing verification, and every test that reached `validate` failed at
  the on-curve branch above it. Now covered by a point that is genuinely on the
  curve and genuinely outside the prime-order subgroup.

### Fixed

- **Proofs now verify.** `prove_from_witness` called `Groth16::<Bn254>::prove`, which uses
  arkworks' default QAP reduction. Circom needs `CircomReduction`: the two compute the H
  polynomial differently — arkworks takes (AB-C)/Z in the evaluation domain and transforms
  back, snarkjs takes the odd coefficients of (AB-C) over a domain twice as large. A proof
  built with the wrong one is well-formed, deserializes cleanly, is exactly 128 bytes, and
  **never verifies**. Every proof this crate produced was invalid.

  Nothing caught it because nothing verified a proof: the tests for that function are all
  negative — empty witness, zero public signals, invalid key bytes — and the happy path only
  ever asserted a byte count. It was always 128.

  The scope was the whole arkworks backend, `src/wasm.rs` included, so
  `@orbinum/proof-generator`'s `{backend: 'arkworks'}` never worked either. It went unnoticed
  because `@orbinum/circuits` shipped no `ark` manifest entries, so the provider threw before
  reaching the prover — one bug hiding another.

### Added

- `prove_circom(pk, matrices, witness)` — the correct prover. Takes the proving key by
  reference: deserializing costs roughly half a second on an M4 and belongs once per session, not once per
  proof. Reads the public-signal count from the key's own matrices rather than from an
  argument that can disagree with it.
- `verify_proof(vk, public_inputs, proof)` and `public_inputs(matrices, witness)`. The crate
  could not verify a proof before, and signal extraction was open-coded in two places.
- **`.ark` v2** (`write_ark_v2` / `read_ark_v2`) — an artifact carrying the proving key _and_
  its constraint matrices. Proving needs both and a v1 `.ark` has only the key, so a v1 file
  cannot produce a proof at all. Measured on unshield: 4.83 MB against the `.zkey`'s 8.25 MB,
  with the matrices adding 1.24 MB and deserializing in about a millisecond. Only A and B are
  stored — `CircomReduction` derives C from their evaluations. A v1 file is rejected by name
  rather than failing deep in deserialization.
- `generate_proof_wasm(artifact_bytes, witness_bytes)` — takes a `.ark` v2 and a raw
  little-endian witness. The old ABI serialized 16,928 field elements to decimal-string JSON,
  hundreds of kilobytes of text parsed back one BigUint at a time.
- `pack-proving-key` — `.zkey` to `.ark` v2. Previously lived in the `circuits`
  repository as a build script; it belongs beside the format it writes.
- `bench-circom` — **verifies every proof it times.** An unverified timing measures nothing,
  which is how `bench-groth16` reported 48 ms for proofs that were never valid. Reports key
  load, prove and verify separately, since on a phone they have different characters.
- `verify-proof` — a proof against a verifying key, for callers outside this crate.
- **A test suite that can fail.** The crate had 48 tests passing in 0.01 s and not one of them
  produced a real proof; every `prove_from_witness` test was negative and the happy path only
  asserted a byte count. 129 now, across eight files:
  - `prove_and_verify.rs` — prove and verify in one run, including from a round-tripped and
    from a shipped `.ark` v2.
  - `cross_verify.rs` — **snarkjs verifies our proofs, and we verify snarkjs's.** Every other
    test checks arkworks against itself, which is exactly what the QAP bug survived: prover
    and verifier agreed perfectly with each other and disagreed with Circom. The chain accepts
    what snarkjs accepts, so this is the test that decides whether the crate can ship.
  - `adversarial.rs` — 17 ways a proof can be wrong while looking right: each public signal
    altered in turn, signals reordered or truncated, a witness that breaks the constraints, a
    flipped bit, a key from another circuit, an artifact cut short at five different points.
  - `cli.rs` — the binaries as a release pipeline uses them, including that `verify-proof`
    rejects a corrupted proof (without which it would pass against a binary that always
    exits 0).
  - `vendor.rs` — pins the vendored ark-circom behaviour, replacing the upstream tests that
    had to be dropped with the wasmer dependency.
- The `tests/e2e/` suite — four scripts that prove through the real `pkg/` build rather than
  the library, and verify what comes back. `make e2e` runs them and `make test-publish`
  includes it. A wasm module that compiles is not a wasm module that works, and nothing in
  the Rust suite would notice if the bindgen boundary mangled a byte array on the way through.
- `make test-publish` — the Rust suite in release mode plus the wasm package. What has to pass
  before publishing.

### Changed

- **BREAKING — `convert-vk` is now `pack-verifying-key`, and `convert-ark-v2` is
  `pack-proving-key`.** The old names described the mechanism (converting a format) rather
  than the output, and the two read as variants of one tool when they are opposite ends of a
  trusted setup: one packs the key the chain verifies against, the other the key a wallet
  proves with. Callers in `circuits` and the node's VK workflows are updated;
  `CONVERT_VK_BIN` becomes `PACK_VERIFYING_KEY_BIN`.
- **`make test` and CI no longer pass `--lib`.** That flag skips `tests/`, where every test
  that proves and then verifies lives — a suite that only ran the unit tests is how a prover
  producing invalid proofs passed CI for two major versions. `make test-lib` keeps the fast
  path for local iteration.
- **`ark-circom` is no longer a dependency.** `CircomReduction` and `read_zkey` are vendored
  into `src/vendor/` (475 lines, MIT/Apache-2.0, attributed). Neither touches WebAssembly, but
  ark-circom's default features pull in **wasmer** — a complete WASM runtime — for a witness
  calculator this crate never calls. Carrying an interpreter for the language the native
  prover exists to leave, into a binary where every megabyte is an app-store download, is not
  a trade worth making for 475 lines. Disabling its default features is not an option: wasmer
  is not optional there.

  Attribution is in `src/vendor/mod.rs` and at the head of each vendored file rather than as
  copied licence texts. ark-circom is MIT OR Apache-2.0 and this crate takes it under MIT —
  one of its own two options, and the one that composes cleanly with the GPL.

- **Licence is now GPL-3.0-or-later only.** It was `Apache-2.0 OR GPL-3.0-or-later`, and the
  GPL text carried a Classpath exception — which permits linking proprietary modules, the
  opposite of what a copyleft licence is for. Both are gone: one `LICENSE` file, the canonical
  GPL-3 text with an Orbinum copyright notice and no exception.

  The vendored ark-circom code moves from its Apache-2.0 option to its MIT one. MIT is
  GPL-compatible and adds no terms; Apache-2.0 is one-way compatible with GPL-3 but carries
  patent provisions the GPL does not, so MIT is the cleaner fit for a GPL-only work. The
  upstream copyright notice stays at the head of both files, which is MIT's only condition.

### Removed

- **Everything that proved through the wrong reduction.** `prove_from_witness`,
  `generate_proof_from_witness`, `generate_proof_from_decimal_wasm`, the `WitnessCircuit`
  adapter they shared, and the `generate-proof-from-witness` and `bench-groth16` binaries.

  Deprecating them was considered and rejected: their only possible use is generating proofs
  that do not verify, so a caller reaching for one is always making a mistake. A compile error
  is a better outcome than a deprecation warning above a silent failure. `bench-groth16` went
  with them because it measured that path — its 48 ms figure was for invalid proofs, and
  keeping a benchmark that reports impossible numbers invites someone to trust them.

- `decimal_to_field` and `hex_to_field`, the 2.x compatibility shims. Nothing used them;
  `from_decimal_str::<Fr>` was the same function with an explicit field parameter.

- `from_hex_le`, which replaced `hex_to_field` and then found no consumer of its own —
  not in this crate, not in `@orbinum/proof-generator`, not in `circuits`, and not in the
  wasm surface. It carried nine unit tests, more than `verify_proof` has, for a function
  nothing called. Use `from_decimal_str` for snarkjs input and `witness_from_le_bytes` for
  `.wtns` data.

  `field_to_le_hex` is a different function and stays: it converts a field element *to*
  the chain's little-endian hex, and `generate_proof_wasm` returns every public signal
  through it.

### Baseline

Apple M4, unshield circuit, every proof verified: prove **131 ms**, key load 573 ms, verify
1.8 ms.

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
