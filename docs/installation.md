# Installation Guide

This guide explains how to install and use `groth16-proofs` as either a native Rust library or a WASM module for JavaScript/TypeScript.

## Requirements

- **Rust**: 1.70+ (for native development)
- **Node.js**: 16+ (for WASM and TypeScript)
- **wasm-pack**: 0.12+ (for WASM compilation, automatically installed via Makefile)

## Installation

### As a Rust Crate

Add to your `Cargo.toml`:

```toml
[dependencies]
groth16-proofs = "2.0"
```

Then import in your code:

```rust
use groth16_proofs::generate_proof_from_witness;

let proof = generate_proof_from_witness(&witness, "proving_key.ark")?;
```

### As a WASM Module

Install from npm:

```bash
npm install @orbinum/groth16-proofs
```

Import in TypeScript/JavaScript:

```typescript
import init, { compress_snarkjs_proof_wasm } from '@orbinum/groth16-proofs';
import groth16pkg from '@orbinum/groth16-proofs/package.json';

// Initialize WASM from CDN (recommended — no bundling required)
const WASM_CDN = `https://unpkg.com/@orbinum/groth16-proofs@${groth16pkg.version}/groth16_proofs_bg.wasm`;
await init(WASM_CDN);

// Convert snarkjs proof to on-chain arkworks format (128 bytes)
const compressed = compress_snarkjs_proof_wasm(JSON.stringify(snarkjsProof));
// compressed => "0x..." (128 bytes)
```

### Development Installation

For contributing or building from source:

```bash
# Clone the repository
git clone https://github.com/orbinum/groth16-proofs.git
cd groth16-proofs

# Install development dependencies
make install-tools

# Verify installation
cargo --version
wasm-pack --version
```

## Building from Source

### Native Binaries

```bash
make build
# Outputs:
#   ./target/release/generate-proof-from-witness  (Rust-native proof generation)
#   ./target/release/convert-vk                   (VK JSON → arkworks binary)
```

### WASM Module

```bash
make build-wasm
# Output: ./pkg/groth16_proofs_bg.wasm
```

### Both

```bash
make build-all
```

## Compilation Targets

### Native (Rust)

**Best for**: Server-side proof generation, Node.js native modules, high performance

```bash
cargo build --release
# Proof generation
./target/release/generate-proof-from-witness witness.json proving_key.ark
# VK format conversion (snarkjs JSON → on-chain arkworks binary)
./target/release/convert-vk verification_key_unshield.json verification_key_unshield.bin
```

**Advantages**:
- ✅ Fastest proof generation (5-8 seconds)
- ✅ Direct file I/O access
- ✅ Deterministic randomness (testable)
- ✅ `convert-vk` produces 424-byte arkworks binary required by on-chain verifier

### WASM

**Best for**: Browser usage, universal JavaScript, edge computing

```bash
wasm-pack build --target web --out-dir ./pkg --release --features wasm
```

**Advantages**:
- ✅ Runs in browsers natively
- ✅ No server required
- ✅ Can use with Node.js via npm
- ✅ Sandboxed execution environment

**Trade-offs**:
- ⚠️ Larger bundle (~3-5 MB)
- ⚠️ Slightly higher initialization time
- ⚠️ Memory constraints in browsers

## Quick Start

Once installed, see the **[Usage Guide](./usage.md)** for:
- Complete API reference for Rust and WASM
- Full working examples (Browser, Node.js, native)
- Error handling and best practices
- Performance optimization tips

**Minimal example**:

```rust
// Rust — native proof generation
use groth16_proofs::generate_proof_from_witness;
let proof = generate_proof_from_witness(&witness_hex, "key.ark")?;
```

```bash
# CLI — convert VK for on-chain registration
./target/release/convert-vk verification_key_unshield.json verification_key_unshield.bin
```

```typescript
// WASM — compress snarkjs proof to on-chain format
import init, { compress_snarkjs_proof_wasm } from '@orbinum/groth16-proofs';
await init(WASM_CDN);
const compressed = compress_snarkjs_proof_wasm(JSON.stringify(snarkjsProof));
```

## Configuration

### Feature Flags

The crate supports feature-based compilation:

```toml
[features]
wasm = ["wasm-bindgen", "console_error_panic_hook"]
```

**Build without WASM support**:
```bash
cargo build --release --no-default-features
```

**Build with WASM support** (default):
```bash
cargo build --release --features wasm
```

## Troubleshooting

### `wasm-pack not found`

Install wasm-pack:
```bash
make install-tools
```

### WASM bundle too large

The WASM module is ~3-5 MB (compressed ~1 MB). Load from CDN instead of bundling:

```typescript
import groth16pkg from '@orbinum/groth16-proofs/package.json';
const WASM_CDN = `https://unpkg.com/@orbinum/groth16-proofs@${groth16pkg.version}/groth16_proofs_bg.wasm`;
await init(WASM_CDN); // does not bundle the .wasm into your JS bundle
```

### Proof generation is slow

Native Rust is 20-30% faster than WASM. For time-critical applications:
- Use native binary in Node.js
- Generate proofs server-side
- Pre-compute and cache proofs

### Type errors in TypeScript

Ensure your TypeScript config includes WASM types:

```json
{
  "compilerOptions": {
    "lib": ["ES2020", "DOM"],
    "module": "ESNext",
    "target": "ES2020"
  }
}
```

## Performance Comparison

| Metric | Native | WASM |
|--------|--------|------|
| Time | ~5-8s | ~6-10s |
| Bundle | N/A | 3-5 MB |
| Setup | 0s | ~500ms |
| Memory | 2 GB | 200-500 MB |
| Platform | Linux/Mac/Win | Browser/Node.js |

## Next Steps

- Read the [Usage Guide](./usage.md) for detailed API reference
