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
groth16-proofs = "0.1"
```

Then import in your code:

```rust
use orbinum_groth16_proofs::generate_proof_from_witness;

let proof = generate_proof_from_witness(&witness, "proving_key.ark")?;
```

### As an NPM Package (WASM)

Install via npm:

```bash
npm install groth16-proofs
```

Or yarn:

```bash
yarn add groth16-proofs
```

Then import in TypeScript/JavaScript:

```typescript
import { generateProofWasm } from 'orbinum-groth16-proofs';

const result = generateProofWasm('unshield', witnessJson, provingKeyBytes);
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

### Native Binary

```bash
make build
# Output: ./target/release/generate-proof-from-witness
```

### WASM Module

```bash
make build-wasm
# Output: ./pkg/orbinum_groth16_proofs.wasm
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
./target/release/generate-proof-from-witness witness.json proving_key.ark
```

**Advantages**:
- ✅ Fastest proof generation (5-8 seconds)
- ✅ Direct file I/O access
- ✅ Deterministic randomness (testable)
- ✅ Minimal dependencies

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

### Rust Example

```rust
use orbinum_groth16_proofs::generate_proof_from_witness;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Witness data (hex-encoded field elements)
    let witness = vec![
        "0x0100000000000000000000000000000000000000000000000000000000000000".to_string(),
        // ... ~11,808 elements total
    ];
    
    // Generate proof
    let proof_bytes = generate_proof_from_witness(&witness, "proving_key.ark")?;
    
    println!("Proof (128 bytes): 0x{}", hex::encode(&proof_bytes));
    Ok(())
}
```

### TypeScript Example (Browser)

```typescript
import { generateProofWasm } from 'orbinum-groth16-proofs';

async function generateProof() {
  // Load witness and proving key
  const witness = [
    "0x0100000000000000000000000000000000000000000000000000000000000000",
    // ...
  ];
  
  const provingKeyFile = await fetch('proving_keys/unshield.ark');
  const provingKeyBytes = new Uint8Array(await provingKeyFile.arrayBuffer());
  
  // Generate proof
  try {
    const resultJson = generateProofWasm(
      'unshield',
      JSON.stringify(witness),
      provingKeyBytes
    );
    
    const { proof, publicSignals } = JSON.parse(resultJson);
    console.log('✓ Proof generated:', proof);
    console.log('✓ Public signals:', publicSignals);
  } catch (error) {
    console.error('✗ Proof generation failed:', error);
  }
}
```

### TypeScript Example (Node.js WASM)

```typescript
import { generateProofWasm } from 'orbinum-groth16-proofs';
import fs from 'fs';

const witness = JSON.parse(fs.readFileSync('witness.json', 'utf-8'));
const provingKeyBytes = fs.readFileSync('proving_key.ark');

const result = generateProofWasm('unshield', JSON.stringify(witness), new Uint8Array(provingKeyBytes));
const { proof, publicSignals } = JSON.parse(result);

console.log(proof, publicSignals);
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

The WASM module is ~3-5 MB (compressed ~1 MB). Consider:
- Serving over gzip/brotli compression
- Using code splitting for lazy loading
- Pre-generating proofs server-side (native)

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
- Check the [tests](../src/) for more examples
- See [GitHub Actions CI](../.github/workflows/) for build examples
