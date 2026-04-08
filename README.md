# groth16-proofs

> High-performance Groth16 proof generator using arkworks for Orbinum privacy protocol

[![npm version](https://img.shields.io/npm/v/@orbinum/groth16-proofs.svg)](https://www.npmjs.com/package/@orbinum/groth16-proofs)
[![Crates.io](https://img.shields.io/crates/v/groth16-proofs.svg)](https://crates.io/crates/groth16-proofs)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20GPL--3.0-blue)](./LICENSE-APACHE2)

Efficient **Groth16 zero-knowledge proof generator** for Orbinum's privacy protocol. Compiles to both native Rust and WebAssembly for maximum flexibility.

## 🚀 Quick Start

### Install

**npm/yarn/pnpm** (WASM for JavaScript/TypeScript):
```bash
npm install @orbinum/groth16-proofs
```

**Rust** (Native binary):
```toml
[dependencies]
groth16-proofs = "2.2"
```

### Use

**JavaScript/TypeScript**:
```typescript
import * as groth16 from '@orbinum/groth16-proofs';
import * as snarkjs from 'snarkjs';

// Initialize WASM
await groth16.default();
groth16.init_panic_hook();

// Calculate witness with snarkjs
const witnessArray = await snarkjs.wtns.exportJson('witness.wtns');

// Generate proof (no conversion needed!)
const result = groth16.generate_proof_from_decimal_wasm(
  5,  // number of public signals
  JSON.stringify(witnessArray),  // direct from snarkjs
  provingKeyBytes
);

const { proof, publicSignals } = JSON.parse(result);
```

**Rust**:
```rust
use groth16_proofs::generate_proof_from_witness;

let proof = generate_proof_from_witness(&witness, "proving_key.ark")?;
```

📖 **Full guides**: 
- [Installation](./docs/installation.md)
- [Usage](./docs/usage.md)
- [Release Process](./docs/release.md)

## What Is This?

This crate generates **128-byte compressed Groth16 proofs** from witness data using the arkworks library. It supports:

- **Performance**: ~1.6–1.8s WASM (small circuits, post-warmup); native Rust faster
- **Curves**: BN254 (Ethereum-compatible)
- **Targets**: Native (Rust) + WebAssembly
- **Circuits**: Unshield, Transfer, Disclosure
- **WASM Input Format**: Decimal witness (snarkjs native)

For interoperability with snarkjs-generated proofs, the WASM API also exposes
`compress_snarkjs_proof_wasm()` to convert `pi_a/pi_b/pi_c` JSON into arkworks
canonical compressed proof bytes (`0x...`, 128 bytes).

## Architecture

```
┌────────────────────────────────────────────────┐
│ groth16-proofs                                 │
├────────────────────────────────────────────────┤
│                                                │
│  ┌──────────────────────────────────────────┐  │
│  │ Core (src/proof.rs)                      │  │
│  │ - Groth16 proof generation               │  │
│  │ - Arkworks constraint system             │  │
│  └──────────────────────────────────────────┘  │
│                                                │
│  ┌──────────────────┐  ┌───────────────────┐   │
│  │ Native Binary    │  │ WASM Module       │   │
│  │ (Rust)           │  │ (JavaScript)      │   │
│  │ - CLI tool       │  │ - Browser support │   │
│  │ - Fastest        │  │ - Portable        │   │
│  └──────────────────┘  └───────────────────┘   │
│                                                │
│  ┌──────────────────────────────────────────┐  │
│  │ Dependencies (arkworks ecosystem)        │  │
│  │ - ark-bn254, ark-groth16, ark-serialize  │  │
│  └──────────────────────────────────────────┘  │
│                                                │
└────────────────────────────────────────────────┘
```

## Components

| Component | Location | Purpose |
|-----------|----------|---------|
| **proof.rs** | `src/` | Core Groth16 generation using arkworks |
| **circuit.rs** | `src/` | Circuit wrapper implementing ConstraintSynthesizer |
| **utils.rs** | `src/` | Format conversions (decimal ↔ hex ↔ field elements) |
| **wasm.rs** | `src/` | WASM FFI bindings and public API re-exports |
| **wasm/snarkjs_proof.rs** | `src/wasm/` | snarkjs proof parsing/validation and compression |
| **binary** | `src/bin/` | CLI tool for Node.js integration |

## Features

✅ **Multiple Targets**: Native + WASM  
✅ **Fast**: ~1.6–1.8s WASM (post-warmup); native Rust faster  
✅ **WASM Decimal-Only API**: Direct snarkjs witness input  
✅ **Type-Safe**: Memory-safe cryptography  
✅ **Well-Tested**: 21+ tests included  
✅ **Automated Release**: CI/CD pipeline ready  
✅ **Zero External Calls**: Everything bundled  

## Development

### Quick Commands

```bash
make help              # Show all commands
make dev              # Format → Lint → Test
make build            # Build native
make build-wasm       # Build WASM
make build-all        # Build both
```

See [Makefile](./Makefile) for all available targets.

## Documentation

- [**Installation Guide**](./docs/installation.md) - Setup for Rust and JavaScript
- [**Usage Guide**](./docs/usage.md) - Complete API reference with examples
- [**Witness Formats**](./docs/witness-formats.md) - Decimal witness flow and format notes
- [**Release Process**](./docs/release.md) - How releases are managed

## Publishing

This crate is published to both registries:

- **Rust**: [crates.io/crates/groth16-proofs](https://crates.io/crates/groth16-proofs)
- **npm**: [npmjs.com/package/@orbinum/groth16-proofs](https://www.npmjs.com/package/@orbinum/groth16-proofs)

## License

- Apache License, Version 2.0 ([LICENSE-APACHE2](LICENSE-APACHE2))
- GNU General Public License v3.0 or later ([LICENSE-GPL3](LICENSE-GPL3))
