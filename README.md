# groth16-proofs

> High-performance Groth16 proof generator using arkworks for Orbinum privacy protocol

[![Crates.io](https://img.shields.io/crates/v/groth16-proofs.svg)](https://crates.io/crates/groth16-proofs)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20GPL--3.0-blue)](./LICENSE-APACHE2)

Efficient **Groth16 zero-knowledge proof generator** for Orbinum's privacy protocol. Compiles to both native Rust and WebAssembly for maximum flexibility.

## Quick Start

### Install

**Rust**:
```toml
[dependencies]
groth16-proofs = "0.1"
```

**JavaScript/npm**:
```bash
npm install groth16-proofs
```

### Use

**Rust**:
```rust
use orbinum_groth16_proofs::generate_proof_from_witness;

let proof = generate_proof_from_witness(&witness, "proving_key.ark")?;
```

**JavaScript (Browser/Node.js)**:
```typescript
import { generateProofWasm } from 'groth16-proofs';

const result = generateProofWasm('unshield', witnessJson, provingKeyBytes);
```

📖 **Full guides**: See [Installation](./docs/installation.md) and [Usage](./docs/usage.md)

## What Is This?

This crate generates **128-byte compressed Groth16 proofs** from witness data using the arkworks library. It supports:

- **Performance**: ~5-8 seconds per proof
- **Curves**: BN254 (Ethereum-compatible)
- **Targets**: Native (Rust) + WebAssembly
- **Circuits**: Unshield, Transfer, Disclosure

## Architecture

```
┌────────────────────────────────────────────────┐
│ orbinum-groth16-proofs                         │
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
| **utils.rs** | `src/` | Hex ↔ field element conversions |
| **wasm.rs** | `src/` | WASM FFI bindings with JSON I/O |
| **binary** | `src/bin/` | CLI tool for Node.js integration |

## Features

✅ **Multiple Targets**: Native + WASM  
✅ **Fast**: 5-8 second proof generation  
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

- 📖 [**Installation Guide**](./docs/installation.md) - Setup for Rust and JavaScript
- 📖 [**Usage Guide**](./docs/usage.md) - Complete API reference with examples
- 🔧 [**Development Guide**](./DEVELOPMENT.md) - CI/CD setup and secrets
- 🚀 [**Release Process**](./docs/release.md) - How releases are managed
- 🤝 [**Contributing**](./CONTRIBUTING.md) - How to contribute

## Performance

| Metric | Value |
|--------|-------|
| Proof Size | 128 bytes (compressed) |
| Generation Time | 5-8 seconds |
| Curve | BN254 |
| WASM Bundle | 3-5 MB |
| Native Binary | 10-15 MB |

**Native is 20-30% faster than WASM**. Choose based on your deployment target.

## Publishing

This crate is published to both registries:

- **Rust**: [crates.io/crates/groth16-proofs](https://crates.io/crates/groth16-proofs)

## License

- Apache License, Version 2.0 ([LICENSE-APACHE2](LICENSE-APACHE2))
- GNU General Public License v3.0 or later ([LICENSE-GPL3](LICENSE-GPL3))
