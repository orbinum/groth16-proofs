# @orbinum/groth16-proofs

> High-performance Groth16 proof generator using arkworks for Orbinum privacy protocol

[![npm version](https://img.shields.io/npm/v/@orbinum/groth16-proofs.svg)](https://www.npmjs.com/package/@orbinum/groth16-proofs)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20GPL--3.0-blue)](https://github.com/orbinum/groth16-proofs/blob/main/LICENSE-APACHE2)

WebAssembly bindings for efficient **Groth16 zero-knowledge proof generation** using arkworks.

## 🚀 Installation

```bash
npm install @orbinum/groth16-proofs
```

## 📖 Usage

### Basic Example

```typescript
import * as groth16 from '@orbinum/groth16-proofs';

// Initialize WASM module
await groth16.default();
groth16.init_panic_hook();

// Generate proof from decimal witness (snarkjs native format)
const result = groth16.generate_proof_from_decimal_wasm(
  numPublicSignals,
  JSON.stringify(witnessArray),
  provingKeyBytes
);

const { proof, publicSignals } = JSON.parse(result);
```

### Node.js

```typescript
import * as groth16 from '@orbinum/groth16-proofs';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Load WASM manually in Node.js
const wasmPath = join(
  __dirname, 
  'node_modules/@orbinum/groth16-proofs/groth16_proofs_bg.wasm'
);
const wasmBytes = readFileSync(wasmPath);

await groth16.default({ module: wasmBytes });
groth16.init_panic_hook();
```

### Browser (with Bundlers)

```typescript
import * as groth16 from '@orbinum/groth16-proofs';

// Automatic WASM loading
await groth16.default();
groth16.init_panic_hook();
```

## 🔧 API

### `generate_proof_from_decimal_wasm(numPublicSignals, witnessJson, provingKeyBytes)`

Generate Groth16 proof from decimal witness (snarkjs native format - **recommended**).

**Parameters:**
- `numPublicSignals: number` - Number of public signals
- `witnessJson: string` - JSON stringified witness array (decimal strings)
- `provingKeyBytes: Uint8Array` - Proving key in arkworks format

**Returns:** `string` - JSON with `{ proof: string, publicSignals: string[] }`

### `compress_snarkjs_proof_wasm(proofJson)`

Convert a snarkjs Groth16 proof JSON (`pi_a`, `pi_b`, `pi_c`) into arkworks
canonical compressed proof bytes.

**Parameters:**
- `proofJson: string` - JSON stringified snarkjs proof

**Returns:** `string` - Hex string (`0x...`) with 128-byte compressed Groth16 proof

### `init_panic_hook()`

Initialize panic hook for better error messages.

### `default(input?)`

Initialize WASM module.

**Parameters:**
- `input?: { module: BufferSource }` - Optional WASM bytes (Node.js)

## 🔗 Related Packages

- [@orbinum/proof-generator](https://www.npmjs.com/package/@orbinum/proof-generator) - High-level proof orchestrator
- [groth16-proofs](https://crates.io/crates/groth16-proofs) - Rust crate (native)

## 📚 Documentation

Full documentation: https://github.com/orbinum/groth16-proofs

## 📄 License

Dual-licensed under Apache-2.0 OR GPL-3.0-or-later

## 🔒 Security

- Deterministic execution
- No network requests
- No local storage access
- Fully auditable (Rust source)

## 🐛 Issues

Report at: https://github.com/orbinum/groth16-proofs/issues
