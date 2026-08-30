# @orbinum/groth16-proofs

> High-performance Groth16 proof generator using arkworks for Orbinum privacy protocol

[![npm version](https://img.shields.io/npm/v/@orbinum/groth16-proofs.svg)](https://www.npmjs.com/package/@orbinum/groth16-proofs)
[![License](https://img.shields.io/badge/license-GPL--3.0--or--later-blue)](https://github.com/orbinum/groth16-proofs/blob/main/LICENSE)

WebAssembly bindings for efficient **Groth16 zero-knowledge proof generation** using arkworks.

## 🚀 Installation

```bash
npm install @orbinum/groth16-proofs
```

## 📖 Usage

### Basic Example

```typescript
import * as groth16 from "@orbinum/groth16-proofs";

// Initialize WASM module
await groth16.default();
groth16.init_panic_hook();

// A .wtns file's data section is already the format this takes:
// n × 32 little-endian bytes.
const result = groth16.generate_proof_wasm(artifactBytes, witnessBytes);

const { proof, publicSignals } = JSON.parse(result);
```

### Node.js

```typescript
import * as groth16 from "@orbinum/groth16-proofs";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));

// Load WASM manually in Node.js
const wasmPath = join(
  __dirname,
  "node_modules/@orbinum/groth16-proofs/groth16_proofs_bg.wasm",
);
const wasmBytes = readFileSync(wasmPath);

await groth16.default({ module_or_path: wasmBytes });
groth16.init_panic_hook();
```

### Browser (with Bundlers)

```typescript
import * as groth16 from "@orbinum/groth16-proofs";

// Automatic WASM loading
await groth16.default();
groth16.init_panic_hook();
```

## 🔧 API

### `generate_proof_wasm(artifactBytes, witnessBytes)`

Generate a Groth16 proof from a `.ark` v2 artifact and a raw witness.

**Parameters:**

- `artifactBytes: Uint8Array` — a `.ark` **v2** artifact: the proving key plus
  the circuit's constraint matrices. A v1 file holds only the key and is
  refused; regenerate it with `pack-proving-key`.
- `witnessBytes: Uint8Array` — the witness as `n × 32` little-endian bytes,
  exactly what a `.wtns` file's data section holds.

**Returns:** `string` — JSON with `{ proof: string, publicSignals: string[] }`.
The proof is 128 compressed bytes as `0x`-prefixed hex; each public signal is a
32-byte little-endian word, which is the encoding the chain expects.

The public-signal count is read from the artifact rather than passed in. It is
a property of the circuit, and a caller that gets it wrong produces a proof
that fails verification with nothing to explain why.

The witness must be exactly as wide as the circuit — not merely long enough to
cover the public signals. A short one used to abort the module; a long one was
silently truncated into a proof that could never verify. Both are now errors that
name the two lengths.

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

- `input?: { module_or_path: BufferSource | string | URL }` — the wasm bytes or a
  path to them. Under Node.js pass the bytes; in a bundler the default export
  resolves the `.wasm` on its own.

## 🔗 Related Packages

- [@orbinum/proof-generator](https://www.npmjs.com/package/@orbinum/proof-generator) - High-level proof orchestrator
- [groth16-proofs](https://crates.io/crates/groth16-proofs) - Rust crate (native)

## 📚 Documentation

Full documentation: https://github.com/orbinum/groth16-proofs

## 📄 License

GNU General Public License v3.0 or later — see
[LICENSE](https://github.com/orbinum/groth16-proofs/blob/main/LICENSE).

The vendored `ark-circom` code is taken under its MIT option, which is
GPL-compatible; the original copyright notice stays in those files.

## 🔒 Security

- **No network requests, no storage access.** The module reads its two arguments
  and returns a result.
- **Proofs are not deterministic, by design.** Groth16 draws two random field
  elements per proof, so proving the same statement twice gives two different
  128-byte proofs — both valid. Reusing that randomness would leak the witness.
- **Malformed input returns an error, not an abort.** wasm has no unwinding, so a
  panic would take the whole module down. Every input path — the artifact, the
  witness bytes, the proof JSON — was fuzzed to confirm it: 1063 hostile inputs,
  zero panics.
- **Artifact integrity is the caller's job.** This module does not know what a
  manifest is. Verify the sha256 of an artifact before handing it over;
  `@orbinum/proof-generator` does this fail-closed.
- Fully auditable — the Rust source is the whole of it.

## 🐛 Issues

Report at: https://github.com/orbinum/groth16-proofs/issues
