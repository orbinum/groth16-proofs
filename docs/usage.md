# Usage Guide

Complete API reference and usage examples for `groth16-proofs`.

## Overview

This library generates **Groth16 zero-knowledge proofs** from pre-calculated witness values. It processes:

1. **Input**: Witness (array of field elements) + Proving Key (binary file)
2. **Processing**: Converts to BN254 field elements, generates Groth16 proof
3. **Output**: 128-byte compressed proof + public signals

## Witness Formats

This library supports **two witness formats**:

### 1. **Decimal Format (snarkjs native)** - Recommended ✅

Direct output from snarkjs - no conversion needed:
```json
["1", "12345", "67890", ...]
```
Use `generate_proof_from_decimal_wasm()` or `decimal_to_field()`.

### 2. **Hex Little-Endian Format** (legacy)

Hex-encoded 32-byte field elements:
```json
["0x0100...00", "0x3930...00", ...]
```
Use `hex_to_field()`.

### Why Two Formats?

- **Decimal**: Native snarkjs output, no conversion overhead
- **Hex LE**: Required by arkworks internally (handled automatically)

The library converts decimal → hex LE internally, so you don't need to worry about the conversion.

## Proof Generation Flow

There are two distinct paths depending on your stack:

### Path A: snarkjs → WASM compress (browser / TypeScript — recommended ✅)

```
Circuit inputs + circuit.wasm + circuit_pk.zkey
    ↓ snarkjs.groth16.fullProve()
    ↓
{ pi_a, pi_b, pi_c }  (snarkjs proof JSON)
    + compress_snarkjs_proof_wasm()  [WASM]
    ↓
0x<128 bytes>  ← submitted on-chain
```

### Path B: Witness → arkworks native (Rust / CLI)

```
Witness (hex LE field elements) + proving_key.ark
    ↓ generate_proof_from_witness()  [Rust]
    ↓
0x<128 bytes>  ← same on-chain format
```

## Native Rust API

### `generate_proof_from_witness()`

Generate a Groth16 proof from witness data.

**Signature**:
```rust
pub fn generate_proof_from_witness(
    witness_hex: &[String],
    proving_key_path: &str,
    num_public_signals: usize,
) -> Result<Vec<u8>, ProofError>
```

**Arguments**:
- `witness_hex`: Array of hex-encoded field elements (little-endian, 32 bytes each)
- `proving_key_path`: Path to the `.ark` proving key file
- `num_public_signals`: Number of public signals (must be 1–(witness\_len-1))

**Returns**:
- `Ok(Vec<u8>)`: 128-byte compressed Groth16 proof
- `Err(ProofError)`: Typed error — see [`ProofError`](#proofError)

**Example**:
```rust
use groth16_proofs::generate_proof_from_witness;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let witness = vec![
        "0x0100000000000000000000000000000000000000000000000000000000000000".to_string(),
        "0x0200000000000000000000000000000000000000000000000000000000000000".to_string(),
        // ... 11,806 more elements
    ];
    
    let proof = generate_proof_from_witness(&witness, "circuits/my_circuit_pk.ark", 5)?;
    println!("Proof: 0x{}", hex::encode(&proof));
    
    Ok(())
}
```

### `decimal_to_field()`

Convert a decimal string (snarkjs format) to a BN254 field element.

> **Backward-compat shim** for `from_decimal_str::<Bn254Fr>()`. Prefer `from_decimal_str` for new generic code.

**Signature**:
```rust
pub fn decimal_to_field(decimal_str: &str) -> Result<Bn254Fr, String>
```

**Arguments**:
- `decimal_str`: Decimal string representation (e.g., `"12345"`)

**Example**:
```rust
use groth16_proofs::decimal_to_field;

let field_element = decimal_to_field("12345")?;
assert_eq!(field_element, Bn254Fr::from(12345u64));
```

### `hex_to_field()`

Convert a hex string (little-endian) to a BN254 field element.

> **Backward-compat shim** for `from_hex_le::<Bn254Fr>()`. Prefer `from_hex_le` for new generic code.

**Signature**:
```rust
pub fn hex_to_field(hex_str: &str) -> Result<Bn254Fr, String>
```

**Arguments**:
- `hex_str`: Hex string with optional `0x` prefix (little-endian, 32 bytes)

**Example**:
```rust
use groth16_proofs::hex_to_field;

// Little-endian hex representation of 1
let field_element = hex_to_field("0x0100000000000000000000000000000000000000000000000000000000000000")?;
assert_eq!(field_element, Bn254Fr::from(1u64));
```

### `from_decimal_str<F>()`

Generic decimal string parser for any `PrimeField` element. Underlying function used by `decimal_to_field`.

**Signature**:
```rust
pub fn from_decimal_str<F: PrimeField>(s: &str) -> Result<F, String>
```

**Example**:
```rust
use groth16_proofs::from_decimal_str;
use ark_bn254::{Fr as Bn254Fr, Fq};

let fr: Bn254Fr = from_decimal_str("12345").unwrap();
let fq: Fq      = from_decimal_str("12345").unwrap(); // same string, different field
```

### `from_hex_le<F>()`

Generic little-endian hex parser for any `PrimeField` element. Underlying function used by `hex_to_field`.

**Signature**:
```rust
pub fn from_hex_le<F: PrimeField>(hex: &str) -> Result<F, String>
```

**Example**:
```rust
use groth16_proofs::from_hex_le;
use ark_bn254::Fr as Bn254Fr;

let val: Bn254Fr = from_hex_le("0x0100000000000000000000000000000000000000000000000000000000000000").unwrap();
```

### `prove_from_witness()`

Core prover shared by the native and WASM paths. Use this when you have already loaded the proving key bytes and converted the witness to field elements.

**Signature**:
```rust
pub fn prove_from_witness(
    pk_bytes: &[u8],
    witness: Vec<Bn254Fr>,
    num_public_signals: usize,
) -> Result<Vec<u8>, ProofError>
```

**Example**:
```rust
use groth16_proofs::{prove_from_witness, from_hex_le};
use ark_bn254::Fr as Bn254Fr;

let pk_bytes = std::fs::read("circuit_pk.ark").unwrap();
let witness: Vec<Bn254Fr> = hex_strings.iter()
    .map(|h| from_hex_le(h).unwrap())
    .collect();
let proof_bytes = prove_from_witness(&pk_bytes, witness, 5).unwrap();
```

### `compress_snarkjs_proof()`

Native (non-WASM) version of the snarkjs compression function. Available in server-side Rust code.

**Signature**:
```rust
pub fn compress_snarkjs_proof(proof_json: &str) -> Result<Vec<u8>, ProofError>
```

**Example**:
```rust
use groth16_proofs::compress_snarkjs_proof;

let proof_bytes = compress_snarkjs_proof(&snarkjs_proof_json_string).unwrap();
// proof_bytes.len() == 128
```

### `ProofError`

Unified error type returned by all Rust proof functions.

| Variant | Description |
|---------|-------------|
| `WitnessEmpty` | The witness vector is empty |
| `WitnessConversion(String)` | Failed to convert a witness element |
| `ProvingKeyIo(String)` | Failed to read the `.ark` file |
| `ProvingKeyParse(String)` | Failed to deserialize the proving key |
| `ProveGeneration(String)` | arkworks proof generation failed |
| `ProofSerialization(String)` | Failed to serialize the proof |
| `NumPublicSignals(String)` | Invalid `num_public_signals` value |
| `WitnessJsonParse(String)` | Failed to parse witness JSON |
| `SnarkjsProofParse(String)` | Failed to parse snarkjs proof JSON |

## WASM JavaScript API

### Initialization

Before calling any WASM function, initialize the module. Load the `.wasm` binary from CDN to avoid bundling it:

```typescript
import init from '@orbinum/groth16-proofs';
import groth16pkg from '@orbinum/groth16-proofs/package.json';

const WASM_CDN = `https://unpkg.com/@orbinum/groth16-proofs@${groth16pkg.version}/groth16_proofs_bg.wasm`;
await init(WASM_CDN);
```

> Note: CJS interop — if `init` is not a function, look for `init.default`. See [loader.ts in proof-generator](../../proof-generator/src/wasm/loader.ts) for a production example.

---

### `compress_snarkjs_proof_wasm()` — Primary browser function ✅

Convert a snarkjs proof (`pi_a`, `pi_b`, `pi_c`) into the **128-byte arkworks compressed format** expected by the on-chain verifier. This is the main function used in the Orbinum TypeScript stack.

**Signature**:
```typescript
function compress_snarkjs_proof_wasm(
    proofJson: string             // snarkjs proof as JSON string
): string                        // 0x-prefixed compressed proof (128 bytes)
```

**Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `proofJson` | string | JSON with `pi_a`, `pi_b`, `pi_c` decimal coordinate arrays |

**Returns**: `"0x..."` — 128-byte arkworks canonical Groth16 proof

**Example**:
```typescript
import init, { compress_snarkjs_proof_wasm } from '@orbinum/groth16-proofs';
import * as snarkjs from 'snarkjs';

await init(WASM_CDN);

// Step 1: Generate proof with snarkjs (uses .wasm circuit + .zkey proving key)
const { proof: snarkjsProof, publicSignals } = await snarkjs.groth16.fullProve(
  circuitInputs,
  'circuit.wasm',        // circuit binary (from CDN or local)
  'circuit_pk.zkey'      // proving key (NOT .ark — that is Rust-only)
);

// Step 2: Compress to on-chain format
const compressedProof = compress_snarkjs_proof_wasm(JSON.stringify(snarkjsProof));
// compressedProof => "0x..." (128 bytes, arkworks canonical)
```

> Implementation: `src/wasm/snarkjs_proof.rs`, re-exported from `src/lib.rs`.

---

### `generate_proof_from_decimal_wasm()` — Witness-based alternative

Generate a proof directly from a raw decimal witness + `.ark` proving key bytes. Use this only when you have a pre-computed witness and the `.ark` key available in-browser.

**Signature**:
```typescript
function generate_proof_from_decimal_wasm(
    numPublicSignals: number,    // Number of public signals to extract
    witnessJson: string,         // JSON array of decimal strings
    provingKeyBytes: Uint8Array  // Binary proving key (.ark format)
): string                        // JSON output
```

**Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `numPublicSignals` | number | Number of public signals to extract from witness |
| `witnessJson` | string | JSON string: `'["1", "12345", ...]'` (decimal) |
| `provingKeyBytes` | Uint8Array | Binary proving key (`.ark` file bytes) |

**Returns**: JSON string
```json
{
  "proof": "0x...",
  "publicSignals": ["0x...", "0x...", ...]
}
```
```

### `initPanicHook()`

Initialize panic handling for better browser error messages. Usually called automatically.

**Signature**:
```typescript
function initPanicHook(): void
```

---

## CLI Binaries

### `convert-vk` — VK format conversion

Converts a snarkjs verification key JSON to the **arkworks compressed binary** (~424 bytes) required by the on-chain verifier. Run this once per circuit before registering keys on-chain.

**Usage**:
```bash
./target/release/convert-vk <input_vk.json> [output_vk.bin]
# If output is omitted, replaces .json with .bin
```

**Example**:
```bash
./target/release/convert-vk artifacts/verification_key_unshield.json verification_key_unshield.bin
# stderr: Converted ... → ... (3657 bytes JSON → 424 bytes binary)
```

**VK artifact sizes**:
| Format | Extension | Size | Used by |
|--------|-----------|------|---------|
| snarkjs JSON | `verification_key_*.json` | ~3.6 KB | input to `convert-vk` |
| arkworks binary | `*.bin` | ~424 bytes | on-chain registration |

> The `setup-dev.sh` and `rotate-dev.sh` scripts in the node repo auto-compile `convert-vk` and run it before VK registration. Do not register JSON bytes directly — the runtime deserializer expects arkworks compressed binary.

### `generate-proof-from-witness` — Rust-native CLI

```bash
./target/release/generate-proof-from-witness <witness.json> <proving_key.ark> [num_public_signals]
```

- `witness.json`: JSON array of hex LE strings (`0x...`, 32 bytes each), or a JSON object `{"witness": [...], "num_public_signals": 5}`
- `proving_key.ark`: arkworks compressed proving key (`.ark` format)
- `num_public_signals`: optional CLI override; defaults to the value in JSON or `5`

Outputs proof and public signals as JSON to stdout (see [witness-formats.md](./witness-formats.md)).

## Complete Examples

### Rust Example

```rust
use groth16_proofs::{generate_proof_from_witness, ProofError};

fn main() -> Result<(), ProofError> {
    // Prepare witness (hex-encoded field elements)
    let witness = vec![
        "0x0100000000000000000000000000000000000000000000000000000000000000".to_string(),
        "0x0200000000000000000000000000000000000000000000000000000000000000".to_string(),
        // ... more elements (typically ~11,808 total for unshield/transfer)
    ];
    
    // Generate proof — 5 public signals for this circuit
    let proof_bytes = generate_proof_from_witness(&witness, "circuits/my_circuit_pk.ark", 5)?;
    
    println!("Proof (128 bytes): 0x{}", hex::encode(&proof_bytes));
    Ok(())
}
```

### Browser Example (snarkjs + compress — Recommended ✅)

```typescript
import init, { compress_snarkjs_proof_wasm } from '@orbinum/groth16-proofs';
import groth16pkg from '@orbinum/groth16-proofs/package.json';
import * as snarkjs from 'snarkjs';

async function generateUnshieldProof(inputs: Record<string, unknown>) {
  // 1. Initialize WASM from CDN
  const WASM_CDN = `https://unpkg.com/@orbinum/groth16-proofs@${groth16pkg.version}/groth16_proofs_bg.wasm`;
  await init(WASM_CDN);

  // 2. Generate proof with snarkjs (.zkey from CDN)
  const { proof: snarkjsProof } = await snarkjs.groth16.fullProve(
    inputs,
    'https://cdn.example.com/circuits/unshield.wasm',
    'https://cdn.example.com/circuits/unshield_pk.zkey'
  );

  // 3. Compress to 128-byte on-chain format
  const compressedProof = compress_snarkjs_proof_wasm(JSON.stringify(snarkjsProof));
  console.log('✓ Proof:', compressedProof); // "0x..." 128 bytes
  return compressedProof;
}
```

### Node.js Example

```typescript
import init, { compress_snarkjs_proof_wasm } from '@orbinum/groth16-proofs';
import groth16pkg from '@orbinum/groth16-proofs/package.json';
import { readFileSync } from 'fs';
import * as snarkjs from 'snarkjs';

async function generateProofNode(circuitName: string, inputs: unknown) {
  // Initialize WASM
  const wasmBytes = readFileSync(`./circuits/${circuitName}_bg.wasm`);
  await init(wasmBytes);

  // Generate with snarkjs
  const { proof: snarkjsProof } = await snarkjs.groth16.fullProve(
    inputs,
    `./circuits/${circuitName}.wasm`,
    `./circuits/${circuitName}_pk.zkey`
  );

  return compress_snarkjs_proof_wasm(JSON.stringify(snarkjsProof));
}
```

## Data Format

### Witness Format

Decimal field elements (snarkjs native output):

```json
[
  "1",
  "2",
  "67890123456789012345678901234567890"
]
```

**Important**: 
- Each element is a decimal string representing a BN254 field element
- Total ~11,808 elements per proof

### Output Format

```json
{
  "proof": "0xabcdef1234567890...",
  "publicSignals": [
    "0x...",
    "0x...",
    "0x...",
    "0x..."
  ]
}
```

## Error Handling

### Rust Errors

```rust
use groth16_proofs::{generate_proof_from_witness, ProofError};

match generate_proof_from_witness(&witness, "key.ark", 5) {
    Ok(proof)                        => println!("0x{}", hex::encode(&proof)),
    Err(ProofError::ProvingKeyIo(e))  => eprintln!("Key file not found: {e}"),
    Err(ProofError::ProvingKeyParse(e))=> eprintln!("Invalid key format: {e}"),
    Err(ProofError::NumPublicSignals(e))=> eprintln!("Bad num_public_signals: {e}"),
    Err(e)                           => eprintln!("Proof failed: {e}"),
}
```

**Error variants**:

| Variant | When it occurs |
|---------|----------------|
| `WitnessEmpty` | Witness vector is empty |
| `WitnessConversion` | Hex LE string cannot be parsed |
| `ProvingKeyIo` | `.ark` file cannot be read |
| `ProvingKeyParse` | `.ark` bytes are not a valid proving key |
| `ProveGeneration` | arkworks constraint violation |
| `NumPublicSignals` | `0` or `>= witness.len()` |

### JavaScript Errors

```typescript
try {
  const numPublicSignals = 5; // Adjust for your circuit
  const result = generate_proof_from_decimal_wasm(numPublicSignals, witnessJson, keyBytes);
  const { proof, publicSignals } = JSON.parse(result);
} catch (error) {
  console.error('Error:', error.message);
  // Handle error...
}
```

**Common Errors**:
- `"Failed to parse witness JSON: ..."`
- `"Failed to deserialize proving key: ..."`
- `"num_public_signals must be greater than 0"`
- `"num_public_signals exceeds witness length"`

## Proving Key Management

### Location

Store proving keys in a secure location:

```
project/
├── circuits/
│   ├── my_circuit_v1_pk.ark
│   ├── my_circuit_v2_pk.ark
│   └── another_circuit_pk.ark
└── src/
```

### Caching

In browser environments, cache proving keys to avoid re-downloading:

```typescript
let cachedProofingKey: Uint8Array | null = null;

async function loadProvingKey(circuitName: string) {
  if (!cachedProofingKey) {
    const response = await fetch(`/proving_keys/${circuitName}.ark`);
    cachedProofingKey = new Uint8Array(await response.arrayBuffer());
  }
  return cachedProofingKey;
}

// Configuration for your circuits
const CIRCUIT_CONFIG = {
  'my_circuit_v1': { publicSignals: 5 },
  'my_circuit_v2': { publicSignals: 7 },
  'simple_circuit': { publicSignals: 3 },
};

async function generateProofCached(circuitName: string, witness: string[]) {
  const provingKey = await loadProvingKey(circuitName);
  const { publicSignals } = CIRCUIT_CONFIG[circuitName];
  return generate_proof_from_decimal_wasm(publicSignals, JSON.stringify(witness), provingKey);
}
```

### Size

Each proving key is approximately:
- **Compressed (.ark format)**: 100-300 KB depending on circuit
- **In memory**: ~1-2 MB after deserialization

## Performance Tips

### 1. Parallel Generation

Generate multiple proofs in parallel (browser workers or server threads):

```typescript
// Browser with Web Workers
const worker = new Worker('proof-worker.js');
worker.postMessage({ witness, circuitType });
worker.onmessage = (e) => { /* handle result */ };
```

### 2. Pre-compute

For known witness values, generate and cache proofs:

```rust
// Server-side pre-computation
let proofs_cache = HashMap::new();
for witness in known_witnesses {
    let proof = generate_proof_from_witness(&witness, "key.ark")?;
    proofs_cache.insert(hash(&witness), proof);
}
```

### 3. Batch Operations

If processing multiple proofs, use a queue:

```typescript
class ProofQueue {
  private queue: ProofTask[] = [];
  
  async addTask(witness: string[]) {
    this.queue.push({ witness });
    await this.process();
  }
  
  async process() {
    while (this.queue.length > 0) {
      const task = this.queue.shift();
      const result = generate_proof_from_decimal_wasm(numPublicSignals, witnessJson, provingKeyBytes);
      // ...
    }
  }
}
```

## Testing

Run tests to verify functionality:

```bash
# All tests
make test

# Specific test
cargo test test_witness_array_conversion

# With output
cargo test -- --nocapture
```

## Debugging

Enable debug output:

```rust
// In Rust code
println!("Witness: {:?}", witness);
println!("Proof bytes: {}", hex::encode(&proof_bytes));
```

```typescript
// In TypeScript
console.log('Witness JSON:', witnessJson);
const result = generate_proof_from_decimal_wasm(numPublicSignals, witnessJson, provingKeyBytes);
console.log('Result:', result);
```

## Next Steps

- [Installation Guide](./installation.md)
- [Witness Formats](./witness-formats.md)
- [Release Process](./release.md)
