# Usage Guide

Complete API reference and usage examples for `groth16-proofs`.

## Overview

This library generates **Groth16 zero-knowledge proofs** from pre-calculated witness values. It processes:

1. **Input**: Witness (array of field elements) + Proving Key (binary file)
2. **Processing**: Converts to BN254 field elements, generates Groth16 proof
3. **Output**: 128-byte compressed proof + public signals

## Proof Generation Flow

```
Witness (hex strings)
    ↓ [parse and convert]
    ↓
Field Elements (BN254)
    + Proving Key (loaded from file/bytes)
    ↓ [arkworks]
    ↓
Groth16 Proof (128 bytes)
    ↓ [extract]
    ↓
Proof (hex) + Public Signals (hex array)
```

## Native Rust API

### `generate_proof_from_witness()`

Generate a Groth16 proof from witness data.

**Signature**:
```rust
pub fn generate_proof_from_witness(
    witness_hex: &[String],
    proving_key_path: &str,
) -> Result<Vec<u8>, String>
```

**Arguments**:
- `witness_hex`: Array of hex-encoded field elements (little-endian), typically 11,808 elements
- `proving_key_path`: Path to the `.ark` proving key file

**Returns**:
- `Ok(Vec<u8>)`: 128-byte compressed Groth16 proof
- `Err(String)`: Error message

**Example**:
```rust
use orbinum_groth16_proofs::generate_proof_from_witness;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let witness = vec![
        "0x0100000000000000000000000000000000000000000000000000000000000000".to_string(),
        "0x0200000000000000000000000000000000000000000000000000000000000000".to_string(),
        // ... 11,806 more elements
    ];
    
    let proof = generate_proof_from_witness(&witness, "circuits/my_circuit_pk.ark")?;
    println!("Proof: 0x{}", hex::encode(&proof));
    
    Ok(())
}
```

### `hex_to_field()`

Convert a hex string to a BN254 field element (mainly for testing/debugging).

**Signature**:
```rust
pub fn hex_to_field(hex_str: &str) -> Result<Bn254Fr, String>
```

**Example**:
```rust
use orbinum_groth16_proofs::hex_to_field;

let field_element = hex_to_field("0x0123456789abcdef")?;
```

## WASM JavaScript API

### `generate_proof_wasm()`

Browser-compatible proof generation.

**Signature**:
```typescript
function generate_proof_wasm(
    numPublicSignals: number,    // Number of public signals to extract (e.g., 5, 4, etc.)
    witnessJson: string,         // JSON array as string
    provingKeyBytes: Uint8Array  // Binary proving key
): string                        // JSON output
```

**Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `numPublicSignals` | number | Number of public signals to extract from witness |
| `witnessJson` | string | JSON string: `'["0x...", "0x...", ...]'` |
| `provingKeyBytes` | Uint8Array | Binary proving key (from `.ark` file) |

**Returns**: JSON string
```json
{
  "proof": "0x...",                         // 128-byte compressed Groth16 proof
  "publicSignals": ["0x...", "0x...", ...]  // Public signals from witness
}
```

**How to determine `numPublicSignals`**:

The number of public signals depends on your specific circuit implementation. Check your circuit definition to know how many signals are public. Common examples:
- Simple circuits: 1-5 signals
- Privacy protocols: 4-8 signals
- Complex applications: 10+ signals

**Example (Browser)**:
```typescript
// Import from downloaded WASM module
import { generate_proof_wasm } from './wasm/groth16_proofs.js';

async function generateProof() {
  // Prepare witness
  const witness = [
    "0x0100000000000000000000000000000000000000000000000000000000000000",
    // ... ~11,808 elements
  ];
  
  // Load proving key
  const response = await fetch('proving_keys/my_circuit.ark');
  const provingKeyBytes = new Uint8Array(await response.arrayBuffer());
  
  // Specify number of public signals for your circuit
  const numPublicSignals = 5; // Adjust based on your circuit
  
  try {
    const resultJson = generate_proof_wasm(
      numPublicSignals,
      JSON.stringify(witness),
      provingKeyBytes
    );
    
    const { proof, publicSignals } = JSON.parse(resultJson);
    
    console.log('Proof:', proof);
    console.log('Signals:', publicSignals);
    
    // Use proof...
    return { proof, publicSignals };
  } catch (error) {
    console.error('Generation failed:', error);
  }
}
```

**Example (Node.js)**:
```typescript
// Import from downloaded WASM module
import { generate_proof_wasm } from './wasm/groth16_proofs.js';
import fs from 'fs';
import path from 'path';

function generateProofFromFile() {
  const witness = JSON.parse(fs.readFileSync('witness.json', 'utf-8'));
  const provingKey = fs.readFileSync('circuits/my_circuit_pk.ark');
  
  // Adjust based on your circuit's public signals
  const numPublicSignals = 5;
  
  const result = generate_proof_wasm(
    numPublicSignals,
    JSON.stringify(witness),
    new Uint8Array(provingKey)
  );
  
  const parsed = JSON.parse(result);
  console.log('Generated proof:', parsed.proof);
  
  return parsed;
}
```

### `initPanicHook()`

Initialize panic handling for better browser error messages. Usually called automatically.

**Signature**:
```typescript
function initPanicHook(): void
```

## Complete Examples

### Rust Example

```rust
use orbinum_groth16_proofs::generate_proof_from_witness;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Prepare witness (hex-encoded field elements)
    let witness = vec![
        "0x0100000000000000000000000000000000000000000000000000000000000000".to_string(),
        "0x0200000000000000000000000000000000000000000000000000000000000000".to_string(),
        // ... more elements (typically ~11,808 total)
    ];
    
    // Generate proof
    let proof_bytes = generate_proof_from_witness(&witness, "circuits/my_circuit_pk.ark")?;
    
    println!("Proof (128 bytes): 0x{}", hex::encode(&proof_bytes));
    Ok(())
}
```

### Browser Example

```typescript
import { generate_proof_wasm } from './wasm/groth16_proofs.js';

async function generateProof() {
  // Load witness data
  const witness = [
    "0x0100000000000000000000000000000000000000000000000000000000000000",
    "0x0200000000000000000000000000000000000000000000000000000000000000",
    // ... more elements
  ];
  
  // Load proving key
  const response = await fetch('proving_keys/my_circuit.ark');
  const provingKeyBytes = new Uint8Array(await response.arrayBuffer());
  
  // Specify number of public signals for your circuit
  const numPublicSignals = 5; // Depends on your circuit definition
  
  try {
    const resultJson = generate_proof_wasm(
      numPublicSignals,
      JSON.stringify(witness),
      provingKeyBytes
    );
    
    const { proof, publicSignals } = JSON.parse(resultJson);
    console.log('✓ Proof:', proof);
    console.log('✓ Public signals:', publicSignals);
    
    return { proof, publicSignals };
  } catch (error) {
    console.error('✗ Generation failed:', error);
    throw error;
  }
}
```

### Node.js Example

```typescript
import { generate_proof_wasm } from './wasm/groth16_proofs.js';
import fs from 'fs';

function generateProofFromFile(circuitName: string, witnessPath: string) {
  // Load witness and proving key
  const witness = JSON.parse(fs.readFileSync(witnessPath, 'utf-8'));
  const provingKey = fs.readFileSync(`circuits/${circuitName}_pk.ark`);
  
  // Configure based on your circuit
  // You need to know how many public signals your circuit has
  const numPublicSignals = 5;
  
  const result = generate_proof_wasm(
    numPublicSignals,
    JSON.stringify(witness),
    new Uint8Array(provingKey)
  );
  
  const { proof, publicSignals } = JSON.parse(result);
  return { proof, publicSignals };
}
```

## Data Format

### Witness Format

Hex-encoded field elements (little-endian, each 256 bits):

```json
[
  "0x0100000000000000000000000000000000000000000000000000000000000000",
  "0x0200000000000000000000000000000000000000000000000000000000000000",
  "0x..."
]
```

**Important**: 
- Each element must be 66 characters (0x + 64 hex digits)
- Little-endian format
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
match generate_proof_from_witness(&witness, "key.ark") {
    Ok(proof) => println!("Success: {}", hex::encode(&proof)),
    Err(e) => eprintln!("Error: {}", e),
}
```

**Common Errors**:
- `"Failed to read proving key: No such file or directory"`
- `"Failed to deserialize proving key: ..."`
- `"Failed to generate proof: Circuit constraint violation"`

### JavaScript Errors

```typescript
try {
  const numPublicSignals = 5; // Adjust for your circuit
  const result = generate_proof_wasm(numPublicSignals, witnessJson, keyBytes);
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
  return generate_proof_wasm(publicSignals, JSON.stringify(witness), provingKey);
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
      const result = generate_proof_wasm(numPublicSignals, witnessJson, provingKeyBytes);
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
const result = generate_proof_wasm(numPublicSignals, witnessJson, provingKeyBytes);
console.log('Result:', result);
console.log('Result:', result);
```

## Next Steps

- [Installation Guide](./installation.md)
- [Development](../DEVELOPMENT.md)
- [Contributing](../CONTRIBUTING.md)
