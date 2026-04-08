# Input Formats Guide

This document explains the different input formats accepted by groth16-proofs functions and when to use each one.

## Overview

The library exposes two conceptually different entry points:

| Entry point | Input | Output | Use case |
|-------------|-------|--------|----------|
| `compress_snarkjs_proof_wasm` | snarkjs proof JSON `{pi_a, pi_b, pi_c}` | 128-byte compressed proof | Browser / TS stack ✅ |
| `generate_proof_from_decimal_wasm` | Decimal witness array + `.ark` key | 128-byte compressed proof | WASM with server-side `.ark` |
| `generate_proof_from_witness` (Rust/CLI) | Hex LE witness array + `.ark` path | 128-byte compressed proof | Rust-native / CLI |

> **Important**: `compress_snarkjs_proof_wasm` does **not** receive a witness — it receives a proof that snarkjs already generated. The witness is consumed internally by `snarkjs.groth16.fullProve()`.

---

## Format Comparison

### Witness formats (for `generate_proof_from_decimal_wasm` and `generate_proof_from_witness` CLI)

| Aspect | Decimal Format | Hex LE Format |
|--------|----------------|---------------|
| **Source** | snarkjs witness export | Custom / Rust internal |
| **Example** | `"12345"` | `"0x3930000000...00"` |
| **Conversion needed** | ❌ No | ✅ Yes |
| **Function (Rust)** | `decimal_to_field()` | `hex_to_field()` |
| **Function (WASM)** | `generate_proof_from_decimal_wasm()` | N/A |
| **Use case** | WASM witness-based flow | Rust CLI (`generate-proof-from-witness`) |

## 1. snarkjs Proof Format (for `compress_snarkjs_proof_wasm` — Primary ✅)

### What is it?

The JSON output of `snarkjs.groth16.fullProve()` containing elliptic curve points `pi_a`, `pi_b`, `pi_c`. This is what the primary Orbinum TypeScript flow sends to `compress_snarkjs_proof_wasm`.

### Example

```json
{
  "pi_a": ["123456...789", "987654...321", "1"],
  "pi_b": [
    ["111...", "222..."],
    ["333...", "444..."]
    ["1", "0"]
  ],
  "pi_c": ["555...", "666...", "1"]
}
```

### How to use

```typescript
import init, { compress_snarkjs_proof_wasm } from '@orbinum/groth16-proofs';
import * as snarkjs from 'snarkjs';

await init(WASM_CDN);

const { proof: snarkjsProof } = await snarkjs.groth16.fullProve(
  inputs,
  circuitWasmUrl,
  circuitZkeyUrl
);

// snarkjsProof already has the right format — pass directly
const compressedProof = compress_snarkjs_proof_wasm(JSON.stringify(snarkjsProof));
// => "0x..." (128 bytes on-chain format)
```

---

## 2. Decimal Witness Format (for `generate_proof_from_decimal_wasm`)

### Example

```json
[
  "1",
  "12345",
  "67890123456789012345678901234567890",
  "100"
]
```

### Why use it?

- ✅ **No conversion overhead**: Direct from snarkjs witness export
- ✅ **Simpler code**: Less data transformation
- ✅ **Human-readable**: Easy to debug

### How to use

**WASM (JavaScript/TypeScript)**:
```typescript
import { generate_proof_from_decimal_wasm } from '@orbinum/groth16-proofs';
import * as snarkjs from 'snarkjs';

// Export witness as decimal array
await snarkjs.wtns.calculate(inputs, 'circuit.wasm', 'witness.wtns');
const witnessArray = await snarkjs.wtns.exportJson('witness.wtns');

// Load .ark proving key (Rust format — NOT .zkey)
const provingKey = new Uint8Array(await fetch('circuit_pk.ark').then(r => r.arrayBuffer()));

const resultJson = generate_proof_from_decimal_wasm(
  5,  // number of public signals
  JSON.stringify(witnessArray),
  provingKey
);
const { proof, publicSignals } = JSON.parse(resultJson);
```

**Rust**:
```rust
use groth16_proofs::decimal_to_field;

let field = decimal_to_field("12345")?;
```

---

## 3. Hex Little-Endian Format (for `generate_proof_from_witness` CLI)

### What is it?

A **32-byte hex string in little-endian order** used by the `generate-proof-from-witness` CLI and the Rust `generate_proof_from_witness()` function. The binary format matches arkworks' internal BN254 field element representation.

### Example

```json
[
  "0x0100000000000000000000000000000000000000000000000000000000000000",
  "0x3930000000000000000000000000000000000000000000000000000000000000",
  "0x6400000000000000000000000000000000000000000000000000000000000000"
]
```

### Structure

- **Prefix**: `0x`
- **Length**: 64 hex characters (32 bytes)
- **Byte order**: Little-endian
- **Padding**: Leading zeros when needed

### Why it exists?

This format exists because:

1. **Arkworks requirement**: The underlying `ark-ff` library uses little-endian byte representation
2. **Historical reasons**: Early versions required this format
3. **Direct field mapping**: Matches internal representation

### Conversion Example

Converting decimal `12345` to hex LE:

```
Decimal: 12345
   ↓
Hex BE: 0x3039 (big-endian)
   ↓
Pad to 32 bytes: 0x0000...00003039
   ↓
Reverse bytes (LE): 0x3930000000...0000
```

### How to use

**CLI**:
```bash
# witness.json is an array of hex LE strings
./target/release/generate-proof-from-witness witness.json proving_key.ark
```

**WASM (JavaScript/TypeScript)**:

Hex LE is not accepted by the WASM proof-generation API. Use decimal witness with `generate_proof_from_decimal_wasm`, or snarkjs proof JSON with `compress_snarkjs_proof_wasm`.

**Rust**:
```rust
use groth16_proofs::hex_to_field;

let field = hex_to_field("0x0100...00")?;
```

---

## Converting Between Formats

### Decimal → Hex LE (if needed)

```typescript
function bigIntToHexLE(value: bigint): string {
  // Convert to hex (big-endian)
  let hex = value.toString(16).padStart(64, '0');

  // Reverse byte order to little-endian
  const bytes: string[] = [];
  for (let i = hex.length - 2; i >= 0; i -= 2) {
    bytes.push(hex.substr(i, 2));
  }

  return '0x' + bytes.join('');
}

// Convert decimal string witness to hex LE
const witnessDecimal = ["1", "12345", "100"];
const witnessHexLE = witnessDecimal.map(d => bigIntToHexLE(BigInt(d)));
```

### Hex LE → Decimal (uncommon)

```typescript
function hexLEToDecimal(hexLE: string): string {
  // Remove 0x prefix
  const hex = hexLE.slice(2);
  
  // Reverse bytes to big-endian
  const bytes: string[] = [];
  for (let i = hex.length - 2; i >= 0; i -= 2) {
    bytes.push(hex.substr(i, 2));
  }
  
  // Convert to BigInt and then to string
  return BigInt('0x' + bytes.join('')).toString();
}
```

## Which Input Should I Use?

### Use `compress_snarkjs_proof_wasm` ✅ if:

- You're in a browser / TypeScript app
- You use `snarkjs.groth16.fullProve()` (standard Orbinum flow)
- You have `pi_a`, `pi_b`, `pi_c` from snarkjs
- You want the 128-byte on-chain format

### Use `generate_proof_from_decimal_wasm` if:

- You have a pre-computed decimal witness array
- You have the `.ark` proving key available (server-hosted)
- You want to generate the proof directly (no snarkjs step)

### Use `generate_proof_from_witness` CLI if:

- You are on a Rust/server environment
- You have hex LE witness + `.ark` proving key file
- You want the fastest native proof generation

## Technical Details

### Why Little-Endian?

Arkworks uses little-endian because:

1. **CPU architecture**: Modern CPUs (x86/x64/ARM) are little-endian
2. **Performance**: No byte swapping needed on modern hardware
3. **Standard**: Many cryptographic libraries use LE
4. **BN254 curve**: Internal representation uses LE

### Field Element Representation

Both formats represent the same BN254 field element:

```
Value: 12345
  ↓
Decimal: "12345"
  ↓
Hex BE: 0x0000...00003039
  ↓
Hex LE: 0x3930000000...0000
  ↓
Field Element: Bn254Fr::from(12345)
```

All three representations are mathematically equivalent.

## Examples

### Complete snarkjs Integration (Decimal)

```typescript
import * as snarkjs from 'snarkjs';
import { generate_proof_from_decimal_wasm } from './groth16_proofs.js';
import fs from 'fs';

async function generateProofForCircuit(inputs: any) {
  // 1. Calculate witness (snarkjs)
  const wtnsPath = 'witness.wtns';
  await snarkjs.wtns.calculate(inputs, 'circuit.wasm', wtnsPath);
  
  // 2. Export witness (already in decimal format!)
  const witnessArray = await snarkjs.wtns.exportJson(wtnsPath);
  
  // 3. Load proving key
  const provingKey = fs.readFileSync('circuit_pk.ark');
  
  // 4. Generate proof (no conversion needed!)
  const resultJson = generate_proof_from_decimal_wasm(
    5,  // adjust based on your circuit
    JSON.stringify(witnessArray),
    new Uint8Array(provingKey)
  );
  
  const { proof, publicSignals } = JSON.parse(resultJson);
  
  return { proof, publicSignals };
}
```

### snarkjs Proof Interoperability

```typescript
import { compress_snarkjs_proof_wasm } from './groth16_proofs.js';

const compressedProof = compress_snarkjs_proof_wasm(JSON.stringify(snarkjsProof));
// "0x..." (128-byte arkworks canonical compressed proof)
```

## Summary

**Recommendation**: Use **decimal format** for all new integrations. It's simpler, more efficient, and matches the native snarkjs output format. The hex LE format remains useful for low-level Rust utilities, but not for WASM proof generation.
