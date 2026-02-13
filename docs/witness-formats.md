# Witness Formats Guide

This document explains the different witness formats supported by groth16-proofs and when to use each one.

## Overview

**groth16-proofs** supports two witness formats:

1. **Decimal Format** (Recommended) - Native snarkjs output
2. **Hex Little-Endian Format** (Legacy) - Custom format

## Format Comparison

| Aspect | Decimal Format | Hex LE Format |
|--------|----------------|---------------|
| **Source** | snarkjs native | Custom conversion |
| **Example** | `"12345"` | `"0x3930000000...00"` |
| **Conversion needed** | ❌ No | ✅ Yes |
| **Function (Rust)** | `decimal_to_field()` | `hex_to_field()` |
| **Function (WASM)** | `generate_proof_from_decimal_wasm()` | `generate_proof_wasm()` |
| **Use case** | Modern integrations | Legacy code |

## 1. Decimal Format (Recommended ✅)

### What is it?

The **native format** used by snarkjs when exporting witness. Each field element is represented as a decimal string.

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

- ✅ **No conversion overhead**: Direct from snarkjs → groth16-proofs
- ✅ **Simpler code**: Less data transformation
- ✅ **Human-readable**: Easy to debug
- ✅ **Standard**: Works with any ZK toolkit

### How to use

**WASM (JavaScript/TypeScript)**:
```typescript
import { generate_proof_from_decimal_wasm } from './wasm/groth16_proofs.js';
import * as snarkjs from 'snarkjs';

// Step 1: Calculate witness
await snarkjs.wtns.calculate(inputs, 'circuit.wasm', 'witness.wtns');

// Step 2: Export as JSON (decimal format - native!)
const witnessArray = await snarkjs.wtns.exportJson('witness.wtns');

// Step 3: Generate proof (no conversion!)
const resultJson = generate_proof_from_decimal_wasm(
  5,  // number of public signals
  JSON.stringify(witnessArray),  // Pass directly
  provingKeyBytes
);
```

**Rust**:
```rust
use groth16_proofs::decimal_to_field;

// Convert individual decimal string to field element
let field = decimal_to_field("12345")?;

// Or convert entire witness array
let witness: Vec<Bn254Fr> = decimal_strings
    .iter()
    .map(|s| decimal_to_field(s))
    .collect::<Result<Vec<_>, _>>()?;
```

## 2. Hex Little-Endian Format (Legacy)

### What is it?

A **custom format** where each field element is a 32-byte hex string in little-endian byte order.

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

**WASM (JavaScript/TypeScript)**:
```typescript
import { generate_proof_wasm } from './wasm/groth16_proofs.js';

// If you already have hex LE witness
const witnessHexLE = [
  "0x0100000000000000000000000000000000000000000000000000000000000000",
  "0x3930000000000000000000000000000000000000000000000000000000000000",
  // ...
];

const resultJson = generate_proof_wasm(
  5,
  JSON.stringify(witnessHexLE),
  provingKeyBytes
);
```

**Rust**:
```rust
use groth16_proofs::hex_to_field;

let field = hex_to_field("0x0100...00")?;
```

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

## Which Format Should I Use?

### Use Decimal Format ✅ if:

- ✅ You're using snarkjs for witness calculation
- ✅ Starting a new integration
- ✅ Want simplest possible code
- ✅ Need human-readable values for debugging

### Use Hex LE Format if:

- Working with existing code that uses it
- Interfacing with systems that expect hex
- Need to maintain compatibility with older versions

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

### Legacy Hex LE Integration

```typescript
import { generate_proof_wasm } from './groth16_proofs.js';

// If you have legacy code that produces hex LE
const witnessHexLE = loadLegacyWitness(); // ["0x...", "0x...", ...]

const resultJson = generate_proof_wasm(
  5,
  JSON.stringify(witnessHexLE),
  provingKeyBytes
);
```

## Summary

**Recommendation**: Use **decimal format** for all new integrations. It's simpler, more efficient, and matches the native snarkjs output format. The hex LE format is supported for backward compatibility but requires unnecessary conversion overhead.
