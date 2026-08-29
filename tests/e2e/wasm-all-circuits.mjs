/**
 * The shipped wasm package proves every published circuit.
 *
 * `cargo test` never loads `pkg/`. It is a separate build with its own bindgen
 * layer, and a wasm module that compiles is not a wasm module that works —
 * nothing in the Rust suite would notice a byte array mangled crossing the ABI.
 *
 * Covering all three circuits rather than one matters because they differ in
 * ways a single-circuit test cannot see: `value_proof` has four public signals
 * where the others have seven, and its first signal is a circuit *output*
 * rather than an input.
 *
 * Usage (after `make build-wasm`):
 *   node tests/e2e/wasm-all-circuits.mjs
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  ROOT, CIRCUITS_UNDER_TEST, artifacts, requireAll, witnessBytes,
  leHexToDecimal, readJson, check, equal, info, section, done, fail,
} from './lib.mjs';

const wasmJs = join(ROOT, 'pkg', 'groth16_proofs.js');
const wasmBin = join(ROOT, 'pkg', 'groth16_proofs_bg.wasm');
requireAll([wasmJs, wasmBin], 'pkg/ not built — run `make build-wasm`');

const { default: init, generate_proof_wasm } = await import(wasmJs);
await init({ module_or_path: readFileSync(wasmBin) });

/**
 * The value a public signal should hold, given the circuit's input JSON.
 *
 * Handles the three shapes: a plain input name, one element of an array input
 * (`nullifiers[0]`), and a circuit output that has no input at all
 * (`owner_hash`), which can only be checked against the witness.
 */
function expectedSignal(name, input, witnessDecimals, index) {
  const arrayMatch = name.match(/^([a-z_]+)\[(\d+)\]$/);
  if (arrayMatch) return input[arrayMatch[1]][Number(arrayMatch[2])];
  if (name in input) return input[name];
  // An output: the witness is the only source, so this checks self-consistency
  // between what the wasm reported and what the fixture recorded.
  return witnessDecimals[index + 1];
}

for (const { name, arity, signalNames } of CIRCUITS_UNDER_TEST) {
  const a = artifacts(name);
  requireAll([a.ark, a.wtns, a.input, a.witnessJson], `${name} artifacts`);

  section(`${name}`);

  const ark = new Uint8Array(readFileSync(a.ark));
  const witness = witnessBytes(new Uint8Array(readFileSync(a.wtns)));
  const input = readJson(a.input);
  const fixtureWitness = readJson(a.witnessJson).witness;

  const started = performance.now();
  let result;
  try {
    result = JSON.parse(generate_proof_wasm(ark, witness));
  } catch (err) {
    fail(`${name}: generate_proof_wasm threw — ${err}`);
    continue;
  }
  const elapsed = performance.now() - started;

  info(`${witness.length / 32} witness elements · proved in ${elapsed.toFixed(0)} ms`);

  const proofBytes = (result.proof.length - 2) / 2;
  equal(proofBytes, 128, `${name}: proof is 128 bytes`);
  equal(result.publicSignals.length, arity, `${name}: ${arity} public signals`);

  // Every signal is a full 32-byte word. A short encoding is a different claim
  // as far as the chain is concerned, not a cosmetic difference.
  const widths = new Set(result.publicSignals.map((s) => s.length));
  check(
    widths.size === 1 && widths.has(66),
    `${name}: every signal is 0x + 64 hex characters`
  );

  // The signals the wasm extracted must be the ones the circuit was given.
  // A mismatch means the witness crossed the bindgen boundary wrong, or the
  // public-signal order is not what we believe it is.
  const decimals = result.publicSignals.map(leHexToDecimal);
  let ordered = true;
  signalNames.forEach((sig, i) => {
    const want = String(expectedSignal(sig, input, fixtureWitness, i));
    if (decimals[i] !== want) {
      fail(`${name}: signal ${i} (${sig}) is ${decimals[i]}, expected ${want}`);
      ordered = false;
    }
  });
  if (ordered) pass(`${name}: signals match the circuit input, in order`);

  // And they must equal witness[1..=arity] — the same values by another route.
  const fromWitness = fixtureWitness.slice(1, arity + 1);
  check(
    decimals.every((d, i) => d === fromWitness[i]),
    `${name}: signals agree with witness[1..=${arity}]`
  );
}

function pass(msg) { check(true, msg); }

done('the shipped wasm proves every published circuit');
