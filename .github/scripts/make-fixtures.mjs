/**
 * Rebuild the two witness fixtures the Rust suite needs, from the published wasm.
 *
 * `@orbinum/circuits` ships proving keys, verifying keys and compiled wasm, but
 * not fixtures: those are derived from an input and a wasm, and shipping a
 * derivation is shipping a cache. The Rust tests need two of them —
 * `value_proof` and `unshield` — and `tests/common/mod.rs` refuses to let a
 * missing artifact turn into a silent skip, so CI has to produce them.
 *
 * Deriving them here rather than cloning the circuits repository keeps CI to one
 * npm package instead of a second checkout and its whole toolchain.
 *
 * This deliberately does *not* reimplement `circuits`' own signal-layout
 * assertion. That check belongs to the repository that owns the layout; a second
 * copy here would be a second thing to keep in step. What this produces is
 * byte-comparable to that script's output — same snarkjs, same wasm, same input.
 *
 * Usage: node .github/scripts/make-fixtures.mjs <circuits-dir>
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';

const root = resolve(process.argv[2] ?? '../circuits');

// snarkjs is installed into the circuits checkout, not this one, so resolve it
// from there rather than from this script's own module graph.
const require = createRequire(join(root, 'package.json'));
const snarkjs = require('snarkjs');

/** Public-signal counts, which the fixture format carries alongside the witness. */
const NEEDED = [
  { name: 'value_proof', publicSignals: 4 },
  { name: 'unshield', publicSignals: 7 },
];

const fixtures = join(root, 'fixtures');
mkdirSync(fixtures, { recursive: true });

for (const { name, publicSignals } of NEEDED) {
  const out = join(fixtures, `${name}.witness.json`);
  if (existsSync(out)) {
    console.log(`  ${name}: already present`);
    continue;
  }

  const input = join(fixtures, `${name}.input.json`);
  const wasm = join(root, 'build', `${name}.wasm`);
  for (const p of [input, wasm]) {
    if (!existsSync(p)) throw new Error(`cannot build the ${name} fixture: ${p} is missing`);
  }

  const witness = { type: 'mem' };
  await snarkjs.wtns.calculate(JSON.parse(readFileSync(input, 'utf8')), readFileSync(wasm), witness);
  const elements = await snarkjs.wtns.exportJson(witness);

  writeFileSync(
    out,
    `${JSON.stringify({ num_public_signals: publicSignals, witness: elements.map(String) })}\n`,
  );
  console.log(`  ${name}: ${elements.length} elements`);
}

// snarkjs leaves worker handles open, so the process does not exit on its own.
process.exit(0);
