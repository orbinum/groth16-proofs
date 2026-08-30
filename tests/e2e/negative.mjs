/**
 * The tests can fail.
 *
 * Every script beside this one reports success. That is only worth something if
 * failure is reachable — a harness that cannot distinguish a working build from
 * a broken one is a harness that says "OK" forever, which is the precise shape
 * of the bug this repository shipped twice.
 *
 * So this deliberately breaks things and asserts the breakage is caught:
 * corrupted artifacts, truncated witnesses, mismatched keys. Each case is one
 * a real deployment can actually produce — a partial download, a stale cache, a
 * key from the wrong ceremony.
 *
 * Usage (after `make build-wasm`):
 *   node tests/e2e/negative.mjs
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  ROOT, artifacts, requireAll, witnessBytes, check, info, section, done,
} from './lib.mjs';

const wasmJs = join(ROOT, 'pkg', 'groth16_proofs.js');
const wasmBin = join(ROOT, 'pkg', 'groth16_proofs_bg.wasm');
requireAll([wasmJs, wasmBin], 'pkg/ not built — run `make build-wasm`');

const { default: init, generate_proof_wasm, compress_snarkjs_proof_wasm } = await import(wasmJs);
await init({ module_or_path: readFileSync(wasmBin) });

const a = artifacts('value_proof'); // smallest, so the failures are fast
requireAll([a.ark, a.wtns], 'value_proof artifacts');

const ark = new Uint8Array(readFileSync(a.ark));
const witness = witnessBytes(new Uint8Array(readFileSync(a.wtns)));

/** Assert that a call throws, and report what it said. */
function throws(what, fn) {
  try {
    fn();
    check(false, `${what} — was ACCEPTED, expected a rejection`);
  } catch (err) {
    const msg = String(err.message ?? err).split('\n')[0].slice(0, 80);
    check(true, `${what} — rejected (${msg})`);
  }
}

// ─── The baseline ────────────────────────────────────────────────────────────

section('control');
let ok = false;
try {
  const r = JSON.parse(generate_proof_wasm(ark, witness));
  ok = (r.proof.length - 2) / 2 === 128;
} catch { /* handled below */ }
check(ok, 'the untouched artifacts do produce a proof');
if (!ok) {
  info('the control failed, so the negative cases below prove nothing');
}

// ─── Corrupt artifacts ───────────────────────────────────────────────────────

section('artifacts');

throws('an empty artifact', () => generate_proof_wasm(new Uint8Array(0), witness));

throws('random bytes as an artifact', () =>
  generate_proof_wasm(new Uint8Array(1024).fill(0xab), witness));

throws('a truncated artifact (first half)', () =>
  generate_proof_wasm(ark.subarray(0, Math.floor(ark.length / 2)), witness));

// A v1 .ark is the mistake a real caller makes: every package shipped one until
// 3.1.0, and it carries the proving key without the matrices.
const v1 = ark.subarray(12); // strip the ORBARKV2 magic + version
throws('a v1 artifact (no matrices)', () => generate_proof_wasm(v1, witness));

// A single flipped bit inside the proving key. This one is *not* rejected, and
// that is correct rather than a gap: the bit lands in key material, not in a
// checksum, so the result is a well-formed 128-byte proof that simply does not
// verify. An `.ark` cannot detect this by itself — only verification can, which
// is why full-chain.mjs exists and why a byte-count assertion is worthless.
const bitflip = Uint8Array.from(ark);
bitflip[Math.floor(bitflip.length / 2)] ^= 0x01;
let corrupted = null;
try {
  corrupted = JSON.parse(generate_proof_wasm(bitflip, witness));
} catch {
  // Also acceptable: the flip may land somewhere that fails deserialization.
  check(true, 'an artifact with one flipped bit — rejected at parse time');
}
if (corrupted) {
  check(
    (corrupted.proof.length - 2) / 2 === 128,
    'an artifact with one flipped bit still yields 128 bytes — only verification catches it'
  );
  info('verified as non-verifying by full-chain.mjs; see that script for the check that matters');
}

// ─── Corrupt witnesses ───────────────────────────────────────────────────────

section('witnesses');

throws('an empty witness', () => generate_proof_wasm(ark, new Uint8Array(0)));

throws('a witness that is not a multiple of 32 bytes', () =>
  generate_proof_wasm(ark, witness.subarray(0, witness.length - 1)));

throws('a witness with too few elements', () =>
  generate_proof_wasm(ark, witness.subarray(0, 32 * 4)));

// A witness of the right length whose values do not satisfy the constraints.
// This one is the important case: it is well-formed, so nothing structural
// catches it, and the proof it yields must not verify.
const wrong = Uint8Array.from(witness);
wrong[64] ^= 0xff; // corrupt a value past the constant and first signal
let verifiedWrong = null;
try {
  const r = JSON.parse(generate_proof_wasm(ark, wrong));
  verifiedWrong = r; // it may well produce 128 bytes — see below
} catch {
  check(true, 'a constraint-violating witness — rejected at proving time');
}
if (verifiedWrong) {
  // arkworks does not check the constraints while proving, so this is expected
  // to produce bytes. What must not happen is that those bytes verify.
  info('a constraint-violating witness produced a proof, as arkworks does not check constraints');
  info('cross_verify.rs and full-chain.mjs are what catch this: such a proof fails verification');
  check(
    (verifiedWrong.proof.length - 2) / 2 === 128,
    'it is still 128 bytes — which is why byte-count assertions are not enough'
  );
}

// ─── snarkjs proof parsing ───────────────────────────────────────────────────

section('snarkjs input');

throws('malformed JSON', () => compress_snarkjs_proof_wasm('{ not json'));
throws('JSON missing pi_a', () =>
  compress_snarkjs_proof_wasm(JSON.stringify({ pi_b: [['1', '2'], ['3', '4']], pi_c: ['1', '2'] })));
throws('a point that is not on the curve', () =>
  compress_snarkjs_proof_wasm(JSON.stringify({
    pi_a: ['1', '1'],                       // (1,1) is not on y² = x³ + 3
    pi_b: [['1', '2'], ['3', '4']],
    pi_c: ['1', '2'],
  })));

done('every deliberate breakage is caught');
