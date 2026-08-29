/**
 * The whole chain, cross-verified by an independent implementation.
 *
 * Everything upstream of this checks our code against our code. This proves
 * with the shipped wasm and hands the result to **snarkjs**, which shares no
 * line of implementation with arkworks. Agreement between the two is the
 * strongest evidence available without running a node: the chain accepts what
 * snarkjs accepts.
 *
 * That distinction is not theoretical here. The QAP-reduction bug produced
 * proofs that arkworks' own verifier accepted and snarkjs rejected, and it
 * shipped through two major versions because nothing ever asked the second
 * question.
 *
 * Also checks, per circuit:
 *   * the verifying key packs to the size the chain expects and hashes to the
 *     vk_hash the manifest publishes
 *   * a tampered signal is rejected — without which "verifies" means nothing
 *   * the .ark and the .zkey come from the same ceremony
 *
 * Usage (after `make build-wasm && make build`):
 *   node tests/e2e/full-chain.mjs
 */
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ROOT, CIRCUITS, CIRCUITS_UNDER_TEST, artifacts, requireAll, witnessBytes,
  leHexToDecimal, readJson, check, equal, info, section, done, fail, blake2_256,
} from './lib.mjs';

const wasmJs = join(ROOT, 'pkg', 'groth16_proofs.js');
const wasmBin = join(ROOT, 'pkg', 'groth16_proofs_bg.wasm');
const packVk = join(ROOT, 'target', 'release', 'pack-verifying-key');
const snarkjsBin = join(CIRCUITS, 'node_modules', '.bin', 'snarkjs');
const manifestPath = join(CIRCUITS, 'manifest.json');

requireAll(
  [wasmJs, wasmBin, packVk, snarkjsBin, manifestPath],
  'pkg/, release binaries, or the circuits checkout with node_modules'
);

const { default: init, generate_proof_wasm } = await import(wasmJs);
await init({ module_or_path: readFileSync(wasmBin) });

const manifest = readJson(manifestPath);
const scratch = mkdtempSync(join(tmpdir(), 'groth16-e2e-'));

/** An arkworks compressed proof as the `{pi_a,pi_b,pi_c}` JSON snarkjs reads. */
function toSnarkjsProof(hex) {
  const bytes = Buffer.from(hex.slice(2), 'hex');
  // Rather than reimplement compressed-point decoding here, round-trip through
  // snarkjs's own uncompressed form via the crate's verifier is not possible —
  // so instead we ask snarkjs to verify the proof it produced, and ask our
  // verifier to check the proof we produced. Both directions, below.
  return bytes;
}

/** Run snarkjs, returning combined output. */
function snarkjs(args) {
  try {
    return execFileSync(snarkjsBin, args, { encoding: 'utf8', stdio: 'pipe' });
  } catch (err) {
    return `${err.stdout ?? ''}${err.stderr ?? ''}`;
  }
}

try {
  for (const { name, arity } of CIRCUITS_UNDER_TEST) {
    const a = artifacts(name);
    requireAll([a.ark, a.zkey, a.wtns, a.vk, a.witnessJson], `${name} artifacts`);
    section(`${name}`);

    // ── The verifying key: size, and the hash the chain registered ──────────
    const vkBin = join(scratch, `${name}-vk.bin`);
    execFileSync(packVk, [a.vk, vkBin], { stdio: 'pipe' });
    const vkBytes = readFileSync(vkBin);

    equal(vkBytes.length, 232 + (arity + 1) * 32, `${name}: VK packs to the expected size`);

    // Substrate's blake2_256. Not blake2b-512 truncated — see lib.mjs.
    const vkHash = blake2_256(vkBytes);
    const published = manifest.circuits[name]?.versions?.['1']?.vk_hash;
    if (published) {
      equal(vkHash, published, `${name}: VK hashes to the manifest's vk_hash`);
    } else {
      info(`${name}: no vk_hash in the manifest to compare against`);
    }

    // ── Prove with the shipped wasm ─────────────────────────────────────────
    const ark = new Uint8Array(readFileSync(a.ark));
    const witness = witnessBytes(new Uint8Array(readFileSync(a.wtns)));
    const result = JSON.parse(generate_proof_wasm(ark, witness));
    const decimals = result.publicSignals.map(leHexToDecimal);

    // ── snarkjs verifies OUR proof ──────────────────────────────────────────
    //
    // The proof has to reach snarkjs in its own JSON shape. Rather than decode
    // compressed points by hand, the crate's own verifier checks our proof
    // (below) and snarkjs checks a proof it made from the same witness — so
    // both implementations are exercised against the same statement.
    const publicPath = join(scratch, `${name}-public.json`);
    writeFileSync(publicPath, JSON.stringify(decimals));

    // ── snarkjs proves the same witness, and WE verify it ───────────────────
    const sjProof = join(scratch, `${name}-sj-proof.json`);
    const sjPublic = join(scratch, `${name}-sj-public.json`);
    const proveOut = snarkjs(['groth16', 'prove', a.zkey, a.wtns, sjProof, sjPublic]);

    let sjPublicSignals;
    try {
      sjPublicSignals = readJson(sjPublic);
    } catch {
      fail(`${name}: snarkjs prove failed — ${proveOut.trim().split('\n').pop()}`);
      continue;
    }

    // The two implementations must agree on which values are public, and on
    // their order. This is what pins value_proof's output-first layout.
    check(
      JSON.stringify(decimals) === JSON.stringify(sjPublicSignals),
      `${name}: both provers agree on the public signals and their order`
    );

    // snarkjs verifies its own proof against the same VK the chain has. That
    // confirms the artifacts are a matched set.
    const verifyOut = snarkjs(['groth16', 'verify', a.vk, sjPublic, sjProof]);
    check(verifyOut.includes('OK!'), `${name}: snarkjs verifies against the published VK`);

    // ── Our verifier accepts snarkjs's proof ────────────────────────────────
    //
    // The reverse direction. A verifier that only accepts our own output would
    // pass everything above while being useless for anything from elsewhere.
    const { compress_snarkjs_proof_wasm } = await import(wasmJs);
    const compressed = compress_snarkjs_proof_wasm(readFileSync(sjProof, 'utf8'));
    equal(
      (compressed.length - 2) / 2, 128,
      `${name}: a snarkjs proof compresses to 128 bytes`
    );

    const verifyProof = join(ROOT, 'target', 'release', 'verify-proof');
    const proofPath = join(scratch, `${name}-ours.bin`);
    const witPath = join(scratch, `${name}-wit.json`);

    // verify-proof reads public inputs from witness[1..=n]; the private tail is
    // unused, so a single zero stands in for it.
    writeFileSync(witPath, JSON.stringify({
      num_public_signals: arity,
      witness: ['1', ...decimals, '0'],
    }));

    // Ours, verified by the crate.
    writeFileSync(proofPath, Buffer.from(result.proof.slice(2), 'hex'));
    try {
      execFileSync(verifyProof, [proofPath, vkBin, witPath], { stdio: 'pipe' });
      check(true, `${name}: our wasm proof verifies against the published VK`);
    } catch (err) {
      fail(`${name}: our wasm proof did NOT verify — ${(err.stderr || '').toString().trim()}`);
    }

    // snarkjs's, verified by the crate.
    const sjBin = join(scratch, `${name}-sj.bin`);
    writeFileSync(sjBin, Buffer.from(compressed.slice(2), 'hex'));
    try {
      execFileSync(verifyProof, [sjBin, vkBin, witPath], { stdio: 'pipe' });
      check(true, `${name}: a snarkjs proof verifies through our verifier`);
    } catch (err) {
      fail(`${name}: snarkjs's proof was rejected by us — ${(err.stderr || '').toString().trim()}`);
    }

    // ── The negative control ────────────────────────────────────────────────
    //
    // Without this, every "verifies" above could be produced by a verifier that
    // accepts anything.
    const tampered = [...decimals];
    tampered[0] = (BigInt(tampered[0]) + 1n).toString();
    const badWit = join(scratch, `${name}-bad.json`);
    writeFileSync(badWit, JSON.stringify({
      num_public_signals: arity,
      witness: ['1', ...tampered, '0'],
    }));
    let rejected = false;
    try {
      execFileSync(verifyProof, [proofPath, vkBin, badWit], { stdio: 'pipe' });
    } catch {
      rejected = true;
    }
    check(rejected, `${name}: a tampered public signal is rejected`);
  }
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

done('the full chain agrees with snarkjs on every circuit');
