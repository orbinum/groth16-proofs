/**
 * `@orbinum/proof-generator`, driven through its own public API, against this
 * working tree.
 *
 * The earlier consumer script linked the fresh wasm and then called
 * `generate_proof_wasm` directly — which proves the wasm works, but skips every
 * line of the consumer's own code: its artifact provider, its witness
 * extraction, its arity cross-check, its error wrapping. Those are exactly the
 * places an integration breaks.
 *
 * So this one calls `generateProof(circuit, inputs, { backend: 'arkworks' })`
 * and nothing else, with all three repositories linked together locally:
 *
 *   proof-generator  →  this tree's pkg/        (the wasm under test)
 *                    →  ../circuits             (real proving keys)
 *
 * It then verifies every proof the consumer returns, because a consumer that
 * returns 128 bytes of garbage looks identical to one that works.
 *
 * Both backends are run over the same inputs. They share no proving code —
 * snarkjs is JavaScript, arkworks is this crate's wasm — so agreement between
 * them on the public signals is independent evidence, and a proof from each
 * verifying against the same registered key is the strongest check available
 * without a node.
 *
 * Nothing is left modified: the links are torn down in a `finally`.
 *
 * Usage (after `make build-wasm`):
 *   node tests/e2e/proof-generator.mjs
 */
import {
  readFileSync, writeFileSync, existsSync, mkdtempSync, rmSync, mkdirSync,
  symlinkSync, lstatSync, readlinkSync, unlinkSync, renameSync, readdirSync,
} from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  ROOT, CIRCUITS, artifacts, requireAll, readJson, leHexToDecimal,
  check, equal, info, section, done, fail, skip, blake2_256,
} from './lib.mjs';

const CONSUMER = process.env.PROOF_GENERATOR
  ? resolve(process.env.PROOF_GENERATOR)
  : join(ROOT, '..', 'proof-generator');

const pkgDir = join(ROOT, 'pkg');
requireAll([join(pkgDir, 'groth16_proofs.js')], 'pkg/ not built — run `make build-wasm`');

if (!existsSync(join(CONSUMER, 'node_modules'))) {
  skip(`proof-generator has no node_modules at ${CONSUMER}`);
}
if (!existsSync(join(CIRCUITS, 'keys'))) {
  skip(`no circuits checkout at ${CIRCUITS}`);
}

// ─── Link the three repositories ─────────────────────────────────────────────
//
// `proof-generator` resolves both dependencies from its own node_modules. To
// exercise *this* tree we swap those links, and to exercise the local circuits
// we build a flat directory of the artifact names its provider expects — they
// live under build/ and keys/ in the checkout, but the package ships them flat.

const links = [];

/** Replace a node_modules entry, remembering how to put it back.
 *
 * Refuses to record a link this script left behind on an earlier run. Without
 * that check, a crashed run's temporary link becomes the next run's "original",
 * and restoring it points the consumer at a scratch directory that no longer
 * exists — which is exactly what happened the first time this ran.
 */
function relink(name, target) {
  const path = join(CONSUMER, 'node_modules', '@orbinum', name);
  let restore = null;
  if (existsSync(path)) {
    const stat = lstatSync(path);
    if (stat.isSymbolicLink()) {
      const current = readlinkSync(path);
      const ours = current.includes('groth16-pg-') || current === pkgDir;
      if (ours) {
        // A leftover from a previous run. Its own target is not a valid
        // restore point, so recover the real one from pnpm's store instead.
        restore = { kind: 'symlink', target: pnpmOriginal(name) };
      } else {
        restore = { kind: 'symlink', target: current };
      }
      unlinkSync(path);
    } else {
      restore = { kind: 'dir', moved: `${path}.e2e-backup` };
      renameSync(path, restore.moved);
    }
  }
  symlinkSync(target, path, 'dir');
  links.push({ path, restore });
}

/** The link pnpm would have created, recovered from its store. */
function pnpmOriginal(name) {
  const store = join(CONSUMER, 'node_modules', '.pnpm');
  const prefix = `@orbinum+${name}@`;
  const entry = existsSync(store)
    ? readdirSync(store).find((d) => d.startsWith(prefix))
    : null;
  if (!entry) {
    throw new Error(
      `cannot recover the original link for @orbinum/${name}: no ${prefix}* in .pnpm. ` +
      `Restore it by hand or re-run pnpm install.`
    );
  }
  return join('..', '.pnpm', entry, 'node_modules', '@orbinum', name);
}

function unlinkAll() {
  for (const { path, restore } of links.reverse()) {
    try {
      if (existsSync(path) && lstatSync(path).isSymbolicLink()) unlinkSync(path);
      if (restore?.kind === 'symlink') symlinkSync(restore.target, path, 'dir');
      else if (restore?.kind === 'dir') renameSync(restore.moved, path);
    } catch (err) {
      fail(`could not restore ${path} — ${err.message}. Fix by hand.`);
    }
  }
}

/** A flat directory of circuit artifacts, in the layout the package ships. */
function flattenCircuits(into) {
  mkdirSync(into, { recursive: true });
  for (const name of ['unshield', 'transfer', 'value_proof']) {
    const files = [
      [join(CIRCUITS, 'build', `${name}_js`, `${name}.wasm`), `${name}.wasm`],
      [join(CIRCUITS, 'keys', `${name}_pk.zkey`), `${name}_pk.zkey`],
      [join(CIRCUITS, 'keys', `${name}_pk.ark`), `${name}_pk.ark`],
    ];
    for (const [src, dest] of files) {
      if (existsSync(src)) symlinkSync(src, join(into, dest));
    }
  }
  // The provider resolves its root from this file.
  writeFileSync(
    join(into, 'package.json'),
    JSON.stringify({ name: '@orbinum/circuits', version: '0.14.0-local' }, null, 2)
  );
  return into;
}

const scratch = mkdtempSync(join(tmpdir(), 'groth16-pg-'));
let exitCode = 0;

try {
  const circuitsFlat = flattenCircuits(join(scratch, 'circuits'));
  relink('groth16-proofs', pkgDir);
  relink('circuits', circuitsFlat);

  section('linked');
  const gp = readJson(join(CONSUMER, 'node_modules', '@orbinum', 'groth16-proofs', 'package.json'));
  equal(gp.version, readJson(join(pkgDir, 'package.json')).version,
    `proof-generator resolves groth16-proofs@${gp.version} (this tree)`);
  info(`circuits artifacts served from ${CIRCUITS}`);

  // ── Load the consumer's own compiled module ───────────────────────────────
  //
  // Its source is TypeScript; `pnpm build` emits CommonJS to dist/. Building
  // here rather than importing src/ means the code under test is the code it
  // would actually publish.
  section('building the consumer');
  try {
    execFileSync('pnpm', ['build'], { cwd: CONSUMER, stdio: 'pipe' });
    check(true, 'proof-generator compiles against this tree');
  } catch (err) {
    const out = `${err.stdout ?? ''}${err.stderr ?? ''}`.trim();
    fail(`proof-generator failed to compile:\n${out.split('\n').slice(0, 12).join('\n')}`);
    throw new Error('cannot continue without a build');
  }

  const { createRequire } = await import('node:module');
  const requireFromConsumer = createRequire(join(CONSUMER, 'package.json'));
  const pg = requireFromConsumer(join(CONSUMER, 'dist', 'index.js'));

  check(typeof pg.generateProof === 'function', 'generateProof is exported');

  // ── Build real circuit inputs ─────────────────────────────────────────────
  //
  // The fixtures carry the exact inputs each circuit was proved with, so the
  // consumer computes its own witness from them via snarkjs and we can check
  // the public signals against a known-good answer.
  const provider = new pg.NodeArtifactProvider(circuitsFlat);

  const cases = [
    { type: pg.CircuitType.ValueProof, name: 'value_proof', arity: 4 },
    { type: pg.CircuitType.Unshield, name: 'unshield', arity: 7 },
    { type: pg.CircuitType.Transfer, name: 'transfer', arity: 7 },
  ];

  const packVk = join(ROOT, 'target', 'release', 'pack-verifying-key');
  const verifyProof = join(ROOT, 'target', 'release', 'verify-proof');
  const manifest = readJson(join(CIRCUITS, 'manifest.json'));

  for (const { type, name, arity } of cases) {
    section(name);
    const a = artifacts(name);
    if (!existsSync(a.input) || !existsSync(a.vk)) {
      info(`skipping ${name}: no fixture or verifying key`);
      continue;
    }
    const inputs = readJson(a.input);

    // ── The arkworks backend: this crate's wasm, through the consumer ───────
    let ark;
    try {
      ark = await pg.generateProof(type, inputs, {
        backend: 'arkworks',
        provider,
        verbose: false,
      });
      check(true, `${name}: generateProof(backend: 'arkworks') returned`);
    } catch (err) {
      fail(`${name}: the arkworks backend threw — ${err.message}`);
      continue;
    }

    equal((ark.proof.length - 2) / 2, 128, `${name}: arkworks proof is 128 bytes`);
    equal(ark.publicSignals.length, arity, `${name}: ${arity} public signals`);
    equal(ark.circuitType, type, `${name}: result names its circuit`);

    // ── The snarkjs backend: independent implementation, same inputs ────────
    let sj = null;
    try {
      sj = await pg.generateProof(type, inputs, { backend: 'snarkjs', provider });
      check(true, `${name}: generateProof(backend: 'snarkjs') returned`);
    } catch (err) {
      fail(`${name}: the snarkjs backend threw — ${err.message}`);
    }

    if (sj) {
      // The proofs differ (both are randomised), but the statement does not.
      check(
        JSON.stringify(ark.publicSignals) === JSON.stringify(sj.publicSignals),
        `${name}: both backends agree on the public signals`
      );
    }

    // ── The half that matters: do these proofs verify? ──────────────────────
    const vkBin = join(scratch, `${name}-vk.bin`);
    execFileSync(packVk, [a.vk, vkBin], { stdio: 'pipe' });

    // And is that the key the chain registered?
    const published = manifest.circuits[name]?.versions?.['1']?.vk_hash;
    if (published) {
      equal(blake2_256(readFileSync(vkBin)), published,
        `${name}: verified against the key the chain registered`);
    }

    for (const [label, result] of [['arkworks', ark], ['snarkjs', sj]]) {
      if (!result) continue;
      const decimals = result.publicSignals.map(leHexToDecimal);
      const proofPath = join(scratch, `${name}-${label}.bin`);
      const witPath = join(scratch, `${name}-${label}-wit.json`);
      writeFileSync(proofPath, Buffer.from(result.proof.slice(2), 'hex'));
      writeFileSync(witPath, JSON.stringify({
        num_public_signals: arity,
        witness: ['1', ...decimals, '0'],
      }));
      try {
        execFileSync(verifyProof, [proofPath, vkBin, witPath], { stdio: 'pipe' });
        check(true, `${name}: the ${label} proof VERIFIES`);
      } catch (err) {
        fail(`${name}: the ${label} proof did NOT verify — ${(err.stderr || '').toString().trim()}`);
      }
    }

    // ── Negative control ───────────────────────────────────────────────────
    //
    // Without this, "verifies" above could be produced by a verifier that
    // accepts anything.
    const tampered = ark.publicSignals.map(leHexToDecimal);
    tampered[0] = (BigInt(tampered[0]) + 1n).toString();
    const badWit = join(scratch, `${name}-bad.json`);
    writeFileSync(badWit, JSON.stringify({
      num_public_signals: arity,
      witness: ['1', ...tampered, '0'],
    }));
    let rejected = false;
    try {
      execFileSync(verifyProof, [join(scratch, `${name}-arkworks.bin`), vkBin, badWit], { stdio: 'pipe' });
    } catch {
      rejected = true;
    }
    check(rejected, `${name}: a tampered signal is rejected`);
  }

  // ── The consumer's own validation still fires ─────────────────────────────
  section('the consumer rejects bad input');
  try {
    await pg.generateProof(cases[0].type, null, { backend: 'arkworks', provider });
    fail('null inputs were accepted');
  } catch (err) {
    check(err.code === 'INVALID_INPUTS' || /invalid/i.test(err.message),
      `null inputs rejected (${err.code ?? err.constructor.name})`);
  }
} catch (err) {
  fail(`run failed: ${err.message}`);
  exitCode = 1;
} finally {
  unlinkAll();
  rmSync(scratch, { recursive: true, force: true });
  section('restored');
  for (const name of ['groth16-proofs', 'circuits']) {
    const p = join(CONSUMER, 'node_modules', '@orbinum', name);
    // `existsSync` follows symlinks, so a dangling link reads as absent —
    // which is the failure to catch: the consumer would be left broken.
    let version = '(absent)';
    try {
      version = readJson(join(p, 'package.json')).version;
    } catch { /* reported below */ }
    check(
      version !== '(absent)',
      `@orbinum/${name} restored to a working link (${version})`
    );
  }
}

done('proof-generator produces verifying proofs with this tree linked in');
