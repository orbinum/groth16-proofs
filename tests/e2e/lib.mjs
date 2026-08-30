/**
 * Shared helpers for the end-to-end scripts.
 *
 * Deliberately dependency-free: these run before anything is published, and a
 * test harness that needs its own install is one more thing between a change
 * and knowing whether it works.
 */
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const HERE = dirname(fileURLToPath(import.meta.url));
export const ROOT = join(HERE, '..', '..');
export const CIRCUITS = process.env.CIRCUITS
  ? process.env.CIRCUITS
  : join(ROOT, '..', 'circuits');

/**
 * The three published circuits and their public-signal counts.
 *
 * Written here rather than read from the manifest so the two are independent
 * sources that can disagree. A table derived from the thing it checks proves
 * nothing.
 *
 * `value_proof` has four signals from three declared inputs: `owner_hash` is a
 * `signal output`, and Circom places outputs *before* public inputs in the
 * witness. The circuit's own header comment lists it last — that comment is
 * wrong, and `signalNames` below records what the witness actually holds.
 */
export const CIRCUITS_UNDER_TEST = [
  {
    name: 'unshield',
    arity: 7,
    signalNames: [
      'merkle_root', 'nullifier', 'amount', 'recipient',
      'asset_id', 'fee', 'change_commitment',
    ],
  },
  {
    name: 'transfer',
    arity: 7,
    // nullifiers and commitments are arrays of two, so five declared names
    // become seven signals.
    signalNames: [
      'merkle_root', 'nullifiers[0]', 'nullifiers[1]',
      'commitments[0]', 'commitments[1]', 'asset_id', 'fee',
    ],
  },
  {
    name: 'value_proof',
    arity: 4,
    signalNames: ['owner_hash', 'commitment', 'value', 'asset_id'],
  },
];

// ─── Output ──────────────────────────────────────────────────────────────────

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const DIM = '\x1b[2m';
const NC = '\x1b[0m';

let failures = 0;

export const pass = (msg) => console.log(`  ${GREEN}✓${NC} ${msg}`);
export const info = (msg) => console.log(`  ${DIM}${msg}${NC}`);
export const section = (msg) => console.log(`\n${msg}`);

export function fail(msg) {
  console.error(`  ${RED}✗${NC} ${msg}`);
  failures++;
}

/** Assert, recording rather than throwing, so one run reports every failure. */
export function check(condition, msg) {
  if (condition) {
    pass(msg);
  } else {
    fail(msg);
  }
  return condition;
}

export function equal(actual, expected, msg) {
  return check(
    actual === expected,
    actual === expected ? msg : `${msg} — got ${actual}, expected ${expected}`
  );
}

/** Exit with the accumulated verdict. */
export function done(what) {
  if (failures > 0) {
    console.error(`\n${RED}FAILED${NC} — ${failures} check(s) in ${what}\n`);
    process.exit(1);
  }
  console.log(`\n${GREEN}OK${NC} — ${what}\n`);
  process.exit(0);
}

/** Print a notice and exit 0: inputs absent is not a failure. */
export function skip(why) {
  console.log(`\nskipping: ${why}\n`);
  process.exit(0);
}

/** Every path must exist, or the whole script skips. */
export function requireAll(paths, why) {
  const missing = paths.filter((p) => !existsSync(p));
  if (missing.length > 0) {
    if (process.env.GROTH16_REQUIRE_ARTIFACTS) {
      console.error(`\n${RED}FAILED${NC} — GROTH16_REQUIRE_ARTIFACTS is set but these are missing:`);
      missing.forEach((p) => console.error(`    ${p}`));
      process.exit(1);
    }
    skip(`${why} (missing ${missing[0]})`);
  }
}

// ─── Formats ─────────────────────────────────────────────────────────────────

/**
 * The witness values from a `.wtns`, as the raw little-endian bytes.
 *
 * A `.wtns` is a 12-byte header then a table of (u32 type, u64 length)
 * sections; section 2 holds the values, already as the 32-byte little-endian
 * words arkworks reads. Handing over that slice untouched is both the fastest
 * path and the one with the least to get wrong.
 */
export function witnessBytes(wtns) {
  if (wtns.length < 12) throw new Error('buffer too short to be a .wtns');
  const view = new DataView(wtns.buffer, wtns.byteOffset, wtns.byteLength);
  if (String.fromCharCode(...wtns.subarray(0, 4)) !== 'wtns') {
    throw new Error('not a .wtns file');
  }

  const sections = view.getUint32(8, true);
  let off = 12;
  for (let i = 0; i < sections; i++) {
    if (off + 12 > wtns.length) throw new Error('.wtns section table overruns the buffer');
    const type = view.getUint32(off, true);
    const len = Number(view.getBigUint64(off + 4, true));
    off += 12;
    if (type === 2) {
      if (off + len > wtns.length) throw new Error('.wtns data section overruns the buffer');
      return wtns.subarray(off, off + len);
    }
    off += len;
  }
  throw new Error('.wtns has no data section');
}

/** A 32-byte little-endian hex signal as the decimal string a verifier reads. */
export const leHexToDecimal = (hex) =>
  BigInt('0x' + Buffer.from(hex.slice(2), 'hex').reverse().toString('hex')).toString();

/** A decimal field element as the 32-byte little-endian hex the chain takes. */
export function decimalToLeHex(dec) {
  const be = BigInt(dec).toString(16).padStart(64, '0');
  return '0x' + Buffer.from(be, 'hex').reverse().toString('hex');
}

/** Read a JSON file. */
export const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));

/** A circuit's artifact paths under the circuits checkout. */
export const artifacts = (name) => ({
  ark: join(CIRCUITS, 'keys', `${name}_pk.ark`),
  zkey: join(CIRCUITS, 'keys', `${name}_pk.zkey`),
  wtns: join(CIRCUITS, 'fixtures', `${name}.wtns`),
  input: join(CIRCUITS, 'fixtures', `${name}.input.json`),
  witnessJson: join(CIRCUITS, 'fixtures', `${name}.witness.json`),
  vk: join(CIRCUITS, 'build', `verification_key_${name}.json`),
});

// ─── blake2b-256 ─────────────────────────────────────────────────────────────

/**
 * Substrate's `blake2_256`, which is how the chain derives a `vk_hash`.
 *
 * Implemented here rather than taken from `node:crypto`, which offers only
 * `blake2b512`, or from a dependency, which a pre-publish harness should not
 * need. The distinction matters more than it looks: blake2b mixes its **output
 * length** into the initial state, so a 32-byte digest is not the first 32
 * bytes of a 64-byte one. Truncating `blake2b512` produces a plausible hash
 * that matches nothing — which is exactly the wrong answer this test first gave.
 *
 * RFC 7693, 64-bit variant, no key, no salt.
 */
const BLAKE2B_IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];

const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

const MASK = 0xffffffffffffffffn;
const rotr = (x, n) => ((x >> n) | (x << (64n - n))) & MASK;

function compress(h, block, counter, last) {
  const v = [...h, ...BLAKE2B_IV];
  v[12] ^= counter & MASK;
  v[13] ^= counter >> 64n;
  if (last) v[14] ^= MASK;

  const m = [];
  for (let i = 0; i < 16; i++) {
    m.push(new DataView(block.buffer, block.byteOffset, block.byteLength).getBigUint64(i * 8, true));
  }

  const mix = (a, b, c, d, x, y) => {
    v[a] = (v[a] + v[b] + x) & MASK;
    v[d] = rotr(v[d] ^ v[a], 32n);
    v[c] = (v[c] + v[d]) & MASK;
    v[b] = rotr(v[b] ^ v[c], 24n);
    v[a] = (v[a] + v[b] + y) & MASK;
    v[d] = rotr(v[d] ^ v[a], 16n);
    v[c] = (v[c] + v[d]) & MASK;
    v[b] = rotr(v[b] ^ v[c], 63n);
  };

  for (let r = 0; r < 12; r++) {
    const s = SIGMA[r];
    mix(0, 4, 8, 12, m[s[0]], m[s[1]]);
    mix(1, 5, 9, 13, m[s[2]], m[s[3]]);
    mix(2, 6, 10, 14, m[s[4]], m[s[5]]);
    mix(3, 7, 11, 15, m[s[6]], m[s[7]]);
    mix(0, 5, 10, 15, m[s[8]], m[s[9]]);
    mix(1, 6, 11, 12, m[s[10]], m[s[11]]);
    mix(2, 7, 8, 13, m[s[12]], m[s[13]]);
    mix(3, 4, 9, 14, m[s[14]], m[s[15]]);
  }
  for (let i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
}

/** blake2b with a 32-byte digest, as `0x`-prefixed hex. */
export function blake2_256(data) {
  const h = [...BLAKE2B_IV];
  h[0] ^= 0x01010000n ^ 32n; // no key, 32-byte output

  const padded = Buffer.alloc(Math.max(128, Math.ceil(data.length / 128) * 128));
  Buffer.from(data).copy(padded);

  const blocks = padded.length / 128;
  for (let i = 0; i < blocks - 1; i++) {
    compress(h, padded.subarray(i * 128, (i + 1) * 128), BigInt((i + 1) * 128), false);
  }
  compress(h, padded.subarray((blocks - 1) * 128), BigInt(data.length), true);

  const out = Buffer.alloc(64);
  h.forEach((word, i) => out.writeBigUInt64LE(word, i * 8));
  return '0x' + out.subarray(0, 32).toString('hex');
}
