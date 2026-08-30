# groth16-proofs

> Groth16 proof generation for Circom circuits, using arkworks.

[![npm version](https://img.shields.io/npm/v/@orbinum/groth16-proofs.svg)](https://www.npmjs.com/package/@orbinum/groth16-proofs)
[![Crates.io](https://img.shields.io/crates/v/groth16-proofs.svg)](https://crates.io/crates/groth16-proofs)
[![License](https://img.shields.io/badge/license-GPL--3.0--or--later-blue)](./LICENSE)

Produces 128-byte compressed Groth16 proofs on BN254 from a pre-computed
witness. Builds native and to WebAssembly.

Witness calculation is the caller's job — snarkjs in a browser, a native
calculator on a phone — so nothing here needs a WebAssembly runtime, which is
what makes the native build usable on a platform that has none.

## Install

**Rust**

```toml
[dependencies]
groth16-proofs = "4.0"
```

**JavaScript** (WASM)

```bash
npm install @orbinum/groth16-proofs
```

## Use

**Rust**

```rust
use groth16_proofs::{prove_circom, public_inputs, read_ark_v2, verify_proof};

let artifact = std::fs::read("unshield_pk.ark")?;
let (pk, matrices) = read_ark_v2(&artifact)?;

// The proving key costs hundreds of milliseconds to deserialize. Hold it
// across proofs rather than reading it per transaction.
let proof = prove_circom(&pk, &matrices, &witness)?;
assert!(verify_proof(&pk.vk, public_inputs(&matrices, &witness)?, &proof)?);
```

**JavaScript**

```javascript
import init, { generate_proof_wasm } from "@orbinum/groth16-proofs";
import * as snarkjs from "snarkjs";

await init();

// A .wtns file's data section is already the format this takes: n × 32
// little-endian bytes.
const { data } = await snarkjs.wtns.calculate(input, wasmBuffer, {
  type: "mem",
});
const result = generate_proof_wasm(artifactBytes, data);

const { proof, publicSignals } = JSON.parse(result);
```

`generate_proof_wasm` reads the public-signal count from the artifact rather
than taking it as an argument. It is a property of the circuit, and a caller
that gets it wrong produces a proof that fails verification with nothing to
explain why — which is how a bug shipped in 2.x.

## What 4.0.0 started rejecting

Four inputs that earlier versions accepted are now errors. Three of them can break
a working caller, so they are listed here rather than only in the CHANGELOG.

- **The witness must be exactly the circuit's width** — `num_instance_variables +
num_witness_variables - 1`, not merely long enough to cover the public signals.
  A short witness used to abort the process (in wasm, the whole module); a long one
  was silently truncated into a proof that could never verify. Both now return an
  error naming the two lengths.
- **A proof must be exactly 128 bytes.** `verify_proof` previously read the first
  128 bytes of a longer slice and ignored the rest, so one proof had many valid
  encodings.
- **`.ark` artifacts may not carry trailing bytes.** A padded file used to parse as
  valid.
- **Decimal strings must be canonical** — digits only, no leading zeros, below the
  field modulus. `"0001"`, `"+1"`, `"1_0"` and values ≥ p were accepted and
  silently normalised, which made `pack_snarkjs_vk` many-to-one and its
  `blake2_256` — the `vk_hash` the chain registers — a many-to-one function of the
  source JSON. Every published artifact was checked before this landed: none is
  affected.

Each is a rejection, never a change in what a valid input produces. Anything that
verified before still verifies, byte for byte.

## Artifacts

Proving needs a **`.ark` v2** file, which carries the proving key _and_ the
circuit's constraint matrices. Both are required: Circom's QAP reduction
computes the H polynomial from the A and B matrices, and a proof built without
them is well-formed, exactly 128 bytes, and never verifies.

```bash
# .zkey → .ark v2 (the proving side)
cargo run --release --bin pack-proving-key -- unshield_pk.zkey

# verification_key.json → the bytes the chain registers (the verifying side)
cargo run --release --bin pack-verifying-key -- verification_key_unshield.json
```

A v1 `.ark` holds only the proving key and is refused with a message saying so.

## Binaries

| Binary               | What it does                                                                         |
| -------------------- | ------------------------------------------------------------------------------------ |
| `pack-proving-key`   | `.zkey` → `.ark` v2 artifact                                                         |
| `pack-verifying-key` | snarkjs `verification_key.json` → the compressed bytes the chain stores              |
| `verify-proof`       | Checks a proof against a verifying key, including the arity the chain does not check |
| `bench-circom`       | Times proving and verification, verifying every proof it times                       |

## Layout

Four layers, with dependency arrows that only point down:

| Layer          | Contents                    | Responsibility                                                                                                         |
| -------------- | --------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `src/core/`    | `error.rs`, `field.rs`      | `ProofError`, and BN254 conversion between decimal strings, `.wtns` bytes and chain hex. Depends on nothing else here. |
| `src/format/`  | `artifact.rs`, `snarkjs.rs` | The `.ark` v2 container, and snarkjs JSON in both directions. Uses `core` only.                                        |
| `src/groth16/` | `prove.rs`, `verify.rs`     | Proving under `CircomReduction`, and the pairing check. Uses `core` and `vendor`.                                      |
| `src/vendor/`  | `qap.rs`, `zkey.rs`         | `CircomReduction` and `read_zkey`, copied from ark-circom.                                                             |

Plus `src/wasm/`, the wasm-bindgen bindings behind the `wasm` feature, and
`src/bin/`, the four CLI tools.

Two boundaries are worth stating because they are easy to erode:

- **`format` does not use `groth16`.** Parsing a verifying key is not proving
  with one.
- **`groth16` does not use `format`.** `prove_circom` takes a key and matrices
  that are already deserialized, so it never learns what a `.ark` file is —
  which is what lets a caller hold one key across many proofs instead of
  re-reading it per transaction.

The grouping is an implementation detail: every public item is re-exported from
the crate root, so the path is `groth16_proofs::prove_circom`, not
`groth16_proofs::groth16::prove::prove_circom`. `tests/api_surface.rs` fails if
that stops being true.

`vendor/` is a copy of two files from [ark-circom](https://github.com/arkworks-rs/circom-compat)
rather than a dependency, because ark-circom pulls in **wasmer** — a complete
WASM runtime — for a witness calculator this crate never calls. Carrying an
interpreter for a language we are trying to leave, into a binary where every
megabyte is an app-store download, is not a trade worth making for 576 lines.

`tests/vendor.rs` pins the copy two ways, because the two files diverge for
different reasons. `qap.rs` is byte-identical to upstream and is pinned by content
digest — it is the QAP reduction, and an edit there is invisible until proofs stop
verifying. `zkey.rs` diverges deliberately: upstream aborts on malformed input in
six places, including point constructors that assert `is_on_curve()` in release
builds, so each fix is marked `DIVERGENCE FROM UPSTREAM` in place and the marks
are what get counted.

## Testing

```bash
make test            # unit + integration
make test-release    # the same, in release — proving is impractically slow in debug
make test-publish    # what has to pass before publishing
```

Integration tests need the sibling `circuits` checkout and skip themselves
without it. That skip is deliberate but dangerous: a suite that skips
everything looks exactly like a suite that passes everything. Set
`GROTH16_REQUIRE_ARTIFACTS=1` to turn absence into a failure, which is what CI
does after fetching the published artifacts.

`tests/cross_verify.rs` is the test that matters most — it proves with arkworks
and verifies with **snarkjs**, for all three circuits, in both directions. The
chain accepts what snarkjs accepts, so agreement with an independent
implementation is stronger evidence than any amount of self-consistency.

`make e2e` goes one step further out, and `make test-publish` includes it. The
scripts under `tests/e2e/` run against the built wasm rather than the library, and
one of them links this tree into `@orbinum/proof-generator` and drives its public
API — the artifact provider, the witness extraction, the arity cross-check. Those
are the seams a Rust test cannot see, and they are where an integration actually
breaks.

## API documentation

`cargo doc --open`. The examples in the crate docs are compiled by `cargo test`,
so a renamed function or a changed signature breaks the build rather than
misleading a reader. They are `no_run` — they open artifact files that a doc build
has no reason to have — so their _assertions_ are not checked; the byte count in
the `pack_snarkjs_vk` example is pinned instead by `tests/chain_rules.rs` against
the real keys.

## License

GNU General Public License v3.0 or later ([LICENSE](LICENSE)).

`src/vendor/` is copied from [ark-circom](https://github.com/arkworks-rs/circom-compat)
(Copyright (c) 2021 Georgios Konstantopoulos), taken under its MIT option. MIT is
GPL-compatible, so the combined work is distributed under the GPL; the original
notice stays in those files.
