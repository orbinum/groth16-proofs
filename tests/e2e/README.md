# End-to-end tests

`cargo test` proves the Rust library correct against itself and against snarkjs.
These scripts answer a different question: **does the artifact this repo ships
actually work, in the shape a consumer receives it?**

Three things sit between a correct library and a working release, and none of
them are exercised by `cargo test`:

| Boundary                   | What can break there                                                                              |
| -------------------------- | ------------------------------------------------------------------------------------------------- |
| `pkg/` (wasm-bindgen)      | A byte array mangled crossing the ABI. The Rust suite never loads the wasm.                       |
| `@orbinum/circuits`        | Artifacts that do not match the manifest, or a `.ark` from a different ceremony than its `.zkey`. |
| `@orbinum/proof-generator` | Calling a wasm export that no longer exists — the 3.0.0 → 3.1.0 rename is exactly this.           |

Each script exits 0 on success, 1 on failure, and 0 with a printed notice when
its inputs are absent, so a bare checkout stays green.

## Running

```sh
make e2e            # everything below, in order
```

Individually:

```sh
node tests/e2e/wasm-all-circuits.mjs   # pkg/ proves all three circuits
node tests/e2e/full-chain.mjs          # circuits → wasm → snarkjs, cross-verified
node tests/e2e/proof-generator.mjs     # the real consumer, through its own API
node tests/e2e/negative.mjs            # deliberate breakage is rejected, not accepted
```

`negative.mjs` is the one that would notice a module that accepts anything. Every
other script here checks that a good input produces a good proof, which a stub
returning 128 fixed bytes would also pass. This one feeds malformed JSON, a
missing `pi_a`, and a point that is not on the curve, and requires each to be
refused — through the wasm boundary, where a panic would abort the module rather
than return an error to JavaScript.

## Why `proof-generator.mjs` links three repositories

`proof-generator` resolves both `@orbinum/groth16-proofs` and
`@orbinum/circuits` from its own `node_modules`, which point at whatever
versions pnpm installed — not at these working trees. So a change here is
invisible to it until a release, and a consumer breakage is discovered by the
consumer.

The script links all three together, builds the consumer, and drives its
**public API** — `generateProof(circuit, inputs, { backend: 'arkworks' })` —
rather than reaching past it to the wasm. That distinction is the point: the
consumer's artifact provider, witness extraction, arity cross-check and error
wrapping are all code that can break independently of the prover, and calling
the wasm directly would skip every one of them.

Both backends are run over the same inputs. snarkjs and arkworks share no
proving code, so their agreement on the public signals is independent evidence,
and each proof is verified against the key the chain registered.

The links are torn down in a `finally`, and the teardown is itself asserted —
an earlier version recorded its own leftover link as the "original" and left
the consumer pointing at a deleted scratch directory.
