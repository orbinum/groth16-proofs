# The C surface, exercised from C

`tests/ffi.rs` calls `orb_*` from Rust, where `orbinum_prover.h` does not exist.
So it proves the functions work and says nothing about whether the published
header describes them — it is hand-written, and nothing checked it against
`src/ffi/mod.rs`.

`host.c` is that check: a host built with `-Wall -Wextra -Werror` that includes
only the header, links the `cdylib`, and does the round trip a phone does —
parse an artifact once, prove, free. The proof it writes is then verified by
`examples/verify_ffi_proof.rs`, which closes the last link: bytes that crossed
the real C boundary still satisfy the verifier.

```sh
cargo build --release --features ffi
cargo run --release --bin pack-proving-key -- \
    ../circuits/keys/unshield_pk.zkey /tmp/unshield.ark
cargo run --release --example dump_witness -- \
    ../circuits/fixtures/unshield.witness.json /tmp/unshield.wit

cc -std=c11 -Wall -Wextra -Werror -Iinclude examples/c/host.c \
   -L target/release -lgroth16_proofs -o /tmp/host
DYLD_LIBRARY_PATH=target/release /tmp/host \
    /tmp/unshield.ark /tmp/unshield.wit /tmp/proof.bin /tmp/signals.bin

cargo run --release --example verify_ffi_proof -- \
    ../circuits/keys/unshield_pk.zkey /tmp/proof.bin /tmp/signals.bin
```

Last run: 128-byte proof, 7 signals, `VERIFIED`.

The host also checks what a header promises and a Rust test cannot observe:
that both free functions accept null, that a failed constructor leaves the
handle null rather than dangling, and that a misaligned witness is its own
status rather than "artifact invalid".
