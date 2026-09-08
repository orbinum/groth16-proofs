/*
 * The C surface of groth16-proofs — for the iOS and Android provers.
 *
 * Written by hand rather than generated. cbindgen would produce this from the
 * Rust, and then the header would be a build artifact nobody reads; the point
 * of a header is that a host developer opens it and learns how to call the
 * library without reading Rust. It is small enough to stay honest, and
 * `tests/ffi.rs` exercises every function in it.
 *
 * ABI version 1. Call orb_abi_version() first and refuse to continue if it
 * disagrees with ORB_ABI_VERSION: the library and the code calling it ship in
 * one app but are built separately, and a mismatch is otherwise a segfault
 * instead of a message.
 *
 * ## Lifetimes, in one paragraph
 *
 * orb_prover_new() gives you a handle that owns tens of megabytes; free it with
 * orb_prover_free() when the session ends. orb_prove() gives you two buffers
 * you own; free each with orb_buffer_free(). Both free functions accept null,
 * so a `finally` block can call them unconditionally.
 *
 * ## SECURITY: the witness is key material
 *
 * The witness passed to orb_prove() contains the spending key. Do not log it,
 * do not write it to disk, do not send it anywhere. The library zeroes its own
 * copy; it cannot zero yours.
 */

#ifndef ORBINUM_PROVER_H
#define ORBINUM_PROVER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ORB_ABI_VERSION 1

/* Outcome of every call. Branch on this, not on a message. */
typedef enum {
    ORB_OK = 0,
    /* A pointer argument was null, or a length was zero where it may not be. */
    ORB_NULL_ARGUMENT = 1,
    /* The bytes were not a valid .ark v2 artifact. */
    ORB_ARTIFACT_INVALID = 2,
    /* The witness was empty, misaligned, or not this circuit's width. */
    ORB_WITNESS_INVALID = 3,
    /* Proving failed for a reason that is not the caller's input. */
    ORB_PROVE_FAILED = 4,
    /* A panic was caught at the boundary — a bug in the library. */
    ORB_PANIC = 5
} OrbStatus;

/* An opaque parsed proving key. */
typedef struct OrbProver OrbProver;

/* A buffer the library owns until you free it. */
typedef struct {
    uint8_t *ptr;
    size_t len;
} OrbBuffer;

/*
 * Parse a .ark v2 artifact into a reusable prover.
 *
 * Do this ONCE per session. Parsing is ~0.5 s on a fast desktop and more on a
 * phone, while proving against an existing handle is a fraction of that — a
 * host that builds a handle per spend pays the parse every time for nothing.
 *
 * On success writes a handle to *out_prover; on failure writes NULL.
 */
OrbStatus orb_prover_new(const uint8_t *artifact, size_t artifact_len,
                         OrbProver **out_prover);

/* Free a prover. NULL is a no-op. */
void orb_prover_free(OrbProver *prover);

/*
 * Prove.
 *
 * `witness` is n * 32 little-endian bytes — a .wtns payload, not text.
 *
 * On success writes the 128-byte compressed proof to *out_proof and the public
 * signals to *out_signals as concatenated 32-byte little-endian values (so
 * out_signals->len / 32 is the signal count). Free both with orb_buffer_free().
 * On failure both are left empty and need no freeing.
 *
 * The signal count is not an argument because it is a property of the circuit,
 * read from the artifact. A caller-supplied count that disagrees produces a
 * proof that fails verification with nothing to explain why.
 */
OrbStatus orb_prove(const OrbProver *prover, const uint8_t *witness,
                    size_t witness_len, OrbBuffer *out_proof,
                    OrbBuffer *out_signals);

/* Free a buffer from orb_prove(). An empty buffer is a no-op. */
void orb_buffer_free(OrbBuffer buf);

/* The ABI version this library was built with. Check it before anything else. */
uint32_t orb_abi_version(void);

#ifdef __cplusplus
}
#endif

#endif /* ORBINUM_PROVER_H */
