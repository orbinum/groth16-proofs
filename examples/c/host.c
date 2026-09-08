/* A host, in C, using only the published header. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "orbinum_prover.h"

int main(int argc, char **argv) {
    if (orb_abi_version() != ORB_ABI_VERSION) {
        fprintf(stderr, "abi mismatch: lib=%u header=%u\n",
                orb_abi_version(), ORB_ABI_VERSION);
        return 1;
    }
    printf("abi ok: %u\n", orb_abi_version());

    /* Both free functions must accept null — the header promises it. */
    orb_prover_free(NULL);
    OrbBuffer empty = { NULL, 0 };
    orb_buffer_free(empty);
    printf("null frees ok\n");

    /* A bad artifact must be a status, not a crash. */
    OrbProver *prover = NULL;
    uint8_t junk[64] = {0};
    OrbStatus st = orb_prover_new(junk, sizeof junk, &prover);
    if (st != ORB_ARTIFACT_INVALID || prover != NULL) {
        fprintf(stderr, "bad artifact: status=%d prover=%p\n", st, (void *)prover);
        return 1;
    }
    printf("bad artifact -> ORB_ARTIFACT_INVALID, handle stays null\n");

    /* Null arguments are rejected rather than dereferenced. */
    if (orb_prover_new(NULL, 10, &prover) != ORB_NULL_ARGUMENT) {
        fprintf(stderr, "null artifact not rejected\n");
        return 1;
    }
    printf("null argument -> ORB_NULL_ARGUMENT\n");

    if (argc < 2) { printf("no artifact given; skipping the proving round trip\n"); return 0; }

    /* The real thing: parse an artifact, prove, free. */
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("open"); return 1; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *art = malloc((size_t)n);
    if (fread(art, 1, (size_t)n, f) != (size_t)n) { fprintf(stderr, "short read\n"); return 1; }
    fclose(f);

    st = orb_prover_new(art, (size_t)n, &prover);
    free(art);
    if (st != ORB_OK || !prover) { fprintf(stderr, "prover_new: %d\n", st); return 1; }
    printf("artifact parsed\n");

    /* A misaligned witness must be its own status, not "artifact invalid". */
    uint8_t bad[33]; memset(bad, 7, sizeof bad);
    OrbBuffer proof = { NULL, 0 }, signals = { NULL, 0 };
    st = orb_prove(prover, bad, sizeof bad, &proof, &signals);
    if (st != ORB_WITNESS_INVALID) { fprintf(stderr, "misaligned witness: %d\n", st); return 1; }
    printf("misaligned witness -> ORB_WITNESS_INVALID\n");

    /* The real round trip: prove, and write out what came back. */
    if (argc < 3) {
        orb_prover_free(prover);
        printf("no witness given; skipping the proof\n");
        return 0;
    }
    FILE *wf = fopen(argv[2], "rb");
    if (!wf) { perror("open witness"); return 1; }
    fseek(wf, 0, SEEK_END); long wn = ftell(wf); fseek(wf, 0, SEEK_SET);
    uint8_t *wit = malloc((size_t)wn);
    if (fread(wit, 1, (size_t)wn, wf) != (size_t)wn) { fprintf(stderr, "short read\n"); return 1; }
    fclose(wf);

    proof = (OrbBuffer){ NULL, 0 };
    signals = (OrbBuffer){ NULL, 0 };
    st = orb_prove(prover, wit, (size_t)wn, &proof, &signals);
    free(wit);
    if (st != ORB_OK) { fprintf(stderr, "prove: %d\n", st); return 1; }
    if (proof.len != 128) { fprintf(stderr, "proof is %zu bytes, expected 128\n", proof.len); return 1; }
    if (signals.len % 32 != 0 || signals.len == 0) {
        fprintf(stderr, "signals: %zu bytes\n", signals.len); return 1;
    }
    printf("proved: %zu-byte proof, %zu signals\n", proof.len, signals.len / 32);

    /* Hand both to the verifier, through files. */
    FILE *pf = fopen(argv[3], "wb"); fwrite(proof.ptr, 1, proof.len, pf); fclose(pf);
    FILE *sf = fopen(argv[4], "wb"); fwrite(signals.ptr, 1, signals.len, sf); fclose(sf);

    orb_buffer_free(proof);
    orb_buffer_free(signals);
    orb_prover_free(prover);
    printf("all checks passed\n");
    return 0;
}
