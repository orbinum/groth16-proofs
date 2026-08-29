//! The `.ark` v2 artifact: a proving key together with its constraint matrices.
//!
//! Proving a Circom circuit needs both, and a v1 `.ark` is only the key — the
//! matrices `read_zkey` returns alongside it were discarded when the file was
//! written. A caller holding one has no way to recover them, so a v1 `.ark`
//! cannot produce a proof at all, however correct the prover is.
//!
//! The alternative is shipping the `.zkey` to the device and parsing it there.
//! Measured on the unshield circuit, that trades 8.25 MB of download for 4.83 MB
//! and buys nothing in load time — the two are within noise of each other, because
//! the cost is deserializing the key's curve points, not parsing the container. Bandwidth is the whole
//! difference, and on a phone's first run it is the difference that shows.
//!
//! Only the A and B matrices are stored. `CircomReduction`'s witness map derives
//! C from their evaluations rather than reading `matrices.c`, which is why
//! `read_zkey` returns an empty C and why that is correct rather than a gap. For
//! unshield the pair is 1.24 MB and deserializes in about a millisecond.
//!
//! # Format
//!
//! ```text
//! magic     8 bytes   b"ORBARKV2"
//! version   u32 LE    2
//! key       arkworks compressed ProvingKey<Bn254>
//! matrices  arkworks compressed MatrixData
//! ```
//!
//! The magic exists because a v1 `.ark` has no header of any kind — it opens
//! directly with the key's alpha_g1. Without a marker the two files are
//! distinguishable only by trying to parse one as the other, and a v1 read as a
//! v2 fails somewhere deep in deserialization with an error that names nothing
//! useful.

use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_groth16::ProvingKey;
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::core::error::ProofError;

/// Identifies a v2 artifact. A v1 file starts with curve-point bytes and will
/// not collide with this.
pub const ARK_V2_MAGIC: &[u8; 8] = b"ORBARKV2";

/// Format version, for when the layout has to change again.
pub const ARK_V2_VERSION: u32 = 2;

/// The matrix rows carried in the artifact, in the shape arkworks uses:
/// per constraint, a list of (coefficient, column index).
type MatrixRows = Vec<Vec<(Bn254Fr, usize)>>;

/// What a v2 artifact stores about the circuit's shape.
///
/// The counts are needed because A and B alone do not determine them: a
/// constraint whose row is entirely zero still occupies a position, and
/// `num_instance_variables` cannot be recovered from the matrices at all.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct MatrixData {
    num_instance_variables: u64,
    num_witness_variables: u64,
    num_constraints: u64,
    a: MatrixRows,
    b: MatrixRows,
}

/// The largest artifact this crate will parse.
///
/// The published circuits are 0.3 MB (value_proof), 4.8 MB (unshield) and
/// 9.6 MB (transfer), so 64 MB leaves an order of magnitude of headroom for
/// circuits that do not exist yet while still being a bound.
///
/// It exists because of how `ark-serialize` allocates. A `Vec<T>` is
/// deserialized by reading a u64 length and passing it straight to
/// `Vec::with_capacity`, unchecked (ark-serialize 0.5.0, `impls.rs:519`). A
/// corrupted length is therefore an arbitrary-allocation primitive, and the
/// failure is an **abort** rather than a panic — `catch_unwind` cannot recover
/// from it. Fuzzing this parser reached requests for 56 PB from single flipped
/// bits, and an audit reproduced a module-killing abort from an 828-byte file.
///
/// # This bound does not close that hole
///
/// It cannot, and the limitation is worth stating plainly rather than leaving
/// a reader to assume otherwise. `Vec::with_capacity(len)` runs *before* any
/// element is read, so the allocation size depends on the declared length and
/// not on the file: a 310 KB artifact with one flipped bit still requests 56 PB.
/// Bounding the input, validating the outer prefixes, and wrapping the reader
/// were each tried and each fail for that reason — the matrix section's inner
/// row vectors carry thousands of their own prefixes, so pre-validating them
/// would mean reimplementing the deserializer.
///
/// What this bound does buy is a cap on legitimate work and on the cheapest
/// abuse. The remaining exposure is a denial of service from a *corrupted or
/// hostile artifact*, which is why artifacts must be integrity-checked before
/// they reach this function — the `manifest.json` sha256 that
/// `@orbinum/proof-generator`'s web provider already enforces is exactly that
/// check, and it is not optional.
pub const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

/// Just the counts, so they can be checked before the rows are allocated.
///
/// `ark-serialize` deserializes a `Vec<T>` by reading a u64 length and handing
/// it straight to `Vec::with_capacity` (ark-serialize 0.5.0, `impls.rs:519`).
/// The length is never compared against the input that remains, so a corrupted
/// or hostile file is an arbitrary-allocation primitive: fuzzing this parser
/// produced a request for 56 PB from a single flipped byte, and an audit
/// reproduced a module-killing abort from an 828-byte artifact. Neither is
/// recoverable — an allocation failure aborts rather than unwinding, so
/// `catch_unwind` does not help.
///
/// Reading the header separately is what makes the bound possible: by the time
/// the row vectors are deserialized, the counts have already been reconciled
/// with the proving key, and a row count that disagrees is rejected before
/// anything is allocated from it.
#[derive(CanonicalDeserialize)]
struct MatrixHeader {
    num_instance_variables: u64,
    num_witness_variables: u64,
    num_constraints: u64,
}

/// Serialize a proving key and its matrices into one `.ark` v2 blob.
///
/// Takes what [`crate::read_zkey`] returns, so converting a `.zkey` is read then
/// write with nothing in between.
pub fn write_ark_v2(
    pk: &ProvingKey<Bn254>,
    matrices: &ConstraintMatrices<Bn254Fr>,
) -> Result<Vec<u8>, ProofError> {
    let mut out = Vec::new();
    out.extend_from_slice(ARK_V2_MAGIC);
    out.extend_from_slice(&ARK_V2_VERSION.to_le_bytes());

    pk.serialize_compressed(&mut out)
        .map_err(|e| ProofError::ProofSerialization(format!("proving key: {e}")))?;

    let data = MatrixData {
        num_instance_variables: matrices.num_instance_variables as u64,
        num_witness_variables: matrices.num_witness_variables as u64,
        num_constraints: matrices.num_constraints as u64,
        a: matrices.a.clone(),
        b: matrices.b.clone(),
    };
    data.serialize_compressed(&mut out)
        .map_err(|e| ProofError::ProofSerialization(format!("matrices: {e}")))?;

    Ok(out)
}

/// The `Vec` length prefix at the cursor, without consuming it.
///
/// ark-serialize writes a `Vec` as a u64 little-endian length followed by the
/// elements, and reads it back by calling `Vec::with_capacity` on that length
/// *before* reading any element. Peeking lets the caller reject an absurd
/// length while the bytes are still just bytes.
fn peek_vec_len(cursor: &[u8], label: &str) -> Result<u64, ProofError> {
    const PREFIX: usize = core::mem::size_of::<u64>();
    if cursor.len() < PREFIX {
        return Err(ProofError::ProvingKeyParse(format!(
            "matrix {label}: the file ends before its row count"
        )));
    }
    let mut buf = [0u8; PREFIX];
    buf.copy_from_slice(&cursor[..PREFIX]);
    Ok(u64::from_le_bytes(buf))
}

/// Read a `.ark` v2 blob back into a proving key and its matrices.
///
/// Rejects a v1 file by name rather than failing partway through
/// deserialization, because that is the mistake a caller will actually make: v1
/// files are what every published package shipped until now.
pub fn read_ark_v2(
    bytes: &[u8],
) -> Result<(ProvingKey<Bn254>, ConstraintMatrices<Bn254Fr>), ProofError> {
    if bytes.len() < ARK_V2_MAGIC.len() + 4 {
        return Err(ProofError::ProvingKeyParse(
            "artifact is too short to be a .ark v2 file".into(),
        ));
    }
    // A cap on input size, and only that. It bounds how much a caller can hand
    // over; it does not bound what a length prefix inside those bytes asks to
    // allocate — see MAX_ARTIFACT_BYTES, which says so at length. The prefix that
    // ark-serialize actually sizes from is checked further down, against the
    // header.
    if bytes.len() > MAX_ARTIFACT_BYTES {
        return Err(ProofError::ProvingKeyParse(format!(
            "artifact is {} bytes, over the {MAX_ARTIFACT_BYTES}-byte limit",
            bytes.len()
        )));
    }
    if &bytes[..ARK_V2_MAGIC.len()] != ARK_V2_MAGIC {
        return Err(ProofError::ProvingKeyParse(
            "not a .ark v2 artifact — a v1 file carries only the proving key and \
             cannot be used for proving. Regenerate it with pack-proving-key."
                .into(),
        ));
    }
    let version = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if version != ARK_V2_VERSION {
        return Err(ProofError::ProvingKeyParse(format!(
            "unsupported .ark version {version}, expected {ARK_V2_VERSION}"
        )));
    }

    let body = &bytes[12..];

    // Both structures are read from the same cursor: the key's own length is
    // implicit in its encoding, so the matrices start wherever it ends.
    let mut cursor = body;
    let pk = ProvingKey::<Bn254>::deserialize_compressed(&mut cursor)
        .map_err(|e| ProofError::ProvingKeyParse(format!("proving key: {e}")))?;

    // The counts come first and are checked before the rows are read, so a
    // hostile row count is rejected rather than allocated. See `MatrixHeader`.
    let header = MatrixHeader::deserialize_compressed(&mut cursor)
        .map_err(|e| ProofError::ProvingKeyParse(format!("matrix header: {e}")))?;

    // ── Reconcile the header against the key it travels with ────────────────
    //
    // These counts are attacker-controlled if the artifact is: they are plain
    // integers in a file that may have been fetched over a network. The proving
    // key carries the same facts independently — `gamma_abc_g1` has one element
    // per instance variable, `l_query` one per private variable, `a_query` one
    // per variable — so the two can be cross-checked here, once, rather than
    // trusted by every consumer downstream.
    let declared_instance = header.num_instance_variables;
    let key_instance = pk.vk.gamma_abc_g1.len() as u64;
    if declared_instance != key_instance {
        return Err(ProofError::ProvingKeyParse(format!(
            "artifact declares {declared_instance} instance variables but its proving key \
             encodes {key_instance} — the header and the key are for different circuits"
        )));
    }

    // `num_witness_variables` needs the same treatment, and for a sharper
    // reason: it is one half of the column bound below, so leaving it free
    // makes that bound vacuous. Set it to `u64::MAX - 2` and every column index
    // passes; set it to `u64::MAX` and the sum *wraps* in release, where
    // overflow is not checked. Either way an out-of-range column reaches
    // `evaluate_constraint`, which indexes the witness without checking and
    // panics — in wasm, taking the module with it.
    // `l_query` covers the private assignment and runs one short of
    // `num_witness_variables`, because `read_zkey` counts the leading constant
    // among the witness variables while the key does not. Measured on all three
    // published circuits, which is why it is written as a relation rather than
    // assumed: unshield 16921/16920, transfer 33723/33722, value_proof
    // 1152/1151.
    let declared_witness = header.num_witness_variables;
    let key_witness = pk.l_query.len() as u64 + 1;
    if declared_witness != key_witness {
        return Err(ProofError::ProvingKeyParse(format!(
            "artifact declares {declared_witness} witness variables but its proving key \
             encodes {key_witness} — the header and the key are for different circuits"
        )));
    }

    // Checked rather than plain addition: release builds wrap silently, and a
    // wrapped bound is worse than no bound because it looks like one.
    let columns = declared_instance
        .checked_add(declared_witness)
        .ok_or_else(|| {
            ProofError::ProvingKeyParse(
                "artifact's variable counts overflow when added — the file is corrupt or hostile"
                    .into(),
            )
        })?;
    // `a_query` has one entry per wire, which is one fewer than
    // instance + witness for the same reason as above.
    if columns != pk.a_query.len() as u64 + 1 {
        return Err(ProofError::ProvingKeyParse(format!(
            "artifact declares {columns} variables but its proving key encodes {} — \
             the header and the key are for different circuits",
            pk.a_query.len() as u64 + 1
        )));
    }

    // A row count larger than the bytes that remain cannot be honest: every row
    // costs at least one byte on the wire. This runs before the row vectors are
    // deserialized, which is the whole reason the header is read separately.
    let remaining = cursor.len() as u64;
    if header.num_constraints > remaining {
        return Err(ProofError::ProvingKeyParse(format!(
            "artifact declares {} constraints but only {remaining} bytes follow — \
             the file is corrupt or hostile",
            header.num_constraints
        )));
    }

    // Bounding `num_constraints` is not enough on its own. `MatrixRows` is a
    // `Vec`, and ark-serialize reads *its own* u64 length prefix and calls
    // `Vec::with_capacity(len)` before reading a single element
    // (ark-serialize 0.5.0, impls.rs:511-519). That prefix is a separate field
    // in the byte stream, and nothing above constrains it: an artifact with an
    // honest `num_constraints` of 2 and an outer prefix of 2^60 reaches the
    // allocation. Measured before this guard existed — a 250 KB file, far under
    // MAX_ARTIFACT_BYTES, aborted with `capacity overflow`. On a native target
    // that is a recoverable panic; in wasm, where the wallet calls
    // `read_ark_v2`, unwinding does not exist and the module dies.
    //
    // So read the prefix here, bound it, and only then hand the bytes over.
    for label in ["A", "B"] {
        let declared = peek_vec_len(cursor, label)?;
        if declared != header.num_constraints {
            return Err(ProofError::ProvingKeyParse(format!(
                "matrix {label} declares {declared} rows but the header says {} \
                 constraints — the file is corrupt or hostile",
                header.num_constraints
            )));
        }
    }

    // Kept for the 32-bit round-trip check below; on 64-bit nothing reads it.
    #[cfg(target_pointer_width = "32")]
    let matrix_bytes: &[u8] = cursor;

    let a = MatrixRows::deserialize_compressed(&mut cursor)
        .map_err(|e| ProofError::ProvingKeyParse(format!("matrix A: {e}")))?;
    let b = MatrixRows::deserialize_compressed(&mut cursor)
        .map_err(|e| ProofError::ProvingKeyParse(format!("matrix B: {e}")))?;

    // The bytes the two matrices actually consumed.
    #[cfg(target_pointer_width = "32")]
    let matrix_bytes = &matrix_bytes[..matrix_bytes.len() - cursor.len()];

    // Nothing may follow the matrices. Measured before this check: a real
    // artifact with a megabyte of padding appended parsed as valid, yielding the
    // same key and the same matrices as the honest file.
    //
    // No consumer is known to be exploitable — `proof-generator` verifies the
    // manifest's sha256 fail-closed before it ever calls this — but that is a
    // contract this crate cannot enforce on its callers, and a format that
    // accepts padding is not the canonical format the manifest claims to pin.
    if !cursor.is_empty() {
        return Err(ProofError::ProvingKeyParse(format!(
            "{} bytes follow the matrix section — a .ark v2 artifact ends there",
            cursor.len()
        )));
    }

    if a.len() as u64 != header.num_constraints || b.len() as u64 != header.num_constraints {
        return Err(ProofError::ProvingKeyParse(format!(
            "artifact declares {} constraints but carries {} A rows and {} B rows",
            header.num_constraints,
            a.len(),
            b.len()
        )));
    }

    // Column indices address the full assignment. One past the end is an
    // out-of-bounds read waiting for whichever consumer indexes with it.
    for (label, rows) in [("A", &a), ("B", &b)] {
        if let Some(bad) = rows
            .iter()
            .flatten()
            .map(|(_, col)| *col as u64)
            .find(|col| *col >= columns)
        {
            return Err(ProofError::ProvingKeyParse(format!(
                "matrix {label} references column {bad}, but the circuit has only {columns} \
                 variables"
            )));
        }
    }

    // The check above widens `usize` back to u64, but on a 32-bit target the high
    // half is already gone: ark-serialize deserializes a column index as
    // `<u64>::from_le_bytes(bytes) as usize` (impls.rs:148), and on wasm32 —
    // where the wallet runs — that truncates silently. A column of
    // 0x0000_0001_0000_0005 arrives as 5, passes the bound above, and two
    // different files decode to the same matrix. The manifest pins artifacts by
    // sha256, so an aliasing encoding is a problem even before it is a
    // memory-safety one.
    //
    // Rather than re-parse the section to inspect raw indices, re-serialize what
    // was decoded and require it to reproduce the bytes that were read. A
    // truncated index cannot: it writes back the low half and the comparison
    // fails. This also catches any other non-canonical encoding for free, which
    // is what the manifest's sha256 assumes.
    //
    // The gate is `target_pointer_width`, not `target_arch`: wasm32 is the target
    // that matters here, but armv7 and i686 truncate identically. On 64-bit the
    // whole check compiles away.
    #[cfg(target_pointer_width = "32")]
    {
        let mut round_trip = Vec::with_capacity(matrix_bytes.len());
        a.serialize_compressed(&mut round_trip)
            .and_then(|()| b.serialize_compressed(&mut round_trip))
            .map_err(|e| {
                ProofError::ProvingKeyParse(format!("re-serializing the matrices: {e}"))
            })?;
        if round_trip != matrix_bytes {
            return Err(ProofError::ProvingKeyParse(
                "the matrix section does not re-encode to the bytes it was read from — \
                 an index does not fit this platform's usize, or the encoding is not canonical"
                    .into(),
            ));
        }
    }

    let matrices = ConstraintMatrices::<Bn254Fr> {
        num_instance_variables: declared_instance as usize,
        num_witness_variables: declared_witness as usize,
        num_constraints: header.num_constraints as usize,
        a_num_non_zero: a.iter().map(Vec::len).sum(),
        b_num_non_zero: b.iter().map(Vec::len).sum(),
        // Empty by design: CircomReduction computes C from the A and B
        // evaluations, so storing it would cost megabytes to no end.
        c_num_non_zero: 0,
        a,
        b,
        c: Vec::new(),
    };
    Ok((pk, matrices))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_v1_artifact_is_rejected_by_name() {
        // A v1 .ark opens with the key's alpha_g1, not a magic string.
        let v1 = vec![0x42u8; 256];
        let err = read_ark_v2(&v1).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("v1"),
            "error should name the v1 case, got: {msg}"
        );
    }

    #[test]
    fn a_truncated_artifact_is_rejected() {
        assert!(read_ark_v2(b"ORB").is_err());
    }

    #[test]
    fn an_unknown_version_is_rejected() {
        let mut bytes = ARK_V2_MAGIC.to_vec();
        bytes.extend_from_slice(&99u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 64]);
        let msg = read_ark_v2(&bytes).unwrap_err().to_string();
        assert!(
            msg.contains("99"),
            "error should name the version, got: {msg}"
        );
    }
}
