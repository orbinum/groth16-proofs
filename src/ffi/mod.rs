//! The C surface, for the iOS and Android provers.
//!
//! Bindings only, like `wasm/`: every function converts arguments, calls into
//! the library, and converts back. The difference is what a mistake costs. In
//! wasm a panic aborts a module the user can reload; here it unwinds across a
//! language boundary, which is undefined behaviour and takes the whole app with
//! it. So every function that can be reached from C is wrapped in
//! [`std::panic::catch_unwind`], and none of them let a `Result` escape as a
//! panic.
//!
//! ## The prover handle
//!
//! `generate_proof_wasm` parses the artifact on every call — 573 ms of the
//! ~700 ms a proof costs on an M4, paid again for each spend. A phone pays it
//! too, and more. So the native surface splits in two:
//!
//! * [`orb_prover_new`] parses a `.ark` v2 once and returns an opaque handle;
//! * [`orb_prove`] proves against that handle, and can be called repeatedly.
//!
//! The handle owns a `ProvingKey` and its matrices, which is tens of megabytes,
//! so it is freed explicitly by [`orb_prover_free`]. A host that leaks it leaks
//! that much.
//!
//! ## SECURITY: the witness is key material
//!
//! `witness` carries the spending key — that is what a Groth16 witness IS for
//! this circuit. The SDK's `ProofBackend` docs say it plainly: sending it to a
//! server is not a privacy degradation, it is a complete compromise. This layer
//! therefore never logs it, never copies it beyond the field vector it must
//! build, and zeroes that vector before it drops. It cannot stop a caller from
//! doing worse with the bytes it was handed.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_groth16::ProvingKey;
use ark_relations::r1cs::ConstraintMatrices;

use crate::core::field::witness_from_le_bytes;
use crate::format::artifact::read_ark_v2;
use crate::groth16::prove::{prove_circom, public_inputs};
use crate::ProofError;

/// Outcome of every call. Zero is success; a caller checks nothing else.
///
/// The variants exist so a host can tell "you gave me the wrong artifact" from
/// "you gave me the wrong witness" without parsing an error string. The message
/// is still available through [`orb_last_error`], but a UI should branch on
/// this.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrbStatus {
    Ok = 0,
    /// A pointer argument was null, or a length was zero where it may not be.
    NullArgument = 1,
    /// The artifact could not be parsed as a `.ark` v2 file.
    ArtifactInvalid = 2,
    /// The witness was empty, misaligned, or not the circuit's width.
    WitnessInvalid = 3,
    /// Proving itself failed.
    ProveFailed = 4,
    /// A panic was caught at the boundary. A bug in this crate, not a bad input.
    Panic = 5,
}

/// An opaque prover. Holds a parsed proving key and its matrices.
pub struct OrbProver {
    pk: ProvingKey<Bn254>,
    matrices: ConstraintMatrices<Bn254Fr>,
}

/// An owned byte buffer handed to C. Freed with [`orb_buffer_free`].
/// Public fields because C reads them directly — a getter across the boundary
/// would be a function call to look at a struct the caller can already see.
#[repr(C)]
pub struct OrbBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

impl OrbBuffer {
    fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
        }
    }

    fn from_vec(mut v: Vec<u8>) -> Self {
        v.shrink_to_fit();
        let len = v.len();
        let ptr = v.as_mut_ptr();
        std::mem::forget(v);
        Self { ptr, len }
    }
}

/// A library error as the one thing a host can branch on.
///
/// `NumPublicSignals` belongs with the witness errors even though its name says
/// signals: its own docs describe the whole family — a witness that is not the
/// circuit's width, a circuit declaring zero instance variables, an arity that
/// does not match. Every one of them means the witness and the key are for
/// different circuits, which is a caller problem and not a proving failure.
/// Reporting it as `ProveFailed` would send a host looking for a bug in the
/// prover.
fn status_of(err: &ProofError) -> OrbStatus {
    match err {
        ProofError::ProvingKeyParse(_) => OrbStatus::ArtifactInvalid,
        ProofError::WitnessEmpty
        | ProofError::WitnessLength(_)
        | ProofError::WitnessJsonParse(_)
        | ProofError::NumPublicSignals(_) => OrbStatus::WitnessInvalid,
        _ => OrbStatus::ProveFailed,
    }
}

/// Runs `f`, turning a panic into [`OrbStatus::Panic`] rather than unwinding
/// into C.
///
/// `AssertUnwindSafe` is sound here for the same reason it usually is not a
/// smell at an FFI boundary: nothing observable outlives a failed call. The
/// handle is `&OrbProver` (shared, never mutated), and the only owned value in
/// flight is the witness, which is dropped either way.
fn guard<T>(fallback: T, f: impl FnOnce() -> (OrbStatus, T)) -> (OrbStatus, T) {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(_) => (OrbStatus::Panic, fallback),
    }
}

/// Parse a `.ark` v2 artifact into a reusable prover.
///
/// Writes the handle to `out_prover` and returns [`OrbStatus::Ok`]; on failure
/// writes null. Free it with [`orb_prover_free`].
///
/// # Safety
///
/// `artifact` must point to `artifact_len` readable bytes, and `out_prover` to
/// a writable pointer slot. Neither may be null.
#[no_mangle]
pub unsafe extern "C" fn orb_prover_new(
    artifact: *const u8,
    artifact_len: usize,
    out_prover: *mut *mut OrbProver,
) -> OrbStatus {
    if artifact.is_null() || out_prover.is_null() || artifact_len == 0 {
        if !out_prover.is_null() {
            unsafe { *out_prover = ptr::null_mut() };
        }
        return OrbStatus::NullArgument;
    }

    let bytes = unsafe { slice::from_raw_parts(artifact, artifact_len) };
    let (status, handle) = guard(ptr::null_mut(), || match read_ark_v2(bytes) {
        Ok((pk, matrices)) => (
            OrbStatus::Ok,
            Box::into_raw(Box::new(OrbProver { pk, matrices })),
        ),
        Err(e) => (status_of(&e), ptr::null_mut()),
    });

    unsafe { *out_prover = handle };
    status
}

/// Free a prover. Null is a no-op, so a host may call it unconditionally.
///
/// # Safety
///
/// `prover` must have come from [`orb_prover_new`] and must not be used again.
#[no_mangle]
pub unsafe extern "C" fn orb_prover_free(prover: *mut OrbProver) {
    if prover.is_null() {
        return;
    }
    // A drop that unwinds across C is undefined behaviour, so even this is
    // guarded. Dropping arkworks types should not panic; "should not" is not a
    // guarantee worth an app crash.
    let _ = catch_unwind(AssertUnwindSafe(|| drop(unsafe { Box::from_raw(prover) })));
}

/// Prove against a parsed prover.
///
/// `witness` is `n × 32` little-endian bytes — exactly a `.wtns` payload, and
/// exactly what the wasm entry takes. Not decimal strings: the old path
/// serialized 16,928 field elements to text and parsed them back one BigUint at
/// a time.
///
/// On success writes the 128-byte compressed proof to `out_proof` and the
/// public signals, concatenated as 32-byte little-endian values, to
/// `out_signals`. Both must be freed with [`orb_buffer_free`].
///
/// The signal count is not an argument: it is read from the artifact, because
/// it is a property of the circuit. A caller-supplied count that is wrong
/// produces a proof that fails verification with nothing to explain why — a bug
/// this crate has already shipped once.
///
/// # Safety
///
/// `prover` must be live, `witness` must point to `witness_len` readable bytes,
/// and both out-pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn orb_prove(
    prover: *const OrbProver,
    witness: *const u8,
    witness_len: usize,
    out_proof: *mut OrbBuffer,
    out_signals: *mut OrbBuffer,
) -> OrbStatus {
    if prover.is_null() || witness.is_null() || out_proof.is_null() || out_signals.is_null() {
        return OrbStatus::NullArgument;
    }
    unsafe {
        *out_proof = OrbBuffer::empty();
        *out_signals = OrbBuffer::empty();
    }

    let prover = unsafe { &*prover };
    let witness_bytes = unsafe { slice::from_raw_parts(witness, witness_len) };

    let (status, (proof, signals)) = guard((OrbBuffer::empty(), OrbBuffer::empty()), || {
        let mut w = match witness_from_le_bytes(witness_bytes) {
            Ok(w) => w,
            Err(e) => return (status_of(&e), (OrbBuffer::empty(), OrbBuffer::empty())),
        };

        let signals = match public_inputs(&prover.matrices, &w) {
            Ok(s) => s.iter().flat_map(field_to_le_bytes).collect::<Vec<u8>>(),
            Err(e) => {
                zero(&mut w);
                return (status_of(&e), (OrbBuffer::empty(), OrbBuffer::empty()));
            }
        };

        let result = prove_circom(&prover.pk, &prover.matrices, &w);
        // The witness is the spending key. It goes as soon as the proof no
        // longer needs it, whether or not that proof succeeded.
        zero(&mut w);

        match result {
            Ok(proof) => (
                OrbStatus::Ok,
                (OrbBuffer::from_vec(proof), OrbBuffer::from_vec(signals)),
            ),
            Err(e) => (status_of(&e), (OrbBuffer::empty(), OrbBuffer::empty())),
        }
    });

    unsafe {
        *out_proof = proof;
        *out_signals = signals;
    }
    status
}

/// Free a buffer produced by this library. Null or empty is a no-op.
///
/// # Safety
///
/// `buf` must have come from [`orb_prove`] and must not be freed twice.
#[no_mangle]
pub unsafe extern "C" fn orb_buffer_free(buf: OrbBuffer) {
    if buf.ptr.is_null() || buf.len == 0 {
        return;
    }
    drop(unsafe { Vec::from_raw_parts(buf.ptr, buf.len, buf.len) });
}

/// The ABI version of this surface. A host checks it before anything else.
///
/// Bumped when a signature changes in a way a linked binary would not survive.
/// A `.so` and the Kotlin that loads it are shipped in one app but built
/// separately, and a mismatch is otherwise a segfault rather than a message.
#[no_mangle]
pub extern "C" fn orb_abi_version() -> u32 {
    1
}

/// A field element as 32 little-endian bytes — the same encoding the witness
/// arrives in, so a host round-trips signals without a second convention.
fn field_to_le_bytes(f: &Bn254Fr) -> [u8; 32] {
    use ark_ff::{BigInteger, PrimeField};
    let mut out = [0u8; 32];
    let bytes = f.into_bigint().to_bytes_le();
    out[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
    out
}

/// Overwrite a witness in place.
///
/// `write_volatile` so the compiler cannot decide that writing to a vector
/// about to be dropped is dead code — which is exactly what it would conclude.
fn zero(witness: &mut [Bn254Fr]) {
    for element in witness.iter_mut() {
        unsafe { ptr::write_volatile(element, Bn254Fr::from(0u64)) };
    }
}
