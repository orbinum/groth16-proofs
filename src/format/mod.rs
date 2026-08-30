//! Byte and text formats that arrive from elsewhere.
//!
//! Everything here is a boundary: a file written by another tool, or bytes
//! another implementation has to agree with. [`artifact`] is the `.ark` v2
//! container this crate defines; [`snarkjs`] reads and writes what snarkjs
//! produces.
//!
//! The two have opposite risk profiles and that is why they sit together. A
//! format we own can be changed; a format we merely have to match cannot, so a
//! disagreement shows up as a proof that never verifies rather than as a parse
//! error. Both are consensus-relevant: the chain identifies a verifying key by
//! the hash of the exact bytes [`snarkjs::pack_snarkjs_vk`] emits.
//!
//! Uses [`core`](crate::core) and nothing else. In particular not
//! [`groth16`](crate::groth16): parsing a key is not proving with it.

pub mod artifact;
pub mod snarkjs;
