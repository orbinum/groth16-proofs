//! The bottom layer: types every other module needs and that need nothing back.
//!
//! [`error`] holds the crate's single error type; [`field`] converts BN254
//! elements between the encodings that cross this crate's borders. Neither
//! knows what a proof is.
//!
//! Nothing here may import from [`format`](crate::format), [`groth16`](crate::groth16)
//! or [`vendor`](crate::vendor) — that direction is what keeps the dependency
//! graph a line rather than a knot, and it is the one rule this split exists to
//! make visible.

pub mod error;
pub mod field;
