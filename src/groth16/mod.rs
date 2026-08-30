//! The protocol itself: making a proof and checking one.
//!
//! Split in two because the halves have genuinely different concerns.
//! [`prove`] is entirely about the QAP reduction — Circom's, not arkworks'
//! default, a distinction that cost this crate two major versions of
//! unverifiable proofs. [`verify`] does not care which reduction produced the
//! proof; the pairing check reads the proof and the key and nothing else.
//!
//! Keeping `verify_proof` out of `prove.rs` means the reduction reasoning lives
//! in exactly the module it governs.
//!
//! Uses [`core`](crate::core) and `vendor`. Notably *not*
//! [`format`](crate::format): [`prove::prove_circom`] takes a proving key and
//! matrices that are already deserialized, so it never learns what a `.ark`
//! file is. That is what lets a caller hold one key across many proofs instead
//! of re-reading it per transaction, and it is why the two layers are
//! genuinely independent rather than merely filed apart.

pub mod prove;
pub mod verify;
