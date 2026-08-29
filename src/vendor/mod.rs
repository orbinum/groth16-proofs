//! Vendored from [ark-circom](https://github.com/arkworks-rs/circom-compat) 0.5.0.
//!
//! Copyright (c) 2021 Georgios Konstantopoulos, licensed MIT OR Apache-2.0.
//! This crate takes it under **MIT**, one of its own two options. MIT is
//! GPL-compatible, so these files can sit inside a GPL-3.0-or-later work: the
//! combined crate is distributed under the GPL, and MIT's only condition — that
//! the copyright notice travel with the code — is met by the header above each
//! file. Full text:
//! <https://github.com/arkworks-rs/circom-compat/blob/master/LICENSE-MIT>.
//!
//! Taking it under Apache-2.0 instead, as this crate did while it was itself
//! dual-licensed, would not work now: Apache-2.0 is one-way compatible with
//! GPL-3 but adds patent terms the GPL does not, so MIT is the cleaner of the
//! two options for a GPL-only work.
//!
//! # Why vendored rather than depended on
//!
//! Two things here are needed to prove a Circom circuit: `CircomReduction` (the
//! QAP reduction snarkjs uses) and `read_zkey` (which yields the proving key and
//! the constraint matrices together). Neither touches WebAssembly.
//!
//! But ark-circom's default features pull in **wasmer**, a complete WASM runtime,
//! because its `WitnessCalculator` executes the circom-emitted `.wasm`. This
//! crate never calls that — it takes a witness that has already been computed —
//! and the whole point of the native prover is to get off WASM on a platform that
//! has no runtime for it. Carrying an interpreter for a language we are trying to
//! leave, into a binary where every megabyte is an app-store download, is not a
//! trade worth making for 475 lines.
//!
//! Turning ark-circom's default features off is not an alternative: `wasmer` is
//! not behind an optional feature there, and disabling defaults breaks its build.
//!
//! # Changes from upstream
//!
//! `zkey.rs` has its `#[cfg(test)]` module removed — those tests are the only
//! place in the file that referenced wasmer, and they depend on test vectors that
//! do not ship in the published crate. Everything else is byte-identical, so a
//! future upstream fix can be re-vendored by copying the file again.
//!
//! `qap.rs` is unmodified.

pub(crate) mod qap;
pub(crate) mod zkey;
