//! Helpers shared by the four binaries.
//!
//! Included with `#[path]` rather than being a library module: this is CLI
//! plumbing, and a library that exports an exit-the-process function invites a
//! caller to use it from somewhere that must not exit.
//!
//! Each binary compiles its own copy, so anything it does not call is dead code
//! from that binary's point of view — hence the blanket allow rather than a
//! per-item one.

#![allow(dead_code)]

/// Print a message and exit non-zero.
///
/// The four binaries had three conventions between them — `panic!`, two
/// byte-identical copies of this function, and a `run() -> Result`. A panic
/// prints a backtrace notice and an "internal error" framing for what is
/// usually a missing file, so the copies were the better of the two; this is
/// the single copy.
pub fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(1);
}

/// Run a fallible entry point, exiting non-zero with its message on failure.
///
/// Lets each binary keep its logic in a `run() -> Result<_, String>` that a
/// test can call directly, with `main` reduced to this one line.
pub fn main_or_die(run: impl FnOnce() -> Result<(), String>) {
    if let Err(msg) = run() {
        die(&msg);
    }
}
