//! Pack a snarkjs `.zkey` into the `.ark` v2 artifact a wallet proves with.
//!
//! This is the *proving* side. Its counterpart is `pack-verifying-key`, which
//! packs the verifying key the chain checks proofs against — same trusted setup,
//! opposite ends of it.
//!
//! A v1 `.ark` holds only the proving key, which is not enough to prove: the
//! constraint matrices `read_zkey` returns beside it were thrown away. This
//! writes both into one file, so a device fetches one artifact and verifies one
//! hash.
//!
//! Usage:
//!   pack-proving-key <input.zkey> [output.ark]
//!
//! With no output path, replaces the `.zkey` extension with `.ark`.

#[path = "common/mod.rs"]
mod common;

use common::die;
use groth16_proofs::{read_zkey, write_ark_v2};
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 || args.len() > 3 {
        die("Usage: pack-proving-key <input.zkey> [output.ark]");
    }
    let input = PathBuf::from(&args[1]);
    let output = args
        .get(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| input.with_extension("ark"));

    eprintln!("Reading {}…", input.display());
    let file = File::open(&input)
        .unwrap_or_else(|e| die(&format!("cannot open {}: {e}", input.display())));
    let (pk, matrices) = read_zkey(&mut BufReader::new(file))
        .unwrap_or_else(|e| die(&format!("read_zkey failed: {e}")));
    eprintln!(
        "  {} constraints · {} instance variables",
        matrices.num_constraints, matrices.num_instance_variables
    );

    let blob =
        write_ark_v2(&pk, &matrices).unwrap_or_else(|e| die(&format!("serialize failed: {e}")));
    std::fs::write(&output, &blob)
        .unwrap_or_else(|e| die(&format!("cannot write {}: {e}", output.display())));

    let mb = |n: u64| n as f64 / 1_048_576.0;
    let zkey_len = std::fs::metadata(&input).map(|m| m.len()).unwrap_or(0);
    eprintln!("\n✓ {}", output.display());
    eprintln!("  .zkey  {:.2} MB", mb(zkey_len));
    eprintln!(
        "  .ark   {:.2} MB  ({:.0}% of the zkey)",
        mb(blob.len() as u64),
        blob.len() as f64 / zkey_len.max(1) as f64 * 100.0
    );
}
