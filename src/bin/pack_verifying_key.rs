//! Pack a snarkjs verifying key into the arkworks binary the chain stores.
//!
//! This is the *verification* side. Its output is what gets registered on-chain
//! as `key_data`, and its blake2_256 is the `vk_hash` a manifest publishes — so
//! the runtime deserializer expects exactly these bytes and never the JSON.
//!
//! Its counterpart is `pack-proving-key`, which packs the other half of a
//! trusted setup: the key a wallet needs to *make* a proof.
//!
//! Usage:
//!   pack-verifying-key <input.json> [output.bin]
//!
//! If output is omitted, replaces .json with .bin.
//! Outputs the byte count to stderr.
//!
//! The conversion itself is [`groth16_proofs::pack_snarkjs_vk`]. It lives in the
//! library because the byte layout is consensus-relevant — a test that has to
//! spawn a process to check it will not be written often enough.

#[path = "common/mod.rs"]
mod common;

use groth16_proofs::pack_snarkjs_vk;

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 || args.len() > 3 {
        return Err("Usage: pack-verifying-key <input.json> [output.bin]".into());
    }

    let in_path = &args[1];
    let out_path = args.get(2).cloned().unwrap_or_else(|| {
        in_path
            .strip_suffix(".json")
            .map_or_else(|| format!("{in_path}.bin"), |s| format!("{s}.bin"))
    });

    let json =
        std::fs::read_to_string(in_path).map_err(|e| format!("cannot read {in_path}: {e}"))?;
    let bytes = pack_snarkjs_vk(&json).map_err(|e| format!("{in_path}: {e}"))?;
    std::fs::write(&out_path, &bytes).map_err(|e| format!("cannot write {out_path}: {e}"))?;

    eprintln!(
        "Converted {} → {} ({} bytes JSON → {} bytes binary)",
        in_path,
        out_path,
        json.len(),
        bytes.len()
    );
    Ok(())
}

fn main() {
    common::main_or_die(run);
}
