//! Writes the unshield witness as the little-endian bytes `orb_prove` takes.
//!
//! An example rather than a test: it exists so a C or Swift host can be handed
//! a real witness file to prove against, which is the one thing `tests/ffi.rs`
//! cannot check — it calls the surface from Rust, where the header does not
//! exist.
use ark_bn254::Fr as Bn254Fr;
use ark_ff::{BigInteger, PrimeField};
use std::io::Write;

fn main() {
    let path = std::env::args().nth(1).expect("usage: dump_witness <witness.json> <out.wit>");
    let out_path = std::env::args().nth(2).expect("usage: dump_witness <witness.json> <out.wit>");
    let text = std::fs::read_to_string(&path).expect("witness json");
    let doc: serde_json::Value = serde_json::from_str(&text).expect("json");
    let values = doc["witness"].as_array().expect("witness array");

    let mut out = Vec::with_capacity(values.len() * 32);
    for v in values {
        let f: Bn254Fr = v.as_str().expect("decimal string").parse().expect("field element");
        let mut buf = [0u8; 32];
        let le = f.into_bigint().to_bytes_le();
        buf[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);
        out.extend_from_slice(&buf);
    }
    std::fs::File::create(&out_path).unwrap().write_all(&out).unwrap();
    eprintln!("{} elements -> {} bytes", values.len(), out.len());
}
