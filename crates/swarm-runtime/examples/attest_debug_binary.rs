//! Write the debug startup-attestation sidecar for a locally built binary.
//!
//! `swarm_detect --serve` verifies a signed statement beside its own
//! executable and refuses to start without one. A release build ships that
//! statement; a `cargo build` does not, so the local walking skeleton in
//! `docs/PERCH-DEV.md` needs this one-shot helper. It signs with the in-repo
//! DEBUG key, which a release daemon does not trust.
//!
//! ```sh
//! cargo run -p swarm-runtime --example attest_debug_binary -- ./target/debug/swarm_detect
//! ```
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(argument) = std::env::args().nth(1) else {
        return Err("usage: attest_debug_binary <path-to-swarm_detect>".into());
    };
    let path = PathBuf::from(argument);
    swarm_runtime::startup_attestation::write_debug_test_binary_attestation(&path)?;
    let sidecar = swarm_runtime::startup_attestation::binary_attestation_sidecar_path(&path);
    println!("wrote {}", sidecar.display());
    Ok(())
}
