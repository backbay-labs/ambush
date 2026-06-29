//! `ambush-verify <bundle-dir>` — the standalone, offline attestation verifier.
//!
//! Re-derives every artifact hash, verifies the detached DSSE signature against keys pinned in
//! BOTH the bundle's own trust-roots AND the `AMBUSH_TRUSTED_SIGNER_KEYS` env (comma-separated hex
//! public keys), and checks the receipt-coverage matrix, claims, and negative cases. Prints a
//! stable JSON outcome to stdout and exits with the 6-bucket code (0 = verified). A client runs
//! this on a clean machine without trusting Ambush.

use std::collections::BTreeSet;
use std::path::PathBuf;

use swarm_attest::{VerifyOutcome, verify_bundle};

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(bundle_dir) = args.next() else {
        eprintln!("usage: ambush-verify <bundle-dir>");
        eprintln!("env:   AMBUSH_TRUSTED_SIGNER_KEYS=<hex,hex,...>  (out-of-band pinned signer keys)");
        std::process::exit(2);
    };
    let root = PathBuf::from(bundle_dir);

    let trusted: BTreeSet<String> = std::env::var("AMBUSH_TRUSTED_SIGNER_KEYS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    match verify_bundle(&root, &trusted) {
        Ok(outcome) => {
            print_outcome(&outcome);
            std::process::exit(0);
        }
        Err(err) => {
            print_outcome(&VerifyOutcome {
                ok: false,
                exit_code: err.exit_code(),
                error_code: Some(err.code().to_string()),
                error: Some(err.to_string()),
                bundle_id: String::new(),
                artifacts_verified: 0,
                signatures_verified: 0,
                claims_verified: 0,
                negative_cases_checked: 0,
            });
            eprintln!("VERIFY FAILED [{}]: {err}", err.code());
            std::process::exit(err.exit_code());
        }
    }
}

fn print_outcome(outcome: &VerifyOutcome) {
    match serde_json::to_string_pretty(outcome) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("failed to serialize outcome: {e}"),
    }
}
