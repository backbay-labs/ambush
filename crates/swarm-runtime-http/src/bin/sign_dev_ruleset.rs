//! Signs a development ruleset with the in-repo DEBUG key.
//!
//! Writes `<ruleset>.sig.json` beside the given YAML using the same debug trust
//! root `swarmctl init` uses in a debug build. A `--release` daemon refuses the
//! resulting signature, because the debug trust root is compiled in under
//! `#[cfg(debug_assertions)]` only; that refusal is the intended behaviour, and
//! production signs its own rulesets. In a release build this binary refuses to
//! run for the same reason rather than pretending to sign.
//!
//! ```text
//! cargo run -p swarm-runtime-http --bin sign_dev_ruleset -- rulesets/perch-dev.yaml
//! ```

const USAGE: &str = "usage: sign_dev_ruleset <ruleset.yaml>";

#[cfg(debug_assertions)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or(USAGE)?;
    swarm_runtime::config::write_debug_test_config_signature(&path)?;
    println!("wrote {path}.sig.json");
    Ok(())
}

#[cfg(not(debug_assertions))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _path = std::env::args().nth(1).ok_or(USAGE)?;
    Err(
        "sign_dev_ruleset only exists in debug builds: the debug config-signing \
         key is compiled out of release binaries, and a release daemon refuses \
         signatures made with it. Sign production rulesets with the production key."
            .into(),
    )
}
