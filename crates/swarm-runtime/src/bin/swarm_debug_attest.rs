#![forbid(unsafe_code)]

#[cfg(debug_assertions)]
use anyhow::Context;
#[cfg(debug_assertions)]
use clap::Parser;
#[cfg(debug_assertions)]
use std::path::PathBuf;

#[cfg(debug_assertions)]
#[derive(Debug, Parser)]
struct Cli {
    #[arg(long)]
    binary: PathBuf,
    #[arg(long)]
    config: Vec<PathBuf>,
}

fn main() -> Result<(), anyhow::Error> {
    #[cfg(not(debug_assertions))]
    {
        anyhow::bail!("swarm_debug_attest is only available in debug builds");
    }

    #[cfg(debug_assertions)]
    {
        let cli = Cli::parse();
        swarm_runtime::startup_attestation::write_debug_test_binary_attestation(&cli.binary)
            .with_context(|| {
                format!(
                    "failed to write debug binary attestation for `{}`",
                    cli.binary.display()
                )
            })?;
        for config in &cli.config {
            swarm_runtime::config::write_debug_test_config_signature(config).with_context(
                || {
                    format!(
                        "failed to write debug config signature for `{}`",
                        config.display()
                    )
                },
            )?;
        }
    }

    Ok(())
}
