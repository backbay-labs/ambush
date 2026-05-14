use clap::Parser;
use std::path::PathBuf;
use swarm_runtime::config::load_config;
use swarm_runtime::evasion_coverage::{
    resolve_repo_root, summarize_repo_adversary_emulation_coverage,
};

#[derive(Debug, Parser)]
#[command(
    name = "generate_adversary_emulation_report",
    about = "Generate the repo-owned adversary emulation coverage report"
)]
struct Args {
    #[arg(long, default_value = "rulesets/default.yaml")]
    config: PathBuf,

    #[arg(long)]
    output: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config = load_config(&args.config)?;
    let repo_root = resolve_repo_root(&args.config);
    let report = summarize_repo_adversary_emulation_coverage(&config, &repo_root)?;
    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&args.output, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", args.output.display());
    Ok(())
}
