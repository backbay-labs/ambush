use clap::Parser;
use swarm_runtime::cli::args::Cli;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    swarm_runtime::cli::dispatch::run(cli).await
}
