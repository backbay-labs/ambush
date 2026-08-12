use clap::Parser;
use swarm_runtime_http::cli::args::Cli;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let _tracing = swarm_runtime_http::cli::tracing::init_tracing("swarmctl", cli.otlp_endpoint())?;
    swarm_runtime_http::cli::dispatch::run(cli).await
}
