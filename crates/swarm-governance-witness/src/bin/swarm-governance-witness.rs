use swarm_governance_witness::{load_public_witness_process_config, run_public_witness_process};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os();
    let _binary = arguments.next();
    let path = arguments
        .next()
        .ok_or("exactly one configuration path is required")?;
    if arguments.next().is_some() {
        return Err("exactly one configuration path is required".into());
    }
    let config = load_public_witness_process_config(path)?;
    run_public_witness_process(config).await?;
    Ok(())
}
