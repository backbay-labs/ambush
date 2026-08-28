use swarm_governance_witness::{PublicWitnessProcessConfigV1, run_public_witness_process};

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
    let bytes = std::fs::read(path)?;
    let config: PublicWitnessProcessConfigV1 = serde_json::from_slice(&bytes)?;
    if serde_json::to_vec(&config)? != bytes {
        return Err("configuration must be canonical JSON".into());
    }
    run_public_witness_process(config).await?;
    Ok(())
}
