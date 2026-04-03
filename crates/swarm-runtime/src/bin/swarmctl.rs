use clap::{ArgGroup, Args, Parser, Subcommand};
use swarm_runtime::control::{
    DefaultControlPlane, IncidentLookupSelector, InvestigationLookupSelector,
    OperatorControlOutput, ReplayLookupSelector, render_output,
};
use swarm_runtime::replay::{DefaultReplayHarness, render_evaluation_report, render_replay_run};

#[derive(Debug, Parser)]
#[command(
    name = "swarmctl",
    about = "Repo-owned operator control surface for Swarm Team Six"
)]
struct Cli {
    #[arg(long, global = true, default_value = "rulesets/default.yaml")]
    config: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/replay-runs")]
    replay_results_dir: std::path::PathBuf,

    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Status,
    Replay(ReplayArgs),
    Investigation(InvestigationArgs),
    Incident(IncidentArgs),
    ReplayRun(ReplayRunArgs),
    ReplayResult(ReplayResultArgs),
    ReplayEvaluate(ReplayEvaluateArgs),
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("selector")
        .required(true)
        .args(["bundle_id", "hunt_id", "receipt_id"]),
))]
struct ReplayArgs {
    #[arg(long)]
    bundle_id: Option<String>,

    #[arg(long)]
    hunt_id: Option<String>,

    #[arg(long)]
    receipt_id: Option<String>,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("selector")
        .required(true)
        .args(["investigation_id", "hunt_id", "receipt_id"]),
))]
struct InvestigationArgs {
    #[arg(long)]
    investigation_id: Option<String>,

    #[arg(long)]
    hunt_id: Option<String>,

    #[arg(long)]
    receipt_id: Option<String>,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("selector")
        .required(true)
        .args(["incident_id", "hunt_id"]),
))]
struct IncidentArgs {
    #[arg(long)]
    incident_id: Option<String>,

    #[arg(long)]
    hunt_id: Option<String>,
}

#[derive(Debug, Args)]
struct ReplayRunArgs {
    #[arg(long)]
    scenario: std::path::PathBuf,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("selector")
        .required(true)
        .args(["run_id", "scenario"]),
))]
struct ReplayResultArgs {
    #[arg(long)]
    run_id: Option<String>,

    #[arg(long)]
    scenario: Option<std::path::PathBuf>,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("selector")
        .required(true)
        .args(["run_id", "scenario"]),
))]
struct ReplayEvaluateArgs {
    #[arg(long)]
    run_id: Option<String>,

    #[arg(long)]
    scenario: Option<std::path::PathBuf>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let plane = DefaultControlPlane::from_path(&cli.config)?;
    let replay_harness = DefaultReplayHarness::from_path(&cli.config, &cli.replay_results_dir)?;

    let output = match cli.command {
        Command::Status => OperatorControlOutput::Status(Box::new(plane.status().await?)),
        Command::Replay(args) => OperatorControlOutput::Replay(Box::new(plane.replay_lookup(
            if let Some(bundle_id) = args.bundle_id.as_deref() {
                ReplayLookupSelector::BundleId(bundle_id)
            } else if let Some(hunt_id) = args.hunt_id.as_deref() {
                ReplayLookupSelector::HuntId(hunt_id)
            } else {
                ReplayLookupSelector::ReceiptId(args.receipt_id.as_deref().expect("receipt id"))
            },
        )?)),
        Command::Investigation(args) => {
            OperatorControlOutput::Investigation(Box::new(plane.investigation_lookup(
                if let Some(investigation_id) = args.investigation_id.as_deref() {
                    InvestigationLookupSelector::InvestigationId(investigation_id)
                } else if let Some(hunt_id) = args.hunt_id.as_deref() {
                    InvestigationLookupSelector::HuntId(hunt_id)
                } else {
                    InvestigationLookupSelector::ReceiptId(
                        args.receipt_id.as_deref().expect("receipt id"),
                    )
                },
            )?))
        }
        Command::Incident(args) => OperatorControlOutput::Incident(Box::new(
            plane.incident_lookup(if let Some(incident_id) = args.incident_id.as_deref() {
                IncidentLookupSelector::IncidentId(incident_id)
            } else {
                IncidentLookupSelector::HuntId(args.hunt_id.as_deref().expect("hunt id"))
            })?,
        )),
        Command::ReplayRun(args) => {
            let run = replay_harness.run_scenario_path(args.scenario).await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&run.bundle)?);
            } else {
                println!("{}", render_replay_run(&run.bundle));
            }
            return Ok(());
        }
        Command::ReplayResult(args) => {
            let maybe_run = if let Some(run_id) = args.run_id.as_deref() {
                replay_harness.load_run(run_id)?
            } else {
                replay_harness.load_run_for_scenario_path(args.scenario.expect("scenario path"))?
            };
            let run = maybe_run.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "offline replay result was not found",
                )
            })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&run.bundle)?);
            } else {
                println!("{}", render_replay_run(&run.bundle));
            }
            return Ok(());
        }
        Command::ReplayEvaluate(args) => {
            let report = if let Some(run_id) = args.run_id.as_deref() {
                let run = replay_harness.load_run(run_id)?.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "offline replay result was not found",
                    )
                })?;
                replay_harness.evaluate_run(&run.bundle)
            } else {
                replay_harness
                    .evaluate_scenario_path(args.scenario.expect("scenario path"))
                    .await?
            };
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", render_evaluation_report(&report));
            }
            if !report.passed {
                std::process::exit(1);
            }
            return Ok(());
        }
    };

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{}", render_output(&output));
    }

    Ok(())
}
