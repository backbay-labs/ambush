#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use swarm_core::config::SwarmConfig;
use swarm_runtime::config::load_config;
use swarm_runtime::kitten_agent::{EvolutionBenchmarkRequest, run_bounded_evolution_benchmark};
use sysinfo::System;
use uuid::Uuid;

type BenchError = Box<dyn Error + Send + Sync>;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn default_config_path() -> PathBuf {
    repo_root().join("rulesets/default.yaml")
}

fn default_baseline_experiment_path() -> PathBuf {
    repo_root().join("experiments/office-baseline-control.yaml")
}

fn benchmark_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "swarm-runtime-evolution-benchmark-{}",
        Uuid::new_v4()
    ))
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn copy_dir_recursive(source: &Path, destination: &Path) -> Result<(), BenchError> {
    if !source.exists() {
        return Ok(());
    }

    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let entry_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&entry_path, &destination_path)?;
        } else {
            fs::copy(&entry_path, &destination_path)?;
        }
    }
    Ok(())
}

fn stage_baseline_experiment(source: &Path, root: &Path) -> Result<PathBuf, BenchError> {
    let experiments_dir = root.join("experiments");
    fs::create_dir_all(&experiments_dir)?;
    let destination = experiments_dir.join(source.file_name().ok_or_else(|| {
        format!(
            "baseline experiment path `{}` has no filename",
            source.display()
        )
    })?);
    fs::copy(source, &destination)?;
    if let Some(source_root) = source.parent().and_then(Path::parent) {
        copy_dir_recursive(
            &source_root.join("scenario-suites"),
            &root.join("scenario-suites"),
        )?;
        copy_dir_recursive(
            &source_root.join("verifications"),
            &root.join("verifications"),
        )?;
        copy_dir_recursive(&source_root.join("scenarios"), &root.join("scenarios"))?;
    }
    Ok(destination)
}

fn configure_paths(config: &mut SwarmConfig, root: &Path) {
    config.evolution.enabled = true;
    config.evolution.max_variants_per_cycle = env_usize("STS_EVO_BENCH_MAX_VARIANTS", 2).max(1);
    config.evolution.shortlist_count = 1;
    config.evolution.population_size = env_usize("STS_EVO_BENCH_POPULATION_SIZE", 8).max(1);
    config.evolution.pareto_tournament_size =
        env_usize("STS_EVO_BENCH_PARETO_TOURNAMENT_SIZE", 2).max(1);
    config.evolution.paths.replay_results_dir = root.join("replay-runs").display().to_string();
    config.evolution.paths.experiment_results_dir =
        root.join("experiments-data").display().to_string();
    config.evolution.paths.verification_results_dir =
        root.join("verifications").display().to_string();
    config.evolution.paths.shadow_results_dir = root.join("shadows").display().to_string();
    config.evolution.paths.strategy_memory_results_dir =
        root.join("strategy-memory").display().to_string();
    config.evolution.paths.strategy_scorecard_results_dir =
        root.join("strategy-scorecards").display().to_string();
    config.evolution.paths.evolution_proof_results_dir =
        root.join("evolution-proofs").display().to_string();
    config.evolution.paths.evolution_queue_results_dir =
        root.join("evolution-queue").display().to_string();
    config.evolution.paths.evolution_selection_results_dir =
        root.join("evolution-selections").display().to_string();
    config.evolution.paths.evolution_bridge_results_dir = root
        .join("evolution-selection-bridges")
        .display()
        .to_string();
    config.evolution.paths.evolution_handoff_results_dir =
        root.join("evolution-handoffs").display().to_string();
    config.evolution.paths.evolution_pressure_results_dir =
        root.join("evolution-pressures").display().to_string();
    config.evolution.paths.evolution_draft_results_dir =
        root.join("evolution-drafts").display().to_string();
    config.evolution.paths.evolution_draft_promotion_results_dir = root
        .join("evolution-draft-promotions")
        .display()
        .to_string();
    config.evolution.paths.evolution_materialization_results_dir = root
        .join("evolution-materializations")
        .display()
        .to_string();
    config.evolution.paths.evolution_validation_results_dir = root
        .join("evolution-validation-bundles")
        .display()
        .to_string();
    config.evolution.paths.evolution_reconciliation_results_dir =
        root.join("evolution-reconciliations").display().to_string();
    config.evolution.paths.evolution_mutation_results_dir =
        root.join("evolution-mutations").display().to_string();
    config
        .evolution
        .paths
        .evolution_mutation_materialization_batch_results_dir = root
        .join("evolution-mutation-materialization-batches")
        .display()
        .to_string();
    config
        .evolution
        .paths
        .evolution_mutation_validation_batch_results_dir = root
        .join("evolution-mutation-validation-batches")
        .display()
        .to_string();
    config.evolution.paths.evolution_ranking_results_dir =
        root.join("evolution-rankings").display().to_string();
    config.evolution.paths.evolution_population_results_dir =
        root.join("evolution-population").display().to_string();
    config.evolution.paths.canary_results_dir = root.join("canaries").display().to_string();
}

#[derive(Debug)]
struct HostProfile {
    os_name: String,
    os_version: String,
    kernel_version: String,
    cpu_cores: usize,
    total_memory_bytes: u64,
}

impl HostProfile {
    fn detect() -> Self {
        let mut system = System::new_all();
        system.refresh_memory();
        Self {
            os_name: System::name().unwrap_or_else(|| "unknown".to_string()),
            os_version: System::os_version().unwrap_or_else(|| "unknown".to_string()),
            kernel_version: System::kernel_version().unwrap_or_else(|| "unknown".to_string()),
            cpu_cores: system.cpus().len(),
            total_memory_bytes: system.total_memory(),
        }
    }

    fn total_memory_gib(&self) -> f64 {
        self.total_memory_bytes as f64 / 1024_f64.powi(3)
    }
}

#[tokio::main]
async fn main() -> Result<(), BenchError> {
    let config_path = default_config_path();
    let mut config = load_config(&config_path)?;
    let benchmark_root = benchmark_root();
    configure_paths(&mut config, &benchmark_root);

    let generation_count = env_usize("STS_EVO_BENCH_GENERATIONS", 3).max(1);
    let source_baseline_experiment_path = std::env::var("STS_EVO_BENCH_BASELINE_EXPERIMENT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_baseline_experiment_path());
    let baseline_experiment_path =
        stage_baseline_experiment(&source_baseline_experiment_path, &benchmark_root)?;
    let label = std::env::var("STS_EVO_BENCH_LABEL")
        .unwrap_or_else(|_| "office_baseline_control".to_string());
    let benchmark_id = format!("evolution-benchmark-{}", Uuid::new_v4());
    let host = HostProfile::detect();

    let run = run_bounded_evolution_benchmark(
        &config_path,
        config.clone(),
        EvolutionBenchmarkRequest {
            benchmark_id,
            label: label.clone(),
            generation_count,
            baseline_experiment_path,
        },
    )
    .await?;

    println!("# Evolution Benchmark");
    println!();
    println!(
        "**Reference host:** {}, {} (kernel {}), {} CPU cores, {:.1} GiB RAM",
        host.os_name,
        host.os_version,
        host.kernel_version,
        host.cpu_cores,
        host.total_memory_gib()
    );
    println!();
    println!("## Benchmark Scope");
    println!();
    println!("- benchmark id: `{}`", run.report.benchmark_id);
    println!("- label: `{}`", run.report.label);
    println!("- detector: `{}`", run.report.detector);
    println!(
        "- baseline experiment: `{}`",
        run.report.baseline_experiment_path
    );
    println!(
        "- generations: `{}` requested, `{}` completed",
        run.report.requested_generation_count, run.report.completed_generation_count
    );
    println!(
        "- max variants per generation: `{}`",
        run.report.max_variants_per_generation
    );
    println!(
        "- tracked corpus: `{}@{}`",
        run.report.corpus_suite_name, run.report.corpus_version
    );
    println!("- isolated artifact root: `{}`", benchmark_root.display());
    if let Some(baseline) = &run.report.baseline {
        println!(
            "- staged baseline: `{}` | measured fitness `{:.3}` | catch-rate `{:.3}` | fp-rate `{:.3}` | latency fitness `{:.3}`",
            baseline.strategy_id,
            baseline.measured_fitness,
            baseline.catch_rate,
            baseline.false_positive_rate,
            baseline.latency_fitness
        );
    }
    println!();
    println!("## Results");
    println!();
    println!(
        "| Gen | Leader Gen | Leader Strategy | Measured Fitness | Delta Prev | Delta First | Delta Baseline | Catch Rate | FP Rate | Latency Fitness |"
    );
    println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
    for generation in &run.report.generations {
        let delta_baseline = run
            .report
            .baseline
            .as_ref()
            .map(|baseline| {
                format!(
                    "{:.3}",
                    generation.leader_measured_fitness - baseline.measured_fitness
                )
            })
            .unwrap_or_else(|| "n/a".to_string());
        println!(
            "| {} | {} | `{}` | {:.3} | {} | {} | {} | {:.3} | {:.3} | {:.3} |",
            generation.generation,
            generation.leader_generation,
            generation.leader_strategy_id,
            generation.leader_measured_fitness,
            generation
                .delta_from_previous
                .as_ref()
                .map(|delta| format!("{:.3}", delta.measured_fitness))
                .unwrap_or_else(|| "n/a".to_string()),
            generation
                .delta_from_first
                .as_ref()
                .map(|delta| format!("{:.3}", delta.measured_fitness))
                .unwrap_or_else(|| "n/a".to_string()),
            delta_baseline,
            generation.leader_catch_rate,
            generation.leader_false_positive_rate,
            generation.leader_latency_fitness,
        );
    }
    println!();
    println!("## Notes");
    println!();
    println!("{}", run.report.notes);

    Ok(())
}
