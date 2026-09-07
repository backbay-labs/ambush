//! WHY: swarmctl's `red-swarm plan` and `red-swarm score` verbs (OPFOR-04,
//! ATKSCORE-04, SC 4).
//!
//! Phase 288 built a pure red genome planner in `swarm_runtime::red_swarm`. This
//! module exposes it as a CLI verb that prints a [`RedPlan`] as JSON, with the
//! `determinism` record at the top level and the graph fingerprint rendered as
//! hex, so a plan is reproducible from its own bytes. The command REFUSES to run
//! without `--virtual-clock-start-ms`: a plan's bytes must never depend on the
//! wall clock, so the clock origin is an explicit input, never `now()`. Nothing
//! here reads a clock or names a response-authority type; it plans and prints.
//!
//! The planning path is split from the process-exit shell on purpose: [`build_plan`]
//! is a pure function returning a typed error (so the refusal is unit-testable
//! without spawning a subprocess), and [`run`] is the thin shell that turns a
//! missing clock into exit 1 and prints the plan.
//!
//! Phase 289 adds `score` alongside `plan`, in the same shape: [`build_score`]
//! plans exactly as [`build_plan`] does, runs the plan through a
//! [`swarm_runtime::red_swarm::budget::StealthBudget`], and scores the
//! *budgeted* plan -- the steps actually emitted, not the ones the planner
//! merely proposed -- against a measured
//! [`swarm_runtime::evasion_coverage::EvasionCoverageSnapshot`] with
//! [`swarm_runtime::red_swarm::scoring::AttackScorer`]. Scoring the emitted
//! plan closes the loophole a red genome would otherwise have: proposing
//! extra loud steps it expects the budget to truncate anyway cannot buy
//! fitness, because a truncated step never reaches the scorer and the
//! truncation itself has already cost `stealth`. `score` refuses on the same
//! missing-clock condition as `plan`, for the same reason.

use clap::{Args, Subcommand};
use serde::Serialize;
use std::path::{Path, PathBuf};
use swarm_runtime::evasion_coverage::EvasionCoverageSnapshot;
use swarm_runtime::red_swarm::budget::{BudgetOutcome, StealthBudget};
use swarm_runtime::red_swarm::scoring::{AttackFitness, AttackScorer};
use swarm_runtime::red_swarm::{
    CampaignParams, Determinism, GeneStep, RedGenome, RedPlan, RedSwarmError, TargetGraph,
};

/// The default evasion technique catalog, repository-relative. The operator runs
/// swarmctl from the repo root (like every other subcommand's `--config`), so a
/// relative default resolves against the repo the plan is drawn for.
const DEFAULT_CATALOG: &str = "rulesets/evasion/attack-technique-catalog.yaml";

/// The default directory holding scenario suites. When no `--suite` is given the
/// command plans against every `*.yaml` in here.
const DEFAULT_SUITES_DIR: &str = "scenario-suites";

/// The refusal message when `--virtual-clock-start-ms` is omitted (SC 4). Kept as
/// a constant so the handler and the test that pins it share one source of truth.
const MISSING_CLOCK_MESSAGE: &str =
    "`--virtual-clock-start-ms` is required: a plan's bytes must not depend on the wall clock";

/// `red-swarm <subcommand>`. Mirrors the `evolution` group's Args/Subcommand shape.
#[derive(Debug, Args)]
pub(crate) struct RedSwarmArgs {
    #[command(subcommand)]
    command: RedSwarmCommand,
}

#[derive(Debug, Subcommand)]
enum RedSwarmCommand {
    /// Plan one generation of one campaign against the target graph.
    Plan(RedSwarmPlanArgs),
    /// Plan, budget, and score one generation of one campaign against a
    /// measured detector coverage snapshot (ATKSCORE-04).
    Score(RedSwarmScoreArgs),
}

/// `red-swarm plan` arguments. Field names kebab-case into flags, so
/// `virtual_clock_start_ms` is `--virtual-clock-start-ms` and so on.
#[derive(Debug, Args)]
struct RedSwarmPlanArgs {
    /// The base seed. The effective RNG seed is `seed ^ generation` (the genome
    /// rotates the generation into the high half before the xor).
    #[arg(long)]
    seed: u64,

    /// The generation index; shifts the whole PRNG stream.
    #[arg(long)]
    generation: u32,

    /// The campaign name, copied onto the plan.
    #[arg(long)]
    campaign: String,

    /// The evasion technique catalog. Defaults to the repository catalog.
    #[arg(long)]
    catalog: Option<PathBuf>,

    /// A scenario suite to plan against; repeatable. Defaults to every
    /// `scenario-suites/*.yaml`.
    #[arg(long = "suite")]
    suites: Vec<PathBuf>,

    /// The virtual clock origin (ms) that step offsets are measured from.
    /// REQUIRED: a plan's bytes must not depend on the wall clock (SC 4), so this
    /// is never defaulted to `now()` -- omitting it is refused.
    #[arg(long)]
    virtual_clock_start_ms: Option<i64>,

    /// Override the interleaved step cap (the genome's default is 24).
    #[arg(long)]
    max_steps: Option<u16>,
}

/// `red-swarm score` arguments. Shares `plan`'s campaign/graph fields (see
/// [`plan_args_for_score`], which builds a [`RedSwarmPlanArgs`] from them so
/// [`build_plan`] can be reused unchanged) and adds the coverage snapshot to
/// score against and the [`StealthBudget`] overrides.
#[derive(Debug, Args)]
struct RedSwarmScoreArgs {
    /// The base seed. The effective RNG seed is `seed ^ generation` (the genome
    /// rotates the generation into the high half before the xor).
    #[arg(long)]
    seed: u64,

    /// The generation index; shifts the whole PRNG stream.
    #[arg(long)]
    generation: u32,

    /// The campaign name, copied onto the plan.
    #[arg(long)]
    campaign: String,

    /// The measured detector coverage snapshot to score against: a JSON file
    /// that deserializes to an evasion coverage snapshot. A missing or
    /// malformed file is an input error (exit 1), not a panic.
    #[arg(long)]
    coverage: PathBuf,

    /// The evasion technique catalog. Defaults to the repository catalog.
    #[arg(long)]
    catalog: Option<PathBuf>,

    /// A scenario suite to plan against; repeatable. Defaults to every
    /// `scenario-suites/*.yaml`.
    #[arg(long = "suite")]
    suites: Vec<PathBuf>,

    /// The virtual clock origin (ms) that step offsets are measured from.
    /// REQUIRED: a plan's bytes must not depend on the wall clock (SC 4), so this
    /// is never defaulted to `now()` -- omitting it is refused.
    #[arg(long)]
    virtual_clock_start_ms: Option<i64>,

    /// Override the stealth budget's cap on the running sum of emitted steps'
    /// event counts. Defaults to the budget's own default cap.
    #[arg(long)]
    max_events: Option<u32>,

    /// Override the stealth budget's cap on how many distinct host slots the
    /// plan may bind. Defaults to the budget's own default cap.
    #[arg(long)]
    max_hosts: Option<u8>,

    /// Override the stealth budget's cap on how many emitted steps may name
    /// the same technique. Defaults to the budget's own default cap.
    #[arg(long)]
    max_technique_repeats: Option<u8>,
}

/// A failure of the planning path, kept separate from the process-exit shell so
/// the refusal and the planner are unit-testable without a subprocess.
#[derive(Debug)]
enum PlanCommandError {
    /// `--virtual-clock-start-ms` was omitted. The shell turns this into exit 1
    /// and [`MISSING_CLOCK_MESSAGE`], never a default-to-now (SC 4).
    MissingVirtualClock,
    /// The default suite glob could not read `scenario-suites/`. Boxed to keep
    /// this error (and the `Result`s that carry it) small.
    Io(Box<std::io::Error>),
    /// The target graph could not be built from the catalog and suites. Boxed for
    /// the same reason: `RedSwarmError` is large.
    Graph(Box<RedSwarmError>),
}

/// A failure of the scoring path, kept separate from the process-exit shell for
/// the same reason [`PlanCommandError`] is: the refusal and the failure modes
/// are unit-testable without a subprocess.
#[derive(Debug)]
enum ScoreCommandError {
    /// `--virtual-clock-start-ms` was omitted. Forwarded from [`build_plan`]
    /// (via [`PlanCommandError`]) unchanged, so `score` refuses with the exact
    /// same message as `plan` (SC 4).
    MissingVirtualClock,
    /// The default suite glob could not read `scenario-suites/`. Forwarded
    /// from [`build_plan`] unchanged.
    Io(Box<std::io::Error>),
    /// The target graph could not be built from the catalog and suites.
    /// Forwarded from [`build_plan`] unchanged.
    Graph(Box<RedSwarmError>),
    /// The `--coverage` file could not be read.
    CoverageIo(Box<std::io::Error>),
    /// The `--coverage` file could not be parsed as an
    /// [`EvasionCoverageSnapshot`].
    CoverageParse(Box<serde_json::Error>),
}

/// Forwards [`build_plan`]'s error unchanged, so `score`'s plan-building step
/// can reuse [`build_plan`] itself with `?` rather than re-implementing
/// catalog/suite loading or its error handling.
impl From<PlanCommandError> for ScoreCommandError {
    fn from(error: PlanCommandError) -> Self {
        match error {
            PlanCommandError::MissingVirtualClock => ScoreCommandError::MissingVirtualClock,
            PlanCommandError::Io(error) => ScoreCommandError::Io(error),
            PlanCommandError::Graph(error) => ScoreCommandError::Graph(error),
        }
    }
}

/// The suites to plan against. An explicit `--suite` list is used as given;
/// otherwise every `scenario-suites/*.yaml`, sorted, so the default graph (and
/// thus the plan's bytes) does not depend on the directory's read order.
fn resolve_suites(explicit: &[PathBuf]) -> Result<Vec<PathBuf>, PlanCommandError> {
    if !explicit.is_empty() {
        return Ok(explicit.to_vec());
    }
    let mut suites = Vec::new();
    let read_dir = std::fs::read_dir(DEFAULT_SUITES_DIR)
        .map_err(|error| PlanCommandError::Io(Box::new(error)))?;
    for entry in read_dir {
        let path = entry
            .map_err(|error| PlanCommandError::Io(Box::new(error)))?
            .path();
        if path.extension().is_some_and(|ext| ext == "yaml") {
            suites.push(path);
        }
    }
    suites.sort();
    Ok(suites)
}

/// Build the plan for `plan` args. Pure apart from reading the catalog and suites
/// off disk: no clock, no globals. The clock check is first, so a missing clock is
/// refused before any file is touched (SC 4).
fn build_plan(args: &RedSwarmPlanArgs) -> Result<RedPlan, PlanCommandError> {
    let virtual_clock_start_ms = args
        .virtual_clock_start_ms
        .ok_or(PlanCommandError::MissingVirtualClock)?;

    let catalog = args
        .catalog
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CATALOG));
    let suites = resolve_suites(&args.suites)?;
    let graph = TargetGraph::from_repo(&catalog, &suites)
        .map_err(|error| PlanCommandError::Graph(Box::new(error)))?;

    let mut campaign = CampaignParams::new(args.campaign.clone(), virtual_clock_start_ms);
    if let Some(max_steps) = args.max_steps {
        campaign.max_steps = max_steps;
    }
    Ok(RedGenome::plan(
        args.seed,
        args.generation,
        &campaign,
        &graph,
    ))
}

/// The [`RedSwarmPlanArgs`] [`build_plan`] expects, drawn from `score`'s
/// shared fields, so `score` can reuse [`build_plan`] verbatim instead of
/// duplicating catalog/suite loading. `score` exposes no `--max-steps`
/// override -- only `plan` does -- so this always leaves it at the planner's
/// own default.
fn plan_args_for_score(args: &RedSwarmScoreArgs) -> RedSwarmPlanArgs {
    RedSwarmPlanArgs {
        seed: args.seed,
        generation: args.generation,
        campaign: args.campaign.clone(),
        catalog: args.catalog.clone(),
        suites: args.suites.clone(),
        virtual_clock_start_ms: args.virtual_clock_start_ms,
        max_steps: None,
    }
}

/// Load the [`EvasionCoverageSnapshot`] `--coverage` names (SC 1, end to end
/// through the CLI). A missing or malformed file is an input error, exit 1 --
/// the same convention [`build_plan`] uses for a malformed catalog -- never a
/// panic: `--coverage` is user input, not a runtime invariant.
fn load_coverage(path: &Path) -> Result<EvasionCoverageSnapshot, ScoreCommandError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|error| ScoreCommandError::CoverageIo(Box::new(error)))?;
    serde_json::from_str(&raw).map_err(|error| ScoreCommandError::CoverageParse(Box::new(error)))
}

/// The result of building, budgeting, and scoring one `score` invocation: the
/// fitness numbers, the extra count `plan` doesn't carry (`events_emitted`),
/// and the identity/determinism fields carried through from the planned
/// campaign so both render paths can show them without re-deriving anything.
struct ScoreOutcome {
    campaign: String,
    generation: u32,
    graph_fingerprint: [u8; 32],
    determinism: Determinism,
    fitness: AttackFitness,
    events_emitted: u32,
}

/// Build the fitness for `score` args (ATKSCORE-04): plan exactly as `plan`
/// does, apply the [`StealthBudget`], load the coverage snapshot, and score
/// the BUDGETED plan -- not the pre-budget one. Scoring what was actually
/// emitted (rather than what the planner merely proposed) means a genome
/// cannot buy `red_fitness` with steps the budget would truncate: only what
/// gets through counts, and truncation has already cost `stealth`. Pure
/// apart from reading the catalog, suites, and coverage file off disk; the
/// clock check inside [`build_plan`] still runs first, so a missing clock is
/// refused before any file -- catalog, suite, or coverage -- is touched.
fn build_score(args: &RedSwarmScoreArgs) -> Result<ScoreOutcome, ScoreCommandError> {
    let plan = build_plan(&plan_args_for_score(args))?;
    let coverage = load_coverage(&args.coverage)?;

    let budget = StealthBudget {
        max_events_per_generation: args
            .max_events
            .unwrap_or(StealthBudget::DEFAULT.max_events_per_generation),
        max_distinct_hosts: args
            .max_hosts
            .unwrap_or(StealthBudget::DEFAULT.max_distinct_hosts),
        max_technique_repeats: args
            .max_technique_repeats
            .unwrap_or(StealthBudget::DEFAULT.max_technique_repeats),
    };

    let RedPlan {
        generation,
        campaign,
        graph_fingerprint,
        steps,
        determinism,
    } = plan;
    let outcome: BudgetOutcome = budget.apply(steps);
    // Score the BUDGETED plan: `steps` here are the budget's emitted steps,
    // not the planner's proposal, and `outcome.stealth` is the matching
    // quietness factor -- see this function's doc for why.
    let budgeted_plan = RedPlan {
        generation,
        campaign: campaign.clone(),
        graph_fingerprint,
        steps: outcome.steps,
        determinism: determinism.clone(),
    };
    let fitness = AttackScorer.score(&budgeted_plan, &coverage, outcome.stealth);

    Ok(ScoreOutcome {
        campaign,
        generation,
        graph_fingerprint,
        determinism,
        fitness,
        events_emitted: outcome.events_emitted,
    })
}

/// Lower-case hex of the 32-byte graph fingerprint. Hand-written to avoid a new
/// dependency; the digest is fixed width, so the output is always 64 chars and
/// the encoding has no failure path.
fn fingerprint_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// The JSON shape on the wire: the plan's fields, but with the fingerprint as a
/// hex string rather than a 32-number array, and the `determinism` record kept at
/// the top level (OPFOR-04). Borrowing the plan keeps the bytes a pure function
/// of it.
#[derive(Serialize)]
struct PlanView<'a> {
    generation: u32,
    campaign: &'a str,
    graph_fingerprint: String,
    steps: &'a [GeneStep],
    determinism: &'a Determinism,
}

impl<'a> PlanView<'a> {
    fn new(plan: &'a RedPlan) -> Self {
        Self {
            generation: plan.generation,
            campaign: &plan.campaign,
            graph_fingerprint: fingerprint_hex(&plan.graph_fingerprint),
            steps: &plan.steps,
            determinism: &plan.determinism,
        }
    }
}

/// Render the plan as pretty JSON with the hex fingerprint and top-level
/// `determinism`. Deterministic: serde_json emits a struct's fields in order, so
/// identical plans render identical bytes.
fn render_plan_json(plan: &RedPlan) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&PlanView::new(plan))
}

/// Render the plan as a human-readable step table (the no-`--json` output).
fn render_plan_table(plan: &RedPlan) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "campaign {} generation {} scheduler {}",
        plan.campaign, plan.generation, plan.determinism.scheduler
    );
    let _ = writeln!(
        out,
        "seed {} virtual_clock_start_ms {} graph_fingerprint {}",
        plan.determinism.rng_seed,
        plan.determinism.virtual_clock_start_ms,
        fingerprint_hex(&plan.graph_fingerprint)
    );
    let _ = writeln!(
        out,
        "{:>3}  {:<9}  {:<30}  {:<16}  {:>9}  scenario",
        "#", "operator", "technique", "threat_class", "offset_ms"
    );
    for (index, step) in plan.steps.iter().enumerate() {
        // Pre-render the enum columns: a derived `Debug` on a fieldless enum
        // ignores the formatter width, so pad the string form instead to keep
        // the columns aligned.
        let operator = format!("{:?}", step.operator);
        let threat_class = format!("{:?}", step.threat_class);
        let _ = writeln!(
            out,
            "{:>3}  {:<9}  {:<30}  {:<16}  {:>9}  {}/{}",
            index,
            operator,
            step.technique,
            threat_class,
            step.offset_ms,
            step.scenario.suite,
            step.scenario.scenario
        );
    }
    out
}

/// The JSON shape on the wire for `score`: the four fitness numbers at the
/// top level, in the order the brief fixes them, plus the `determinism`
/// record -- mirroring [`PlanView`]'s top-level `determinism` (SC 4,
/// reproducibility).
#[derive(Serialize)]
struct ScoreView<'a> {
    red_fitness: f64,
    evasion_rate: f64,
    stealth: f64,
    events_emitted: u32,
    determinism: &'a Determinism,
}

impl<'a> ScoreView<'a> {
    fn new(outcome: &'a ScoreOutcome) -> Self {
        Self {
            red_fitness: outcome.fitness.red_fitness,
            evasion_rate: outcome.fitness.evasion_rate,
            stealth: outcome.fitness.stealth,
            events_emitted: outcome.events_emitted,
            determinism: &outcome.determinism,
        }
    }
}

/// Render the score as pretty JSON with the four top-level fitness numbers
/// and `determinism`, mirroring [`render_plan_json`]. Deterministic for the
/// same reason: serde_json emits a struct's fields in declaration order, so
/// identical scores render identical bytes.
fn render_score_json(outcome: &ScoreOutcome) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&ScoreView::new(outcome))
}

/// Render the score as a short human-readable table (the no-`--json`
/// output): the same determinism header [`render_plan_table`] prints, then
/// the four fitness numbers, one per labelled row.
fn render_score_table(outcome: &ScoreOutcome) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "campaign {} generation {} scheduler {}",
        outcome.campaign, outcome.generation, outcome.determinism.scheduler
    );
    let _ = writeln!(
        out,
        "seed {} virtual_clock_start_ms {} graph_fingerprint {}",
        outcome.determinism.rng_seed,
        outcome.determinism.virtual_clock_start_ms,
        fingerprint_hex(&outcome.graph_fingerprint)
    );
    let _ = writeln!(out, "{:<15}{}", "red_fitness", outcome.fitness.red_fitness);
    let _ = writeln!(
        out,
        "{:<15}{}",
        "evasion_rate", outcome.fitness.evasion_rate
    );
    let _ = writeln!(out, "{:<15}{}", "stealth", outcome.fitness.stealth);
    let _ = writeln!(out, "{:<15}{}", "events_emitted", outcome.events_emitted);
    out
}

/// Dispatch `red-swarm <subcommand>`: `plan` or `score`.
pub(crate) fn run(args: &RedSwarmArgs, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    match &args.command {
        RedSwarmCommand::Plan(plan_args) => run_plan(plan_args, json),
        RedSwarmCommand::Score(score_args) => run_score(score_args, json),
    }
}

/// The `plan` shell: build the plan, and on a missing clock refuse with exit 1 and
/// [`MISSING_CLOCK_MESSAGE`] rather than defaulting to now (SC 4). Other failures
/// surface as errors through the CLI's normal path.
fn run_plan(args: &RedSwarmPlanArgs, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let plan = match build_plan(args) {
        Ok(plan) => plan,
        Err(PlanCommandError::MissingVirtualClock) => {
            eprintln!("{MISSING_CLOCK_MESSAGE}");
            std::process::exit(1);
        }
        Err(PlanCommandError::Io(error)) => return Err(error),
        Err(PlanCommandError::Graph(error)) => return Err(error),
    };
    if json {
        println!("{}", render_plan_json(&plan)?);
    } else {
        println!("{}", render_plan_table(&plan));
    }
    Ok(())
}

/// The `score` shell: build the score, and on a missing clock refuse with
/// exit 1 and [`MISSING_CLOCK_MESSAGE`] -- same as [`run_plan`] (SC 4). Other
/// failures, including a missing/malformed `--coverage` file, surface as
/// errors through the CLI's normal path.
fn run_score(args: &RedSwarmScoreArgs, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let outcome = match build_score(args) {
        Ok(outcome) => outcome,
        Err(ScoreCommandError::MissingVirtualClock) => {
            eprintln!("{MISSING_CLOCK_MESSAGE}");
            std::process::exit(1);
        }
        Err(ScoreCommandError::Io(error)) => return Err(error),
        Err(ScoreCommandError::Graph(error)) => return Err(error),
        Err(ScoreCommandError::CoverageIo(error)) => return Err(error),
        Err(ScoreCommandError::CoverageParse(error)) => return Err(error),
    };
    if json {
        println!("{}", render_score_json(&outcome)?);
    } else {
        println!("{}", render_score_table(&outcome));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use swarm_core::pheromone::ThreatClass;
    use swarm_runtime::evasion_coverage::{DetectorEvasionCoverageReport, EvasionScenarioCoverage};

    /// The repository root, from either crate that compiles this file: both
    /// manifests sit two levels below it.
    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    /// The four tracked suites, so the graph the test plans against is the same
    /// one the default glob would assemble.
    const SUITES: [&str; 4] = [
        "scenario-suites/command-line-deobfuscation-v1.yaml",
        "scenario-suites/evasion-breadth-v1.yaml",
        "scenario-suites/hellcat-office-v1.yaml",
        "scenario-suites/kill-chain-sequences-v1.yaml",
    ];

    /// Args pinned to the real repo catalog and suites with absolute paths, so a
    /// test never depends on the process CWD, and with an explicit clock so it
    /// never depends on the wall clock.
    fn plan_args(
        seed: u64,
        generation: u32,
        virtual_clock_start_ms: Option<i64>,
    ) -> RedSwarmPlanArgs {
        let root = repo_root();
        RedSwarmPlanArgs {
            seed,
            generation,
            campaign: "smoke".to_string(),
            catalog: Some(root.join(DEFAULT_CATALOG)),
            suites: SUITES.iter().map(|rel| root.join(rel)).collect(),
            virtual_clock_start_ms,
            max_steps: None,
        }
    }

    #[test]
    fn the_plan_json_is_byte_identical_across_two_runs_with_the_same_arguments() {
        let first =
            render_plan_json(&build_plan(&plan_args(7, 0, Some(1_700_000_000_000))).unwrap())
                .unwrap();
        let second =
            render_plan_json(&build_plan(&plan_args(7, 0, Some(1_700_000_000_000))).unwrap())
                .unwrap();
        assert_eq!(
            first, second,
            "identical arguments must produce byte-identical JSON"
        );
    }

    #[test]
    fn the_plan_json_carries_determinism_at_top_level_and_a_hex_fingerprint() {
        let plan = build_plan(&plan_args(7, 0, Some(1_700_000_000_000))).unwrap();
        let json = render_plan_json(&plan).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        let determinism = value
            .get("determinism")
            .expect("determinism object at the top level");
        assert_eq!(
            determinism.get("rng_seed").and_then(|v| v.as_u64()),
            Some(plan.determinism.rng_seed)
        );
        assert!(
            determinism.get("virtual_clock_start_ms").is_some(),
            "determinism carries the virtual clock origin"
        );
        assert_eq!(
            determinism.get("scheduler").and_then(|v| v.as_str()),
            Some("round_robin_v1")
        );

        let fingerprint = value
            .get("graph_fingerprint")
            .and_then(|v| v.as_str())
            .expect("graph_fingerprint is a hex string, not a byte array");
        assert_eq!(fingerprint.len(), 64, "32 bytes render to 64 hex chars");
        assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(fingerprint, fingerprint_hex(&plan.graph_fingerprint));
    }

    #[test]
    fn a_plan_omitting_the_virtual_clock_is_refused_rather_than_defaulting_to_now() {
        let result = build_plan(&plan_args(7, 0, None));
        assert!(
            matches!(result, Err(PlanCommandError::MissingVirtualClock)),
            "a missing --virtual-clock-start-ms must refuse, not plan"
        );
        assert_eq!(
            MISSING_CLOCK_MESSAGE,
            "`--virtual-clock-start-ms` is required: a plan's bytes must not depend on the wall clock"
        );
    }

    #[test]
    fn the_human_table_lists_every_step_and_the_scheduler() {
        let plan = build_plan(&plan_args(7, 0, Some(1_700_000_000_000))).unwrap();
        let table = render_plan_table(&plan);
        assert!(table.contains("round_robin_v1"));
        for step in &plan.steps {
            assert!(
                table.contains(step.technique.as_str()),
                "the table must name technique {}",
                step.technique
            );
        }
    }

    /// A coverage snapshot with one detector fully catching (`catch_rate:
    /// 1.0`) every technique in `techniques`: one scenario per technique,
    /// mirroring `scoring.rs`'s own test fixture shape. Built here (rather
    /// than reusing that module's private helper) because this test drives
    /// scoring through `--coverage`, not `AttackScorer` directly.
    fn fully_caught_coverage(techniques: &[String]) -> EvasionCoverageSnapshot {
        let scenarios: Vec<EvasionScenarioCoverage> = techniques
            .iter()
            .map(|technique| EvasionScenarioCoverage {
                scenario_name: format!("{technique}_scenario"),
                threat_class: ThreatClass::Execution,
                total_payloads: 1,
                detected_payloads: 1,
                catch_rate: 1.0,
                techniques: vec![technique.clone()],
            })
            .collect();
        let total_payloads = scenarios.len();
        EvasionCoverageSnapshot {
            generated_at_ms: 0,
            suite_name: "test-suite".to_string(),
            suite_path: "scenario-suites/test-suite.yaml".to_string(),
            corpus_version: "test".to_string(),
            detectors: vec![DetectorEvasionCoverageReport {
                detector: "test_detector".to_string(),
                total_payloads,
                detected_payloads: total_payloads,
                catch_rate: 1.0,
                threat_classes: Vec::new(),
                scenarios,
                intentionally_uncovered: Vec::new(),
            }],
        }
    }

    /// A coverage snapshot with no detectors at all: every technique the plan
    /// names has no report whatsoever, not a zeroed-out entry -- the
    /// "uncovered" case `scoring.rs`'s doc distinguishes from a `catch_rate:
    /// 0.0` entry.
    fn all_uncovered_coverage() -> EvasionCoverageSnapshot {
        EvasionCoverageSnapshot {
            generated_at_ms: 0,
            suite_name: "test-suite".to_string(),
            suite_path: "scenario-suites/test-suite.yaml".to_string(),
            corpus_version: "test".to_string(),
            detectors: Vec::new(),
        }
    }

    /// A process-unique path under the OS temp dir, so parallel test threads
    /// never collide on the same `--coverage` fixture file. Reading the wall
    /// clock here is fine: this helper lives after `#[cfg(test)]`, which
    /// `no_entropy_path_exists_in_the_red_swarm_cli` never scans.
    ///
    /// Uniqueness alone only prevents collisions between tests -- it does
    /// not clean up after them. A test that writes to this path owns
    /// removing it (see [`TempFixture`]) rather than leaving it under
    /// `/tmp` for every run.
    fn unique_temp_path(label: &str) -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("red-swarm-score-{label}-{suffix}.json"))
    }

    /// RAII guard for a fixture file written under the OS temp dir: the file
    /// is removed when the guard drops, so a test leaves no `/tmp` residue
    /// regardless of how it exits (including an early return via `?` or a
    /// failed assertion unwinding the test). Call [`TempFixture::path`] to
    /// hand an owned `PathBuf` to a call site (such as a `RedSwarmScoreArgs`
    /// field) while the guard itself stays alive to clean up at the end of
    /// the test.
    struct TempFixture(PathBuf);

    impl TempFixture {
        /// A clone of the guarded path, for callers that need to hand off an
        /// owned `PathBuf` (like the `coverage` field of
        /// [`RedSwarmScoreArgs`]) while the guard itself stays alive to clean
        /// up at the end of the test.
        fn path(&self) -> PathBuf {
            self.0.clone()
        }
    }

    impl Drop for TempFixture {
        fn drop(&mut self) {
            // Best-effort: some tests exercise a path that was never
            // written (a deliberately missing `--coverage` file), so a
            // failed removal here is expected, not a bug.
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// Writes `contents` to a fresh, process-unique temp file and returns an
    /// RAII guard that removes it when dropped -- see [`TempFixture`].
    fn write_temp_fixture(label: &str, contents: &[u8]) -> TempFixture {
        let path = unique_temp_path(label);
        std::fs::write(&path, contents).unwrap();
        TempFixture(path)
    }

    /// Writes `snapshot` to a fresh temp file as JSON and returns an RAII
    /// guard for it, so a test can drive `--coverage` end to end through the
    /// CLI rather than calling `AttackScorer` directly (SC 1).
    fn write_coverage_fixture(label: &str, snapshot: &EvasionCoverageSnapshot) -> TempFixture {
        write_temp_fixture(label, serde_json::to_string(snapshot).unwrap().as_bytes())
    }

    /// `score` args pinned to the real repo catalog and suites, mirroring
    /// `plan_args`, plus the given coverage fixture and no budget overrides.
    fn score_args(
        seed: u64,
        generation: u32,
        coverage: PathBuf,
        virtual_clock_start_ms: Option<i64>,
    ) -> RedSwarmScoreArgs {
        let root = repo_root();
        RedSwarmScoreArgs {
            seed,
            generation,
            campaign: "smoke".to_string(),
            coverage,
            catalog: Some(root.join(DEFAULT_CATALOG)),
            suites: SUITES.iter().map(|rel| root.join(rel)).collect(),
            virtual_clock_start_ms,
            max_events: None,
            max_hosts: None,
            max_technique_repeats: None,
        }
    }

    #[test]
    fn the_score_json_is_byte_identical_across_two_runs_with_the_same_arguments() {
        let coverage = write_coverage_fixture("determinism", &all_uncovered_coverage());
        let args = score_args(7, 0, coverage.path(), Some(1_700_000_000_000));

        let first = render_score_json(&build_score(&args).unwrap()).unwrap();
        let second = render_score_json(&build_score(&args).unwrap()).unwrap();

        assert_eq!(
            first, second,
            "identical arguments must produce byte-identical JSON"
        );
    }

    #[test]
    fn the_score_json_carries_the_four_top_level_fitness_fields_all_finite_and_determinism() {
        let coverage = write_coverage_fixture("sc4", &all_uncovered_coverage());
        let outcome =
            build_score(&score_args(7, 0, coverage.path(), Some(1_700_000_000_000))).unwrap();
        let json = render_score_json(&outcome).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        for field in ["red_fitness", "evasion_rate", "stealth", "events_emitted"] {
            let number = value
                .get(field)
                .and_then(|value| value.as_f64())
                .unwrap_or_else(|| panic!("`{field}` must be a top-level JSON number"));
            assert!(number.is_finite(), "`{field}` must be finite, got {number}");
        }
        let determinism = value
            .get("determinism")
            .expect("determinism object at the top level");
        assert_eq!(
            determinism.get("scheduler").and_then(|v| v.as_str()),
            Some("round_robin_v1")
        );
    }

    #[test]
    fn a_fully_caught_coverage_fixture_scores_zero_red_fitness_through_the_cli() {
        let plan = build_plan(&plan_args(7, 0, Some(1_700_000_000_000))).unwrap();
        assert!(
            !plan.steps.is_empty(),
            "test needs at least one planned step to be meaningful"
        );
        let techniques: std::collections::BTreeSet<String> = plan
            .steps
            .iter()
            .map(|step| step.technique.clone())
            .collect();
        let techniques: Vec<String> = techniques.into_iter().collect();
        let coverage = write_coverage_fixture("fully-caught", &fully_caught_coverage(&techniques));

        let outcome =
            build_score(&score_args(7, 0, coverage.path(), Some(1_700_000_000_000))).unwrap();

        assert_eq!(outcome.fitness.evasion_rate, 0.0);
        assert_eq!(outcome.fitness.red_fitness, 0.0);
    }

    #[test]
    fn an_all_uncovered_coverage_fixture_scores_red_fitness_above_one_half_through_the_cli() {
        let coverage = write_coverage_fixture("all-uncovered", &all_uncovered_coverage());

        let outcome =
            build_score(&score_args(7, 0, coverage.path(), Some(1_700_000_000_000))).unwrap();

        assert_eq!(outcome.fitness.evasion_rate, 1.0);
        assert!(
            outcome.fitness.red_fitness > 0.5,
            "expected red_fitness > 0.5, got {}",
            outcome.fitness.red_fitness
        );
    }

    #[test]
    fn a_score_omitting_the_virtual_clock_is_refused_rather_than_defaulting_to_now() {
        let coverage = write_coverage_fixture("refusal", &all_uncovered_coverage());
        let result = build_score(&score_args(7, 0, coverage.path(), None));
        assert!(
            matches!(result, Err(ScoreCommandError::MissingVirtualClock)),
            "a missing --virtual-clock-start-ms must refuse, not score"
        );
    }

    #[test]
    fn a_missing_coverage_file_is_refused_rather_than_panicking() {
        let missing = unique_temp_path("missing");
        let result = build_score(&score_args(7, 0, missing, Some(1_700_000_000_000)));
        assert!(
            matches!(result, Err(ScoreCommandError::CoverageIo(_))),
            "a missing --coverage file must be a CoverageIo error, not a panic"
        );
    }

    #[test]
    fn a_malformed_coverage_file_is_refused_rather_than_panicking() {
        let coverage = write_temp_fixture("malformed", b"not valid json");
        let result = build_score(&score_args(7, 0, coverage.path(), Some(1_700_000_000_000)));
        assert!(
            matches!(result, Err(ScoreCommandError::CoverageParse(_))),
            "a malformed --coverage file must be a CoverageParse error, not a panic"
        );
    }

    #[test]
    fn a_tight_max_events_override_truncates_the_budget_and_lowers_events_emitted() {
        let coverage = write_coverage_fixture("max-events", &all_uncovered_coverage());
        let mut args = score_args(7, 0, coverage.path(), Some(1_700_000_000_000));
        args.max_events = Some(0);

        let outcome = build_score(&args).unwrap();

        assert_eq!(outcome.events_emitted, 0);
    }

    #[test]
    fn the_score_human_table_lists_the_four_fitness_numbers() {
        let coverage = write_coverage_fixture("table", &all_uncovered_coverage());
        let outcome =
            build_score(&score_args(7, 0, coverage.path(), Some(1_700_000_000_000))).unwrap();
        let table = render_score_table(&outcome);
        assert!(table.contains("round_robin_v1"));
        for label in ["red_fitness", "evasion_rate", "stealth", "events_emitted"] {
            assert!(table.contains(label), "the table must label {label}");
        }
    }

    fn strip_comments(source: &str) -> String {
        let mut out = String::with_capacity(source.len());
        let mut chars = source.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '/' && chars.peek() == Some(&'/') {
                for n in chars.by_ref() {
                    if n == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            } else if c == '/' && chars.peek() == Some(&'*') {
                chars.next();
                let mut prev = ' ';
                for n in chars.by_ref() {
                    if prev == '*' && n == '/' {
                        break;
                    }
                    prev = n;
                }
                out.push(' ');
            } else {
                out.push(c);
            }
        }
        out
    }

    /// Production code only: comments stripped and everything from the first
    /// `#[cfg(test)]` onward removed. This file keeps its tests in a single
    /// trailing `#[cfg(test)] mod tests`, so the cut isolates production exactly.
    fn production_code(source: &str) -> String {
        let without_comments = strip_comments(source);
        match without_comments.find("#[cfg(test)]") {
            Some(idx) => without_comments[..idx].to_string(),
            None => without_comments,
        }
    }

    /// SC 4, the CLI half: neither the `plan` nor the `score` output path
    /// reads OS entropy or the wall clock. This extends Task 1's
    /// `no_entropy_path_exists_in_the_red_lane` to the CLI module; scanning
    /// the whole file's production code (see `production_code`) means a new
    /// verb added below is covered automatically, with no separate test to
    /// remember to extend. The file is located from the repo root, not from
    /// `CARGO_MANIFEST_DIR/src`, because this test compiles into both swarm-cli
    /// and swarm-runtime-http and the file lives only under swarm-cli.
    #[test]
    fn no_entropy_path_exists_in_the_red_swarm_cli() {
        let file = repo_root().join("crates/swarm-cli/src/red_swarm_cmd.rs");
        let forbidden = [
            "getrandom",
            "OsRng",
            "thread_rng",
            "SystemTime",
            "Instant::now",
            "Utc::now",
            "Local::now",
        ];
        let source = std::fs::read_to_string(&file).unwrap();
        let production = production_code(&source);
        for needle in forbidden {
            assert!(
                !production.contains(needle),
                "forbidden entropy identifier `{needle}` in production code of {}",
                file.display()
            );
        }
    }
}
