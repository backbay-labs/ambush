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
//!
//! Phase 290 (Task 4) adds `campaign`: it builds a
//! [`swarm_runtime::red_swarm::CampaignConfig`] the same way `plan`/`score`
//! build a graph (through [`build_graph`], shared by all three verbs -- see
//! that function's doc), and runs the whole bounded red/blue loop through
//! [`swarm_runtime::red_swarm::RedSwarmCampaign::run`]. That function is
//! CLOCK-FREE and deterministic (COEVOLVE-01 part B); this module wraps its
//! [`swarm_runtime::red_swarm::CampaignReport`] in a [`CampaignReportView`]
//! that adds exactly one clock read, `generated_at_ms` -- see
//! [`generated_at_ms`]'s doc for why reading it here, rather than inside the
//! engine, is what keeps `RedSwarmCampaign::run` itself clock-free. Two
//! `campaign` invocations with identical arguments still produce
//! byte-identical report JSON once `generated_at_ms` is stripped (SC 4;
//! pinned by this module's own test). `campaign` persists that JSON under
//! [`DEFAULT_CAMPAIGN_REPORTS_DIR`] and refuses on the same missing-clock
//! condition as `plan`/`score`.

use clap::{Args, Subcommand};
use serde::Serialize;
use std::path::{Path, PathBuf};
use swarm_core::config::{DetectionConfig, DetectorProfilesConfig};
use swarm_runtime::evasion_coverage::EvasionCoverageSnapshot;
use swarm_runtime::red_swarm::budget::{BudgetOutcome, StealthBudget};
use swarm_runtime::red_swarm::pattern_db::AttackPatternRecord;
use swarm_runtime::red_swarm::scoring::{AttackFitness, AttackScorer};
use swarm_runtime::red_swarm::{
    CampaignConfig, CampaignParams, CampaignReport, Convergence, Determinism, GeneStep,
    GenerationOutcome, RedGenome, RedPlan, RedSwarmCampaign, RedSwarmError, StopReason,
    TargetGraph, generation_corpus_sequence_id,
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

/// `campaign`'s default starting detector strategy when `--strategies` is
/// omitted entirely: [`DetectionConfig::strategy`] still needs some value,
/// even though [`DetectionConfig::active_strategies`] (which
/// `run_generation` actually consumes through `.strategies`) ignores it
/// once `.strategies` is non-empty. Mirrors
/// `swarm_runtime::red_swarm::campaign`'s own test fixture default.
const DEFAULT_DETECTION_STRATEGY: &str = "kill_chain_sequence";

/// `campaign`'s default `convergence.min_delta` when `--min-delta` is
/// omitted: a generation-to-generation `red_fitness` change smaller than
/// this counts as "no change" for the `Plateau` stop condition
/// (COEVOLVE-02).
const DEFAULT_MIN_DELTA: f64 = 0.01;

/// `campaign`'s default `convergence.patience` when `--patience` is
/// omitted: this many consecutive small changes in a row before `Plateau`
/// fires (COEVOLVE-02).
const DEFAULT_PATIENCE: u32 = 3;

/// `campaign`'s fixed `initial_detection.high_confidence_threshold`. Not a
/// CLI override -- `--strategies` is the only detection knob the brief
/// gives `campaign` -- mirrors the same `0.9` used throughout this
/// codebase's own `DetectionConfig` defaults (e.g.
/// `swarm_runtime::red_swarm::campaign`'s own test fixture).
const DEFAULT_HIGH_CONFIDENCE_THRESHOLD: f64 = 0.9;

/// `campaign`'s fixed `initial_detection.medium_confidence_threshold`; see
/// [`DEFAULT_HIGH_CONFIDENCE_THRESHOLD`]'s doc.
const DEFAULT_MEDIUM_CONFIDENCE_THRESHOLD: f64 = 0.7;

/// The default base directory a persisted campaign report is written under,
/// repository-relative -- the operator runs swarmctl from the repo root, the
/// same convention [`DEFAULT_CATALOG`] and [`DEFAULT_SUITES_DIR`] already
/// rely on. Mirrors every other cwd-relative `data/...` store default in
/// this codebase (e.g. `data/canaries/`, `data/replay-runs/`); see
/// [`persist_campaign_report`]'s doc for why this is a plain constant here
/// rather than a `--output-dir` flag: only [`run_campaign`], the process-exit
/// shell, ever uses it directly, and a test injects its own temp directory
/// instead.
const DEFAULT_CAMPAIGN_REPORTS_DIR: &str = "data/red-swarm/campaigns";

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
    /// Run a bounded red/blue campaign end to end and persist its report
    /// (COEVOLVE-01 part B / COEVOLVE-02 / COEVOLVE-04, Task 4).
    Campaign(RedSwarmCampaignArgs),
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

/// `red-swarm campaign` arguments (Task 4): runs the whole bounded red/blue
/// loop, generation 0 through `stop_reason`, rather than one generation like
/// `plan`/`score`. There is deliberately no `--generation` flag -- a
/// campaign always starts at generation 0 -- and no `--max-steps` override,
/// the same omission [`plan_args_for_score`] documents for `score`.
#[derive(Debug, Args)]
struct RedSwarmCampaignArgs {
    /// The base seed every generation's plan derives its own effective seed
    /// from (see [`RedGenome::plan_weighted`]'s doc).
    #[arg(long)]
    seed: u64,

    /// The campaign name: copied onto every generation's plan and used
    /// (with `seed`) to name the persisted report file.
    #[arg(long)]
    campaign: String,

    /// The hard cap on how many generations to run, regardless of what the
    /// convergence or coverage checks say.
    #[arg(long)]
    max_generations: u32,

    /// The `Plateau` stop condition's minimum meaningful
    /// generation-to-generation `red_fitness` change. Defaults to
    /// [`DEFAULT_MIN_DELTA`] when omitted.
    #[arg(long)]
    min_delta: Option<f64>,

    /// The `Plateau` stop condition's window: this many consecutive small
    /// changes in a row before it fires. Defaults to [`DEFAULT_PATIENCE`]
    /// when omitted.
    #[arg(long)]
    patience: Option<u32>,

    /// Blue's starting enabled detector strategies, before any generation's
    /// gap-closing move; repeatable. Defaults to none enabled, so
    /// generation 0 runs with an empty detection config and blue only ever
    /// grows it from there.
    #[arg(long = "strategies")]
    strategies: Vec<String>,

    /// The evasion technique catalog. Defaults to the repository catalog.
    #[arg(long)]
    catalog: Option<PathBuf>,

    /// A scenario suite to plan against; repeatable. Defaults to every
    /// `scenario-suites/*.yaml`.
    #[arg(long = "suite")]
    suites: Vec<PathBuf>,

    /// The virtual clock origin (ms) that step offsets are measured from.
    /// REQUIRED: a report's bytes must not depend on the wall clock (SC 4),
    /// so this is never defaulted to `now()` -- omitting it is refused.
    #[arg(long)]
    virtual_clock_start_ms: Option<i64>,

    /// Override the stealth budget's cap on the running sum of one
    /// generation's emitted steps' event counts. Defaults to the budget's
    /// own default cap.
    #[arg(long)]
    max_events: Option<u32>,

    /// Override the stealth budget's cap on how many distinct host slots
    /// one generation's plan may bind. Defaults to the budget's own
    /// default cap.
    #[arg(long)]
    max_hosts: Option<u8>,

    /// Override the stealth budget's cap on how many emitted steps in one
    /// generation may name the same technique. Defaults to the budget's
    /// own default cap.
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

/// A failure of the campaign path (Task 4), kept separate from the
/// process-exit shell for the same reason [`PlanCommandError`] is.
#[derive(Debug)]
enum CampaignCommandError {
    /// `--virtual-clock-start-ms` was omitted. Forwarded from
    /// [`build_graph`] (via [`PlanCommandError`]) unchanged, so `campaign`
    /// refuses with the exact same message as `plan`/`score` (SC 4).
    MissingVirtualClock,
    /// The default suite glob could not read `scenario-suites/`. Forwarded
    /// from [`build_graph`] unchanged.
    Io(Box<std::io::Error>),
    /// The target graph could not be built from the catalog and suites.
    /// Forwarded from [`build_graph`] unchanged.
    Graph(Box<RedSwarmError>),
    /// [`RedSwarmCampaign::run`] itself failed -- a suite/graph mismatch or
    /// similar runtime failure surfaced as [`RedSwarmError`], never a panic.
    Run(Box<RedSwarmError>),
}

/// Forwards [`build_graph`]'s error unchanged (via [`PlanCommandError`]), so
/// `campaign`'s graph-building step can reuse it with `?` exactly as `score`
/// reuses [`build_plan`]'s.
impl From<PlanCommandError> for CampaignCommandError {
    fn from(error: PlanCommandError) -> Self {
        match error {
            PlanCommandError::MissingVirtualClock => CampaignCommandError::MissingVirtualClock,
            PlanCommandError::Io(error) => CampaignCommandError::Io(error),
            PlanCommandError::Graph(error) => CampaignCommandError::Graph(error),
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

/// The catalog, suites and [`TargetGraph`] shared by every red-swarm verb --
/// `plan`, `score` and `campaign` alike (see the module doc): resolves
/// `--catalog`/`--suite` (or their repo defaults) and refuses a missing
/// `--virtual-clock-start-ms` before touching disk (SC 4). Returns the
/// resolved suite paths alongside the graph because
/// [`swarm_runtime::red_swarm::CampaignConfig::suite_paths`] (and
/// `run_generation`'s own `suite_paths` argument, reached through
/// [`RedSwarmCampaign::run`]) needs the EXACT paths the graph was built
/// from, not just the graph -- the same requirement
/// `swarm_runtime::red_swarm::genome_adapter::GenomeRedSwarm::new`
/// documents.
fn build_graph(
    catalog: &Option<PathBuf>,
    suites: &[PathBuf],
    virtual_clock_start_ms: Option<i64>,
) -> Result<(i64, Vec<PathBuf>, TargetGraph), PlanCommandError> {
    let virtual_clock_start_ms =
        virtual_clock_start_ms.ok_or(PlanCommandError::MissingVirtualClock)?;

    let catalog = catalog
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CATALOG));
    let suite_paths = resolve_suites(suites)?;
    let graph = TargetGraph::from_repo(&catalog, &suite_paths)
        .map_err(|error| PlanCommandError::Graph(Box::new(error)))?;
    Ok((virtual_clock_start_ms, suite_paths, graph))
}

/// Build the plan for `plan` args. Pure apart from reading the catalog and suites
/// off disk: no clock, no globals. The clock check is first, so a missing clock is
/// refused before any file is touched (SC 4).
fn build_plan(args: &RedSwarmPlanArgs) -> Result<RedPlan, PlanCommandError> {
    let (virtual_clock_start_ms, _suite_paths, graph) =
        build_graph(&args.catalog, &args.suites, args.virtual_clock_start_ms)?;

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

/// Dedup `raw`'s repeated `--strategies <id>` values before they become
/// [`DetectionConfig::strategies`]: preserves first-seen order rather than
/// sorting, since [`build_campaign_config`] takes its `strategy` fallback
/// from `strategies.first()`, and reordering here would silently change
/// which id that is for a caller who lists more than one. The `BTreeSet`
/// below is used only to test membership, never iterated, so the result
/// is a deterministic function of `raw`'s own order, never of hash order.
///
/// A literal duplicate costs nothing observable today -- `run_generation`
/// builds one `RuntimeDetector` per `detection.strategies` entry, and two
/// instances built from the same id share one `hits` key, so the second
/// silently collapses into the first rather than doubling a catch (see
/// that function's own NOTE on `detectors`) -- but it does leave
/// `detection.strategies.len()` inflated relative to the distinct ids
/// actually enabled, which is what a duplicate-free `records` (one entry
/// per distinct `(technique, detector)` pair) is measured against.
/// Deduping here is the CLI-side half of keeping `run_generation`'s own
/// "no caller in this crate constructs a `DetectionConfig` that way today"
/// comment true for `--strategies`, the one flag a caller could otherwise
/// use to violate it.
fn dedup_strategies(raw: &[String]) -> Vec<String> {
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    let mut deduped = Vec::with_capacity(raw.len());
    for id in raw {
        if seen.insert(id.as_str()) {
            deduped.push(id.clone());
        }
    }
    deduped
}

/// Build the [`CampaignConfig`] for `campaign` args (Task 4): resolves the
/// graph exactly as [`build_plan`]/[`build_score`] do (through
/// [`build_graph`]), then fills in the budget, the starting detection
/// config, and the convergence rule from `args`, applying this module's own
/// defaults ([`DEFAULT_MIN_DELTA`], [`DEFAULT_PATIENCE`],
/// [`DEFAULT_DETECTION_STRATEGY`]) wherever the matching flag was omitted.
/// Pure apart from reading the catalog/suites off disk; the missing-clock
/// refusal inside [`build_graph`] still runs first.
fn build_campaign_config(
    args: &RedSwarmCampaignArgs,
) -> Result<CampaignConfig, CampaignCommandError> {
    let (virtual_clock_start_ms, suite_paths, graph) =
        build_graph(&args.catalog, &args.suites, args.virtual_clock_start_ms)?;

    let campaign = CampaignParams::new(args.campaign.clone(), virtual_clock_start_ms);

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

    // `--strategies` seeds blue's STARTING enabled set; an empty list (the
    // default) means generation 0 runs with nothing enabled and blue only
    // ever grows `.strategies` from there (see
    // `swarm_runtime::red_swarm::campaign::close_blue_gaps`). Deduped first
    // (M2, see `dedup_strategies`) so a repeated id never inflates
    // `.strategies` beyond the distinct ids actually enabled. `.strategy`
    // still needs some value even though `.active_strategies()` ignores it
    // once `.strategies` is non-empty -- see [`DEFAULT_DETECTION_STRATEGY`].
    let strategies = dedup_strategies(&args.strategies);
    let strategy = strategies
        .first()
        .cloned()
        .unwrap_or_else(|| DEFAULT_DETECTION_STRATEGY.to_string());
    let initial_detection = DetectionConfig {
        strategy,
        strategies,
        high_confidence_threshold: DEFAULT_HIGH_CONFIDENCE_THRESHOLD,
        medium_confidence_threshold: DEFAULT_MEDIUM_CONFIDENCE_THRESHOLD,
        profiles: DetectorProfilesConfig::default(),
    };

    Ok(CampaignConfig {
        seed: args.seed,
        campaign,
        graph,
        suite_paths,
        budget,
        initial_detection,
        max_generations: args.max_generations,
        convergence: Convergence {
            min_delta: args.min_delta.unwrap_or(DEFAULT_MIN_DELTA),
            patience: args.patience.unwrap_or(DEFAULT_PATIENCE),
        },
    })
}

/// The wall-clock timestamp stamped onto a persisted campaign report's own
/// `generated_at_ms` field -- the ONLY clock read anywhere on the
/// `campaign` path (see the module doc's "Phase 290 (Task 4)" paragraph).
/// [`build_campaign_config`] and
/// [`swarm_runtime::red_swarm::RedSwarmCampaign::run`] never read a clock,
/// so this is the single point a fresh timestamp enters a report, called
/// exactly once per [`build_campaign`] call.
///
/// Delegates to [`swarm_runtime::runtime_events::now_ms`] rather than
/// reading `SystemTime` in this file directly. That is what keeps this
/// file's OWN production code clock-free under
/// `no_entropy_path_exists_in_the_red_swarm_cli`'s literal scan below (that
/// test scans this file's text for `SystemTime`/`Instant::now`/etc., not
/// its callees) -- the exemption is deliberate, not a gap in the scan:
/// `campaign`'s persisted report needs a real timestamp; `plan` and `score`
/// never did, and still do not.
fn generated_at_ms() -> i64 {
    swarm_runtime::runtime_events::now_ms()
}

/// The `determinism`-style identity block on a persisted/rendered campaign
/// report (Task 4): the [`CampaignConfig`] fields that determine the
/// report's bytes, echoed back rather than re-derived -- mirroring
/// [`PlanView`]/[`ScoreView`]'s own top-level `determinism` record.
#[derive(Debug, Serialize)]
struct CampaignReportDeterminism {
    seed: u64,
    campaign: String,
    max_generations: u32,
    convergence: Convergence,
}

/// One generation's entry in a persisted/rendered campaign report: a
/// [`GenerationOutcome`]'s own fields, plus the `corpus_sequence_id`
/// (COEVOLVE-04) that names it. [`generation_corpus_sequence_id`] is
/// applied to `outcome.generation` itself, never tracked as a separate
/// counter, so the id can never drift from the generation it labels.
#[derive(Debug, Serialize)]
struct GenerationOutcomeView {
    corpus_sequence_id: String,
    generation: u32,
    red_fitness: AttackFitness,
    blue_catch_rate: f64,
    records: Vec<AttackPatternRecord>,
    evaded_techniques: Vec<String>,
}

impl GenerationOutcomeView {
    fn new(outcome: GenerationOutcome) -> Self {
        Self {
            corpus_sequence_id: generation_corpus_sequence_id(outcome.generation),
            generation: outcome.generation,
            red_fitness: outcome.red_fitness,
            blue_catch_rate: outcome.blue_catch_rate,
            records: outcome.records,
            evaded_techniques: outcome.evaded_techniques,
        }
    }
}

/// The JSON shape on the wire (and on disk) for `campaign`: a single clock
/// read, `generated_at_ms`, wrapping the CLOCK-FREE
/// [`CampaignReport`] [`RedSwarmCampaign::run`] returned (see the module
/// doc and [`generated_at_ms`]'s doc for why the clock lives here and
/// nowhere inside the engine). Two `campaign` invocations with identical
/// arguments produce byte-identical JSON once `generated_at_ms` is stripped
/// (SC 4; pinned by this module's own test), because every other field here
/// is a deterministic function of `config` and `report`.
#[derive(Debug, Serialize)]
struct CampaignReportView {
    generated_at_ms: i64,
    determinism: CampaignReportDeterminism,
    generations: Vec<GenerationOutcomeView>,
    stop_reason: StopReason,
    final_blue_catch_rate: f64,
}

impl CampaignReportView {
    /// Consumes `report`: [`build_campaign`] owns it locally and has no use
    /// for it afterward, so moving its `Vec`s into the view's owned fields
    /// avoids cloning a report that can hold one entry per generation times
    /// one record per `(technique, detector)` pair.
    fn new(config: &CampaignConfig, report: CampaignReport, generated_at_ms: i64) -> Self {
        Self {
            generated_at_ms,
            determinism: CampaignReportDeterminism {
                seed: config.seed,
                campaign: config.campaign.name.clone(),
                max_generations: config.max_generations,
                convergence: config.convergence,
            },
            generations: report
                .generations
                .into_iter()
                .map(GenerationOutcomeView::new)
                .collect(),
            stop_reason: report.stop_reason,
            final_blue_catch_rate: report.final_blue_catch_rate,
        }
    }
}

/// Build the full campaign report view for `campaign` args (Task 4): build
/// the config exactly as `plan`/`score` build a graph, run the whole
/// bounded red/blue loop through [`RedSwarmCampaign::run`], and wrap the
/// result with the single clock read [`generated_at_ms`] contributes. Pure
/// apart from that one clock read and reading the catalog/suites off disk;
/// the missing-clock refusal inside [`build_campaign_config`] still runs
/// first, so a missing `--virtual-clock-start-ms` is refused before any
/// file -- catalog, suite, or the wall clock -- is touched.
fn build_campaign(args: &RedSwarmCampaignArgs) -> Result<CampaignReportView, CampaignCommandError> {
    let config = build_campaign_config(args)?;
    let report = RedSwarmCampaign::run(&config)
        .map_err(|error| CampaignCommandError::Run(Box::new(error)))?;
    Ok(CampaignReportView::new(&config, report, generated_at_ms()))
}

/// The path a campaign report for `campaign`/`seed` is persisted at, under
/// `base_dir` -- injectable so a test can point this at a temp directory
/// instead of the repo's own `data/` tree (see [`persist_campaign_report`]'s
/// doc). [`run_campaign`], the only production caller, always passes
/// [`DEFAULT_CAMPAIGN_REPORTS_DIR`].
fn campaign_report_path(base_dir: &Path, campaign: &str, seed: u64) -> PathBuf {
    base_dir.join(format!("{campaign}-{seed}.json"))
}

/// Persists `json` (the exact bytes [`render_campaign_json`] produced) to
/// `campaign_report_path(base_dir, ..)`, creating `base_dir` first if it
/// does not exist yet. The only disk WRITE this module performs (see the
/// module doc) -- so a test that must never touch the repo's own `data/`
/// tree calls this directly with a temp directory as `base_dir`, rather
/// than going through [`run_campaign`] (which always passes
/// [`DEFAULT_CAMPAIGN_REPORTS_DIR`]).
fn persist_campaign_report(
    base_dir: &Path,
    view: &CampaignReportView,
    json: &str,
) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(base_dir)?;
    let path = campaign_report_path(base_dir, &view.determinism.campaign, view.determinism.seed);
    std::fs::write(&path, json)?;
    Ok(path)
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

/// Render the campaign report as pretty JSON, mirroring
/// [`render_plan_json`]/[`render_score_json`]. Deterministic apart from
/// `generated_at_ms` (SC 4; see the module doc and [`CampaignReportView`]'s
/// own doc): serde_json emits a struct's fields in declaration order, so
/// identical configs render identical bytes once that one field is
/// stripped.
fn render_campaign_json(view: &CampaignReportView) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(view)
}

/// Render the campaign report as a short human-readable table (the
/// no-`--json` output): the determinism header, one row per generation
/// (its `corpus_sequence_id` and measured numbers), and the stop reason
/// with the final blue catch rate.
fn render_campaign_table(view: &CampaignReportView) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "campaign {} seed {} max_generations {}",
        view.determinism.campaign, view.determinism.seed, view.determinism.max_generations
    );
    let _ = writeln!(
        out,
        "convergence min_delta {} patience {}",
        view.determinism.convergence.min_delta, view.determinism.convergence.patience
    );
    let _ = writeln!(
        out,
        "{:>3}  {:<16}  {:>11}  {:>15}",
        "#", "corpus_sequence_id", "red_fitness", "blue_catch_rate"
    );
    for generation in &view.generations {
        let _ = writeln!(
            out,
            "{:>3}  {:<16}  {:>11}  {:>15}",
            generation.generation,
            generation.corpus_sequence_id,
            generation.red_fitness.red_fitness,
            generation.blue_catch_rate
        );
    }
    let _ = writeln!(out, "stop_reason {:?}", view.stop_reason);
    let _ = writeln!(out, "final_blue_catch_rate {}", view.final_blue_catch_rate);
    out
}

/// Dispatch `red-swarm <subcommand>`: `plan`, `score` or `campaign`.
pub(crate) fn run(args: &RedSwarmArgs, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    match &args.command {
        RedSwarmCommand::Plan(plan_args) => run_plan(plan_args, json),
        RedSwarmCommand::Score(score_args) => run_score(score_args, json),
        RedSwarmCommand::Campaign(campaign_args) => run_campaign(campaign_args, json),
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

/// The `campaign` shell: build the report, and on a missing clock refuse
/// with exit 1 and [`MISSING_CLOCK_MESSAGE`] -- same as [`run_plan`] and
/// [`run_score`] (SC 4). Persists the rendered JSON under
/// [`DEFAULT_CAMPAIGN_REPORTS_DIR`] regardless of `--json` -- persistence
/// is an unconditional side effect of running a campaign, never gated on
/// how the report is printed (see the module doc). Other failures,
/// including [`RedSwarmCampaign::run`]'s own and a persistence I/O
/// failure, surface as errors through the CLI's normal path.
fn run_campaign(args: &RedSwarmCampaignArgs, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let view = match build_campaign(args) {
        Ok(view) => view,
        Err(CampaignCommandError::MissingVirtualClock) => {
            eprintln!("{MISSING_CLOCK_MESSAGE}");
            std::process::exit(1);
        }
        Err(CampaignCommandError::Io(error)) => return Err(error),
        Err(CampaignCommandError::Graph(error)) => return Err(error),
        Err(CampaignCommandError::Run(error)) => return Err(error),
    };
    let rendered_json = render_campaign_json(&view)?;
    persist_campaign_report(
        Path::new(DEFAULT_CAMPAIGN_REPORTS_DIR),
        &view,
        &rendered_json,
    )?;
    if json {
        println!("{rendered_json}");
    } else {
        println!("{}", render_campaign_table(&view));
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

    /// `campaign` args pinned to the real repo catalog and suites, mirroring
    /// `plan_args`/`score_args`. `max_generations` stays small so these
    /// tests run quickly while still exercising the whole loop end to end.
    fn campaign_args(
        seed: u64,
        max_generations: u32,
        virtual_clock_start_ms: Option<i64>,
    ) -> RedSwarmCampaignArgs {
        let root = repo_root();
        RedSwarmCampaignArgs {
            seed,
            campaign: "smoke".to_string(),
            max_generations,
            min_delta: None,
            patience: None,
            strategies: Vec::new(),
            catalog: Some(root.join(DEFAULT_CATALOG)),
            suites: SUITES.iter().map(|rel| root.join(rel)).collect(),
            virtual_clock_start_ms,
            max_events: None,
            max_hosts: None,
            max_technique_repeats: None,
        }
    }

    /// A process-unique DIRECTORY path under the OS temp dir, mirroring
    /// [`unique_temp_path`] but for [`persist_campaign_report`]'s
    /// `base_dir`, which must be a directory it can `create_dir_all` into,
    /// not a single file.
    fn unique_temp_dir(label: &str) -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("red-swarm-campaign-{label}-{suffix}"))
    }

    /// RAII guard for a directory tree written under the OS temp dir,
    /// mirroring [`TempFixture`] but removing a whole directory
    /// (`remove_dir_all`) rather than one file, so a `campaign` persistence
    /// test never leaves a `data/red-swarm/campaigns`-shaped tree under
    /// `/tmp` regardless of how it exits.
    struct TempDirFixture(PathBuf);

    impl TempDirFixture {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDirFixture {
        fn drop(&mut self) {
            // Best-effort, same rationale as `TempFixture`'s `Drop`.
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A fresh, empty temp directory guarded by [`TempDirFixture`]. Never
    /// pre-created here (beyond the guard itself existing): exercising
    /// [`persist_campaign_report`]'s own `create_dir_all` is part of the
    /// point of these tests, matching the real `campaign` code path
    /// against [`DEFAULT_CAMPAIGN_REPORTS_DIR`], which also does not exist
    /// until the first report is persisted.
    fn temp_report_dir(label: &str) -> TempDirFixture {
        TempDirFixture(unique_temp_dir(label))
    }

    #[test]
    fn a_campaign_json_report_is_byte_identical_across_two_runs_after_stripping_generated_at_ms() {
        let args = campaign_args(11, 2, Some(1_700_000_000_000));

        let first = render_campaign_json(&build_campaign(&args).unwrap()).unwrap();
        let second = render_campaign_json(&build_campaign(&args).unwrap()).unwrap();

        let mut first_value: serde_json::Value = serde_json::from_str(&first).unwrap();
        let mut second_value: serde_json::Value = serde_json::from_str(&second).unwrap();
        assert!(
            first_value
                .as_object_mut()
                .unwrap()
                .remove("generated_at_ms")
                .is_some(),
            "the report must carry generated_at_ms before it is stripped"
        );
        assert!(
            second_value
                .as_object_mut()
                .unwrap()
                .remove("generated_at_ms")
                .is_some()
        );

        assert_eq!(
            first_value, second_value,
            "SC4: identical arguments must produce byte-identical report JSON \
             once generated_at_ms is stripped"
        );
    }

    #[test]
    fn dedup_strategies_drops_repeats_and_keeps_first_seen_order() {
        let raw = [
            "kill_chain_sequence".to_string(),
            "suspicious_process_tree".to_string(),
            "kill_chain_sequence".to_string(),
        ];

        let deduped = dedup_strategies(&raw);

        assert_eq!(
            deduped,
            vec![
                "kill_chain_sequence".to_string(),
                "suspicious_process_tree".to_string(),
            ],
            "a repeated id must drop, and the surviving ids must stay in \
             first-seen order rather than sorted order"
        );
    }

    #[test]
    fn a_repeated_strategies_id_yields_the_same_campaign_report_as_passing_it_once() {
        let mut once = campaign_args(11, 2, Some(1_700_000_000_000));
        once.strategies = vec![
            "kill_chain_sequence".to_string(),
            "suspicious_process_tree".to_string(),
        ];
        let mut repeated = campaign_args(11, 2, Some(1_700_000_000_000));
        repeated.strategies = vec![
            "kill_chain_sequence".to_string(),
            "suspicious_process_tree".to_string(),
            "kill_chain_sequence".to_string(),
        ];

        let once_json = render_campaign_json(&build_campaign(&once).unwrap()).unwrap();
        let repeated_json = render_campaign_json(&build_campaign(&repeated).unwrap()).unwrap();

        let mut once_value: serde_json::Value = serde_json::from_str(&once_json).unwrap();
        let mut repeated_value: serde_json::Value = serde_json::from_str(&repeated_json).unwrap();
        once_value
            .as_object_mut()
            .unwrap()
            .remove("generated_at_ms");
        repeated_value
            .as_object_mut()
            .unwrap()
            .remove("generated_at_ms");

        assert_eq!(
            once_value, repeated_value,
            "M2: a --strategies id repeated on the command line must report \
             exactly what passing it once would, once generated_at_ms is stripped"
        );
    }

    #[test]
    fn a_campaign_report_omitting_the_virtual_clock_is_refused_rather_than_defaulting_to_now() {
        let result = build_campaign(&campaign_args(11, 2, None));
        assert!(
            matches!(result, Err(CampaignCommandError::MissingVirtualClock)),
            "a missing --virtual-clock-start-ms must refuse, not run the campaign"
        );
    }

    #[test]
    fn each_generation_view_carries_the_corpus_sequence_id_for_its_own_generation() {
        let view = build_campaign(&campaign_args(5, 3, Some(1_700_000_000_000))).unwrap();

        assert!(
            !view.generations.is_empty(),
            "test needs at least one generation to be meaningful"
        );
        for generation in &view.generations {
            assert_eq!(
                generation.corpus_sequence_id,
                generation_corpus_sequence_id(generation.generation),
                "corpus_sequence_id must reference exactly the generation it labels"
            );
        }
    }

    #[test]
    fn the_campaign_report_carries_the_four_top_level_facts_for_a_small_fixture_campaign() {
        let view = build_campaign(&campaign_args(13, 2, Some(1_700_000_000_000))).unwrap();

        assert!(
            !view.generations.is_empty(),
            "a max_generations >= 1 campaign must run at least one generation"
        );
        assert!(view.generations.len() as u32 <= view.determinism.max_generations);

        let last = view.generations.last().expect("checked non-empty above");
        assert_eq!(
            view.final_blue_catch_rate, last.blue_catch_rate,
            "final_blue_catch_rate must echo the last generation's own blue_catch_rate"
        );

        for generation in &view.generations {
            assert!(
                generation.red_fitness.red_fitness.is_finite(),
                "red_fitness must be finite"
            );
            assert!(
                (0.0..=1.0).contains(&generation.blue_catch_rate),
                "blue_catch_rate must be in [0.0, 1.0], got {}",
                generation.blue_catch_rate
            );
        }
        // `stop_reason` is exhaustively one of three variants by
        // construction (the type system), so there is nothing further to
        // assert about its mere presence -- the interesting property, that
        // it is one of `StopReason`'s variants, cannot fail to hold.
        let _: StopReason = view.stop_reason;
    }

    #[test]
    fn the_campaign_json_carries_generated_at_ms_and_the_determinism_block() {
        let view = build_campaign(&campaign_args(7, 1, Some(1_700_000_000_000))).unwrap();
        let json = render_campaign_json(&view).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(
            value
                .get("generated_at_ms")
                .and_then(|v| v.as_i64())
                .is_some()
        );
        let determinism = value
            .get("determinism")
            .expect("determinism object at the top level");
        assert_eq!(determinism.get("seed").and_then(|v| v.as_u64()), Some(7));
        assert_eq!(
            determinism.get("campaign").and_then(|v| v.as_str()),
            Some("smoke")
        );
        assert_eq!(
            determinism.get("max_generations").and_then(|v| v.as_u64()),
            Some(1)
        );
        assert!(determinism.get("convergence").is_some());

        let generations = value
            .get("generations")
            .and_then(|v| v.as_array())
            .expect("generations array at the top level");
        assert_eq!(generations.len(), 1);
        assert_eq!(
            generations[0]
                .get("corpus_sequence_id")
                .and_then(|v| v.as_str()),
            Some("generation-0")
        );
    }

    #[test]
    fn the_campaign_human_table_lists_stop_reason_and_every_generations_corpus_sequence_id() {
        let view = build_campaign(&campaign_args(7, 2, Some(1_700_000_000_000))).unwrap();
        let table = render_campaign_table(&view);
        assert!(table.contains("stop_reason"));
        assert!(table.contains("final_blue_catch_rate"));
        for generation in &view.generations {
            assert!(table.contains(&generation.corpus_sequence_id));
        }
    }

    #[test]
    fn persisting_a_campaign_report_writes_the_expected_path_under_a_temp_dir_with_matching_content()
     {
        let dir = temp_report_dir("persist");
        let view = build_campaign(&campaign_args(9, 1, Some(1_700_000_000_000))).unwrap();
        let json = render_campaign_json(&view).unwrap();

        let written_path = persist_campaign_report(dir.path(), &view, &json).unwrap();

        assert_eq!(
            written_path,
            campaign_report_path(dir.path(), "smoke", 9),
            "the persisted path must be <base_dir>/<campaign>-<seed>.json"
        );
        assert!(
            !written_path.starts_with(repo_root()),
            "a test must never persist under the repository's own data/ tree"
        );
        let on_disk = std::fs::read_to_string(&written_path).unwrap();
        assert_eq!(
            on_disk, json,
            "the persisted content must match the --json output exactly"
        );
    }

    #[test]
    fn persist_campaign_report_creates_a_base_dir_that_does_not_exist_yet() {
        let dir = temp_report_dir("create-dir");
        assert!(
            !dir.path().exists(),
            "the fixture directory must not exist before persisting"
        );
        let view = build_campaign(&campaign_args(9, 1, Some(1_700_000_000_000))).unwrap();
        let json = render_campaign_json(&view).unwrap();

        persist_campaign_report(dir.path(), &view, &json).unwrap();

        assert!(dir.path().is_dir());
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
