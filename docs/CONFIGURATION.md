# Swarm Team Six: Configuration Reference

> Hunt mission YAML format, tuning parameters, and environment variables.  
> Last updated: 2026-04-02

---

## Hunt Mission YAML Format

Hunt missions are defined in YAML files under `rulesets/`. The swarm assembles from config, not code -- which archetypes participate, how many, what autonomy tiers, pheromone tuning, consensus rules, and NATS connectivity are all declared in the mission file.

The config is loaded at startup and validated fail-closed: invalid configuration rejects at load time, not at runtime. Unknown fields are rejected (`deny_unknown_fields`).

## Rust-First Runtime Additions

The current production slice is much narrower than the historical mission schema below. The live Rust runtime reads these repository-owned sections today:

```yaml
runtime:
  mode: detect_only | live_response
  telemetry_sources:
    - name: synthetic-process
      subject: telemetry.synthetic.process
  max_in_flight_actions: 4
  require_durable_live_response: true

detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.90
  medium_confidence_threshold: 0.70

pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
  backend:
    kind: in_memory | local_journal
    path: data/pheromones.jsonl   # local_journal only

policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000

audit:
  bundle_store:
    kind: memory | local_files
    directory: data/replay        # local_files only
  recent_decisions_limit: 20

investigation:
  enabled: false
  worker_count: 1
  max_pending_jobs: 16
  time_budget_ms: 250
  bundle_store:
    kind: memory | local_files
    directory: data/investigations

correlation:
  enabled: false
  time_window_ms: 300000
  min_shared_keys: 1
  candidate_limit: 32
  incident_store:
    kind: memory | local_files
    directory: data/incidents
```

### Investigation

- `enabled`: turns the async investigation queue on or off without affecting the hot path.
- `worker_count`: concurrency limit for background investigation workers.
- `max_pending_jobs`: queue depth before new submissions degrade visibly as async failures instead of blocking response execution.
- `time_budget_ms`: hard timeout per investigation job.
- `bundle_store`: where durable investigation bundles are written for later review and correlation.

### Correlation

- `enabled`: turns incident assembly on or off.
- `time_window_ms`: maximum age difference allowed between investigation bundles considered for one incident.
- `min_shared_keys`: minimum overlapping correlation keys required for inclusion.
- `candidate_limit`: how many recent investigation bundles to scan when assembling one incident.
- `incident_store`: where correlated incidents are persisted for operator review.

### Operator Review Surface

`RuntimeService::operator_review_status` combines the original hot-path report with:

- investigation queue state, including `last_failure_reason`
- recent persisted investigation summaries and status
- recent incidents and linked hunt IDs
- freshness markers for hot-path decisions, investigation updates, and incidents

Degraded investigation or incident stores surface as warnings in the operator report. They do not block startup in this milestone.

### Operator Control CLI

The repo now ships a CLI-backed control surface in `swarmctl` for runtime review and stable-ID artifact lookup.

Examples:

```bash
cargo run -p swarm-runtime --bin swarmctl -- status --config rulesets/default.yaml
cargo run -p swarm-runtime --bin swarmctl -- --json replay --receipt-id receipt-123 --config rulesets/default.yaml
cargo run -p swarm-runtime --bin swarmctl -- investigation --hunt-id evt-123 --config rulesets/default.yaml
cargo run -p swarm-runtime --bin swarmctl -- incident --incident-id incident:evt-123:1 --config rulesets/default.yaml
```

The CLI labels output by origin:

- `live_runtime_status`: current operator review report from the configured runtime stack
- `persisted_runtime_artifact`: replay, investigation, or incident artifacts loaded from durable runtime stores
- `offline_replay_artifact`: reserved for the offline replay workflows added in later milestones

### Offline Replay Harness

The repo now ships a deterministic offline replay harness. It uses the same Rust detector, policy, and receipt types as the production runtime, but forces `detect_only` execution so no live response action is executed.

Repo-owned scenarios live under `scenarios/`:

- `scenarios/office-dropper-correlation.yaml`
- `scenarios/benign-baseline.yaml`
- `scenarios/pdf-lolbin-execution.yaml`
- `scenarios/python-maintenance-benign.yaml`

Scenario manifests now carry explicit offline corpus metadata:

- `metadata.class`: `adversarial`, `benign`, or `mixed`
- `metadata.campaign`: campaign or operator workflow label
- `metadata.techniques`: MITRE ATT&CK technique IDs or internal technique labels
- `metadata.tags`: free-form suite or debugging tags

Named suite manifests live under `scenario-suites/` and point at repo-owned scenario manifests:

- `scenario-suites/hellcat-office-v1.yaml`

Replay results are written under `data/replay-runs/` by default.

Examples:

```bash
cargo run -p swarm-runtime --bin swarmctl -- replay-run --scenario scenarios/office-dropper-correlation.yaml
cargo run -p swarm-runtime --bin swarmctl -- replay-result --scenario scenarios/office-dropper-correlation.yaml
cargo run -p swarm-runtime --bin swarmctl -- --json replay-result --run-id replay_run:office_dropper_correlation:1700000100000
```

Scenario manifests currently support two input modes:

- `kind: events`: inline fixture telemetry plus the response action to request for each step
- `kind: replay_bundles`: one or more persisted replay bundle JSON files that should be re-run offline

The durable replay run bundle captures:

- replay bundles produced by the offline run
- deterministic inline investigation artifacts
- deterministic correlated incidents
- a stable summary for repeatability checks
- measured stage latency snapshots for later regression gates

### Replay Evaluation And Gates

Replay evaluation compares replay-run bundles against the expectations embedded in each scenario manifest, including hunt-level policy or response outcomes, incident grouping, and hot-path latency thresholds.

Examples:

```bash
cargo run -p swarm-runtime --bin swarmctl -- replay-evaluate --scenario scenarios/office-dropper-correlation.yaml
cargo run -p swarm-runtime --bin swarmctl -- replay-evaluate --run-id replay_run:office_dropper_correlation:1700000100000
cargo run -p swarm-runtime --bin swarmctl -- replay-evaluate --scenarios-dir scenarios
cargo run -p swarm-runtime --bin swarmctl -- replay-evaluate --suite scenario-suites/hellcat-office-v1.yaml
```

Failure behavior:

- `replay-evaluate` exits nonzero when any expectation or latency threshold fails
- `--scenarios-dir` evaluates the full tracked corpus and is intended for local or CI gating
- `--suite` evaluates one named replay suite and aggregates pass/fail status by scenario and technique group

End-to-end flow:

1. Run one tracked scenario with `replay-run`.
2. Inspect the persisted result bundle with `replay-result`.
3. Validate one scenario with `replay-evaluate --scenario ...`.
4. Validate one named suite with `replay-evaluate --suite scenario-suites/hellcat-office-v1.yaml`.
5. Gate the whole tracked corpus with `replay-evaluate --scenarios-dir scenarios`.

The runtime test suite also includes a tracked-scenario regression test in `swarm-runtime` so the repo corpus acts as an executable baseline.

### Detector Experiments

Offline baseline-vs-candidate detector experiments are defined under `experiments/`. Each manifest references one suite manifest, one candidate detector profile, lineage metadata, and offline gate thresholds.

Tracked manifests:

- `experiments/office-baseline-control.yaml` — control candidate matching production behavior
- `experiments/office-python-parent-broadening.yaml` — intentionally broader candidate that should fail the false-positive gate

Experiment results are written under `data/experiments/` by default.

Examples:

```bash
cargo run -p swarm-runtime --bin swarmctl -- experiment-evaluate --experiment experiments/office-baseline-control.yaml
cargo run -p swarm-runtime --bin swarmctl -- experiment-evaluate --experiment experiments/office-python-parent-broadening.yaml
cargo run -p swarm-runtime --bin swarmctl -- experiment-result --experiment-id experiment:office_baseline_control:office_baseline_control
```

What the experiment report captures:

- baseline and candidate suite reports over the same replay corpus
- aggregate detection rate, false positive rate, and detect-latency comparisons
- lineage metadata (`parent_strategy_id`, mutation, rationale)
- scenario regressions and technique regressions
- offline gate verdicts for known-bad coverage, false-positive delta, and detect-latency delta

Failure behavior:

- `experiment-evaluate` exits nonzero when any offline experiment gate fails
- the persisted experiment report can still be loaded later with `experiment-result`

### Verification Corpora

Repo-owned detector verification inputs now live under `verifications/`. A verification corpus defines the invariant inputs that later candidate-gating and promotion-review workflows use.

Tracked corpora:

- `verifications/office-detector-safety-v1.yaml`

Each verification corpus currently records:

- `known_bad.suite`: the named replay suite the candidate must continue to cover
- `benign_controls.scenarios`: explicit benign scenarios used for false-positive inspection
- `canonical_templates`: one or more threat-class templates the detector must still match
- `resource_budgets`: repo-owned thresholds such as max false-positive rate, max detect latency, and max total detections

Existing experiment manifests now bind to one verification corpus through:

```yaml
verification:
  corpus: ../verifications/office-detector-safety-v1.yaml
```

This keeps canonical verification inputs in tracked YAML instead of hardcoded tests and gives later phases one stable contract for per-invariant pass or fail reporting.

### Verification Gate

Candidate verification runs the experiment's candidate detector against the repo-owned verification corpus and emits per-invariant pass or fail output.

Verification results are written under `data/verifications/` by default.

Examples:

```bash
cargo run -p swarm-runtime --bin swarmctl -- verification-evaluate --experiment experiments/office-baseline-control.yaml
cargo run -p swarm-runtime --bin swarmctl -- verification-evaluate --experiment experiments/office-python-parent-broadening.yaml
cargo run -p swarm-runtime --bin swarmctl -- verification-result --verification-id verification:office_baseline_control:office_baseline_control:office_detector_safety_v1
```

Current invariant set:

- `known_bad_coverage`: candidate must not miss tracked adversarial verification scenarios
- `threat_class_templates`: candidate must still match canonical threat-class templates
- `false_positive_bound`: candidate must stay under the repo-owned benign false-positive threshold
- `detect_latency_budget`: candidate max detect latency must stay within the corpus budget
- `total_detection_budget`: candidate total emitted detections must stay within the corpus volume budget

Failure behavior:

- `verification-evaluate` exits nonzero when any invariant fails
- failing output preserves scenario or template references for operator inspection

### Offline Shadow

Offline shadow reuses the same baseline-vs-candidate replay comparison as the experiment flow, but persists the result as a dedicated shadow artifact for later promotion review.

Shadow results are written under `data/shadows/` by default.

Examples:

```bash
cargo run -p swarm-runtime --bin swarmctl -- shadow-evaluate --experiment experiments/office-baseline-control.yaml
cargo run -p swarm-runtime --bin swarmctl -- shadow-result --shadow-id shadow:office_baseline_control:office_baseline_control:2026-04-03
```

Shadow reports capture:

- baseline-vs-candidate detection-rate delta
- false-positive-rate delta
- detect-latency delta
- the replay artifacts used as the comparison window
- pass or fail shadow gates derived from the experiment manifest thresholds

Failure behavior:

- `shadow-evaluate` exits nonzero when the candidate fails the offline shadow gates
- shadow execution remains fully offline and never emits live pheromones or response actions

### Promotion Review Packets

Promotion review packets assemble one candidate experiment, one persisted verification artifact, and one persisted shadow artifact into a durable manual-review handoff.

Promotion review packets are written under `data/promotion-reviews/` by default.

Examples:

```bash
cargo run -p swarm-runtime --bin swarmctl -- promotion-review-create --experiment experiments/office-baseline-control.yaml --verification-id verification:office_baseline_control:office_baseline_control:office_detector_safety_v1 --shadow-id shadow:office_baseline_control:office_baseline_control:2026-04-03
cargo run -p swarm-runtime --bin swarmctl -- promotion-review-result --review-id promotion_review:office_baseline_control:office_baseline_control:2026-04-03
```

Packets capture:

- candidate lineage and description from the experiment manifest
- stable verification and shadow IDs
- shadow deltas for detection rate, false-positive rate, and detect latency
- a `ready_for_manual_review` or `blocked` recommendation
- blocking reasons derived from failed verification invariants or failed shadow gates

This remains an operator review surface only. The packet does not approve, deploy, or promote anything automatically.

### Bounded Canary

Bounded canary extends the runtime from offline shadow into a scoped live detector lane. The candidate detector is admitted only after verification and shadow have already passed, and its findings remain inside a dedicated canary artifact instead of affecting the production substrate.

Repo-owned canary settings now live in `rulesets/default.yaml`:

```yaml
canary:
  enabled: true
  slot_id: canary-primary
  observation_window_events: 2
  max_candidate_only_rate: 0.25
  max_baseline_miss_rate: 0.25
  max_detect_latency_us: 10000
  max_total_detections: 8
```

Current canary inputs and semantics:

- `slot_id`: stable identifier for the single bounded canary lane
- `observation_window_events`: how many live events the candidate must survive before the run can complete normally
- `max_candidate_only_rate`: conservative false-positive proxy bound, based on candidate-only detections versus the production baseline
- `max_baseline_miss_rate`: bound on how often the candidate misses a detection that the baseline still produces
- `max_detect_latency_us`: maximum candidate detect latency over the canary window
- `max_total_detections`: resource budget for total candidate detections over the window

Canary artifacts are written under `data/canaries/` by default.

Example operator flow:

```bash
cargo run -p swarm-runtime --bin swarmctl -- verification-evaluate --experiment experiments/office-baseline-control.yaml
cargo run -p swarm-runtime --bin swarmctl -- shadow-evaluate --experiment experiments/office-baseline-control.yaml

cargo run -p swarm-runtime --bin swarmctl -- canary-start \
  --experiment experiments/office-baseline-control.yaml \
  --verification-id verification:office_baseline_control:office_baseline_control:office_detector_safety_v1 \
  --shadow-id shadow:office_baseline_control:office_baseline_control:office_detector_safety_v1

cargo run -p swarm-runtime --bin swarmctl -- canary-event \
  --run-id YOUR_CANARY_RUN_ID \
  --event fixtures/canary/word-powershell.yaml

cargo run -p swarm-runtime --bin swarmctl -- canary-event \
  --run-id YOUR_CANARY_RUN_ID \
  --event fixtures/canary/outlook-cmd.yaml

cargo run -p swarm-runtime --bin swarmctl -- canary-result --run-id YOUR_CANARY_RUN_ID
```

Automatic failure behavior:

- `canary-event` exits nonzero when the canary auto-rolls back on a threshold or budget violation
- rollback history preserves the trigger, reason, slot ID, and reverted baseline strategy
- the final canary artifact carries an `observing`, `ready_for_promotion_review`, or `blocked` recommendation

Manual operator actions:

```bash
cargo run -p swarm-runtime --bin swarmctl -- canary-halt --run-id YOUR_CANARY_RUN_ID --reason "operator requested stop"
cargo run -p swarm-runtime --bin swarmctl -- canary-rollback --run-id YOUR_CANARY_RUN_ID --reason "candidate diverged from baseline"
```

This milestone still stops short of fleet-wide promotion. The canary artifact is the handoff into the next decision step, not the promotion itself.

### Controlled Production Promotion

Controlled production promotion extends the staged rollout from canary into the production detector role. Promotion starts from a completed canary artifact that is already `ready_for_promotion_review`, rotates the promoted detector into the production lane, retains the previous production detector as the rollback target, and observes the promoted detector through a bounded production window.

Repo-owned promotion settings now live in `rulesets/default.yaml`:

```yaml
promotion:
  enabled: true
  window_id: production-primary
  observation_window_events: 2
  max_promoted_only_rate: 0.20
  max_fallback_recovery_rate: 0.20
  max_detect_latency_us: 10000
  max_total_detections: 12
```

Current promotion inputs and semantics:

- `window_id`: stable identifier for the active production observation window
- `observation_window_events`: how many live events the promoted detector must survive before the promotion can complete normally
- `max_promoted_only_rate`: divergence bound for promoted-only detections versus the retained fallback baseline
- `max_fallback_recovery_rate`: bound on how often the retained fallback baseline still detects activity that the promoted detector misses
- `max_detect_latency_us`: maximum promoted detect latency during the observation window
- `max_total_detections`: resource budget for total promoted detections over the production window

Production-promotion artifacts are written under `data/promotions/` by default.

Example operator flow:

```bash
cargo run -p swarm-runtime --bin swarmctl -- canary-result --run-id YOUR_CANARY_RUN_ID

cargo run -p swarm-runtime --bin swarmctl -- promotion-start \
  --canary-run-id YOUR_CANARY_RUN_ID

cargo run -p swarm-runtime --bin swarmctl -- promotion-event \
  --promotion-id YOUR_PROMOTION_ID \
  --event fixtures/canary/word-powershell.yaml

cargo run -p swarm-runtime --bin swarmctl -- promotion-event \
  --promotion-id YOUR_PROMOTION_ID \
  --event fixtures/canary/outlook-cmd.yaml

cargo run -p swarm-runtime --bin swarmctl -- promotion-result --promotion-id YOUR_PROMOTION_ID
```

Automatic failure behavior:

- `promotion-event` exits nonzero when the promoted detector auto-rolls back on a threshold or budget violation
- rollback history preserves the trigger, reason, restored baseline strategy, and observed event count
- the final promotion artifact carries an `observing`, `stable_in_production`, or `blocked` recommendation

Manual operator actions:

```bash
cargo run -p swarm-runtime --bin swarmctl -- promotion-halt --promotion-id YOUR_PROMOTION_ID --reason "operator requested stop"
cargo run -p swarm-runtime --bin swarmctl -- promotion-rollback --promotion-id YOUR_PROMOTION_ID --reason "promoted detector diverged from fallback baseline"
```

This milestone still stops short of quorum governance or partial-fleet rollout. The production-promotion artifact is the bounded single-node promotion record, not a distributed approval system.

### Complete Field Reference

Below is the full schema, documented field by field. The reference configuration is `rulesets/default.yaml`.

```yaml
# ─── Mission Identity ───────────────────────────────────────────────

name: default
# Required. String.
# A short identifier for this mission. Used in log prefixes, NATS subject
# namespacing, and audit trail tagging. Must be unique across concurrent missions.

description: Standard threat hunting mission
# Required. String.
# Human-readable description of the mission's purpose and scope.

# ─── Agent Population ───────────────────────────────────────────────

population:
  # Required. Map of agent role -> population config.
  # Defines how many of each archetype to spawn and their autonomy tier.
  # All 8 archetypes may be specified. Omitted archetypes will not be spawned.

  whisker:
    count: 4
    # Required. Integer >= 0.
    # Number of Whisker agents to spawn at mission start.
    # Whiskers are the primary detection layer. More Whiskers = more telemetry
    # coverage, but each consumes a NATS subscription and CPU for embedding
    # similarity computation. 4 is a good baseline for moderate telemetry volume.

    max_count: 16
    # Required. Integer >= count.
    # Maximum Whiskers the swarm can auto-scale to during Alert/Incident modes.
    # The Dispatcher spawns additional Whiskers when pheromone concentration
    # indicates elevated threat activity.

    tier: tier1
    # Required. One of: tier1, tier2, tier3.
    # Autonomy tier governing what this archetype can do without human approval.
    # tier1: Fully autonomous (routine detection, IOC matching).
    # tier2: Autonomous with reporting (novel detections, hypothesis generation).
    # tier3: Human-approved (response actions, policy changes).

  stalker:
    count: 2
    max_count: 8
    tier: tier2
    # Stalkers investigate leads from Whisker pheromones using LLM-powered
    # hypothesis-driven reasoning. 2 is sufficient for low-to-moderate alert
    # volume. Auto-scales up during active incidents.

  weaver:
    count: 1
    max_count: 4
    tier: tier2
    # Weavers correlate signals across investigations using multi-graph memory.
    # 1 is typically sufficient -- Weavers process aggregated data, not raw
    # telemetry. Scale up only for very high investigation concurrency.

  pouncer:
    count: 1
    max_count: 4
    tier: tier3
    # Pouncers execute response actions (block, isolate, revoke). Always tier3
    # because response actions require BFT consensus from the Tom committee.
    # 1 is sufficient; multiple Pouncers allow parallel response execution
    # during multi-front incidents.

  tom:
    count: 3
    max_count: 5
    tier: tier3
    # Toms govern the swarm: enforce policy, manage lifecycle, run BFT consensus.
    # Minimum 3 for BFT with f=1 (need 2f+1=3 votes out of 3f+1=4 eligible,
    # but 3 Toms can tolerate 0 Byzantine faults with 3/3 agreement).
    # For f=1 tolerance, use 4+ Toms. The default of 3 is minimum viable.
    # max_count should be odd for clean majority thresholds.

  kitten:
    count: 1
    max_count: 2
    tier: tier2
    # Kittens evolve detection strategies via mutation + Z3 verification.
    # 1 is sufficient for most missions. 2 allows parallel exploration of
    # different mutation strategies.

  sphinx:
    count: 1
    max_count: 1
    tier: tier1
    # Sphinx maintains long-term threat memory and the knowledge graph.
    # Singleton by design -- multiple Sphinxes would need graph synchronization.
    # max_count: 1 is intentional.

  calico:
    count: 1
    max_count: 2
    tier: tier1
    # Calico manages deception infrastructure (honeypots, canary tokens).
    # tier1 because deploying deception assets is low-risk and autonomous.
    # Scale up for environments with many deception zones.

# ─── Pheromone Substrate ────────────────────────────────────────────

pheromone:
  # Required. Tunes the stigmergic communication layer.

  default_half_life_secs: 3600
  # Required. Float > 0. Default: 3600 (1 hour).
  # Default exponential decay half-life for pheromone deposits.
  # After this many seconds, a deposit's effective strength is halved.
  #
  # Shorter half-life (e.g., 900 = 15 min): signals fade fast, swarm focuses
  # on recent activity. Good for high-velocity environments.
  # Longer half-life (e.g., 86400 = 24 hrs): signals persist, swarm maintains
  # awareness of older threats. Good for slow-burn APT detection.
  #
  # Individual deposits can override this with their own decay_half_life.

  evaporation_threshold: 0.01
  # Required. Float > 0, < 1. Default: 0.01.
  # Effective strength below which a pheromone is garbage-collected.
  # At default settings (half_life=3600, threshold=0.01), a deposit fully
  # evaporates after approximately 6.6 half-lives = 6.6 hours.
  #
  # Lower values keep faint signals longer (more memory, more noise).
  # Higher values aggressively prune (less memory, risk losing slow signals).

  min_sources_for_escalation: 2
  # Required. Integer >= 1. Default: 2.
  # Minimum number of distinct agents that must contribute deposits to a
  # threat class before concentration can trigger mode escalation.
  # Prevents a single agent from flooding a threat class and causing a
  # false escalation. Set to 1 only if you trust individual agent signals.

  alert_threshold: 2.0
  # Required. Float > 0. Default: 2.0.
  # Pheromone concentration (sum of effective strengths from distinct sources)
  # that triggers Normal -> Alert mode transition.
  # Lower values = more sensitive (more alerts, more false positives).
  # Higher values = less sensitive (fewer alerts, risk missing threats).

  incident_threshold: 5.0
  # Required. Float > alert_threshold. Default: 5.0.
  # Concentration that triggers Alert -> Incident mode transition.
  # Incident mode unlocks Pouncers and focuses all agents.
  # This should be significantly above alert_threshold to prevent
  # premature incident declaration.

# ─── Consensus ──────────────────────────────────────────────────────

consensus:
  # Required. BFT consensus settings for the Tom committee.

  max_byzantine_faults: 1
  # Required. Integer >= 0. Default: 1.
  # Maximum Byzantine faults the consensus protocol tolerates.
  # With f=1, the protocol needs 3f+1=4 total voters and 2f+1=3 approvals.
  # Ensure tom.count >= 2f+1. If tom.count < 2f+1, consensus cannot
  # be reached and response actions will be blocked (fail-closed).
  #
  # f=0: No fault tolerance. All Toms must agree. Fast but fragile.
  # f=1: Tolerates 1 compromised/failed Tom. Minimum for production.
  # f=2: Tolerates 2 faults. Requires 7 Toms (3f+1). High resilience.

  round_timeout_ms: 5000
  # Required. Integer > 0. Default: 5000 (5 seconds).
  # Timeout for a single consensus round (propose + prevote + precommit).
  # If consensus is not reached within this window, the round fails and
  # can be retried with a view change.
  #
  # Lower timeout: faster response but more likely to fail under load.
  # Higher timeout: more tolerant of slow Toms but delays response actions.

  committee_rotation_interval_secs: 3600
  # Required. Integer > 0. Default: 3600 (1 hour).
  # How often the Tom committee membership rotates via VRF.
  # Rotation prevents a persistent attacker from targeting specific Toms.
  # Shorter intervals increase security but cause more state transitions.

# ─── Autonomy Tiers ────────────────────────────────────────────────

autonomy:
  # Required. Defines the confidence boundaries between autonomy tiers.

  tier1_confidence: 0.9
  # Required. Float in (0, 1]. Default: 0.9.
  # Minimum confidence for an action to qualify as Tier 1 (fully autonomous).
  # Actions below this confidence are escalated to Tier 2.
  # High values (0.9+) mean only very confident detections are autonomous.

  tier2_confidence: 0.7
  # Required. Float in (0, tier1_confidence). Default: 0.7.
  # Minimum confidence for Tier 2 (autonomous with reporting).
  # Actions below this confidence are escalated to Tier 3 (human approval).
  # The gap between tier2 and tier1 is the "report but proceed" band.

  require_human_above_severity: critical
  # Required. One of: low, medium, high, critical. Default: critical.
  # Regardless of confidence, any finding at or above this severity
  # requires human approval before response actions.
  # Set to "low" to require human approval for everything (conservative).
  # Set to "critical" to only require humans for the worst threats.

# ─── NATS Connection ───────────────────────────────────────────────

nats:
  # Required. NATS server connection and subject configuration.

  servers:
    - "nats://localhost:4222"
  # Required. List of NATS server URLs.
  # For production, provide multiple servers for cluster failover:
  #   - "nats://nats-1.internal:4222"
  #   - "nats://nats-2.internal:4222"
  #   - "nats://nats-3.internal:4222"

  subject_prefix: "swarm"
  # Required. String. Default: "swarm".
  # Prefix for all NATS subjects used by this mission.
  # Change this to run multiple isolated swarm instances on the same
  # NATS cluster: e.g., "swarm-prod", "swarm-staging", "swarm-test".

  pheromone_stream: "swarm-pheromones"
  # Required. String. Default: "swarm-pheromones".
  # JetStream stream name for pheromone persistence.
  # Must be unique per mission if running multiple swarms on the same cluster.
```

---

## Environment Variables

Environment variables override YAML config for deployment flexibility. They are prefixed with `STS_` (Swarm Team Six).

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `STS_CONFIG_PATH` | Path | `rulesets/default.yaml` | Path to the hunt mission YAML file |
| `STS_NATS_SERVERS` | Comma-separated URLs | `nats://localhost:4222` | NATS server URLs (overrides `nats.servers`) |
| `STS_NATS_CREDS` | Path | (none) | Path to NATS credentials file for authenticated connections |
| `STS_NATS_TLS_CERT` | Path | (none) | Path to TLS certificate for NATS |
| `STS_NATS_TLS_KEY` | Path | (none) | Path to TLS private key for NATS |
| `STS_SUBJECT_PREFIX` | String | `swarm` | NATS subject prefix (overrides `nats.subject_prefix`) |
| `STS_LOG_LEVEL` | String | `info` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `STS_LOG_FORMAT` | String | `pretty` | Log format: `pretty` (human), `json` (structured) |
| `STS_ANTHROPIC_API_KEY` | String | (required) | Anthropic API key for Stalker/Weaver/Kitten LLM calls |
| `STS_ANTHROPIC_MODEL` | String | `claude-sonnet-4-20250514` | Model ID for LLM-backed agents |
| `STS_SPIDER_SENSE_PATTERNS` | Path | `builtin:s2bench-v1` | Path to Spider Sense pattern DB (or `builtin:` prefix for embedded) |
| `STS_KEYSTORE_PATH` | Path | (in-memory) | Path to persist agent keypairs. If unset, keys are ephemeral. |
| `STS_MEMORY_BACKEND` | String | `memory` | Knowledge graph backend: `memory`, `sqlite`, `neo4j`, `kuzudb` |
| `STS_MEMORY_DSN` | String | (none) | Connection string for graph database (required for `neo4j`/`kuzudb`) |
| `STS_Z3_TIMEOUT_MS` | Integer | `30000` | Z3 solver timeout for strategy verification |
| `STS_EVOLUTION_CADENCE` | String | `adaptive` | Evolution trigger: `continuous`, `hourly`, `daily`, `adaptive` |
| `STS_RED_SWARM_ENABLED` | Boolean | `false` | Enable the Hellcat red swarm for co-evolutionary training |
| `STS_RED_SWARM_SANDBOX` | Path | (none) | Path to sandboxed target environment for red swarm |

---

## Example Configurations

### Aggressive Hunting

For environments with known active threats where speed matters more than false positive avoidance. High Whisker density, sensitive pheromone thresholds, fast consensus.

```yaml
name: aggressive-hunt
description: Active threat hunting — high sensitivity, fast response

population:
  whisker:
    count: 8
    max_count: 16
    tier: tier1
  stalker:
    count: 4
    max_count: 8
    tier: tier2
  weaver:
    count: 2
    max_count: 4
    tier: tier2
  pouncer:
    count: 2
    max_count: 4
    tier: tier3
  tom:
    count: 5
    max_count: 5
    tier: tier3
  kitten:
    count: 1
    max_count: 2
    tier: tier2
  sphinx:
    count: 1
    max_count: 1
    tier: tier1
  calico:
    count: 2
    max_count: 2
    tier: tier1

pheromone:
  default_half_life_secs: 1800     # 30 min — focus on recent activity
  evaporation_threshold: 0.05      # Aggressive pruning
  min_sources_for_escalation: 1    # Single-agent escalation allowed
  alert_threshold: 1.0             # Very sensitive
  incident_threshold: 3.0          # Low bar for incident declaration

consensus:
  max_byzantine_faults: 1
  round_timeout_ms: 2000           # Fast consensus rounds
  committee_rotation_interval_secs: 1800  # Rotate every 30 min

autonomy:
  tier1_confidence: 0.8            # Lower bar for autonomous action
  tier2_confidence: 0.5            # Lower bar for autonomous + report
  require_human_above_severity: critical

nats:
  servers:
    - "nats://localhost:4222"
  subject_prefix: "swarm"
  pheromone_stream: "swarm-pheromones"
```

**Key differences from default:**
- `min_sources_for_escalation: 1` -- a single Whisker detection can trigger escalation. Trades false positive risk for speed.
- `alert_threshold: 1.0` -- the swarm enters Alert mode quickly.
- `tier1_confidence: 0.8` -- more actions qualify as fully autonomous.
- `round_timeout_ms: 2000` -- consensus rounds complete in 2 seconds.
- Double the Whiskers and Stalkers for broader and deeper coverage.

---

### Passive Monitoring

For production environments where stability matters and the swarm should observe without acting. No Pouncers, high confidence requirements, long pheromone persistence.

```yaml
name: passive-monitor
description: Observation only — detect and report, no response actions

population:
  whisker:
    count: 4
    max_count: 8
    tier: tier1
  stalker:
    count: 1
    max_count: 4
    tier: tier2
  weaver:
    count: 1
    max_count: 2
    tier: tier2
  pouncer:
    count: 0              # No Pouncers — observe only
    max_count: 0
    tier: tier3
  tom:
    count: 3
    max_count: 3
    tier: tier3
  kitten:
    count: 0              # No evolution — stable detection
    max_count: 0
    tier: tier2
  sphinx:
    count: 1
    max_count: 1
    tier: tier1
  calico:
    count: 0              # No deception assets
    max_count: 0
    tier: tier1

pheromone:
  default_half_life_secs: 86400    # 24 hours — long memory
  evaporation_threshold: 0.001     # Keep faint signals
  min_sources_for_escalation: 3    # High source diversity required
  alert_threshold: 4.0             # High bar for alert
  incident_threshold: 10.0         # Very high bar for incident

consensus:
  max_byzantine_faults: 1
  round_timeout_ms: 10000          # Generous timeout
  committee_rotation_interval_secs: 7200

autonomy:
  tier1_confidence: 0.95           # Very high bar for autonomous action
  tier2_confidence: 0.85           # High bar for autonomous + report
  require_human_above_severity: medium  # Human required for medium+

nats:
  servers:
    - "nats://localhost:4222"
  subject_prefix: "swarm"
  pheromone_stream: "swarm-pheromones"
```

**Key differences from default:**
- Pouncers, Kittens, and Calicos set to 0 -- no response, no evolution, no deception.
- `default_half_life_secs: 86400` -- pheromones persist for a full day, enabling slow-burn APT pattern detection.
- `min_sources_for_escalation: 3` -- requires 3 independent agents to confirm before escalation.
- `require_human_above_severity: medium` -- almost everything needs human sign-off.
- This configuration is useful for initial deployment where you want to validate detection quality before enabling response.

---

### Red Team Exercise

For running co-evolutionary training with the Hellcat red swarm enabled. The blue swarm detects while the red swarm attacks a sandboxed environment. Kittens actively evolve.

```yaml
name: red-team-exercise
description: Co-evolutionary training — blue vs red swarm arms race

population:
  whisker:
    count: 6
    max_count: 12
    tier: tier1
  stalker:
    count: 3
    max_count: 6
    tier: tier2
  weaver:
    count: 2
    max_count: 4
    tier: tier2
  pouncer:
    count: 1
    max_count: 2
    tier: tier3
  tom:
    count: 4
    max_count: 5
    tier: tier3
  kitten:
    count: 2              # More Kittens for faster evolution
    max_count: 2
    tier: tier2
  sphinx:
    count: 1
    max_count: 1
    tier: tier1
  calico:
    count: 1
    max_count: 2
    tier: tier1

pheromone:
  default_half_life_secs: 7200     # 2 hours
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0

consensus:
  max_byzantine_faults: 1
  round_timeout_ms: 5000
  committee_rotation_interval_secs: 1800  # Faster rotation for exercise

autonomy:
  tier1_confidence: 0.9
  tier2_confidence: 0.7
  require_human_above_severity: critical

nats:
  servers:
    - "nats://localhost:4222"
  subject_prefix: "swarm-redteam"   # Isolated prefix
  pheromone_stream: "swarm-redteam-pheromones"
```

**Environment variables for this scenario:**

```bash
export STS_CONFIG_PATH=rulesets/red-team-exercise.yaml
export STS_RED_SWARM_ENABLED=true
export STS_RED_SWARM_SANDBOX=/path/to/sandboxed-target
export STS_EVOLUTION_CADENCE=adaptive   # Evolve on red swarm evasion events
export STS_Z3_TIMEOUT_MS=60000          # Longer Z3 timeout for complex strategies
export STS_SUBJECT_PREFIX=swarm-redteam
export STS_LOG_LEVEL=debug              # Verbose logging for exercise analysis
export STS_LOG_FORMAT=json              # Structured logs for post-exercise analysis
```

**Key differences from default:**
- `STS_RED_SWARM_ENABLED=true` -- activates the Hellcat red swarm.
- 2 Kittens for parallel strategy exploration.
- 4 Toms for proper BFT with f=1 (need 4 voters for 3 approvals).
- Isolated NATS prefix (`swarm-redteam`) to prevent interference with production.
- `STS_EVOLUTION_CADENCE=adaptive` -- Kittens evolve when red swarm evasion events are detected, not on a fixed schedule.

---

## Parameter Tuning Guide

### Pheromone Tuning

The pheromone parameters control the swarm's collective sensitivity. They interact with each other:

| Want | Adjust |
|------|--------|
| Faster response to new threats | Lower `alert_threshold`, lower `min_sources_for_escalation` |
| Fewer false escalations | Raise `min_sources_for_escalation`, raise `alert_threshold` |
| Detect slow/persistent threats | Raise `default_half_life_secs`, lower `evaporation_threshold` |
| Focus on recent activity only | Lower `default_half_life_secs`, raise `evaporation_threshold` |
| More aggressive garbage collection | Raise `evaporation_threshold` |

**Effective signal lifetime** (time until a deposit is garbage-collected):

```
lifetime = half_life * log2(initial_confidence / evaporation_threshold)
```

With defaults (half_life=3600, confidence=1.0, threshold=0.01):
`3600 * log2(1.0 / 0.01) = 3600 * 6.64 = 23,918 seconds = ~6.6 hours`

### Consensus Tuning

| Voters (Toms) | max_byzantine_faults (f) | Quorum (2f+1) | Fault Tolerance |
|---------------|--------------------------|---------------|-----------------|
| 3 | 0 | 3 (unanimous) | None — any failure blocks consensus |
| 4 | 1 | 3 | 1 Byzantine or crashed Tom |
| 5 | 1 | 3 | 1 Byzantine, survives 2 crashes |
| 7 | 2 | 5 | 2 Byzantine or crashed Toms |

Rule of thumb: set `tom.count >= 3 * max_byzantine_faults + 1`.

### Population Scaling

Agent counts should match telemetry volume and investigation complexity:

| Telemetry Volume | Whiskers | Stalkers | Notes |
|-----------------|----------|----------|-------|
| Low (<1K events/sec) | 2-4 | 1-2 | Development or small environments |
| Medium (1K-10K events/sec) | 4-8 | 2-4 | Typical production |
| High (10K-100K events/sec) | 8-16 | 4-8 | Large-scale or high-security |
| Very High (>100K events/sec) | 16+ | 8+ | Consider multiple swarm instances |

Weavers scale with investigation concurrency, not telemetry volume. 1 Weaver handles up to ~50 concurrent investigations. Sphinx is always a singleton.
