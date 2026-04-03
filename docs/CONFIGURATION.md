# Swarm Team Six: Configuration Reference

> Hunt mission YAML format, tuning parameters, and environment variables.  
> Last updated: 2026-04-02

---

## Hunt Mission YAML Format

Hunt missions are defined in YAML files under `rulesets/`. The swarm assembles from config, not code -- which archetypes participate, how many, what autonomy tiers, pheromone tuning, consensus rules, and NATS connectivity are all declared in the mission file.

The config is loaded at startup and validated fail-closed: invalid configuration rejects at load time, not at runtime. Unknown fields are rejected (`deny_unknown_fields`).

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
