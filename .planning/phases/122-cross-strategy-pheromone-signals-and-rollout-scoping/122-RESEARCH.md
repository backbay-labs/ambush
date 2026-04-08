# Phase 122 Research: Cross-Strategy Pheromone Signals And Rollout Scoping

## Goal

Plan Phase 122 around three concrete changes:

1. Detection deposits from different strategies must count as different pheromone sources toward escalation.
2. Correlation must favor cross-strategy evidence over same-strategy duplication.
3. Canary and promotion runs must be able to target one baseline strategy when runtime detection is using a composite detector.

## Current State Snapshot

- `DetectionConfig.active_strategies()` already enables composite detection in `crates/swarm-core/src/config.rs` and `crates/swarm-runtime/src/control.rs`.
- `DetectionFinding` already carries `strategy_id` in `crates/swarm-whisker/src/detector.rs`.
- Detection deposits do not use `strategy_id` yet:
  - `crates/swarm-runtime/src/detection/pipeline.rs` stamps every deposit with the raw runtime `agent_id`.
  - `crates/swarm-whisker/src/stream.rs` does the same for canary and promotion deposit previews.
- Distinct-source counting already works off the full `deposit.agent_id` string:
  - `crates/swarm-pheromone/src/substrate.rs` uses a `HashSet` of `deposit.agent_id.0`.
  - This means Phase 122 does not need a substrate math change. It needs a better deposit identity.
- Deposit signatures already include `agent_id` via `DepositSigningPayload`, so the final strategy-scoped ID must be assigned before signing.
- Correlation is not strategy-aware yet:
  - `crates/swarm-runtime/src/correlation.rs` includes or rejects candidates based on raw `shared_keys.len()` and time window only.
  - `crates/swarm-runtime/src/investigation.rs` already adds `strategy:{strategy_id}` into `correlation_keys`.
  - That currently biases same-strategy investigations upward, because same-strategy pairs share an extra key that cross-strategy pairs do not.
- Canary and promotion still assume one baseline strategy from `config.detection.strategy`:
  - `crates/swarm-runtime/src/canary.rs` uses `baseline_detector(&self.config)` and stores `baseline_strategy_id = self.config.detection.strategy.clone()`.
  - `crates/swarm-runtime/src/promotion.rs` uses `baseline_candidate_from_config(&self.config)` and validates against `self.config.detection.strategy`.
  - Neither path consults `active_strategies()`.

## Standard Stack

- Reuse `DetectionFinding.strategy_id` as the source of strategy identity.
- Reuse `PheromoneDeposit.agent_id` as the source-diversity key. Do not add a separate distinct-source counter.
- Reuse `InvestigationBundle.strategy_id` as the source of truth for correlation weighting.
- Extend `CanaryConfig` and `PromotionConfig` in `crates/swarm-core/src/config.rs` with `strategy_id: Option<String>`.
- Reuse existing `serde(default)` and `deny_unknown_fields` config patterns.
- Reuse the existing composite-detector build path in `crates/swarm-runtime/src/control.rs` instead of creating a fourth detector selection table.

## Architecture Patterns

### 1. Scope deposit identity at the deposit boundary, not at agent registration

Recommended shape:

- Keep the registered runtime agent ID unchanged (`whisker-primary`, `stalker-primary`, etc.).
- Derive a strategy-scoped deposit source ID only when creating a `PheromoneDeposit`.
- Use the detection finding's strategy ID, not a parsed value from deposit indicator JSON.

Recommended helper:

```rust
fn strategy_scoped_agent_id(base: &AgentId, strategy_id: &str) -> AgentId {
    AgentId(format!("{}:{}", base, strategy_id))
}
```

Where to apply it:

- `crates/swarm-runtime/src/detection/pipeline.rs`
  - In `resolve_deposits()`, set `agent_id` from `strategy_scoped_agent_id(agent_id, &finding.strategy_id)`.
  - This must happen before `sign_deposit()`.
- `crates/swarm-whisker/src/stream.rs`
  - Apply the same helper in `findings_to_deposits()` so canary and promotion preview deposits stay consistent with runtime deposits.

Why this is enough:

- `distinct_sources` already keys off full `agent_id`.
- Prefix-based filters in `stalker_agent.rs` and `weaver_agent.rs` use `starts_with("whisker-")` and `starts_with("stalker-")`, so `whisker-primary:dns_exfiltration` still matches correctly.

Recommended non-goal:

- Do not change `AgentRegistry`, dispatcher IDs, or peer-finding agent identity. This phase is about deposit identity, not agent lifecycle identity.

### 2. Correlation should use explicit pair scoring, not raw shared-key count

Current problem:

- `InvestigationOutcome` adds `strategy:{strategy_id}` as a correlation key.
- Same-strategy pairs therefore look more correlated than cross-strategy pairs before any Phase 122 logic is added.
- If you only add a cross-strategy bonus on top of the current raw `shared_keys.len()` check, same-strategy bias may still remain.

Recommended shape:

- Keep `InvestigationBundle.strategy_id` as the source of truth.
- Introduce a helper in `crates/swarm-runtime/src/correlation.rs` that computes:
  - the shared keys to persist for audit,
  - the shared-key count used for scoring, excluding any `strategy:` keys,
  - whether the pair is cross-strategy,
  - a weighted score used for inclusion.

Recommended weighting rule for this phase:

```rust
base_shared = shared_keys_without_strategy.len();
cross_strategy_bonus = usize::from(seed.strategy_id != candidate.strategy_id);
weighted_score = base_shared + cross_strategy_bonus;
```

Recommended inclusion rule:

- Continue enforcing completion status and time window exactly as today.
- Compare `weighted_score` against `self.config.min_shared_keys`.
- Preserve the existing config surface. Do not add a new config field unless planning explicitly decides the extra complexity is worth it.

Recommended audit behavior:

- Keep `IncidentMemberDecision` unchanged.
- Put the weighted-score details into `reason`, for example:
  - `"shared host:host-1, user:alice with cross-strategy bonus (+1)"`
  - `"weighted score 1 below minimum 2"`

This keeps the stored incident artifact explainable without a schema change in `swarm-spine`.

### 3. Multi-strategy rollout scoping should select one baseline strategy explicitly

Recommended config addition:

- `CanaryConfig.strategy_id: Option<String>`
- `PromotionConfig.strategy_id: Option<String>`

Recommended validation rules in `crates/swarm-core/src/config.rs`:

- If `canary.enabled` and `canary.strategy_id` is `Some`, it must be non-empty and present in `detection.active_strategies()`.
- If `promotion.enabled` and `promotion.strategy_id` is `Some`, it must be non-empty and present in `detection.active_strategies()`.
- If `canary.enabled` and `detection.active_strategies().len() > 1`, require `canary.strategy_id`.
- If `promotion.enabled` and `detection.active_strategies().len() > 1`, require `promotion.strategy_id` or explicitly inherit the canary baseline and validate that choice at promotion start.

Why this matters:

- `detection.strategies` takes precedence over `detection.strategy`.
- In composite mode, a missing rollout scope is ambiguous.
- Falling back to `detection.strategy` in multi-strategy mode is risky because that field is still required for backward compatibility, but it is no longer the runtime's active-strategy selector.

Recommended canary behavior:

- Replace `baseline_detector(&self.config)` with a baseline builder that accepts a selected strategy ID.
- Set `assignment.baseline_strategy_id` from the selected rollout scope, not from `self.config.detection.strategy`.
- Persist the selected scope in the canary report so promotion can validate against it.

Recommended promotion behavior:

- Build `previous_production_candidate` from the selected promotion scope, not from `self.config.detection.strategy`.
- If `promotion.strategy_id` is set, require it to match `canary.report.assignment.baseline_strategy_id`.
- If `promotion.strategy_id` is not set, promotion can safely inherit the canary baseline strategy, but this should be an explicit code path, not an accidental fallback.

### 4. Extract one shared detector-factory path

Current duplication:

- `crates/swarm-runtime/src/control.rs` has `build_single_detector()`.
- `crates/swarm-runtime/src/canary.rs` has `SupportedCanaryDetector` plus `baseline_detector()`.
- `crates/swarm-runtime/src/promotion.rs` has `SupportedPromotionDetector` plus `baseline_candidate_from_config()` and `detector_from_candidate()`.

Recommended direction:

- Extract a reusable detector-construction helper in `swarm-runtime` that can build a detector from:
  - a strategy family name plus `DetectionConfig`, or
  - a `DetectorCandidateManifest`.
- Let canary and promotion reuse that helper instead of carrying their own strategy switchboards.

Why it matters in this phase:

- Phase 121 and Phase 122 can execute in parallel.
- Detector-family additions and rollout-scoping changes will otherwise conflict in three separate files.

## Don't Hand-Roll

- Do not add a new distinct-source counter. The substrate already computes this correctly from `agent_id`.
- Do not mutate agent registry identity or dispatcher identity to satisfy COMPOSE-03.
- Do not parse strategy identity back out of `agent_id` for correlation or rollout state. Use `DetectionFinding.strategy_id`, `InvestigationBundle.strategy_id`, and rollout assignment fields directly.
- Do not copy another strategy-selection `match` block into canary or promotion.
- Do not widen slot/window active-run uniqueness in this phase unless the plan explicitly wants concurrent canaries or promotions per scope. The requirement only asks for scoped observation, not concurrent scoped runs.

## Common Pitfalls

- Signature ordering:
  - If `agent_id` changes after signing, the substrate will reject the deposit.
  - Strategy-scoped IDs must be computed before `sign_deposit()` and before any manual stalker-style signing logic if that path is ever extended.
- Exact-string test failures:
  - Several tests currently assert `deposit.agent_id.0 == "whisker-primary"`.
  - Those tests must move to prefix or helper-based assertions for detection deposits.
- Same-strategy correlation bias:
  - `strategy:{strategy_id}` is already in investigation correlation keys.
  - If scoring still uses raw shared-key count, same-strategy pairs remain advantaged.
- Ambiguous rollout fallback:
  - In composite mode, no scope field means no obvious baseline detector.
  - Requiring an explicit `strategy_id` in multi-strategy rollout configs is the safest bounded behavior.
- Candidate/baseline mismatch:
  - A canary scoped to `dns_exfiltration` should not silently evaluate a `SuspiciousProcessTree` candidate as its baseline comparison.
  - Recommended guardrail: validate `experiment.lineage.parent_strategy_id` against the selected baseline scope.
- Config surface drift:
  - `rulesets/default.yaml`, config defaults, validation, and any inline config fixtures all need the new field.
  - `serde(deny_unknown_fields)` means partial changes will break config loading.

## Code Examples

### Deposit identity

```rust
// crates/swarm-runtime/src/detection/pipeline.rs
let deposit_agent_id = strategy_scoped_agent_id(agent_id, &finding.strategy_id);
deposits.push(PheromoneDeposit {
    agent_id: deposit_agent_id,
    // ...
});
```

### Correlation weighting

```rust
// crates/swarm-runtime/src/correlation.rs
let shared = shared_keys(seed, candidate);
let scoreable_shared = shared
    .iter()
    .filter(|key| !key.starts_with("strategy:"))
    .count();
let cross_strategy = seed.strategy_id != candidate.strategy_id;
let weighted_score = scoreable_shared + usize::from(cross_strategy);

if weighted_score < self.config.min_shared_keys {
    // reject with reason including weighted_score and cross_strategy
}
```

### Rollout scope resolution

```rust
fn resolve_rollout_scope(
    enabled: bool,
    scope: Option<&str>,
    detection: &DetectionConfig,
) -> Result<String, ConfigValidationError> {
    let active = detection.active_strategies();
    match (scope, active.len()) {
        (Some(id), _) if active.iter().any(|entry| entry == id) => Ok(id.to_string()),
        (None, 1) => Ok(active[0].clone()),
        (None, _) if enabled => Err(/* rollout scope required in composite mode */),
        _ => Err(/* invalid scope */),
    }
}
```

## Testing Strategy

Cover this phase at four layers.

### 1. Deposit identity and escalation

- `crates/swarm-runtime/src/detection/pipeline.rs`
  - Add a unit test where a composite detector returns two findings for the same event and the same base agent.
  - Assert the two deposits get different `agent_id` values because their `strategy_id` values differ.
- `crates/swarm-pheromone/src/substrate.rs`
  - Add a concentration test that proves:
    - `whisker-primary:suspicious_process_tree` plus `whisker-primary:dns_exfiltration` yields `distinct_sources == 2`.
    - repeated `whisker-primary:suspicious_process_tree` deposits still yield `distinct_sources == 1`.
- `crates/swarm-runtime/tests/escalation_integration.rs`
  - Add the success-criteria test:
    - multi-strategy deposits from one base whisker agent satisfy `min_sources_for_escalation`,
    - the same number of repeated same-strategy deposits do not.

### 2. Correlation weighting

- `crates/swarm-runtime/src/correlation.rs`
  - Add a unit test with identical host and user keys but different `strategy_id` values.
  - Assert the cross-strategy candidate gets a higher effective score than a same-strategy candidate with the same non-strategy keys.
  - Assert the decision reason records the bonus or weighted score.
- Add a regression test proving raw `strategy:` shared keys no longer make same-strategy pairs easier to include than cross-strategy pairs.

### 3. Canary and promotion scoping

- `crates/swarm-core/src/config.rs`
  - Add validation tests for:
    - blank `strategy_id`,
    - unknown `strategy_id`,
    - missing `strategy_id` when `strategies.len() > 1` and rollout is enabled.
- `crates/swarm-runtime/src/canary.rs`
  - Add a test with `detection.strategies = ["suspicious_process_tree", "dns_exfiltration"]` and `canary.strategy_id = "dns_exfiltration"`.
  - Assert the canary report stores `baseline_strategy_id == "dns_exfiltration"`.
- `crates/swarm-runtime/src/promotion.rs`
  - Add the same multi-strategy scope test for promotion.
  - Add a mismatch test where `promotion.strategy_id` disagrees with the canary baseline and `start_run()` fails cleanly.

### 4. Regression coverage for existing assumptions

- Update `crates/swarm-runtime/tests/multi_agent_pipeline_integration.rs` to stop asserting exact equality on whisker deposit IDs.
- Keep `stalker` and `weaver` prefix-based filters covered so `whisker-primary:<strategy>` still flows through the multi-agent pipeline.

## Suggested File Touches

- `crates/swarm-core/src/config.rs`
- `crates/swarm-runtime/src/detection/pipeline.rs`
- `crates/swarm-whisker/src/stream.rs`
- `crates/swarm-runtime/src/correlation.rs`
- `crates/swarm-runtime/src/canary.rs`
- `crates/swarm-runtime/src/promotion.rs`
- `crates/swarm-runtime/src/control.rs` or a new shared detector-factory module
- `crates/swarm-runtime/tests/composite_integration.rs`
- `crates/swarm-runtime/tests/escalation_integration.rs`
- `crates/swarm-runtime/tests/multi_agent_pipeline_integration.rs`
- `rulesets/default.yaml`

## Planning Notes

The main implementation shortcut is that distinct-source counting already works. Phase 122 should not spend planning budget on substrate internals. The real planning work is:

- deriving a strategy-scoped deposit ID before signing,
- neutralizing the existing same-strategy bias in correlation scoring,
- making rollout scope explicit in composite mode,
- and reducing detector-factory duplication so this phase does not fight Phase 121 changes.

The highest-risk design decision to lock before planning is rollout fallback behavior in multi-strategy mode. The safest bounded choice is:

- optional `strategy_id` in the schema for backward compatibility,
- but required when rollout is enabled and `active_strategies().len() > 1`.

That keeps single-strategy configs unchanged and avoids ambiguous baseline selection in composite mode.
