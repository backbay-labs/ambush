use super::*;

pub(super) const fn default_recent_decisions_limit() -> usize {
    20
}

pub(super) const fn default_agent_tick_timeout_ms() -> u64 {
    500
}

pub(super) const fn default_governance_degraded_tick_threshold() -> usize {
    3
}

pub(super) const fn default_partition_contingency_lease_ttl_ms() -> i64 {
    300_000
}

pub(super) const fn default_partition_contingency_blast_radius_cap() -> usize {
    1
}

pub(super) const fn default_drain_timeout_ms() -> u64 {
    30_000
}

pub(super) const fn default_max_heap_pressure() -> f64 {
    0.90
}

pub(super) const fn default_temporal_event_window_retention_ms() -> i64 {
    900_000
}

pub(super) const fn default_temporal_event_window_max_events() -> usize {
    512
}

pub(super) const fn default_temporal_event_window_max_match_span_ms() -> i64 {
    300_000
}

pub(super) const fn default_temporal_event_window_max_predicates_per_match() -> usize {
    8
}

pub(super) const fn default_runtime_anti_tamper_enabled() -> bool {
    true
}

pub(super) const fn default_runtime_anti_tamper_check_interval_ms() -> u64 {
    5_000
}

pub(super) fn default_runtime_anti_tamper_allowed_library_prefixes() -> Vec<String> {
    vec![
        "/lib".to_string(),
        "/lib64".to_string(),
        "/usr/lib".to_string(),
        "/usr/local/lib".to_string(),
        "/nix/store".to_string(),
    ]
}

pub(super) const fn default_deception_monitoring_threat_class() -> ThreatClass {
    ThreatClass::InitialAccess
}

pub(super) const fn default_deception_monitoring_severity() -> Severity {
    Severity::High
}

pub(super) const fn default_deception_monitoring_confidence() -> f64 {
    0.99
}

pub(super) fn default_agent_key_dir() -> String {
    "data/agent-keys".to_string()
}

pub(super) fn default_identity_registry_dir() -> String {
    "data/agent-identity".to_string()
}

pub(super) const fn default_investigation_worker_count() -> usize {
    1
}

pub(super) const fn default_response_adapter_timeout_ms() -> u64 {
    5_000
}

pub(super) const fn default_splunk_batch_max_events() -> usize {
    32
}

pub(super) const fn default_splunk_batch_max_bytes() -> usize {
    131_072
}

pub(super) const fn default_max_retries() -> u32 {
    3
}

pub(super) const fn default_initial_backoff_ms() -> u64 {
    200
}

pub(super) const fn default_backoff_multiplier() -> f64 {
    2.0
}

pub(super) const fn default_circuit_breaker_threshold() -> u32 {
    5
}

pub(super) const fn default_circuit_breaker_cooldown_ms() -> u64 {
    30_000
}

pub(super) fn default_dead_letter_path() -> String {
    "./dead-letter.jsonl".to_string()
}

pub(super) fn default_siem_dead_letter_path() -> String {
    "./siem-dead-letter.jsonl".to_string()
}

pub(super) fn default_notification_dead_letter_path() -> String {
    "./notification-dead-letter.jsonl".to_string()
}

pub(super) fn default_request_signature_header() -> String {
    "X-Swarm-Signature".to_string()
}

pub(super) fn default_elk_index() -> String {
    "swarm-findings".to_string()
}

pub(super) const fn default_notification_rate_limit_max_notifications() -> usize {
    10
}

pub(super) const fn default_notification_rate_limit_window_ms() -> u64 {
    60_000
}

pub(super) const fn default_notification_dedup_window_ms() -> u64 {
    30_000
}

pub(super) const fn default_nats_connect_timeout_ms() -> u64 {
    5_000
}

pub(super) const fn default_tetragon_reconnect_backoff_ms() -> u64 {
    1_000
}

pub(super) const fn default_tetragon_max_reconnect_backoff_ms() -> u64 {
    30_000
}

pub(super) const fn default_tetragon_event_timeout_secs() -> u64 {
    30
}

pub(super) const fn default_sentinel_scrape_interval_ms() -> u64 {
    5_000
}

pub(super) const fn default_sentinel_scrape_timeout_ms() -> u64 {
    3_000
}

pub(super) const fn default_thermal_anomaly_threshold_celsius() -> f64 {
    60.0
}

pub(super) const fn default_memory_exhaustion_threshold_percent() -> f64 {
    85.0
}

pub(super) const fn default_disk_exhaustion_threshold_percent() -> f64 {
    90.0
}

pub(super) const fn default_max_consecutive_sentinel_failures() -> u32 {
    5
}

pub(super) const fn default_deescalation_cooldown_secs() -> i64 {
    300
}

pub(super) const fn default_jetstream_gc_page_size() -> usize {
    512
}

pub(super) fn default_operator_bind_addr() -> String {
    "127.0.0.1:7766".to_string()
}

pub(super) fn default_operator_runtime_base_url() -> String {
    "http://127.0.0.1:9090".to_string()
}

pub(super) fn default_operator_public_base_url() -> String {
    "http://127.0.0.1:7766".to_string()
}

pub(super) const fn default_operator_max_list_results() -> usize {
    50
}

pub(super) const fn default_operator_widget_token_ttl_secs() -> u64 {
    15 * 60
}

pub(super) fn default_operator_id() -> String {
    "local-operator".to_string()
}

pub(super) fn default_operator_token_env() -> String {
    "SWARM_OPERATOR_TOKEN".to_string()
}

pub(super) fn default_operator_context_token_env() -> String {
    default_operator_token_env()
}

pub(super) const fn default_http_rate_limit_burst_max_requests() -> usize {
    32
}

pub(super) const fn default_http_rate_limit_burst_window_ms() -> u64 {
    1_000
}

pub(super) const fn default_http_rate_limit_sustained_max_requests() -> usize {
    600
}

pub(super) const fn default_http_rate_limit_sustained_window_ms() -> u64 {
    60_000
}

pub(super) const fn default_investigation_max_pending_jobs() -> usize {
    16
}

pub(super) const fn default_investigation_starvation_boost_per_second_basis_points() -> u16 {
    15
}

pub(super) const fn default_investigation_max_starvation_boost_basis_points() -> u16 {
    2_500
}

pub(super) const fn default_investigation_ambiguity_margin_basis_points() -> u16 {
    900
}

pub(super) const fn default_investigation_time_budget_ms() -> u64 {
    250
}

pub(super) const fn default_correlation_time_window_ms() -> i64 {
    300_000
}

pub(super) const fn default_correlation_min_shared_keys() -> usize {
    1
}

pub(super) const fn default_correlation_candidate_limit() -> usize {
    32
}

pub(super) fn default_canary_slot_id() -> String {
    "canary-primary".to_string()
}

pub(super) const fn default_canary_observation_window_events() -> usize {
    3
}

pub(super) const fn default_canary_max_candidate_only_rate() -> f64 {
    0.25
}

pub(super) const fn default_canary_max_baseline_miss_rate() -> f64 {
    0.25
}

pub(super) const fn default_canary_max_detect_latency_us() -> u64 {
    10_000
}

pub(super) const fn default_canary_max_total_detections() -> usize {
    8
}

pub(super) fn default_promotion_window_id() -> String {
    "production-primary".to_string()
}

pub(super) const fn default_promotion_observation_window_events() -> usize {
    3
}

pub(super) const fn default_promotion_max_promoted_only_rate() -> f64 {
    0.20
}

pub(super) const fn default_promotion_max_fallback_recovery_rate() -> f64 {
    0.20
}

pub(super) const fn default_promotion_max_detect_latency_us() -> u64 {
    10_000
}

pub(super) const fn default_promotion_max_total_detections() -> usize {
    12
}

pub(super) const fn default_evolution_observation_window_secs() -> u64 {
    3_600
}

pub(super) const fn default_evolution_drift_threshold_pct() -> f64 {
    0.40
}

pub(super) const fn default_evolution_minimum_observations() -> usize {
    3
}

pub(super) const fn default_evolution_cooldown_secs() -> u64 {
    900
}

pub(super) const fn default_evolution_max_variants_per_cycle() -> usize {
    2
}

pub(super) const fn default_evolution_shortlist_count() -> usize {
    1
}

pub(super) const fn default_evolution_population_size() -> usize {
    16
}

pub(super) const fn default_evolution_pareto_tournament_size() -> usize {
    4
}

pub(super) const fn default_evolution_max_proposals_per_hour() -> usize {
    4
}

pub(super) const fn default_evolution_assurance_min_detector_catch_rate() -> f64 {
    0.25
}

pub(super) fn default_evolution_assurance_allowed_solver_statuses()
-> Vec<EvolutionAssuranceSolverStatusConfig> {
    vec![
        EvolutionAssuranceSolverStatusConfig::Proved,
        EvolutionAssuranceSolverStatusConfig::Disabled,
    ]
}

pub(super) fn default_evolution_assurance_harvest_results_dir() -> String {
    "data/evolution-assurance-cases".to_string()
}

pub(super) const fn default_evolution_assurance_harvest_max_cases_per_proposal() -> usize {
    8
}

pub(super) const fn default_evolution_assurance_harvest_max_events_per_case() -> usize {
    16
}

pub(super) const fn default_evolution_assurance_waiver_max_ttl_secs() -> u64 {
    3600
}

pub(super) const fn default_evolution_assurance_waiver_max_actionable_gap_count() -> usize {
    4
}

pub(super) fn default_evolution_safety_invariant_bundle_paths() -> Vec<String> {
    vec!["safety/office-detector-admission.yaml".to_string()]
}

pub(super) const fn default_evolution_fitness_detection_rate_weight() -> f64 {
    0.40
}

pub(super) const fn default_evolution_fitness_false_positive_cost_weight() -> f64 {
    0.30
}

pub(super) const fn default_evolution_fitness_speed_weight() -> f64 {
    0.15
}

pub(super) const fn default_evolution_fitness_threat_class_coverage_weight() -> f64 {
    0.15
}

pub(super) fn default_replay_results_dir() -> String {
    "data/replay-runs".to_string()
}

pub(super) fn default_experiment_results_dir() -> String {
    "data/experiments".to_string()
}

pub(super) fn default_verification_results_dir() -> String {
    "data/verifications".to_string()
}

pub(super) fn default_shadow_results_dir() -> String {
    "data/shadows".to_string()
}

pub(super) fn default_strategy_memory_results_dir() -> String {
    "data/strategy-memory".to_string()
}

pub(super) fn default_memory_knowledge_graph_results_dir() -> String {
    "data/knowledge-graph".to_string()
}

pub(super) fn default_deception_lifecycle_results_dir() -> String {
    "data/deception-lifecycle".to_string()
}

pub(super) const fn default_deception_rotation_interval_secs() -> u64 {
    86_400
}

pub(super) const fn default_deception_cleanup_grace_secs() -> u64 {
    3_600
}

pub(super) const fn default_deception_interaction_fitness_weight() -> f64 {
    0.15
}

pub(super) const fn default_memory_temporal_window_secs() -> u64 {
    3_600
}

pub(super) const fn default_memory_knowledge_retention_days() -> u64 {
    90
}

pub(super) fn default_strategy_scorecard_results_dir() -> String {
    "data/strategy-scorecards".to_string()
}

pub(super) fn default_evolution_proof_results_dir() -> String {
    "data/evolution-proofs".to_string()
}

pub(super) fn default_evolution_queue_results_dir() -> String {
    "data/evolution-queue".to_string()
}

pub(super) fn default_evolution_selection_results_dir() -> String {
    "data/evolution-selections".to_string()
}

pub(super) fn default_evolution_bridge_results_dir() -> String {
    "data/evolution-selection-bridges".to_string()
}

pub(super) fn default_evolution_handoff_results_dir() -> String {
    "data/evolution-handoffs".to_string()
}

pub(super) fn default_evolution_pressure_results_dir() -> String {
    "data/evolution-pressures".to_string()
}

pub(super) fn default_evolution_draft_results_dir() -> String {
    "data/evolution-drafts".to_string()
}

pub(super) fn default_evolution_draft_promotion_results_dir() -> String {
    "data/evolution-draft-promotions".to_string()
}

pub(super) fn default_evolution_materialization_results_dir() -> String {
    "data/evolution-materializations".to_string()
}

pub(super) fn default_evolution_validation_results_dir() -> String {
    "data/evolution-validation-bundles".to_string()
}

pub(super) fn default_evolution_reconciliation_results_dir() -> String {
    "data/evolution-reconciliations".to_string()
}

pub(super) fn default_evolution_mutation_results_dir() -> String {
    "data/evolution-mutations".to_string()
}

pub(super) fn default_evolution_mutation_materialization_batch_results_dir() -> String {
    "data/evolution-mutation-materialization-batches".to_string()
}

pub(super) fn default_evolution_mutation_validation_batch_results_dir() -> String {
    "data/evolution-mutation-validation-batches".to_string()
}

pub(super) fn default_evolution_ranking_results_dir() -> String {
    "data/evolution-rankings".to_string()
}

pub(super) fn default_evolution_population_results_dir() -> String {
    "data/evolution-population".to_string()
}

pub(super) fn default_canary_results_dir() -> String {
    "data/canaries".to_string()
}

pub(super) const fn default_max_actions_per_scope_per_minute() -> usize {
    5
}

pub(super) const fn default_policy_rule_min_severity() -> Severity {
    Severity::Low
}

pub(super) const fn default_policy_rule_max_severity() -> Severity {
    Severity::Critical
}
