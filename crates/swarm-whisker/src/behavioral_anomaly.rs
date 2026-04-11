use crate::detector::{
    DetectionFinding, DetectionStrategy, ProcessStartEvent, TelemetryEvent, TelemetryPayload,
};
use crate::{ProfileValidationError, validate_confidence_thresholds};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use swarm_core::pheromone::{
    BehavioralBaselineSnapshot, BehavioralFrequencyEntry, BehavioralHostBaseline,
    BehavioralIdentityBaseline, BehavioralPeerGroupBaseline, BehavioralRoleToolFrequencyEntry,
    ThreatClass,
};
use swarm_core::types::Severity;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehavioralAnomalyProfile {
    #[serde(default = "default_sensitive_parent_processes")]
    pub sensitive_parent_processes: Vec<String>,
    #[serde(default = "default_sensitive_child_processes")]
    pub sensitive_child_processes: Vec<String>,
    #[serde(default = "default_rare_role_tools")]
    pub rare_role_tools: Vec<String>,
    #[serde(default = "default_trusted_binary_prefixes")]
    pub trusted_binary_prefixes: Vec<String>,
    #[serde(default = "default_privileged_user_indicators")]
    pub privileged_user_indicators: Vec<String>,
    #[serde(default = "default_service_user_indicators")]
    pub service_user_indicators: Vec<String>,
    #[serde(default = "default_min_host_observations")]
    pub min_host_observations: u64,
    #[serde(default = "default_min_identity_observations")]
    pub min_identity_observations: u64,
    #[serde(default = "default_min_peer_group_observations")]
    pub min_peer_group_observations: u64,
    #[serde(default = "default_min_feature_weight")]
    pub min_feature_weight: f64,
    #[serde(default = "default_baseline_half_life_secs")]
    pub baseline_half_life_secs: f64,
    #[serde(default = "default_high_confidence_threshold")]
    pub high_confidence_threshold: f64,
    #[serde(default = "default_medium_confidence_threshold")]
    pub medium_confidence_threshold: f64,
}

impl Default for BehavioralAnomalyProfile {
    fn default() -> Self {
        Self {
            sensitive_parent_processes: default_sensitive_parent_processes(),
            sensitive_child_processes: default_sensitive_child_processes(),
            rare_role_tools: default_rare_role_tools(),
            trusted_binary_prefixes: default_trusted_binary_prefixes(),
            privileged_user_indicators: default_privileged_user_indicators(),
            service_user_indicators: default_service_user_indicators(),
            min_host_observations: default_min_host_observations(),
            min_identity_observations: default_min_identity_observations(),
            min_peer_group_observations: default_min_peer_group_observations(),
            min_feature_weight: default_min_feature_weight(),
            baseline_half_life_secs: default_baseline_half_life_secs(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BehavioralAnomalyDetector {
    sensitive_parent_processes: Vec<String>,
    sensitive_child_processes: Vec<String>,
    rare_role_tools: Vec<String>,
    trusted_binary_prefixes: Vec<String>,
    privileged_user_indicators: Vec<String>,
    service_user_indicators: Vec<String>,
    min_host_observations: u64,
    min_identity_observations: u64,
    min_peer_group_observations: u64,
    min_feature_weight: f64,
    baseline_half_life_secs: f64,
    high_confidence_threshold: f64,
    medium_confidence_threshold: f64,
    state: Arc<RwLock<BehavioralDetectorState>>,
}

#[derive(Debug, Clone, Default)]
struct BehavioralDetectorState {
    hydrated: bool,
    dirty: bool,
    hosts: HashMap<String, ScopeBaselineState>,
    identities: HashMap<String, ScopeBaselineState>,
    peer_groups: HashMap<String, ScopeBaselineState>,
}

#[derive(Debug, Clone, Default)]
struct ScopeBaselineState {
    observation_count: u64,
    parent_child_pairs: HashMap<String, DecayedObservation>,
    binaries: HashMap<String, DecayedObservation>,
    role_tools: HashMap<RoleToolKey, DecayedObservation>,
}

#[derive(Debug, Clone)]
struct DecayedObservation {
    weight: f64,
    last_seen_at: i64,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct RoleToolKey {
    user_role: String,
    tool: String,
}

#[derive(Debug, Clone)]
struct ScopeObservationSummary {
    scope: &'static str,
    observation_count: u64,
    pair_weight: f64,
    binary_weight: f64,
    role_tool_weight: f64,
    anomaly_modes: Vec<String>,
}

impl Default for BehavioralAnomalyDetector {
    fn default() -> Self {
        let profile = BehavioralAnomalyProfile::default();
        debug_assert!(profile.validate().is_ok());
        Self {
            sensitive_parent_processes: normalize_entries(profile.sensitive_parent_processes),
            sensitive_child_processes: normalize_entries(profile.sensitive_child_processes),
            rare_role_tools: normalize_entries(profile.rare_role_tools),
            trusted_binary_prefixes: normalize_entries(profile.trusted_binary_prefixes),
            privileged_user_indicators: normalize_entries(profile.privileged_user_indicators),
            service_user_indicators: normalize_entries(profile.service_user_indicators),
            min_host_observations: profile.min_host_observations,
            min_identity_observations: profile.min_identity_observations,
            min_peer_group_observations: profile.min_peer_group_observations,
            min_feature_weight: profile.min_feature_weight,
            baseline_half_life_secs: profile.baseline_half_life_secs,
            high_confidence_threshold: profile.high_confidence_threshold,
            medium_confidence_threshold: profile.medium_confidence_threshold,
            state: Arc::default(),
        }
    }
}

impl BehavioralAnomalyProfile {
    pub fn validate(&self) -> Result<(), ProfileValidationError> {
        validate_confidence_thresholds(
            "BehavioralAnomalyProfile",
            self.high_confidence_threshold,
            self.medium_confidence_threshold,
        )?;
        if self.min_host_observations == 0 {
            return Err(ProfileValidationError {
                profile: "BehavioralAnomalyProfile",
                field: "min_host_observations",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.min_identity_observations == 0 {
            return Err(ProfileValidationError {
                profile: "BehavioralAnomalyProfile",
                field: "min_identity_observations",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.min_peer_group_observations == 0 {
            return Err(ProfileValidationError {
                profile: "BehavioralAnomalyProfile",
                field: "min_peer_group_observations",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.min_feature_weight <= 0.0 {
            return Err(ProfileValidationError {
                profile: "BehavioralAnomalyProfile",
                field: "min_feature_weight",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.baseline_half_life_secs <= 0.0 {
            return Err(ProfileValidationError {
                profile: "BehavioralAnomalyProfile",
                field: "baseline_half_life_secs",
                reason: "must be greater than zero".to_string(),
            });
        }
        Ok(())
    }
}

impl BehavioralAnomalyDetector {
    pub fn from_profile(profile: BehavioralAnomalyProfile) -> Result<Self, ProfileValidationError> {
        profile.validate()?;
        Ok(Self {
            sensitive_parent_processes: normalize_entries(profile.sensitive_parent_processes),
            sensitive_child_processes: normalize_entries(profile.sensitive_child_processes),
            rare_role_tools: normalize_entries(profile.rare_role_tools),
            trusted_binary_prefixes: normalize_entries(profile.trusted_binary_prefixes),
            privileged_user_indicators: normalize_entries(profile.privileged_user_indicators),
            service_user_indicators: normalize_entries(profile.service_user_indicators),
            min_host_observations: profile.min_host_observations,
            min_identity_observations: profile.min_identity_observations,
            min_peer_group_observations: profile.min_peer_group_observations,
            min_feature_weight: profile.min_feature_weight,
            baseline_half_life_secs: profile.baseline_half_life_secs,
            high_confidence_threshold: profile.high_confidence_threshold,
            medium_confidence_threshold: profile.medium_confidence_threshold,
            state: Arc::default(),
        })
    }

    pub fn profile(&self) -> BehavioralAnomalyProfile {
        BehavioralAnomalyProfile {
            sensitive_parent_processes: self.sensitive_parent_processes.clone(),
            sensitive_child_processes: self.sensitive_child_processes.clone(),
            rare_role_tools: self.rare_role_tools.clone(),
            trusted_binary_prefixes: self.trusted_binary_prefixes.clone(),
            privileged_user_indicators: self.privileged_user_indicators.clone(),
            service_user_indicators: self.service_user_indicators.clone(),
            min_host_observations: self.min_host_observations,
            min_identity_observations: self.min_identity_observations,
            min_peer_group_observations: self.min_peer_group_observations,
            min_feature_weight: self.min_feature_weight,
            baseline_half_life_secs: self.baseline_half_life_secs,
            high_confidence_threshold: self.high_confidence_threshold,
            medium_confidence_threshold: self.medium_confidence_threshold,
        }
    }

    pub fn needs_hydration(&self) -> bool {
        self.state
            .read()
            .ok()
            .map(|state| !state.hydrated)
            .unwrap_or(false)
    }

    pub fn hydrate_from_snapshot(&self, snapshot: Option<BehavioralBaselineSnapshot>) {
        let mut guard = match self.state.write() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        if guard.hydrated {
            return;
        }

        guard.hosts.clear();
        guard.identities.clear();
        guard.peer_groups.clear();
        if let Some(snapshot) = snapshot {
            for host in snapshot.hosts {
                guard.hosts.insert(
                    host.host_id,
                    scope_state_from_entries(
                        host.observation_count,
                        host.parent_child_pairs,
                        host.binaries,
                        host.role_tools,
                    ),
                );
            }
            for identity in snapshot.identities {
                guard.identities.insert(
                    identity.identity_id,
                    scope_state_from_entries(
                        identity.observation_count,
                        identity.parent_child_pairs,
                        identity.binaries,
                        identity.role_tools,
                    ),
                );
            }
            for peer_group in snapshot.peer_groups {
                guard.peer_groups.insert(
                    peer_group.peer_group_id,
                    scope_state_from_entries(
                        peer_group.observation_count,
                        peer_group.parent_child_pairs,
                        peer_group.binaries,
                        peer_group.role_tools,
                    ),
                );
            }
        }
        guard.hydrated = true;
        guard.dirty = false;
    }

    pub fn snapshot_if_dirty(&self, strategy_id: &str) -> Option<BehavioralBaselineSnapshot> {
        let guard = self.state.read().ok()?;
        if !guard.dirty {
            return None;
        }

        let mut hosts = guard
            .hosts
            .iter()
            .map(|(host_id, host)| BehavioralHostBaseline {
                host_id: host_id.clone(),
                observation_count: host.observation_count,
                parent_child_pairs: frequency_entries(&host.parent_child_pairs),
                binaries: frequency_entries(&host.binaries),
                role_tools: role_tool_entries(&host.role_tools),
            })
            .collect::<Vec<_>>();
        hosts.sort_by(|left, right| left.host_id.cmp(&right.host_id));

        let mut identities = guard
            .identities
            .iter()
            .map(|(identity_id, identity)| BehavioralIdentityBaseline {
                identity_id: identity_id.clone(),
                observation_count: identity.observation_count,
                parent_child_pairs: frequency_entries(&identity.parent_child_pairs),
                binaries: frequency_entries(&identity.binaries),
                role_tools: role_tool_entries(&identity.role_tools),
            })
            .collect::<Vec<_>>();
        identities.sort_by(|left, right| left.identity_id.cmp(&right.identity_id));

        let mut peer_groups = guard
            .peer_groups
            .iter()
            .map(|(peer_group_id, peer_group)| BehavioralPeerGroupBaseline {
                peer_group_id: peer_group_id.clone(),
                observation_count: peer_group.observation_count,
                parent_child_pairs: frequency_entries(&peer_group.parent_child_pairs),
                binaries: frequency_entries(&peer_group.binaries),
                role_tools: role_tool_entries(&peer_group.role_tools),
            })
            .collect::<Vec<_>>();
        peer_groups.sort_by(|left, right| left.peer_group_id.cmp(&right.peer_group_id));

        Some(BehavioralBaselineSnapshot {
            strategy_id: strategy_id.to_string(),
            captured_at: hosts
                .iter()
                .flat_map(|host| {
                    baseline_timestamps(&host.parent_child_pairs, &host.binaries, &host.role_tools)
                })
                .chain(identities.iter().flat_map(|identity| {
                    baseline_timestamps(
                        &identity.parent_child_pairs,
                        &identity.binaries,
                        &identity.role_tools,
                    )
                }))
                .chain(peer_groups.iter().flat_map(|peer_group| {
                    baseline_timestamps(
                        &peer_group.parent_child_pairs,
                        &peer_group.binaries,
                        &peer_group.role_tools,
                    )
                }))
                .max()
                .unwrap_or_default(),
            hosts,
            identities,
            peer_groups,
        })
    }

    pub fn mark_persisted(&self) {
        if let Ok(mut guard) = self.state.write() {
            guard.dirty = false;
        }
    }

    fn evaluate_process_start(
        &self,
        event: &TelemetryEvent,
        process: &ProcessStartEvent,
    ) -> Vec<DetectionFinding> {
        let host_id = normalized_host_id(event);
        let identity_id = normalized_identity(process.user.as_deref());
        let now = normalized_timestamp_secs(event.timestamp);
        let parent_process = process.parent_process.trim().to_ascii_lowercase();
        let process_name = process.process_name.trim().to_ascii_lowercase();
        let executable_key = normalized_binary_key(process);
        let user_role = inferred_user_role(
            process.user.as_deref(),
            &self.privileged_user_indicators,
            &self.service_user_indicators,
        );
        let peer_group_id = format!("role:{user_role}");

        let pair_key = format!("{parent_process}->{process_name}");
        let role_tool_key = RoleToolKey {
            user_role: user_role.clone(),
            tool: process_name.clone(),
        };
        let process_is_rare_tool = self.rare_role_tools.contains(&process_name);

        let mut state = match self.state.write() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(),
        };
        let host_summary = observe_scope(
            state.hosts.entry(host_id.clone()).or_default(),
            "host",
            self.min_host_observations,
            now,
            self.baseline_half_life_secs,
            self.min_feature_weight,
            &pair_key,
            &executable_key,
            &role_tool_key,
            self.is_sensitive_pair(&parent_process, &process_name),
            self.is_first_seen_binary_alert(&executable_key, &process_name),
            process_is_rare_tool,
        );
        let identity_summary = observe_scope(
            state.identities.entry(identity_id.clone()).or_default(),
            "identity",
            self.min_identity_observations,
            now,
            self.baseline_half_life_secs,
            self.min_feature_weight,
            &pair_key,
            &executable_key,
            &role_tool_key,
            self.is_sensitive_pair(&parent_process, &process_name),
            self.is_first_seen_binary_alert(&executable_key, &process_name),
            process_is_rare_tool,
        );
        let peer_group_summary = observe_scope(
            state.peer_groups.entry(peer_group_id.clone()).or_default(),
            "peer_group",
            self.min_peer_group_observations,
            now,
            self.baseline_half_life_secs,
            self.min_feature_weight,
            &pair_key,
            &executable_key,
            &role_tool_key,
            self.is_sensitive_pair(&parent_process, &process_name),
            self.is_first_seen_binary_alert(&executable_key, &process_name),
            process_is_rare_tool,
        );
        state.dirty = true;

        let mut anomaly_modes = host_summary.anomaly_modes.clone();
        anomaly_modes.extend(identity_summary.anomaly_modes.clone());
        anomaly_modes.extend(peer_group_summary.anomaly_modes.clone());
        if anomaly_modes.is_empty() {
            return Vec::new();
        }

        let scope_hits = [
            host_summary.scope,
            identity_summary.scope,
            peer_group_summary.scope,
        ]
        .into_iter()
        .zip([
            &host_summary.anomaly_modes,
            &identity_summary.anomaly_modes,
            &peer_group_summary.anomaly_modes,
        ])
        .filter_map(|(scope, modes)| (!modes.is_empty()).then_some(scope))
        .collect::<Vec<_>>();
        let signal_count = anomaly_modes.len();
        let confidence = (self.medium_confidence_threshold
            + 0.05 * (signal_count.saturating_sub(1) as f64)
            + 0.03 * (scope_hits.len().saturating_sub(1) as f64))
            .min(self.high_confidence_threshold);
        let severity = if signal_count >= 2 || scope_hits.len() >= 2 {
            Severity::High
        } else {
            Severity::Medium
        };
        let threat_class = infer_threat_class(&process_name);

        vec![DetectionFinding {
            finding_id: format!("{}:{}", self.id(), event.event_id),
            event_id: event.event_id.clone(),
            threat_class,
            severity,
            confidence,
            evidence: json!({
                "source": event.source,
                "host_id": host_id,
                "user": process.user,
                "user_role": user_role,
                "parent_process": process.parent_process,
                "process_name": process.process_name,
                "executable_path": process.executable_path,
                "identity_id": identity_id,
                "peer_group_id": peer_group_id,
                "anomaly_modes": anomaly_modes,
                "baseline_scope_hits": scope_hits,
                "baseline": {
                    "host": scope_summary_json(&host_summary),
                    "identity": scope_summary_json(&identity_summary),
                    "peer_group": scope_summary_json(&peer_group_summary),
                    "baseline_half_life_secs": self.baseline_half_life_secs,
                }
            }),
            strategy_id: self.id().to_string(),
        }]
    }

    fn is_sensitive_pair(&self, parent_process: &str, process_name: &str) -> bool {
        self.sensitive_parent_processes
            .iter()
            .any(|parent| parent_process.contains(parent))
            || self
                .sensitive_child_processes
                .iter()
                .any(|child| process_name.contains(child))
            || self.rare_role_tools.contains(&process_name.to_string())
    }

    fn is_first_seen_binary_alert(&self, executable_key: &str, process_name: &str) -> bool {
        if self.rare_role_tools.contains(&process_name.to_string()) {
            return true;
        }
        !self
            .trusted_binary_prefixes
            .iter()
            .any(|prefix| executable_key.starts_with(prefix))
    }
}

impl DetectionStrategy for BehavioralAnomalyDetector {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn id(&self) -> &str {
        "behavioral_anomaly"
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        match &event.payload {
            TelemetryPayload::ProcessStart(process) => self.evaluate_process_start(event, process),
            TelemetryPayload::NetworkConnect(_)
            | TelemetryPayload::ProcessMemoryAccess(_)
            | TelemetryPayload::DnsQuery(_)
            | TelemetryPayload::RegistryAccess(_)
            | TelemetryPayload::RegistryPersistence(_)
            | TelemetryPayload::FilePersistence(_)
            | TelemetryPayload::AuthenticationEvent(_)
            | TelemetryPayload::InfrastructureHealth(_)
            | TelemetryPayload::ThermalAnomaly(_)
            | TelemetryPayload::ResourceExhaustion(_) => Vec::new(),
        }
    }
}

impl ScopeBaselineState {
    fn normalize(&mut self, now: i64, half_life_secs: f64, min_feature_weight: f64) {
        normalize_observation_map(
            &mut self.parent_child_pairs,
            now,
            half_life_secs,
            min_feature_weight,
        );
        normalize_observation_map(&mut self.binaries, now, half_life_secs, min_feature_weight);
        self.role_tools.retain(|_, value| {
            value.weight = decayed_weight(value.weight, value.last_seen_at, now, half_life_secs);
            value.last_seen_at = now;
            value.weight >= min_feature_weight / 4.0
        });
    }

    fn weight_for_pair(&self, key: &str) -> Option<f64> {
        self.parent_child_pairs.get(key).map(|entry| entry.weight)
    }

    fn weight_for_binary(&self, key: &str) -> Option<f64> {
        self.binaries.get(key).map(|entry| entry.weight)
    }

    fn weight_for_role_tool(&self, key: &RoleToolKey) -> Option<f64> {
        self.role_tools.get(key).map(|entry| entry.weight)
    }

    fn observe_pair(&mut self, key: String, now: i64) {
        observe_key(&mut self.parent_child_pairs, key, now);
    }

    fn observe_binary(&mut self, key: String, now: i64) {
        observe_key(&mut self.binaries, key, now);
    }

    fn observe_role_tool(&mut self, key: RoleToolKey, now: i64) {
        observe_role_tool(&mut self.role_tools, key, now);
    }
}

#[allow(clippy::too_many_arguments)]
fn observe_scope(
    state: &mut ScopeBaselineState,
    scope: &'static str,
    min_observations: u64,
    now: i64,
    baseline_half_life_secs: f64,
    min_feature_weight: f64,
    pair_key: &str,
    executable_key: &str,
    role_tool_key: &RoleToolKey,
    sensitive_pair: bool,
    first_seen_binary_alert: bool,
    process_is_rare_tool: bool,
) -> ScopeObservationSummary {
    state.normalize(now, baseline_half_life_secs, min_feature_weight);

    let pair_weight = state.weight_for_pair(pair_key).unwrap_or_default();
    let binary_weight = state.weight_for_binary(executable_key).unwrap_or_default();
    let role_tool_weight = state
        .weight_for_role_tool(role_tool_key)
        .unwrap_or_default();
    let scope_is_warm = state.observation_count >= min_observations;

    let mut anomaly_modes = Vec::new();
    if scope_is_warm && pair_weight < min_feature_weight && sensitive_pair {
        anomaly_modes.push(format!("{scope}_unusual_parent_child_pair"));
    }
    if scope_is_warm && binary_weight < min_feature_weight && first_seen_binary_alert {
        anomaly_modes.push(format!("{scope}_first_seen_binary"));
    }
    if scope_is_warm && role_tool_weight < min_feature_weight && process_is_rare_tool {
        anomaly_modes.push(format!("{scope}_atypical_role_tool_usage"));
    }

    state.observe_pair(pair_key.to_string(), now);
    state.observe_binary(executable_key.to_string(), now);
    state.observe_role_tool(role_tool_key.clone(), now);
    state.observation_count = state.observation_count.saturating_add(1);

    ScopeObservationSummary {
        scope,
        observation_count: state.observation_count,
        pair_weight,
        binary_weight,
        role_tool_weight,
        anomaly_modes,
    }
}

fn scope_summary_json(summary: &ScopeObservationSummary) -> serde_json::Value {
    json!({
        "observation_count": summary.observation_count,
        "pair_weight_before_update": summary.pair_weight,
        "binary_weight_before_update": summary.binary_weight,
        "role_tool_weight_before_update": summary.role_tool_weight,
        "anomaly_modes": summary.anomaly_modes,
    })
}

fn scope_state_from_entries(
    observation_count: u64,
    parent_child_pairs: Vec<BehavioralFrequencyEntry>,
    binaries: Vec<BehavioralFrequencyEntry>,
    role_tools: Vec<BehavioralRoleToolFrequencyEntry>,
) -> ScopeBaselineState {
    let mut pair_map = HashMap::new();
    for entry in parent_child_pairs {
        pair_map.insert(
            entry.key,
            DecayedObservation {
                weight: entry.weight,
                last_seen_at: entry.last_seen_at,
            },
        );
    }
    let mut binary_map = HashMap::new();
    for entry in binaries {
        binary_map.insert(
            entry.key,
            DecayedObservation {
                weight: entry.weight,
                last_seen_at: entry.last_seen_at,
            },
        );
    }
    let mut role_tool_map = HashMap::new();
    for entry in role_tools {
        role_tool_map.insert(
            RoleToolKey {
                user_role: entry.user_role,
                tool: entry.tool,
            },
            DecayedObservation {
                weight: entry.weight,
                last_seen_at: entry.last_seen_at,
            },
        );
    }

    ScopeBaselineState {
        observation_count,
        parent_child_pairs: pair_map,
        binaries: binary_map,
        role_tools: role_tool_map,
    }
}

fn frequency_entries(map: &HashMap<String, DecayedObservation>) -> Vec<BehavioralFrequencyEntry> {
    let mut entries = map
        .iter()
        .map(|(key, value)| BehavioralFrequencyEntry {
            key: key.clone(),
            weight: value.weight,
            last_seen_at: value.last_seen_at,
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.key.cmp(&right.key));
    entries
}

fn role_tool_entries(
    map: &HashMap<RoleToolKey, DecayedObservation>,
) -> Vec<BehavioralRoleToolFrequencyEntry> {
    let mut entries = map
        .iter()
        .map(|(key, value)| BehavioralRoleToolFrequencyEntry {
            user_role: key.user_role.clone(),
            tool: key.tool.clone(),
            weight: value.weight,
            last_seen_at: value.last_seen_at,
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        left.user_role
            .cmp(&right.user_role)
            .then(left.tool.cmp(&right.tool))
    });
    entries
}

fn baseline_timestamps<'a>(
    parent_child_pairs: &'a [BehavioralFrequencyEntry],
    binaries: &'a [BehavioralFrequencyEntry],
    role_tools: &'a [BehavioralRoleToolFrequencyEntry],
) -> impl Iterator<Item = i64> + 'a {
    parent_child_pairs
        .iter()
        .map(|entry| entry.last_seen_at)
        .chain(binaries.iter().map(|entry| entry.last_seen_at))
        .chain(role_tools.iter().map(|entry| entry.last_seen_at))
}

fn observe_key(map: &mut HashMap<String, DecayedObservation>, key: String, now: i64) {
    let entry = map.entry(key).or_insert(DecayedObservation {
        weight: 0.0,
        last_seen_at: now,
    });
    entry.weight += 1.0;
    entry.last_seen_at = now;
}

fn observe_role_tool(
    map: &mut HashMap<RoleToolKey, DecayedObservation>,
    key: RoleToolKey,
    now: i64,
) {
    let entry = map.entry(key).or_insert(DecayedObservation {
        weight: 0.0,
        last_seen_at: now,
    });
    entry.weight += 1.0;
    entry.last_seen_at = now;
}

fn normalize_observation_map(
    map: &mut HashMap<String, DecayedObservation>,
    now: i64,
    half_life_secs: f64,
    min_feature_weight: f64,
) {
    map.retain(|_, value| {
        value.weight = decayed_weight(value.weight, value.last_seen_at, now, half_life_secs);
        value.last_seen_at = now;
        value.weight >= min_feature_weight / 4.0
    });
}

fn decayed_weight(weight: f64, last_seen_at: i64, now: i64, half_life_secs: f64) -> f64 {
    if now <= last_seen_at {
        return weight;
    }
    let elapsed = (now - last_seen_at) as f64;
    weight * (0.5_f64).powf(elapsed / half_life_secs)
}

fn normalize_entries(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect()
}

fn normalized_host_id(event: &TelemetryEvent) -> String {
    event
        .host_id
        .as_deref()
        .unwrap_or(event.source.as_str())
        .trim()
        .to_ascii_lowercase()
}

fn normalized_identity(user: Option<&str>) -> String {
    user.unwrap_or("unknown").trim().to_ascii_lowercase()
}

fn normalized_binary_key(process: &ProcessStartEvent) -> String {
    process
        .executable_path
        .as_deref()
        .unwrap_or(process.process_name.as_str())
        .trim()
        .to_ascii_lowercase()
}

fn normalized_timestamp_secs(timestamp: i64) -> i64 {
    if timestamp.abs() >= 100_000_000_000 {
        timestamp / 1_000
    } else {
        timestamp
    }
}

fn inferred_user_role(
    user: Option<&str>,
    privileged_indicators: &[String],
    service_indicators: &[String],
) -> String {
    let user = user.unwrap_or("unknown").trim().to_ascii_lowercase();
    if privileged_indicators
        .iter()
        .any(|indicator| user.contains(indicator))
    {
        "privileged".to_string()
    } else if service_indicators
        .iter()
        .any(|indicator| user.contains(indicator))
        || user.ends_with('$')
    {
        "service".to_string()
    } else {
        "interactive".to_string()
    }
}

fn infer_threat_class(process_name: &str) -> ThreatClass {
    if [
        "powershell",
        "pwsh",
        "rundll32",
        "regsvr32",
        "mshta",
        "wmic",
        "cscript",
        "wscript",
        "certutil",
    ]
    .iter()
    .any(|value| process_name.contains(value))
    {
        ThreatClass::DefenseEvasion
    } else {
        ThreatClass::Execution
    }
}

fn default_sensitive_parent_processes() -> Vec<String> {
    [
        "winword", "excel", "outlook", "acrord32", "teams", "explorer",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_sensitive_child_processes() -> Vec<String> {
    [
        "powershell",
        "pwsh",
        "cmd",
        "rundll32",
        "regsvr32",
        "mshta",
        "wmic",
        "certutil",
        "cscript",
        "wscript",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_rare_role_tools() -> Vec<String> {
    [
        "powershell",
        "pwsh",
        "rundll32",
        "regsvr32",
        "mshta",
        "wmic",
        "certutil",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_trusted_binary_prefixes() -> Vec<String> {
    [
        "c:\\windows\\system32\\",
        "c:\\windows\\syswow64\\",
        "/usr/bin/",
        "/bin/",
        "/usr/sbin/",
        "/sbin/",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_privileged_user_indicators() -> Vec<String> {
    ["system", "root", "administrator", "admin"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_service_user_indicators() -> Vec<String> {
    ["svc", "service", "daemon"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_min_host_observations() -> u64 {
    3
}

fn default_min_identity_observations() -> u64 {
    3
}

fn default_min_peer_group_observations() -> u64 {
    4
}

fn default_min_feature_weight() -> f64 {
    0.25
}

fn default_baseline_half_life_secs() -> f64 {
    3_600.0
}

fn default_high_confidence_threshold() -> f64 {
    0.9
}

fn default_medium_confidence_threshold() -> f64 {
    0.7
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{BehavioralAnomalyDetector, BehavioralAnomalyProfile};
    use crate::detector::{DetectionStrategy, ProcessStartEvent, TelemetryEvent, TelemetryPayload};
    use swarm_core::types::Severity;

    fn event(
        event_id: &str,
        timestamp: i64,
        parent_process: &str,
        process_name: &str,
        executable_path: Option<&str>,
        user: Option<&str>,
    ) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: event_id.to_string(),
            timestamp,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: parent_process.to_string(),
                process_name: process_name.to_string(),
                command_line: process_name.to_string(),
                user: user.map(str::to_string),
                executable_path: executable_path.map(str::to_string),
                signer: None,
                signature_valid: None,
            }),
        }
    }

    fn detector() -> BehavioralAnomalyDetector {
        BehavioralAnomalyDetector::default()
    }

    #[test]
    fn behavioral_anomaly_flags_unusual_parent_child_pair_after_warm_host() {
        let detector = detector();
        for (index, (parent, child)) in [
            ("services", "svchost"),
            ("services", "taskhostw"),
            ("explorer", "notepad"),
        ]
        .into_iter()
        .enumerate()
        {
            assert!(
                detector
                    .evaluate(&event(
                        &format!("warm-{index}"),
                        1_800_000_000 + index as i64,
                        parent,
                        child,
                        None,
                        Some("alice"),
                    ))
                    .is_empty()
            );
        }

        let findings = detector.evaluate(&event(
            "evt-parent-child",
            1_800_000_010,
            "winword",
            "powershell",
            Some("C:\\Users\\alice\\AppData\\Local\\Temp\\pwsh.exe"),
            Some("alice"),
        ));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(
            findings[0].evidence["anomaly_modes"],
            serde_json::json!([
                "host_unusual_parent_child_pair",
                "host_first_seen_binary",
                "host_atypical_role_tool_usage",
                "identity_unusual_parent_child_pair",
                "identity_first_seen_binary",
                "identity_atypical_role_tool_usage"
            ])
        );
        assert_eq!(
            findings[0].evidence["baseline_scope_hits"],
            serde_json::json!(["host", "identity"])
        );
    }

    #[test]
    fn behavioral_anomaly_flags_first_seen_binary_for_untrusted_path() {
        let detector = detector();
        for index in 0..3 {
            detector.evaluate(&event(
                &format!("warm-{index}"),
                1_800_001_000 + index as i64,
                "services",
                "svchost",
                Some("C:\\Windows\\System32\\svchost.exe"),
                Some("SYSTEM"),
            ));
        }

        let findings = detector.evaluate(&event(
            "evt-binary",
            1_800_001_010,
            "chrome",
            "helper",
            Some("C:\\Users\\alice\\Downloads\\helper.exe"),
            Some("alice"),
        ));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(
            findings[0].evidence["anomaly_modes"],
            serde_json::json!(["host_first_seen_binary"])
        );
        assert_eq!(
            findings[0].evidence["baseline_scope_hits"],
            serde_json::json!(["host"])
        );
    }

    #[test]
    fn behavioral_anomaly_can_trigger_peer_group_scope_independently() {
        let detector = BehavioralAnomalyDetector::from_profile(BehavioralAnomalyProfile {
            min_host_observations: 10,
            min_identity_observations: 10,
            min_peer_group_observations: 2,
            ..BehavioralAnomalyProfile::default()
        })
        .unwrap();

        for (index, user) in ["alice", "bob"].into_iter().enumerate() {
            assert!(
                detector
                    .evaluate(&event(
                        &format!("warm-peer-group-{index}"),
                        1_800_001_500 + index as i64,
                        "explorer",
                        "notepad",
                        Some("C:\\Windows\\System32\\notepad.exe"),
                        Some(user),
                    ))
                    .is_empty()
            );
        }

        let findings = detector.evaluate(&event(
            "evt-peer-group",
            1_800_001_510,
            "winword",
            "powershell",
            Some("C:\\Users\\carol\\AppData\\Local\\Temp\\powershell.exe"),
            Some("carol"),
        ));

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].evidence["anomaly_modes"],
            serde_json::json!([
                "peer_group_unusual_parent_child_pair",
                "peer_group_first_seen_binary",
                "peer_group_atypical_role_tool_usage"
            ])
        );
        assert_eq!(
            findings[0].evidence["baseline_scope_hits"],
            serde_json::json!(["peer_group"])
        );
    }

    #[test]
    fn behavioral_anomaly_snapshot_round_trips_and_marks_dirty() {
        let subject = detector();
        for index in 0..4 {
            subject.evaluate(&event(
                &format!("evt-{index}"),
                1_800_002_000 + index as i64,
                "services",
                "svchost",
                Some("C:\\Windows\\System32\\svchost.exe"),
                Some("SYSTEM"),
            ));
        }

        let snapshot = subject
            .snapshot_if_dirty("behavioral_anomaly")
            .expect("snapshot should exist");
        assert_eq!(snapshot.strategy_id, "behavioral_anomaly");
        assert_eq!(snapshot.hosts.len(), 1);
        assert_eq!(snapshot.identities.len(), 1);
        assert_eq!(snapshot.peer_groups.len(), 1);
        assert_eq!(snapshot.hosts[0].observation_count, 4);
        assert_eq!(snapshot.identities[0].identity_id, "system");
        assert_eq!(snapshot.identities[0].observation_count, 4);
        assert_eq!(snapshot.peer_groups[0].peer_group_id, "role:privileged");
        assert_eq!(snapshot.peer_groups[0].observation_count, 4);

        let restored = detector();
        restored.hydrate_from_snapshot(Some(snapshot.clone()));
        let restored_snapshot = restored.snapshot_if_dirty("behavioral_anomaly").is_none();
        assert!(restored_snapshot);
        assert!(!restored.needs_hydration());
    }

    #[test]
    fn behavioral_anomaly_profile_round_trips() {
        let profile = BehavioralAnomalyProfile::default();
        let detector = BehavioralAnomalyDetector::from_profile(profile.clone()).unwrap();
        assert_eq!(detector.profile(), profile);
    }
}
