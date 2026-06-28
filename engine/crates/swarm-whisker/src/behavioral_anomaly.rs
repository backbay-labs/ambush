use crate::detector::{
    AuthenticationEventData, DetectionFinding, DetectionStrategy, DnsQueryEvent,
    FilePersistenceEvent, NetworkConnectEvent, ProcessMemoryAccessEvent, ProcessStartEvent,
    RegistryAccessEvent, RegistryPersistenceEvent, TelemetryEvent, TelemetryPayload,
};
use crate::{ProfileValidationError, validate_confidence_thresholds};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use swarm_core::pheromone::{
    BehavioralBaselineSnapshot, BehavioralFrequencyEntry, BehavioralHostBaseline,
    BehavioralIdentityBaseline, BehavioralOnlineDistributionSnapshot, BehavioralPeerGroupBaseline,
    BehavioralRoleToolFrequencyEntry, BehavioralTelemetryFamilyBaseline, ThreatClass,
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
    #[serde(default = "default_distribution_min_observations")]
    pub distribution_min_observations: u64,
    #[serde(default = "default_distribution_stddev_floor")]
    pub distribution_stddev_floor: f64,
    #[serde(default = "default_high_confidence_z_score")]
    pub high_confidence_z_score: f64,
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
            distribution_min_observations: default_distribution_min_observations(),
            distribution_stddev_floor: default_distribution_stddev_floor(),
            high_confidence_z_score: default_high_confidence_z_score(),
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
    distribution_min_observations: u64,
    distribution_stddev_floor: f64,
    high_confidence_z_score: f64,
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
    novelty_distribution: OnlineDistributionState,
    telemetry_families: HashMap<String, TelemetryFamilyState>,
    parent_child_pairs: HashMap<String, DecayedObservation>,
    binaries: HashMap<String, DecayedObservation>,
    role_tools: HashMap<RoleToolKey, DecayedObservation>,
}

#[derive(Debug, Clone, Default)]
struct TelemetryFamilyState {
    observation_count: u64,
    novelty_distribution: OnlineDistributionState,
    features: HashMap<String, DecayedObservation>,
}

#[derive(Debug, Clone, Default)]
struct OnlineDistributionState {
    sample_count: u64,
    mean: f64,
    m2: f64,
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
    family: &'static str,
    scope: &'static str,
    observation_count: u64,
    pair_weight: f64,
    binary_weight: f64,
    role_tool_weight: f64,
    novelty_pressure: f64,
    distribution_sample_count: u64,
    distribution_mean: f64,
    distribution_stddev: f64,
    feature_observations: Vec<FeatureObservationSummary>,
    anomaly_modes: Vec<String>,
}

#[derive(Debug, Clone)]
struct FeatureObservationSummary {
    label: &'static str,
    key: String,
    weight: f64,
    novelty_pressure: f64,
    suspicious: bool,
}

#[derive(Debug, Clone)]
struct TelemetryFeatureInput {
    label: &'static str,
    key: String,
    anomaly_mode: &'static str,
    suspicious: bool,
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
            distribution_min_observations: profile.distribution_min_observations,
            distribution_stddev_floor: profile.distribution_stddev_floor,
            high_confidence_z_score: profile.high_confidence_z_score,
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
        if self.distribution_min_observations == 0 {
            return Err(ProfileValidationError {
                profile: "BehavioralAnomalyProfile",
                field: "distribution_min_observations",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.distribution_stddev_floor <= 0.0 {
            return Err(ProfileValidationError {
                profile: "BehavioralAnomalyProfile",
                field: "distribution_stddev_floor",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.high_confidence_z_score <= 0.0 {
            return Err(ProfileValidationError {
                profile: "BehavioralAnomalyProfile",
                field: "high_confidence_z_score",
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
            distribution_min_observations: profile.distribution_min_observations,
            distribution_stddev_floor: profile.distribution_stddev_floor,
            high_confidence_z_score: profile.high_confidence_z_score,
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
            distribution_min_observations: self.distribution_min_observations,
            distribution_stddev_floor: self.distribution_stddev_floor,
            high_confidence_z_score: self.high_confidence_z_score,
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
                        host.novelty_distribution,
                        host.telemetry_families,
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
                        identity.novelty_distribution,
                        identity.telemetry_families,
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
                        peer_group.novelty_distribution,
                        peer_group.telemetry_families,
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
                novelty_distribution: host.novelty_distribution.snapshot(),
                telemetry_families: telemetry_family_entries(&host.telemetry_families),
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
                novelty_distribution: identity.novelty_distribution.snapshot(),
                telemetry_families: telemetry_family_entries(&identity.telemetry_families),
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
                novelty_distribution: peer_group.novelty_distribution.snapshot(),
                telemetry_families: telemetry_family_entries(&peer_group.telemetry_families),
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
                    baseline_timestamps(
                        &host.telemetry_families,
                        &host.parent_child_pairs,
                        &host.binaries,
                        &host.role_tools,
                    )
                })
                .chain(identities.iter().flat_map(|identity| {
                    baseline_timestamps(
                        &identity.telemetry_families,
                        &identity.parent_child_pairs,
                        &identity.binaries,
                        &identity.role_tools,
                    )
                }))
                .chain(peer_groups.iter().flat_map(|peer_group| {
                    baseline_timestamps(
                        &peer_group.telemetry_families,
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

        self.build_behavioral_finding(
            event,
            infer_threat_class(&process_name),
            &host_id,
            &identity_id,
            &peer_group_id,
            "process_start",
            json!({
                "user": process.user,
                "user_role": user_role,
                "parent_process": process.parent_process,
                "process_name": process.process_name,
                "executable_path": process.executable_path,
            }),
            [&host_summary, &identity_summary, &peer_group_summary],
        )
    }

    fn evaluate_network_connect(
        &self,
        event: &TelemetryEvent,
        connect: &NetworkConnectEvent,
    ) -> Vec<DetectionFinding> {
        let host_id = normalized_host_id(event);
        let now = normalized_timestamp_secs(event.timestamp);
        let process_name = normalized_process_name(&connect.process_name);
        let identity_id = process_subject_identity(Some(&process_name));
        let peer_group_id = format!("network_process:{process_name}");
        let protocol = connect.protocol.trim().to_ascii_lowercase();
        let destination_ip = connect.destination_ip.trim().to_ascii_lowercase();
        let feature_inputs = vec![
            TelemetryFeatureInput {
                label: "network_flow",
                key: format!(
                    "network:{process_name}->{destination_ip}:{}:{protocol}",
                    connect.destination_port
                ),
                anomaly_mode: "network_novel_flow",
                suspicious: true,
            },
            TelemetryFeatureInput {
                label: "network_destination",
                key: format!(
                    "network_destination:{process_name}->{protocol}:{}",
                    connect.destination_port
                ),
                anomaly_mode: "network_novel_destination",
                suspicious: true,
            },
        ];
        let (host_summary, identity_summary, peer_group_summary) = {
            let mut state = match self.state.write() {
                Ok(guard) => guard,
                Err(_) => return Vec::new(),
            };
            let summaries = self.observe_family_summaries(
                &mut state,
                &host_id,
                &identity_id,
                &peer_group_id,
                now,
                "network_connect",
                &feature_inputs,
            );
            state.dirty = true;
            summaries
        };

        self.build_behavioral_finding(
            event,
            ThreatClass::CommandAndControl,
            &host_id,
            &identity_id,
            &peer_group_id,
            "network_connect",
            json!({
                "process_name": connect.process_name,
                "destination_ip": connect.destination_ip,
                "destination_port": connect.destination_port,
                "protocol": connect.protocol,
            }),
            [&host_summary, &identity_summary, &peer_group_summary],
        )
    }

    fn evaluate_dns_query(
        &self,
        event: &TelemetryEvent,
        dns: &DnsQueryEvent,
    ) -> Vec<DetectionFinding> {
        let host_id = normalized_host_id(event);
        let now = normalized_timestamp_secs(event.timestamp);
        let process_name = normalized_optional_process_name(dns.process_name.as_deref());
        let identity_id = if process_name == "unknown" {
            source_subject_identity(dns.source_ip.as_deref())
        } else {
            process_subject_identity(Some(&process_name))
        };
        let peer_group_id = format!("dns_process:{process_name}");
        let family_domain = apex_domain(&dns.query_name);
        let feature_inputs = vec![TelemetryFeatureInput {
            label: "dns_query",
            key: format!(
                "dns:{process_name}->{family_domain}:{}",
                dns.query_type.trim().to_ascii_lowercase()
            ),
            anomaly_mode: "dns_novel_query",
            suspicious: true,
        }];
        let (host_summary, identity_summary, peer_group_summary) = {
            let mut state = match self.state.write() {
                Ok(guard) => guard,
                Err(_) => return Vec::new(),
            };
            let summaries = self.observe_family_summaries(
                &mut state,
                &host_id,
                &identity_id,
                &peer_group_id,
                now,
                "dns_query",
                &feature_inputs,
            );
            state.dirty = true;
            summaries
        };

        self.build_behavioral_finding(
            event,
            ThreatClass::DataExfiltration,
            &host_id,
            &identity_id,
            &peer_group_id,
            "dns_query",
            json!({
                "process_name": dns.process_name,
                "query_name": dns.query_name,
                "query_type": dns.query_type,
                "source_ip": dns.source_ip,
                "response_code": dns.response_code,
            }),
            [&host_summary, &identity_summary, &peer_group_summary],
        )
    }

    fn evaluate_authentication(
        &self,
        event: &TelemetryEvent,
        auth: &AuthenticationEventData,
    ) -> Vec<DetectionFinding> {
        let host_id = normalized_host_id(event);
        let now = normalized_timestamp_secs(event.timestamp);
        let identity_id = if auth.user.is_some() {
            normalized_identity(auth.user.as_deref())
        } else {
            process_subject_identity(auth.process_name.as_deref())
        };
        let auth_type = auth.auth_type.trim().to_ascii_lowercase();
        let target_service = auth
            .target_service
            .as_deref()
            .unwrap_or("unknown")
            .trim()
            .to_ascii_lowercase();
        let peer_group_id = format!("authentication:{auth_type}:{target_service}");
        let user_role = inferred_user_role(
            auth.user.as_deref(),
            &self.privileged_user_indicators,
            &self.service_user_indicators,
        );
        let feature_inputs = vec![
            TelemetryFeatureInput {
                label: "authentication_target",
                key: format!(
                    "auth:{user_role}:{auth_type}:{}:{}:{}",
                    auth.target_host
                        .as_deref()
                        .unwrap_or("unknown")
                        .trim()
                        .to_ascii_lowercase(),
                    target_service,
                    if auth.success { "success" } else { "failure" }
                ),
                anomaly_mode: "authentication_novel_target",
                suspicious: true,
            },
            TelemetryFeatureInput {
                label: "authentication_source",
                key: format!(
                    "auth_source:{}:{}",
                    auth.source_host
                        .as_deref()
                        .unwrap_or("unknown")
                        .trim()
                        .to_ascii_lowercase(),
                    auth.target_host
                        .as_deref()
                        .unwrap_or("unknown")
                        .trim()
                        .to_ascii_lowercase(),
                ),
                anomaly_mode: "authentication_novel_source",
                suspicious: true,
            },
        ];
        let (host_summary, identity_summary, peer_group_summary) = {
            let mut state = match self.state.write() {
                Ok(guard) => guard,
                Err(_) => return Vec::new(),
            };
            let summaries = self.observe_family_summaries(
                &mut state,
                &host_id,
                &identity_id,
                &peer_group_id,
                now,
                "authentication_event",
                &feature_inputs,
            );
            state.dirty = true;
            summaries
        };

        self.build_behavioral_finding(
            event,
            if auth.success {
                ThreatClass::LateralMovement
            } else {
                ThreatClass::CredentialAccess
            },
            &host_id,
            &identity_id,
            &peer_group_id,
            "authentication_event",
            json!({
                "auth_type": auth.auth_type,
                "source_host": auth.source_host,
                "target_host": auth.target_host,
                "target_service": auth.target_service,
                "process_name": auth.process_name,
                "user": auth.user,
                "success": auth.success,
                "user_role": user_role,
            }),
            [&host_summary, &identity_summary, &peer_group_summary],
        )
    }

    fn evaluate_registry_access(
        &self,
        event: &TelemetryEvent,
        registry: &RegistryAccessEvent,
    ) -> Vec<DetectionFinding> {
        let host_id = normalized_host_id(event);
        let now = normalized_timestamp_secs(event.timestamp);
        let process_name = normalized_process_name(&registry.process_name);
        let identity_id = process_subject_identity(Some(&process_name));
        let peer_group_id = format!("registry_access_process:{process_name}");
        let feature_inputs = vec![TelemetryFeatureInput {
            label: "registry_access",
            key: format!(
                "registry_access:{process_name}:{}:{}:{}",
                registry.access_type.trim().to_ascii_lowercase(),
                normalized_registry_bucket(&registry.registry_path),
                registry
                    .target_process
                    .as_deref()
                    .unwrap_or("unknown")
                    .trim()
                    .to_ascii_lowercase(),
            ),
            anomaly_mode: "credential_novel_registry_access",
            suspicious: true,
        }];
        let (host_summary, identity_summary, peer_group_summary) = {
            let mut state = match self.state.write() {
                Ok(guard) => guard,
                Err(_) => return Vec::new(),
            };
            let summaries = self.observe_family_summaries(
                &mut state,
                &host_id,
                &identity_id,
                &peer_group_id,
                now,
                "registry_access",
                &feature_inputs,
            );
            state.dirty = true;
            summaries
        };

        self.build_behavioral_finding(
            event,
            ThreatClass::CredentialAccess,
            &host_id,
            &identity_id,
            &peer_group_id,
            "registry_access",
            json!({
                "process_name": registry.process_name,
                "registry_path": registry.registry_path,
                "access_type": registry.access_type,
                "target_process": registry.target_process,
            }),
            [&host_summary, &identity_summary, &peer_group_summary],
        )
    }

    fn evaluate_registry_persistence(
        &self,
        event: &TelemetryEvent,
        registry: &RegistryPersistenceEvent,
    ) -> Vec<DetectionFinding> {
        let host_id = normalized_host_id(event);
        let now = normalized_timestamp_secs(event.timestamp);
        let process_name = normalized_process_name(&registry.process_name);
        let identity_id = process_subject_identity(Some(&process_name));
        let peer_group_id = format!("registry_persistence_process:{process_name}");
        let feature_inputs = vec![TelemetryFeatureInput {
            label: "registry_persistence",
            key: format!(
                "registry_persistence:{process_name}:{}:{}:{}",
                registry.access_type.trim().to_ascii_lowercase(),
                normalized_registry_bucket(&registry.registry_path),
                registry
                    .value_name
                    .as_deref()
                    .unwrap_or("unknown")
                    .trim()
                    .to_ascii_lowercase(),
            ),
            anomaly_mode: "persistence_novel_registry_artifact",
            suspicious: true,
        }];
        let (host_summary, identity_summary, peer_group_summary) = {
            let mut state = match self.state.write() {
                Ok(guard) => guard,
                Err(_) => return Vec::new(),
            };
            let summaries = self.observe_family_summaries(
                &mut state,
                &host_id,
                &identity_id,
                &peer_group_id,
                now,
                "registry_persistence",
                &feature_inputs,
            );
            state.dirty = true;
            summaries
        };

        self.build_behavioral_finding(
            event,
            ThreatClass::Persistence,
            &host_id,
            &identity_id,
            &peer_group_id,
            "registry_persistence",
            json!({
                "process_name": registry.process_name,
                "registry_path": registry.registry_path,
                "value_name": registry.value_name,
                "value_data": registry.value_data,
                "access_type": registry.access_type,
            }),
            [&host_summary, &identity_summary, &peer_group_summary],
        )
    }

    fn evaluate_file_persistence(
        &self,
        event: &TelemetryEvent,
        file: &FilePersistenceEvent,
    ) -> Vec<DetectionFinding> {
        let host_id = normalized_host_id(event);
        let now = normalized_timestamp_secs(event.timestamp);
        let process_name = normalized_process_name(&file.process_name);
        let identity_id = process_subject_identity(Some(&process_name));
        let peer_group_id = format!("file_persistence_process:{process_name}");
        let feature_inputs = vec![TelemetryFeatureInput {
            label: "file_persistence",
            key: format!(
                "file_persistence:{process_name}:{}:{}",
                file.operation.trim().to_ascii_lowercase(),
                normalized_path_bucket(&file.file_path),
            ),
            anomaly_mode: "persistence_novel_file_artifact",
            suspicious: true,
        }];
        let (host_summary, identity_summary, peer_group_summary) = {
            let mut state = match self.state.write() {
                Ok(guard) => guard,
                Err(_) => return Vec::new(),
            };
            let summaries = self.observe_family_summaries(
                &mut state,
                &host_id,
                &identity_id,
                &peer_group_id,
                now,
                "file_persistence",
                &feature_inputs,
            );
            state.dirty = true;
            summaries
        };

        self.build_behavioral_finding(
            event,
            ThreatClass::Persistence,
            &host_id,
            &identity_id,
            &peer_group_id,
            "file_persistence",
            json!({
                "process_name": file.process_name,
                "file_path": file.file_path,
                "operation": file.operation,
                "content_preview": file.content_preview,
            }),
            [&host_summary, &identity_summary, &peer_group_summary],
        )
    }

    fn evaluate_process_memory_access(
        &self,
        event: &TelemetryEvent,
        access: &ProcessMemoryAccessEvent,
    ) -> Vec<DetectionFinding> {
        let host_id = normalized_host_id(event);
        let now = normalized_timestamp_secs(event.timestamp);
        let source_process = normalized_process_name(&access.source_process);
        let identity_id = process_subject_identity(Some(&source_process));
        let peer_group_id = format!("memory_source:{source_process}");
        let feature_inputs = vec![
            TelemetryFeatureInput {
                label: "memory_access_pattern",
                key: format!(
                    "memory:{source_process}->{}:{}",
                    normalized_process_name(&access.target_process),
                    access.allocation_type.trim().to_ascii_lowercase(),
                ),
                anomaly_mode: "memory_novel_access_pattern",
                suspicious: true,
            },
            TelemetryFeatureInput {
                label: "memory_protection_flags",
                key: format!(
                    "memory_flags:{source_process}->{}",
                    normalized_flag_set(&access.protection_flags),
                ),
                anomaly_mode: "memory_novel_protection_flags",
                suspicious: true,
            },
        ];
        let (host_summary, identity_summary, peer_group_summary) = {
            let mut state = match self.state.write() {
                Ok(guard) => guard,
                Err(_) => return Vec::new(),
            };
            let summaries = self.observe_family_summaries(
                &mut state,
                &host_id,
                &identity_id,
                &peer_group_id,
                now,
                "process_memory_access",
                &feature_inputs,
            );
            state.dirty = true;
            summaries
        };

        self.build_behavioral_finding(
            event,
            ThreatClass::DefenseEvasion,
            &host_id,
            &identity_id,
            &peer_group_id,
            "process_memory_access",
            json!({
                "source_process": access.source_process,
                "target_process": access.target_process,
                "allocation_type": access.allocation_type,
                "protection_flags": access.protection_flags,
                "region_size": access.region_size,
                "call_stack_hint": access.call_stack_hint,
            }),
            [&host_summary, &identity_summary, &peer_group_summary],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_family_summaries(
        &self,
        state: &mut BehavioralDetectorState,
        host_id: &str,
        identity_id: &str,
        peer_group_id: &str,
        now: i64,
        family: &'static str,
        feature_inputs: &[TelemetryFeatureInput],
    ) -> (
        ScopeObservationSummary,
        ScopeObservationSummary,
        ScopeObservationSummary,
    ) {
        let host_summary = observe_family_scope(
            state.hosts.entry(host_id.to_string()).or_default(),
            family,
            "host",
            self.min_host_observations,
            now,
            self.baseline_half_life_secs,
            self.min_feature_weight,
            feature_inputs,
        );
        let identity_summary = observe_family_scope(
            state.identities.entry(identity_id.to_string()).or_default(),
            family,
            "identity",
            self.min_identity_observations,
            now,
            self.baseline_half_life_secs,
            self.min_feature_weight,
            feature_inputs,
        );
        let peer_group_summary = observe_family_scope(
            state
                .peer_groups
                .entry(peer_group_id.to_string())
                .or_default(),
            family,
            "peer_group",
            self.min_peer_group_observations,
            now,
            self.baseline_half_life_secs,
            self.min_feature_weight,
            feature_inputs,
        );
        (host_summary, identity_summary, peer_group_summary)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_behavioral_finding(
        &self,
        event: &TelemetryEvent,
        threat_class: ThreatClass,
        host_id: &str,
        identity_id: &str,
        peer_group_id: &str,
        telemetry_family: &'static str,
        extra_evidence: serde_json::Value,
        summaries: [&ScopeObservationSummary; 3],
    ) -> Vec<DetectionFinding> {
        let anomaly_modes = summaries
            .iter()
            .flat_map(|summary| summary.anomaly_modes.clone())
            .collect::<Vec<_>>();
        if anomaly_modes.is_empty() {
            return Vec::new();
        }

        let scope_hits = summaries
            .into_iter()
            .filter_map(|summary| (!summary.anomaly_modes.is_empty()).then_some(summary.scope))
            .collect::<Vec<_>>();
        let signal_count = anomaly_modes.len();
        let confidence_scopes = summaries
            .into_iter()
            .filter(|summary| !summary.anomaly_modes.is_empty())
            .map(|summary| {
                let z_score = summary.deviation_z_score(self.distribution_stddev_floor);
                let sample_support =
                    summary.sample_support(self.distribution_min_observations);
                let deviation_score = z_score * sample_support;
                json!({
                    "family": summary.family,
                    "scope": summary.scope,
                    "novelty_pressure": summary.novelty_pressure,
                    "distribution_sample_count": summary.distribution_sample_count,
                    "distribution_mean": summary.distribution_mean,
                    "distribution_stddev": summary.distribution_stddev,
                    "distribution_ready": summary.distribution_sample_count >= self.distribution_min_observations,
                    "z_score": z_score,
                    "sample_support": sample_support,
                    "deviation_score": deviation_score,
                    "feature_observations": summary.feature_observations.iter().map(|feature| {
                        json!({
                            "label": feature.label,
                            "key": feature.key,
                            "weight_before_update": feature.weight,
                            "novelty_pressure": feature.novelty_pressure,
                            "suspicious": feature.suspicious,
                        })
                    }).collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>();
        let aggregate_deviation_score = confidence_scopes
            .iter()
            .filter_map(|scope| {
                scope
                    .get("deviation_score")
                    .and_then(|value| value.as_f64())
            })
            .sum::<f64>()
            / confidence_scopes.len() as f64;
        let confidence_ratio =
            (aggregate_deviation_score / self.high_confidence_z_score).clamp(0.0, 1.0);
        let confidence = (self.medium_confidence_threshold
            + confidence_ratio
                * (self.high_confidence_threshold - self.medium_confidence_threshold))
            .clamp(
                self.medium_confidence_threshold,
                self.high_confidence_threshold,
            );
        let severity = if signal_count >= 2 || scope_hits.len() >= 2 {
            Severity::High
        } else {
            Severity::Medium
        };

        let mut evidence = serde_json::Map::new();
        evidence.insert("source".to_string(), json!(event.source));
        evidence.insert("host_id".to_string(), json!(host_id));
        evidence.insert("identity_id".to_string(), json!(identity_id));
        evidence.insert("peer_group_id".to_string(), json!(peer_group_id));
        evidence.insert("telemetry_family".to_string(), json!(telemetry_family));
        evidence.insert("anomaly_modes".to_string(), json!(anomaly_modes));
        evidence.insert("baseline_scope_hits".to_string(), json!(scope_hits));
        evidence.insert(
            "baseline".to_string(),
            json!({
                "host": scope_summary_json(summaries[0]),
                "identity": scope_summary_json(summaries[1]),
                "peer_group": scope_summary_json(summaries[2]),
                "baseline_half_life_secs": self.baseline_half_life_secs,
            }),
        );
        evidence.insert(
            "deviation_scoring".to_string(),
            json!({
                "model": "z_score",
                "distribution_min_observations": self.distribution_min_observations,
                "distribution_stddev_floor": self.distribution_stddev_floor,
                "high_confidence_z_score": self.high_confidence_z_score,
                "aggregate_deviation_score": aggregate_deviation_score,
                "confidence_ratio": confidence_ratio,
                "scopes": confidence_scopes,
            }),
        );
        if let Some(extra_object) = extra_evidence.as_object() {
            for (key, value) in extra_object {
                evidence.insert(key.clone(), value.clone());
            }
        }

        vec![DetectionFinding {
            finding_id: format!("{}:{}", self.id(), event.event_id),
            event_id: event.event_id.clone(),
            threat_class,
            severity,
            confidence,
            evidence: serde_json::Value::Object(evidence),
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
            TelemetryPayload::NetworkConnect(connect) => {
                self.evaluate_network_connect(event, connect)
            }
            TelemetryPayload::ProcessMemoryAccess(access) => {
                self.evaluate_process_memory_access(event, access)
            }
            TelemetryPayload::DnsQuery(dns) => self.evaluate_dns_query(event, dns),
            TelemetryPayload::RegistryAccess(registry) => {
                self.evaluate_registry_access(event, registry)
            }
            TelemetryPayload::RegistryPersistence(registry) => {
                self.evaluate_registry_persistence(event, registry)
            }
            TelemetryPayload::FilePersistence(file) => self.evaluate_file_persistence(event, file),
            TelemetryPayload::AuthenticationEvent(auth) => {
                self.evaluate_authentication(event, auth)
            }
            TelemetryPayload::InfrastructureHealth(_)
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
        self.telemetry_families.retain(|_, family| {
            normalize_observation_map(
                &mut family.features,
                now,
                half_life_secs,
                min_feature_weight,
            );
            !family.features.is_empty() || family.observation_count > 0
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

impl OnlineDistributionState {
    fn from_snapshot(snapshot: BehavioralOnlineDistributionSnapshot) -> Self {
        Self {
            sample_count: snapshot.sample_count,
            mean: snapshot.mean,
            m2: snapshot.m2,
        }
    }

    fn snapshot(&self) -> BehavioralOnlineDistributionSnapshot {
        BehavioralOnlineDistributionSnapshot {
            sample_count: self.sample_count,
            mean: self.mean,
            m2: self.m2,
        }
    }

    fn observe(&mut self, value: f64) {
        self.sample_count = self.sample_count.saturating_add(1);
        let delta = value - self.mean;
        self.mean += delta / self.sample_count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    fn stddev(&self) -> f64 {
        if self.sample_count < 2 {
            return 0.0;
        }
        (self.m2 / (self.sample_count as f64 - 1.0)).sqrt()
    }
}

impl ScopeObservationSummary {
    fn deviation_z_score(&self, stddev_floor: f64) -> f64 {
        if self.novelty_pressure <= 0.0 {
            return 0.0;
        }
        let deviation = (self.novelty_pressure - self.distribution_mean).max(0.0);
        let stddev = self.distribution_stddev.max(stddev_floor);
        if stddev <= 0.0 {
            return 0.0;
        }
        deviation / stddev
    }

    fn sample_support(&self, min_samples: u64) -> f64 {
        if min_samples == 0 {
            return 1.0;
        }
        (self.distribution_sample_count as f64 / min_samples as f64).clamp(0.0, 1.0)
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
    let learning_active = state.observation_count.saturating_add(1) >= min_observations;
    let pair_pressure = novelty_pressure(pair_weight, min_feature_weight);
    let binary_pressure = novelty_pressure(binary_weight, min_feature_weight);
    let role_tool_pressure = novelty_pressure(role_tool_weight, min_feature_weight);

    let mut anomaly_modes = Vec::new();
    if scope_is_warm && pair_pressure > 0.0 && sensitive_pair {
        anomaly_modes.push(format!("{scope}_unusual_parent_child_pair"));
    }
    if scope_is_warm && binary_pressure > 0.0 && first_seen_binary_alert {
        anomaly_modes.push(format!("{scope}_first_seen_binary"));
    }
    if scope_is_warm && role_tool_pressure > 0.0 && process_is_rare_tool {
        anomaly_modes.push(format!("{scope}_atypical_role_tool_usage"));
    }
    let novelty_pressure = if scope_is_warm {
        let pair_component = if sensitive_pair { pair_pressure } else { 0.0 };
        let binary_component = if first_seen_binary_alert {
            binary_pressure
        } else {
            0.0
        };
        let role_tool_component = if process_is_rare_tool {
            role_tool_pressure
        } else {
            0.0
        };
        ((pair_component + binary_component + role_tool_component) / 3.0).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let distribution_sample_count = state.novelty_distribution.sample_count;
    let distribution_mean = state.novelty_distribution.mean;
    let distribution_stddev = state.novelty_distribution.stddev();
    if learning_active {
        state.novelty_distribution.observe(novelty_pressure);
    }

    state.observe_pair(pair_key.to_string(), now);
    state.observe_binary(executable_key.to_string(), now);
    state.observe_role_tool(role_tool_key.clone(), now);
    state.observation_count = state.observation_count.saturating_add(1);

    ScopeObservationSummary {
        family: "process_start",
        scope,
        observation_count: state.observation_count,
        pair_weight,
        binary_weight,
        role_tool_weight,
        novelty_pressure,
        distribution_sample_count,
        distribution_mean,
        distribution_stddev,
        feature_observations: vec![
            FeatureObservationSummary {
                label: "parent_child_pair",
                key: pair_key.to_string(),
                weight: pair_weight,
                novelty_pressure: pair_pressure,
                suspicious: sensitive_pair,
            },
            FeatureObservationSummary {
                label: "binary",
                key: executable_key.to_string(),
                weight: binary_weight,
                novelty_pressure: binary_pressure,
                suspicious: first_seen_binary_alert,
            },
            FeatureObservationSummary {
                label: "role_tool",
                key: format!("{}:{}", role_tool_key.user_role, role_tool_key.tool),
                weight: role_tool_weight,
                novelty_pressure: role_tool_pressure,
                suspicious: process_is_rare_tool,
            },
        ],
        anomaly_modes,
    }
}

#[allow(clippy::too_many_arguments)]
fn observe_family_scope(
    state: &mut ScopeBaselineState,
    family: &'static str,
    scope: &'static str,
    min_observations: u64,
    now: i64,
    baseline_half_life_secs: f64,
    min_feature_weight: f64,
    feature_inputs: &[TelemetryFeatureInput],
) -> ScopeObservationSummary {
    state.normalize(now, baseline_half_life_secs, min_feature_weight);
    let family_state = state
        .telemetry_families
        .entry(family.to_string())
        .or_default();
    let scope_is_warm = family_state.observation_count >= min_observations;
    let learning_active = family_state.observation_count.saturating_add(1) >= min_observations;

    let mut anomaly_modes = Vec::new();
    let mut novelty_total = 0.0;
    let mut feature_observations = Vec::new();
    for feature in feature_inputs {
        let weight = family_state
            .features
            .get(&feature.key)
            .map(|entry| entry.weight)
            .unwrap_or_default();
        let pressure = novelty_pressure(weight, min_feature_weight);
        if scope_is_warm && feature.suspicious && pressure > 0.0 {
            anomaly_modes.push(format!("{scope}_{}", feature.anomaly_mode));
        }
        novelty_total += if feature.suspicious { pressure } else { 0.0 };
        feature_observations.push(FeatureObservationSummary {
            label: feature.label,
            key: feature.key.clone(),
            weight,
            novelty_pressure: pressure,
            suspicious: feature.suspicious,
        });
    }

    let novelty_pressure = if scope_is_warm && !feature_inputs.is_empty() {
        (novelty_total / feature_inputs.len() as f64).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let distribution_sample_count = family_state.novelty_distribution.sample_count;
    let distribution_mean = family_state.novelty_distribution.mean;
    let distribution_stddev = family_state.novelty_distribution.stddev();
    if learning_active {
        family_state.novelty_distribution.observe(novelty_pressure);
    }
    for feature in feature_inputs {
        observe_key(&mut family_state.features, feature.key.clone(), now);
    }
    family_state.observation_count = family_state.observation_count.saturating_add(1);

    ScopeObservationSummary {
        family,
        scope,
        observation_count: family_state.observation_count,
        pair_weight: 0.0,
        binary_weight: 0.0,
        role_tool_weight: 0.0,
        novelty_pressure,
        distribution_sample_count,
        distribution_mean,
        distribution_stddev,
        feature_observations,
        anomaly_modes,
    }
}

fn scope_summary_json(summary: &ScopeObservationSummary) -> serde_json::Value {
    json!({
        "family": summary.family,
        "observation_count": summary.observation_count,
        "pair_weight_before_update": summary.pair_weight,
        "binary_weight_before_update": summary.binary_weight,
        "role_tool_weight_before_update": summary.role_tool_weight,
        "novelty_pressure_before_update": summary.novelty_pressure,
        "online_distribution_before_update": {
            "sample_count": summary.distribution_sample_count,
            "mean": summary.distribution_mean,
            "stddev": summary.distribution_stddev,
        },
        "feature_observations": summary.feature_observations.iter().map(|feature| {
            json!({
                "label": feature.label,
                "key": feature.key,
                "weight_before_update": feature.weight,
                "novelty_pressure": feature.novelty_pressure,
                "suspicious": feature.suspicious,
            })
        }).collect::<Vec<_>>(),
        "anomaly_modes": summary.anomaly_modes,
    })
}

fn scope_state_from_entries(
    observation_count: u64,
    novelty_distribution: BehavioralOnlineDistributionSnapshot,
    telemetry_families: Vec<BehavioralTelemetryFamilyBaseline>,
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
    let mut telemetry_family_map = HashMap::new();
    for family in telemetry_families {
        let mut feature_map = HashMap::new();
        for entry in family.features {
            feature_map.insert(
                entry.key,
                DecayedObservation {
                    weight: entry.weight,
                    last_seen_at: entry.last_seen_at,
                },
            );
        }
        telemetry_family_map.insert(
            family.family,
            TelemetryFamilyState {
                observation_count: family.observation_count,
                novelty_distribution: OnlineDistributionState::from_snapshot(
                    family.novelty_distribution,
                ),
                features: feature_map,
            },
        );
    }

    ScopeBaselineState {
        observation_count,
        novelty_distribution: OnlineDistributionState::from_snapshot(novelty_distribution),
        telemetry_families: telemetry_family_map,
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

fn telemetry_family_entries(
    map: &HashMap<String, TelemetryFamilyState>,
) -> Vec<BehavioralTelemetryFamilyBaseline> {
    let mut entries = map
        .iter()
        .map(|(family, state)| BehavioralTelemetryFamilyBaseline {
            family: family.clone(),
            observation_count: state.observation_count,
            novelty_distribution: state.novelty_distribution.snapshot(),
            features: frequency_entries(&state.features),
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.family.cmp(&right.family));
    entries
}

fn baseline_timestamps<'a>(
    telemetry_families: &'a [BehavioralTelemetryFamilyBaseline],
    parent_child_pairs: &'a [BehavioralFrequencyEntry],
    binaries: &'a [BehavioralFrequencyEntry],
    role_tools: &'a [BehavioralRoleToolFrequencyEntry],
) -> impl Iterator<Item = i64> + 'a {
    telemetry_families
        .iter()
        .flat_map(|family| family.features.iter().map(|entry| entry.last_seen_at))
        .chain(parent_child_pairs.iter().map(|entry| entry.last_seen_at))
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

fn novelty_pressure(weight: f64, min_feature_weight: f64) -> f64 {
    if min_feature_weight <= 0.0 || weight >= min_feature_weight {
        return 0.0;
    }
    ((min_feature_weight - weight) / min_feature_weight).clamp(0.0, 1.0)
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

fn normalized_process_name(process_name: &str) -> String {
    process_name.trim().to_ascii_lowercase()
}

fn normalized_optional_process_name(process_name: Option<&str>) -> String {
    process_name
        .unwrap_or("unknown")
        .trim()
        .to_ascii_lowercase()
}

fn process_subject_identity(process_name: Option<&str>) -> String {
    format!("process:{}", normalized_optional_process_name(process_name))
}

fn source_subject_identity(source: Option<&str>) -> String {
    format!(
        "source:{}",
        source.unwrap_or("unknown").trim().to_ascii_lowercase()
    )
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

fn normalized_registry_bucket(path: &str) -> String {
    let segments = path
        .split(['\\', '/'])
        .filter(|segment| !segment.trim().is_empty())
        .take(3)
        .map(|segment| segment.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        "unknown".to_string()
    } else {
        segments.join("\\")
    }
}

fn normalized_path_bucket(path: &str) -> String {
    path.trim().to_ascii_lowercase()
}

fn normalized_flag_set(flags: &[String]) -> String {
    let mut flags = flags
        .iter()
        .map(|flag| flag.trim().to_ascii_lowercase())
        .filter(|flag| !flag.is_empty())
        .collect::<Vec<_>>();
    flags.sort();
    if flags.is_empty() {
        "none".to_string()
    } else {
        flags.join("|")
    }
}

fn apex_domain(query_name: &str) -> String {
    let normalized = query_name.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels = normalized
        .split('.')
        .filter(|label| !label.is_empty())
        .collect::<Vec<_>>();
    if labels.len() <= 2 {
        return labels.join(".");
    }
    labels[labels.len() - 2..].join(".")
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

fn default_distribution_min_observations() -> u64 {
    2
}

fn default_distribution_stddev_floor() -> f64 {
    0.2
}

fn default_high_confidence_z_score() -> f64 {
    3.0
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
    use crate::detector::{
        AuthenticationEventData, DetectionStrategy, DnsQueryEvent, FilePersistenceEvent,
        NetworkConnectEvent, ProcessMemoryAccessEvent, ProcessStartEvent, RegistryAccessEvent,
        RegistryPersistenceEvent, TelemetryEvent, TelemetryPayload,
    };
    use swarm_core::{ThreatClass, types::Severity};

    fn telemetry_event(
        event_id: &str,
        timestamp: i64,
        payload: TelemetryPayload,
    ) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: event_id.to_string(),
            timestamp,
            host_id: Some("host-1".to_string()),
            payload,
        }
    }

    fn event(
        event_id: &str,
        timestamp: i64,
        parent_process: &str,
        process_name: &str,
        executable_path: Option<&str>,
        user: Option<&str>,
    ) -> TelemetryEvent {
        telemetry_event(
            event_id,
            timestamp,
            TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: parent_process.to_string(),
                process_name: process_name.to_string(),
                command_line: process_name.to_string(),
                user: user.map(str::to_string),
                executable_path: executable_path.map(str::to_string),
                signer: None,
                signature_valid: None,
            }),
        )
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
        for index in 0..4 {
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
        assert!(findings[0].confidence > detector.profile().medium_confidence_threshold);
        assert_eq!(
            findings[0].evidence["anomaly_modes"],
            serde_json::json!(["host_first_seen_binary"])
        );
        assert_eq!(
            findings[0].evidence["baseline_scope_hits"],
            serde_json::json!(["host"])
        );
        assert_eq!(
            findings[0].evidence["deviation_scoring"]["model"],
            serde_json::json!("z_score")
        );
        assert!(
            findings[0].evidence["deviation_scoring"]["aggregate_deviation_score"]
                .as_f64()
                .unwrap()
                > 0.0
        );
        assert_eq!(
            findings[0].evidence["deviation_scoring"]["scopes"][0]["scope"],
            serde_json::json!("host")
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
        for index in 0..3 {
            subject.evaluate(&telemetry_event(
                &format!("net-{index}"),
                1_800_002_100 + index as i64,
                TelemetryPayload::NetworkConnect(NetworkConnectEvent {
                    process_name: "svchost.exe".to_string(),
                    destination_ip: "10.0.0.5".to_string(),
                    destination_port: 443,
                    protocol: "tcp".to_string(),
                }),
            ));
        }

        let snapshot = subject
            .snapshot_if_dirty("behavioral_anomaly")
            .expect("snapshot should exist");
        assert_eq!(snapshot.strategy_id, "behavioral_anomaly");
        assert_eq!(snapshot.hosts.len(), 1);
        assert_eq!(snapshot.identities.len(), 2);
        assert_eq!(snapshot.peer_groups.len(), 2);
        assert_eq!(snapshot.hosts[0].observation_count, 4);
        assert_eq!(snapshot.hosts[0].novelty_distribution.sample_count, 2);
        assert_eq!(snapshot.hosts[0].telemetry_families.len(), 1);
        assert_eq!(
            snapshot.hosts[0].telemetry_families[0].family,
            "network_connect"
        );
        let system_identity = snapshot
            .identities
            .iter()
            .find(|identity| identity.identity_id == "system")
            .unwrap();
        assert_eq!(system_identity.observation_count, 4);
        assert_eq!(system_identity.novelty_distribution.sample_count, 2);
        let process_identity = snapshot
            .identities
            .iter()
            .find(|identity| identity.identity_id == "process:svchost.exe")
            .unwrap();
        assert_eq!(
            process_identity.telemetry_families[0].family,
            "network_connect"
        );
        let privileged_peer_group = snapshot
            .peer_groups
            .iter()
            .find(|peer_group| peer_group.peer_group_id == "role:privileged")
            .unwrap();
        assert_eq!(privileged_peer_group.observation_count, 4);
        assert_eq!(privileged_peer_group.novelty_distribution.sample_count, 1);
        let network_peer_group = snapshot
            .peer_groups
            .iter()
            .find(|peer_group| peer_group.peer_group_id == "network_process:svchost.exe")
            .unwrap();
        assert_eq!(
            network_peer_group.telemetry_families[0].family,
            "network_connect"
        );

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

    #[test]
    fn behavioral_anomaly_profile_rejects_invalid_distribution_learning_bounds() {
        let invalid_min = BehavioralAnomalyProfile {
            distribution_min_observations: 0,
            ..BehavioralAnomalyProfile::default()
        };
        assert!(invalid_min.validate().is_err());

        let invalid_floor = BehavioralAnomalyProfile {
            distribution_stddev_floor: 0.0,
            ..BehavioralAnomalyProfile::default()
        };
        assert!(invalid_floor.validate().is_err());

        let invalid_z_score = BehavioralAnomalyProfile {
            high_confidence_z_score: 0.0,
            ..BehavioralAnomalyProfile::default()
        };
        assert!(invalid_z_score.validate().is_err());
    }

    #[test]
    fn behavioral_anomaly_emits_findings_for_non_process_telemetry_families() {
        let detector = BehavioralAnomalyDetector::from_profile(BehavioralAnomalyProfile {
            min_host_observations: 2,
            min_identity_observations: 2,
            min_peer_group_observations: 2,
            distribution_min_observations: 1,
            ..BehavioralAnomalyProfile::default()
        })
        .unwrap();

        let cases = vec![
            (
                "network_connect",
                ThreatClass::CommandAndControl,
                telemetry_event(
                    "network-warm-1",
                    1_800_003_000,
                    TelemetryPayload::NetworkConnect(NetworkConnectEvent {
                        process_name: "svchost.exe".to_string(),
                        destination_ip: "10.0.0.5".to_string(),
                        destination_port: 443,
                        protocol: "tcp".to_string(),
                    }),
                ),
                telemetry_event(
                    "network-warm-2",
                    1_800_003_001,
                    TelemetryPayload::NetworkConnect(NetworkConnectEvent {
                        process_name: "svchost.exe".to_string(),
                        destination_ip: "10.0.0.5".to_string(),
                        destination_port: 443,
                        protocol: "tcp".to_string(),
                    }),
                ),
                telemetry_event(
                    "network-novel",
                    1_800_003_002,
                    TelemetryPayload::NetworkConnect(NetworkConnectEvent {
                        process_name: "svchost.exe".to_string(),
                        destination_ip: "198.51.100.25".to_string(),
                        destination_port: 8443,
                        protocol: "tcp".to_string(),
                    }),
                ),
            ),
            (
                "dns_query",
                ThreatClass::DataExfiltration,
                telemetry_event(
                    "dns-warm-1",
                    1_800_003_010,
                    TelemetryPayload::DnsQuery(DnsQueryEvent {
                        query_name: "updates.example.com".to_string(),
                        query_type: "A".to_string(),
                        source_ip: Some("10.0.0.10".to_string()),
                        process_name: Some("chrome.exe".to_string()),
                        response_code: Some("NOERROR".to_string()),
                    }),
                ),
                telemetry_event(
                    "dns-warm-2",
                    1_800_003_011,
                    TelemetryPayload::DnsQuery(DnsQueryEvent {
                        query_name: "updates.example.com".to_string(),
                        query_type: "A".to_string(),
                        source_ip: Some("10.0.0.10".to_string()),
                        process_name: Some("chrome.exe".to_string()),
                        response_code: Some("NOERROR".to_string()),
                    }),
                ),
                telemetry_event(
                    "dns-novel",
                    1_800_003_012,
                    TelemetryPayload::DnsQuery(DnsQueryEvent {
                        query_name: "exfiltration.bad.example".to_string(),
                        query_type: "TXT".to_string(),
                        source_ip: Some("10.0.0.10".to_string()),
                        process_name: Some("chrome.exe".to_string()),
                        response_code: Some("NOERROR".to_string()),
                    }),
                ),
            ),
            (
                "authentication_event",
                ThreatClass::LateralMovement,
                telemetry_event(
                    "auth-warm-1",
                    1_800_003_020,
                    TelemetryPayload::AuthenticationEvent(AuthenticationEventData {
                        auth_type: "kerberos".to_string(),
                        source_host: Some("host-a".to_string()),
                        target_host: Some("dc-1".to_string()),
                        target_service: Some("cifs".to_string()),
                        process_name: Some("lsass.exe".to_string()),
                        success: true,
                        user: Some("alice".to_string()),
                    }),
                ),
                telemetry_event(
                    "auth-warm-2",
                    1_800_003_021,
                    TelemetryPayload::AuthenticationEvent(AuthenticationEventData {
                        auth_type: "kerberos".to_string(),
                        source_host: Some("host-a".to_string()),
                        target_host: Some("dc-1".to_string()),
                        target_service: Some("cifs".to_string()),
                        process_name: Some("lsass.exe".to_string()),
                        success: true,
                        user: Some("alice".to_string()),
                    }),
                ),
                telemetry_event(
                    "auth-novel",
                    1_800_003_022,
                    TelemetryPayload::AuthenticationEvent(AuthenticationEventData {
                        auth_type: "kerberos".to_string(),
                        source_host: Some("host-b".to_string()),
                        target_host: Some("admin-share".to_string()),
                        target_service: Some("winrm".to_string()),
                        process_name: Some("powershell.exe".to_string()),
                        success: true,
                        user: Some("alice".to_string()),
                    }),
                ),
            ),
            (
                "registry_access",
                ThreatClass::CredentialAccess,
                telemetry_event(
                    "reg-access-warm-1",
                    1_800_003_030,
                    TelemetryPayload::RegistryAccess(RegistryAccessEvent {
                        process_name: "reg.exe".to_string(),
                        registry_path: "HKLM\\SAM\\Domains\\Account".to_string(),
                        access_type: "query".to_string(),
                        target_process: Some("lsass.exe".to_string()),
                    }),
                ),
                telemetry_event(
                    "reg-access-warm-2",
                    1_800_003_031,
                    TelemetryPayload::RegistryAccess(RegistryAccessEvent {
                        process_name: "reg.exe".to_string(),
                        registry_path: "HKLM\\SAM\\Domains\\Account".to_string(),
                        access_type: "query".to_string(),
                        target_process: Some("lsass.exe".to_string()),
                    }),
                ),
                telemetry_event(
                    "reg-access-novel",
                    1_800_003_032,
                    TelemetryPayload::RegistryAccess(RegistryAccessEvent {
                        process_name: "reg.exe".to_string(),
                        registry_path: "HKLM\\SECURITY\\Policy\\Secrets".to_string(),
                        access_type: "query".to_string(),
                        target_process: Some("winlogon.exe".to_string()),
                    }),
                ),
            ),
            (
                "registry_persistence",
                ThreatClass::Persistence,
                telemetry_event(
                    "reg-persist-warm-1",
                    1_800_003_040,
                    TelemetryPayload::RegistryPersistence(RegistryPersistenceEvent {
                        process_name: "reg.exe".to_string(),
                        registry_path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                        value_name: Some("OneDrive".to_string()),
                        value_data: None,
                        access_type: "set_value".to_string(),
                    }),
                ),
                telemetry_event(
                    "reg-persist-warm-2",
                    1_800_003_041,
                    TelemetryPayload::RegistryPersistence(RegistryPersistenceEvent {
                        process_name: "reg.exe".to_string(),
                        registry_path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                        value_name: Some("OneDrive".to_string()),
                        value_data: None,
                        access_type: "set_value".to_string(),
                    }),
                ),
                telemetry_event(
                    "reg-persist-novel",
                    1_800_003_042,
                    TelemetryPayload::RegistryPersistence(RegistryPersistenceEvent {
                        process_name: "reg.exe".to_string(),
                        registry_path: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                        value_name: Some("Updater".to_string()),
                        value_data: None,
                        access_type: "set_value".to_string(),
                    }),
                ),
            ),
            (
                "file_persistence",
                ThreatClass::Persistence,
                telemetry_event(
                    "file-warm-1",
                    1_800_003_050,
                    TelemetryPayload::FilePersistence(FilePersistenceEvent {
                        file_path: "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\onedrive.lnk".to_string(),
                        operation: "create".to_string(),
                        process_name: "explorer.exe".to_string(),
                        content_preview: None,
                    }),
                ),
                telemetry_event(
                    "file-warm-2",
                    1_800_003_051,
                    TelemetryPayload::FilePersistence(FilePersistenceEvent {
                        file_path: "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\onedrive.lnk".to_string(),
                        operation: "create".to_string(),
                        process_name: "explorer.exe".to_string(),
                        content_preview: None,
                    }),
                ),
                telemetry_event(
                    "file-novel",
                    1_800_003_052,
                    TelemetryPayload::FilePersistence(FilePersistenceEvent {
                        file_path: "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.lnk".to_string(),
                        operation: "create".to_string(),
                        process_name: "explorer.exe".to_string(),
                        content_preview: None,
                    }),
                ),
            ),
            (
                "process_memory_access",
                ThreatClass::DefenseEvasion,
                telemetry_event(
                    "memory-warm-1",
                    1_800_003_060,
                    TelemetryPayload::ProcessMemoryAccess(ProcessMemoryAccessEvent {
                        source_process: "winword.exe".to_string(),
                        target_process: "teams.exe".to_string(),
                        allocation_type: "virtual_alloc_ex".to_string(),
                        protection_flags: vec!["readwrite".to_string()],
                        region_size: 4096,
                        call_stack_hint: None,
                    }),
                ),
                telemetry_event(
                    "memory-warm-2",
                    1_800_003_061,
                    TelemetryPayload::ProcessMemoryAccess(ProcessMemoryAccessEvent {
                        source_process: "winword.exe".to_string(),
                        target_process: "teams.exe".to_string(),
                        allocation_type: "virtual_alloc_ex".to_string(),
                        protection_flags: vec!["readwrite".to_string()],
                        region_size: 4096,
                        call_stack_hint: None,
                    }),
                ),
                telemetry_event(
                    "memory-novel",
                    1_800_003_062,
                    TelemetryPayload::ProcessMemoryAccess(ProcessMemoryAccessEvent {
                        source_process: "winword.exe".to_string(),
                        target_process: "lsass.exe".to_string(),
                        allocation_type: "virtual_alloc_ex".to_string(),
                        protection_flags: vec!["execute_readwrite".to_string()],
                        region_size: 8192,
                        call_stack_hint: Some("ntdll!NtWriteVirtualMemory".to_string()),
                    }),
                ),
            ),
        ];

        for (family, threat_class, warm_1, warm_2, novel) in cases {
            assert!(detector.evaluate(&warm_1).is_empty());
            assert!(detector.evaluate(&warm_2).is_empty());
            let findings = detector.evaluate(&novel);
            assert_eq!(findings.len(), 1, "family {family}");
            assert_eq!(findings[0].threat_class, threat_class, "family {family}");
            assert_eq!(
                findings[0].evidence["telemetry_family"],
                serde_json::json!(family),
                "family {family}"
            );
            assert!(
                findings[0].evidence["deviation_scoring"]["aggregate_deviation_score"]
                    .as_f64()
                    .unwrap()
                    > 0.0,
                "family {family}"
            );
        }
    }
}
