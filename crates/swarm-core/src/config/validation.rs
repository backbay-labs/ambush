use super::*;

/// Semantic validation errors that survive after deserialization.
#[derive(Debug, thiserror::Error)]
pub enum ConfigValidationError {
    #[error("invalid field `{field}`: {reason}")]
    InvalidField { field: &'static str, reason: String },
}

impl SwarmConfig {
    /// Validate cross-field and semantic constraints after deserialization.
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.name.trim().is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "name",
                reason: "must not be empty".to_string(),
            });
        }

        if self.schema_version == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "schema_version",
                reason: "must be greater than zero".to_string(),
            });
        }
        if let Some(tls) = self.tls.as_ref() {
            tls.validate()?;
        }

        if self.runtime.telemetry_sources.is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.telemetry_sources",
                reason: "at least one telemetry source is required".to_string(),
            });
        }

        if self.runtime.max_in_flight_actions == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.max_in_flight_actions",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.runtime.drain_timeout_ms == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.drain_timeout_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        if !(0.0..=1.0).contains(&self.runtime.max_heap_pressure)
            || self.runtime.max_heap_pressure == 0.0
        {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.max_heap_pressure",
                reason: "must be greater than 0.0 and less than or equal to 1.0".to_string(),
            });
        }
        if self.runtime.temporal_event_window.retention_ms <= 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.temporal_event_window.retention_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.runtime.temporal_event_window.max_events == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.temporal_event_window.max_events",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.runtime.temporal_event_window.max_match_span_ms <= 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.temporal_event_window.max_match_span_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.runtime.temporal_event_window.max_match_span_ms
            > self.runtime.temporal_event_window.retention_ms
        {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.temporal_event_window.max_match_span_ms",
                reason: "must be less than or equal to retention_ms".to_string(),
            });
        }
        if self.runtime.temporal_event_window.max_predicates_per_match == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.temporal_event_window.max_predicates_per_match",
                reason: "must be greater than zero".to_string(),
            });
        }
        if let Some(secret_dir) = &self.runtime.secret_dir
            && secret_dir.trim().is_empty()
        {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.secret_dir",
                reason: "must not be empty when provided".to_string(),
            });
        }
        if self.runtime.anti_tamper.enabled && self.runtime.anti_tamper.check_interval_ms == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.anti_tamper.check_interval_ms",
                reason: "must be greater than zero when anti-tamper monitoring is enabled"
                    .to_string(),
            });
        }
        if !self.runtime.anti_tamper.enabled && self.runtime.anti_tamper.fail_closed_live_response {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.anti_tamper.fail_closed_live_response",
                reason: "requires runtime.anti_tamper.enabled".to_string(),
            });
        }
        if self
            .runtime
            .anti_tamper
            .allowed_library_prefixes
            .iter()
            .any(|prefix| prefix.trim().is_empty())
        {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.anti_tamper.allowed_library_prefixes",
                reason: "entries must not be empty".to_string(),
            });
        }

        let mut source_names = BTreeSet::new();
        for source in &self.runtime.telemetry_sources {
            if source.name.trim().is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "runtime.telemetry_sources.name",
                    reason: "must not be empty".to_string(),
                });
            }
            if source.subject.trim().is_empty() && source.bridge.is_none() {
                return Err(ConfigValidationError::InvalidField {
                    field: "runtime.telemetry_sources.subject",
                    reason: "must not be empty when bridge is absent".to_string(),
                });
            }
            if let Some(bridge) = &source.bridge {
                bridge.validate()?;
            }
            if !source_names.insert(source.name.clone()) {
                return Err(ConfigValidationError::InvalidField {
                    field: "runtime.telemetry_sources.name",
                    reason: format!("duplicate telemetry source `{}`", source.name),
                });
            }
        }

        let mut threat_intel_feed_names = BTreeSet::new();
        for feed in &self.runtime.threat_intel_feeds {
            match feed {
                ThreatIntelFeedConfig::Taxii { config } => {
                    if config.name.trim().is_empty() {
                        return Err(ConfigValidationError::InvalidField {
                            field: "runtime.threat_intel_feeds.name",
                            reason: "must not be empty".to_string(),
                        });
                    }
                    if config.collection_url.trim().is_empty() {
                        return Err(ConfigValidationError::InvalidField {
                            field: "runtime.threat_intel_feeds.collection_url",
                            reason: "must not be empty".to_string(),
                        });
                    }
                    if config.poll_interval_ms == 0 {
                        return Err(ConfigValidationError::InvalidField {
                            field: "runtime.threat_intel_feeds.poll_interval_ms",
                            reason: "must be greater than zero".to_string(),
                        });
                    }
                    if config.default_ttl_secs <= 0 {
                        return Err(ConfigValidationError::InvalidField {
                            field: "runtime.threat_intel_feeds.default_ttl_secs",
                            reason: "must be greater than zero".to_string(),
                        });
                    }
                    if !threat_intel_feed_names.insert(config.name.clone()) {
                        return Err(ConfigValidationError::InvalidField {
                            field: "runtime.threat_intel_feeds.name",
                            reason: format!("duplicate threat-intel feed `{}`", config.name),
                        });
                    }
                }
            }
        }

        if self.detection.strategy.trim().is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "detection.strategy",
                reason: "must not be empty".to_string(),
            });
        }
        let mut active_strategy_ids = BTreeSet::new();
        for strategy_id in self.detection.active_strategies() {
            let strategy_id = strategy_id.trim();
            if strategy_id.is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "detection.strategies",
                    reason: "entries must not be empty".to_string(),
                });
            }
            if !active_strategy_ids.insert(strategy_id.to_string()) {
                return Err(ConfigValidationError::InvalidField {
                    field: "detection.strategies",
                    reason: format!("duplicate detector strategy `{strategy_id}`"),
                });
            }
        }
        if !(0.0..=1.0).contains(&self.detection.medium_confidence_threshold) {
            return Err(ConfigValidationError::InvalidField {
                field: "detection.medium_confidence_threshold",
                reason: "must be between 0.0 and 1.0".to_string(),
            });
        }
        if !(0.0..=1.0).contains(&self.detection.high_confidence_threshold) {
            return Err(ConfigValidationError::InvalidField {
                field: "detection.high_confidence_threshold",
                reason: "must be between 0.0 and 1.0".to_string(),
            });
        }
        if self.detection.high_confidence_threshold < self.detection.medium_confidence_threshold {
            return Err(ConfigValidationError::InvalidField {
                field: "detection.high_confidence_threshold",
                reason: "must be greater than or equal to medium_confidence_threshold".to_string(),
            });
        }
        self.detection.validate_rollout_strategy_id(
            "canary.strategy_id",
            self.canary.strategy_id.as_deref(),
        )?;
        self.detection.validate_rollout_strategy_id(
            "promotion.strategy_id",
            self.promotion.strategy_id.as_deref(),
        )?;

        if self.pheromone.default_half_life_secs <= 0.0 {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.default_half_life_secs",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.pheromone.evaporation_threshold <= 0.0 {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.evaporation_threshold",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.pheromone.min_sources_for_escalation == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.min_sources_for_escalation",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.pheromone.alert_threshold <= 0.0 {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.alert_threshold",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.pheromone.incident_threshold < self.pheromone.alert_threshold {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.incident_threshold",
                reason: "must be greater than or equal to alert_threshold".to_string(),
            });
        }
        if self.pheromone.deescalation_cooldown_secs <= 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.deescalation_cooldown_secs",
                reason: "must be greater than zero".to_string(),
            });
        }
        self.pheromone.response_playbook.validate()?;
        match &self.pheromone.backend {
            PheromoneBackendConfig::InMemory => {
                if self.runtime.mode == RuntimeMode::LiveResponse
                    && self.runtime.require_durable_live_response
                {
                    return Err(ConfigValidationError::InvalidField {
                        field: "runtime.require_durable_live_response",
                        reason: "requires a durable pheromone backend in live_response mode"
                            .to_string(),
                    });
                }
            }
            PheromoneBackendConfig::LocalJournal { path } => {
                if path.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "pheromone.backend.path",
                        reason: "must not be empty".to_string(),
                    });
                }
            }
            PheromoneBackendConfig::JetStream {
                url,
                connect_timeout_ms,
                gc_page_size,
            } => {
                if url.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "pheromone.backend.url",
                        reason: "must not be empty".to_string(),
                    });
                }
                if *connect_timeout_ms == 0 {
                    return Err(ConfigValidationError::InvalidField {
                        field: "pheromone.backend.connect_timeout_ms",
                        reason: "must be greater than zero".to_string(),
                    });
                }
                if *gc_page_size == 0 {
                    return Err(ConfigValidationError::InvalidField {
                        field: "pheromone.backend.gc_page_size",
                        reason: "must be greater than zero".to_string(),
                    });
                }
            }
        }

        if self.policy.lease_ttl_ms <= 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "policy.lease_ttl_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.policy.max_actions_per_scope_per_minute == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "policy.max_actions_per_scope_per_minute",
                reason: "must be greater than zero".to_string(),
            });
        }
        for (index, rule) in self.policy.rules.iter().enumerate() {
            rule.validate(index)?;
        }

        if self.runtime.governance_degraded_tick_threshold == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.governance_degraded_tick_threshold",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.runtime.partition_contingency_lease_ttl_ms <= 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.partition_contingency_lease_ttl_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.runtime.partition_contingency_blast_radius_cap == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.partition_contingency_blast_radius_cap",
                reason: "must be greater than zero".to_string(),
            });
        }

        self.response_adapter.validate()?;
        if let Some(config) = &self.siem_forward {
            config.validate()?;
        }
        for (channel_name, channel) in &self.notification_channels {
            if channel_name.trim().is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "notification_channels",
                    reason: "channel names must not be empty".to_string(),
                });
            }
            channel.validate()?;
        }
        self.notification_routing
            .validate(&self.notification_channels)?;

        if self.audit.recent_decisions_limit == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "audit.recent_decisions_limit",
                reason: "must be greater than zero".to_string(),
            });
        }
        match &self.audit.bundle_store {
            BundleStoreConfig::Memory => {}
            BundleStoreConfig::LocalFiles { directory } => {
                if directory.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "audit.bundle_store.directory",
                        reason: "must not be empty".to_string(),
                    });
                }
            }
        }

        if self.investigation.enabled {
            if self.investigation.worker_count == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "investigation.worker_count",
                    reason: "must be greater than zero when investigation is enabled".to_string(),
                });
            }
            if self.investigation.max_pending_jobs == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "investigation.max_pending_jobs",
                    reason: "must be greater than zero when investigation is enabled".to_string(),
                });
            }
            if self.investigation.time_budget_ms == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "investigation.time_budget_ms",
                    reason: "must be greater than zero when investigation is enabled".to_string(),
                });
            }
            if self.investigation.starvation_boost_per_second_basis_points == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "investigation.starvation_boost_per_second_basis_points",
                    reason: "must be greater than zero when investigation is enabled".to_string(),
                });
            }
            if self.investigation.max_starvation_boost_basis_points == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "investigation.max_starvation_boost_basis_points",
                    reason: "must be greater than zero when investigation is enabled".to_string(),
                });
            }
            if self.investigation.ambiguity_margin_basis_points == 0
                || self.investigation.ambiguity_margin_basis_points > 10_000
            {
                return Err(ConfigValidationError::InvalidField {
                    field: "investigation.ambiguity_margin_basis_points",
                    reason: "must be between 1 and 10000 when investigation is enabled".to_string(),
                });
            }
        }
        match &self.investigation.bundle_store {
            BundleStoreConfig::Memory => {}
            BundleStoreConfig::LocalFiles { directory } => {
                if directory.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "investigation.bundle_store.directory",
                        reason: "must not be empty".to_string(),
                    });
                }
            }
        }

        if self.correlation.enabled {
            if self.correlation.time_window_ms <= 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "correlation.time_window_ms",
                    reason: "must be greater than zero when correlation is enabled".to_string(),
                });
            }
            if self.correlation.min_shared_keys == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "correlation.min_shared_keys",
                    reason: "must be greater than zero when correlation is enabled".to_string(),
                });
            }
            if self.correlation.candidate_limit == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "correlation.candidate_limit",
                    reason: "must be greater than zero when correlation is enabled".to_string(),
                });
            }
        }
        match &self.correlation.incident_store {
            BundleStoreConfig::Memory => {}
            BundleStoreConfig::LocalFiles { directory } => {
                if directory.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "correlation.incident_store.directory",
                        reason: "must not be empty".to_string(),
                    });
                }
            }
        }

        if self.canary.enabled {
            if self.canary.slot_id.trim().is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "canary.slot_id",
                    reason: "must not be empty when canary is enabled".to_string(),
                });
            }
            if self.canary.observation_window_events == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "canary.observation_window_events",
                    reason: "must be greater than zero when canary is enabled".to_string(),
                });
            }
            if !(0.0..=1.0).contains(&self.canary.max_candidate_only_rate) {
                return Err(ConfigValidationError::InvalidField {
                    field: "canary.max_candidate_only_rate",
                    reason: "must be between 0.0 and 1.0".to_string(),
                });
            }
            if !(0.0..=1.0).contains(&self.canary.max_baseline_miss_rate) {
                return Err(ConfigValidationError::InvalidField {
                    field: "canary.max_baseline_miss_rate",
                    reason: "must be between 0.0 and 1.0".to_string(),
                });
            }
            // Still validated even though it is advisory: it is the reference
            // point recorded next to the non-gating detect-latency observation,
            // and a zero budget would mark every run as over budget forever.
            if self.canary.max_detect_latency_us == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "canary.max_detect_latency_us",
                    reason: "must be greater than zero when canary is enabled".to_string(),
                });
            }
            if self.canary.max_total_detections == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "canary.max_total_detections",
                    reason: "must be greater than zero when canary is enabled".to_string(),
                });
            }
            if self.detection.active_strategies().len() > 1 && self.canary.strategy_id.is_none() {
                return Err(ConfigValidationError::InvalidField {
                    field: "canary.strategy_id",
                    reason: format!(
                        "is required when multiple detection.strategies are active: {}",
                        self.detection.active_strategies().join(", ")
                    ),
                });
            }
        }

        if self.promotion.enabled {
            if self.promotion.window_id.trim().is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "promotion.window_id",
                    reason: "must not be empty when promotion is enabled".to_string(),
                });
            }
            if self.promotion.observation_window_events == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "promotion.observation_window_events",
                    reason: "must be greater than zero when promotion is enabled".to_string(),
                });
            }
            if !(0.0..=1.0).contains(&self.promotion.max_promoted_only_rate) {
                return Err(ConfigValidationError::InvalidField {
                    field: "promotion.max_promoted_only_rate",
                    reason: "must be between 0.0 and 1.0".to_string(),
                });
            }
            if !(0.0..=1.0).contains(&self.promotion.max_fallback_recovery_rate) {
                return Err(ConfigValidationError::InvalidField {
                    field: "promotion.max_fallback_recovery_rate",
                    reason: "must be between 0.0 and 1.0".to_string(),
                });
            }
            // Advisory, but still validated -- see the canary twin above.
            if self.promotion.max_detect_latency_us == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "promotion.max_detect_latency_us",
                    reason: "must be greater than zero when promotion is enabled".to_string(),
                });
            }
            if self.promotion.max_total_detections == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "promotion.max_total_detections",
                    reason: "must be greater than zero when promotion is enabled".to_string(),
                });
            }
        }

        if self.evolution.enabled {
            self.evolution.validate()?;
        }
        if self.deception.enabled || !self.deception.playbook.entries.is_empty() {
            self.deception.validate()?;
        }
        if self.memory.enabled {
            self.memory.validate()?;
        }
        self.identity.validate()?;

        self.platform_api.validate()?;
        validate_http_rate_limit_config(
            &self.platform_api.rate_limit,
            HttpRateLimitFieldNames {
                burst_max_requests: "platform_api.rate_limit.burst_max_requests",
                burst_window_ms: "platform_api.rate_limit.burst_window_ms",
                sustained_max_requests: "platform_api.rate_limit.sustained_max_requests",
                sustained_window_ms: "platform_api.rate_limit.sustained_window_ms",
            },
        )?;

        let needs_operator_urls = self.operator.enabled
            || self
                .notification_channels
                .contains_key("providence_webhook");
        let needs_operator_auth = self.operator.enabled || !self.platform_api.keys.is_empty();

        if needs_operator_urls {
            let runtime_base_url = self.operator.runtime_base_url.trim();
            if runtime_base_url.is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.runtime_base_url",
                    reason:
                        "must not be empty when operator surface or Providence delivery is enabled"
                            .to_string(),
                });
            }
            if !(runtime_base_url.starts_with("http://")
                || runtime_base_url.starts_with("https://"))
            {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.runtime_base_url",
                    reason: "must start with http:// or https://".to_string(),
                });
            }

            let public_base_url = self.operator.public_base_url.trim();
            if public_base_url.is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.public_base_url",
                    reason:
                        "must not be empty when operator surface or Providence delivery is enabled"
                            .to_string(),
                });
            }
            if !(public_base_url.starts_with("http://") || public_base_url.starts_with("https://"))
            {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.public_base_url",
                    reason: "must start with http:// or https://".to_string(),
                });
            }
        }

        if needs_operator_auth {
            let principals = self.operator.auth.effective_principals();
            if principals.is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.auth.principals",
                    reason: "must contain at least one principal".to_string(),
                });
            }

            let mut seen_operator_ids = BTreeSet::new();
            let mut seen_token_envs = BTreeSet::new();
            for (index, principal) in principals.iter().enumerate() {
                if principal.operator_id.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "operator_surface.auth.principals.operator_id",
                        reason: format!("principal {index} must not have an empty operator_id"),
                    });
                }
                if !seen_operator_ids.insert(principal.operator_id.trim().to_string()) {
                    return Err(ConfigValidationError::InvalidField {
                        field: "operator_surface.auth.principals.operator_id",
                        reason: format!(
                            "principal {index} duplicates operator_id `{}`",
                            principal.operator_id.trim()
                        ),
                    });
                }
                if principal.token_env.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "operator_surface.auth.principals.token_env",
                        reason: format!("principal {index} must not have an empty token_env"),
                    });
                }
                if principal
                    .token_expires_at_ms
                    .is_some_and(|expires_at_ms| expires_at_ms <= 0)
                {
                    return Err(ConfigValidationError::InvalidField {
                        field: "operator_surface.auth.principals.token_expires_at_ms",
                        reason: format!(
                            "principal {index} token_expires_at_ms must be greater than zero when configured"
                        ),
                    });
                }
                if !seen_token_envs.insert(principal.token_env.trim().to_string()) {
                    return Err(ConfigValidationError::InvalidField {
                        field: "operator_surface.auth.principals.token_env",
                        reason: format!(
                            "principal {index} reuses token_env `{}`; bearer secrets must map to one principal",
                            principal.token_env.trim()
                        ),
                    });
                }
                if principal.scopes.is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "operator_surface.auth.principals.scopes",
                        reason: format!("principal {index} must grant at least one scope"),
                    });
                }
            }

            if !principals
                .iter()
                .any(|principal| principal.scopes.contains(&OperatorScope::Read))
            {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.auth.principals.scopes",
                    reason: "at least one principal must grant `read` scope".to_string(),
                });
            }
        }

        if self.operator.enabled {
            validate_http_rate_limit_config(
                &self.operator.rate_limit,
                HttpRateLimitFieldNames {
                    burst_max_requests: "operator_surface.rate_limit.burst_max_requests",
                    burst_window_ms: "operator_surface.rate_limit.burst_window_ms",
                    sustained_max_requests: "operator_surface.rate_limit.sustained_max_requests",
                    sustained_window_ms: "operator_surface.rate_limit.sustained_window_ms",
                },
            )?;
            if self.operator.max_list_results == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.max_list_results",
                    reason: "must be greater than zero when operator surface is enabled"
                        .to_string(),
                });
            }
            if self.operator.widget_token_ttl_secs == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.widget_token_ttl_secs",
                    reason: "must be greater than zero when operator surface is enabled"
                        .to_string(),
                });
            }

            if self.operator.auth.context_token_env().is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.auth.context_token_env",
                    reason: "must not be empty when operator surface is enabled".to_string(),
                });
            }
            if self
                .operator
                .auth
                .token_expires_at_ms
                .is_some_and(|expires_at_ms| expires_at_ms <= 0)
            {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.auth.token_expires_at_ms",
                    reason: "must be greater than zero when configured".to_string(),
                });
            }

            let bind_addr: SocketAddr = self.operator.bind_addr.parse().map_err(|_| {
                ConfigValidationError::InvalidField {
                    field: "operator_surface.bind_addr",
                    reason: "must be a valid socket address".to_string(),
                }
            })?;
            let _ = bind_addr;
        }

        for (index, origin) in self.operator.allowed_embed_origins.iter().enumerate() {
            let trimmed = origin.trim();
            if trimmed.is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.allowed_embed_origins",
                    reason: format!("origin {index} must not be empty"),
                });
            }
            if !(trimmed == "'self'"
                || trimmed.starts_with("http://")
                || trimmed.starts_with("https://"))
            {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.allowed_embed_origins",
                    reason: format!(
                        "origin {index} must be 'self' or start with http:// or https://"
                    ),
                });
            }
        }

        Ok(())
    }
}

struct HttpRateLimitFieldNames {
    burst_max_requests: &'static str,
    burst_window_ms: &'static str,
    sustained_max_requests: &'static str,
    sustained_window_ms: &'static str,
}

fn validate_http_rate_limit_config(
    config: &HttpRateLimitConfig,
    fields: HttpRateLimitFieldNames,
) -> Result<(), ConfigValidationError> {
    if config.burst_max_requests == 0 {
        return Err(ConfigValidationError::InvalidField {
            field: fields.burst_max_requests,
            reason: "must be greater than zero".to_string(),
        });
    }
    if config.burst_window_ms == 0 {
        return Err(ConfigValidationError::InvalidField {
            field: fields.burst_window_ms,
            reason: "must be greater than zero".to_string(),
        });
    }
    if config.sustained_max_requests == 0 {
        return Err(ConfigValidationError::InvalidField {
            field: fields.sustained_max_requests,
            reason: "must be greater than zero".to_string(),
        });
    }
    if config.sustained_window_ms == 0 {
        return Err(ConfigValidationError::InvalidField {
            field: fields.sustained_window_ms,
            reason: "must be greater than zero".to_string(),
        });
    }
    if config.sustained_window_ms < config.burst_window_ms {
        return Err(ConfigValidationError::InvalidField {
            field: fields.sustained_window_ms,
            reason: "must be greater than or equal to burst_window_ms".to_string(),
        });
    }

    Ok(())
}
