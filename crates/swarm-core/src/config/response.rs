use super::*;

/// Configuration for the HTTP EDR response adapter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpEdrConfig {
    /// Endpoint receiving block/isolate requests.
    pub endpoint: String,
    /// Bearer token used for outbound authentication.
    pub auth_token: SecretString,
    /// Request timeout in milliseconds.
    #[serde(default = "default_response_adapter_timeout_ms")]
    pub timeout_ms: u64,
    /// Retry policy for transient outbound failures.
    #[serde(default)]
    pub retry: RetryConfig,
    /// Circuit breaker policy for repeated failures.
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    /// JSONL file capturing final failed actions for later inspection.
    #[serde(default = "default_dead_letter_path")]
    pub dead_letter_path: String,
}

/// Configuration for the generic webhook response adapter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    /// Webhook URL receiving escalation payloads.
    pub url: String,
    /// Request timeout in milliseconds.
    #[serde(default = "default_response_adapter_timeout_ms")]
    pub timeout_ms: u64,
    /// Optional channel hint for Slack-compatible receivers.
    #[serde(default)]
    pub channel: Option<String>,
    /// Optional bearer token used for outbound authentication.
    #[serde(default)]
    pub auth_token: Option<SecretString>,
    /// Retry policy for transient outbound failures.
    #[serde(default)]
    pub retry: RetryConfig,
    /// Circuit breaker policy for repeated failures.
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    /// JSONL file capturing final failed actions for later inspection.
    #[serde(default = "default_dead_letter_path")]
    pub dead_letter_path: String,
}

/// Configuration for the CrowdStrike RTR response adapter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdStrikeRtrConfig {
    /// Base API URL used for OAuth2 and RTR operations.
    pub base_url: String,
    /// OAuth2 client identifier used for service-to-service auth.
    pub client_id: SecretString,
    /// OAuth2 client secret used for service-to-service auth.
    pub client_secret: SecretString,
    /// Request timeout in milliseconds.
    #[serde(default = "default_response_adapter_timeout_ms")]
    pub timeout_ms: u64,
    /// Retry policy for transient outbound failures.
    #[serde(default)]
    pub retry: RetryConfig,
    /// Circuit breaker policy for repeated failures.
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    /// JSONL file capturing final failed actions for later inspection.
    #[serde(default = "default_dead_letter_path")]
    pub dead_letter_path: String,
}

/// Retry policy for resilient response adapters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryConfig {
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: u64,
    #[serde(default = "default_backoff_multiplier")]
    pub backoff_multiplier: f64,
}

/// Circuit-breaker policy for resilient response adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_circuit_breaker_threshold")]
    pub threshold: u32,
    #[serde(default = "default_circuit_breaker_cooldown_ms")]
    pub cooldown_ms: u64,
}

/// Configured response adapter selection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResponseAdapterConfig {
    #[default]
    Sandbox,
    HttpEdr {
        #[serde(flatten)]
        config: HttpEdrConfig,
    },
    CrowdStrikeRtr {
        #[serde(flatten)]
        config: CrowdStrikeRtrConfig,
    },
    Webhook {
        #[serde(flatten)]
        config: WebhookConfig,
    },
}

/// Optional SIEM finding forwarder selection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SiemForwardConfig {
    SplunkHec {
        endpoint: String,
        auth_token: SecretString,
        #[serde(default = "default_response_adapter_timeout_ms")]
        timeout_ms: u64,
        #[serde(default = "default_splunk_batch_max_events")]
        batch_max_events: usize,
        #[serde(default = "default_splunk_batch_max_bytes")]
        batch_max_bytes: usize,
        #[serde(default)]
        retry: RetryConfig,
        #[serde(default)]
        circuit_breaker: CircuitBreakerConfig,
        #[serde(default = "default_siem_dead_letter_path")]
        dead_letter_path: String,
    },
    ElkBulk {
        endpoint: String,
        #[serde(default)]
        auth_token: Option<SecretString>,
        #[serde(default = "default_elk_index")]
        index: String,
        #[serde(default = "default_response_adapter_timeout_ms")]
        timeout_ms: u64,
        #[serde(default)]
        retry: RetryConfig,
        #[serde(default)]
        circuit_breaker: CircuitBreakerConfig,
        #[serde(default = "default_siem_dead_letter_path")]
        dead_letter_path: String,
    },
    Chronicle {
        endpoint: String,
        auth_token: SecretString,
        #[serde(default)]
        customer_id: Option<String>,
        #[serde(default = "default_response_adapter_timeout_ms")]
        timeout_ms: u64,
        #[serde(default)]
        retry: RetryConfig,
        #[serde(default)]
        circuit_breaker: CircuitBreakerConfig,
        #[serde(default = "default_siem_dead_letter_path")]
        dead_letter_path: String,
    },
}

/// One named outbound notification target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationChannelConfig {
    pub target_url: String,
    #[serde(default)]
    pub auth_token: Option<SecretString>,
    #[serde(default)]
    pub request_signature: Option<RequestSignatureConfig>,
    #[serde(default = "default_response_adapter_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub rate_limit: NotificationRateLimitConfig,
    #[serde(default)]
    pub quiet_hours: Option<QuietHoursConfig>,
    #[serde(default = "default_notification_dead_letter_path")]
    pub dead_letter_path: String,
}

/// Optional HMAC request signing for outbound notification channels.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestSignatureConfig {
    /// HTTP header receiving the detached signature value.
    #[serde(default = "default_request_signature_header")]
    pub header: String,
    /// Shared secret used to compute an HMAC-SHA256 over the canonical JSON body.
    pub secret: SecretString,
}

/// In-memory rate limiting for one notification channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationRateLimitConfig {
    #[serde(default = "default_notification_rate_limit_max_notifications")]
    pub max_notifications: usize,
    #[serde(default = "default_notification_rate_limit_window_ms")]
    pub window_ms: u64,
}

/// Optional UTC quiet-hours window for one notification channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuietHoursConfig {
    pub start_hour_utc: u8,
    pub end_hour_utc: u8,
}

/// Repo-owned routing DSL for finding-based notification delivery.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationRoutingConfig {
    #[serde(default = "default_notification_dedup_window_ms")]
    pub dedup_window_ms: u64,
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
}

/// One rule matching findings onto named notification channels.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingRule {
    #[serde(default)]
    pub min_severity: Option<Severity>,
    #[serde(default)]
    pub threat_class: Option<crate::pheromone::ThreatClass>,
    #[serde(default)]
    pub utc_start_hour: Option<u8>,
    #[serde(default)]
    pub utc_end_hour: Option<u8>,
    pub channels: Vec<String>,
}

impl ResponseAdapterConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        match self {
            Self::Sandbox => Ok(()),
            Self::HttpEdr { config } => {
                if config.endpoint.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "response_adapter.endpoint",
                        reason: "must not be empty".to_string(),
                    });
                }
                if config.auth_token.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "response_adapter.auth_token",
                        reason: "must not be empty".to_string(),
                    });
                }
                if config.timeout_ms == 0 {
                    return Err(ConfigValidationError::InvalidField {
                        field: "response_adapter.timeout_ms",
                        reason: "must be greater than zero".to_string(),
                    });
                }
                validate_retry_config("response_adapter.retry", &config.retry)?;
                validate_circuit_breaker_config(
                    "response_adapter.circuit_breaker",
                    &config.circuit_breaker,
                )?;
                if config.dead_letter_path.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "response_adapter.dead_letter_path",
                        reason: "must not be empty".to_string(),
                    });
                }
                Ok(())
            }
            Self::CrowdStrikeRtr { config } => {
                validate_non_empty("response_adapter.base_url", &config.base_url)?;
                validate_non_empty("response_adapter.client_id", &config.client_id)?;
                validate_non_empty("response_adapter.client_secret", &config.client_secret)?;
                if config.timeout_ms == 0 {
                    return Err(ConfigValidationError::InvalidField {
                        field: "response_adapter.timeout_ms",
                        reason: "must be greater than zero".to_string(),
                    });
                }
                validate_retry_config("response_adapter.retry", &config.retry)?;
                validate_circuit_breaker_config(
                    "response_adapter.circuit_breaker",
                    &config.circuit_breaker,
                )?;
                validate_non_empty(
                    "response_adapter.dead_letter_path",
                    &config.dead_letter_path,
                )
            }
            Self::Webhook { config } => {
                if config.url.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "response_adapter.url",
                        reason: "must not be empty".to_string(),
                    });
                }
                if let Some(auth_token) = &config.auth_token
                    && auth_token.trim().is_empty()
                {
                    return Err(ConfigValidationError::InvalidField {
                        field: "response_adapter.auth_token",
                        reason: "must not be empty when provided".to_string(),
                    });
                }
                if config.timeout_ms == 0 {
                    return Err(ConfigValidationError::InvalidField {
                        field: "response_adapter.timeout_ms",
                        reason: "must be greater than zero".to_string(),
                    });
                }
                validate_retry_config("response_adapter.retry", &config.retry)?;
                validate_circuit_breaker_config(
                    "response_adapter.circuit_breaker",
                    &config.circuit_breaker,
                )?;
                if config.dead_letter_path.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "response_adapter.dead_letter_path",
                        reason: "must not be empty".to_string(),
                    });
                }
                Ok(())
            }
        }
    }
}

impl SiemForwardConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        match self {
            Self::SplunkHec {
                endpoint,
                auth_token,
                timeout_ms,
                batch_max_events,
                batch_max_bytes,
                retry,
                circuit_breaker,
                dead_letter_path,
            } => {
                validate_non_empty("siem_forward.endpoint", endpoint)?;
                validate_non_empty("siem_forward.auth_token", auth_token)?;
                if *timeout_ms == 0 {
                    return Err(ConfigValidationError::InvalidField {
                        field: "siem_forward.timeout_ms",
                        reason: "must be greater than zero".to_string(),
                    });
                }
                if *batch_max_events == 0 {
                    return Err(ConfigValidationError::InvalidField {
                        field: "siem_forward.batch_max_events",
                        reason: "must be greater than zero".to_string(),
                    });
                }
                if *batch_max_bytes == 0 {
                    return Err(ConfigValidationError::InvalidField {
                        field: "siem_forward.batch_max_bytes",
                        reason: "must be greater than zero".to_string(),
                    });
                }
                validate_retry_config("siem_forward.retry", retry)?;
                validate_circuit_breaker_config("siem_forward.circuit_breaker", circuit_breaker)?;
                validate_non_empty("siem_forward.dead_letter_path", dead_letter_path)
            }
            Self::ElkBulk {
                endpoint,
                auth_token,
                index,
                timeout_ms,
                retry,
                circuit_breaker,
                dead_letter_path,
            } => {
                validate_non_empty("siem_forward.endpoint", endpoint)?;
                if let Some(auth_token) = auth_token {
                    validate_non_empty("siem_forward.auth_token", auth_token)?;
                }
                validate_non_empty("siem_forward.index", index)?;
                validate_timeout("siem_forward.timeout_ms", *timeout_ms)?;
                validate_retry_config("siem_forward.retry", retry)?;
                validate_circuit_breaker_config("siem_forward.circuit_breaker", circuit_breaker)?;
                validate_non_empty("siem_forward.dead_letter_path", dead_letter_path)
            }
            Self::Chronicle {
                endpoint,
                auth_token,
                customer_id,
                timeout_ms,
                retry,
                circuit_breaker,
                dead_letter_path,
            } => {
                validate_non_empty("siem_forward.endpoint", endpoint)?;
                validate_non_empty("siem_forward.auth_token", auth_token)?;
                if let Some(customer_id) = customer_id {
                    validate_non_empty("siem_forward.customer_id", customer_id)?;
                }
                validate_timeout("siem_forward.timeout_ms", *timeout_ms)?;
                validate_retry_config("siem_forward.retry", retry)?;
                validate_circuit_breaker_config("siem_forward.circuit_breaker", circuit_breaker)?;
                validate_non_empty("siem_forward.dead_letter_path", dead_letter_path)
            }
        }
    }
}

impl NotificationChannelConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        validate_non_empty("notification_channels.target_url", &self.target_url)?;
        if let Some(auth_token) = &self.auth_token {
            validate_non_empty("notification_channels.auth_token", auth_token)?;
        }
        if let Some(signature) = &self.request_signature {
            signature.validate()?;
        }
        validate_timeout("notification_channels.timeout_ms", self.timeout_ms)?;
        self.rate_limit.validate()?;
        if let Some(quiet_hours) = &self.quiet_hours {
            quiet_hours.validate()?;
        }
        validate_non_empty(
            "notification_channels.dead_letter_path",
            &self.dead_letter_path,
        )
    }
}

impl RequestSignatureConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        validate_non_empty(
            "notification_channels.request_signature.header",
            &self.header,
        )?;
        validate_non_empty(
            "notification_channels.request_signature.secret",
            &self.secret,
        )
    }
}

impl NotificationRateLimitConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.max_notifications == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_channels.rate_limit.max_notifications",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.window_ms == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_channels.rate_limit.window_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        Ok(())
    }
}

impl QuietHoursConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.start_hour_utc > 23 {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_channels.quiet_hours.start_hour_utc",
                reason: "must be between 0 and 23".to_string(),
            });
        }
        if self.end_hour_utc > 23 {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_channels.quiet_hours.end_hour_utc",
                reason: "must be between 0 and 23".to_string(),
            });
        }
        if self.start_hour_utc == self.end_hour_utc {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_channels.quiet_hours",
                reason: "start and end hour must differ".to_string(),
            });
        }
        Ok(())
    }
}

impl NotificationRoutingConfig {
    pub(super) fn validate(
        &self,
        channels: &BTreeMap<String, NotificationChannelConfig>,
    ) -> Result<(), ConfigValidationError> {
        if self.dedup_window_ms == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_routing.dedup_window_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        for rule in &self.rules {
            rule.validate(channels)?;
        }
        Ok(())
    }
}

impl RoutingRule {
    pub(super) fn validate(
        &self,
        channels: &BTreeMap<String, NotificationChannelConfig>,
    ) -> Result<(), ConfigValidationError> {
        if self.channels.is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_routing.rules.channels",
                reason: "must contain at least one channel".to_string(),
            });
        }
        for channel in &self.channels {
            if channel.trim().is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "notification_routing.rules.channels",
                    reason: "channel names must not be empty".to_string(),
                });
            }
            if !channels.contains_key(channel) {
                return Err(ConfigValidationError::InvalidField {
                    field: "notification_routing.rules.channels",
                    reason: format!("references unknown channel `{channel}`"),
                });
            }
        }
        if let Some(start) = self.utc_start_hour
            && start > 23
        {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_routing.rules.utc_start_hour",
                reason: "must be between 0 and 23".to_string(),
            });
        }
        if let Some(end) = self.utc_end_hour
            && end > 23
        {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_routing.rules.utc_end_hour",
                reason: "must be between 0 and 23".to_string(),
            });
        }
        if self.utc_start_hour.is_some() != self.utc_end_hour.is_some() {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_routing.rules",
                reason: "utc_start_hour and utc_end_hour must be provided together".to_string(),
            });
        }
        if self.utc_start_hour == self.utc_end_hour && self.utc_start_hour.is_some() {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_routing.rules",
                reason: "utc_start_hour and utc_end_hour must differ".to_string(),
            });
        }
        Ok(())
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            initial_backoff_ms: default_initial_backoff_ms(),
            backoff_multiplier: default_backoff_multiplier(),
        }
    }
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            threshold: default_circuit_breaker_threshold(),
            cooldown_ms: default_circuit_breaker_cooldown_ms(),
        }
    }
}

impl Default for NotificationRateLimitConfig {
    fn default() -> Self {
        Self {
            max_notifications: default_notification_rate_limit_max_notifications(),
            window_ms: default_notification_rate_limit_window_ms(),
        }
    }
}

impl Default for NotificationRoutingConfig {
    fn default() -> Self {
        Self {
            dedup_window_ms: default_notification_dedup_window_ms(),
            rules: Vec::new(),
        }
    }
}
