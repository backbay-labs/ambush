use super::*;

/// Bridge-backed telemetry source configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TelemetryBridgeConfig {
    Tetragon {
        #[serde(flatten)]
        config: Box<TetragonBridgeConfig>,
    },
    WindowsEventLog {
        #[serde(flatten)]
        config: Box<WindowsEventLogBridgeConfig>,
    },
    CloudTrail {
        #[serde(flatten)]
        config: Box<CloudTrailBridgeConfig>,
    },
    KubernetesAudit {
        #[serde(flatten)]
        config: Box<KubernetesAuditBridgeConfig>,
    },
    Sysmon {
        #[serde(flatten)]
        config: Box<SysmonBridgeConfig>,
    },
    Auditd {
        #[serde(flatten)]
        config: Box<AuditdBridgeConfig>,
    },
    GenericJson {
        #[serde(flatten)]
        config: Box<GenericJsonBridgeConfig>,
    },
    Sentinel {
        #[serde(flatten)]
        config: Box<SentinelBridgeConfig>,
    },
}

/// File-backed JSON record source used by JSON-oriented bridges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonFileSourceConfig {
    pub path: String,
}

/// Tetragon gRPC bridge configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TetragonBridgeConfig {
    pub endpoint: String,
    #[serde(default = "default_tetragon_reconnect_backoff_ms")]
    pub reconnect_backoff_ms: u64,
    #[serde(default = "default_tetragon_max_reconnect_backoff_ms")]
    pub max_reconnect_backoff_ms: u64,
    #[serde(default = "default_tetragon_event_timeout_secs")]
    pub event_timeout_secs: u64,
}

/// CloudTrail bridge configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudTrailBridgeConfig {
    #[serde(flatten)]
    pub source: JsonFileSourceConfig,
}

/// Kubernetes audit webhook bridge configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesAuditBridgeConfig {
    #[serde(flatten)]
    pub source: JsonFileSourceConfig,
}

/// Windows Event Log bridge configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsEventLogBridgeConfig {
    #[serde(flatten)]
    pub source: JsonFileSourceConfig,
}

/// Sysmon bridge configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SysmonBridgeConfig {
    #[serde(flatten)]
    pub source: JsonFileSourceConfig,
}

/// Linux auditd bridge configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditdBridgeConfig {
    #[serde(flatten)]
    pub source: JsonFileSourceConfig,
}

/// Generic JSON bridge configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenericJsonBridgeConfig {
    #[serde(flatten)]
    pub source: JsonFileSourceConfig,
    pub mapping: FieldMappingConfig,
}

/// Sentinel Prometheus scrape bridge configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SentinelBridgeConfig {
    pub endpoint: String,
    #[serde(default = "default_sentinel_scrape_interval_ms")]
    pub scrape_interval_ms: u64,
    #[serde(default = "default_sentinel_scrape_timeout_ms")]
    pub scrape_timeout_ms: u64,
    #[serde(default = "default_thermal_anomaly_threshold_celsius")]
    pub thermal_anomaly_threshold_celsius: f64,
    #[serde(default = "default_memory_exhaustion_threshold_percent")]
    pub memory_exhaustion_threshold_percent: f64,
    #[serde(default = "default_disk_exhaustion_threshold_percent")]
    pub disk_exhaustion_threshold_percent: f64,
    #[serde(default = "default_max_consecutive_sentinel_failures")]
    pub max_consecutive_failures: u32,
}

/// Config-driven field mapping for generic JSON bridge normalization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldMappingConfig {
    pub event_id_path: String,
    pub timestamp_path: String,
    #[serde(default)]
    pub host_id_path: Option<String>,
    pub payload: GenericJsonPayloadMappingConfig,
}

/// Configurable payload mappings supported by the generic JSON bridge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GenericJsonPayloadMappingConfig {
    ProcessStart {
        parent_process_path: String,
        process_name_path: String,
        command_line_path: String,
        #[serde(default)]
        user_path: Option<String>,
        #[serde(default)]
        executable_path_path: Option<String>,
        #[serde(default)]
        signer_path: Option<String>,
        #[serde(default)]
        signature_valid_path: Option<String>,
    },
    NetworkConnect {
        process_name_path: String,
        destination_ip_path: String,
        destination_port_path: String,
        protocol_path: String,
    },
    DnsQuery {
        query_name_path: String,
        query_type_path: String,
        #[serde(default)]
        source_ip_path: Option<String>,
        #[serde(default)]
        process_name_path: Option<String>,
        #[serde(default)]
        response_code_path: Option<String>,
    },
    RegistryAccess {
        process_name_path: String,
        registry_path_path: String,
        access_type_path: String,
        #[serde(default)]
        target_process_path: Option<String>,
    },
    RegistryPersistence {
        process_name_path: String,
        registry_path_path: String,
        access_type_path: String,
        #[serde(default)]
        value_name_path: Option<String>,
        #[serde(default)]
        value_data_path: Option<String>,
    },
    FilePersistence {
        file_path_path: String,
        operation_path: String,
        process_name_path: String,
        #[serde(default)]
        content_preview_path: Option<String>,
    },
    AuthenticationEvent {
        auth_type_path: String,
        #[serde(default)]
        source_host_path: Option<String>,
        #[serde(default)]
        target_host_path: Option<String>,
        #[serde(default)]
        target_service_path: Option<String>,
        #[serde(default)]
        process_name_path: Option<String>,
        success_path: String,
        #[serde(default)]
        user_path: Option<String>,
    },
}

impl TelemetryBridgeConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        match self {
            Self::Tetragon { config } => config.validate(),
            Self::WindowsEventLog { config } => config.validate(),
            Self::CloudTrail { config } => config.validate(),
            Self::KubernetesAudit { config } => config.validate(),
            Self::Sysmon { config } => config.validate(),
            Self::Auditd { config } => config.validate(),
            Self::GenericJson { config } => config.validate(),
            Self::Sentinel { config } => config.validate(),
        }
    }
}

impl JsonFileSourceConfig {
    pub(super) fn validate(&self, field: &'static str) -> Result<(), ConfigValidationError> {
        if self.path.trim().is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field,
                reason: "must not be empty".to_string(),
            });
        }
        Ok(())
    }
}

impl TetragonBridgeConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.endpoint.trim().is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.telemetry_sources.bridge.endpoint",
                reason: "must not be empty".to_string(),
            });
        }
        if self.reconnect_backoff_ms == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.telemetry_sources.bridge.reconnect_backoff_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.max_reconnect_backoff_ms < self.reconnect_backoff_ms {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.telemetry_sources.bridge.max_reconnect_backoff_ms",
                reason: "must be greater than or equal to reconnect_backoff_ms".to_string(),
            });
        }
        if self.event_timeout_secs == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "tetragon.event_timeout_secs",
                reason: "must be greater than zero".to_string(),
            });
        }
        Ok(())
    }
}

impl CloudTrailBridgeConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        self.source
            .validate("runtime.telemetry_sources.bridge.path")
    }
}

impl KubernetesAuditBridgeConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        self.source
            .validate("runtime.telemetry_sources.bridge.path")
    }
}

impl WindowsEventLogBridgeConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        self.source
            .validate("runtime.telemetry_sources.bridge.path")
    }
}

impl SysmonBridgeConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        self.source
            .validate("runtime.telemetry_sources.bridge.path")
    }
}

impl AuditdBridgeConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        self.source
            .validate("runtime.telemetry_sources.bridge.path")
    }
}

impl GenericJsonBridgeConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        self.source
            .validate("runtime.telemetry_sources.bridge.path")?;
        self.mapping.validate()
    }
}

impl SentinelBridgeConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.endpoint.trim().is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.telemetry_sources.bridge.endpoint",
                reason: "must not be empty".to_string(),
            });
        }
        if !self.endpoint.starts_with("http://") && !self.endpoint.starts_with("https://") {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.telemetry_sources.bridge.endpoint",
                reason: "must start with http:// or https://".to_string(),
            });
        }
        if self.scrape_interval_ms == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.telemetry_sources.bridge.scrape_interval_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.scrape_timeout_ms == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.telemetry_sources.bridge.scrape_timeout_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        validate_percentage_threshold(
            "runtime.telemetry_sources.bridge.memory_exhaustion_threshold_percent",
            self.memory_exhaustion_threshold_percent,
        )?;
        validate_percentage_threshold(
            "runtime.telemetry_sources.bridge.disk_exhaustion_threshold_percent",
            self.disk_exhaustion_threshold_percent,
        )?;
        if self.thermal_anomaly_threshold_celsius <= 0.0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.telemetry_sources.bridge.thermal_anomaly_threshold_celsius",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.max_consecutive_failures == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.telemetry_sources.bridge.max_consecutive_failures",
                reason: "must be greater than zero".to_string(),
            });
        }
        Ok(())
    }
}

impl FieldMappingConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        validate_json_pointer(
            "runtime.telemetry_sources.bridge.mapping.event_id_path",
            &self.event_id_path,
        )?;
        validate_json_pointer(
            "runtime.telemetry_sources.bridge.mapping.timestamp_path",
            &self.timestamp_path,
        )?;
        if let Some(path) = &self.host_id_path {
            validate_json_pointer(
                "runtime.telemetry_sources.bridge.mapping.host_id_path",
                path,
            )?;
        }
        self.payload.validate()
    }
}

impl GenericJsonPayloadMappingConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        match self {
            Self::ProcessStart {
                parent_process_path,
                process_name_path,
                command_line_path,
                user_path,
                executable_path_path,
                signer_path,
                signature_valid_path,
            } => {
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.parent_process_path",
                    parent_process_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.process_name_path",
                    process_name_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.command_line_path",
                    command_line_path,
                )?;
                if let Some(path) = user_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.user_path",
                        path,
                    )?;
                }
                if let Some(path) = executable_path_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.executable_path_path",
                        path,
                    )?;
                }
                if let Some(path) = signer_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.signer_path",
                        path,
                    )?;
                }
                if let Some(path) = signature_valid_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.signature_valid_path",
                        path,
                    )?;
                }
            }
            Self::NetworkConnect {
                process_name_path,
                destination_ip_path,
                destination_port_path,
                protocol_path,
            } => {
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.process_name_path",
                    process_name_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.destination_ip_path",
                    destination_ip_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.destination_port_path",
                    destination_port_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.protocol_path",
                    protocol_path,
                )?;
            }
            Self::DnsQuery {
                query_name_path,
                query_type_path,
                source_ip_path,
                process_name_path,
                response_code_path,
            } => {
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.query_name_path",
                    query_name_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.query_type_path",
                    query_type_path,
                )?;
                if let Some(path) = source_ip_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.source_ip_path",
                        path,
                    )?;
                }
                if let Some(path) = process_name_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.process_name_path",
                        path,
                    )?;
                }
                if let Some(path) = response_code_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.response_code_path",
                        path,
                    )?;
                }
            }
            Self::RegistryAccess {
                process_name_path,
                registry_path_path,
                access_type_path,
                target_process_path,
            } => {
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.process_name_path",
                    process_name_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.registry_path_path",
                    registry_path_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.access_type_path",
                    access_type_path,
                )?;
                if let Some(path) = target_process_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.target_process_path",
                        path,
                    )?;
                }
            }
            Self::RegistryPersistence {
                process_name_path,
                registry_path_path,
                access_type_path,
                value_name_path,
                value_data_path,
            } => {
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.process_name_path",
                    process_name_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.registry_path_path",
                    registry_path_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.access_type_path",
                    access_type_path,
                )?;
                if let Some(path) = value_name_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.value_name_path",
                        path,
                    )?;
                }
                if let Some(path) = value_data_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.value_data_path",
                        path,
                    )?;
                }
            }
            Self::FilePersistence {
                file_path_path,
                operation_path,
                process_name_path,
                content_preview_path,
            } => {
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.file_path_path",
                    file_path_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.operation_path",
                    operation_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.process_name_path",
                    process_name_path,
                )?;
                if let Some(path) = content_preview_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.content_preview_path",
                        path,
                    )?;
                }
            }
            Self::AuthenticationEvent {
                auth_type_path,
                source_host_path,
                target_host_path,
                target_service_path,
                process_name_path,
                success_path,
                user_path,
            } => {
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.auth_type_path",
                    auth_type_path,
                )?;
                if let Some(path) = source_host_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.source_host_path",
                        path,
                    )?;
                }
                if let Some(path) = target_host_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.target_host_path",
                        path,
                    )?;
                }
                if let Some(path) = target_service_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.target_service_path",
                        path,
                    )?;
                }
                if let Some(path) = process_name_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.process_name_path",
                        path,
                    )?;
                }
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.success_path",
                    success_path,
                )?;
                if let Some(path) = user_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.user_path",
                        path,
                    )?;
                }
            }
        }

        Ok(())
    }
}
