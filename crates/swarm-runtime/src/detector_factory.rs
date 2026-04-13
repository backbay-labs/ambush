use crate::config::{
    DetectorProfileError, behavioral_anomaly_profile, credential_access_profile,
    dns_exfiltration_profile, fileless_execution_profile, infrastructure_anomaly_profile,
    lateral_movement_profile, network_connect_profile, persistence_profile, supply_chain_profile,
    suspicious_process_tree_profile, suspicious_scripting_profile,
};
use crate::replay::DetectorCandidateManifest;
use swarm_core::config::DetectionConfig;
use swarm_whisker::{
    BehavioralAnomalyDetector, CredentialAccessDetector, DetectionFinding, DetectionStrategy,
    DnsExfiltrationDetector, FilelessExecutionDetector, InfrastructureAnomalyDetector,
    LateralMovementDetector, NetworkConnectDetector, PersistenceDetector, SupplyChainDetector,
    SuspiciousProcessTreeDetector, SuspiciousScriptingDetector, TelemetryEvent,
};

#[derive(Debug, thiserror::Error)]
pub enum DetectorFactoryError {
    #[error(transparent)]
    DetectorProfile(#[from] DetectorProfileError),

    #[error("unsupported detector strategy `{strategy}`")]
    UnsupportedDetector { strategy: String },
}

#[derive(Debug, Clone)]
pub enum RuntimeDetector {
    Noop {
        strategy_id: String,
    },
    SuspiciousProcessTree {
        strategy_id: String,
        detector: SuspiciousProcessTreeDetector,
    },
    FilelessExecution {
        strategy_id: String,
        detector: FilelessExecutionDetector,
    },
    BehavioralAnomaly {
        strategy_id: String,
        detector: BehavioralAnomalyDetector,
    },
    DnsExfiltration {
        strategy_id: String,
        detector: DnsExfiltrationDetector,
    },
    LateralMovement {
        strategy_id: String,
        detector: LateralMovementDetector,
    },
    CredentialAccess {
        strategy_id: String,
        detector: CredentialAccessDetector,
    },
    SuspiciousScripting {
        strategy_id: String,
        detector: SuspiciousScriptingDetector,
    },
    Persistence {
        strategy_id: String,
        detector: PersistenceDetector,
    },
    SupplyChain {
        strategy_id: String,
        detector: SupplyChainDetector,
    },
    NetworkConnect {
        strategy_id: String,
        detector: NetworkConnectDetector,
    },
    InfrastructureAnomaly {
        strategy_id: String,
        detector: InfrastructureAnomalyDetector,
    },
}

impl RuntimeDetector {
    fn suspicious_process_tree(
        strategy_id: impl Into<String>,
        profile: swarm_whisker::SuspiciousProcessTreeProfile,
    ) -> Result<Self, DetectorFactoryError> {
        Ok(Self::SuspiciousProcessTree {
            strategy_id: strategy_id.into(),
            detector: SuspiciousProcessTreeDetector::from_profile(profile).map_err(|source| {
                DetectorProfileError::Validation {
                    strategy: "suspicious_process_tree",
                    source,
                }
            })?,
        })
    }

    fn noop(strategy_id: impl Into<String>) -> Self {
        Self::Noop {
            strategy_id: strategy_id.into(),
        }
    }

    fn dns_exfiltration(
        strategy_id: impl Into<String>,
        profile: swarm_whisker::DnsExfiltrationProfile,
    ) -> Result<Self, DetectorFactoryError> {
        Ok(Self::DnsExfiltration {
            strategy_id: strategy_id.into(),
            detector: DnsExfiltrationDetector::from_profile(profile).map_err(|source| {
                DetectorProfileError::Validation {
                    strategy: "dns_exfiltration",
                    source,
                }
            })?,
        })
    }

    fn fileless_execution(
        strategy_id: impl Into<String>,
        profile: swarm_whisker::FilelessExecutionProfile,
    ) -> Result<Self, DetectorFactoryError> {
        Ok(Self::FilelessExecution {
            strategy_id: strategy_id.into(),
            detector: FilelessExecutionDetector::from_profile(profile).map_err(|source| {
                DetectorProfileError::Validation {
                    strategy: "fileless_execution",
                    source,
                }
            })?,
        })
    }

    fn behavioral_anomaly(
        strategy_id: impl Into<String>,
        profile: swarm_whisker::BehavioralAnomalyProfile,
    ) -> Result<Self, DetectorFactoryError> {
        Ok(Self::BehavioralAnomaly {
            strategy_id: strategy_id.into(),
            detector: BehavioralAnomalyDetector::from_profile(profile).map_err(|source| {
                DetectorProfileError::Validation {
                    strategy: "behavioral_anomaly",
                    source,
                }
            })?,
        })
    }

    fn lateral_movement(
        strategy_id: impl Into<String>,
        profile: swarm_whisker::LateralMovementProfile,
    ) -> Result<Self, DetectorFactoryError> {
        Ok(Self::LateralMovement {
            strategy_id: strategy_id.into(),
            detector: LateralMovementDetector::from_profile(profile).map_err(|source| {
                DetectorProfileError::Validation {
                    strategy: "lateral_movement",
                    source,
                }
            })?,
        })
    }

    fn credential_access(
        strategy_id: impl Into<String>,
        profile: swarm_whisker::CredentialAccessProfile,
    ) -> Result<Self, DetectorFactoryError> {
        Ok(Self::CredentialAccess {
            strategy_id: strategy_id.into(),
            detector: CredentialAccessDetector::from_profile(profile).map_err(|source| {
                DetectorProfileError::Validation {
                    strategy: "credential_access",
                    source,
                }
            })?,
        })
    }

    fn suspicious_scripting(
        strategy_id: impl Into<String>,
        profile: swarm_whisker::SuspiciousScriptingProfile,
    ) -> Result<Self, DetectorFactoryError> {
        Ok(Self::SuspiciousScripting {
            strategy_id: strategy_id.into(),
            detector: SuspiciousScriptingDetector::from_profile(profile).map_err(|source| {
                DetectorProfileError::Validation {
                    strategy: "suspicious_scripting",
                    source,
                }
            })?,
        })
    }

    fn persistence(
        strategy_id: impl Into<String>,
        profile: swarm_whisker::PersistenceProfile,
    ) -> Result<Self, DetectorFactoryError> {
        Ok(Self::Persistence {
            strategy_id: strategy_id.into(),
            detector: PersistenceDetector::from_profile(profile).map_err(|source| {
                DetectorProfileError::Validation {
                    strategy: "persistence",
                    source,
                }
            })?,
        })
    }

    fn supply_chain(
        strategy_id: impl Into<String>,
        profile: swarm_whisker::SupplyChainProfile,
    ) -> Result<Self, DetectorFactoryError> {
        Ok(Self::SupplyChain {
            strategy_id: strategy_id.into(),
            detector: SupplyChainDetector::from_profile(profile).map_err(|source| {
                DetectorProfileError::Validation {
                    strategy: "supply_chain",
                    source,
                }
            })?,
        })
    }

    fn network_connect(
        strategy_id: impl Into<String>,
        profile: swarm_whisker::NetworkConnectProfile,
    ) -> Result<Self, DetectorFactoryError> {
        Ok(Self::NetworkConnect {
            strategy_id: strategy_id.into(),
            detector: NetworkConnectDetector::from_profile(profile).map_err(|source| {
                DetectorProfileError::Validation {
                    strategy: "network_connect",
                    source,
                }
            })?,
        })
    }

    fn infrastructure_anomaly(
        strategy_id: impl Into<String>,
        profile: swarm_whisker::InfrastructureAnomalyProfile,
    ) -> Result<Self, DetectorFactoryError> {
        Ok(Self::InfrastructureAnomaly {
            strategy_id: strategy_id.into(),
            detector: InfrastructureAnomalyDetector::from_profile(profile).map_err(|source| {
                DetectorProfileError::Validation {
                    strategy: "infrastructure_anomaly",
                    source,
                }
            })?,
        })
    }

    fn scoped_findings(
        strategy_id: &str,
        findings: Vec<DetectionFinding>,
    ) -> Vec<DetectionFinding> {
        findings
            .into_iter()
            .map(|mut finding| {
                finding.strategy_id = strategy_id.to_string();
                finding.finding_id = format!("{strategy_id}:{}", finding.event_id);
                finding
            })
            .collect()
    }

    pub fn behavioral_anomaly_detector(&self) -> Option<(&str, &BehavioralAnomalyDetector)> {
        match self {
            Self::BehavioralAnomaly {
                strategy_id,
                detector,
            } => Some((strategy_id.as_str(), detector)),
            _ => None,
        }
    }
}

impl DetectionStrategy for RuntimeDetector {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn id(&self) -> &str {
        match self {
            Self::Noop { strategy_id } => strategy_id.as_str(),
            Self::SuspiciousProcessTree { strategy_id, .. } => strategy_id.as_str(),
            Self::FilelessExecution { strategy_id, .. } => strategy_id.as_str(),
            Self::BehavioralAnomaly { strategy_id, .. } => strategy_id.as_str(),
            Self::DnsExfiltration { strategy_id, .. } => strategy_id.as_str(),
            Self::LateralMovement { strategy_id, .. } => strategy_id.as_str(),
            Self::CredentialAccess { strategy_id, .. } => strategy_id.as_str(),
            Self::SuspiciousScripting { strategy_id, .. } => strategy_id.as_str(),
            Self::Persistence { strategy_id, .. } => strategy_id.as_str(),
            Self::SupplyChain { strategy_id, .. } => strategy_id.as_str(),
            Self::NetworkConnect { strategy_id, .. } => strategy_id.as_str(),
            Self::InfrastructureAnomaly { strategy_id, .. } => strategy_id.as_str(),
        }
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        match self {
            Self::Noop { .. } => Vec::new(),
            Self::SuspiciousProcessTree {
                strategy_id,
                detector,
            } => Self::scoped_findings(strategy_id, detector.evaluate(event)),
            Self::FilelessExecution {
                strategy_id,
                detector,
            } => Self::scoped_findings(strategy_id, detector.evaluate(event)),
            Self::BehavioralAnomaly {
                strategy_id,
                detector,
            } => Self::scoped_findings(strategy_id, detector.evaluate(event)),
            Self::DnsExfiltration {
                strategy_id,
                detector,
            } => Self::scoped_findings(strategy_id, detector.evaluate(event)),
            Self::LateralMovement {
                strategy_id,
                detector,
            } => Self::scoped_findings(strategy_id, detector.evaluate(event)),
            Self::CredentialAccess {
                strategy_id,
                detector,
            } => Self::scoped_findings(strategy_id, detector.evaluate(event)),
            Self::SuspiciousScripting {
                strategy_id,
                detector,
            } => Self::scoped_findings(strategy_id, detector.evaluate(event)),
            Self::Persistence {
                strategy_id,
                detector,
            } => Self::scoped_findings(strategy_id, detector.evaluate(event)),
            Self::SupplyChain {
                strategy_id,
                detector,
            } => Self::scoped_findings(strategy_id, detector.evaluate(event)),
            Self::NetworkConnect {
                strategy_id,
                detector,
            } => Self::scoped_findings(strategy_id, detector.evaluate(event)),
            Self::InfrastructureAnomaly {
                strategy_id,
                detector,
            } => Self::scoped_findings(strategy_id, detector.evaluate(event)),
        }
    }
}

pub fn build_detector_from_strategy(
    strategy_id: &str,
    config: &DetectionConfig,
) -> Result<RuntimeDetector, DetectorFactoryError> {
    match strategy_id {
        "kill_chain_sequence" => Ok(RuntimeDetector::noop(strategy_id)),
        "suspicious_process_tree" => RuntimeDetector::suspicious_process_tree(
            strategy_id,
            suspicious_process_tree_profile(config)?,
        ),
        "fileless_execution" => {
            RuntimeDetector::fileless_execution(strategy_id, fileless_execution_profile(config)?)
        }
        "behavioral_anomaly" => {
            RuntimeDetector::behavioral_anomaly(strategy_id, behavioral_anomaly_profile(config)?)
        }
        "dns_exfiltration" => {
            RuntimeDetector::dns_exfiltration(strategy_id, dns_exfiltration_profile(config)?)
        }
        "lateral_movement" => {
            RuntimeDetector::lateral_movement(strategy_id, lateral_movement_profile(config)?)
        }
        "credential_access" => {
            RuntimeDetector::credential_access(strategy_id, credential_access_profile(config)?)
        }
        "suspicious_scripting" => RuntimeDetector::suspicious_scripting(
            strategy_id,
            suspicious_scripting_profile(config)?,
        ),
        "persistence" => RuntimeDetector::persistence(strategy_id, persistence_profile(config)?),
        "supply_chain" => RuntimeDetector::supply_chain(strategy_id, supply_chain_profile(config)?),
        "network_connect" => {
            RuntimeDetector::network_connect(strategy_id, network_connect_profile(config)?)
        }
        "infrastructure_anomaly" => RuntimeDetector::infrastructure_anomaly(
            strategy_id,
            infrastructure_anomaly_profile(config)?,
        ),
        other => Err(DetectorFactoryError::UnsupportedDetector {
            strategy: other.to_string(),
        }),
    }
}

pub fn build_detector_from_candidate(
    candidate: &DetectorCandidateManifest,
) -> Result<RuntimeDetector, DetectorFactoryError> {
    match candidate {
        DetectorCandidateManifest::SuspiciousProcessTree {
            strategy_id,
            profile,
            ..
        } => RuntimeDetector::suspicious_process_tree(strategy_id.clone(), profile.clone()),
        DetectorCandidateManifest::FilelessExecution {
            strategy_id,
            profile,
            ..
        } => RuntimeDetector::fileless_execution(strategy_id.clone(), profile.clone()),
        DetectorCandidateManifest::BehavioralAnomaly {
            strategy_id,
            profile,
            ..
        } => RuntimeDetector::behavioral_anomaly(strategy_id.clone(), profile.clone()),
        DetectorCandidateManifest::DnsExfiltration {
            strategy_id,
            profile,
            ..
        } => RuntimeDetector::dns_exfiltration(strategy_id.clone(), profile.clone()),
        DetectorCandidateManifest::LateralMovement {
            strategy_id,
            profile,
            ..
        } => RuntimeDetector::lateral_movement(strategy_id.clone(), profile.clone()),
        DetectorCandidateManifest::CredentialAccess {
            strategy_id,
            profile,
            ..
        } => RuntimeDetector::credential_access(strategy_id.clone(), profile.clone()),
        DetectorCandidateManifest::SuspiciousScripting {
            strategy_id,
            profile,
            ..
        } => RuntimeDetector::suspicious_scripting(strategy_id.clone(), profile.clone()),
        DetectorCandidateManifest::Persistence {
            strategy_id,
            profile,
            ..
        } => RuntimeDetector::persistence(strategy_id.clone(), profile.clone()),
        DetectorCandidateManifest::SupplyChain {
            strategy_id,
            profile,
            ..
        } => RuntimeDetector::supply_chain(strategy_id.clone(), profile.clone()),
        DetectorCandidateManifest::NetworkConnect {
            strategy_id,
            profile,
            ..
        } => RuntimeDetector::network_connect(strategy_id.clone(), profile.clone()),
    }
}

pub fn build_candidate_manifest_from_strategy(
    strategy_id: &str,
    config: &DetectionConfig,
    description: impl Into<String>,
) -> Result<DetectorCandidateManifest, DetectorFactoryError> {
    let description = description.into();
    match strategy_id {
        "suspicious_process_tree" => Ok(DetectorCandidateManifest::SuspiciousProcessTree {
            strategy_id: strategy_id.to_string(),
            description,
            profile: suspicious_process_tree_profile(config)?,
        }),
        "fileless_execution" => Ok(DetectorCandidateManifest::FilelessExecution {
            strategy_id: strategy_id.to_string(),
            description,
            profile: fileless_execution_profile(config)?,
        }),
        "behavioral_anomaly" => Ok(DetectorCandidateManifest::BehavioralAnomaly {
            strategy_id: strategy_id.to_string(),
            description,
            profile: behavioral_anomaly_profile(config)?,
        }),
        "dns_exfiltration" => Ok(DetectorCandidateManifest::DnsExfiltration {
            strategy_id: strategy_id.to_string(),
            description,
            profile: dns_exfiltration_profile(config)?,
        }),
        "lateral_movement" => Ok(DetectorCandidateManifest::LateralMovement {
            strategy_id: strategy_id.to_string(),
            description,
            profile: lateral_movement_profile(config)?,
        }),
        "credential_access" => Ok(DetectorCandidateManifest::CredentialAccess {
            strategy_id: strategy_id.to_string(),
            description,
            profile: credential_access_profile(config)?,
        }),
        "suspicious_scripting" => Ok(DetectorCandidateManifest::SuspiciousScripting {
            strategy_id: strategy_id.to_string(),
            description,
            profile: suspicious_scripting_profile(config)?,
        }),
        "persistence" => Ok(DetectorCandidateManifest::Persistence {
            strategy_id: strategy_id.to_string(),
            description,
            profile: persistence_profile(config)?,
        }),
        "supply_chain" => Ok(DetectorCandidateManifest::SupplyChain {
            strategy_id: strategy_id.to_string(),
            description,
            profile: supply_chain_profile(config)?,
        }),
        "network_connect" => Ok(DetectorCandidateManifest::NetworkConnect {
            strategy_id: strategy_id.to_string(),
            description,
            profile: network_connect_profile(config)?,
        }),
        other => Err(DetectorFactoryError::UnsupportedDetector {
            strategy: other.to_string(),
        }),
    }
}
