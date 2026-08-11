use super::types::ReviewArtifactRef;
use crate::operator_maintenance::OperatorMaintenanceStatus;
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn normalize_artifact_refs(
    artifact_refs: Vec<ReviewArtifactRef>,
) -> Vec<ReviewArtifactRef> {
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::new();
    for artifact in artifact_refs {
        let id = artifact.id.trim();
        if id.is_empty() {
            continue;
        }
        let key = format!("{}:{}", artifact.kind.as_str(), id);
        if seen.insert(key) {
            normalized.push(ReviewArtifactRef {
                kind: artifact.kind,
                id: id.to_string(),
            });
        }
    }
    normalized
}

pub(super) fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

pub(super) fn maintenance_status_label(status: OperatorMaintenanceStatus) -> &'static str {
    match status {
        OperatorMaintenanceStatus::Applied => "applied",
        OperatorMaintenanceStatus::Blocked => "blocked",
        OperatorMaintenanceStatus::Failed => "failed",
    }
}

pub(super) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub(super) fn now_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

pub(super) fn sanitize_id(value: &str) -> String {
    value
        .trim()
        .chars()
        .map(|character| match character {
            'a'..='z' | 'A'..='Z' | '0'..='9' => character.to_ascii_lowercase(),
            _ => '_',
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}
