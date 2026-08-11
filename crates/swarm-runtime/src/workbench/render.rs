use super::helpers::maintenance_status_label;
use super::types::{
    ReviewCapsule, ReviewCapsuleImport, ReviewDelegationPacket, ReviewLane, ReviewSessionExport,
    ReviewSessionList, ReviewSessionMaintenanceHandoff, ReviewSessionPromotionReadiness,
    ReviewSessionResolved,
};

pub fn render_review_session_list(list: &ReviewSessionList) -> String {
    let mut lines = vec![
        "Ambush Review Sessions".to_string(),
        format!("Total: {}", list.total_count),
    ];
    for session in &list.sessions {
        lines.push(format!(
            "- {} | title={} | artifacts={} | bundles={} | verifications={} | packets={}",
            session.session_id,
            session.title.as_deref().unwrap_or("untitled"),
            session.artifact_count,
            session.evidence_bundle_count,
            session.verification_count,
            session.promotion_packet_count
        ));
    }
    lines.join("\n")
}

pub fn render_review_session(resolved: &ReviewSessionResolved) -> String {
    let mut lines = vec![
        "Ambush Review Session".to_string(),
        format!("Session ID: {}", resolved.session.report.session_id),
        format!(
            "Title: {}",
            resolved
                .session
                .report
                .title
                .as_deref()
                .unwrap_or("untitled")
        ),
        format!("Artifacts: {}", resolved.session.report.artifact_refs.len()),
        format!("Evidence bundles: {}", resolved.evidence_bundles.len()),
        format!(
            "Evidence verifications: {}",
            resolved.evidence_verifications.len()
        ),
        format!("Promotion packets: {}", resolved.promotion_packets.len()),
        format!("Cross-lane summaries: {}", resolved.lane_summaries.len()),
        format!("Unresolved gaps: {}", resolved.unresolved_gaps.len()),
    ];
    if let Some(notes) = resolved.session.report.notes.as_deref() {
        lines.push(format!("Notes: {}", notes));
    }
    if !resolved.lane_summaries.is_empty() {
        lines.push("Lane summaries:".to_string());
        for summary in &resolved.lane_summaries {
            lines.push(format!(
                "- {} | artifacts={} | bundles={} | verifications={} | packets={} | refs={}",
                summary.lane.title(),
                summary.artifact_count,
                summary.evidence_bundle_count,
                summary.verification_count,
                summary.promotion_packet_count,
                summary.subject_refs.len()
            ));
        }
    }
    if !resolved.unresolved_gaps.is_empty() {
        lines.push("Gaps:".to_string());
        for gap in &resolved.unresolved_gaps {
            lines.push(format!(
                "- {}:{} | {}",
                gap.lane.map(ReviewLane::as_str).unwrap_or("cross_lane"),
                gap.code,
                gap.details
            ));
        }
    }
    lines.join("\n")
}

pub fn render_review_session_export(export: &ReviewSessionExport) -> String {
    let mut lines = vec![
        "Ambush Review Session Export".to_string(),
        format!("Export ID: {}", export.export_id),
        format!("Session ID: {}", export.session_id),
        format!("Artifacts: {}", export.artifact_refs.len()),
        format!("Evidence bundles: {}", export.evidence_bundles.len()),
        format!(
            "Evidence verifications: {}",
            export.evidence_verifications.len()
        ),
        format!("Promotion packets: {}", export.promotion_packets.len()),
        format!("Lane summaries: {}", export.lane_summaries.len()),
        format!("Unresolved gaps: {}", export.unresolved_gaps.len()),
    ];
    for summary in &export.lane_summaries {
        lines.push(format!(
            "- {} | artifacts={} | bundles={} | verifications={} | packets={}",
            summary.lane.title(),
            summary.artifact_count,
            summary.evidence_bundle_count,
            summary.verification_count,
            summary.promotion_packet_count
        ));
    }
    lines.join("\n")
}

pub fn render_review_capsule(capsule: &ReviewCapsule) -> String {
    let mut lines = vec![
        "Ambush Portable Review Capsule".to_string(),
        format!("Capsule ID: {}", capsule.capsule_id),
        format!("Session ID: {}", capsule.session_id),
        format!(
            "Source: {} ({})",
            capsule.source_kind.as_str(),
            capsule.source_id
        ),
        format!("Artifacts: {}", capsule.artifact_refs.len()),
        format!("Lane summaries: {}", capsule.lane_summaries.len()),
        format!("Unresolved gaps: {}", capsule.unresolved_gaps.len()),
        format!("Related refs: {}", capsule.related_refs.len()),
        format!(
            "Signer: {} ({})",
            capsule.signature.signer_id, capsule.signature.key_id
        ),
        format!("Advisory only: {}", capsule.advisory_only),
    ];
    if let Some(title) = capsule.title.as_deref() {
        lines.push(format!("Title: {}", title));
    }
    if let Some(notes) = capsule.notes.as_deref() {
        lines.push(format!("Notes: {}", notes));
    }
    for summary in &capsule.lane_summaries {
        lines.push(format!(
            "- {} | artifacts={} | bundles={} | verifications={} | packets={}",
            summary.lane.title(),
            summary.artifact_count,
            summary.evidence_bundle_count,
            summary.verification_count,
            summary.promotion_packet_count
        ));
    }
    lines.join("\n")
}

pub fn render_review_capsule_import(import: &ReviewCapsuleImport) -> String {
    let mut lines = vec![
        "Ambush Review Capsule Import".to_string(),
        format!("Import ID: {}", import.import_id),
        format!("Source path: {}", import.source_path),
        format!("Trust status: {}", import.trust_status.as_str()),
        format!("Checks: {}", import.checks.len()),
    ];
    if let Some(capsule_id) = import.source_capsule_id.as_deref() {
        lines.push(format!("Capsule ID: {}", capsule_id));
    }
    if let Some(session_id) = import.session_id.as_deref() {
        lines.push(format!("Session ID: {}", session_id));
    }
    if let Some(signer_id) = import.remote_signer_id.as_deref() {
        lines.push(format!("Remote signer: {}", signer_id));
    }
    if let Some(key_id) = import.remote_signer_key_id.as_deref() {
        lines.push(format!("Remote key: {}", key_id));
    }
    for check in &import.checks {
        lines.push(format!(
            "- {} | passed={} | {}",
            check.name, check.passed, check.details
        ));
    }
    lines.join("\n")
}

pub fn render_review_delegation_packet(packet: &ReviewDelegationPacket) -> String {
    let mut lines = vec![
        "Ambush Review Delegation Packet".to_string(),
        format!("Delegation ID: {}", packet.delegation_id),
        format!("Session ID: {}", packet.session_id),
        format!("Source kind: {}", packet.source_kind.as_str()),
        format!("Source capsule: {}", packet.source_capsule_id),
        format!("Reason: {}", packet.reason),
        format!("Advisory only: {}", packet.advisory_only),
    ];
    if let Some(import_id) = packet.source_import_id.as_deref() {
        lines.push(format!("Source import: {}", import_id));
    }
    if let Some(delegate_label) = packet.delegate_label.as_deref() {
        lines.push(format!("Delegate label: {}", delegate_label));
    }
    if let Some(imported_trust_status) = packet.imported_trust_status {
        lines.push(format!(
            "Imported trust status: {}",
            imported_trust_status.as_str()
        ));
    }
    for summary in &packet.lane_summaries {
        lines.push(format!(
            "- {} | artifacts={} | bundles={} | verifications={} | packets={}",
            summary.lane.title(),
            summary.artifact_count,
            summary.evidence_bundle_count,
            summary.verification_count,
            summary.promotion_packet_count
        ));
    }
    lines.join("\n")
}

pub fn render_review_session_handoff(handoff: &ReviewSessionMaintenanceHandoff) -> String {
    let mut lines = vec![
        "Ambush Review Session Maintenance Handoff".to_string(),
        format!("Handoff ID: {}", handoff.handoff_id),
        format!("Session ID: {}", handoff.session_id),
        format!("Status: {}", maintenance_status_label(handoff.status)),
        format!("Selected refs: {}", handoff.selected_artifact_refs.len()),
        format!("Derived bundle ids: {}", handoff.derived_bundle_ids.len()),
    ];
    for result in &handoff.action_results {
        lines.push(format!(
            "- bundle={} | action={} | status={} | verification={}",
            result.bundle_id,
            result.action_id,
            maintenance_status_label(result.status),
            result.verification_id.as_deref().unwrap_or("none")
        ));
    }
    lines.join("\n")
}

pub fn render_review_session_promotion_readiness(
    readiness: &ReviewSessionPromotionReadiness,
) -> String {
    let mut lines = vec![
        "Ambush Promotion Readiness Review".to_string(),
        format!("Readiness ID: {}", readiness.readiness_id),
        format!("Session ID: {}", readiness.session_id),
        format!("Recommendation: {}", readiness.recommendation.as_str()),
        format!("Lane summaries: {}", readiness.lane_summaries.len()),
        format!("Unresolved gaps: {}", readiness.unresolved_gaps.len()),
        format!("Advisory only: {}", readiness.advisory_only),
    ];
    for summary in &readiness.lane_summaries {
        lines.push(format!(
            "- {} | artifacts={} | bundles={} | verifications={} | packets={}",
            summary.lane.title(),
            summary.artifact_count,
            summary.evidence_bundle_count,
            summary.verification_count,
            summary.promotion_packet_count
        ));
    }
    if !readiness.unresolved_gaps.is_empty() {
        lines.push("Blocking gaps:".to_string());
        for gap in &readiness.unresolved_gaps {
            lines.push(format!(
                "- {}:{} | {}",
                gap.lane.map(ReviewLane::as_str).unwrap_or("cross_lane"),
                gap.code,
                gap.details
            ));
        }
    }
    lines.join("\n")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::render_review_session_list;
    use crate::workbench::types::{ReviewSessionList, ReviewSessionRecord};

    #[test]
    fn render_review_session_list_includes_session_metadata() {
        let list = ReviewSessionList {
            total_count: 1,
            sessions: vec![ReviewSessionRecord {
                session_id: "session:red".to_string(),
                created_at_ms: 1_700_000_000_000,
                title: Some("Office Loader".to_string()),
                artifact_count: 3,
                evidence_bundle_count: 1,
                verification_count: 1,
                promotion_packet_count: 1,
                bundle_path: "bundle.json".to_string(),
            }],
        };

        let rendered = render_review_session_list(&list);
        assert!(rendered.contains("session:red"));
        assert!(rendered.contains("Office Loader"));
        assert!(rendered.contains("artifacts=3"));
    }
}
