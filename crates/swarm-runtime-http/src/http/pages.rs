use super::helpers::ReviewEvidenceVerificationFilter;
use super::render::{
    escape_html, render_demo_dashboard_panel, render_maintenance_status_pill,
    render_promotion_recommendation_options, render_providence_incident_status,
    render_providence_reconciliation_outcome, render_rehearsal_preview_details,
    render_related_ref_link, render_review_layout, render_status_pill, render_subject_kind_options,
    render_verification_filter_options, review_link, subject_api_path,
};
use super::review::ReviewHomeContext;
use swarm_runtime::evidence::{
    EvidenceBundle, EvidenceBundleList, EvidenceVerificationReport, EvidenceVerificationStatus,
    PromotionEvidencePacket, PromotionEvidencePacketList, PromotionEvidenceRecommendation,
};
use swarm_runtime::review_workbench::{
    ReviewCapsule, ReviewCapsuleImport, ReviewCapsuleImportList, ReviewCapsuleList,
    ReviewDelegationPacket, ReviewDelegationPacketList, ReviewSessionExport, ReviewSessionList,
    ReviewSessionMaintenanceHandoff, ReviewSessionPromotionReadiness, ReviewSessionResolved,
};

pub(super) fn render_review_session_list_page(list: &ReviewSessionList) -> String {
    let mut rows = String::new();
    for session in &list.sessions {
        rows.push_str(&format!(
            "<tr><td>{session_link}</td><td>{title}</td><td>{artifacts}</td><td>{bundles}</td><td>{verifications}</td><td>{packets}</td></tr>",
            session_link = review_link(
                &format!("/v1/operator/review/sessions/{}", session.session_id),
                &session.session_id
            ),
            title = escape_html(session.title.as_deref().unwrap_or("untitled")),
            artifacts = session.artifact_count,
            bundles = session.evidence_bundle_count,
            verifications = session.verification_count,
            packets = session.promotion_packet_count
        ));
    }
    if rows.is_empty() {
        rows.push_str(
            "<tr><td colspan=\"6\" class=\"muted\">No review sessions created yet.</td></tr>",
        );
    }

    render_review_layout(
        "Review Sessions",
        "Assemble durable multi-artifact evidence sessions from existing stable IDs, then export or hand them into bounded maintenance actions.",
        &format!(
            "<section class=\"grid\">\
                <article class=\"card\">\
                    <h2>Create Session</h2>\
                    <form class=\"toolbar\" method=\"post\" action=\"/v1/operator/review/sessions\">\
                        <label>Title<input type=\"text\" name=\"title\" placeholder=\"red evidence workbench\"></label>\
                        <label>Notes<input type=\"text\" name=\"notes\" placeholder=\"optional operator context\"></label>\
                        <label style=\"min-width:100%;\">Artifact refs<textarea name=\"artifact_refs\" rows=\"6\" placeholder=\"promotion_review:review:red&#10;canary_run:canary:red&#10;production_promotion:promotion:red\"></textarea></label>\
                        <button type=\"submit\">Create Review Session</button>\
                    </form>\
                    <p class=\"muted\">One artifact ref per line. Supported kinds: <code>evidence_bundle</code>, <code>evidence_verification</code>, <code>promotion_evidence_packet</code>, <code>promotion_review</code>, <code>canary_run</code>, <code>production_promotion</code>.</p>\
                </article>\
                <article class=\"card\">\
                    <h2>Recent Sessions</h2>\
                    <table><thead><tr><th>Session</th><th>Title</th><th>Artifacts</th><th>Bundles</th><th>Verifications</th><th>Packets</th></tr></thead><tbody>{rows}</tbody></table>\
                </article>\
            </section>",
            rows = rows
        ),
    )
}

pub(super) fn render_review_session_page(
    resolved: &ReviewSessionResolved,
    exports: &[swarm_runtime::review_workbench::ReviewSessionExportRecord],
    readiness_reports: &[swarm_runtime::review_workbench::ReviewSessionPromotionReadinessRecord],
    handoffs: &[swarm_runtime::review_workbench::ReviewSessionMaintenanceHandoffRecord],
    capsules: &[swarm_runtime::review_workbench::ReviewCapsuleRecord],
    delegations: &[swarm_runtime::review_workbench::ReviewDelegationPacketRecord],
) -> String {
    let mut lane_rows = String::new();
    for summary in &resolved.lane_summaries {
        lane_rows.push_str(&format!(
            "<tr><td>{lane}</td><td>{artifacts}</td><td>{bundles}</td><td>{verifications}</td><td>{packets}</td><td>{refs}</td></tr>",
            lane = escape_html(summary.lane.title()),
            artifacts = summary.artifact_count,
            bundles = summary.evidence_bundle_count,
            verifications = summary.verification_count,
            packets = summary.promotion_packet_count,
            refs = summary.subject_refs.len()
        ));
    }
    if lane_rows.is_empty() {
        lane_rows.push_str(
            "<tr><td colspan=\"6\" class=\"muted\">No cross-lane summary available.</td></tr>",
        );
    }

    let mut gap_rows = String::new();
    for gap in &resolved.unresolved_gaps {
        gap_rows.push_str(&format!(
            "<tr><td>{lane}</td><td><code>{code}</code></td><td>{details}</td></tr>",
            lane = escape_html(
                gap.lane
                    .map(|lane| lane.title().to_string())
                    .unwrap_or_else(|| "Cross-Lane".to_string())
                    .as_str()
            ),
            code = escape_html(&gap.code),
            details = escape_html(&gap.details)
        ));
    }
    if gap_rows.is_empty() {
        gap_rows.push_str(
            "<tr><td colspan=\"3\" class=\"muted\">No unresolved evidence gaps.</td></tr>",
        );
    }

    let mut bundle_rows = String::new();
    for bundle in &resolved.evidence_bundles {
        let verification = bundle
            .record
            .latest_verification_status
            .map(|status| render_status_pill(status.as_str(), status.as_str()))
            .unwrap_or_else(|| render_status_pill("unverified", "unverified"));
        bundle_rows.push_str(&format!(
            "<tr><td>{bundle_link}</td><td>{subject_kind}</td><td><code>{subject_id}</code></td><td>{verification}</td></tr>",
            bundle_link = review_link(
                &format!("/v1/operator/review/evidence/{}", bundle.record.bundle_id),
                &bundle.record.bundle_id
            ),
            subject_kind = escape_html(bundle.record.subject_kind.as_str()),
            subject_id = escape_html(&bundle.record.subject_id),
            verification = verification
        ));
    }
    if bundle_rows.is_empty() {
        bundle_rows.push_str(
            "<tr><td colspan=\"4\" class=\"muted\">No evidence bundles in this session.</td></tr>",
        );
    }

    let mut verification_rows = String::new();
    for verification in &resolved.evidence_verifications {
        verification_rows.push_str(&format!(
            "<tr><td>{verification_link}</td><td>{bundle_link}</td><td>{status}</td><td><code>{key_id}</code></td></tr>",
            verification_link = review_link(
                &format!(
                    "/v1/operator/review/verifications/{}",
                    verification.report.verification_id
                ),
                &verification.report.verification_id
            ),
            bundle_link = review_link(
                &format!("/v1/operator/review/evidence/{}", verification.report.bundle_id),
                &verification.report.bundle_id
            ),
            status = render_status_pill(
                verification.report.status.as_str(),
                verification.report.status.as_str()
            ),
            key_id = escape_html(&verification.report.signer_key_id)
        ));
    }
    if verification_rows.is_empty() {
        verification_rows.push_str(
            "<tr><td colspan=\"4\" class=\"muted\">No evidence verifications in this session.</td></tr>",
        );
    }

    let mut packet_rows = String::new();
    for packet in &resolved.promotion_packets {
        let recommendation = match packet.packet.recommendation {
            PromotionEvidenceRecommendation::ReadyForExternalReview => {
                render_status_pill("ready_for_external_review", "ready")
            }
            PromotionEvidenceRecommendation::Blocked => render_status_pill("blocked", "blocked"),
        };
        packet_rows.push_str(&format!(
            "<tr><td>{packet_link}</td><td><code>{promotion_id}</code></td><td>{recommendation}</td><td>{attachments}</td></tr>",
            packet_link = review_link(
                &format!("/v1/operator/review/promotion-packets/{}", packet.packet.packet_id),
                &packet.packet.packet_id
            ),
            promotion_id = escape_html(&packet.packet.promotion_id),
            recommendation = recommendation,
            attachments = packet.packet.supporting_evidence.len()
        ));
    }
    if packet_rows.is_empty() {
        packet_rows.push_str(
            "<tr><td colspan=\"4\" class=\"muted\">No promotion evidence packets in this session.</td></tr>",
        );
    }

    let mut export_rows = String::new();
    for export in exports {
        export_rows.push_str(&format!(
            "<tr><td>{export_link}</td><td>{artifacts}</td></tr>",
            export_link = review_link(
                &format!("/v1/operator/review/exports/{}", export.export_id),
                &export.export_id
            ),
            artifacts = export.artifact_count
        ));
    }
    if export_rows.is_empty() {
        export_rows
            .push_str("<tr><td colspan=\"2\" class=\"muted\">No exports created yet.</td></tr>");
    }

    let mut readiness_rows = String::new();
    for readiness in readiness_reports {
        readiness_rows.push_str(&format!(
            "<tr><td>{readiness_link}</td><td>{recommendation}</td><td>{gaps}</td></tr>",
            readiness_link = review_link(
                &format!(
                    "/v1/operator/review/promotion-readiness/{}",
                    readiness.readiness_id
                ),
                &readiness.readiness_id
            ),
            recommendation = render_status_pill(
                readiness.recommendation.as_str(),
                readiness.recommendation.as_str()
            ),
            gaps = readiness.gap_count
        ));
    }
    if readiness_rows.is_empty() {
        readiness_rows.push_str(
            "<tr><td colspan=\"3\" class=\"muted\">No promotion readiness reviews created yet.</td></tr>",
        );
    }

    let mut handoff_rows = String::new();
    for handoff in handoffs {
        handoff_rows.push_str(&format!(
            "<tr><td>{handoff_link}</td><td>{status}</td><td>{actions}</td></tr>",
            handoff_link = review_link(
                &format!("/v1/operator/review/handoffs/{}", handoff.handoff_id),
                &handoff.handoff_id
            ),
            status = render_maintenance_status_pill(handoff.status),
            actions = handoff.action_count
        ));
    }
    if handoff_rows.is_empty() {
        handoff_rows.push_str(
            "<tr><td colspan=\"3\" class=\"muted\">No maintenance handoffs created yet.</td></tr>",
        );
    }

    let mut capsule_rows = String::new();
    for capsule in capsules {
        capsule_rows.push_str(&format!(
            "<tr><td>{capsule_link}</td><td><code>{source_kind}</code></td><td><code>{key_id}</code></td><td>{gaps}</td></tr>",
            capsule_link = review_link(
                &format!("/v1/operator/review/capsules/{}", capsule.capsule_id),
                &capsule.capsule_id
            ),
            source_kind = escape_html(capsule.source_kind.as_str()),
            key_id = escape_html(&capsule.signer_key_id),
            gaps = capsule.gap_count
        ));
    }
    if capsule_rows.is_empty() {
        capsule_rows.push_str(
            "<tr><td colspan=\"4\" class=\"muted\">No portable review capsules created yet.</td></tr>",
        );
    }

    let mut delegation_rows = String::new();
    for delegation in delegations {
        delegation_rows.push_str(&format!(
            "<tr><td>{delegation_link}</td><td><code>{source_kind}</code></td><td><code>{capsule_id}</code></td><td>{gaps}</td></tr>",
            delegation_link = review_link(
                &format!("/v1/operator/review/delegations/{}", delegation.delegation_id),
                &delegation.delegation_id
            ),
            source_kind = escape_html(delegation.source_kind.as_str()),
            capsule_id = escape_html(&delegation.source_capsule_id),
            gaps = delegation.gap_count
        ));
    }
    if delegation_rows.is_empty() {
        delegation_rows.push_str(
            "<tr><td colspan=\"4\" class=\"muted\">No delegation packets created yet.</td></tr>",
        );
    }

    render_review_layout(
        "Review Session Detail",
        "Compare the reviewed evidence set across governance-prep, canary, and production lanes, export a stable snapshot, sign a portable capsule, or launch one bounded evidence re-verification handoff.",
        &format!(
            "<section class=\"card\">\
                <div class=\"meta\">\
                    <div><dt>Session ID</dt><dd><code>{session_id}</code></dd></div>\
                    <div><dt>Title</dt><dd>{title}</dd></div>\
                    <div><dt>Artifacts</dt><dd>{artifact_count}</dd></div>\
                    <div><dt>Cross-Lane Gaps</dt><dd>{gap_count}</dd></div>\
                    <div><dt>Notes</dt><dd>{notes}</dd></div>\
                </div>\
                <div class=\"grid\">\
                    <article class=\"card\">\
                        <h3>Export Snapshot</h3>\
                        <form method=\"post\" action=\"/v1/operator/review/sessions/{session_id}/export\">\
                            <button type=\"submit\">Create Export</button>\
                        </form>\
                        <p class=\"muted\">Exports preserve digests, signer metadata, verification state, and related stable references for this session.</p>\
                    </article>\
                    <article class=\"card\">\
                        <h3>Portable Review Capsule</h3>\
                        <form method=\"post\" action=\"/v1/operator/review/sessions/{session_id}/capsules\">\
                            <button type=\"submit\">Create Signed Capsule</button>\
                        </form>\
                        <p class=\"muted\">Portable capsules package the cross-lane session into one signed review artifact for external verification without direct store access.</p>\
                    </article>\
                    <article class=\"card\">\
                        <h3>Promotion Readiness Review</h3>\
                        <form method=\"post\" action=\"/v1/operator/review/sessions/{session_id}/promotion-readiness\">\
                            <button type=\"submit\">Create Promotion Readiness Review</button>\
                        </form>\
                        <p class=\"muted\">This remains advisory-only. It summarizes whether governance-prep, canary, and production evidence are all present and free of unresolved gaps.</p>\
                    </article>\
                    <article class=\"card\">\
                        <h3>Re-Verification Handoff</h3>\
                        <form class=\"toolbar\" method=\"post\" action=\"/v1/operator/review/sessions/{session_id}/handoffs/reverify\">\
                            <label>Reason<input type=\"text\" name=\"reason\" placeholder=\"recheck signer integrity before maintenance review\"></label>\
                            <label>Expected key ID<input type=\"text\" name=\"expected_key_id\" placeholder=\"optional signer fingerprint\"></label>\
                            <label style=\"min-width:100%;\">Selected refs<textarea name=\"selected_artifact_refs\" rows=\"4\" placeholder=\"optional; leave empty to use all session refs\"></textarea></label>\
                            <button type=\"submit\">Launch Bounded Handoff</button>\
                        </form>\
                    </article>\
                </div>\
            </section>\
            <section class=\"grid\" style=\"margin-top:18px;\">\
                <article class=\"card\"><h2>Cross-Lane Summary</h2><table><thead><tr><th>Lane</th><th>Artifacts</th><th>Bundles</th><th>Verifications</th><th>Packets</th><th>Refs</th></tr></thead><tbody>{lane_rows}</tbody></table></article>\
                <article class=\"card\"><h2>Evidence Gaps</h2><table><thead><tr><th>Lane</th><th>Code</th><th>Details</th></tr></thead><tbody>{gap_rows}</tbody></table></article>\
            </section>\
            <section class=\"grid\" style=\"margin-top:18px;\">\
                <article class=\"card\"><h2>Evidence Bundles</h2><table><thead><tr><th>Bundle</th><th>Kind</th><th>Subject</th><th>Verification</th></tr></thead><tbody>{bundle_rows}</tbody></table></article>\
                <article class=\"card\"><h2>Verification Reports</h2><table><thead><tr><th>Verification</th><th>Bundle</th><th>Status</th><th>Signer Key</th></tr></thead><tbody>{verification_rows}</tbody></table></article>\
            </section>\
            <section class=\"grid\" style=\"margin-top:18px;\">\
                <article class=\"card\"><h2>Promotion Evidence Packets</h2><table><thead><tr><th>Packet</th><th>Promotion</th><th>Recommendation</th><th>Attachments</th></tr></thead><tbody>{packet_rows}</tbody></table></article>\
                <article class=\"card\"><h2>Recent Exports</h2><table><thead><tr><th>Export</th><th>Artifacts</th></tr></thead><tbody>{export_rows}</tbody></table>\
                <h2 style=\"margin-top:20px;\">Portable Capsules</h2><table><thead><tr><th>Capsule</th><th>Source</th><th>Signer Key</th><th>Gaps</th></tr></thead><tbody>{capsule_rows}</tbody></table>\
                <h2 style=\"margin-top:20px;\">Promotion Readiness Reviews</h2><table><thead><tr><th>Review</th><th>Recommendation</th><th>Gaps</th></tr></thead><tbody>{readiness_rows}</tbody></table>\
                <h2 style=\"margin-top:20px;\">Delegation Packets</h2><table><thead><tr><th>Delegation</th><th>Source</th><th>Capsule</th><th>Gaps</th></tr></thead><tbody>{delegation_rows}</tbody></table>\
                <h2 style=\"margin-top:20px;\">Recent Handoffs</h2><table><thead><tr><th>Handoff</th><th>Status</th><th>Actions</th></tr></thead><tbody>{handoff_rows}</tbody></table></article>\
            </section>",
            session_id = escape_html(&resolved.session.report.session_id),
            title = escape_html(
                resolved
                    .session
                    .report
                    .title
                    .as_deref()
                    .unwrap_or("untitled")
            ),
            artifact_count = resolved.session.report.artifact_refs.len(),
            gap_count = resolved.unresolved_gaps.len(),
            notes = escape_html(resolved.session.report.notes.as_deref().unwrap_or("none")),
            lane_rows = lane_rows,
            gap_rows = gap_rows,
            bundle_rows = bundle_rows,
            verification_rows = verification_rows,
            packet_rows = packet_rows,
            export_rows = export_rows,
            capsule_rows = capsule_rows,
            readiness_rows = readiness_rows,
            delegation_rows = delegation_rows,
            handoff_rows = handoff_rows
        ),
    )
}

pub(super) fn render_review_session_export_page(export: &ReviewSessionExport) -> String {
    let mut lane_rows = String::new();
    for summary in &export.lane_summaries {
        lane_rows.push_str(&format!(
            "<tr><td>{lane}</td><td>{artifacts}</td><td>{bundles}</td><td>{verifications}</td><td>{packets}</td></tr>",
            lane = escape_html(summary.lane.title()),
            artifacts = summary.artifact_count,
            bundles = summary.evidence_bundle_count,
            verifications = summary.verification_count,
            packets = summary.promotion_packet_count
        ));
    }
    if lane_rows.is_empty() {
        lane_rows.push_str(
            "<tr><td colspan=\"5\" class=\"muted\">No lane summaries exported.</td></tr>",
        );
    }

    let mut gap_rows = String::new();
    for gap in &export.unresolved_gaps {
        gap_rows.push_str(&format!(
            "<tr><td>{lane}</td><td><code>{code}</code></td><td>{details}</td></tr>",
            lane = escape_html(
                gap.lane
                    .map(|lane| lane.title().to_string())
                    .unwrap_or_else(|| "Cross-Lane".to_string())
                    .as_str()
            ),
            code = escape_html(&gap.code),
            details = escape_html(&gap.details)
        ));
    }
    if gap_rows.is_empty() {
        gap_rows.push_str(
            "<tr><td colspan=\"3\" class=\"muted\">No unresolved gaps exported.</td></tr>",
        );
    }

    let mut bundle_rows = String::new();
    for bundle in &export.evidence_bundles {
        let verification = bundle
            .latest_verification_status
            .map(|status| render_status_pill(status.as_str(), status.as_str()))
            .unwrap_or_else(|| render_status_pill("unverified", "unverified"));
        bundle_rows.push_str(&format!(
            "<tr><td><code>{bundle_id}</code></td><td>{subject_kind}</td><td><code>{subject_id}</code></td><td><code>{digest}</code></td><td>{verification}</td></tr>",
            bundle_id = escape_html(&bundle.bundle_id),
            subject_kind = escape_html(bundle.subject_kind.as_str()),
            subject_id = escape_html(&bundle.subject_id),
            digest = escape_html(&bundle.payload_sha256),
            verification = verification
        ));
    }
    if bundle_rows.is_empty() {
        bundle_rows
            .push_str("<tr><td colspan=\"5\" class=\"muted\">No bundles exported.</td></tr>");
    }

    let mut verification_rows = String::new();
    for verification in &export.evidence_verifications {
        verification_rows.push_str(&format!(
            "<tr><td><code>{verification_id}</code></td><td><code>{bundle_id}</code></td><td>{status}</td><td><code>{key_id}</code></td></tr>",
            verification_id = escape_html(&verification.verification_id),
            bundle_id = escape_html(&verification.bundle_id),
            status = render_status_pill(verification.status.as_str(), verification.status.as_str()),
            key_id = escape_html(&verification.signer_key_id)
        ));
    }
    if verification_rows.is_empty() {
        verification_rows.push_str(
            "<tr><td colspan=\"4\" class=\"muted\">No verification reports exported.</td></tr>",
        );
    }

    let mut packet_rows = String::new();
    for packet in &export.promotion_packets {
        packet_rows.push_str(&format!(
            "<tr><td><code>{packet_id}</code></td><td><code>{promotion_id}</code></td><td>{recommendation}</td><td>{attachments}</td></tr>",
            packet_id = escape_html(&packet.packet_id),
            promotion_id = escape_html(&packet.promotion_id),
            recommendation = match packet.recommendation {
                PromotionEvidenceRecommendation::ReadyForExternalReview => render_status_pill("ready_for_external_review", "ready"),
                PromotionEvidenceRecommendation::Blocked => render_status_pill("blocked", "blocked"),
            },
            attachments = packet.supporting_evidence.len()
        ));
    }
    if packet_rows.is_empty() {
        packet_rows.push_str(
            "<tr><td colspan=\"4\" class=\"muted\">No promotion packets exported.</td></tr>",
        );
    }

    render_review_layout(
        "Review Session Export",
        "Stable export snapshot preserving the current review set and its trust metadata.",
        &format!(
            "<section class=\"card\">\
                <div class=\"meta\">\
                    <div><dt>Export ID</dt><dd><code>{export_id}</code></dd></div>\
                    <div><dt>Session ID</dt><dd>{session_link}</dd></div>\
                    <div><dt>Artifacts</dt><dd>{artifacts}</dd></div>\
                    <div><dt>Lane Summaries</dt><dd>{lane_count}</dd></div>\
                    <div><dt>Gaps</dt><dd>{gap_count}</dd></div>\
                    <div><dt>Title</dt><dd>{title}</dd></div>\
                </div>\
                <p class=\"muted\">This export preserves digests, signer metadata, verification state, and related stable references without rereading raw store files.</p>\
                <h2>Cross-Lane Summary</h2><table><thead><tr><th>Lane</th><th>Artifacts</th><th>Bundles</th><th>Verifications</th><th>Packets</th></tr></thead><tbody>{lane_rows}</tbody></table>\
                <h2 style=\"margin-top:20px;\">Unresolved Gaps</h2><table><thead><tr><th>Lane</th><th>Code</th><th>Details</th></tr></thead><tbody>{gap_rows}</tbody></table>\
                <h2>Bundles</h2><table><thead><tr><th>Bundle</th><th>Kind</th><th>Subject</th><th>Payload SHA-256</th><th>Verification</th></tr></thead><tbody>{bundle_rows}</tbody></table>\
                <h2 style=\"margin-top:20px;\">Verification Reports</h2><table><thead><tr><th>Verification</th><th>Bundle</th><th>Status</th><th>Signer Key</th></tr></thead><tbody>{verification_rows}</tbody></table>\
                <h2 style=\"margin-top:20px;\">Promotion Packets</h2><table><thead><tr><th>Packet</th><th>Promotion</th><th>Recommendation</th><th>Attachments</th></tr></thead><tbody>{packet_rows}</tbody></table>\
            </section>",
            export_id = escape_html(&export.export_id),
            session_link = review_link(
                &format!("/v1/operator/review/sessions/{}", export.session_id),
                &export.session_id
            ),
            artifacts = export.artifact_refs.len(),
            lane_count = export.lane_summaries.len(),
            gap_count = export.unresolved_gaps.len(),
            title = escape_html(export.title.as_deref().unwrap_or("untitled")),
            lane_rows = lane_rows,
            gap_rows = gap_rows,
            bundle_rows = bundle_rows,
            verification_rows = verification_rows,
            packet_rows = packet_rows
        ),
    )
}

pub(super) fn render_review_capsule_page(capsule: &ReviewCapsule) -> String {
    let mut lane_rows = String::new();
    for summary in &capsule.lane_summaries {
        lane_rows.push_str(&format!(
            "<tr><td>{lane}</td><td>{artifacts}</td><td>{bundles}</td><td>{verifications}</td><td>{packets}</td></tr>",
            lane = escape_html(summary.lane.title()),
            artifacts = summary.artifact_count,
            bundles = summary.evidence_bundle_count,
            verifications = summary.verification_count,
            packets = summary.promotion_packet_count
        ));
    }
    if lane_rows.is_empty() {
        lane_rows.push_str(
            "<tr><td colspan=\"5\" class=\"muted\">No lane summaries captured.</td></tr>",
        );
    }

    let mut gap_rows = String::new();
    for gap in &capsule.unresolved_gaps {
        gap_rows.push_str(&format!(
            "<tr><td>{lane}</td><td><code>{code}</code></td><td>{details}</td></tr>",
            lane = escape_html(
                gap.lane
                    .map(|lane| lane.title().to_string())
                    .unwrap_or_else(|| "Cross-Lane".to_string())
                    .as_str()
            ),
            code = escape_html(&gap.code),
            details = escape_html(&gap.details)
        ));
    }
    if gap_rows.is_empty() {
        gap_rows.push_str(
            "<tr><td colspan=\"3\" class=\"muted\">No unresolved gaps captured.</td></tr>",
        );
    }

    let mut related_ref_rows = String::new();
    for related in &capsule.related_refs {
        related_ref_rows.push_str(&format!(
            "<tr><td><code>{kind}</code></td><td><code>{id}</code></td></tr>",
            kind = escape_html(&related.kind),
            id = escape_html(&related.id)
        ));
    }
    if related_ref_rows.is_empty() {
        related_ref_rows.push_str(
            "<tr><td colspan=\"2\" class=\"muted\">No related stable refs preserved.</td></tr>",
        );
    }

    render_review_layout(
        "Portable Review Capsule",
        "Signed cross-lane review capsule suitable for external verification without direct store access.",
        &format!(
            "<section class=\"card\">\
                <div class=\"meta\">\
                    <div><dt>Capsule ID</dt><dd><code>{capsule_id}</code></dd></div>\
                    <div><dt>Session ID</dt><dd>{session_link}</dd></div>\
                    <div><dt>Source</dt><dd><code>{source_kind}</code> / <code>{source_id}</code></dd></div>\
                    <div><dt>Signer</dt><dd><code>{signer_id}</code></dd></div>\
                    <div><dt>Signer Key</dt><dd><code>{signer_key_id}</code></dd></div>\
                    <div><dt>Advisory Only</dt><dd>{advisory_only}</dd></div>\
                </div>\
                <p class=\"muted\">This capsule is signed and portable. It preserves lane summaries, unresolved gaps, and stable evidence references without exposing the local store.</p>\
                <form class=\"toolbar\" method=\"post\" action=\"/v1/operator/review/capsules/{capsule_id}/delegations\">\
                    <label>Reason<input type=\"text\" name=\"reason\" placeholder=\"handoff this signed review to a separate trust boundary\"></label>\
                    <label>Delegate label<input type=\"text\" name=\"delegate_label\" placeholder=\"optional external review group\"></label>\
                    <button type=\"submit\">Create Delegation Packet</button>\
                </form>\
                <h2>Lane Summary</h2><table><thead><tr><th>Lane</th><th>Artifacts</th><th>Bundles</th><th>Verifications</th><th>Packets</th></tr></thead><tbody>{lane_rows}</tbody></table>\
                <h2 style=\"margin-top:20px;\">Unresolved Gaps</h2><table><thead><tr><th>Lane</th><th>Code</th><th>Details</th></tr></thead><tbody>{gap_rows}</tbody></table>\
                <h2 style=\"margin-top:20px;\">Related Stable Refs</h2><table><thead><tr><th>Kind</th><th>ID</th></tr></thead><tbody>{related_ref_rows}</tbody></table>\
            </section>",
            capsule_id = escape_html(&capsule.capsule_id),
            session_link = review_link(
                &format!("/v1/operator/review/sessions/{}", capsule.session_id),
                &capsule.session_id
            ),
            source_kind = escape_html(capsule.source_kind.as_str()),
            source_id = escape_html(&capsule.source_id),
            signer_id = escape_html(&capsule.signature.signer_id),
            signer_key_id = escape_html(&capsule.signature.key_id),
            advisory_only = capsule.advisory_only,
            lane_rows = lane_rows,
            gap_rows = gap_rows,
            related_ref_rows = related_ref_rows
        ),
    )
}

pub(super) fn render_review_capsule_import_page(import: &ReviewCapsuleImport) -> String {
    let mut check_rows = String::new();
    for check in &import.checks {
        check_rows.push_str(&format!(
            "<tr><td><code>{name}</code></td><td>{status}</td><td>{details}</td></tr>",
            name = escape_html(&check.name),
            status = if check.passed {
                render_status_pill("passed", "passed")
            } else {
                render_status_pill("failed", "failed")
            },
            details = escape_html(&check.details)
        ));
    }
    if check_rows.is_empty() {
        check_rows.push_str("<tr><td colspan=\"3\" class=\"muted\">No checks recorded.</td></tr>");
    }

    let continuation_form = if import.capsule.is_some() {
        format!(
            "<form class=\"toolbar\" method=\"post\" action=\"/v1/operator/review/capsule-imports/{import_id}/delegations\">\
                <label>Reason<input type=\"text\" name=\"reason\" placeholder=\"preserve signed review continuity after import\"></label>\
                <label>Delegate label<input type=\"text\" name=\"delegate_label\" placeholder=\"optional receiving trust boundary\"></label>\
                <button type=\"submit\">Create Delegation Packet</button>\
            </form>",
            import_id = escape_html(&import.import_id)
        )
    } else {
        "<p class=\"muted\">This import did not decode into a valid review capsule, so delegation is unavailable.</p>".to_string()
    };

    render_review_layout(
        "Imported Review Capsule",
        "Local inspection result for one foreign signed review capsule with explicit local trust status.",
        &format!(
            "<section class=\"card\">\
                <div class=\"meta\">\
                    <div><dt>Import ID</dt><dd><code>{import_id}</code></dd></div>\
                    <div><dt>Source Path</dt><dd><code>{source_path}</code></dd></div>\
                    <div><dt>Trust Status</dt><dd>{trust_status}</dd></div>\
                    <div><dt>Capsule ID</dt><dd><code>{capsule_id}</code></dd></div>\
                    <div><dt>Remote Signer</dt><dd><code>{remote_signer}</code></dd></div>\
                    <div><dt>Remote Key</dt><dd><code>{remote_key}</code></dd></div>\
                    <div><dt>Trusted Key</dt><dd><code>{trusted_key}</code></dd></div>\
                </div>\
                {continuation_form}\
                <h2>Verification Checks</h2><table><thead><tr><th>Check</th><th>Status</th><th>Details</th></tr></thead><tbody>{check_rows}</tbody></table>\
            </section>",
            import_id = escape_html(&import.import_id),
            source_path = escape_html(&import.source_path),
            trust_status =
                render_status_pill(import.trust_status.as_str(), import.trust_status.as_str()),
            capsule_id = escape_html(import.source_capsule_id.as_deref().unwrap_or("unavailable")),
            remote_signer =
                escape_html(import.remote_signer_id.as_deref().unwrap_or("unavailable")),
            remote_key = escape_html(
                import
                    .remote_signer_key_id
                    .as_deref()
                    .unwrap_or("unavailable")
            ),
            trusted_key = escape_html(import.trusted_key_id.as_deref().unwrap_or("none")),
            continuation_form = continuation_form,
            check_rows = check_rows
        ),
    )
}

pub(super) fn render_review_session_promotion_readiness_page(
    readiness: &ReviewSessionPromotionReadiness,
) -> String {
    let mut lane_rows = String::new();
    for summary in &readiness.lane_summaries {
        lane_rows.push_str(&format!(
            "<tr><td>{lane}</td><td>{artifacts}</td><td>{bundles}</td><td>{verifications}</td><td>{packets}</td></tr>",
            lane = escape_html(summary.lane.title()),
            artifacts = summary.artifact_count,
            bundles = summary.evidence_bundle_count,
            verifications = summary.verification_count,
            packets = summary.promotion_packet_count
        ));
    }
    if lane_rows.is_empty() {
        lane_rows.push_str(
            "<tr><td colspan=\"5\" class=\"muted\">No lane summaries recorded.</td></tr>",
        );
    }

    let mut gap_rows = String::new();
    for gap in &readiness.unresolved_gaps {
        gap_rows.push_str(&format!(
            "<tr><td>{lane}</td><td><code>{code}</code></td><td>{details}</td></tr>",
            lane = escape_html(
                gap.lane
                    .map(|lane| lane.title().to_string())
                    .unwrap_or_else(|| "Cross-Lane".to_string())
                    .as_str()
            ),
            code = escape_html(&gap.code),
            details = escape_html(&gap.details)
        ));
    }
    if gap_rows.is_empty() {
        gap_rows
            .push_str("<tr><td colspan=\"3\" class=\"muted\">No blocking gaps recorded.</td></tr>");
    }

    render_review_layout(
        "Promotion Readiness Review",
        "Advisory-only cross-lane review summarizing whether governance-prep, canary, and production evidence are all present and free of unresolved gaps.",
        &format!(
            "<section class=\"card\">\
                <div class=\"meta\">\
                    <div><dt>Readiness ID</dt><dd><code>{readiness_id}</code></dd></div>\
                    <div><dt>Session ID</dt><dd>{session_link}</dd></div>\
                    <div><dt>Recommendation</dt><dd>{recommendation}</dd></div>\
                    <div><dt>Advisory Only</dt><dd>{advisory_only}</dd></div>\
                </div>\
                <form method=\"post\" action=\"/v1/operator/review/promotion-readiness/{readiness_id}/capsules\">\
                    <button type=\"submit\">Create Signed Capsule</button>\
                </form>\
                <h2>Lane Summary</h2><table><thead><tr><th>Lane</th><th>Artifacts</th><th>Bundles</th><th>Verifications</th><th>Packets</th></tr></thead><tbody>{lane_rows}</tbody></table>\
                <h2 style=\"margin-top:20px;\">Blocking Gaps</h2><table><thead><tr><th>Lane</th><th>Code</th><th>Details</th></tr></thead><tbody>{gap_rows}</tbody></table>\
            </section>",
            readiness_id = escape_html(&readiness.readiness_id),
            session_link = review_link(
                &format!("/v1/operator/review/sessions/{}", readiness.session_id),
                &readiness.session_id
            ),
            recommendation = render_status_pill(
                readiness.recommendation.as_str(),
                readiness.recommendation.as_str()
            ),
            advisory_only = readiness.advisory_only,
            lane_rows = lane_rows,
            gap_rows = gap_rows
        ),
    )
}

pub(super) fn render_review_session_handoff_page(
    handoff: &ReviewSessionMaintenanceHandoff,
) -> String {
    let mut action_rows = String::new();
    for result in &handoff.action_results {
        action_rows.push_str(&format!(
            "<tr><td><code>{bundle_id}</code></td><td>{action_link}</td><td>{status}</td><td>{verification}</td></tr>",
            bundle_id = escape_html(&result.bundle_id),
            action_link = review_link(
                &format!("/v1/operator/maintenance/actions/{}", result.action_id),
                &result.action_id
            ),
            status = render_maintenance_status_pill(result.status),
            verification = result
                .verification_id
                .as_ref()
                .map(|id| review_link(&format!("/v1/operator/review/verifications/{id}"), id))
                .unwrap_or_else(|| "<span class=\"muted\">none</span>".to_string())
        ));
    }
    if action_rows.is_empty() {
        action_rows.push_str(
            "<tr><td colspan=\"4\" class=\"muted\">No maintenance actions were recorded.</td></tr>",
        );
    }

    let selected_refs = if handoff.selected_artifact_refs.is_empty() {
        "<li class=\"muted\">No selected refs recorded.</li>".to_string()
    } else {
        handoff
            .selected_artifact_refs
            .iter()
            .map(|artifact| {
                format!(
                    "<li><code>{}:{}</code></li>",
                    artifact.kind.as_str(),
                    escape_html(&artifact.id)
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    render_review_layout(
        "Review Session Handoff",
        "Bounded maintenance handoff launched from the evidence workbench. This flow can re-verify evidence bundles but cannot bypass rollout or governance lanes.",
        &format!(
            "<section class=\"card\">\
                <div class=\"meta\">\
                    <div><dt>Handoff ID</dt><dd><code>{handoff_id}</code></dd></div>\
                    <div><dt>Session ID</dt><dd>{session_link}</dd></div>\
                    <div><dt>Status</dt><dd>{status}</dd></div>\
                    <div><dt>Reason</dt><dd>{reason}</dd></div>\
                    <div><dt>Expected Key</dt><dd>{expected_key}</dd></div>\
                    <div><dt>Derived Bundles</dt><dd>{bundle_count}</dd></div>\
                </div>\
                <h3>Selected Artifact Refs</h3><ul>{selected_refs}</ul>\
                <h3>Maintenance Actions</h3><table><thead><tr><th>Bundle</th><th>Action</th><th>Status</th><th>Verification</th></tr></thead><tbody>{action_rows}</tbody></table>\
            </section>",
            handoff_id = escape_html(&handoff.handoff_id),
            session_link = review_link(
                &format!("/v1/operator/review/sessions/{}", handoff.session_id),
                &handoff.session_id
            ),
            status = render_maintenance_status_pill(handoff.status),
            reason = escape_html(&handoff.reason),
            expected_key = handoff
                .expected_key_id
                .as_deref()
                .map(escape_html)
                .unwrap_or_else(|| "none".to_string()),
            bundle_count = handoff.derived_bundle_ids.len(),
            selected_refs = selected_refs,
            action_rows = action_rows
        ),
    )
}

pub(super) fn render_review_delegation_page(packet: &ReviewDelegationPacket) -> String {
    let mut lane_rows = String::new();
    for summary in &packet.lane_summaries {
        lane_rows.push_str(&format!(
            "<tr><td>{lane}</td><td>{artifacts}</td><td>{bundles}</td><td>{verifications}</td><td>{packets}</td></tr>",
            lane = escape_html(summary.lane.title()),
            artifacts = summary.artifact_count,
            bundles = summary.evidence_bundle_count,
            verifications = summary.verification_count,
            packets = summary.promotion_packet_count
        ));
    }
    if lane_rows.is_empty() {
        lane_rows.push_str(
            "<tr><td colspan=\"5\" class=\"muted\">No lane summaries preserved.</td></tr>",
        );
    }

    render_review_layout(
        "Review Delegation Packet",
        "Signed advisory-only continuity artifact preserving one review handoff across trust boundaries.",
        &format!(
            "<section class=\"card\">\
                <div class=\"meta\">\
                    <div><dt>Delegation ID</dt><dd><code>{delegation_id}</code></dd></div>\
                    <div><dt>Session ID</dt><dd>{session_link}</dd></div>\
                    <div><dt>Source Capsule</dt><dd>{capsule_link}</dd></div>\
                    <div><dt>Source Kind</dt><dd><code>{source_kind}</code></dd></div>\
                    <div><dt>Imported Trust</dt><dd>{imported_trust}</dd></div>\
                    <div><dt>Signer Key</dt><dd><code>{signer_key}</code></dd></div>\
                    <div><dt>Delegate Label</dt><dd>{delegate_label}</dd></div>\
                </div>\
                <p>{reason}</p>\
                <h2>Lane Summary</h2><table><thead><tr><th>Lane</th><th>Artifacts</th><th>Bundles</th><th>Verifications</th><th>Packets</th></tr></thead><tbody>{lane_rows}</tbody></table>\
            </section>",
            delegation_id = escape_html(&packet.delegation_id),
            session_link = review_link(
                &format!("/v1/operator/review/sessions/{}", packet.session_id),
                &packet.session_id
            ),
            capsule_link = review_link(
                &format!("/v1/operator/review/capsules/{}", packet.source_capsule_id),
                &packet.source_capsule_id
            ),
            source_kind = escape_html(packet.source_kind.as_str()),
            imported_trust = packet
                .imported_trust_status
                .map(|status| render_status_pill(status.as_str(), status.as_str()))
                .unwrap_or_else(|| "<span class=\"muted\">local capsule</span>".to_string()),
            signer_key = escape_html(&packet.signature.key_id),
            delegate_label = escape_html(packet.delegate_label.as_deref().unwrap_or("none")),
            reason = escape_html(&packet.reason),
            lane_rows = lane_rows
        ),
    )
}

fn render_review_home_context_card(context: &ReviewHomeContext) -> String {
    let selected_bundle_card = context
        .selected_bundle
        .as_ref()
        .map(|bundle| {
            format!(
                "<article class=\"card\">\
                    <h2>Scoped Replay</h2>\
                    <div class=\"meta\">\
                        <div><dt>Bundle</dt><dd><code>{bundle_id}</code></dd></div>\
                        <div><dt>Hunt</dt><dd><code>{hunt_id}</code></dd></div>\
                        <div><dt>Response</dt><dd><code>{response_kind}</code></dd></div>\
                    </div>\
                    <p class=\"muted\">{note}</p>\
                    <p>{replay_link}</p>\
                </article>",
                bundle_id = escape_html(&bundle.record.bundle_id),
                hunt_id = escape_html(&bundle.record.hunt_id),
                response_kind = escape_html(&bundle.preview.response_kind),
                note = escape_html(&bundle.preview.note),
                replay_link = review_link(
                    &format!("/v1/operator/replay?bundle_id={}", bundle.record.bundle_id),
                    "Open raw replay JSON"
                ),
            )
        })
        .unwrap_or_else(|| {
            "<article class=\"card\"><h2>Scoped Replay</h2><p class=\"muted\">No replay bundle matched the supplied scope.</p></article>"
                .to_string()
        });

    let rehearsal_card = context
        .latest_rehearsal_bundle
        .as_ref()
        .and_then(|bundle| bundle.bundle.rehearsal.as_ref().map(|preview| (bundle, preview)))
        .map(|(bundle, preview)| {
            let signed_proof = context
                .signed_rehearsal_bundle_id
                .as_deref()
                .map(|bundle_id| {
                    review_link(
                        &format!("/v1/operator/review/evidence/{bundle_id}"),
                        "Open signed rehearsal proof",
                    )
                })
                .unwrap_or_else(|| {
                    format!(
                        "<form method=\"post\" action=\"/v1/operator/review/rehearsals/{bundle_id}/export\">\
                            <button type=\"submit\">Export Signed Rehearsal Proof</button>\
                        </form>",
                        bundle_id = escape_html(&bundle.record.bundle_id),
                    )
                });
            format!(
                "<article class=\"card\">\
                    <h2>Latest Rehearsal Proof</h2>\
                    <p>{signed_proof}</p>\
                    {details}\
                </article>",
                signed_proof = signed_proof,
                details = render_rehearsal_preview_details(preview),
            )
        })
        .unwrap_or_else(|| {
            "<article class=\"card\"><h2>Latest Rehearsal Proof</h2><p class=\"muted\">No persisted dry-run rehearsal is available for this scope yet.</p></article>"
                .to_string()
        });

    let incident_card = context
        .incident
        .as_ref()
        .map(|incident| {
            let reconciliation = incident
                .incident
                .providence_reconciliation
                .as_ref()
                .map(|reconciliation| {
                    let (outcome_label, outcome_class) =
                        render_providence_reconciliation_outcome(reconciliation.outcome);
                    format!(
                        "<div class=\"meta\">\
                            <div><dt>Remote Incident</dt><dd><code>{remote_id}</code></dd></div>\
                            <div><dt>Outcome</dt><dd>{outcome}</dd></div>\
                            <div><dt>Remote Status</dt><dd><code>{remote_status}</code></dd></div>\
                            <div><dt>Needs Review</dt><dd>{needs_review}</dd></div>\
                        </div>\
                        <p class=\"muted\">{summary}</p>",
                        remote_id = escape_html(&reconciliation.remote_incident_id),
                        outcome = render_status_pill(outcome_label, outcome_class),
                        remote_status = escape_html(render_providence_incident_status(
                            reconciliation.remote_status
                        )),
                        needs_review = if reconciliation.needs_review { "yes" } else { "no" },
                        summary = escape_html(&reconciliation.summary),
                    )
                })
                .unwrap_or_else(|| {
                    "<p class=\"muted\">No Providence reconciliation has been recorded for this incident yet.</p>"
                        .to_string()
                });
            format!(
                "<article class=\"card\">\
                    <h2>Providence Reconciliation</h2>\
                    <div class=\"meta\">\
                        <div><dt>Incident</dt><dd><code>{incident_id}</code></dd></div>\
                        <div><dt>Summary</dt><dd>{summary}</dd></div>\
                    </div>\
                    {reconciliation}\
                    <p>{incident_link}</p>\
                </article>",
                incident_id = escape_html(&incident.record.incident_id),
                summary = escape_html(&incident.record.summary),
                reconciliation = reconciliation,
                incident_link = review_link(
                    &format!("/v1/operator/incident?incident_id={}", incident.record.incident_id),
                    "Open raw incident JSON"
                ),
            )
        })
        .unwrap_or_else(|| {
            "<article class=\"card\"><h2>Providence Reconciliation</h2><p class=\"muted\">No correlated incident matched the supplied scope.</p></article>"
                .to_string()
        });

    format!(
        "<section class=\"grid\" style=\"margin-bottom:18px;\">{selected_bundle_card}{rehearsal_card}{incident_card}</section>",
        selected_bundle_card = selected_bundle_card,
        rehearsal_card = rehearsal_card,
        incident_card = incident_card,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn render_review_home_page(
    runtime_base_url: &str,
    context: Option<&ReviewHomeContext>,
    bundles: &EvidenceBundleList,
    packets: &PromotionEvidencePacketList,
    sessions: &ReviewSessionList,
    capsules: &ReviewCapsuleList,
    imports: &ReviewCapsuleImportList,
    delegations: &ReviewDelegationPacketList,
) -> String {
    let mut bundle_rows = String::new();
    for bundle in &bundles.bundles {
        let verification = bundle
            .latest_verification_status
            .map(|status| render_status_pill(status.as_str(), status.as_str()))
            .unwrap_or_else(|| render_status_pill("unverified", "unverified"));
        bundle_rows.push_str(&format!(
            "<tr><td>{bundle_link}</td><td>{kind}</td><td>{subject}</td><td>{verification}</td></tr>",
            bundle_link = review_link(
                &format!("/v1/operator/review/evidence/{}", bundle.bundle_id),
                &bundle.bundle_id
            ),
            kind = escape_html(bundle.subject_kind.as_str()),
            subject = escape_html(&bundle.subject_id),
            verification = verification
        ));
    }

    let mut packet_rows = String::new();
    for packet in &packets.packets {
        let recommendation = if packet.ready_for_external_review {
            render_status_pill("ready_for_external_review", "ready")
        } else {
            render_status_pill("blocked", "blocked")
        };
        packet_rows.push_str(&format!(
            "<tr><td>{packet_link}</td><td>{promotion}</td><td>{recommendation}</td></tr>",
            packet_link = review_link(
                &format!("/v1/operator/review/promotion-packets/{}", packet.packet_id),
                &packet.packet_id
            ),
            promotion = escape_html(&packet.promotion_id),
            recommendation = recommendation
        ));
    }

    let mut session_rows = String::new();
    for session in &sessions.sessions {
        session_rows.push_str(&format!(
            "<tr><td>{session_link}</td><td>{title}</td><td>{artifacts}</td></tr>",
            session_link = review_link(
                &format!("/v1/operator/review/sessions/{}", session.session_id),
                &session.session_id
            ),
            title = escape_html(session.title.as_deref().unwrap_or("untitled")),
            artifacts = session.artifact_count
        ));
    }
    if session_rows.is_empty() {
        session_rows.push_str(
            "<tr><td colspan=\"3\" class=\"muted\">No review sessions created yet.</td></tr>",
        );
    }

    let mut capsule_rows = String::new();
    for capsule in &capsules.capsules {
        capsule_rows.push_str(&format!(
            "<tr><td>{capsule_link}</td><td><code>{source_kind}</code></td><td><code>{key_id}</code></td></tr>",
            capsule_link = review_link(
                &format!("/v1/operator/review/capsules/{}", capsule.capsule_id),
                &capsule.capsule_id
            ),
            source_kind = escape_html(capsule.source_kind.as_str()),
            key_id = escape_html(&capsule.signer_key_id)
        ));
    }
    if capsule_rows.is_empty() {
        capsule_rows.push_str(
            "<tr><td colspan=\"3\" class=\"muted\">No review capsules created yet.</td></tr>",
        );
    }

    let mut import_rows = String::new();
    for import in &imports.imports {
        import_rows.push_str(&format!(
            "<tr><td>{import_link}</td><td>{status}</td><td><code>{remote_key}</code></td></tr>",
            import_link = review_link(
                &format!("/v1/operator/review/capsule-imports/{}", import.import_id),
                &import.import_id
            ),
            status = render_status_pill(import.trust_status.as_str(), import.trust_status.as_str()),
            remote_key = escape_html(
                import
                    .remote_signer_key_id
                    .as_deref()
                    .unwrap_or("unavailable")
            )
        ));
    }
    if import_rows.is_empty() {
        import_rows.push_str(
            "<tr><td colspan=\"3\" class=\"muted\">No foreign review capsules imported yet.</td></tr>",
        );
    }

    let mut delegation_rows = String::new();
    for delegation in &delegations.delegations {
        delegation_rows.push_str(&format!(
            "<tr><td>{delegation_link}</td><td><code>{source_kind}</code></td><td><code>{capsule_id}</code></td></tr>",
            delegation_link = review_link(
                &format!("/v1/operator/review/delegations/{}", delegation.delegation_id),
                &delegation.delegation_id
            ),
            source_kind = escape_html(delegation.source_kind.as_str()),
            capsule_id = escape_html(&delegation.source_capsule_id)
        ));
    }
    if delegation_rows.is_empty() {
        delegation_rows.push_str(
            "<tr><td colspan=\"3\" class=\"muted\">No delegation packets created yet.</td></tr>",
        );
    }

    let demo_dashboard = render_demo_dashboard_panel(runtime_base_url);

    let scoped_context = context
        .map(render_review_home_context_card)
        .unwrap_or_default();

    render_review_layout(
        "Local Evidence Review",
        "Authenticated local evidence workbench layered on the operator API. Portable signed review capsules and imported continuity are available, but rollout and governance remain out of scope.",
        &format!(
            "{demo_dashboard}\
            {scoped_context}\
            <section class=\"grid\">\
                <article class=\"card\"><h2>Review Scope</h2><p>Use this surface to inspect signed evidence bundles, verification reports, and promotion evidence packets without reading store files directly.</p><p class=\"muted\">Authentication stays on the existing bearer-token boundary, and follow-on write actions remain on the existing maintenance or rollout paths.</p></article>\
                <article class=\"card\"><h2>Import Foreign Capsule</h2>\
                    <form class=\"toolbar\" method=\"post\" action=\"/v1/operator/review/capsule-imports\">\
                        <label>Source path<input type=\"text\" name=\"source_path\" placeholder=\"/tmp/review_capsule.json\"></label>\
                        <label>Expected key ID<input type=\"text\" name=\"expected_key_id\" placeholder=\"optional local trust anchor\"></label>\
                        <button type=\"submit\">Import Capsule</button>\
                    </form>\
                    <p class=\"muted\">Imported capsules stay advisory-only and preserve remote signer lineage, local trust status, and related stable refs.</p>\
                </article>\
                <article class=\"card\"><h2>Quick Links</h2><ul>\
                    <li>{sessions_link}</li><li>{evidence}</li><li>{packets}</li><li>{json}</li>\
                </ul></article>\
            </section>\
            <section class=\"grid\" style=\"margin-top:18px;\">\
                <article class=\"card\"><h2>Recent Evidence Bundles</h2><table><thead><tr><th>Bundle</th><th>Kind</th><th>Subject</th><th>Verification</th></tr></thead><tbody>{bundle_rows}</tbody></table></article>\
                <article class=\"card\"><h2>Recent Promotion Packets</h2><table><thead><tr><th>Packet</th><th>Promotion</th><th>Recommendation</th></tr></thead><tbody>{packet_rows}</tbody></table></article>\
            </section>\
            <section class=\"grid\" style=\"margin-top:18px;\">\
                <article class=\"card\"><h2>Recent Review Sessions</h2><table><thead><tr><th>Session</th><th>Title</th><th>Artifacts</th></tr></thead><tbody>{session_rows}</tbody></table></article>\
                <article class=\"card\"><h2>Portable Capsules</h2><table><thead><tr><th>Capsule</th><th>Source</th><th>Signer Key</th></tr></thead><tbody>{capsule_rows}</tbody></table></article>\
            </section>\
            <section class=\"grid\" style=\"margin-top:18px;\">\
                <article class=\"card\"><h2>Imported Capsules</h2><table><thead><tr><th>Import</th><th>Trust</th><th>Remote Key</th></tr></thead><tbody>{import_rows}</tbody></table></article>\
                <article class=\"card\"><h2>Delegation Packets</h2><table><thead><tr><th>Delegation</th><th>Source</th><th>Capsule</th></tr></thead><tbody>{delegation_rows}</tbody></table></article>\
            </section>",
            sessions_link = review_link("/v1/operator/review/sessions", "Open review sessions"),
            evidence = review_link("/v1/operator/review/evidence", "Browse signed evidence"),
            packets = review_link(
                "/v1/operator/review/promotion-packets",
                "Browse promotion evidence packets"
            ),
            json = review_link(
                "/v1/operator/evidence/bundles",
                "Open raw evidence JSON API"
            ),
            demo_dashboard = demo_dashboard,
            scoped_context = scoped_context,
            bundle_rows = bundle_rows,
            packet_rows = packet_rows,
            session_rows = session_rows,
            capsule_rows = capsule_rows,
            import_rows = import_rows,
            delegation_rows = delegation_rows
        ),
    )
}

pub(super) fn render_review_evidence_list_page(
    list: &EvidenceBundleList,
    verification_status: Option<ReviewEvidenceVerificationFilter>,
) -> String {
    let mut rows = String::new();
    for bundle in &list.bundles {
        let verification = bundle
            .latest_verification_status
            .map(|status| render_status_pill(status.as_str(), status.as_str()))
            .unwrap_or_else(|| render_status_pill("unverified", "unverified"));
        let verification_link = bundle
            .latest_verification_id
            .as_ref()
            .map(|id| review_link(&format!("/v1/operator/review/verifications/{id}"), id))
            .unwrap_or_else(|| "<span class=\"muted\">none</span>".to_string());
        rows.push_str(&format!(
            "<tr><td>{bundle_link}</td><td>{kind}</td><td>{subject}</td><td>{verification}</td><td>{verification_link}</td></tr>",
            bundle_link = review_link(
                &format!("/v1/operator/review/evidence/{}", bundle.bundle_id),
                &bundle.bundle_id
            ),
            kind = escape_html(bundle.subject_kind.as_str()),
            subject = escape_html(&bundle.subject_id),
            verification = verification,
            verification_link = verification_link
        ));
    }

    render_review_layout(
        "Evidence Inspection",
        "Browse signed evidence bundles by subject kind and latest verification state.",
        &format!(
            "<section class=\"card\">\
                <form class=\"toolbar\" method=\"get\" action=\"/v1/operator/review/evidence\">\
                    <label>Subject kind<select name=\"subject_kind\">{subject_options}</select></label>\
                    <label>Verification<select name=\"verification_status\">{verification_options}</select></label>\
                    <label>Limit<input type=\"number\" min=\"1\" name=\"limit\" value=\"{limit}\"></label>\
                    <button type=\"submit\">Apply Filters</button>\
                </form>\
                <p class=\"muted\">Showing {count} evidence bundles from the authenticated evidence store.</p>\
                <table><thead><tr><th>Bundle</th><th>Subject Kind</th><th>Subject ID</th><th>Latest Verification</th><th>Verification Page</th></tr></thead><tbody>{rows}</tbody></table>\
            </section>",
            subject_options = render_subject_kind_options(list.subject_kind),
            verification_options = render_verification_filter_options(verification_status),
            limit = list.total_count.max(1),
            count = list.total_count,
            rows = rows
        ),
    )
}

pub(super) fn render_review_evidence_bundle_page(
    bundle: &EvidenceBundle,
    latest_verification_status: Option<EvidenceVerificationStatus>,
    latest_verification: Option<&EvidenceVerificationReport>,
) -> String {
    let verification_badge = latest_verification_status
        .map(|status| render_status_pill(status.as_str(), status.as_str()))
        .unwrap_or_else(|| render_status_pill("unverified", "unverified"));
    let verification_link = latest_verification
        .map(|report| {
            review_link(
                &format!(
                    "/v1/operator/review/verifications/{}",
                    report.verification_id
                ),
                &report.verification_id,
            )
        })
        .unwrap_or_else(|| "<span class=\"muted\">none</span>".to_string());

    let subject_target = subject_api_path(bundle.subject.kind, &bundle.subject.stable_id)
        .map(|href| review_link(&href, "Open related raw API artifact"))
        .unwrap_or_else(|| {
            "<span class=\"muted\">No raw API route for this subject kind yet</span>".to_string()
        });

    let mut related_refs = String::new();
    for related in &bundle.subject.related_refs {
        related_refs.push_str(&format!(
            "<li>{kind}: {link}</li>",
            kind = escape_html(&related.kind),
            link = render_related_ref_link(&related.kind, &related.id)
        ));
    }
    if related_refs.is_empty() {
        related_refs.push_str("<li class=\"muted\">No related references recorded.</li>");
    }

    let mut receipt_refs = String::new();
    for reference in &bundle.subject.receipt_chain_refs {
        receipt_refs.push_str(&format!("<li><code>{}</code></li>", escape_html(reference)));
    }
    if receipt_refs.is_empty() {
        receipt_refs.push_str("<li class=\"muted\">No receipt references recorded.</li>");
    }

    render_review_layout(
        "Evidence Bundle Detail",
        "Signed artifact metadata first, canonical payload second. This page stays read-only and points back to the authenticated JSON API when needed.",
        &format!(
            "<section class=\"card\">\
                <div class=\"meta\">\
                    <div><dt>Bundle ID</dt><dd><code>{bundle_id}</code></dd></div>\
                    <div><dt>Subject</dt><dd>{kind} <code>{subject_id}</code></dd></div>\
                    <div><dt>Latest Verification</dt><dd>{verification_badge}</dd></div>\
                    <div><dt>Signer</dt><dd>{signer} (<code>{key_id}</code>)</dd></div>\
                    <div><dt>Payload SHA-256</dt><dd><code>{payload_sha}</code></dd></div>\
                    <div><dt>Related Artifact</dt><dd>{subject_target}</dd></div>\
                </div>\
                <p><strong>Verification page:</strong> {verification_link}</p>\
                <h3>Related References</h3><ul>{related_refs}</ul>\
                <h3>Receipt Chain References</h3><ul>{receipt_refs}</ul>\
                <details><summary>Canonical payload JSON</summary><pre>{payload}</pre></details>\
                <details><summary>Raw JSON API</summary><p>{raw_link}</p></details>\
            </section>",
            bundle_id = escape_html(&bundle.bundle_id),
            kind = escape_html(bundle.subject.kind.as_str()),
            subject_id = escape_html(&bundle.subject.stable_id),
            verification_badge = verification_badge,
            signer = escape_html(&bundle.signature.signer_id),
            key_id = escape_html(&bundle.signature.key_id),
            payload_sha = escape_html(&bundle.payload_sha256),
            subject_target = subject_target,
            verification_link = verification_link,
            related_refs = related_refs,
            receipt_refs = receipt_refs,
            payload = escape_html(&bundle.canonical_payload),
            raw_link = review_link(
                &format!("/v1/operator/evidence/bundles/{}", bundle.bundle_id),
                "Open the raw JSON bundle response"
            )
        ),
    )
}

pub(super) fn render_review_evidence_verification_page(
    report: &EvidenceVerificationReport,
) -> String {
    let mut checks = String::new();
    for check in &report.checks {
        checks.push_str(&format!(
            "<tr><td>{name}</td><td>{status}</td><td>{details}</td></tr>",
            name = escape_html(&check.name),
            status = if check.passed {
                render_status_pill("passed", "passed")
            } else {
                render_status_pill("failed", "failed")
            },
            details = escape_html(&check.details)
        ));
    }
    if checks.is_empty() {
        checks.push_str(
            "<tr><td colspan=\"3\" class=\"muted\">No verification checks recorded.</td></tr>",
        );
    }

    render_review_layout(
        "Evidence Verification Detail",
        "Verification reports show the exact integrity checks applied to one signed evidence bundle.",
        &format!(
            "<section class=\"card\">\
                <div class=\"meta\">\
                    <div><dt>Verification ID</dt><dd><code>{verification_id}</code></dd></div>\
                    <div><dt>Bundle</dt><dd>{bundle_link}</dd></div>\
                    <div><dt>Status</dt><dd>{status}</dd></div>\
                    <div><dt>Signer</dt><dd>{signer} (<code>{key_id}</code>)</dd></div>\
                    <div><dt>Expected Key</dt><dd>{expected_key}</dd></div>\
                </div>\
                <table><thead><tr><th>Check</th><th>Status</th><th>Details</th></tr></thead><tbody>{checks}</tbody></table>\
                <details><summary>Raw JSON API</summary><p>{raw_link}</p></details>\
            </section>",
            verification_id = escape_html(&report.verification_id),
            bundle_link = review_link(
                &format!("/v1/operator/review/evidence/{}", report.bundle_id),
                &report.bundle_id
            ),
            status = render_status_pill(report.status.as_str(), report.status.as_str()),
            signer = escape_html(&report.signer_id),
            key_id = escape_html(&report.signer_key_id),
            expected_key = report
                .expected_key_id
                .as_deref()
                .map(escape_html)
                .unwrap_or_else(|| "none".to_string()),
            checks = checks,
            raw_link = review_link(
                &format!(
                    "/v1/operator/evidence/verifications/{}",
                    report.verification_id
                ),
                "Open the raw JSON verification response"
            )
        ),
    )
}

pub(super) fn render_review_promotion_packet_list_page(
    list: &PromotionEvidencePacketList,
    recommendation: Option<PromotionEvidenceRecommendation>,
) -> String {
    let mut rows = String::new();
    for packet in &list.packets {
        let pill = if packet.ready_for_external_review {
            render_status_pill("ready_for_external_review", "ready")
        } else {
            render_status_pill("blocked", "blocked")
        };
        rows.push_str(&format!(
            "<tr><td>{packet_link}</td><td>{promotion_id}</td><td>{recommendation}</td></tr>",
            packet_link = review_link(
                &format!("/v1/operator/review/promotion-packets/{}", packet.packet_id),
                &packet.packet_id
            ),
            promotion_id = escape_html(&packet.promotion_id),
            recommendation = pill
        ));
    }

    render_review_layout(
        "Promotion Evidence Review",
        "Promotion evidence packets stay advisory. This review flow is for operator understanding, not approval or deployment.",
        &format!(
            "<section class=\"card\">\
                <form class=\"toolbar\" method=\"get\" action=\"/v1/operator/review/promotion-packets\">\
                    <label>Recommendation<select name=\"recommendation\">{recommendation_options}</select></label>\
                    <label>Limit<input type=\"number\" min=\"1\" name=\"limit\" value=\"{limit}\"></label>\
                    <button type=\"submit\">Apply Filters</button>\
                </form>\
                <table><thead><tr><th>Packet</th><th>Promotion ID</th><th>Recommendation</th></tr></thead><tbody>{rows}</tbody></table>\
            </section>",
            recommendation_options = render_promotion_recommendation_options(recommendation),
            limit = list.total_count.max(1),
            rows = rows
        ),
    )
}

pub(super) fn render_review_promotion_packet_page(packet: &PromotionEvidencePacket) -> String {
    let mut attachment_rows = String::new();
    for attachment in &packet.supporting_evidence {
        let bundle_link = attachment
            .bundle_id
            .as_ref()
            .map(|id| review_link(&format!("/v1/operator/review/evidence/{id}"), id))
            .unwrap_or_else(|| "<span class=\"muted\">none</span>".to_string());
        let verification_link = attachment
            .verification_id
            .as_ref()
            .map(|id| review_link(&format!("/v1/operator/review/verifications/{id}"), id))
            .unwrap_or_else(|| "<span class=\"muted\">none</span>".to_string());
        let status = attachment
            .verification_status
            .map(|status| render_status_pill(status.as_str(), status.as_str()))
            .unwrap_or_else(|| render_status_pill("unverified", "unverified"));
        attachment_rows.push_str(&format!(
            "<tr><td>{kind}</td><td><code>{subject_id}</code></td><td>{bundle_link}</td><td>{verification_link}</td><td>{status}</td><td>{details}</td></tr>",
            kind = escape_html(attachment.subject_kind.as_str()),
            subject_id = escape_html(&attachment.subject_id),
            bundle_link = bundle_link,
            verification_link = verification_link,
            status = status,
            details = escape_html(&attachment.details)
        ));
    }
    if attachment_rows.is_empty() {
        attachment_rows.push_str(
            "<tr><td colspan=\"6\" class=\"muted\">No supporting evidence attached.</td></tr>",
        );
    }

    let mut blocking_reasons = String::new();
    for reason in &packet.blocking_reasons {
        blocking_reasons.push_str(&format!(
            "<li><strong>{name}</strong>: {details}</li>",
            name = escape_html(&reason.name),
            details = escape_html(&reason.details)
        ));
    }
    if blocking_reasons.is_empty() {
        blocking_reasons.push_str("<li class=\"muted\">No blocking reasons recorded.</li>");
    }

    let recommendation = render_status_pill(
        packet.recommendation.as_str(),
        match packet.recommendation {
            PromotionEvidenceRecommendation::ReadyForExternalReview => "ready",
            PromotionEvidenceRecommendation::Blocked => "blocked",
        },
    );

    render_review_layout(
        "Promotion Evidence Packet Detail",
        "Promotion evidence packets summarize rollout outcome and supporting signed evidence. They remain advisory and do not authorize rollout.",
        &format!(
            "<section class=\"card\">\
                <div class=\"meta\">\
                    <div><dt>Packet ID</dt><dd><code>{packet_id}</code></dd></div>\
                    <div><dt>Promotion ID</dt><dd><code>{promotion_id}</code></dd></div>\
                    <div><dt>Recommendation</dt><dd>{recommendation}</dd></div>\
                    <div><dt>Promotion Status</dt><dd>{promotion_status}</dd></div>\
                    <div><dt>Promoted Strategy</dt><dd><code>{promoted_strategy}</code></dd></div>\
                    <div><dt>Fallback Strategy</dt><dd><code>{fallback_strategy}</code></dd></div>\
                    <div><dt>Canary Run</dt><dd><code>{canary_run}</code></dd></div>\
                    <div><dt>Verification ID</dt><dd><code>{verification_id}</code></dd></div>\
                    <div><dt>Shadow ID</dt><dd><code>{shadow_id}</code></dd></div>\
                    <div><dt>Advisory Only</dt><dd>{advisory_only}</dd></div>\
                </div>\
                <p class=\"muted\">Follow-on rollout or maintenance actions still go through the existing authenticated APIs and audit trails. This page is read-only by design.</p>\
                <h3>Blocking Reasons</h3><ul>{blocking_reasons}</ul>\
                <h3>Supporting Evidence</h3><table><thead><tr><th>Kind</th><th>Subject ID</th><th>Bundle</th><th>Verification</th><th>Status</th><th>Details</th></tr></thead><tbody>{attachment_rows}</tbody></table>\
                <details><summary>Raw JSON API</summary><p>{raw_link}</p></details>\
            </section>",
            packet_id = escape_html(&packet.packet_id),
            promotion_id = escape_html(&packet.promotion_id),
            recommendation = recommendation,
            promotion_status =
                escape_html(&format!("{:?}", packet.promotion_status).to_lowercase()),
            promoted_strategy = escape_html(&packet.promoted_strategy_id),
            fallback_strategy = escape_html(&packet.fallback_strategy_id),
            canary_run = escape_html(&packet.canary_run_id),
            verification_id = escape_html(&packet.verification_id),
            shadow_id = escape_html(&packet.shadow_id),
            advisory_only = if packet.advisory_only { "yes" } else { "no" },
            blocking_reasons = blocking_reasons,
            attachment_rows = attachment_rows,
            raw_link = review_link(
                &format!(
                    "/v1/operator/evidence/promotion-packets/{}",
                    packet.packet_id
                ),
                "Open the raw JSON promotion evidence packet"
            )
        ),
    )
}
