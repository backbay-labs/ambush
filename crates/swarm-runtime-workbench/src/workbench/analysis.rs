//! Derived views over a review session: resolving selected artifact refs to
//! evidence bundles, deduplicating evidence lookups, and building the lane
//! summaries, unresolved gaps and advisory readiness recommendation.

use super::types::{
    ReviewArtifactRef, ReviewArtifactRefKind, ReviewLane, ReviewLaneGap, ReviewLaneSummary,
    ReviewPromotionReadinessRecommendation, ReviewSessionResolved, ReviewWorkbenchError,
};
use std::collections::BTreeSet;
use swarm_runtime::evidence::{
    EvidenceBundleLookup, EvidenceSubjectKind, EvidenceVerificationLookup,
    EvidenceVerificationStatus, OperatorEvidenceReadService, PromotionEvidencePacketLookup,
};

pub(super) fn ensure_selected_refs_belong_to_session(
    session_refs: &[ReviewArtifactRef],
    selected_refs: &[ReviewArtifactRef],
) -> Result<(), ReviewWorkbenchError> {
    let allowed = session_refs
        .iter()
        .map(|artifact| format!("{}:{}", artifact.kind.as_str(), artifact.id))
        .collect::<BTreeSet<_>>();
    for artifact in selected_refs {
        let key = format!("{}:{}", artifact.kind.as_str(), artifact.id);
        if !allowed.contains(&key) {
            return Err(ReviewWorkbenchError::InvalidRequest(format!(
                "selected artifact `{}` does not belong to the review session",
                key
            )));
        }
    }
    Ok(())
}

pub(super) fn derive_bundle_ids(
    resolved: &ReviewSessionResolved,
    selected_refs: &[ReviewArtifactRef],
) -> Result<Vec<String>, ReviewWorkbenchError> {
    let mut bundle_ids = BTreeSet::new();
    for artifact in selected_refs {
        match artifact.kind {
            ReviewArtifactRefKind::EvidenceBundle => {
                bundle_ids.insert(artifact.id.clone());
            }
            ReviewArtifactRefKind::EvidenceVerification => {
                let lookup = resolved
                    .evidence_verifications
                    .iter()
                    .find(|lookup| lookup.report.verification_id == artifact.id)
                    .ok_or_else(|| {
                        ReviewWorkbenchError::InvalidRequest(format!(
                            "verification `{}` is not available in the review session",
                            artifact.id
                        ))
                    })?;
                bundle_ids.insert(lookup.report.bundle_id.clone());
            }
            ReviewArtifactRefKind::PromotionEvidencePacket => {
                let lookup = resolved
                    .promotion_packets
                    .iter()
                    .find(|lookup| lookup.packet.packet_id == artifact.id)
                    .ok_or_else(|| {
                        ReviewWorkbenchError::InvalidRequest(format!(
                            "promotion evidence packet `{}` is not available in the review session",
                            artifact.id
                        ))
                    })?;
                for attachment in &lookup.packet.supporting_evidence {
                    if let Some(bundle_id) = attachment.bundle_id.as_ref() {
                        bundle_ids.insert(bundle_id.clone());
                    }
                }
            }
            ReviewArtifactRefKind::PromotionReview => {
                let bundle_lookup = resolved
                    .evidence_bundles
                    .iter()
                    .find(|lookup| {
                        lookup.record.subject_kind == EvidenceSubjectKind::PromotionReview
                            && lookup.record.subject_id == artifact.id
                    })
                    .ok_or_else(|| {
                        ReviewWorkbenchError::InvalidRequest(format!(
                            "promotion review `{}` is not available in the review session",
                            artifact.id
                        ))
                    })?;
                bundle_ids.insert(bundle_lookup.record.bundle_id.clone());
            }
            ReviewArtifactRefKind::CanaryRun => {
                let bundle_lookup = resolved
                    .evidence_bundles
                    .iter()
                    .find(|lookup| {
                        lookup.record.subject_kind == EvidenceSubjectKind::CanaryRun
                            && lookup.record.subject_id == artifact.id
                    })
                    .ok_or_else(|| {
                        ReviewWorkbenchError::InvalidRequest(format!(
                            "canary run `{}` is not available in the review session",
                            artifact.id
                        ))
                    })?;
                bundle_ids.insert(bundle_lookup.record.bundle_id.clone());
            }
            ReviewArtifactRefKind::ProductionPromotion => {
                let bundle_lookup = resolved
                    .evidence_bundles
                    .iter()
                    .find(|lookup| {
                        lookup.record.subject_kind == EvidenceSubjectKind::ProductionPromotion
                            && lookup.record.subject_id == artifact.id
                    })
                    .ok_or_else(|| {
                        ReviewWorkbenchError::InvalidRequest(format!(
                            "production promotion `{}` is not available in the review session",
                            artifact.id
                        ))
                    })?;
                bundle_ids.insert(bundle_lookup.record.bundle_id.clone());
            }
        }
    }
    Ok(bundle_ids.into_iter().collect())
}

pub(super) fn push_unique_bundle(
    target: &mut Vec<EvidenceBundleLookup>,
    lookup: EvidenceBundleLookup,
) {
    if !target
        .iter()
        .any(|existing| existing.record.bundle_id == lookup.record.bundle_id)
    {
        target.push(lookup);
    }
}

pub(super) fn push_unique_verification(
    target: &mut Vec<EvidenceVerificationLookup>,
    lookup: EvidenceVerificationLookup,
) {
    if !target
        .iter()
        .any(|existing| existing.report.verification_id == lookup.report.verification_id)
    {
        target.push(lookup);
    }
}

pub(super) fn push_unique_packet(
    target: &mut Vec<PromotionEvidencePacketLookup>,
    lookup: PromotionEvidencePacketLookup,
) {
    if !target
        .iter()
        .any(|existing| existing.packet.packet_id == lookup.packet.packet_id)
    {
        target.push(lookup);
    }
}

pub(super) fn attach_bundle_dependencies(
    evidence: &OperatorEvidenceReadService,
    bundle_lookup: &EvidenceBundleLookup,
    evidence_bundles: &mut Vec<EvidenceBundleLookup>,
    evidence_verifications: &mut Vec<EvidenceVerificationLookup>,
) -> Result<(), ReviewWorkbenchError> {
    push_unique_bundle(evidence_bundles, bundle_lookup.clone());
    if let Some(verification_id) = bundle_lookup.record.latest_verification_id.as_deref()
        && let Some(verification_lookup) = evidence.load_verification(verification_id)?
    {
        push_unique_verification(evidence_verifications, verification_lookup);
    }
    Ok(())
}

fn classify_subject_lane(subject_kind: EvidenceSubjectKind) -> Option<ReviewLane> {
    match subject_kind {
        EvidenceSubjectKind::PromotionReview
        | EvidenceSubjectKind::DetectorVerification
        | EvidenceSubjectKind::StrategyShadow => Some(ReviewLane::GovernancePrep),
        EvidenceSubjectKind::CanaryRun => Some(ReviewLane::Canary),
        EvidenceSubjectKind::ProductionPromotion => Some(ReviewLane::Production),
        _ => None,
    }
}

pub(super) fn build_lane_summaries(
    evidence_bundles: &[EvidenceBundleLookup],
    evidence_verifications: &[EvidenceVerificationLookup],
    promotion_packets: &[PromotionEvidencePacketLookup],
) -> Vec<ReviewLaneSummary> {
    let mut by_lane = std::collections::BTreeMap::new();
    for lane in [
        ReviewLane::GovernancePrep,
        ReviewLane::Canary,
        ReviewLane::Production,
    ] {
        by_lane.insert(
            lane,
            ReviewLaneSummary {
                lane,
                artifact_count: 0,
                evidence_bundle_count: 0,
                verification_count: 0,
                promotion_packet_count: 0,
                latest_source_created_at_ms: None,
                latest_verified_at_ms: None,
                subject_refs: Vec::new(),
            },
        );
    }

    for bundle in evidence_bundles {
        if let Some(lane) = classify_subject_lane(bundle.record.subject_kind) {
            let Some(summary) = by_lane.get_mut(&lane) else {
                continue;
            };
            summary.artifact_count += 1;
            summary.evidence_bundle_count += 1;
            summary.latest_source_created_at_ms = Some(
                summary
                    .latest_source_created_at_ms
                    .map_or(bundle.record.source_created_at_ms, |current| {
                        current.max(bundle.record.source_created_at_ms)
                    }),
            );
            let subject_ref = format!(
                "{}:{}",
                bundle.record.subject_kind.as_str(),
                bundle.record.subject_id
            );
            if !summary.subject_refs.contains(&subject_ref) {
                summary.subject_refs.push(subject_ref);
            }
        }
    }

    for verification in evidence_verifications {
        if let Some(lane) = classify_subject_lane(verification.report.subject_kind) {
            let Some(summary) = by_lane.get_mut(&lane) else {
                continue;
            };
            summary.artifact_count += 1;
            summary.verification_count += 1;
            summary.latest_verified_at_ms = Some(
                summary
                    .latest_verified_at_ms
                    .map_or(verification.report.verified_at_ms, |current| {
                        current.max(verification.report.verified_at_ms)
                    }),
            );
        }
    }

    for packet in promotion_packets {
        let Some(summary) = by_lane.get_mut(&ReviewLane::Production) else {
            continue;
        };
        summary.artifact_count += 1;
        summary.promotion_packet_count += 1;
        let subject_ref = format!("promotion_evidence_packet:{}", packet.packet.promotion_id);
        if !summary.subject_refs.contains(&subject_ref) {
            summary.subject_refs.push(subject_ref);
        }
    }

    by_lane.into_values().collect()
}

pub(super) fn collect_lane_gaps(
    lane_summaries: &[ReviewLaneSummary],
    evidence_bundles: &[EvidenceBundleLookup],
    promotion_packets: &[PromotionEvidencePacketLookup],
) -> Vec<ReviewLaneGap> {
    let mut gaps = Vec::new();
    for lane in [
        ReviewLane::GovernancePrep,
        ReviewLane::Canary,
        ReviewLane::Production,
    ] {
        let Some(summary) = lane_summaries.iter().find(|summary| summary.lane == lane) else {
            gaps.push(ReviewLaneGap {
                lane: Some(lane),
                code: "lane_missing".to_string(),
                details: format!(
                    "{} lane summary is missing from the review session",
                    lane.title()
                ),
                references: Vec::new(),
            });
            continue;
        };
        if summary.artifact_count == 0 {
            gaps.push(ReviewLaneGap {
                lane: Some(lane),
                code: "lane_missing".to_string(),
                details: format!(
                    "{} lane evidence is missing from the review session",
                    lane.title()
                ),
                references: Vec::new(),
            });
        }
    }

    for bundle in evidence_bundles {
        if let Some(lane) = classify_subject_lane(bundle.record.subject_kind)
            && bundle.record.latest_verification_status != Some(EvidenceVerificationStatus::Passed)
        {
            gaps.push(ReviewLaneGap {
                lane: Some(lane),
                code: "bundle_unverified".to_string(),
                details: format!(
                    "{} evidence `{}` is missing a passing verification result",
                    lane.title(),
                    bundle.record.bundle_id
                ),
                references: vec![bundle.record.bundle_id.clone()],
            });
        }
    }

    for packet in promotion_packets {
        for reason in &packet.packet.blocking_reasons {
            gaps.push(ReviewLaneGap {
                lane: Some(ReviewLane::Production),
                code: reason.name.clone(),
                details: reason.details.clone(),
                references: reason.references.clone(),
            });
        }
    }

    if promotion_packets.is_empty()
        && evidence_bundles
            .iter()
            .any(|bundle| bundle.record.subject_kind == EvidenceSubjectKind::ProductionPromotion)
    {
        gaps.push(ReviewLaneGap {
            lane: Some(ReviewLane::Production),
            code: "promotion_evidence_packet_missing".to_string(),
            details:
                "production lane is present but no promotion evidence packet was included or derived"
                    .to_string(),
            references: Vec::new(),
        });
    }

    gaps
}

pub(super) fn promotion_readiness_recommendation(
    resolved: &ReviewSessionResolved,
) -> ReviewPromotionReadinessRecommendation {
    let has_all_lanes = [
        ReviewLane::GovernancePrep,
        ReviewLane::Canary,
        ReviewLane::Production,
    ]
    .iter()
    .all(|lane| {
        resolved
            .lane_summaries
            .iter()
            .find(|summary| &summary.lane == lane)
            .map(|summary| summary.artifact_count > 0)
            .unwrap_or(false)
    });
    if has_all_lanes && resolved.unresolved_gaps.is_empty() {
        ReviewPromotionReadinessRecommendation::ReadyForAdvisoryPromotionReview
    } else {
        ReviewPromotionReadinessRecommendation::Blocked
    }
}
