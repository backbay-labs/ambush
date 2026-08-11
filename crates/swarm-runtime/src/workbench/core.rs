use super::helpers::{
    maintenance_status_label, normalize_artifact_refs, normalize_optional_text, now_ms,
    now_unix_nanos,
};
use super::stores::{
    FileReviewCapsuleImportStore, FileReviewCapsuleStore, FileReviewDelegationPacketStore,
    FileReviewSessionExportStore, FileReviewSessionMaintenanceHandoffStore,
    FileReviewSessionPromotionReadinessStore, FileReviewSessionStore,
};
use super::types::*;
use crate::evidence::{
    EvidenceBundleLookup, EvidenceRelatedRef, EvidenceSignature, EvidenceSubjectKind,
    EvidenceVerificationCheck, EvidenceVerificationLookup, EvidenceVerificationStatus,
    OperatorEvidenceReadService, PromotionEvidencePacketLookup,
};
use crate::operator_http::OperatorSurfacePaths;
use crate::operator_maintenance::{
    OperatorMaintenanceRequest, OperatorMaintenanceService, OperatorMaintenanceStatus,
};
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use swarm_crypto::{
    CryptoError, Ed25519Signer, canonical_json_bytes, canonical_json_string,
    normalize_canonical_json, sha256_hex, verify_detached_signature,
};

/// Repo-owned workbench harness above signed evidence and maintenance audit flows.
#[derive(Debug, Clone)]
pub struct DefaultReviewWorkbenchHarness {
    evidence: OperatorEvidenceReadService,
    maintenance: OperatorMaintenanceService,
    signer_id: String,
    signing_key_env: String,
    session_store: FileReviewSessionStore,
    export_store: FileReviewSessionExportStore,
    capsule_store: FileReviewCapsuleStore,
    capsule_import_store: FileReviewCapsuleImportStore,
    delegation_store: FileReviewDelegationPacketStore,
    readiness_store: FileReviewSessionPromotionReadinessStore,
    handoff_store: FileReviewSessionMaintenanceHandoffStore,
}

impl DefaultReviewWorkbenchHarness {
    pub fn from_paths(paths: &OperatorSurfacePaths) -> Result<Self, ReviewWorkbenchError> {
        Ok(Self {
            signer_id: paths.evidence_signer_id.clone(),
            signing_key_env: paths.evidence_signing_key_env.clone(),
            evidence: OperatorEvidenceReadService::from_store_paths(
                &paths.evidence_results_dir,
                &paths.evidence_verification_results_dir,
                &paths.promotion_evidence_results_dir,
            )?,
            maintenance: OperatorMaintenanceService::from_paths(paths)?,
            session_store: FileReviewSessionStore::open(&paths.review_session_results_dir)?,
            export_store: FileReviewSessionExportStore::open(
                &paths.review_session_export_results_dir,
            )?,
            capsule_store: FileReviewCapsuleStore::open(&paths.review_capsule_results_dir)?,
            capsule_import_store: FileReviewCapsuleImportStore::open(
                &paths.review_capsule_import_results_dir,
            )?,
            delegation_store: FileReviewDelegationPacketStore::open(
                &paths.review_delegation_results_dir,
            )?,
            readiness_store: FileReviewSessionPromotionReadinessStore::open(
                &paths.review_session_readiness_results_dir,
            )?,
            handoff_store: FileReviewSessionMaintenanceHandoffStore::open(
                &paths.review_session_handoff_results_dir,
            )?,
        })
    }

    pub fn create_session(
        &self,
        request: ReviewSessionCreateRequest,
    ) -> Result<ReviewSessionLookup, ReviewWorkbenchError> {
        let artifact_refs = normalize_artifact_refs(request.artifact_refs);
        if artifact_refs.is_empty() {
            return Err(ReviewWorkbenchError::InvalidRequest(
                "review sessions require at least one artifact ref".to_string(),
            ));
        }
        for artifact in &artifact_refs {
            self.ensure_artifact_exists(artifact)?;
        }
        let report = ReviewSessionReport {
            session_id: format!("review_session:{}", now_unix_nanos()),
            title: normalize_optional_text(request.title),
            notes: normalize_optional_text(request.notes),
            created_at_ms: now_ms(),
            artifact_refs,
        };
        self.session_store.persist(&report).map_err(Into::into)
    }

    pub fn load_session(
        &self,
        session_id: &str,
    ) -> Result<Option<ReviewSessionLookup>, ReviewWorkbenchError> {
        self.session_store.load(session_id).map_err(Into::into)
    }

    pub fn list_sessions(&self) -> Result<ReviewSessionList, ReviewWorkbenchError> {
        self.session_store.list().map_err(Into::into)
    }

    pub fn resolve_session(
        &self,
        session_id: &str,
    ) -> Result<ReviewSessionResolved, ReviewWorkbenchError> {
        let session = self.load_session(session_id)?.ok_or_else(|| {
            ReviewWorkbenchError::SessionNotFound {
                session_id: session_id.to_string(),
            }
        })?;
        self.resolve_lookup(session)
    }

    pub fn export_session(
        &self,
        session_id: &str,
    ) -> Result<ReviewSessionExportLookup, ReviewWorkbenchError> {
        let resolved = self.resolve_session(session_id)?;
        let export = ReviewSessionExport {
            export_id: format!("review_session_export:{}", now_unix_nanos()),
            session_id: resolved.session.report.session_id.clone(),
            created_at_ms: now_ms(),
            title: resolved.session.report.title.clone(),
            notes: resolved.session.report.notes.clone(),
            artifact_refs: resolved.session.report.artifact_refs.clone(),
            lane_summaries: resolved.lane_summaries.clone(),
            unresolved_gaps: resolved.unresolved_gaps.clone(),
            evidence_bundles: resolved
                .evidence_bundles
                .iter()
                .map(|lookup| ReviewSessionExportBundle {
                    bundle_id: lookup.record.bundle_id.clone(),
                    subject_kind: lookup.record.subject_kind,
                    subject_id: lookup.record.subject_id.clone(),
                    payload_sha256: lookup.record.payload_sha256.clone(),
                    signer_id: lookup.record.signer_id.clone(),
                    signer_key_id: lookup.record.signer_key_id.clone(),
                    latest_verification_id: lookup.record.latest_verification_id.clone(),
                    latest_verification_status: lookup.record.latest_verification_status,
                    related_refs: lookup.bundle.subject.related_refs.clone(),
                })
                .collect(),
            evidence_verifications: resolved
                .evidence_verifications
                .iter()
                .map(|lookup| ReviewSessionExportVerification {
                    verification_id: lookup.report.verification_id.clone(),
                    bundle_id: lookup.report.bundle_id.clone(),
                    subject_kind: lookup.report.subject_kind,
                    subject_id: lookup.report.subject_id.clone(),
                    status: lookup.report.status,
                    signer_id: lookup.report.signer_id.clone(),
                    signer_key_id: lookup.report.signer_key_id.clone(),
                    checks: lookup.report.checks.clone(),
                })
                .collect(),
            promotion_packets: resolved
                .promotion_packets
                .iter()
                .map(|lookup| ReviewSessionExportPromotionPacket {
                    packet_id: lookup.packet.packet_id.clone(),
                    promotion_id: lookup.packet.promotion_id.clone(),
                    recommendation: lookup.packet.recommendation,
                    promoted_strategy_id: lookup.packet.promoted_strategy_id.clone(),
                    fallback_strategy_id: lookup.packet.fallback_strategy_id.clone(),
                    canary_run_id: lookup.packet.canary_run_id.clone(),
                    verification_id: lookup.packet.verification_id.clone(),
                    shadow_id: lookup.packet.shadow_id.clone(),
                    supporting_evidence: lookup.packet.supporting_evidence.clone(),
                    blocking_reasons: lookup.packet.blocking_reasons.clone(),
                })
                .collect(),
        };
        self.export_store.persist(&export).map_err(Into::into)
    }

    pub fn load_export(
        &self,
        export_id: &str,
    ) -> Result<Option<ReviewSessionExportLookup>, ReviewWorkbenchError> {
        self.export_store.load(export_id).map_err(Into::into)
    }

    pub fn list_exports(
        &self,
        session_id: Option<&str>,
    ) -> Result<ReviewSessionExportList, ReviewWorkbenchError> {
        self.export_store.list(session_id).map_err(Into::into)
    }

    pub fn create_capsule_from_session(
        &self,
        session_id: &str,
    ) -> Result<ReviewCapsuleLookup, ReviewWorkbenchError> {
        let export_lookup = self.export_session(session_id)?;
        let related_refs = collect_related_refs_from_export(&export_lookup.export);
        let payload = ReviewCapsulePayload::SessionExport(export_lookup.export.clone());
        let capsule = self.build_capsule(ReviewCapsuleBuildRequest {
            session_id: export_lookup.export.session_id.clone(),
            title: export_lookup.export.title.clone(),
            notes: export_lookup.export.notes.clone(),
            source_kind: ReviewCapsuleSourceKind::SessionExport,
            source_id: export_lookup.export.export_id.clone(),
            artifact_refs: export_lookup.export.artifact_refs.clone(),
            lane_summaries: export_lookup.export.lane_summaries.clone(),
            unresolved_gaps: export_lookup.export.unresolved_gaps.clone(),
            related_refs,
            payload,
        })?;
        self.capsule_store.persist(&capsule).map_err(Into::into)
    }

    pub fn create_capsule_from_readiness(
        &self,
        readiness_id: &str,
    ) -> Result<ReviewCapsuleLookup, ReviewWorkbenchError> {
        let readiness = self
            .load_promotion_readiness(readiness_id)?
            .ok_or_else(|| ReviewWorkbenchError::ReadinessNotFound {
                readiness_id: readiness_id.to_string(),
            })?;
        let session = self
            .load_session(&readiness.report.session_id)?
            .ok_or_else(|| ReviewWorkbenchError::SessionNotFound {
                session_id: readiness.report.session_id.clone(),
            })?;
        let resolved = self.resolve_lookup(session.clone())?;
        let related_refs = collect_related_refs_from_resolved(&resolved);
        let payload = ReviewCapsulePayload::PromotionReadiness(ReviewCapsuleReadinessPayload {
            readiness: readiness.report.clone(),
            title: session.report.title.clone(),
            notes: session.report.notes.clone(),
            artifact_refs: session.report.artifact_refs.clone(),
            related_refs: related_refs.clone(),
        });
        let capsule = self.build_capsule(ReviewCapsuleBuildRequest {
            session_id: readiness.report.session_id.clone(),
            title: session.report.title.clone(),
            notes: session.report.notes.clone(),
            source_kind: ReviewCapsuleSourceKind::PromotionReadiness,
            source_id: readiness.report.readiness_id.clone(),
            artifact_refs: session.report.artifact_refs.clone(),
            lane_summaries: readiness.report.lane_summaries.clone(),
            unresolved_gaps: readiness.report.unresolved_gaps.clone(),
            related_refs,
            payload,
        })?;
        self.capsule_store.persist(&capsule).map_err(Into::into)
    }

    pub fn load_capsule(
        &self,
        capsule_id: &str,
    ) -> Result<Option<ReviewCapsuleLookup>, ReviewWorkbenchError> {
        self.capsule_store.load(capsule_id).map_err(Into::into)
    }

    pub fn list_capsules(
        &self,
        session_id: Option<&str>,
    ) -> Result<ReviewCapsuleList, ReviewWorkbenchError> {
        self.capsule_store.list(session_id).map_err(Into::into)
    }

    pub fn import_capsule(
        &self,
        request: ReviewCapsuleImportRequest,
    ) -> Result<ReviewCapsuleImportLookup, ReviewWorkbenchError> {
        let source_path = PathBuf::from(request.source_path.trim());
        if source_path.as_os_str().is_empty() {
            return Err(ReviewWorkbenchError::InvalidRequest(
                "review capsule import requires a non-empty source path".to_string(),
            ));
        }
        let raw_document = fs::read_to_string(&source_path).map_err(|source| {
            ReviewWorkbenchError::ReadSource {
                path: source_path.clone(),
                source,
            }
        })?;
        let imported_at_ms = now_ms();
        let import_id = format!("review_capsule_import:{}", now_unix_nanos());
        let mut checks = Vec::new();

        let normalized_document = match normalize_canonical_json(&raw_document) {
            Ok(normalized) => {
                checks.push(EvidenceVerificationCheck {
                    name: "document_parse".to_string(),
                    passed: true,
                    details: "review capsule JSON parsed and normalized cleanly".to_string(),
                });
                Some(normalized)
            }
            Err(error) => {
                checks.push(EvidenceVerificationCheck {
                    name: "document_parse".to_string(),
                    passed: false,
                    details: error.to_string(),
                });
                None
            }
        };

        let capsule = normalized_document
            .as_deref()
            .and_then(|normalized| serde_json::from_str::<ReviewCapsule>(normalized).ok());
        if capsule.is_none() {
            checks.push(EvidenceVerificationCheck {
                name: "capsule_decode".to_string(),
                passed: false,
                details: "normalized JSON did not decode into a portable review capsule"
                    .to_string(),
            });
        }

        let mut trust_status = ReviewCapsuleImportTrustStatus::Invalid;
        let mut source_capsule_id = None;
        let mut source_kind = None;
        let mut source_id = None;
        let mut session_id = None;
        let mut remote_signer_id = None;
        let mut remote_signer_key_id = None;
        let trusted_key_id =
            resolve_trusted_key_id(&self.signing_key_env, request.expected_key_id.as_deref());

        if let Some(capsule) = capsule.as_ref() {
            source_capsule_id = Some(capsule.capsule_id.clone());
            source_kind = Some(capsule.source_kind);
            source_id = Some(capsule.source_id.clone());
            session_id = Some(capsule.session_id.clone());
            remote_signer_id = Some(capsule.signature.signer_id.clone());
            remote_signer_key_id = Some(capsule.signature.key_id.clone());

            let normalized_payload = normalize_canonical_json(&capsule.canonical_payload);
            let normalized_payload = match normalized_payload {
                Ok(payload) => {
                    let passed = payload == capsule.canonical_payload;
                    checks.push(EvidenceVerificationCheck {
                        name: "canonical_payload".to_string(),
                        passed,
                        details: if passed {
                            "capsule payload bytes normalized cleanly".to_string()
                        } else {
                            "capsule payload bytes changed after normalization".to_string()
                        },
                    });
                    Some(payload)
                }
                Err(error) => {
                    checks.push(EvidenceVerificationCheck {
                        name: "canonical_payload".to_string(),
                        passed: false,
                        details: error.to_string(),
                    });
                    None
                }
            };

            let payload_hash = normalized_payload
                .as_deref()
                .map(|payload| sha256_hex(payload.as_bytes()));
            let hash_passed = payload_hash
                .as_deref()
                .map(|value| value == capsule.payload_sha256)
                .unwrap_or(false);
            checks.push(EvidenceVerificationCheck {
                name: "payload_sha256".to_string(),
                passed: hash_passed,
                details: if hash_passed {
                    "payload hash matches canonical payload bytes".to_string()
                } else {
                    format!(
                        "expected `{}`, recalculated `{}`",
                        capsule.payload_sha256,
                        payload_hash.unwrap_or_else(|| "unavailable".to_string())
                    )
                },
            });

            let signature_passed = review_capsule_signature_statement_bytes(capsule)
                .ok()
                .and_then(|statement| {
                    verify_detached_signature(
                        &statement,
                        &signature_to_detached(&capsule.signature),
                    )
                    .ok()
                })
                .is_some();
            checks.push(EvidenceVerificationCheck {
                name: "detached_signature".to_string(),
                passed: signature_passed,
                details: if signature_passed {
                    "signature verified against signed review capsule statement".to_string()
                } else {
                    "signature verification failed".to_string()
                },
            });

            let trust_match = trusted_key_id
                .as_deref()
                .map(|trusted_key| capsule.signature.key_id == trusted_key)
                .unwrap_or(false);
            checks.push(EvidenceVerificationCheck {
                name: "local_trust".to_string(),
                passed: trust_match,
                details: if let Some(trusted_key_id) = trusted_key_id.as_deref() {
                    if trust_match {
                        format!("matched trusted local signer key id `{trusted_key_id}`")
                    } else {
                        format!(
                            "trusted local signer key id `{trusted_key_id}` does not match remote `{}`",
                            capsule.signature.key_id
                        )
                    }
                } else {
                    "no local trusted signer key configured; capsule remains untrusted".to_string()
                },
            });

            trust_status = if signature_passed && hash_passed && normalized_payload.is_some() {
                if trust_match {
                    ReviewCapsuleImportTrustStatus::Trusted
                } else {
                    ReviewCapsuleImportTrustStatus::SignatureValidUntrusted
                }
            } else {
                ReviewCapsuleImportTrustStatus::Invalid
            };
        }

        let import = ReviewCapsuleImport {
            import_id,
            imported_at_ms,
            source_path: source_path.display().to_string(),
            source_capsule_id,
            source_kind,
            source_id,
            session_id,
            remote_signer_id,
            remote_signer_key_id,
            trusted_key_id,
            trust_status,
            checks,
            raw_document,
            capsule,
        };
        self.capsule_import_store
            .persist(&import)
            .map_err(Into::into)
    }

    pub fn load_capsule_import(
        &self,
        import_id: &str,
    ) -> Result<Option<ReviewCapsuleImportLookup>, ReviewWorkbenchError> {
        self.capsule_import_store
            .load(import_id)
            .map_err(Into::into)
    }

    pub fn list_capsule_imports(&self) -> Result<ReviewCapsuleImportList, ReviewWorkbenchError> {
        self.capsule_import_store.list().map_err(Into::into)
    }

    pub fn create_delegation_packet(
        &self,
        request: ReviewDelegationCreateRequest,
    ) -> Result<ReviewDelegationPacketLookup, ReviewWorkbenchError> {
        let reason = normalize_optional_text(Some(request.reason.clone())).ok_or_else(|| {
            ReviewWorkbenchError::InvalidRequest(
                "review delegation packets require a non-empty reason".to_string(),
            )
        })?;
        let delegate_label = normalize_optional_text(request.delegate_label);
        let source_count =
            usize::from(request.capsule_id.is_some()) + usize::from(request.import_id.is_some());
        if source_count != 1 {
            return Err(ReviewWorkbenchError::InvalidRequest(
                "review delegation packets require exactly one of capsule_id or import_id"
                    .to_string(),
            ));
        }

        let (
            source_kind,
            source_capsule_id,
            source_import_id,
            source_signer_id,
            source_signer_key_id,
            imported_trust_status,
            session_id,
            artifact_refs,
            lane_summaries,
            unresolved_gaps,
            related_refs,
        ) = if let Some(capsule_id) = request.capsule_id.as_deref() {
            let capsule = self.load_capsule(capsule_id)?.ok_or_else(|| {
                ReviewWorkbenchError::CapsuleNotFound {
                    capsule_id: capsule_id.to_string(),
                }
            })?;
            (
                ReviewDelegationSourceKind::LocalCapsule,
                capsule.capsule.capsule_id.clone(),
                None,
                capsule.capsule.signature.signer_id.clone(),
                capsule.capsule.signature.key_id.clone(),
                None,
                capsule.capsule.session_id.clone(),
                capsule.capsule.artifact_refs.clone(),
                capsule.capsule.lane_summaries.clone(),
                capsule.capsule.unresolved_gaps.clone(),
                capsule.capsule.related_refs.clone(),
            )
        } else {
            let import_id = request.import_id.as_deref().ok_or_else(|| {
                ReviewWorkbenchError::InvalidRequest(
                    "review delegation packets require exactly one of capsule_id or import_id"
                        .to_string(),
                )
            })?;
            let imported = self.load_capsule_import(import_id)?.ok_or_else(|| {
                ReviewWorkbenchError::CapsuleImportNotFound {
                    import_id: import_id.to_string(),
                }
            })?;
            if imported.import.trust_status == ReviewCapsuleImportTrustStatus::Invalid {
                return Err(ReviewWorkbenchError::InvalidRequest(format!(
                    "imported review capsule `{import_id}` is invalid and cannot be delegated"
                )));
            }
            let capsule = imported.import.capsule.as_ref().ok_or_else(|| {
                ReviewWorkbenchError::InvalidRequest(format!(
                    "imported review capsule `{import_id}` does not contain a decoded capsule"
                ))
            })?;
            (
                ReviewDelegationSourceKind::ImportedCapsule,
                capsule.capsule_id.clone(),
                Some(imported.import.import_id.clone()),
                capsule.signature.signer_id.clone(),
                capsule.signature.key_id.clone(),
                Some(imported.import.trust_status),
                capsule.session_id.clone(),
                capsule.artifact_refs.clone(),
                capsule.lane_summaries.clone(),
                capsule.unresolved_gaps.clone(),
                capsule.related_refs.clone(),
            )
        };

        let payload = ReviewDelegationPayload {
            session_id: session_id.clone(),
            source_capsule_id: source_capsule_id.clone(),
            source_import_id: source_import_id.clone(),
            reason: reason.clone(),
            delegate_label: delegate_label.clone(),
            imported_trust_status,
            advisory_only: true,
            artifact_refs: artifact_refs.clone(),
            lane_summaries: lane_summaries.clone(),
            unresolved_gaps: unresolved_gaps.clone(),
            related_refs: related_refs.clone(),
        };
        let canonical_payload = canonical_json_string(&payload)?;
        let payload_sha256 = sha256_hex(canonical_payload.as_bytes());
        let signer = self.load_signer()?;
        let packet = ReviewDelegationPacket {
            delegation_id: format!("review_delegation:{}", now_unix_nanos()),
            schema_version: "v1".to_string(),
            created_at_ms: now_ms(),
            session_id,
            source_kind,
            source_capsule_id,
            source_import_id,
            source_signer_id,
            source_signer_key_id,
            imported_trust_status,
            reason,
            delegate_label,
            advisory_only: true,
            artifact_refs,
            lane_summaries,
            unresolved_gaps,
            related_refs,
            payload_sha256,
            canonical_payload,
            signature: empty_signature_placeholder(),
        };
        let signature = signer.sign(&review_delegation_signature_statement_bytes(&packet)?);
        let packet = ReviewDelegationPacket {
            signature: signature_from_detached(self.signer_id.clone(), signature),
            ..packet
        };
        self.delegation_store.persist(&packet).map_err(Into::into)
    }

    pub fn load_delegation(
        &self,
        delegation_id: &str,
    ) -> Result<Option<ReviewDelegationPacketLookup>, ReviewWorkbenchError> {
        self.delegation_store
            .load(delegation_id)
            .map_err(Into::into)
    }

    pub fn list_delegations(
        &self,
        session_id: Option<&str>,
    ) -> Result<ReviewDelegationPacketList, ReviewWorkbenchError> {
        self.delegation_store.list(session_id).map_err(Into::into)
    }

    pub fn create_promotion_readiness_review(
        &self,
        session_id: &str,
    ) -> Result<ReviewSessionPromotionReadinessLookup, ReviewWorkbenchError> {
        let resolved = self.resolve_session(session_id)?;
        let report = ReviewSessionPromotionReadiness {
            readiness_id: format!("review_session_readiness:{}", now_unix_nanos()),
            session_id: resolved.session.report.session_id.clone(),
            created_at_ms: now_ms(),
            lane_summaries: resolved.lane_summaries.clone(),
            unresolved_gaps: resolved.unresolved_gaps.clone(),
            recommendation: promotion_readiness_recommendation(&resolved),
            advisory_only: true,
        };
        self.readiness_store.persist(&report).map_err(Into::into)
    }

    pub fn load_promotion_readiness(
        &self,
        readiness_id: &str,
    ) -> Result<Option<ReviewSessionPromotionReadinessLookup>, ReviewWorkbenchError> {
        self.readiness_store.load(readiness_id).map_err(Into::into)
    }

    pub fn list_promotion_readiness(
        &self,
        session_id: Option<&str>,
    ) -> Result<ReviewSessionPromotionReadinessList, ReviewWorkbenchError> {
        self.readiness_store.list(session_id).map_err(Into::into)
    }

    pub fn create_reverify_handoff(
        &self,
        actor: &str,
        request: ReviewSessionReverifyRequest,
    ) -> Result<ReviewSessionMaintenanceHandoffLookup, ReviewWorkbenchError> {
        let resolved = self.resolve_session(&request.session_id)?;
        let selected_artifact_refs = if request.selected_artifact_refs.is_empty() {
            resolved.session.report.artifact_refs.clone()
        } else {
            normalize_artifact_refs(request.selected_artifact_refs)
        };
        if normalize_optional_text(Some(request.reason.clone())).is_none() {
            return Err(ReviewWorkbenchError::InvalidRequest(
                "review-driven maintenance handoffs require a non-empty reason".to_string(),
            ));
        }
        ensure_selected_refs_belong_to_session(
            &resolved.session.report.artifact_refs,
            &selected_artifact_refs,
        )?;
        let bundle_ids = derive_bundle_ids(&resolved, &selected_artifact_refs)?;
        if bundle_ids.is_empty() {
            return Err(ReviewWorkbenchError::InvalidRequest(
                "selected artifacts did not resolve to any evidence bundles".to_string(),
            ));
        }

        let mut action_results = Vec::new();
        for bundle_id in &bundle_ids {
            let execution = self.maintenance.execute(
                actor,
                OperatorMaintenanceRequest::ReverifyEvidenceBundle {
                    bundle_id: bundle_id.clone(),
                    expected_key_id: request.expected_key_id.clone(),
                    reason: request.reason.clone(),
                },
            )?;
            let lookup = execution.lookup();
            let verification_id = lookup
                .record
                .artifacts
                .iter()
                .find(|artifact| artifact.kind == "evidence_verification")
                .map(|artifact| artifact.id.clone());
            action_results.push(ReviewSessionMaintenanceActionResult {
                bundle_id: bundle_id.clone(),
                action_id: lookup.record.action_id.clone(),
                status: lookup.record.status,
                verification_id,
            });
        }

        let applied_count = action_results
            .iter()
            .filter(|result| result.status == OperatorMaintenanceStatus::Applied)
            .count();
        let blocked_count = action_results
            .iter()
            .filter(|result| result.status == OperatorMaintenanceStatus::Blocked)
            .count();
        let failed_count = action_results
            .iter()
            .filter(|result| result.status == OperatorMaintenanceStatus::Failed)
            .count();
        let status = if failed_count > 0 {
            OperatorMaintenanceStatus::Failed
        } else if blocked_count > 0 {
            OperatorMaintenanceStatus::Blocked
        } else {
            OperatorMaintenanceStatus::Applied
        };
        let summary = format!(
            "re-verified {} evidence bundle(s) from review session `{}` (applied={}, blocked={}, failed={})",
            bundle_ids.len(),
            resolved.session.report.session_id,
            applied_count,
            blocked_count,
            failed_count
        );
        let handoff = ReviewSessionMaintenanceHandoff {
            handoff_id: format!("review_handoff:{}", now_unix_nanos()),
            session_id: resolved.session.report.session_id.clone(),
            created_at_ms: now_ms(),
            selected_artifact_refs,
            derived_bundle_ids: bundle_ids,
            expected_key_id: request.expected_key_id,
            reason: request.reason,
            status,
            summary,
            action_results,
        };
        self.handoff_store.persist(&handoff).map_err(Into::into)
    }

    pub fn load_handoff(
        &self,
        handoff_id: &str,
    ) -> Result<Option<ReviewSessionMaintenanceHandoffLookup>, ReviewWorkbenchError> {
        self.handoff_store.load(handoff_id).map_err(Into::into)
    }

    pub fn list_handoffs(
        &self,
        session_id: Option<&str>,
    ) -> Result<ReviewSessionMaintenanceHandoffList, ReviewWorkbenchError> {
        self.handoff_store.list(session_id).map_err(Into::into)
    }

    fn build_capsule(
        &self,
        request: ReviewCapsuleBuildRequest,
    ) -> Result<ReviewCapsule, ReviewWorkbenchError> {
        let canonical_payload = canonical_json_string(&request.payload)?;
        let payload_sha256 = sha256_hex(canonical_payload.as_bytes());
        let signer = self.load_signer()?;
        let capsule = ReviewCapsule {
            capsule_id: format!("review_capsule:{}", now_unix_nanos()),
            schema_version: "v1".to_string(),
            created_at_ms: now_ms(),
            session_id: request.session_id,
            title: request.title,
            notes: request.notes,
            source_kind: request.source_kind,
            source_id: request.source_id,
            artifact_refs: request.artifact_refs,
            lane_summaries: request.lane_summaries,
            unresolved_gaps: request.unresolved_gaps,
            related_refs: request.related_refs,
            advisory_only: true,
            payload_sha256,
            canonical_payload,
            signature: empty_signature_placeholder(),
        };
        let signature = signer.sign(&review_capsule_signature_statement_bytes(&capsule)?);
        Ok(ReviewCapsule {
            signature: signature_from_detached(self.signer_id.clone(), signature),
            ..capsule
        })
    }

    fn load_signer(&self) -> Result<Ed25519Signer, ReviewWorkbenchError> {
        let secret_material = std::env::var(&self.signing_key_env)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| ReviewWorkbenchError::MissingSigningKey {
                env_name: self.signing_key_env.clone(),
            })?;
        Ok(Ed25519Signer::from_secret_material(&secret_material))
    }

    fn resolve_lookup(
        &self,
        session: ReviewSessionLookup,
    ) -> Result<ReviewSessionResolved, ReviewWorkbenchError> {
        let mut evidence_bundles = Vec::new();
        let mut evidence_verifications = Vec::new();
        let mut promotion_packets = Vec::new();

        for artifact in &session.report.artifact_refs {
            match artifact.kind {
                ReviewArtifactRefKind::EvidenceBundle => {
                    let lookup = self.evidence.load_bundle(&artifact.id)?.ok_or_else(|| {
                        ReviewWorkbenchError::InvalidRequest(format!(
                            "evidence bundle `{}` no longer exists",
                            artifact.id
                        ))
                    })?;
                    push_unique_bundle(&mut evidence_bundles, lookup);
                }
                ReviewArtifactRefKind::EvidenceVerification => {
                    let lookup =
                        self.evidence
                            .load_verification(&artifact.id)?
                            .ok_or_else(|| {
                                ReviewWorkbenchError::InvalidRequest(format!(
                                    "evidence verification `{}` no longer exists",
                                    artifact.id
                                ))
                            })?;
                    if let Some(bundle_lookup) =
                        self.evidence.load_bundle(&lookup.report.bundle_id)?
                    {
                        push_unique_bundle(&mut evidence_bundles, bundle_lookup);
                    }
                    push_unique_verification(&mut evidence_verifications, lookup);
                }
                ReviewArtifactRefKind::PromotionEvidencePacket => {
                    let lookup = self
                        .evidence
                        .load_promotion_evidence_packet(&artifact.id)?
                        .ok_or_else(|| {
                            ReviewWorkbenchError::InvalidRequest(format!(
                                "promotion evidence packet `{}` no longer exists",
                                artifact.id
                            ))
                        })?;
                    push_unique_packet(&mut promotion_packets, lookup);
                }
                ReviewArtifactRefKind::PromotionReview => {
                    let bundle_lookup = self
                        .evidence
                        .find_bundle_by_subject(EvidenceSubjectKind::PromotionReview, &artifact.id)?
                        .ok_or_else(|| {
                            ReviewWorkbenchError::InvalidRequest(format!(
                                "promotion review `{}` does not have exported evidence",
                                artifact.id
                            ))
                        })?;
                    attach_bundle_dependencies(
                        &self.evidence,
                        &bundle_lookup,
                        &mut evidence_bundles,
                        &mut evidence_verifications,
                    )?;
                }
                ReviewArtifactRefKind::CanaryRun => {
                    let bundle_lookup = self
                        .evidence
                        .find_bundle_by_subject(EvidenceSubjectKind::CanaryRun, &artifact.id)?
                        .ok_or_else(|| {
                            ReviewWorkbenchError::InvalidRequest(format!(
                                "canary run `{}` does not have exported evidence",
                                artifact.id
                            ))
                        })?;
                    attach_bundle_dependencies(
                        &self.evidence,
                        &bundle_lookup,
                        &mut evidence_bundles,
                        &mut evidence_verifications,
                    )?;
                }
                ReviewArtifactRefKind::ProductionPromotion => {
                    let bundle_lookup = self
                        .evidence
                        .find_bundle_by_subject(
                            EvidenceSubjectKind::ProductionPromotion,
                            &artifact.id,
                        )?
                        .ok_or_else(|| {
                            ReviewWorkbenchError::InvalidRequest(format!(
                                "production promotion `{}` does not have exported evidence",
                                artifact.id
                            ))
                        })?;
                    attach_bundle_dependencies(
                        &self.evidence,
                        &bundle_lookup,
                        &mut evidence_bundles,
                        &mut evidence_verifications,
                    )?;
                    if let Some(packet_lookup) = self.evidence.load_promotion_evidence_packet(
                        &format!("promotion_evidence:{}", artifact.id),
                    )? {
                        push_unique_packet(&mut promotion_packets, packet_lookup);
                    }
                }
            }
        }

        let lane_summaries = build_lane_summaries(
            &evidence_bundles,
            &evidence_verifications,
            &promotion_packets,
        );
        let unresolved_gaps =
            collect_lane_gaps(&lane_summaries, &evidence_bundles, &promotion_packets);

        Ok(ReviewSessionResolved {
            session,
            evidence_bundles,
            evidence_verifications,
            promotion_packets,
            lane_summaries,
            unresolved_gaps,
        })
    }

    fn ensure_artifact_exists(
        &self,
        artifact: &ReviewArtifactRef,
    ) -> Result<(), ReviewWorkbenchError> {
        let exists = match artifact.kind {
            ReviewArtifactRefKind::EvidenceBundle => {
                self.evidence.load_bundle(&artifact.id)?.is_some()
            }
            ReviewArtifactRefKind::EvidenceVerification => {
                self.evidence.load_verification(&artifact.id)?.is_some()
            }
            ReviewArtifactRefKind::PromotionEvidencePacket => self
                .evidence
                .load_promotion_evidence_packet(&artifact.id)?
                .is_some(),
            ReviewArtifactRefKind::PromotionReview => self
                .evidence
                .find_bundle_by_subject(EvidenceSubjectKind::PromotionReview, &artifact.id)?
                .is_some(),
            ReviewArtifactRefKind::CanaryRun => self
                .evidence
                .find_bundle_by_subject(EvidenceSubjectKind::CanaryRun, &artifact.id)?
                .is_some(),
            ReviewArtifactRefKind::ProductionPromotion => self
                .evidence
                .find_bundle_by_subject(EvidenceSubjectKind::ProductionPromotion, &artifact.id)?
                .is_some(),
        };
        if exists {
            Ok(())
        } else {
            Err(ReviewWorkbenchError::InvalidRequest(format!(
                "{} `{}` was not found",
                artifact.kind, artifact.id
            )))
        }
    }
}

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
fn ensure_selected_refs_belong_to_session(
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

fn derive_bundle_ids(
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

fn push_unique_bundle(target: &mut Vec<EvidenceBundleLookup>, lookup: EvidenceBundleLookup) {
    if !target
        .iter()
        .any(|existing| existing.record.bundle_id == lookup.record.bundle_id)
    {
        target.push(lookup);
    }
}

fn push_unique_verification(
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

fn push_unique_packet(
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

fn attach_bundle_dependencies(
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

fn build_lane_summaries(
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

fn collect_lane_gaps(
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

fn promotion_readiness_recommendation(
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

#[derive(Debug, Serialize)]
struct ReviewCapsuleSignatureStatement<'a> {
    capsule_id: &'a str,
    schema_version: &'a str,
    created_at_ms: i64,
    session_id: &'a str,
    source_kind: &'a str,
    source_id: &'a str,
    payload_sha256: &'a str,
}

#[derive(Debug, Serialize)]
struct ReviewDelegationSignatureStatement<'a> {
    delegation_id: &'a str,
    schema_version: &'a str,
    created_at_ms: i64,
    session_id: &'a str,
    source_kind: &'a str,
    source_capsule_id: &'a str,
    source_import_id: Option<&'a str>,
    payload_sha256: &'a str,
}

fn collect_related_refs_from_export(export: &ReviewSessionExport) -> Vec<EvidenceRelatedRef> {
    let mut refs = Vec::new();
    for bundle in &export.evidence_bundles {
        push_unique_related_ref(
            &mut refs,
            bundle.subject_kind.as_str(),
            bundle.subject_id.clone(),
        );
        push_unique_related_ref(&mut refs, "evidence_bundle", bundle.bundle_id.clone());
        if let Some(verification_id) = bundle.latest_verification_id.as_ref() {
            push_unique_related_ref(&mut refs, "evidence_verification", verification_id.clone());
        }
        for related in &bundle.related_refs {
            push_unique_related_ref(&mut refs, &related.kind, related.id.clone());
        }
    }
    for packet in &export.promotion_packets {
        push_unique_related_ref(
            &mut refs,
            "promotion_evidence_packet",
            packet.packet_id.clone(),
        );
        push_unique_related_ref(
            &mut refs,
            "production_promotion",
            packet.promotion_id.clone(),
        );
        push_unique_related_ref(&mut refs, "canary_run", packet.canary_run_id.clone());
        push_unique_related_ref(
            &mut refs,
            "evidence_verification",
            packet.verification_id.clone(),
        );
        push_unique_related_ref(&mut refs, "strategy_shadow", packet.shadow_id.clone());
    }
    refs
}

fn collect_related_refs_from_resolved(resolved: &ReviewSessionResolved) -> Vec<EvidenceRelatedRef> {
    let mut refs = Vec::new();
    for bundle in &resolved.evidence_bundles {
        push_unique_related_ref(
            &mut refs,
            bundle.record.subject_kind.as_str(),
            bundle.record.subject_id.clone(),
        );
        push_unique_related_ref(
            &mut refs,
            "evidence_bundle",
            bundle.record.bundle_id.clone(),
        );
        if let Some(verification_id) = bundle.record.latest_verification_id.as_ref() {
            push_unique_related_ref(&mut refs, "evidence_verification", verification_id.clone());
        }
        for related in &bundle.bundle.subject.related_refs {
            push_unique_related_ref(&mut refs, &related.kind, related.id.clone());
        }
    }
    for packet in &resolved.promotion_packets {
        push_unique_related_ref(
            &mut refs,
            "promotion_evidence_packet",
            packet.packet.packet_id.clone(),
        );
        push_unique_related_ref(
            &mut refs,
            "production_promotion",
            packet.packet.promotion_id.clone(),
        );
    }
    refs
}

fn push_unique_related_ref(
    target: &mut Vec<EvidenceRelatedRef>,
    kind: impl Into<String>,
    id: impl Into<String>,
) {
    let kind = kind.into();
    let id = id.into();
    if kind.trim().is_empty() || id.trim().is_empty() {
        return;
    }
    if !target
        .iter()
        .any(|existing| existing.kind == kind && existing.id == id)
    {
        target.push(EvidenceRelatedRef { kind, id });
    }
}

fn review_capsule_signature_statement_bytes(
    capsule: &ReviewCapsule,
) -> Result<Vec<u8>, CryptoError> {
    canonical_json_bytes(&ReviewCapsuleSignatureStatement {
        capsule_id: &capsule.capsule_id,
        schema_version: &capsule.schema_version,
        created_at_ms: capsule.created_at_ms,
        session_id: &capsule.session_id,
        source_kind: capsule.source_kind.as_str(),
        source_id: &capsule.source_id,
        payload_sha256: &capsule.payload_sha256,
    })
}

fn review_delegation_signature_statement_bytes(
    packet: &ReviewDelegationPacket,
) -> Result<Vec<u8>, CryptoError> {
    canonical_json_bytes(&ReviewDelegationSignatureStatement {
        delegation_id: &packet.delegation_id,
        schema_version: &packet.schema_version,
        created_at_ms: packet.created_at_ms,
        session_id: &packet.session_id,
        source_kind: packet.source_kind.as_str(),
        source_capsule_id: &packet.source_capsule_id,
        source_import_id: packet.source_import_id.as_deref(),
        payload_sha256: &packet.payload_sha256,
    })
}

fn signature_from_detached(
    signer_id: String,
    detached: swarm_crypto::DetachedSignature,
) -> EvidenceSignature {
    EvidenceSignature {
        signer_id,
        algorithm: detached.algorithm,
        key_id: detached.key_id,
        public_key_hex: detached.public_key_hex,
        signature_hex: detached.signature_hex,
    }
}

fn signature_to_detached(signature: &EvidenceSignature) -> swarm_crypto::DetachedSignature {
    swarm_crypto::DetachedSignature {
        algorithm: signature.algorithm.clone(),
        key_id: signature.key_id.clone(),
        public_key_hex: signature.public_key_hex.clone(),
        signature_hex: signature.signature_hex.clone(),
    }
}

fn resolve_trusted_key_id(signing_key_env: &str, expected_key_id: Option<&str>) -> Option<String> {
    if let Some(expected_key_id) = expected_key_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(expected_key_id.to_string());
    }
    std::env::var(signing_key_env)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|secret_material| Ed25519Signer::from_secret_material(&secret_material))
        .map(|signer| signer.key_id().to_string())
}

fn empty_signature_placeholder() -> EvidenceSignature {
    EvidenceSignature {
        signer_id: String::new(),
        algorithm: String::new(),
        key_id: String::new(),
        public_key_hex: String::new(),
        signature_hex: String::new(),
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{ReviewSessionList, ReviewSessionRecord, render_review_session_list};

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
