use super::analysis::{
    attach_bundle_dependencies, build_lane_summaries, collect_lane_gaps, derive_bundle_ids,
    ensure_selected_refs_belong_to_session, promotion_readiness_recommendation, push_unique_bundle,
    push_unique_packet, push_unique_verification,
};
use super::helpers::{normalize_artifact_refs, normalize_optional_text, now_ms, now_unix_nanos};
use super::signing::{
    collect_related_refs_from_export, collect_related_refs_from_resolved,
    empty_signature_placeholder, resolve_trusted_key_id, review_capsule_signature_statement_bytes,
    review_delegation_signature_statement_bytes, signature_from_detached, signature_to_detached,
};
use super::stores::{
    FileReviewCapsuleImportStore, FileReviewCapsuleStore, FileReviewDelegationPacketStore,
    FileReviewSessionExportStore, FileReviewSessionMaintenanceHandoffStore,
    FileReviewSessionPromotionReadinessStore, FileReviewSessionStore,
};
use super::types::{
    ReviewArtifactRef, ReviewArtifactRefKind, ReviewCapsule, ReviewCapsuleBuildRequest,
    ReviewCapsuleImport, ReviewCapsuleImportList, ReviewCapsuleImportLookup,
    ReviewCapsuleImportRequest, ReviewCapsuleImportTrustStatus, ReviewCapsuleList,
    ReviewCapsuleLookup, ReviewCapsulePayload, ReviewCapsuleReadinessPayload,
    ReviewCapsuleSourceKind, ReviewDelegationCreateRequest, ReviewDelegationPacket,
    ReviewDelegationPacketList, ReviewDelegationPacketLookup, ReviewDelegationPayload,
    ReviewDelegationSourceKind, ReviewSessionCreateRequest, ReviewSessionExport,
    ReviewSessionExportBundle, ReviewSessionExportList, ReviewSessionExportLookup,
    ReviewSessionExportPromotionPacket, ReviewSessionExportVerification, ReviewSessionList,
    ReviewSessionLookup, ReviewSessionMaintenanceActionResult, ReviewSessionMaintenanceHandoff,
    ReviewSessionMaintenanceHandoffList, ReviewSessionMaintenanceHandoffLookup,
    ReviewSessionPromotionReadiness, ReviewSessionPromotionReadinessList,
    ReviewSessionPromotionReadinessLookup, ReviewSessionReport, ReviewSessionResolved,
    ReviewSessionReverifyRequest, ReviewWorkbenchError,
};
use std::fs;
use std::path::PathBuf;
use swarm_core::config::OperatorSurfacePaths;
use swarm_crypto::{
    Ed25519Signer, canonical_json_string, normalize_canonical_json, sha256_hex,
    verify_detached_signature,
};
use swarm_evolution::evidence::{
    EvidenceSubjectKind, EvidenceVerificationCheck, OperatorEvidenceReadService,
};
use swarm_evolution::operator_maintenance::{
    OperatorMaintenanceRequest, OperatorMaintenanceService, OperatorMaintenanceStatus,
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
