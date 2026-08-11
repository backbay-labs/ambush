use super::*;

pub struct RuntimeService<P, E> {
    pub config: SwarmConfig,
    pub runtime: Arc<SwarmRuntime<P, E>>,
    metrics: RuntimeMetrics,
    prometheus: Option<CriticalPathMetrics>,
    sequence_detector: Option<KillChainSequenceDetector>,
    siem_forwarder: Option<SiemFindingForwarder>,
    notification_router: Option<NotificationRouter>,
}

impl<P, E> RuntimeService<P, E>
where
    P: ApprovalGate,
    E: ResponseExecutor,
{
    pub fn new(config: SwarmConfig, mut runtime: SwarmRuntime<P, E>) -> Self {
        runtime.configure_temporal_event_window(config.runtime.temporal_event_window.clone());
        let siem_forwarder = config.siem_forward.clone().map(|cfg| {
            SiemFindingForwarder::with_max_dead_letter_bytes(
                cfg,
                config.runtime.max_dead_letter_bytes,
            )
        });
        let (notification_channels, notification_routing) =
            notification_config_without_providence(&config);
        let notification_router =
            if notification_channels.is_empty() || notification_routing.rules.is_empty() {
                None
            } else {
                Some(NotificationRouter::new(
                    notification_channels,
                    notification_routing,
                    config.runtime.max_dead_letter_bytes,
                ))
            };
        Self {
            config,
            runtime: Arc::new(runtime),
            metrics: RuntimeMetrics::default(),
            prometheus: None,
            sequence_detector: None,
            siem_forwarder,
            notification_router,
        }
    }

    pub fn with_prometheus(mut self, metrics: CriticalPathMetrics) -> Self {
        self.prometheus = Some(metrics);
        self
    }

    pub fn with_sequence_detector(mut self, detector: KillChainSequenceDetector) -> Self {
        self.sequence_detector = Some(detector);
        self
    }

    pub fn with_configured_sequence_detector(mut self) -> Result<Self, ServiceError> {
        if self
            .config
            .detection
            .active_strategies()
            .iter()
            .any(|strategy| strategy == KILL_CHAIN_SEQUENCE_STRATEGY_ID)
        {
            let detector = KillChainSequenceDetector::from_profile(
                KILL_CHAIN_SEQUENCE_STRATEGY_ID,
                kill_chain_sequence_profile(&self.config.detection)?,
                self.runtime.temporal_event_window(),
            )?;
            self = self.with_sequence_detector(detector);
        }
        Ok(self)
    }

    pub fn mode(&self) -> RuntimeMode {
        self.runtime.mode()
    }

    pub fn runtime_config(&self) -> &RuntimeConfig {
        &self.config.runtime
    }

    pub fn shared_runtime(&self) -> Arc<SwarmRuntime<P, E>> {
        Arc::clone(&self.runtime)
    }

    pub fn playbook_action_for_finding(
        &self,
        finding: &DetectionFinding,
        mode: swarm_core::agent::SwarmMode,
    ) -> Option<ResponseAction> {
        let rule = self.config.pheromone.response_playbook.resolve(
            &finding.threat_class,
            finding.severity,
            finding.confidence,
            mode,
        )?;
        // The live executor is single-action: ActionRequest carries one
        // ResponseAction. Silently dropping the tail of a multi-action rule
        // would skip configured isolate-then-scan-then-escalate sequences.
        // Until the executor supports ordered action sequences, fail closed
        // so operators see the misconfiguration rather than partial response.
        if rule.actions.len() > 1 {
            tracing::warn!(
                rule_index = rule.rule_index,
                action_count = rule.actions.len(),
                threat_class = ?finding.threat_class,
                severity = ?finding.severity,
                confidence = finding.confidence,
                "playbook rule has multiple actions but the live executor only \
                 supports one — refusing to execute partial sequence"
            );
            return None;
        }
        rule.actions.into_iter().next()
    }

    pub async fn ensure_substrate_ready<S>(
        &self,
        substrate: &S,
    ) -> Result<SubstrateHealth, ServiceError>
    where
        S: PheromoneSubstrate,
    {
        let health = substrate.health().await?;
        if self.runtime.mode() == RuntimeMode::LiveResponse
            && self.config.runtime.require_durable_live_response
        {
            if !health.ready {
                return Err(ServiceError::Readiness {
                    component: "substrate",
                    source: ReadinessError::SubstrateNotReady {
                        backend: health.backend.clone(),
                    },
                });
            }
            if !health.durable {
                return Err(ServiceError::Readiness {
                    component: "substrate",
                    source: ReadinessError::SubstrateNotDurable {
                        backend: health.backend.clone(),
                    },
                });
            }
        }
        Ok(health)
    }

    async fn evaluate_sequence_findings<S>(
        &self,
        substrate: &S,
        event: &TelemetryEvent,
        agent_id: &AgentId,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<
        (
            Vec<DetectionFinding>,
            Vec<swarm_core::pheromone::PheromoneDeposit>,
        ),
        ServiceError,
    >
    where
        S: PheromoneSubstrate,
    {
        let Some(detector) = &self.sequence_detector else {
            return Ok((Vec::new(), Vec::new()));
        };
        let findings = detector.evaluate(event);
        if findings.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let deposits = persist_findings_as_deposits(
            substrate,
            &findings,
            event,
            agent_id,
            infer_agent_role(agent_id),
            &self.config.pheromone,
            signing_key,
        )
        .await?;
        Ok((findings, deposits))
    }

    /// Run the full critical lane for one event and build a replay bundle.
    pub async fn process_event<D, S, F>(
        &self,
        detector: &D,
        substrate: &S,
        event: &TelemetryEvent,
        execution: EventExecutionContext<'_>,
        request_builder: F,
    ) -> Result<Option<ReplayBundle>, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        F: Fn(&DetectionFinding) -> Option<ResponseAction>,
    {
        self.process_event_with_finding_observer(
            detector,
            substrate,
            event,
            execution,
            request_builder,
            |_event, _findings| {},
        )
        .await
    }

    /// Run the full critical lane and expose enriched findings before action selection.
    pub async fn process_event_with_finding_observer<D, S, F, O>(
        &self,
        detector: &D,
        substrate: &S,
        event: &TelemetryEvent,
        execution: EventExecutionContext<'_>,
        request_builder: F,
        observe_findings: O,
    ) -> Result<Option<ReplayBundle>, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        F: Fn(&DetectionFinding) -> Option<ResponseAction>,
        O: Fn(&TelemetryEvent, &[DetectionFinding]),
    {
        let trace_id = approval_correlation_id(execution.approval).to_string();
        let span = tracing::info_span!(
            "runtime.process_event_with_finding_observer",
            trace_id = %trace_id,
            event_id = %event.event_id,
            host_id = ?event.host_id,
            requested_by = %execution.agent_id.0
        );

        with_trace_id(
            trace_id,
            async {
                let substrate_health = self.ensure_substrate_ready(substrate).await?;
                tracing::debug!(
                    backend = %substrate_health.backend,
                    durable = substrate_health.durable,
                    ready = substrate_health.ready,
                    "substrate health verified"
                );
                self.runtime.record_temporal_event(event);

                let detect_started = Instant::now();
                let detection_result = detect_and_deposit(
                    detector,
                    substrate,
                    event,
                    execution.agent_id,
                    &self.config.pheromone,
                    execution.signing_key,
                )
                .await;
                let detect_elapsed_us = detect_started.elapsed().as_micros() as u64;
                self.metrics.record(
                    RuntimeStage::Detect,
                    detect_elapsed_us,
                    detection_result.is_ok(),
                );
                if let Some(prometheus) = &self.prometheus {
                    prometheus.observe_detect(detect_elapsed_us as f64);
                }

                let DetectionPipelineOutcome {
                    event,
                    findings,
                    deposits,
                } = detection_result?;
                let (sequence_findings, sequence_deposits) = self
                    .evaluate_sequence_findings(
                        substrate,
                        &event,
                        execution.agent_id,
                        execution.signing_key,
                    )
                    .await?;
                let mut findings = findings;
                findings.extend(sequence_findings);
                let mut deposits = deposits;
                deposits.extend(sequence_deposits);
                let detected_at_ms = execution.approval.now_ms;
                let findings = FindingEnrichmentService.enrich(&event, findings, detected_at_ms);
                observe_findings(&event, &findings);
                tracing::info!(
                    correlation_id = %approval_correlation_id(execution.approval),
                    event_id = %event.event_id,
                    finding_count = findings.len(),
                    deposit_count = deposits.len(),
                    module = module_path!(),
                    "detection completed"
                );
                if let Some(prometheus) = &self.prometheus {
                    for finding in &findings {
                        prometheus.observe_finding(
                            threat_class_label(&finding.threat_class),
                            &finding.strategy_id,
                        );
                    }
                }
                if let Some(forwarder) = &self.siem_forwarder {
                    // Spawn the SIEM forward as fire-and-forget so a slow or
                    // retrying Splunk/ELK/Chronicle endpoint cannot delay the
                    // live-response action selected just below. Receipts are
                    // observed in the spawned task; failures degrade reporting,
                    // not isolation/quarantine timing.
                    let forwarder = forwarder.clone();
                    let prometheus = self.prometheus.clone();
                    let event_id = event.event_id.clone();
                    let findings_for_siem = findings.clone();
                    tokio::spawn(async move {
                        match forwarder.forward_findings(&findings_for_siem).await {
                            Ok(receipts) => {
                                for receipt in receipts {
                                    if let Some(prometheus) = prometheus.as_ref() {
                                        observe_siem_forward_receipt_with(prometheus, &receipt);
                                    }
                                    if receipt.status.indicates_success() {
                                        tracing::info!(
                                            event_id = %event_id,
                                            transport = "siem_forward",
                                            status = ?receipt.status,
                                            event_count = receipt.details.get("event_count").and_then(serde_json::Value::as_u64).unwrap_or(0),
                                            "forwarded finding batch to SIEM"
                                        );
                                    } else {
                                        tracing::warn!(
                                            event_id = %event_id,
                                            status = ?receipt.status,
                                            summary = %receipt.summary,
                                            event_count = receipt.details.get("event_count").and_then(serde_json::Value::as_u64).unwrap_or(0),
                                            "siem finding forward degraded"
                                        );
                                    }
                                }
                            }
                            Err(error) => {
                                tracing::error!(
                                    event_id = %event_id,
                                    reason = %error,
                                    "siem finding forward failed"
                                );
                            }
                        }
                    });
                }
                if let Some(router) = &self.notification_router {
                    for finding in &findings {
                        router.route_finding(finding).await;
                    }
                }

                if findings.is_empty() {
                    tracing::info!(
                        correlation_id = %approval_correlation_id(execution.approval),
                        event_id = %event.event_id,
                        module = module_path!(),
                        "no findings emitted for event"
                    );
                    return Ok(None);
                }

                let Some((primary_finding, action)) = findings
                    .iter()
                    .find_map(|finding| request_builder(finding).map(|action| (finding.clone(), action)))
                else {
                    tracing::info!(
                        correlation_id = %approval_correlation_id(execution.approval),
                        event_id = %event.event_id,
                        module = module_path!(),
                        finding_count = findings.len(),
                        "no playbook action proposed for any finding on event"
                    );
                    return Ok(None);
                };

                let request = ActionRequest {
                    hunt_id: swarm_core::types::HuntId(primary_finding.event_id.clone()),
                    requested_by: execution.agent_id.clone(),
                    action,
                    severity: primary_finding.severity,
                    evidence: primary_finding.evidence.clone(),
                };
                let execution_started = Instant::now();
                let execution_result = self
                    .runtime
                    .audit_authorize_and_execute_instrumented(
                        &primary_finding,
                        &request,
                        execution.approval,
                    )
                    .await;
                let execution_report = match execution_result {
                    Ok(report) => report,
                    Err(error) => {
                        let elapsed_us = execution_started.elapsed().as_micros() as u64;
                        self.metrics.record(RuntimeStage::Policy, elapsed_us, false);
                        if let Some(prometheus) = &self.prometheus {
                            prometheus.observe_policy(elapsed_us as f64);
                        }
                        tracing::error!(
                            correlation_id = %approval_correlation_id(execution.approval),
                            event_id = %event.event_id,
                            reason = %error,
                            module = module_path!(),
                            "authorization or response execution failed"
                        );
                        return Err(error.into());
                    }
                };
                self.metrics.record(
                    RuntimeStage::Policy,
                    execution_report.policy_elapsed_us,
                    true,
                );
                if let Some(prometheus) = &self.prometheus {
                    prometheus.observe_policy(execution_report.policy_elapsed_us as f64);
                    prometheus
                        .observe_verdict(verdict_label(execution_report.audit.policy.verdict));
                    if let AuditResponseRecord::GuardRejected { guard_name, .. } =
                        &execution_report.audit.response
                    {
                        prometheus.observe_guard_rejection(guard_name);
                    }
                    if let Some(outcome) = adapter_outcome_label(&execution_report.audit.response) {
                        prometheus.observe_adapter_outcome(outcome);
                    }
                }
                if let Some(response_elapsed_us) = execution_report.response_elapsed_us {
                    self.metrics.record(
                        RuntimeStage::Response,
                        response_elapsed_us,
                        execution_report.response_succeeded,
                    );
                    if let Some(prometheus) = &self.prometheus {
                        prometheus.observe_response(response_elapsed_us as f64);
                    }
                }

                Ok(Some(ReplayBundle {
                    bundle_id: format!(
                        "bundle:{}:{}",
                        request.hunt_id.0, execution.approval.now_ms
                    ),
                    event,
                    findings,
                    deposits,
                    action_request: request,
                    rehearsal: None,
                    audit: execution_report.audit,
                }))
            }
            .instrument(span),
        )
        .await
    }

    pub fn metrics_snapshot(&self) -> RuntimeMetricsSnapshot {
        self.metrics.snapshot()
    }

    pub fn prometheus_metrics(&self) -> Option<&CriticalPathMetrics> {
        self.prometheus.as_ref()
    }

    pub fn notification_router(&self) -> Option<&NotificationRouter> {
        self.notification_router.as_ref()
    }

    pub fn persist_replay_bundle<Store>(
        &self,
        store: &Store,
        bundle: &ReplayBundle,
    ) -> Result<ReplayBundleRecord, ServiceError>
    where
        Store: ReplayBundleStore,
    {
        let started = Instant::now();
        let persisted = store.persist(bundle);
        let elapsed_us = started.elapsed().as_micros() as u64;
        self.metrics
            .record(RuntimeStage::Persist, elapsed_us, persisted.is_ok());
        let record = persisted?;
        tracing::info!(
            hunt_id = %record.hunt_id,
            trail_id = %record.trail_id,
            bundle_id = %record.bundle_id,
            response_receipt_id = ?record.response_receipt_id,
            "persisted replay bundle"
        );
        Ok(record)
    }

    pub async fn rehearse_bundle_with_store<Store>(
        &self,
        store: &Store,
        source: &ReplayBundle,
        approval: &ApprovalContext,
    ) -> Result<PersistedReplayBundle, ServiceError>
    where
        Store: ReplayBundleStore,
    {
        let preview =
            build_rehearsal_preview(&source.action_request, &source.bundle_id, approval.now_ms)?;
        let approval = merge_rehearsal_receipt_chain(approval, source);
        let execution_started = Instant::now();
        let execution_result = self
            .runtime
            .audit_rehearse_authorize_and_execute_instrumented(
                &source.audit.detection,
                &source.action_request,
                &approval,
            )
            .await;
        let execution_report = match execution_result {
            Ok(report) => report,
            Err(error) => {
                let elapsed_us = execution_started.elapsed().as_micros() as u64;
                self.metrics.record(RuntimeStage::Policy, elapsed_us, false);
                if let Some(prometheus) = &self.prometheus {
                    prometheus.observe_policy(elapsed_us as f64);
                }
                tracing::error!(
                    correlation_id = %approval_correlation_id(&approval),
                    hunt_id = %source.action_request.hunt_id.0,
                    source_bundle_id = %source.bundle_id,
                    reason = %error,
                    module = module_path!(),
                    "rehearsal authorization or response execution failed"
                );
                return Err(error.into());
            }
        };
        self.metrics.record(
            RuntimeStage::Policy,
            execution_report.policy_elapsed_us,
            true,
        );
        if let Some(prometheus) = &self.prometheus {
            prometheus.observe_policy(execution_report.policy_elapsed_us as f64);
            prometheus.observe_verdict(verdict_label(execution_report.audit.policy.verdict));
            if let AuditResponseRecord::GuardRejected { guard_name, .. } =
                &execution_report.audit.response
            {
                prometheus.observe_guard_rejection(guard_name);
            }
            if let Some(outcome) = adapter_outcome_label(&execution_report.audit.response) {
                prometheus.observe_adapter_outcome(outcome);
            }
        }
        if let Some(response_elapsed_us) = execution_report.response_elapsed_us {
            self.metrics.record(
                RuntimeStage::Response,
                response_elapsed_us,
                execution_report.response_succeeded,
            );
            if let Some(prometheus) = &self.prometheus {
                prometheus.observe_response(response_elapsed_us as f64);
            }
        }

        let bundle = ReplayBundle {
            bundle_id: format!(
                "bundle:rehearsal:{}:{}",
                source.action_request.hunt_id.0, approval.now_ms
            ),
            event: source.event.clone(),
            findings: source.findings.clone(),
            deposits: source.deposits.clone(),
            action_request: source.action_request.clone(),
            rehearsal: Some(preview),
            audit: execution_report.audit,
        };
        let record = self.persist_replay_bundle(store, &bundle)?;
        Ok(PersistedReplayBundle { record, bundle })
    }

    pub async fn process_event_with_store<D, S, F, Store>(
        &self,
        detector: &D,
        substrate: &S,
        store: &Store,
        event: &TelemetryEvent,
        execution: EventExecutionContext<'_>,
        request_builder: F,
    ) -> Result<Option<PersistedReplayBundle>, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        F: Fn(&DetectionFinding) -> Option<ResponseAction>,
        Store: ReplayBundleStore,
    {
        self.process_event_with_store_and_finding_observer(
            detector,
            substrate,
            store,
            event,
            execution,
            request_builder,
            |_event, _findings| {},
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn process_event_with_store_and_finding_observer<D, S, F, Store, O>(
        &self,
        detector: &D,
        substrate: &S,
        store: &Store,
        event: &TelemetryEvent,
        execution: EventExecutionContext<'_>,
        request_builder: F,
        observe_findings: O,
    ) -> Result<Option<PersistedReplayBundle>, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        F: Fn(&DetectionFinding) -> Option<ResponseAction>,
        Store: ReplayBundleStore,
        O: Fn(&TelemetryEvent, &[DetectionFinding]),
    {
        let Some(bundle) = self
            .process_event_with_finding_observer(
                detector,
                substrate,
                event,
                execution,
                request_builder,
                observe_findings,
            )
            .await?
        else {
            return Ok(None);
        };
        let record = self.persist_replay_bundle(store, &bundle)?;
        Ok(Some(PersistedReplayBundle { record, bundle }))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn process_event_with_store_and_investigation<
        D,
        S,
        F,
        Store,
        Strategy,
        InvestigationStore,
    >(
        &self,
        detector: &D,
        substrate: &S,
        store: &Store,
        investigation: &InvestigationCoordinator<Strategy, InvestigationStore>,
        event: &TelemetryEvent,
        execution: EventExecutionContext<'_>,
        request_builder: F,
    ) -> Result<Option<PersistedReplayBundleWithInvestigation>, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        F: Fn(&DetectionFinding) -> Option<ResponseAction>,
        Store: ReplayBundleStore,
        Strategy: InvestigationStrategy,
        InvestigationStore: InvestigationBundleStore + Clone + Send + Sync + 'static,
    {
        self.process_event_with_store_and_investigation_and_finding_observer(
            detector,
            substrate,
            store,
            investigation,
            event,
            execution,
            request_builder,
            |_event, _findings| {},
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn process_event_with_store_and_investigation_and_finding_observer<
        D,
        S,
        F,
        Store,
        Strategy,
        InvestigationStore,
        O,
    >(
        &self,
        detector: &D,
        substrate: &S,
        store: &Store,
        investigation: &InvestigationCoordinator<Strategy, InvestigationStore>,
        event: &TelemetryEvent,
        execution: EventExecutionContext<'_>,
        request_builder: F,
        observe_findings: O,
    ) -> Result<Option<PersistedReplayBundleWithInvestigation>, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        F: Fn(&DetectionFinding) -> Option<ResponseAction>,
        Store: ReplayBundleStore,
        Strategy: InvestigationStrategy,
        InvestigationStore: InvestigationBundleStore + Clone + Send + Sync + 'static,
        O: Fn(&TelemetryEvent, &[DetectionFinding]),
    {
        let Some(replay) = self
            .process_event_with_store_and_finding_observer(
                detector,
                substrate,
                store,
                event,
                execution,
                request_builder,
                observe_findings,
            )
            .await?
        else {
            return Ok(None);
        };
        let investigation_record = investigation.submit(&replay.bundle)?;
        Ok(Some(PersistedReplayBundleWithInvestigation {
            replay,
            investigation: investigation_record,
        }))
    }

    pub fn load_persisted_bundle_by_hunt_id<Store>(
        &self,
        store: &Store,
        hunt_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ServiceError>
    where
        Store: ReplayBundleStore,
    {
        Ok(store.load_by_hunt_id(hunt_id)?)
    }

    pub fn load_persisted_bundle_by_bundle_id<Store>(
        &self,
        store: &Store,
        bundle_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ServiceError>
    where
        Store: ReplayBundleStore,
    {
        Ok(store.load_by_bundle_id(bundle_id)?)
    }

    pub fn load_persisted_bundle_by_receipt_id<Store>(
        &self,
        store: &Store,
        receipt_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ServiceError>
    where
        Store: ReplayBundleStore,
    {
        Ok(store.load_by_receipt_id(receipt_id)?)
    }

    pub fn load_persisted_investigation_by_hunt_id<Store>(
        &self,
        store: &Store,
        hunt_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, ServiceError>
    where
        Store: InvestigationBundleStore,
    {
        Ok(store
            .load_by_hunt_id(hunt_id)
            .map_err(InvestigationError::from)?)
    }

    pub fn load_persisted_investigation_by_investigation_id<Store>(
        &self,
        store: &Store,
        investigation_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, ServiceError>
    where
        Store: InvestigationBundleStore,
    {
        Ok(store
            .load_by_investigation_id(investigation_id)
            .map_err(InvestigationError::from)?)
    }

    pub fn load_persisted_investigation_by_receipt_id<Store>(
        &self,
        store: &Store,
        receipt_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, ServiceError>
    where
        Store: InvestigationBundleStore,
    {
        Ok(store
            .load_by_receipt_id(receipt_id)
            .map_err(InvestigationError::from)?)
    }

    pub fn correlate_hunt<Investigations, Incidents>(
        &self,
        engine: &CorrelationEngine,
        investigations: &Investigations,
        incidents: &Incidents,
        hunt_id: &str,
    ) -> Result<Option<CorrelationOutcome>, ServiceError>
    where
        Investigations: InvestigationBundleStore,
        Incidents: IncidentStore,
    {
        Ok(engine.correlate_hunt(investigations, incidents, hunt_id)?)
    }

    pub fn load_incident_by_hunt_id<Store>(
        &self,
        store: &Store,
        hunt_id: &str,
    ) -> Result<Option<IncidentLookup>, ServiceError>
    where
        Store: IncidentStore,
    {
        Ok(store
            .load_by_hunt_id(hunt_id)
            .map_err(CorrelationError::from)?)
    }

    pub fn load_incident_by_incident_id<Store>(
        &self,
        store: &Store,
        incident_id: &str,
    ) -> Result<Option<IncidentLookup>, ServiceError>
    where
        Store: IncidentStore,
    {
        Ok(store
            .load_by_incident_id(incident_id)
            .map_err(CorrelationError::from)?)
    }

    pub fn replay_preview(&self, bundle: &ReplayBundle) -> ReplayPreview {
        ReplayPreview::from_bundle(bundle)
    }

    pub fn rehearsal_preview(
        &self,
        request: &ActionRequest,
        source_bundle_id: &str,
        prepared_at_ms: i64,
    ) -> Result<ResponseRehearsalPreview, ServiceError> {
        build_rehearsal_preview(request, source_bundle_id, prepared_at_ms)
    }

    pub fn playbook_preview(
        &self,
        request: ResponsePlaybookPreviewRequest,
        prepared_at_ms: i64,
    ) -> Result<ResponsePlaybookPreviewReport, ServiceError> {
        let mut notes = Vec::new();
        if self.runtime.mode() != RuntimeMode::LiveResponse {
            notes.push(
                "configured runtime mode is detect_only; preview still evaluates the playbook and policy path without executor side effects"
                    .to_string(),
            );
        }

        let Some(matched_rule) = self.config.pheromone.response_playbook.resolve(
            &request.threat_class,
            request.severity,
            request.confidence,
            request.mode,
        ) else {
            notes.push(
                "no response playbook rule matched the supplied threat class, severity, confidence, and swarm mode"
                    .to_string(),
            );
            return Ok(ResponsePlaybookPreviewReport {
                status: ResponsePlaybookPreviewStatus::NoMatch,
                configured_runtime_mode: self.runtime.mode(),
                request,
                matched_rule: None,
                actions: Vec::new(),
                approval_summary: ResponsePlaybookApprovalSummary::default(),
                notes,
            });
        };

        let source_bundle_id = format!("playbook-preview:{prepared_at_ms}");
        let approval = playbook_preview_approval_context(
            prepared_at_ms,
            self.runtime.mode() == RuntimeMode::LiveResponse,
        );
        let hunt_id = playbook_preview_hunt_id(prepared_at_ms);
        let requested_by = AgentId("operator-preview".to_string());
        let evidence = playbook_preview_evidence(&request, &matched_rule);
        let gate = ConfigurableApprovalGate::from_config(&self.config.policy);
        let mut approval_summary = ResponsePlaybookApprovalSummary::default();
        let mut actions = Vec::with_capacity(matched_rule.actions.len());

        for (order, action) in matched_rule.actions.iter().cloned().enumerate() {
            let request_action = ActionRequest {
                hunt_id: hunt_id.clone(),
                requested_by: requested_by.clone(),
                action: action.clone(),
                severity: request.severity,
                evidence: evidence.clone(),
            };
            let policy = gate.evaluate(&request_action, &approval)?;
            let lease = if policy.verdict == PolicyVerdict::Allow {
                Some(gate.issue_lease(&request_action, &approval)?)
            } else {
                None
            };
            let rehearsal =
                build_rehearsal_preview(&request_action, &source_bundle_id, prepared_at_ms)?;

            match policy.verdict {
                PolicyVerdict::Allow => approval_summary.allow_count += 1,
                PolicyVerdict::RequireHuman => approval_summary.require_human_count += 1,
                PolicyVerdict::Deny => approval_summary.deny_count += 1,
            }

            actions.push(ResponsePlaybookActionPreview {
                order,
                action,
                rehearsal,
                policy: ResponsePlaybookPolicyPreview {
                    verdict: policy.verdict,
                    rule_name: policy.rule_name,
                    reason: policy.reason,
                    lease_scope: lease.as_ref().and_then(|value| value.scope.clone()),
                    lease_expires_at_ms: lease.as_ref().map(|value| value.expires_at_ms),
                },
            });
        }

        Ok(ResponsePlaybookPreviewReport {
            status: ResponsePlaybookPreviewStatus::Matched,
            configured_runtime_mode: self.runtime.mode(),
            request,
            matched_rule: Some(matched_rule),
            actions,
            approval_summary,
            notes,
        })
    }

    pub async fn operator_status<D, S, Store>(
        &self,
        detector: &D,
        substrate: &S,
        store: &Store,
    ) -> Result<OperatorStatusReport, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        Store: ReplayBundleStore,
    {
        let substrate_health = substrate.health().await?;
        let replay_store_health = store.health()?;
        let captured_at_ms = now_ms();
        let mut warnings = Vec::new();
        if self.runtime.mode() == RuntimeMode::LiveResponse
            && self.config.runtime.require_durable_live_response
            && !substrate_health.durable
        {
            warnings.push("live response requires a durable substrate backend".to_string());
        }
        if !substrate_health.ready {
            warnings.push(format!(
                "substrate backend `{}` is not ready",
                substrate_health.backend
            ));
        }
        if self.runtime.mode() == RuntimeMode::LiveResponse
            && self.config.audit.bundle_store.is_durable()
            && !replay_store_health.ready
        {
            warnings.push("durable replay store is not ready".to_string());
        }
        let recent_decisions = store.recent(self.config.audit.recent_decisions_limit)?;
        // Read the substrate with the same tolerance twice. `substrate.health()` above is
        // deliberately tolerant -- an unreachable JetStream returns `Ok(ready: false)` and
        // is downgraded to a `warnings` entry -- but a hard `?` here would abort the whole
        // operator-status computation on the very same fault. That makes
        // `current_async_lane_status()` return `Err`, which `ingest/health.rs` reports as
        // async-lane degradation, double-counting a substrate fault that
        // `components.substrate` and `components.degradation` already report and overriding
        // the degradation ladder's contract that `DetectOnly` is a serving state
        // (`RuntimeDegradationLevel::operator_read_surfaces_ready()` is true at every level).
        //
        // Degrade the field, not the surface -- but push a warning so the outage stays
        // loud. Turning a noisy failure into a silent one would be the same class of bug.
        let latest_escalation = match substrate.query_escalations(0).await {
            Ok(records) => records
                .into_iter()
                .max_by_key(|record| record.timestamp)
                .map(|record| OperatorEscalationSummary {
                    mode: record.mode,
                    threat_class: record.threat_class,
                    timestamp: record.timestamp,
                    distinct_sources: record.distinct_sources,
                    total_strength: record.total_strength,
                }),
            Err(error) => {
                warnings.push(format!(
                    "substrate escalation history is unavailable: {error}"
                ));
                None
            }
        };
        let degradation = derive_runtime_degradation_status(RuntimeDegradationSignals {
            configured_mode: self.runtime.mode(),
            detector_ready: true,
            substrate_ready: substrate_health.ready
                && (!self.config.runtime.require_durable_live_response
                    || self.runtime.mode() != RuntimeMode::LiveResponse
                    || substrate_health.durable),
            replay_store_ready: replay_store_health.ready,
            startup_attestation_ready: true,
            anti_tamper_ready: true,
            heap_ready: true,
            draining: false,
            degraded_agents: 0,
            failed_agents: 0,
            transitioned_at_ms: captured_at_ms,
        });
        let bearer_tokens = operator_bearer_token_statuses(&self.config.operator, captured_at_ms);
        for token in bearer_tokens.iter().filter(|token| token.expired) {
            warnings.push(format!(
                "operator bearer token for `{}` expired at {}",
                token.operator_id,
                token.expires_at_ms.unwrap_or_default()
            ));
        }

        Ok(OperatorStatusReport {
            mode: self.runtime.mode(),
            active_detectors: self.config.detection.active_strategies(),
            degradation,
            detector: ComponentStatus {
                ready: true,
                durable: None,
                details: format!("strategy `{}`", detector.id()),
            },
            substrate: component_status_from_substrate(&substrate_health),
            policy: ComponentStatus {
                ready: true,
                durable: None,
                details: type_name::<P>().to_string(),
            },
            response: ComponentStatus {
                ready: true,
                durable: None,
                details: type_name::<E>().to_string(),
            },
            replay_store: component_status_from_replay_store(&replay_store_health),
            providence: None,
            bridges: None,
            metrics: self.metrics_snapshot(),
            recent_finding_count: recent_decisions.len(),
            recent_decisions: recent_decisions.clone(),
            latest_escalation,
            async_lane: AsyncLaneStatusSnapshot::disabled(),
            investigation_review: None,
            incident_review: None,
            freshness: ReviewFreshness {
                latest_hot_path_decision_at_ms: recent_decisions
                    .first()
                    .map(|record| record.created_at_ms),
                latest_investigation_update_at_ms: None,
                latest_incident_at_ms: None,
            },
            evolution: None,
            false_positive_tracking: FalsePositiveMeasurementReport::default(),
            alert_tuning: AlertTuningReport::default(),
            bearer_tokens,
            rate_limit: HttpRateLimitStatus {
                surface: "operator".to_string(),
                config: self.config.operator.rate_limit.clone(),
                recent_violations: Vec::new(),
            },
            warnings,
        })
    }

    pub async fn operator_review_status<
        D,
        S,
        ReplayStore,
        Strategy,
        InvestigationStoreT,
        IncidentStoreT,
    >(
        &self,
        detector: &D,
        substrate: &S,
        replay_store: &ReplayStore,
        investigation: &InvestigationCoordinator<Strategy, InvestigationStoreT>,
        incident_store: &IncidentStoreT,
    ) -> Result<OperatorStatusReport, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        ReplayStore: ReplayBundleStore,
        Strategy: InvestigationStrategy,
        InvestigationStoreT: InvestigationBundleStore + Clone + Send + Sync + 'static,
        IncidentStoreT: IncidentStore,
    {
        let mut report = self
            .operator_status(detector, substrate, replay_store)
            .await?;
        let queue = investigation.snapshot();
        let investigation_store_health = investigation.health()?;
        let incident_store_health = incident_store.health().map_err(CorrelationError::from)?;
        let recent_investigations =
            investigation.recent(self.config.audit.recent_decisions_limit)?;
        let recent_incidents = incident_store
            .recent(self.config.audit.recent_decisions_limit)
            .map_err(CorrelationError::from)?;

        if self.config.investigation.enabled && !investigation_store_health.ready {
            report
                .warnings
                .push("durable investigation store is not ready".to_string());
        }
        if self.config.correlation.enabled && !incident_store_health.ready {
            report
                .warnings
                .push("durable incident store is not ready".to_string());
        }
        if let Some(reason) = &queue.last_failure_reason {
            report.warnings.push(format!(
                "investigation queue reported recent failure: {reason}"
            ));
        }

        let async_lane = summarize_async_lane_status(
            &self.config,
            investigation.strategy_id(),
            &queue,
            &investigation_store_health,
            &incident_store_health,
            &recent_investigations,
            &recent_incidents,
        );
        extend_unique_warnings(&mut report.warnings, async_lane.warnings.clone());

        report.investigation_review = Some(InvestigationReviewStatus {
            queue,
            store: component_status_from_investigation_store(&investigation_store_health),
            recent: recent_investigations.clone(),
        });
        report.incident_review = Some(IncidentReviewStatus {
            store: component_status_from_incident_store(&incident_store_health),
            recent: recent_incidents.clone(),
        });
        report.false_positive_tracking = summarize_false_positive_measurements(&recent_incidents);
        report.alert_tuning = build_alert_tuning_report(&recent_incidents);
        report.async_lane = async_lane;
        report.freshness.latest_investigation_update_at_ms = recent_investigations
            .first()
            .map(|record| record.last_updated_ms);
        report.freshness.latest_incident_at_ms =
            recent_incidents.first().map(|record| record.created_at_ms);

        Ok(report)
    }

    pub async fn operator_status_with_bridges<D, S, Store>(
        &self,
        detector: &D,
        substrate: &S,
        store: &Store,
        bridges: BridgeStatusReport,
    ) -> Result<OperatorStatusReport, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        Store: ReplayBundleStore,
    {
        Ok(self
            .operator_status(detector, substrate, store)
            .await?
            .with_bridges(bridges))
    }

    pub async fn operator_review_status_with_bridges<
        D,
        S,
        ReplayStore,
        Strategy,
        InvestigationStoreT,
        IncidentStoreT,
    >(
        &self,
        detector: &D,
        substrate: &S,
        replay_store: &ReplayStore,
        investigation: &InvestigationCoordinator<Strategy, InvestigationStoreT>,
        incident_store: &IncidentStoreT,
        bridges: BridgeStatusReport,
    ) -> Result<OperatorStatusReport, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        ReplayStore: ReplayBundleStore,
        Strategy: InvestigationStrategy,
        InvestigationStoreT: InvestigationBundleStore + Clone + Send + Sync + 'static,
        IncidentStoreT: IncidentStore,
    {
        Ok(self
            .operator_review_status(
                detector,
                substrate,
                replay_store,
                investigation,
                incident_store,
            )
            .await?
            .with_bridges(bridges))
    }

    pub fn save_replay_bundle(
        &self,
        bundle: &ReplayBundle,
        path: impl AsRef<Path>,
    ) -> Result<(), ServiceError> {
        let path = path.as_ref();
        let serialized = serde_json::to_string_pretty(bundle)?;
        fs::write(path, serialized).map_err(|source| ServiceError::Write {
            path: path.display().to_string(),
            source,
        })
    }

    pub fn load_replay_bundle(&self, path: impl AsRef<Path>) -> Result<ReplayBundle, ServiceError> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path).map_err(|source| ServiceError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Ok(serde_json::from_str(&raw)?)
    }
}

fn observe_siem_forward_receipt_with(
    prometheus: &CriticalPathMetrics,
    receipt: &swarm_response::ResponseReceipt,
) {
    let Some(transport) = receipt
        .details
        .get("transport")
        .and_then(serde_json::Value::as_str)
    else {
        return;
    };
    let event_count = receipt
        .details
        .get("event_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let payload_bytes = receipt
        .details
        .get("payload_bytes")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let outcome = match receipt.status {
        swarm_response::ResponseStatus::Executed => "success",
        swarm_response::ResponseStatus::Simulated => "simulated",
        swarm_response::ResponseStatus::Timeout => "timeout",
        swarm_response::ResponseStatus::Failed => "failure",
    };
    prometheus.observe_delivery_batch(transport, outcome, event_count, payload_bytes);
}

fn operator_bearer_token_statuses(
    operator: &swarm_core::config::OperatorSurfaceConfig,
    now_ms: i64,
) -> Vec<OperatorBearerTokenStatus> {
    operator
        .auth
        .effective_principals()
        .into_iter()
        .map(|principal| {
            let expired = principal.token_is_expired(now_ms);
            OperatorBearerTokenStatus {
                operator_id: principal.operator_id,
                token_env: principal.token_env,
                expires_at_ms: principal.token_expires_at_ms,
                expired,
            }
        })
        .collect()
}
