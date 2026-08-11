use super::*;

impl<P, E, Strategy> ConfiguredRuntimeStack<P, E, Strategy>
where
    P: ApprovalGate,
    E: ResponseExecutor,
    Strategy: InvestigationStrategy,
{
    /// Build the runtime composition root directly from repository-owned config.
    pub fn from_runtime(
        config: SwarmConfig,
        runtime: SwarmRuntime<P, E>,
        strategy: Strategy,
    ) -> Result<Self, ServiceError> {
        let substrate = ConfiguredPheromoneSubstrate::from_config(&config.pheromone)?;
        let replay_store = ConfiguredReplayBundleStore::from_config(&config.audit.bundle_store)?;
        let investigation_store =
            ConfiguredInvestigationBundleStore::from_config(&config.investigation.bundle_store)
                .map_err(InvestigationError::from)?;
        let incident_store =
            ConfiguredIncidentStore::from_config(&config.correlation.incident_store)
                .map_err(CorrelationError::from)?;
        let investigation = InvestigationCoordinator::new(
            config.investigation.clone(),
            strategy,
            investigation_store.clone(),
        );
        let correlation = CorrelationEngine::new(config.correlation.clone());
        let service = RuntimeService::new(config, runtime).with_configured_sequence_detector()?;
        let service = service.with_prometheus(CriticalPathMetrics::new());

        Ok(Self {
            service,
            substrate,
            replay_store,
            investigation,
            investigation_store,
            correlation,
            incident_store,
        })
    }

    /// Build the runtime stack from policy, response, and investigation components.
    pub fn from_components(
        config: SwarmConfig,
        policy: P,
        response: E,
        strategy: Strategy,
    ) -> Result<Self, ServiceError> {
        let mode = config.runtime.mode;
        Self::from_runtime(config, SwarmRuntime::new(mode, policy, response), strategy)
    }

    /// Run the critical path, persist the replay bundle, and queue async investigation.
    pub async fn process_event<D, F>(
        &self,
        detector: &D,
        event: &TelemetryEvent,
        execution: EventExecutionContext<'_>,
        request_builder: F,
    ) -> Result<Option<PersistedReplayBundleWithInvestigation>, ServiceError>
    where
        D: DetectionStrategy,
        F: Fn(&DetectionFinding) -> Option<ResponseAction>,
    {
        self.process_event_with_finding_observer(
            detector,
            event,
            execution,
            request_builder,
            |_event, _findings| {},
        )
        .await
    }

    /// Run the critical path, persist the replay bundle, queue investigation, and observe findings.
    pub async fn process_event_with_finding_observer<D, F, O>(
        &self,
        detector: &D,
        event: &TelemetryEvent,
        execution: EventExecutionContext<'_>,
        request_builder: F,
        observe_findings: O,
    ) -> Result<Option<PersistedReplayBundleWithInvestigation>, ServiceError>
    where
        D: DetectionStrategy,
        F: Fn(&DetectionFinding) -> Option<ResponseAction>,
        O: Fn(&TelemetryEvent, &[DetectionFinding]),
    {
        self.service
            .process_event_with_store_and_investigation_and_finding_observer(
                detector,
                &self.substrate,
                &self.replay_store,
                &self.investigation,
                event,
                execution,
                request_builder,
                observe_findings,
            )
            .await
    }

    /// Assemble or reload one correlated incident from the configured stores.
    pub fn correlate_hunt(
        &self,
        hunt_id: &str,
    ) -> Result<Option<CorrelationOutcome>, ServiceError> {
        self.service.correlate_hunt(
            &self.correlation,
            &self.investigation_store,
            &self.incident_store,
            hunt_id,
        )
    }

    /// Load a persisted replay bundle from the configured replay store.
    pub fn replay_bundle_by_bundle_id(
        &self,
        bundle_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ServiceError> {
        self.service
            .load_persisted_bundle_by_bundle_id(&self.replay_store, bundle_id)
    }

    /// Load a persisted replay bundle by hunt identifier from the configured replay store.
    pub fn replay_bundle_by_hunt_id(
        &self,
        hunt_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ServiceError> {
        self.service
            .load_persisted_bundle_by_hunt_id(&self.replay_store, hunt_id)
    }

    /// Load a persisted replay bundle by receipt identifier from the configured replay store.
    pub fn replay_bundle_by_receipt_id(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ServiceError> {
        self.service
            .load_persisted_bundle_by_receipt_id(&self.replay_store, receipt_id)
    }

    /// Load a persisted investigation bundle from the configured investigation store.
    pub fn investigation_by_investigation_id(
        &self,
        investigation_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, ServiceError> {
        self.service
            .load_persisted_investigation_by_investigation_id(
                &self.investigation_store,
                investigation_id,
            )
    }

    /// Load a persisted investigation bundle by hunt identifier from the configured store.
    pub fn investigation_by_hunt_id(
        &self,
        hunt_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, ServiceError> {
        self.service
            .load_persisted_investigation_by_hunt_id(&self.investigation_store, hunt_id)
    }

    /// Load a persisted investigation bundle by receipt identifier from the configured store.
    pub fn investigation_by_receipt_id(
        &self,
        receipt_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, ServiceError> {
        self.service
            .load_persisted_investigation_by_receipt_id(&self.investigation_store, receipt_id)
    }

    /// Load a correlated incident from the configured incident store by incident id.
    pub fn incident_by_incident_id(
        &self,
        incident_id: &str,
    ) -> Result<Option<IncidentLookup>, ServiceError> {
        self.service
            .load_incident_by_incident_id(&self.incident_store, incident_id)
    }

    /// Load a correlated incident from the configured incident store by hunt id.
    pub fn incident_by_hunt_id(
        &self,
        hunt_id: &str,
    ) -> Result<Option<IncidentLookup>, ServiceError> {
        self.service
            .load_incident_by_hunt_id(&self.incident_store, hunt_id)
    }

    /// Produce the full operator review report from the configured stack.
    pub async fn operator_review_status<D>(
        &self,
        detector: &D,
    ) -> Result<OperatorStatusReport, ServiceError>
    where
        D: DetectionStrategy,
    {
        self.service
            .operator_review_status(
                detector,
                &self.substrate,
                &self.replay_store,
                &self.investigation,
                &self.incident_store,
            )
            .await
    }
}

impl<Strategy> ConfiguredRuntimeStack<ConfigurableApprovalGate, DispatchingExecutor, Strategy>
where
    Strategy: InvestigationStrategy,
{
    /// Build the runtime stack from repository config using the configured response adapter.
    pub fn from_config(config: SwarmConfig, strategy: Strategy) -> Result<Self, ServiceError> {
        let response = DispatchingExecutor::from_config(
            config.response_adapter.clone(),
            config.runtime.max_dead_letter_bytes,
        )
        .map_err(|error| ServiceError::Runtime(crate::RuntimeError::Response(error)))?;
        let gate = ConfigurableApprovalGate::from_config(&config.policy);
        Self::from_components(config, gate, response, strategy)
    }
}
