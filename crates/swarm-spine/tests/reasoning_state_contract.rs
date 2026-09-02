//! Post-Plan-03 contract checks for the existing spine boundaries.
//!
//! These tests intentionally consume only the public store traits and the
//! additive core records.  They do not create a coordinator, a second task
//! ledger, or a terminal outbox.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use swarm_core::config::HypothesisGraphConfig;
use swarm_core::hypothesis_graph::{
    EvidenceId, EvidenceScope, EvidenceSourceFamily, FencingToken, GraphId, GraphLogicalTime,
    GraphProducerRole, GraphResourceLimits, GraphSchedulerKey, HypothesisDelta, HypothesisGraph,
    HypothesisId, MemoryOutcome, MemoryProvenance, SchedulerBudget, StrategyMemory,
    TaskCapabilityProof, TaskClaimRequest, TaskCompletion, TaskCompletionKind, TaskId, TaskKind,
    TaskTarget, TaskTerminalEnvelope,
};
use swarm_core::types::AgentId;
use swarm_crypto::Keypair;
use swarm_spine::{
    FileHypothesisGraphStore, FileStrategyMemoryStore, GraphCasEnvelope, GraphStoreError,
    HypothesisGraphStore, MemoryHypothesisGraphStore, MemoryStrategyMemoryStore,
    StrategyMemoryStore, TaskClaimEnvelope, validate_task_terminal_envelope,
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

fn signer(byte: u8) -> Keypair {
    Keypair::from_seed(&[byte; 32])
}

fn graph(name: &str) -> HypothesisGraph {
    HypothesisGraph::new(GraphId::new(name), GraphResourceLimits::default()).unwrap()
}

fn temp_dir(name: &str) -> PathBuf {
    let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "swarm-reasoning-state-{name}-{}-{id}",
        std::process::id()
    ))
}

fn request(key: &Keypair, task_id: &str, evidence_id: &str) -> TaskClaimRequest {
    let claimant = AgentId::from_public_key_hex(&key.public_key().to_hex());
    TaskClaimRequest::new(
        TaskId::new(task_id),
        TaskKind::AcquireEvidence,
        TaskTarget::Evidence {
            evidence_id: EvidenceId::new(evidence_id),
        },
        GraphProducerRole::Hunter,
        claimant,
        EvidenceScope::new(
            [EvidenceSourceFamily::Process],
            [EvidenceId::new(evidence_id)],
            std::iter::empty(),
        )
        .unwrap(),
        GraphLogicalTime::new(100),
    )
    .unwrap()
}

fn memory(byte: u8, suffix: &str) -> StrategyMemory {
    let key = signer(byte);
    let identity = AgentId::from_public_key_hex(&key.public_key().to_hex());
    let evidence_id = EvidenceId::new(format!("evidence:{suffix}"));
    let provenance = MemoryProvenance::new(identity, [evidence_id.clone()])
        .signed_with(&key, GraphProducerRole::Hunter, format!("hunter-{suffix}"))
        .unwrap();
    StrategyMemory::new(
        GraphId::new("graph:memory-contract"),
        HypothesisId::new("hypothesis:selected"),
        HypothesisDelta::new([], [], []),
        [swarm_core::hypothesis_graph::EvidenceUtility::new(
            evidence_id,
            7_500,
        )],
        [HypothesisId::new("hypothesis:alternative")],
        MemoryOutcome::Confirmed,
        provenance,
    )
    .unwrap()
    .signed_with(&key, GraphProducerRole::Hunter, format!("hunter-{suffix}"))
    .unwrap()
}

fn assert_high_water_cas(store: &dyn HypothesisGraphStore) {
    let baseline = store.snapshot().unwrap();
    let mut candidate = baseline.state.clone();
    candidate.graph.version = candidate.graph.version.saturating_add(1);
    candidate.logical_time_high_water = GraphLogicalTime::new(20);
    let envelope = GraphCasEnvelope::new(baseline.revision.clone(), candidate)
        .unwrap()
        .authorized_by(&signer(1), "graph-cas:high-water-contract")
        .unwrap();
    let error = store.compare_and_swap(envelope).unwrap_err();
    assert!(matches!(
        error,
        GraphStoreError::InvalidState { reason }
            if reason.contains("store-owned logical time high-water")
    ));
    assert_eq!(store.snapshot().unwrap(), baseline);
}

#[test]
fn cas_rejects_future_logical_high_water_for_both_backends() {
    let memory_store =
        MemoryHypothesisGraphStore::new(graph("graph:cas-memory"), signer(1)).unwrap();
    assert_high_water_cas(&memory_store);

    let path = temp_dir("graph-cas-file");
    let file_store =
        FileHypothesisGraphStore::new(&path, graph("graph:cas-file"), signer(1)).unwrap();
    assert_high_water_cas(&file_store);
    drop(file_store);
    let _ = fs::remove_dir_all(path);
}

#[test]
fn terminal_validator_uses_core_exact_task_boundary_without_seed_fiction() {
    let key = signer(10);
    let authority = signer(11);
    let store =
        MemoryHypothesisGraphStore::new(graph("graph:terminal"), authority.clone()).unwrap();
    let claim = request(&key, "task:terminal", "evidence:terminal");
    let claimant = AgentId::from_public_key_hex(&key.public_key().to_hex());
    let claim_capability = TaskCapabilityProof::signed_with(
        claim.task_id.clone(),
        claimant.clone(),
        GraphProducerRole::Hunter,
        TaskKind::AcquireEvidence,
        claim.canonical_digest().unwrap(),
        &key,
        "hunter-terminal-claim",
    )
    .unwrap();
    let claim_envelope = TaskClaimEnvelope::new(
        claim.clone(),
        GraphLogicalTime::new(100),
        100,
        claim_capability,
    )
    .unwrap()
    .authorized_by(&authority, "planner-terminal-claim")
    .unwrap();
    let claimed = store.claim_task(claim_envelope).unwrap().task;
    let capability = TaskCapabilityProof::signed_with(
        claimed.request.task_id.clone(),
        claimant.clone(),
        GraphProducerRole::Hunter,
        TaskKind::AcquireEvidence,
        claim.canonical_digest().unwrap(),
        &key,
        "hunter-terminal",
    )
    .unwrap();
    let completion = TaskCompletion::new(
        TaskCompletionKind::EvidenceAdded,
        claimant.clone(),
        GraphLogicalTime::new(110),
        [EvidenceId::new("evidence:terminal")],
        "summary:terminal",
    )
    .unwrap();
    let envelope = TaskTerminalEnvelope::new(
        claimed.request.task_id.clone(),
        claimed.request.idempotency_key.clone(),
        claimed.lease.as_ref().unwrap().lease_id.clone(),
        claimed.lease.as_ref().unwrap().fencing_token,
        completion,
        None,
        claimant,
        capability.clone(),
    )
    .unwrap()
    .signed_with(&key, "terminal-proof")
    .unwrap();
    validate_task_terminal_envelope(&claimed, &envelope, &GraphResourceLimits::default()).unwrap();

    let mut forged = envelope;
    forged.fencing_token = FencingToken::new(99);
    assert!(
        validate_task_terminal_envelope(&claimed, &forged, &GraphResourceLimits::default(),)
            .is_err()
    );
}

#[test]
fn scheduler_key_and_budget_remain_core_owned_and_deterministic() {
    let low = GraphSchedulerKey::new(
        GraphLogicalTime::new(5),
        TaskKind::ChallengeEdge,
        1_000,
        TaskId::new("task:b"),
    )
    .unwrap();
    let high = GraphSchedulerKey::new(
        GraphLogicalTime::new(5),
        TaskKind::AcquireEvidence,
        9_000,
        TaskId::new("task:z"),
    )
    .unwrap();
    assert!(high.dispatches_before(&low));

    let config = HypothesisGraphConfig {
        max_work_units_per_tick: 10,
        max_claims_per_tick: 2,
        ..HypothesisGraphConfig::default()
    };
    let mut budget = SchedulerBudget::new(&config, GraphLogicalTime::new(7)).unwrap();
    budget
        .admit_at(&config, GraphLogicalTime::new(7), 6, 1)
        .unwrap();
    assert!(
        budget
            .admit_at(&config, GraphLogicalTime::new(7), 5, 1)
            .is_err()
    );
    assert!(
        budget
            .admit_at(&config, GraphLogicalTime::new(7), 1, 2)
            .is_err()
    );
}

#[test]
fn strategy_memory_expiry_is_backend_identical() {
    let path = temp_dir("memory-expiry");
    let key = signer(20);
    let memory_store = MemoryStrategyMemoryStore::with_defaults(key.clone()).unwrap();
    let file_store =
        FileStrategyMemoryStore::new(&path, key.clone(), GraphResourceLimits::default()).unwrap();

    let first = memory(21, "first");
    let second = memory(22, "second");
    let legacy = memory(23, "legacy");
    let first_memory = memory_store
        .append_at(first.clone(), GraphLogicalTime::new(100), 10)
        .unwrap();
    let first_file = file_store
        .append_at(first, GraphLogicalTime::new(100), 10)
        .unwrap();
    assert_eq!(first_memory.record, first_file.record);
    let second_memory = memory_store
        .append_at(second.clone(), GraphLogicalTime::new(200), 10)
        .unwrap();
    let second_file = file_store
        .append_at(second, GraphLogicalTime::new(200), 10)
        .unwrap();
    assert_eq!(second_memory.record, second_file.record);
    let legacy_memory = memory_store.append(legacy.clone()).unwrap();
    let legacy_file = file_store.append(legacy).unwrap();
    assert_eq!(legacy_memory.record, legacy_file.record);
    assert!(matches!(
        memory_store.append_at(
            legacy_memory.record.memory.clone(),
            GraphLogicalTime::new(100),
            10,
        ),
        Err(swarm_spine::StrategyMemoryStoreError::InvalidState { .. })
    ));
    assert!(matches!(
        file_store.append_at(
            legacy_file.record.memory.clone(),
            GraphLogicalTime::new(100),
            10,
        ),
        Err(swarm_spine::StrategyMemoryStoreError::InvalidState { .. })
    ));
    assert_eq!(
        memory_store.state_digest().unwrap(),
        file_store.state_digest().unwrap()
    );

    let graph_id = GraphId::new("graph:memory-contract");
    let hypothesis_id = HypothesisId::new("hypothesis:selected");
    let evidence = BTreeSet::from([EvidenceId::new("evidence:first")]);
    for now in [GraphLogicalTime::new(99), GraphLogicalTime::new(110)] {
        assert!(
            memory_store
                .retrieve_at(&graph_id, &hypothesis_id, &evidence, now, 8)
                .unwrap()
                .is_empty()
        );
        assert!(
            file_store
                .retrieve_at(&graph_id, &hypothesis_id, &evidence, now, 8)
                .unwrap()
                .is_empty()
        );
    }
    for now in [GraphLogicalTime::new(100), GraphLogicalTime::new(109)] {
        let memory_matches = memory_store
            .retrieve_at(&graph_id, &hypothesis_id, &evidence, now, 8)
            .unwrap();
        let file_matches = file_store
            .retrieve_at(&graph_id, &hypothesis_id, &evidence, now, 8)
            .unwrap();
        assert_eq!(memory_matches, file_matches);
        assert_eq!(memory_matches.len(), 1);
        assert_eq!(
            memory_matches[0].record.memory.memory_id,
            first_memory.record.memory.memory_id
        );
    }

    let root = file_store.root().to_path_buf();
    drop(file_store);
    let reopened =
        FileStrategyMemoryStore::open_with_signer(&root, key, GraphResourceLimits::default())
            .unwrap();
    let reopened_matches = reopened
        .retrieve_at(
            &graph_id,
            &hypothesis_id,
            &evidence,
            GraphLogicalTime::new(105),
            8,
        )
        .unwrap();
    assert_eq!(reopened_matches.len(), 1);
    assert_eq!(
        reopened.state_digest().unwrap(),
        memory_store.state_digest().unwrap()
    );
    assert!(
        reopened
            .retrieve_at(
                &graph_id,
                &hypothesis_id,
                &evidence,
                GraphLogicalTime::new(110),
                8,
            )
            .unwrap()
            .is_empty()
    );
    drop(reopened);
    let _ = fs::remove_dir_all(path);
}

#[test]
fn configured_memory_ttl_ceiling_rejects_lower_append_and_restart_mutation() {
    let config = HypothesisGraphConfig {
        max_memory_ttl_ticks: 5,
        ..HypothesisGraphConfig::default()
    };
    let key = signer(29);
    let memory_store = MemoryStrategyMemoryStore::new_with_config(key.clone(), &config).unwrap();
    let first = memory(30, "configured-ttl-memory");
    let before = memory_store.state_digest().unwrap();
    assert!(
        memory_store
            .append_at(first.clone(), GraphLogicalTime::new(100), 6)
            .is_err()
    );
    assert_eq!(memory_store.state_digest().unwrap(), before);
    memory_store
        .append_at(first, GraphLogicalTime::new(100), 5)
        .unwrap();

    let path = temp_dir("configured-ttl-file");
    let file_store = FileStrategyMemoryStore::new_with_config(&path, key.clone(), &config).unwrap();
    let second = memory(31, "configured-ttl-file");
    let before = file_store.state_digest().unwrap();
    assert!(
        file_store
            .append_at(second.clone(), GraphLogicalTime::new(100), 6)
            .is_err()
    );
    assert_eq!(file_store.state_digest().unwrap(), before);
    file_store
        .append_at(second, GraphLogicalTime::new(100), 5)
        .unwrap();
    drop(file_store);

    let mut lower = config.clone();
    lower.max_memory_ttl_ticks = 4;
    assert!(FileStrategyMemoryStore::open_with_config(&path, key.clone(), &lower).is_err());
    let reopened = FileStrategyMemoryStore::open_with_config(&path, key, &config).unwrap();
    assert!(reopened.state_digest().is_ok());
    drop(reopened);
    let _ = fs::remove_dir_all(path);
}

#[test]
fn append_at_idempotency_is_bound_to_the_exact_expiry_envelope() {
    let key = signer(32);
    let candidate = memory(33, "expiry-idempotency");
    let graph_id = candidate.graph_id.clone();
    let hypothesis_id = candidate.selected_hypothesis_id.clone();

    let memory_store = MemoryStrategyMemoryStore::with_defaults(key.clone()).unwrap();
    memory_store
        .append_at(candidate.clone(), GraphLogicalTime::new(100), 10)
        .unwrap();
    let memory_digest = memory_store.state_digest().unwrap();
    assert!(
        memory_store
            .append_at(candidate.clone(), GraphLogicalTime::new(100), 10)
            .unwrap()
            .idempotent
    );
    assert!(
        memory_store
            .append_at(candidate.clone(), GraphLogicalTime::new(101), 10)
            .is_err(),
        "altered creation time must not be accepted as an idempotent retry"
    );
    assert!(
        memory_store
            .append_at(candidate.clone(), GraphLogicalTime::new(100), 11)
            .is_err(),
        "altered TTL must not be accepted as an idempotent retry"
    );
    assert!(
        memory_store.append(candidate.clone()).is_err(),
        "removing expiry must not be accepted as an idempotent retry"
    );
    assert_eq!(memory_store.state_digest().unwrap(), memory_digest);
    assert!(
        memory_store
            .retrieve_at(
                &graph_id,
                &hypothesis_id,
                &BTreeSet::new(),
                GraphLogicalTime::new(110),
                8,
            )
            .unwrap()
            .is_empty(),
        "rejected retries must not extend the original expiry"
    );

    let path = temp_dir("expiry-idempotency-file");
    let file_store =
        FileStrategyMemoryStore::new(&path, key, GraphResourceLimits::default()).unwrap();
    file_store
        .append_at(candidate.clone(), GraphLogicalTime::new(100), 10)
        .unwrap();
    let file_digest = file_store.state_digest().unwrap();
    assert!(
        file_store
            .append_at(candidate.clone(), GraphLogicalTime::new(100), 10)
            .unwrap()
            .idempotent
    );
    assert!(
        file_store
            .append_at(candidate.clone(), GraphLogicalTime::new(101), 10)
            .is_err()
    );
    assert!(file_store.append(candidate.clone()).is_err());
    assert!(
        file_store
            .append_at(candidate, GraphLogicalTime::new(100), 11)
            .is_err()
    );
    assert_eq!(file_store.state_digest().unwrap(), file_digest);
    assert!(
        file_store
            .retrieve_at(
                &graph_id,
                &hypothesis_id,
                &BTreeSet::new(),
                GraphLogicalTime::new(110),
                8,
            )
            .unwrap()
            .is_empty()
    );
    drop(file_store);
    let _ = fs::remove_dir_all(path);
}
