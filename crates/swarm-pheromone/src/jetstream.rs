use crate::substrate::{
    AdmissionControl, BEHAVIORAL_BASELINE_STATE_KIND, DepositQuery, FeedbackSuppressionKey,
    FeedbackSuppressionOrder, FeedbackSuppressionState, MAX_ACTIVE_DEPOSIT_BYTES,
    MAX_ACTIVE_DEPOSITS, MAX_SINGLE_DEPOSIT_BYTES, PheromoneSubstrate, SubstrateError,
    SubstrateHealth, VerifiedDeposit, concentration_for, decode_deposit_payload,
    deposit_operation_id, deposit_suppression_key, feedback_suppression_marker, filter_deposits,
    filter_escalations, is_retention_expired, normalize_threat_intel_value,
    retention_initial_strength, trusted_system_unix_seconds, validate_deposit_policy,
    validate_deposit_retention,
};
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
#[cfg(feature = "nats")]
use sha2::{Digest, Sha256};
#[cfg(feature = "nats")]
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
#[cfg(feature = "nats")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "nats")]
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig};
use swarm_core::pheromone::{
    BehavioralBaselineSnapshot, EscalationRecord, PheromoneConcentration, PheromoneDeposit,
    ThreatClass, ThreatClassConfig, ThreatClassPolicy, ThreatIntelEntry, ThreatIntelIndicatorType,
};
use swarm_core::signed_state::{SignedStateEnvelope, SignedStateExpectation};
use swarm_core::types::AgentId;
#[cfg(feature = "nats")]
use tokio::sync::{Mutex as AsyncMutex, OnceCell};
#[cfg(feature = "nats")]
use tokio::time::timeout;
#[cfg(feature = "nats")]
use tokio_stream::StreamExt;

const DEFAULT_BUCKET_NAME: &str = "swarm-pheromone-deposits";
#[cfg(feature = "nats")]
const DEFAULT_NATS_CONNECT_TIMEOUT_MS: u64 = 5_000;
#[cfg(feature = "nats")]
const DEFAULT_JETSTREAM_GC_PAGE_SIZE: usize = 512;
#[cfg(feature = "nats")]
const GC_KEY_PREFIX: &str = "exp";
#[cfg(feature = "nats")]
const ESCALATION_KEY_PREFIX: &str = "esc";
#[cfg(feature = "nats")]
const THREAT_CLASS_CONFIG_KEY_PREFIX: &str = "cfg";
#[cfg(feature = "nats")]
const THREAT_INTEL_KEY_PREFIX: &str = "intel";
#[cfg(feature = "nats")]
const BEHAVIORAL_BASELINE_KEY_PREFIX: &str = "baseline";
#[cfg(feature = "nats")]
const GC_PAGE_SPAN_SECS: i64 = 300;
#[cfg(feature = "nats")]
const MAX_VERIFIED_DEPOSIT_CACHE_ENTRIES: usize = MAX_ACTIVE_DEPOSITS * 2;
#[cfg(feature = "nats")]
const MAX_DEPOSIT_KEY_INDEX_PARTITIONS: usize = 128;
#[cfg(feature = "nats")]
const RECENT_DEPOSIT_INDEX_KEY_PREFIX: &str = "idx_recent";
#[cfg(feature = "nats")]
const RECENT_DEPOSIT_INDEX_STATE_KEY_PREFIX: &str = "idx_recent_state";
#[cfg(feature = "nats")]
const RECENT_DEPOSIT_COMPATIBILITY_STATE_KEY: &str = "idx_recent_compatibility";
#[cfg(feature = "nats")]
const RECENT_DEPOSIT_MIGRATION_STATE_KEY: &str = "idx_recent_migration";
#[cfg(feature = "nats")]
const RECENT_DEPOSIT_INTENT_KEY_PREFIX: &str = "idx_recent_intent";
#[cfg(feature = "nats")]
const MAX_RECENT_DEPOSIT_INDEX_CAS_ATTEMPTS: usize = 256;
#[cfg(feature = "nats")]
const MAX_JETSTREAM_BUCKET_BYTES: i64 = 128 * 1024 * 1024;
#[cfg(feature = "nats")]
const RECENT_DEPOSIT_SCOPE_READ_CONCURRENCY: usize = 32;
// Previous releases placed intents in this finite four-choice namespace. Keep
// it readable for rolling upgrades, but never place a new operation there:
// occupied choices permanently rejected unrelated valid operations.
#[cfg(feature = "nats")]
const MAX_IDEMPOTENT_DEPOSIT_INTENT_SLOTS: u64 = 262_139;
#[cfg(feature = "nats")]
const IDEMPOTENT_DEPOSIT_INTENT_SLOT_CHOICES: usize = 4;
// The runtime's largest periodic request is 100 records. The additional 27
// slots absorb recently suppressed or expired records without making the hot
// path proportional to the bucket's lifetime subject count. Evidence and
// zero-strength control records have independent rings so one class cannot
// evict the other before feedback suppression is applied.
#[cfg(feature = "nats")]
const MAX_RECENT_DEPOSIT_INDEX_SLOTS: u64 = 127;

#[cfg(feature = "nats")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum DepositKeyKind {
    Evidence,
    Control,
}

#[cfg(feature = "nats")]
#[derive(Debug, Clone)]
struct CachedVerifiedDeposit {
    revision: u64,
    deposit: VerifiedDeposit,
}

#[cfg(feature = "nats")]
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct RecentDepositPointer {
    ordinal: u64,
    kind: DepositKeyKind,
    deposit_key: String,
    deposit_revision: u64,
}

#[cfg(feature = "nats")]
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct RecentDepositIndexState {
    last_ordinal: u64,
    #[serde(default)]
    last_compatibility_revision: u64,
    #[serde(default)]
    last_compatibility_key: Option<String>,
    #[serde(default)]
    last_compatibility_ordinal: u64,
    /// Two-phase compatibility pointer intent. The committed compatibility
    /// revision never advances until this exact pointer has been written (or
    /// has been legitimately superseded by a complete ring rotation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_compatibility_pointer: Option<RecentDepositPointer>,
}

#[cfg(feature = "nats")]
#[derive(Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct RecentDepositCompatibilityState {
    last_stream_sequence: u64,
}

#[cfg(feature = "nats")]
#[derive(Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct RecentDepositMigrationState {
    boundary_stream_sequence: u64,
}

#[cfg(feature = "nats")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct IdempotentDepositIntent {
    operation_id: String,
    payload_digest: String,
    kind: DepositKeyKind,
    ordinal: u64,
    deposit_key: String,
    #[serde(default)]
    committed_deposit_revision: Option<u64>,
}

#[cfg(feature = "nats")]
#[derive(Debug)]
struct StoredIdempotentDepositIntent {
    key: String,
    revision: u64,
    intent: IdempotentDepositIntent,
}

#[cfg(feature = "nats")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecentDepositPointerWrite {
    Indexed,
    Superseded,
}

#[cfg(all(test, feature = "nats"))]
#[derive(Debug)]
struct RecentDepositPointerCasHook {
    armed: std::sync::atomic::AtomicBool,
    reached: tokio::sync::Barrier,
    release: tokio::sync::Barrier,
}

#[cfg(all(test, feature = "nats"))]
impl RecentDepositPointerCasHook {
    fn new() -> Self {
        Self {
            armed: std::sync::atomic::AtomicBool::new(true),
            reached: tokio::sync::Barrier::new(2),
            release: tokio::sync::Barrier::new(2),
        }
    }

    async fn pause_once(&self) {
        if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            self.reached.wait().await;
            self.release.wait().await;
        }
    }
}

#[cfg(feature = "nats")]
#[derive(Debug, Clone)]
struct SelectedDepositKey {
    key: String,
    kind: Option<DepositKeyKind>,
    expected_revision: Option<u64>,
    expected_encoded_len: Option<usize>,
    suppression_scope_digest: Option<String>,
}

/// Bounded, revision-aware cache for deposits that have already crossed the
/// full signature and structural admission boundary. JetStream revisions are
/// immutable, so an exact `(key, revision)` hit can safely avoid repeating
/// Ed25519 verification on every concentration scan. A revision change always
/// misses and therefore re-runs admission before the cache is updated.
#[cfg(feature = "nats")]
#[derive(Debug, Default)]
struct VerifiedDepositCache {
    entries: BTreeMap<String, CachedVerifiedDeposit>,
    encoded_bytes: usize,
}

#[cfg(feature = "nats")]
impl VerifiedDepositCache {
    fn get(&self, key: &str, revision: u64) -> Option<VerifiedDeposit> {
        self.entries
            .get(key)
            .filter(|entry| entry.revision == revision)
            .map(|entry| entry.deposit.clone())
    }

    fn insert(&mut self, key: String, revision: u64, deposit: VerifiedDeposit) {
        if let Some(previous) = self.entries.remove(&key) {
            self.encoded_bytes = self
                .encoded_bytes
                .saturating_sub(previous.deposit.encoded_len());
        }
        let encoded_len = deposit.encoded_len();
        while !self.entries.is_empty()
            && (self.entries.len() >= MAX_VERIFIED_DEPOSIT_CACHE_ENTRIES
                || self.encoded_bytes.saturating_add(encoded_len) > MAX_ACTIVE_DEPOSIT_BYTES)
        {
            let Some(evicted) = self.entries.keys().next().cloned() else {
                break;
            };
            if let Some(evicted) = self.entries.remove(&evicted) {
                self.encoded_bytes = self
                    .encoded_bytes
                    .saturating_sub(evicted.deposit.encoded_len());
            }
        }
        self.encoded_bytes = self.encoded_bytes.saturating_add(encoded_len);
        self.entries
            .insert(key, CachedVerifiedDeposit { revision, deposit });
    }

    fn remove(&mut self, key: &str) {
        if let Some(removed) = self.entries.remove(key) {
            self.encoded_bytes = self
                .encoded_bytes
                .saturating_sub(removed.deposit.encoded_len());
        }
    }
}

#[cfg(feature = "nats")]
#[derive(Debug, Clone)]
struct IndexedDepositKey {
    timestamp: i64,
    key: String,
    encoded_len: usize,
    suppression_key: Option<FeedbackSuppressionKey>,
    feedback_marker: Option<IndexedFeedbackMarker>,
}

#[cfg(feature = "nats")]
#[derive(Debug, Clone)]
struct IndexedFeedbackMarker {
    key: FeedbackSuppressionKey,
    state: FeedbackSuppressionState,
    order: FeedbackSuppressionOrder,
}

#[cfg(feature = "nats")]
impl PartialEq for IndexedDepositKey {
    fn eq(&self, other: &Self) -> bool {
        self.timestamp == other.timestamp && self.key == other.key
    }
}

#[cfg(feature = "nats")]
impl Eq for IndexedDepositKey {}

#[cfg(feature = "nats")]
impl PartialOrd for IndexedDepositKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(feature = "nats")]
impl Ord for IndexedDepositKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.timestamp
            .cmp(&other.timestamp)
            .then_with(|| self.key.cmp(&other.key))
    }
}

#[cfg(feature = "nats")]
fn retain_newest_deposit_key(window: &mut BTreeSet<(i64, String)>, key: String, limit: usize) {
    let _ = insert_newest_deposit_key(window, key, limit);
}

#[cfg(feature = "nats")]
fn insert_newest_deposit_key(
    window: &mut BTreeSet<(i64, String)>,
    key: String,
    limit: usize,
) -> Option<String> {
    window.insert((deposit_key_timestamp(&key).unwrap_or(i64::MIN), key));
    if window.len() > limit
        && let Some(oldest) = window.first().cloned()
    {
        window.remove(&oldest);
        return Some(oldest.1);
    }
    None
}

#[cfg(feature = "nats")]
fn select_recent_deposit_keys_within_byte_limit(
    mut selected: Vec<SelectedDepositKey>,
) -> Vec<SelectedDepositKey> {
    let selection_order = |left: &SelectedDepositKey, right: &SelectedDepositKey| {
        // Control records include terminal dismissals. Admit the bounded
        // control ring before evidence at equal quota and order by recency
        // within each class.
        right
            .kind
            .or_else(|| deposit_key_kind(&right.key))
            .map(deposit_kind_selection_priority)
            .cmp(
                &left
                    .kind
                    .or_else(|| deposit_key_kind(&left.key))
                    .map(deposit_kind_selection_priority),
            )
            .then_with(|| deposit_key_timestamp(&right.key).cmp(&deposit_key_timestamp(&left.key)))
            .then_with(|| right.key.cmp(&left.key))
    };
    selected.sort_by(selection_order);

    let mut controls = Vec::new();
    let mut evidence = Vec::new();
    for candidate in selected {
        let kind = candidate.kind.or_else(|| deposit_key_kind(&candidate.key));
        if kind == Some(DepositKeyKind::Control) {
            controls.push(candidate);
        } else {
            // Prior-layout keys cannot prove their kind without a load. Keep
            // them in the evidence quota so current controls cannot starve
            // both current evidence and the rolling-upgrade compatibility set.
            evidence.push(candidate);
        }
    }

    let mut controls_by_scope = BTreeMap::<String, Vec<SelectedDepositKey>>::new();
    for control in &controls {
        if let Some(scope) = &control.suppression_scope_digest {
            controls_by_scope
                .entry(scope.clone())
                .or_default()
                .push(control.clone());
        }
    }

    let mut admitted = Vec::new();
    let mut admitted_keys = BTreeSet::new();
    let mut admitted_bytes = 0usize;
    let evidence_reservation = MAX_ACTIVE_DEPOSIT_BYTES / 2;
    let mut reserved_evidence_bytes = 0usize;

    // Admit recent evidence first, but atomically with every terminal-control
    // candidate for its authenticated suppression scope. The reader derives
    // every event-bearing pointer scope before selection; a missing scope is
    // therefore unscoped and cannot suppress evidence. A scoped pair that
    // cannot fit is omitted together.
    for evidence_candidate in &evidence {
        let Some(evidence_bytes) = selected_deposit_encoded_len(evidence_candidate) else {
            continue;
        };
        if reserved_evidence_bytes.saturating_add(evidence_bytes) > evidence_reservation {
            continue;
        }
        let required_controls = controls_by_scope
            .get(
                evidence_candidate
                    .suppression_scope_digest
                    .as_deref()
                    .unwrap_or_default(),
            )
            .map(Vec::as_slice)
            .unwrap_or_default();
        if !selected_group_fits(
            required_controls,
            evidence_candidate,
            &admitted_keys,
            admitted_bytes,
        ) {
            continue;
        }
        for control in required_controls {
            admit_selected_deposit(
                control.clone(),
                &mut admitted,
                &mut admitted_keys,
                &mut admitted_bytes,
            );
        }
        admit_selected_deposit(
            evidence_candidate.clone(),
            &mut admitted,
            &mut admitted_keys,
            &mut admitted_bytes,
        );
        reserved_evidence_bytes = reserved_evidence_bytes.saturating_add(evidence_bytes);
    }

    // Fill remaining aggregate capacity with additional scoped evidence, then
    // unrelated controls. This preserves evidence availability without ever
    // admitting governed evidence separately from its terminal-control view.
    for evidence_candidate in &evidence {
        if admitted_keys.contains(&evidence_candidate.key) {
            continue;
        }
        let required_controls = controls_by_scope
            .get(
                evidence_candidate
                    .suppression_scope_digest
                    .as_deref()
                    .unwrap_or_default(),
            )
            .map(Vec::as_slice)
            .unwrap_or_default();
        if !selected_group_fits(
            required_controls,
            evidence_candidate,
            &admitted_keys,
            admitted_bytes,
        ) {
            continue;
        }
        for control in required_controls {
            admit_selected_deposit(
                control.clone(),
                &mut admitted,
                &mut admitted_keys,
                &mut admitted_bytes,
            );
        }
        admit_selected_deposit(
            evidence_candidate.clone(),
            &mut admitted,
            &mut admitted_keys,
            &mut admitted_bytes,
        );
    }
    for control in controls {
        admit_selected_deposit(
            control,
            &mut admitted,
            &mut admitted_keys,
            &mut admitted_bytes,
        );
    }
    admitted.sort_by(selection_order);
    admitted
}

#[cfg(feature = "nats")]
fn selected_deposit_encoded_len(candidate: &SelectedDepositKey) -> Option<usize> {
    let encoded_len = candidate
        .expected_encoded_len
        .unwrap_or(MAX_SINGLE_DEPOSIT_BYTES);
    (encoded_len > 0 && encoded_len <= MAX_SINGLE_DEPOSIT_BYTES).then_some(encoded_len)
}

#[cfg(feature = "nats")]
fn selected_group_fits(
    controls: &[SelectedDepositKey],
    evidence: &SelectedDepositKey,
    admitted_keys: &BTreeSet<String>,
    admitted_bytes: usize,
) -> bool {
    let mut additional = selected_deposit_encoded_len(evidence).unwrap_or(usize::MAX);
    for control in controls {
        if !admitted_keys.contains(&control.key) {
            additional = additional
                .saturating_add(selected_deposit_encoded_len(control).unwrap_or(usize::MAX));
        }
    }
    admitted_bytes.saturating_add(additional) <= MAX_ACTIVE_DEPOSIT_BYTES
}

#[cfg(feature = "nats")]
fn admit_selected_deposit(
    candidate: SelectedDepositKey,
    admitted: &mut Vec<SelectedDepositKey>,
    admitted_keys: &mut BTreeSet<String>,
    admitted_bytes: &mut usize,
) {
    if admitted_keys.contains(&candidate.key) {
        return;
    }
    let Some(encoded_len) = selected_deposit_encoded_len(&candidate) else {
        return;
    };
    if admitted_bytes.saturating_add(encoded_len) > MAX_ACTIVE_DEPOSIT_BYTES {
        return;
    }
    *admitted_bytes = admitted_bytes.saturating_add(encoded_len);
    admitted_keys.insert(candidate.key.clone());
    admitted.push(candidate);
}

#[cfg(feature = "nats")]
fn balance_recent_deposit_results(
    mut deposits: Vec<PheromoneDeposit>,
    limit: usize,
) -> Vec<PheromoneDeposit> {
    if limit == 0 || deposits.len() <= limit {
        return deposits;
    }

    let evidence_available = deposits
        .iter()
        .filter(|deposit| deposit_kind(deposit) == DepositKeyKind::Evidence)
        .count();
    let control_available = deposits.len().saturating_sub(evidence_available);
    if evidence_available == 0 || control_available == 0 {
        deposits.truncate(limit);
        return deposits;
    }

    let evidence_target = evidence_available.min(limit.div_ceil(2));
    let control_target = control_available.min(limit / 2);
    let mut selected = vec![false; deposits.len()];
    let mut selected_evidence = 0usize;
    let mut selected_controls = 0usize;
    let mut selected_count = 0usize;
    for (index, deposit) in deposits.iter().enumerate() {
        let take = match deposit_kind(deposit) {
            DepositKeyKind::Evidence if selected_evidence < evidence_target => {
                selected_evidence = selected_evidence.saturating_add(1);
                true
            }
            DepositKeyKind::Control if selected_controls < control_target => {
                selected_controls = selected_controls.saturating_add(1);
                true
            }
            _ => false,
        };
        if take {
            selected[index] = true;
            selected_count = selected_count.saturating_add(1);
        }
    }

    // If either class could not fill its reservation, use the newest remaining
    // records regardless of class. The vector is already newest-first after
    // feedback suppression, so this preserves the public ordering contract.
    if selected_count < limit {
        for is_selected in &mut selected {
            if !*is_selected {
                *is_selected = true;
                selected_count = selected_count.saturating_add(1);
                if selected_count == limit {
                    break;
                }
            }
        }
    }

    deposits
        .into_iter()
        .zip(selected)
        .filter_map(|(deposit, selected)| selected.then_some(deposit))
        .collect()
}

#[cfg(feature = "nats")]
fn deposit_kind_selection_priority(kind: DepositKeyKind) -> u8 {
    match kind {
        DepositKeyKind::Evidence => 0,
        DepositKeyKind::Control => 1,
    }
}

#[cfg(feature = "nats")]
fn retain_newest_partitioned_deposit_key_as(
    evidence_window: &mut BTreeSet<(i64, String)>,
    control_window: &mut BTreeSet<(i64, String)>,
    key: String,
    kind: DepositKeyKind,
    limit: usize,
) {
    let window = match kind {
        DepositKeyKind::Control => control_window,
        DepositKeyKind::Evidence => evidence_window,
    };
    retain_newest_deposit_key(window, key, limit);
}

#[cfg(feature = "nats")]
#[derive(Debug, Default)]
struct DepositKeyScanCursor {
    initialized: bool,
    last_sequence: u64,
}

#[cfg(feature = "nats")]
#[derive(Debug, Clone, Copy)]
enum DepositKeyLayout {
    Current,
    Legacy,
    LegacyCustomCurrent,
    LegacyCustomLegacy,
}

#[cfg(feature = "nats")]
impl DepositKeyLayout {
    fn allows_colliding_legacy_custom_class(self) -> bool {
        matches!(self, Self::LegacyCustomCurrent | Self::LegacyCustomLegacy)
    }
}

#[cfg(feature = "nats")]
#[derive(Debug, Clone, Copy)]
struct DepositKeyRefreshBounds {
    high_water: u64,
    retention_now: Option<i64>,
    retention_half_life_secs: Option<f64>,
    retention_evaporation_threshold: Option<f64>,
    partition_limit: usize,
}

#[cfg(feature = "nats")]
#[derive(Debug, Default)]
struct DepositKeyPartitionIndex {
    evidence: BTreeSet<IndexedDepositKey>,
    controls: BTreeSet<IndexedDepositKey>,
    evidence_bytes: usize,
    control_bytes: usize,
    current_layout: DepositKeyScanCursor,
    legacy_layout: DepositKeyScanCursor,
    legacy_custom_current_layout: DepositKeyScanCursor,
    legacy_custom_legacy_layout: DepositKeyScanCursor,
}

#[cfg(feature = "nats")]
impl DepositKeyPartitionIndex {
    fn insert_for_feedback_reconciliation(
        &mut self,
        indexed: IndexedDepositKey,
        kind: DepositKeyKind,
    ) {
        let _ = self.remove_key(&indexed.key);
        match kind {
            DepositKeyKind::Evidence => {
                self.evidence_bytes = self.evidence_bytes.saturating_add(indexed.encoded_len);
                self.evidence.insert(indexed);
            }
            DepositKeyKind::Control => {
                self.control_bytes = self.control_bytes.saturating_add(indexed.encoded_len);
                self.controls.insert(indexed);
            }
        }
    }

    fn remove_key(&mut self, key: &str) -> Option<IndexedDepositKey> {
        let evidence = self
            .evidence
            .iter()
            .find(|candidate| candidate.key == key)
            .cloned();
        if let Some(evidence) = evidence {
            self.evidence.remove(&evidence);
            self.evidence_bytes = self.evidence_bytes.saturating_sub(evidence.encoded_len);
            return Some(evidence);
        }
        let control = self
            .controls
            .iter()
            .find(|candidate| candidate.key == key)
            .cloned();
        if let Some(control) = control {
            self.controls.remove(&control);
            self.control_bytes = self.control_bytes.saturating_sub(control.encoded_len);
            return Some(control);
        }
        None
    }

    fn remove_oldest(&mut self, kind: DepositKeyKind) -> Option<IndexedDepositKey> {
        let oldest = match kind {
            DepositKeyKind::Evidence => self.evidence.first().cloned(),
            DepositKeyKind::Control => self.controls.first().cloned(),
        }?;
        self.remove_key(&oldest.key)
    }

    fn insert_bounded(
        &mut self,
        indexed: IndexedDepositKey,
        kind: DepositKeyKind,
        count_limit: usize,
    ) -> Vec<IndexedDepositKey> {
        let mut removed = Vec::new();
        self.insert_for_feedback_reconciliation(indexed, kind);

        while self.evidence.len() > count_limit {
            if let Some(evicted) = self.remove_oldest(DepositKeyKind::Evidence) {
                removed.push(evicted);
            }
        }
        while self.controls.len() > count_limit {
            if let Some(evicted) = self.remove_oldest(DepositKeyKind::Control) {
                removed.push(evicted);
            }
        }
        while self.evidence_bytes.saturating_add(self.control_bytes) > MAX_ACTIVE_DEPOSIT_BYTES {
            let kind = if self.evidence_bytes >= self.control_bytes {
                DepositKeyKind::Evidence
            } else {
                DepositKeyKind::Control
            };
            let Some(evicted) = self.remove_oldest(kind).or_else(|| {
                self.remove_oldest(match kind {
                    DepositKeyKind::Evidence => DepositKeyKind::Control,
                    DepositKeyKind::Control => DepositKeyKind::Evidence,
                })
            }) else {
                break;
            };
            removed.push(evicted);
        }
        removed
    }

    fn remove_evidence_orphaned_by_feedback(
        &mut self,
        removed: &IndexedDepositKey,
    ) -> Vec<IndexedDepositKey> {
        let Some(removed_marker) = removed.feedback_marker.as_ref() else {
            return Vec::new();
        };
        if self.controls.iter().chain(&self.evidence).any(|entry| {
            entry.feedback_marker.as_ref().is_some_and(|candidate| {
                candidate.key == removed_marker.key
                    && (candidate.order > removed_marker.order
                        || (candidate.order == removed_marker.order && entry.key > removed.key))
            })
        }) {
            return Vec::new();
        }
        let superseded_markers = self
            .controls
            .iter()
            .chain(&self.evidence)
            .filter(|entry| {
                entry.feedback_marker.as_ref().is_some_and(|candidate| {
                    candidate.key == removed_marker.key && candidate.order <= removed_marker.order
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        for entry in &superseded_markers {
            let _ = self.remove_key(&entry.key);
        }
        if removed_marker.state == FeedbackSuppressionState::Confirm {
            // A terminal confirmation cannot be represented once its marker
            // is evicted. Remove every superseded marker for the same event so
            // an older dismissal cannot become current again; ordinary
            // positive evidence remains active.
            return superseded_markers;
        }
        let mut related = self
            .evidence
            .iter()
            .filter(|entry| {
                entry.suppression_key.as_ref() == Some(&removed_marker.key)
                    && removed_marker
                        .order
                        .governs_evidence_timestamp(entry.timestamp)
            })
            .cloned()
            .collect::<Vec<_>>();
        for entry in &related {
            let _ = self.remove_key(&entry.key);
        }
        related.extend(superseded_markers);
        related
    }

    fn total_bytes(&self) -> usize {
        self.evidence_bytes.saturating_add(self.control_bytes)
    }
}

#[cfg(feature = "nats")]
#[derive(Debug, Default)]
struct DepositKeyIndexes {
    partitions: BTreeMap<String, DepositKeyPartitionIndex>,
}

#[cfg(feature = "nats")]
impl DepositKeyIndexes {
    fn make_room_for(&mut self, segment: &str) {
        if self.partitions.contains_key(segment) {
            return;
        }
        while self.partitions.len() >= MAX_DEPOSIT_KEY_INDEX_PARTITIONS {
            let Some(evicted) = self.partitions.keys().next().cloned() else {
                break;
            };
            self.partitions.remove(&evicted);
        }
    }

    fn enforce_global_byte_bound(&mut self, current_segment: &str) {
        while self
            .partitions
            .values()
            .map(DepositKeyPartitionIndex::total_bytes)
            .sum::<usize>()
            > MAX_ACTIVE_DEPOSIT_BYTES
        {
            let evicted = self
                .partitions
                .keys()
                .find(|segment| segment.as_str() != current_segment)
                .cloned();
            let Some(evicted) = evicted else {
                break;
            };
            self.partitions.remove(&evicted);
        }
    }
}

/// JetStream-backed durable pheromone substrate.
#[derive(Clone)]
pub struct JetStreamPheromoneSubstrate {
    config: PheromoneConfig,
    admission_control: AdmissionControl,
    url: String,
    bucket: String,
    #[cfg(feature = "nats")]
    connect_timeout_ms: u64,
    #[cfg(feature = "nats")]
    gc_page_size: usize,
    #[cfg(feature = "nats")]
    connection: Arc<OnceCell<JetStreamConnection>>,
    #[cfg(feature = "nats")]
    gc_page_cursor: Arc<Mutex<Option<i64>>>,
    #[cfg(feature = "nats")]
    legacy_gc_complete: Arc<Mutex<bool>>,
    #[cfg(feature = "nats")]
    verified_deposit_cache: Arc<Mutex<VerifiedDepositCache>>,
    #[cfg(feature = "nats")]
    deposit_key_indexes: Arc<AsyncMutex<DepositKeyIndexes>>,
}

#[cfg(feature = "nats")]
struct JetStreamConnection {
    client: async_nats::Client,
    store: async_nats::jetstream::kv::Store,
}

#[cfg(feature = "nats")]
enum NatsAuthentication {
    None,
    Token(String),
    UserPassword { username: String, password: String },
}

#[cfg(feature = "nats")]
struct NatsEndpoint {
    server_url: String,
    display_url: String,
    authentication: NatsAuthentication,
}

#[cfg(feature = "nats")]
fn decode_nats_credential(component: &str, label: &'static str) -> Result<String, SubstrateError> {
    percent_encoding::percent_decode_str(component)
        .decode_utf8()
        .map(|decoded| decoded.into_owned())
        .map_err(|_| SubstrateError::Nats {
            operation: "parse endpoint",
            reason: format!("NATS {label} is not valid UTF-8"),
        })
}

#[cfg(feature = "nats")]
fn parse_nats_endpoint(raw_url: &str) -> Result<NatsEndpoint, SubstrateError> {
    let mut parsed = url::Url::parse(raw_url).map_err(|error| SubstrateError::Nats {
        operation: "parse endpoint",
        reason: format!("invalid NATS endpoint: {error}"),
    })?;
    if !matches!(parsed.scheme(), "nats" | "tls" | "ws" | "wss") {
        return Err(SubstrateError::Nats {
            operation: "parse endpoint",
            reason: format!("unsupported NATS endpoint scheme `{}`", parsed.scheme()),
        });
    }

    let username = decode_nats_credential(parsed.username(), "username")?;
    let password = parsed
        .password()
        .map(|value| decode_nats_credential(value, "password"))
        .transpose()?;
    let authentication = match (username.is_empty(), password) {
        (true, None) => NatsAuthentication::None,
        (false, None) => NatsAuthentication::Token(username),
        (false, Some(password)) => NatsAuthentication::UserPassword { username, password },
        (true, Some(_)) => {
            return Err(SubstrateError::Nats {
                operation: "parse endpoint",
                reason: "NATS endpoint password requires a username".to_string(),
            });
        }
    };
    parsed.set_username("").map_err(|()| SubstrateError::Nats {
        operation: "parse endpoint",
        reason: "NATS endpoint does not support an authority username".to_string(),
    })?;
    parsed
        .set_password(None)
        .map_err(|()| SubstrateError::Nats {
            operation: "parse endpoint",
            reason: "NATS endpoint does not support an authority password".to_string(),
        })?;
    let server_url = parsed.to_string();
    Ok(NatsEndpoint {
        display_url: server_url.clone(),
        server_url,
        authentication,
    })
}

#[cfg(feature = "nats")]
async fn connect_nats_endpoint(
    endpoint: NatsEndpoint,
) -> Result<async_nats::Client, SubstrateError> {
    let options = match endpoint.authentication {
        NatsAuthentication::None => async_nats::ConnectOptions::new(),
        NatsAuthentication::Token(token) => async_nats::ConnectOptions::with_token(token),
        NatsAuthentication::UserPassword { username, password } => {
            async_nats::ConnectOptions::with_user_and_password(username, password)
        }
    };
    options
        .connect(endpoint.server_url)
        .await
        .map_err(|error| nats_error("connect", error))
}

impl fmt::Debug for JetStreamPheromoneSubstrate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(feature = "nats")]
        let endpoint = parse_nats_endpoint(&self.url)
            .map(|parsed| parsed.display_url)
            .unwrap_or_else(|_| "<invalid NATS endpoint>".to_string());
        #[cfg(not(feature = "nats"))]
        let endpoint = "<NATS support disabled>";
        f.debug_struct("JetStreamPheromoneSubstrate")
            .field("url", &endpoint)
            .field("bucket", &self.bucket)
            .finish()
    }
}

impl JetStreamPheromoneSubstrate {
    pub fn new(config: PheromoneConfig, url: impl Into<String>) -> Self {
        Self::with_bucket(config, url, DEFAULT_BUCKET_NAME)
    }

    pub fn with_bucket(
        config: PheromoneConfig,
        url: impl Into<String>,
        bucket: impl Into<String>,
    ) -> Self {
        #[cfg(feature = "nats")]
        let (connect_timeout_ms, gc_page_size) = match &config.backend {
            PheromoneBackendConfig::JetStream {
                connect_timeout_ms,
                gc_page_size,
                ..
            } => (*connect_timeout_ms, *gc_page_size),
            _ => (
                DEFAULT_NATS_CONNECT_TIMEOUT_MS,
                DEFAULT_JETSTREAM_GC_PAGE_SIZE,
            ),
        };

        Self {
            config,
            admission_control: AdmissionControl::default(),
            url: url.into(),
            bucket: bucket.into(),
            #[cfg(feature = "nats")]
            connect_timeout_ms,
            #[cfg(feature = "nats")]
            gc_page_size,
            #[cfg(feature = "nats")]
            connection: Arc::new(OnceCell::new()),
            #[cfg(feature = "nats")]
            gc_page_cursor: Arc::new(Mutex::new(None)),
            #[cfg(feature = "nats")]
            legacy_gc_complete: Arc::new(Mutex::new(false)),
            #[cfg(feature = "nats")]
            verified_deposit_cache: Arc::new(Mutex::new(VerifiedDepositCache::default())),
            #[cfg(feature = "nats")]
            deposit_key_indexes: Arc::new(AsyncMutex::new(DepositKeyIndexes::default())),
        }
    }

    pub async fn connect(
        config: PheromoneConfig,
        url: impl Into<String>,
    ) -> Result<Self, SubstrateError> {
        let substrate = Self::new(config, url);
        substrate.ensure_connected().await?;
        Ok(substrate)
    }

    pub async fn connect_with_bucket(
        config: PheromoneConfig,
        url: impl Into<String>,
        bucket: impl Into<String>,
    ) -> Result<Self, SubstrateError> {
        let substrate = Self::with_bucket(config, url, bucket);
        substrate.ensure_connected().await?;
        Ok(substrate)
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    pub fn set_admitted_identities(
        &self,
        identities: impl IntoIterator<Item = AgentId>,
    ) -> Result<(), SubstrateError> {
        self.admission_control.set_admitted_identities(identities)
    }

    #[cfg(feature = "nats")]
    async fn ensure_connected(&self) -> Result<&JetStreamConnection, SubstrateError> {
        let endpoint = parse_nats_endpoint(&self.url)?;
        let display_url = endpoint.display_url.clone();
        let bucket = self.bucket.clone();
        let connect_timeout_ms = self.connect_timeout_ms;

        self.connection
            .get_or_try_init(|| async move {
                let client = timeout(
                    std::time::Duration::from_millis(connect_timeout_ms),
                    connect_nats_endpoint(endpoint),
                )
                .await
                .map_err(|_| SubstrateError::Nats {
                    operation: "connect",
                    reason: format!(
                        "timed out after {connect_timeout_ms}ms while connecting to {display_url}"
                    ),
                })??;
                let jetstream = async_nats::jetstream::new(client.clone());
                let store = ensure_kv_bucket(&jetstream, &bucket).await?;
                Ok(JetStreamConnection { client, store })
            })
            .await
    }

    #[cfg(feature = "nats")]
    async fn purge_deposit_key(
        &self,
        connection: &JetStreamConnection,
        key: &str,
    ) -> Result<(), SubstrateError> {
        let subject = format!("{}{}", connection.store.prefix, key);
        let response = connection
            .store
            .stream
            .purge()
            .filter(subject)
            .await
            .map_err(|error| nats_error("purge bounded deposit key", error))?;
        if !response.success {
            return Err(SubstrateError::Nats {
                operation: "purge bounded deposit key",
                reason: format!("JetStream did not confirm purge for key `{key}`"),
            });
        }
        self.verified_deposit_cache
            .lock()
            .map_err(|_| SubstrateError::PoisonedLock)?
            .remove(key);
        Ok(())
    }

    #[cfg(feature = "nats")]
    async fn resolve_idempotent_deposit_intent(
        &self,
        connection: &JetStreamConnection,
        deposit: &PheromoneDeposit,
        payload: &[u8],
        operation_id: &str,
        kind: DepositKeyKind,
        retention_policy: (f64, f64),
    ) -> Result<StoredIdempotentDepositIntent, SubstrateError> {
        use async_nats::jetstream::kv::{CreateErrorKind, Operation};

        let payload_digest = hash_prefix(payload, 64);
        // The operation locator is independent of mutable retention policy.
        // The first successful intent freezes its deposit key (and therefore
        // its GC page) in the signed-payload binding below.
        let current_key = idempotent_deposit_intent_key(operation_id);
        for _ in 0..MAX_RECENT_DEPOSIT_INDEX_CAS_ATTEMPTS {
            let legacy_key = legacy_idempotent_deposit_intent_key(operation_id);
            for (candidate_index, intent_key) in std::iter::once(legacy_key)
                .chain(idempotent_deposit_intent_slot_keys(operation_id))
                .chain(std::iter::once(current_key.clone()))
                .enumerate()
            {
                let existing = connection
                    .store
                    .entry(&intent_key)
                    .await
                    .map_err(|error| nats_error("read idempotent deposit intent", error))?
                    .filter(|entry| {
                        !matches!(entry.operation, Operation::Delete | Operation::Purge)
                    });
                let Some(existing) = existing else {
                    continue;
                };
                let location = format!("jetstream://{}/{}", self.bucket, intent_key);
                let intent = serde_json::from_slice::<IdempotentDepositIntent>(&existing.value)
                    .map_err(|source| SubstrateError::Decode { location, source })?;
                if intent.operation_id != operation_id {
                    if candidate_index == 0 || intent_key == current_key {
                        return Err(SubstrateError::InvalidDeposit {
                            reason: "Providence intent digest identifies a different operation"
                                .to_string(),
                        });
                    }
                    continue;
                }
                if intent.payload_digest != payload_digest
                    || intent.kind != kind
                    || intent.ordinal == 0
                    || deposit_key_ordinal(&intent.deposit_key)
                        .is_some_and(|ordinal| ordinal != intent.ordinal)
                    || deposit_key_kind(&intent.deposit_key) != Some(kind)
                    || deposit_key_timestamp(&intent.deposit_key) != Some(deposit.timestamp)
                    || deposit_key_encoded_len(&intent.deposit_key) != Some(payload.len())
                    || intent.committed_deposit_revision == Some(0)
                {
                    return Err(SubstrateError::InvalidDeposit {
                        reason:
                            "idempotent Providence deposit intent conflicts with the signed payload"
                                .to_string(),
                    });
                }
                return Ok(StoredIdempotentDepositIntent {
                    key: intent_key,
                    revision: existing.revision,
                    intent,
                });
            }

            let ordinal = self
                .allocate_recent_deposit_ordinal(connection, kind)
                .await?;
            let intent = IdempotentDepositIntent {
                operation_id: operation_id.to_string(),
                payload_digest: payload_digest.clone(),
                kind,
                ordinal,
                deposit_key: idempotent_deposit_key(
                    deposit,
                    payload,
                    retention_policy.0,
                    retention_policy.1,
                    operation_id,
                ),
                committed_deposit_revision: None,
            };
            let encoded = serde_json::to_vec(&intent).map_err(|source| SubstrateError::Encode {
                context: "JetStream idempotent deposit intent".to_string(),
                source,
            })?;
            match connection.store.create(&current_key, encoded.into()).await {
                Ok(revision) => {
                    return Ok(StoredIdempotentDepositIntent {
                        key: current_key.clone(),
                        revision,
                        intent,
                    });
                }
                Err(error) if error.kind() == CreateErrorKind::AlreadyExists => continue,
                Err(error) => return Err(nats_error("create idempotent deposit intent", error)),
            }
        }
        Err(SubstrateError::Nats {
            operation: "resolve idempotent deposit intent",
            reason: format!(
                "compare-and-swap contention exceeded {MAX_RECENT_DEPOSIT_INDEX_CAS_ATTEMPTS} attempts"
            ),
        })
    }

    #[cfg(feature = "nats")]
    async fn refresh_uncommitted_deposit_intent_ordinal(
        &self,
        connection: &JetStreamConnection,
        stored: &StoredIdempotentDepositIntent,
    ) -> Result<bool, SubstrateError> {
        use async_nats::jetstream::kv::{Operation, UpdateErrorKind};

        if stored.intent.committed_deposit_revision.is_some() {
            return Ok(false);
        }
        let current = connection
            .store
            .entry(&stored.key)
            .await
            .map_err(|error| nats_error("read idempotent deposit intent for refresh", error))?
            .filter(|entry| !matches!(entry.operation, Operation::Delete | Operation::Purge));
        let Some(current) = current else {
            return Ok(false);
        };
        if current.revision != stored.revision {
            return Ok(false);
        }

        let mut refreshed = stored.intent.clone();
        refreshed.ordinal = self
            .allocate_recent_deposit_ordinal(connection, refreshed.kind)
            .await?;
        let payload = serde_json::to_vec(&refreshed).map_err(|source| SubstrateError::Encode {
            context: "JetStream refreshed idempotent deposit intent".to_string(),
            source,
        })?;
        match connection
            .store
            .update(&stored.key, payload.into(), stored.revision)
            .await
        {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == UpdateErrorKind::WrongLastRevision => Ok(false),
            Err(error) => Err(nats_error("refresh idempotent deposit intent", error)),
        }
    }

    #[cfg(feature = "nats")]
    async fn commit_idempotent_deposit_intent(
        &self,
        connection: &JetStreamConnection,
        stored: &StoredIdempotentDepositIntent,
        deposit_revision: u64,
    ) -> Result<bool, SubstrateError> {
        use async_nats::jetstream::kv::UpdateErrorKind;

        if deposit_revision == 0 {
            return Err(SubstrateError::InvalidDeposit {
                reason: "idempotent deposit committed with zero JetStream revision".to_string(),
            });
        }
        let mut committed = stored.intent.clone();
        committed.committed_deposit_revision = Some(deposit_revision);
        let payload = serde_json::to_vec(&committed).map_err(|source| SubstrateError::Encode {
            context: "JetStream committed idempotent deposit intent".to_string(),
            source,
        })?;
        match connection
            .store
            .update(&stored.key, payload.into(), stored.revision)
            .await
        {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == UpdateErrorKind::WrongLastRevision => Ok(false),
            Err(error) => Err(nats_error("commit idempotent deposit intent", error)),
        }
    }

    #[cfg(feature = "nats")]
    async fn ensure_recent_deposit_index_initialized(
        &self,
        connection: &JetStreamConnection,
    ) -> Result<(), SubstrateError> {
        use async_nats::jetstream::kv::Operation;

        let mut missing = Vec::new();
        for kind in [DepositKeyKind::Evidence, DepositKeyKind::Control] {
            let state_key = recent_deposit_index_state_key(kind);
            match connection
                .store
                .entry(&state_key)
                .await
                .map_err(|error| nats_error("read recent-deposit index state", error))?
            {
                None
                | Some(async_nats::jetstream::kv::Entry {
                    operation: Operation::Delete | Operation::Purge,
                    ..
                }) => missing.push(kind),
                Some(entry) => {
                    let location = format!("jetstream://{}/{}", self.bucket, state_key);
                    serde_json::from_slice::<RecentDepositIndexState>(&entry.value)
                        .map_err(|source| SubstrateError::Decode { location, source })?;
                }
            }
        }
        let compatibility_initialized = match connection
            .store
            .entry(RECENT_DEPOSIT_COMPATIBILITY_STATE_KEY)
            .await
            .map_err(|error| nats_error("read recent-deposit compatibility state", error))?
        {
            None
            | Some(async_nats::jetstream::kv::Entry {
                operation: Operation::Delete | Operation::Purge,
                ..
            }) => false,
            Some(entry) => {
                let location = format!(
                    "jetstream://{}/{}",
                    self.bucket, RECENT_DEPOSIT_COMPATIBILITY_STATE_KEY
                );
                serde_json::from_slice::<RecentDepositCompatibilityState>(&entry.value)
                    .map_err(|source| SubstrateError::Decode { location, source })?;
                true
            }
        };
        if missing.is_empty() && compatibility_initialized {
            return Ok(());
        }
        let scans_kind = |kind| !compatibility_initialized || missing.contains(&kind);
        let migration_high_water = self.recent_deposit_migration_boundary(connection).await?;

        // One compatibility scan upgrades buckets created before the bounded
        // recent index existed. The state marker is published only after all
        // retained pointers are durable, so readers never accept a partial
        // migration. Concurrent initializers converge through monotonic slot
        // CAS and create-only state publication.
        let mut evidence_window = BTreeSet::new();
        let mut control_window = BTreeSet::new();
        let mut keys = connection
            .store
            .keys()
            .await
            .map_err(|error| nats_error("list deposits for recent-index migration", error))?;
        while let Some(entry) = keys.next().await {
            let key = entry
                .map_err(|error| nats_error("stream deposits for recent-index migration", error))?;
            if is_non_deposit_key(&key) || deposit_key_timestamp(&key).is_none() {
                continue;
            }
            let Some(kind) = self.classify_deposit_key(connection, &key).await? else {
                continue;
            };
            if !scans_kind(kind) {
                continue;
            }
            let window = match kind {
                DepositKeyKind::Evidence => &mut evidence_window,
                DepositKeyKind::Control => &mut control_window,
            };
            retain_newest_deposit_key(window, key, MAX_RECENT_DEPOSIT_INDEX_SLOTS as usize);
        }

        for (kind, window) in [
            (DepositKeyKind::Evidence, evidence_window),
            (DepositKeyKind::Control, control_window),
        ] {
            if !scans_kind(kind) {
                continue;
            }
            let mut pointers = Vec::with_capacity(window.len());
            for (_, key) in window {
                let Some(entry) =
                    connection.store.entry(&key).await.map_err(|error| {
                        nats_error("load recent-index migration deposit", error)
                    })?
                else {
                    continue;
                };
                if matches!(entry.operation, Operation::Delete | Operation::Purge) {
                    continue;
                }
                if entry.revision > migration_high_water {
                    continue;
                }
                let location = format!("jetstream://{}/{}", self.bucket, key);
                let deposit = decode_deposit_payload(&entry.value, location)?;
                self.admission_control
                    .validate_deposit_admission(&deposit)?;
                if deposit_kind(&deposit) != kind
                    || deposit_key_kind(&key).is_some_and(|key_kind| key_kind != kind)
                {
                    return Err(SubstrateError::InvalidDeposit {
                        reason: format!(
                            "JetStream migration key `{key}` class does not match its signed payload"
                        ),
                    });
                }
                pointers.push((key, entry.revision));
            }
            let existing = self
                .existing_recent_deposit_pointers(connection, kind)
                .await?;
            let (migration_pointers, effective_high_water) =
                migration_recent_deposit_pointers(kind, pointers, migration_high_water, &existing)?;
            for pointer in migration_pointers {
                self.write_recent_deposit_pointer(connection, &pointer)
                    .await?;
            }
            self.publish_recent_deposit_index_state_at_least(
                connection,
                kind,
                effective_high_water,
            )
            .await?;
        }
        self.publish_recent_deposit_compatibility_state_at_least(
            connection,
            // This cursor is a JetStream sequence, not a synthetic ring
            // ordinal. Only the shared boundary captured before both kind
            // scans proves that every deposit through the cursor was seen.
            migration_high_water,
        )
        .await?;

        Ok(())
    }

    #[cfg(feature = "nats")]
    async fn recent_deposit_migration_boundary(
        &self,
        connection: &JetStreamConnection,
    ) -> Result<u64, SubstrateError> {
        use async_nats::jetstream::kv::{CreateErrorKind, Operation};

        for _ in 0..MAX_RECENT_DEPOSIT_INDEX_CAS_ATTEMPTS {
            match connection
                .store
                .entry(RECENT_DEPOSIT_MIGRATION_STATE_KEY)
                .await
                .map_err(|error| nats_error("read recent-index migration state", error))?
            {
                Some(entry) if !matches!(entry.operation, Operation::Delete | Operation::Purge) => {
                    let location = format!(
                        "jetstream://{}/{}",
                        self.bucket, RECENT_DEPOSIT_MIGRATION_STATE_KEY
                    );
                    let state = serde_json::from_slice::<RecentDepositMigrationState>(&entry.value)
                        .map_err(|source| SubstrateError::Decode { location, source })?;
                    if state.boundary_stream_sequence == 0 {
                        return Err(SubstrateError::InvalidDeposit {
                            reason: "JetStream recent-index migration boundary is zero".to_string(),
                        });
                    }
                    return Ok(state.boundary_stream_sequence);
                }
                _ => {
                    let boundary_stream_sequence = connection
                        .store
                        .stream
                        .get_info()
                        .await
                        .map_err(|error| {
                            nats_error("read recent-index migration high-water", error)
                        })?
                        .state
                        .last_sequence;
                    if boundary_stream_sequence == 0 {
                        return Ok(0);
                    }
                    let payload = serde_json::to_vec(&RecentDepositMigrationState {
                        boundary_stream_sequence,
                    })
                    .map_err(|source| SubstrateError::Encode {
                        context: "JetStream recent-deposit migration state".to_string(),
                        source,
                    })?;
                    match connection
                        .store
                        .create(RECENT_DEPOSIT_MIGRATION_STATE_KEY, payload.into())
                        .await
                    {
                        Ok(_) => return Ok(boundary_stream_sequence),
                        Err(error) if error.kind() == CreateErrorKind::AlreadyExists => continue,
                        Err(error) => {
                            return Err(nats_error("publish recent-index migration state", error));
                        }
                    }
                }
            }
        }

        Err(SubstrateError::Nats {
            operation: "publish recent-index migration state",
            reason: format!(
                "compare-and-swap contention exceeded {MAX_RECENT_DEPOSIT_INDEX_CAS_ATTEMPTS} attempts"
            ),
        })
    }

    #[cfg(feature = "nats")]
    async fn publish_recent_deposit_index_state_at_least(
        &self,
        connection: &JetStreamConnection,
        kind: DepositKeyKind,
        minimum_ordinal: u64,
    ) -> Result<(), SubstrateError> {
        use async_nats::jetstream::kv::{CreateErrorKind, Operation, UpdateErrorKind};

        let state_key = recent_deposit_index_state_key(kind);
        for _ in 0..MAX_RECENT_DEPOSIT_INDEX_CAS_ATTEMPTS {
            let entry = connection
                .store
                .entry(&state_key)
                .await
                .map_err(|error| nats_error("read recent-deposit index state", error))?;
            match entry {
                None
                | Some(async_nats::jetstream::kv::Entry {
                    operation: Operation::Delete | Operation::Purge,
                    ..
                }) => {
                    let payload = serde_json::to_vec(&RecentDepositIndexState {
                        last_ordinal: minimum_ordinal,
                        last_compatibility_revision: 0,
                        last_compatibility_key: None,
                        last_compatibility_ordinal: 0,
                        pending_compatibility_pointer: None,
                    })
                    .map_err(|source| SubstrateError::Encode {
                        context: "JetStream recent-deposit index state".to_string(),
                        source,
                    })?;
                    match connection.store.create(&state_key, payload.into()).await {
                        Ok(_) => return Ok(()),
                        Err(error) if error.kind() == CreateErrorKind::AlreadyExists => continue,
                        Err(error) => {
                            return Err(nats_error("publish recent-deposit index state", error));
                        }
                    }
                }
                Some(entry) => {
                    let location = format!("jetstream://{}/{}", self.bucket, state_key);
                    let current = serde_json::from_slice::<RecentDepositIndexState>(&entry.value)
                        .map_err(|source| SubstrateError::Decode { location, source })?;
                    if current.last_ordinal >= minimum_ordinal {
                        return Ok(());
                    }
                    let payload = serde_json::to_vec(&RecentDepositIndexState {
                        last_ordinal: minimum_ordinal,
                        ..current
                    })
                    .map_err(|source| SubstrateError::Encode {
                        context: "JetStream recent-deposit index state".to_string(),
                        source,
                    })?;
                    match connection
                        .store
                        .update(&state_key, payload.into(), entry.revision)
                        .await
                    {
                        Ok(_) => return Ok(()),
                        Err(error) if error.kind() == UpdateErrorKind::WrongLastRevision => {
                            continue;
                        }
                        Err(error) => {
                            return Err(nats_error("publish recent-deposit index state", error));
                        }
                    }
                }
            }
        }

        Err(SubstrateError::Nats {
            operation: "publish recent-deposit index state",
            reason: format!(
                "compare-and-swap contention exceeded {MAX_RECENT_DEPOSIT_INDEX_CAS_ATTEMPTS} attempts"
            ),
        })
    }

    #[cfg(feature = "nats")]
    async fn publish_recent_deposit_compatibility_state_at_least(
        &self,
        connection: &JetStreamConnection,
        minimum_sequence: u64,
    ) -> Result<(), SubstrateError> {
        use async_nats::jetstream::kv::{CreateErrorKind, Operation, UpdateErrorKind};

        let payload = serde_json::to_vec(&RecentDepositCompatibilityState {
            last_stream_sequence: minimum_sequence,
        })
        .map_err(|source| SubstrateError::Encode {
            context: "JetStream recent-deposit compatibility state".to_string(),
            source,
        })?;
        for _ in 0..MAX_RECENT_DEPOSIT_INDEX_CAS_ATTEMPTS {
            let entry = connection
                .store
                .entry(RECENT_DEPOSIT_COMPATIBILITY_STATE_KEY)
                .await
                .map_err(|error| nats_error("read recent-deposit compatibility state", error))?;
            match entry {
                None
                | Some(async_nats::jetstream::kv::Entry {
                    operation: Operation::Delete | Operation::Purge,
                    ..
                }) => match connection
                    .store
                    .create(
                        RECENT_DEPOSIT_COMPATIBILITY_STATE_KEY,
                        payload.clone().into(),
                    )
                    .await
                {
                    Ok(_) => return Ok(()),
                    Err(error) if error.kind() == CreateErrorKind::AlreadyExists => continue,
                    Err(error) => {
                        return Err(nats_error(
                            "publish recent-deposit compatibility state",
                            error,
                        ));
                    }
                },
                Some(entry) => {
                    let location = format!(
                        "jetstream://{}/{}",
                        self.bucket, RECENT_DEPOSIT_COMPATIBILITY_STATE_KEY
                    );
                    let current =
                        serde_json::from_slice::<RecentDepositCompatibilityState>(&entry.value)
                            .map_err(|source| SubstrateError::Decode { location, source })?;
                    if current.last_stream_sequence >= minimum_sequence {
                        return Ok(());
                    }
                    match connection
                        .store
                        .update(
                            RECENT_DEPOSIT_COMPATIBILITY_STATE_KEY,
                            payload.clone().into(),
                            entry.revision,
                        )
                        .await
                    {
                        Ok(_) => return Ok(()),
                        Err(error) if error.kind() == UpdateErrorKind::WrongLastRevision => {
                            continue;
                        }
                        Err(error) => {
                            return Err(nats_error(
                                "publish recent-deposit compatibility state",
                                error,
                            ));
                        }
                    }
                }
            }
        }

        Err(SubstrateError::Nats {
            operation: "publish recent-deposit compatibility state",
            reason: format!(
                "compare-and-swap contention exceeded {MAX_RECENT_DEPOSIT_INDEX_CAS_ATTEMPTS} attempts"
            ),
        })
    }

    #[cfg(feature = "nats")]
    async fn refresh_recent_deposit_compatibility(
        &self,
        connection: &JetStreamConnection,
    ) -> Result<(), SubstrateError> {
        use async_nats::jetstream::kv::Operation;

        let high_water = connection
            .store
            .stream
            .get_info()
            .await
            .map_err(|error| nats_error("read compatibility refresh high-water", error))?
            .state
            .last_sequence;
        let state_entry = connection
            .store
            .entry(RECENT_DEPOSIT_COMPATIBILITY_STATE_KEY)
            .await
            .map_err(|error| nats_error("read recent-deposit compatibility state", error))?
            .ok_or_else(|| SubstrateError::InvalidDeposit {
                reason:
                    "JetStream recent-deposit compatibility state is missing after initialization"
                        .to_string(),
            })?;
        if matches!(state_entry.operation, Operation::Delete | Operation::Purge) {
            return Err(SubstrateError::InvalidDeposit {
                reason:
                    "JetStream recent-deposit compatibility state is deleted after initialization"
                        .to_string(),
            });
        }
        let location = format!(
            "jetstream://{}/{}",
            self.bucket, RECENT_DEPOSIT_COMPATIBILITY_STATE_KEY
        );
        let state = serde_json::from_slice::<RecentDepositCompatibilityState>(&state_entry.value)
            .map_err(|source| SubstrateError::Decode { location, source })?;
        if high_water <= state.last_stream_sequence {
            return Ok(());
        }

        let consumer = connection
            .store
            .stream
            .create_consumer(async_nats::jetstream::consumer::push::OrderedConfig {
                deliver_subject: connection.client.new_inbox(),
                description: Some("mixed-version pheromone deposit compatibility".to_string()),
                filter_subject: format!("{}{GC_KEY_PREFIX}.>", connection.store.prefix),
                replay_policy: async_nats::jetstream::consumer::ReplayPolicy::Instant,
                deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::ByStartSequence {
                    start_sequence: state.last_stream_sequence.saturating_add(1),
                },
                ..Default::default()
            })
            .await
            .map_err(|error| nats_error("create deposit compatibility consumer", error))?;

        let mut processed_through_boundary = false;
        if consumer.cached_info().num_pending != 0 {
            let mut messages = consumer
                .messages()
                .await
                .map_err(|error| nats_error("subscribe deposit compatibility consumer", error))?;
            while let Some(message) = messages.next().await {
                let message = message
                    .map_err(|error| nats_error("stream deposit compatibility writes", error))?;
                let info = message
                    .info()
                    .map_err(|error| nats_error("parse deposit compatibility metadata", error))?;
                if info.stream_sequence > high_water {
                    break;
                }
                processed_through_boundary = true;
                let removed = message
                    .message
                    .headers
                    .as_ref()
                    .and_then(|headers| headers.get("KV-Operation"))
                    .is_some_and(|operation| matches!(operation.as_str(), "DEL" | "PURGE"));
                if !removed {
                    let key = message
                        .subject
                        .strip_prefix(&connection.store.prefix)
                        .map(ToString::to_string)
                        .unwrap_or_else(|| message.subject.to_string());
                    if deposit_key_timestamp(&key).is_none() {
                        return Err(SubstrateError::InvalidDeposit {
                            reason: format!(
                                "JetStream compatibility key `{key}` is not a valid deposit key"
                            ),
                        });
                    }
                    let location = format!("jetstream://{}/{}", self.bucket, key);
                    let deposit = decode_deposit_payload(&message.message.payload, location)?;
                    self.admission_control
                        .validate_deposit_admission(&deposit)?;
                    let kind = deposit_kind(&deposit);
                    if deposit_key_kind(&key).is_some_and(|key_kind| key_kind != kind) {
                        return Err(SubstrateError::InvalidDeposit {
                            reason: format!(
                                "JetStream compatibility key `{key}` class does not match its signed payload"
                            ),
                        });
                    }
                    let embedded_ordinal = deposit_key_ordinal(&key);
                    if let Some(ordinal) = embedded_ordinal {
                        self.write_recent_deposit_pointer(
                            connection,
                            &RecentDepositPointer {
                                ordinal,
                                kind,
                                deposit_key: key,
                                deposit_revision: info.stream_sequence,
                            },
                        )
                        .await?;
                    } else {
                        self.ensure_compatibility_deposit_pointer(
                            connection,
                            kind,
                            &key,
                            info.stream_sequence,
                        )
                        .await?;
                    }
                }
                if info.stream_sequence == high_water || info.pending == 0 {
                    break;
                }
            }
        }

        // The compatibility-state write itself advances the shared KV stream.
        // If no deposit subject matched this interval, publishing that global
        // high-water would create another apparent interval on every read.
        if !processed_through_boundary {
            return Ok(());
        }

        // Advancing the persistent cursor is the commit record: it happens
        // only after every matching deposit through the captured boundary has
        // a durable ring pointer. A crash before this CAS safely replays the
        // same deterministic pointers.
        self.publish_recent_deposit_compatibility_state_at_least(connection, high_water)
            .await
    }

    #[cfg(feature = "nats")]
    async fn allocate_recent_deposit_ordinal(
        &self,
        connection: &JetStreamConnection,
        kind: DepositKeyKind,
    ) -> Result<u64, SubstrateError> {
        use async_nats::jetstream::kv::{CreateErrorKind, Operation, UpdateErrorKind};

        let state_key = recent_deposit_index_state_key(kind);
        for _ in 0..MAX_RECENT_DEPOSIT_INDEX_CAS_ATTEMPTS {
            let entry = connection
                .store
                .entry(&state_key)
                .await
                .map_err(|error| nats_error("read recent-deposit index state", error))?;
            match entry {
                None
                | Some(async_nats::jetstream::kv::Entry {
                    operation: Operation::Delete | Operation::Purge,
                    ..
                }) => {
                    let payload = serde_json::to_vec(&RecentDepositIndexState {
                        last_ordinal: 1,
                        last_compatibility_revision: 0,
                        last_compatibility_key: None,
                        last_compatibility_ordinal: 0,
                        pending_compatibility_pointer: None,
                    })
                    .map_err(|source| SubstrateError::Encode {
                        context: "JetStream recent-deposit index state".to_string(),
                        source,
                    })?;
                    match connection.store.create(&state_key, payload.into()).await {
                        Ok(_) => return Ok(1),
                        Err(error) if error.kind() == CreateErrorKind::AlreadyExists => continue,
                        Err(error) => {
                            return Err(nats_error("create recent-deposit index state", error));
                        }
                    }
                }
                Some(entry) => {
                    let location = format!("jetstream://{}/{}", self.bucket, state_key);
                    let state = serde_json::from_slice::<RecentDepositIndexState>(&entry.value)
                        .map_err(|source| SubstrateError::Decode { location, source })?;
                    let next_ordinal = state.last_ordinal.checked_add(1).ok_or_else(|| {
                        SubstrateError::InvalidDeposit {
                            reason: "JetStream recent-deposit index ordinal is exhausted"
                                .to_string(),
                        }
                    })?;
                    let payload = serde_json::to_vec(&RecentDepositIndexState {
                        last_ordinal: next_ordinal,
                        ..state
                    })
                    .map_err(|source| SubstrateError::Encode {
                        context: "JetStream recent-deposit index state".to_string(),
                        source,
                    })?;
                    match connection
                        .store
                        .update(&state_key, payload.into(), entry.revision)
                        .await
                    {
                        Ok(_) => return Ok(next_ordinal),
                        Err(error) if error.kind() == UpdateErrorKind::WrongLastRevision => {
                            continue;
                        }
                        Err(error) => {
                            return Err(nats_error("advance recent-deposit index state", error));
                        }
                    }
                }
            }
        }

        Err(SubstrateError::Nats {
            operation: "advance recent-deposit index state",
            reason: format!(
                "compare-and-swap contention exceeded {MAX_RECENT_DEPOSIT_INDEX_CAS_ATTEMPTS} attempts"
            ),
        })
    }

    #[cfg(feature = "nats")]
    async fn ensure_compatibility_deposit_pointer(
        &self,
        connection: &JetStreamConnection,
        kind: DepositKeyKind,
        deposit_key: &str,
        deposit_revision: u64,
    ) -> Result<(), SubstrateError> {
        use async_nats::jetstream::kv::{Operation, UpdateErrorKind};

        let state_key = recent_deposit_index_state_key(kind);
        for _ in 0..MAX_RECENT_DEPOSIT_INDEX_CAS_ATTEMPTS {
            let entry = connection
                .store
                .entry(&state_key)
                .await
                .map_err(|error| nats_error("read compatibility ordinal state", error))?
                .ok_or_else(|| SubstrateError::InvalidDeposit {
                    reason: format!(
                        "JetStream recent-deposit index state `{state_key}` is missing after initialization"
                    ),
                })?;
            if matches!(entry.operation, Operation::Delete | Operation::Purge) {
                return Err(SubstrateError::InvalidDeposit {
                    reason: format!(
                        "JetStream recent-deposit index state `{state_key}` is deleted after initialization"
                    ),
                });
            }
            let location = format!("jetstream://{}/{}", self.bucket, state_key);
            let mut state = serde_json::from_slice::<RecentDepositIndexState>(&entry.value)
                .map_err(|source| SubstrateError::Decode { location, source })?;
            if let Some(pending) = state.pending_compatibility_pointer.clone() {
                self.write_recent_deposit_pointer(connection, &pending)
                    .await?;
                if pending.deposit_revision >= state.last_compatibility_revision {
                    state.last_compatibility_revision = pending.deposit_revision;
                    state.last_compatibility_key = Some(pending.deposit_key.clone());
                    state.last_compatibility_ordinal = pending.ordinal;
                }
                state.pending_compatibility_pointer = None;
                let payload =
                    serde_json::to_vec(&state).map_err(|source| SubstrateError::Encode {
                        context: "JetStream committed compatibility pointer state".to_string(),
                        source,
                    })?;
                match connection
                    .store
                    .update(&state_key, payload.into(), entry.revision)
                    .await
                {
                    Ok(_) => continue,
                    Err(error) if error.kind() == UpdateErrorKind::WrongLastRevision => continue,
                    Err(error) => {
                        return Err(nats_error("commit compatibility pointer state", error));
                    }
                }
            }
            if deposit_revision < state.last_compatibility_revision {
                // A pre-two-phase process could have advanced the revision and
                // crashed before writing this pointer. Only an exact pointer
                // proves the older record is safe to skip.
                if self
                    .existing_recent_deposit_pointers(connection, kind)
                    .await?
                    .iter()
                    .any(|pointer| {
                        pointer.deposit_revision == deposit_revision
                            && pointer.deposit_key == deposit_key
                    })
                {
                    return Ok(());
                }
            }
            if deposit_revision == state.last_compatibility_revision {
                if state.last_compatibility_key.as_deref() != Some(deposit_key)
                    || state.last_compatibility_ordinal == 0
                {
                    return Err(SubstrateError::InvalidDeposit {
                        reason: format!(
                            "JetStream compatibility revision {deposit_revision} identifies conflicting deposits"
                        ),
                    });
                }
                self.write_recent_deposit_pointer(
                    connection,
                    &RecentDepositPointer {
                        ordinal: state.last_compatibility_ordinal,
                        kind,
                        deposit_key: deposit_key.to_string(),
                        deposit_revision,
                    },
                )
                .await?;
                return Ok(());
            }
            let next_ordinal = state.last_ordinal.checked_add(1).ok_or_else(|| {
                SubstrateError::InvalidDeposit {
                    reason: "JetStream recent-deposit index ordinal is exhausted".to_string(),
                }
            })?;
            let payload = serde_json::to_vec(&RecentDepositIndexState {
                last_ordinal: next_ordinal,
                pending_compatibility_pointer: Some(RecentDepositPointer {
                    ordinal: next_ordinal,
                    kind,
                    deposit_key: deposit_key.to_string(),
                    deposit_revision,
                }),
                ..state
            })
            .map_err(|source| SubstrateError::Encode {
                context: "JetStream compatibility ordinal state".to_string(),
                source,
            })?;
            match connection
                .store
                .update(&state_key, payload.into(), entry.revision)
                .await
            {
                // The next iteration writes the pointer before committing the
                // compatibility revision. Any concurrent refresher helps the
                // same durable intent to completion.
                Ok(_) => continue,
                Err(error) if error.kind() == UpdateErrorKind::WrongLastRevision => continue,
                Err(error) => {
                    return Err(nats_error("advance compatibility ordinal state", error));
                }
            }
        }

        Err(SubstrateError::Nats {
            operation: "commit compatibility pointer state",
            reason: format!(
                "compare-and-swap contention exceeded {MAX_RECENT_DEPOSIT_INDEX_CAS_ATTEMPTS} attempts"
            ),
        })
    }

    #[cfg(feature = "nats")]
    async fn write_recent_deposit_pointer(
        &self,
        connection: &JetStreamConnection,
        pointer: &RecentDepositPointer,
    ) -> Result<RecentDepositPointerWrite, SubstrateError> {
        self.write_recent_deposit_pointer_with_hook(
            connection,
            pointer,
            #[cfg(test)]
            None,
        )
        .await
    }

    #[cfg(feature = "nats")]
    async fn write_recent_deposit_pointer_with_hook(
        &self,
        connection: &JetStreamConnection,
        pointer: &RecentDepositPointer,
        #[cfg(test)] before_update: Option<&RecentDepositPointerCasHook>,
    ) -> Result<RecentDepositPointerWrite, SubstrateError> {
        use async_nats::jetstream::kv::{CreateErrorKind, Operation, UpdateErrorKind};

        if pointer.ordinal == 0
            || pointer.deposit_revision == 0
            || deposit_key_timestamp(&pointer.deposit_key).is_none()
            || deposit_key_ordinal(&pointer.deposit_key)
                .is_some_and(|ordinal| ordinal != pointer.ordinal)
            || deposit_key_kind(&pointer.deposit_key).is_some_and(|kind| kind != pointer.kind)
        {
            return Err(SubstrateError::InvalidDeposit {
                reason: "recent-deposit pointer metadata does not match its deposit key"
                    .to_string(),
            });
        }
        let key = recent_deposit_index_key(pointer.kind, pointer.ordinal);
        let payload = serde_json::to_vec(pointer).map_err(|source| SubstrateError::Encode {
            context: "JetStream recent-deposit pointer".to_string(),
            source,
        })?;
        for _ in 0..MAX_RECENT_DEPOSIT_INDEX_CAS_ATTEMPTS {
            let entry = connection
                .store
                .entry(&key)
                .await
                .map_err(|error| nats_error("read recent-deposit pointer", error))?;
            match entry {
                None
                | Some(async_nats::jetstream::kv::Entry {
                    operation: Operation::Delete | Operation::Purge,
                    ..
                }) => match connection.store.create(&key, payload.clone().into()).await {
                    Ok(_) => return Ok(RecentDepositPointerWrite::Indexed),
                    Err(error) if error.kind() == CreateErrorKind::AlreadyExists => continue,
                    Err(error) => {
                        return Err(nats_error("create recent-deposit pointer", error));
                    }
                },
                Some(entry) => {
                    let location = format!("jetstream://{}/{}", self.bucket, key);
                    let current = serde_json::from_slice::<RecentDepositPointer>(&entry.value)
                        .map_err(|source| SubstrateError::Decode { location, source })?;
                    if current.ordinal == 0
                        || current.deposit_revision == 0
                        || deposit_key_timestamp(&current.deposit_key).is_none()
                        || deposit_key_ordinal(&current.deposit_key)
                            .is_some_and(|ordinal| ordinal != current.ordinal)
                        || deposit_key_kind(&current.deposit_key)
                            .is_some_and(|kind| kind != current.kind)
                        || recent_deposit_index_key(current.kind, current.ordinal) != key
                    {
                        return Err(SubstrateError::InvalidDeposit {
                            reason: "JetStream recent index contains an invalid existing pointer"
                                .to_string(),
                        });
                    }
                    if current.ordinal == pointer.ordinal {
                        if &current == pointer {
                            return Ok(RecentDepositPointerWrite::Indexed);
                        }
                        return Err(SubstrateError::InvalidDeposit {
                            reason: format!(
                                "JetStream recent index ordinal {} identifies conflicting deposits",
                                pointer.ordinal
                            ),
                        });
                    }
                    if current.ordinal > pointer.ordinal {
                        // A delayed writer may arrive after the ring has
                        // already wrapped. It must never overwrite a newer
                        // occupant of the same slot.
                        return Ok(RecentDepositPointerWrite::Superseded);
                    }
                    #[cfg(test)]
                    if let Some(hook) = before_update {
                        hook.pause_once().await;
                    }
                    match connection
                        .store
                        .update(&key, payload.clone().into(), entry.revision)
                        .await
                    {
                        Ok(_) => {
                            if current.kind == DepositKeyKind::Control {
                                // Cleanup is authorized only by the writer
                                // that actually committed the slot CAS.  The
                                // reconciliation reads the committed ring;
                                // a losing writer must never purge evidence
                                // preserved by a concurrent confirmation.
                                let orphaned = self
                                    .recent_pointers_orphaned_by_control_eviction(
                                        connection, &current,
                                    )
                                    .await?;
                                for orphaned_pointer in orphaned {
                                    // Re-evaluate immediately before each
                                    // destructive operation so a later
                                    // committed control update can retain the
                                    // governed evidence.
                                    let still_orphaned = self
                                        .recent_pointers_orphaned_by_control_eviction(
                                            connection, &current,
                                        )
                                        .await?
                                        .iter()
                                        .any(|candidate| candidate == &orphaned_pointer);
                                    if still_orphaned {
                                        self.remove_recent_pointer_and_value_if_unchanged(
                                            connection,
                                            &orphaned_pointer,
                                        )
                                        .await?;
                                    }
                                }
                            }
                            return Ok(RecentDepositPointerWrite::Indexed);
                        }
                        Err(error) if error.kind() == UpdateErrorKind::WrongLastRevision => {
                            continue;
                        }
                        Err(error) => {
                            return Err(nats_error("update recent-deposit pointer", error));
                        }
                    }
                }
            }
        }

        Err(SubstrateError::Nats {
            operation: "write recent-deposit pointer",
            reason: format!(
                "compare-and-swap contention exceeded {MAX_RECENT_DEPOSIT_INDEX_CAS_ATTEMPTS} attempts"
            ),
        })
    }

    #[cfg(feature = "nats")]
    async fn recent_pointers_orphaned_by_control_eviction(
        &self,
        connection: &JetStreamConnection,
        evicted: &RecentDepositPointer,
    ) -> Result<Vec<RecentDepositPointer>, SubstrateError> {
        let removed = self
            .indexed_recent_pointer_entry(connection, evicted)
            .await?;
        if removed.feedback_marker.is_none() {
            return Ok(Vec::new());
        }

        let mut pointers = self
            .existing_recent_deposit_pointers(connection, DepositKeyKind::Evidence)
            .await?;
        pointers.extend(
            self.existing_recent_deposit_pointers(connection, DepositKeyKind::Control)
                .await?,
        );
        pointers.retain(|pointer| pointer != evicted);

        let mut partition = DepositKeyPartitionIndex::default();
        let mut pointers_by_key = BTreeMap::new();
        for pointer in pointers {
            let indexed = self
                .indexed_recent_pointer_entry(connection, &pointer)
                .await?;
            partition.insert_for_feedback_reconciliation(indexed, pointer.kind);
            pointers_by_key.insert(pointer.deposit_key.clone(), pointer);
        }
        Ok(partition
            .remove_evidence_orphaned_by_feedback(&removed)
            .into_iter()
            .filter_map(|entry| pointers_by_key.remove(&entry.key))
            .collect())
    }

    #[cfg(feature = "nats")]
    async fn indexed_recent_pointer_entry(
        &self,
        connection: &JetStreamConnection,
        pointer: &RecentDepositPointer,
    ) -> Result<IndexedDepositKey, SubstrateError> {
        use async_nats::jetstream::kv::Operation;

        let Some(entry) = connection
            .store
            .entry_for_revision(&pointer.deposit_key, pointer.deposit_revision)
            .await
            .map_err(|error| nats_error("load recent pointer for feedback reconciliation", error))?
            .filter(|entry| !matches!(entry.operation, Operation::Delete | Operation::Purge))
        else {
            return Err(SubstrateError::InvalidDeposit {
                reason: format!(
                    "recent pointer for `{}` lost its signed deposit before feedback reconciliation",
                    pointer.deposit_key
                ),
            });
        };
        if entry.value.is_empty()
            || entry.value.len() > MAX_SINGLE_DEPOSIT_BYTES
            || deposit_key_timestamp(&pointer.deposit_key).is_none()
            || deposit_key_ordinal(&pointer.deposit_key)
                .is_some_and(|ordinal| ordinal != pointer.ordinal)
            || deposit_key_kind(&pointer.deposit_key).is_some_and(|kind| kind != pointer.kind)
            || deposit_key_encoded_len(&pointer.deposit_key)
                .is_some_and(|encoded_len| encoded_len != entry.value.len())
        {
            return Err(SubstrateError::InvalidDeposit {
                reason: format!(
                    "recent pointer for `{}` has conflicting metadata",
                    pointer.deposit_key
                ),
            });
        }
        let location = format!("jetstream://{}/{}", self.bucket, pointer.deposit_key);
        let deposit = decode_deposit_payload(&entry.value, location)?;
        self.admission_control
            .validate_deposit_admission(&deposit)?;
        if deposit_kind(&deposit) != pointer.kind
            || deposit.timestamp != deposit_key_timestamp(&pointer.deposit_key).unwrap_or_default()
        {
            return Err(SubstrateError::InvalidDeposit {
                reason: format!(
                    "recent pointer for `{}` does not bind its signed deposit",
                    pointer.deposit_key
                ),
            });
        }
        Ok(IndexedDepositKey {
            timestamp: deposit.timestamp,
            key: pointer.deposit_key.clone(),
            encoded_len: entry.value.len(),
            suppression_key: deposit_suppression_key(&deposit),
            feedback_marker: feedback_suppression_marker(&deposit)
                .map(|(key, state, order)| IndexedFeedbackMarker { key, state, order }),
        })
    }

    #[cfg(feature = "nats")]
    async fn remove_recent_pointer_and_value_if_unchanged(
        &self,
        connection: &JetStreamConnection,
        pointer: &RecentDepositPointer,
    ) -> Result<(), SubstrateError> {
        use async_nats::jetstream::kv::{Operation, UpdateErrorKind};

        let key = recent_deposit_index_key(pointer.kind, pointer.ordinal);
        let Some(entry) = connection
            .store
            .entry(&key)
            .await
            .map_err(|error| nats_error("read governed recent pointer", error))?
            .filter(|entry| !matches!(entry.operation, Operation::Delete | Operation::Purge))
        else {
            return Ok(());
        };
        let location = format!("jetstream://{}/{}", self.bucket, key);
        let observed = serde_json::from_slice::<RecentDepositPointer>(&entry.value)
            .map_err(|source| SubstrateError::Decode { location, source })?;
        if &observed != pointer {
            return Ok(());
        }
        match connection
            .store
            .delete_expect_revision(&key, Some(entry.revision))
            .await
        {
            Ok(()) => {}
            Err(error) if error.kind() == UpdateErrorKind::WrongLastRevision => return Ok(()),
            Err(error) => return Err(nats_error("delete governed recent pointer", error)),
        }
        self.purge_deposit_key(connection, &pointer.deposit_key)
            .await
    }

    #[cfg(feature = "nats")]
    async fn existing_recent_deposit_pointers(
        &self,
        connection: &JetStreamConnection,
        kind: DepositKeyKind,
    ) -> Result<Vec<RecentDepositPointer>, SubstrateError> {
        use async_nats::jetstream::kv::Operation;

        let mut pointers = Vec::new();
        for slot in 0..MAX_RECENT_DEPOSIT_INDEX_SLOTS {
            let key = recent_deposit_index_key(kind, slot);
            let Some(entry) = connection
                .store
                .entry(&key)
                .await
                .map_err(|error| nats_error("read existing recent-deposit pointer", error))?
            else {
                continue;
            };
            if matches!(entry.operation, Operation::Delete | Operation::Purge) {
                continue;
            }
            let location = format!("jetstream://{}/{}", self.bucket, key);
            let pointer = serde_json::from_slice::<RecentDepositPointer>(&entry.value)
                .map_err(|source| SubstrateError::Decode { location, source })?;
            if pointer.ordinal == 0
                || pointer.deposit_revision == 0
                || pointer.kind != kind
                || pointer.ordinal % MAX_RECENT_DEPOSIT_INDEX_SLOTS != slot
                || deposit_key_timestamp(&pointer.deposit_key).is_none()
                || deposit_key_ordinal(&pointer.deposit_key)
                    .is_some_and(|ordinal| ordinal != pointer.ordinal)
                || deposit_key_kind(&pointer.deposit_key)
                    .is_some_and(|key_kind| key_kind != pointer.kind)
            {
                return Err(SubstrateError::InvalidDeposit {
                    reason: format!(
                        "JetStream recent index key `{key}` contains an invalid existing pointer"
                    ),
                });
            }
            pointers.push(pointer);
        }
        Ok(pointers)
    }

    #[cfg(feature = "nats")]
    async fn recent_deposit_pointer_metadata(
        store: async_nats::jetstream::kv::Store,
        admission_control: AdmissionControl,
        verified_deposit_cache: Arc<Mutex<VerifiedDepositCache>>,
        bucket: String,
        deposit_key: &str,
        deposit_revision: u64,
        kind: DepositKeyKind,
    ) -> Result<(Option<String>, Option<usize>), SubstrateError> {
        use async_nats::jetstream::kv::Operation;

        let Some(entry) = store
            .entry_for_revision(deposit_key, deposit_revision)
            .await
            .map_err(|error| nats_error("load legacy recent-deposit pointer", error))?
        else {
            return Ok((None, deposit_key_encoded_len(deposit_key)));
        };
        if matches!(entry.operation, Operation::Delete | Operation::Purge) {
            return Ok((None, deposit_key_encoded_len(deposit_key)));
        }
        if entry.value.is_empty() || entry.value.len() > MAX_SINGLE_DEPOSIT_BYTES {
            return Err(SubstrateError::InvalidDeposit {
                reason: format!(
                    "JetStream recent index references an invalid encoded length for deposit key `{}`",
                    deposit_key
                ),
            });
        }
        if deposit_key_encoded_len(deposit_key)
            .is_some_and(|expected| expected != entry.value.len())
        {
            return Err(SubstrateError::InvalidDeposit {
                reason: format!(
                    "JetStream recent index encoded length does not match deposit key `{}`",
                    deposit_key
                ),
            });
        }
        let location = format!("jetstream://{bucket}/{deposit_key}");
        let deposit = decode_deposit_payload(&entry.value, location)?;
        admission_control.validate_deposit_admission(&deposit)?;
        if deposit_kind(&deposit) != kind {
            return Err(SubstrateError::InvalidDeposit {
                reason: format!(
                    "JetStream recent index class does not match signed deposit `{}`",
                    deposit_key
                ),
            });
        }
        let scope = suppression_scope_digest(&deposit)?;
        verified_deposit_cache
            .lock()
            .map_err(|_| SubstrateError::PoisonedLock)?
            .insert(deposit_key.to_string(), deposit_revision, deposit);
        Ok((scope, Some(entry.value.len())))
    }

    #[cfg(feature = "nats")]
    async fn indexed_recent_deposit_keys(
        &self,
        connection: &JetStreamConnection,
    ) -> Result<Vec<SelectedDepositKey>, SubstrateError> {
        self.ensure_recent_deposit_index_initialized(connection)
            .await?;
        self.refresh_recent_deposit_compatibility(connection)
            .await?;
        let consumer = connection
            .store
            .stream
            .create_consumer(async_nats::jetstream::consumer::push::OrderedConfig {
                deliver_subject: connection.client.new_inbox(),
                description: Some("bounded global recent-deposit index".to_string()),
                filter_subject: format!(
                    "{}{RECENT_DEPOSIT_INDEX_KEY_PREFIX}.>",
                    connection.store.prefix
                ),
                replay_policy: async_nats::jetstream::consumer::ReplayPolicy::Instant,
                deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::LastPerSubject,
                ..Default::default()
            })
            .await
            .map_err(|error| nats_error("create recent-deposit index consumer", error))?;

        // `LastPerSubject` establishes its snapshot when the consumer is
        // created. Read exactly that initial pending cardinality. A separate
        // stream high-water captured before creation is not a valid boundary:
        // a concurrent slot overwrite can replace the old value in the
        // LastPerSubject snapshot before the consumer exists.
        let snapshot_pending = consumer.cached_info().num_pending;
        if snapshot_pending == 0 {
            return Ok(Vec::new());
        }

        let mut pointers = BTreeMap::<String, (u64, DepositKeyKind)>::new();
        let mut messages = consumer
            .messages()
            .await
            .map_err(|error| nats_error("subscribe recent-deposit index", error))?;
        for _ in 0..snapshot_pending {
            let message = messages
                .next()
                .await
                .ok_or_else(|| SubstrateError::Nats {
                    operation: "stream recent-deposit index",
                    reason: "consumer ended before its creation snapshot was delivered".to_string(),
                })?
                .map_err(|error| nats_error("stream recent-deposit index", error))?;
            let removed = message
                .message
                .headers
                .as_ref()
                .and_then(|headers| headers.get("KV-Operation"))
                .is_some_and(|operation| matches!(operation.as_str(), "DEL" | "PURGE"));
            if !removed {
                let pointer =
                    serde_json::from_slice::<RecentDepositPointer>(&message.message.payload)
                        .map_err(|source| SubstrateError::Decode {
                            location: format!("jetstream://{}/{}", self.bucket, message.subject),
                            source,
                        })?;
                let explicit_kind = deposit_key_kind(&pointer.deposit_key);
                let encoded_len = deposit_key_encoded_len(&pointer.deposit_key);
                let expected_subject = format!(
                    "{}{}",
                    connection.store.prefix,
                    recent_deposit_index_key(pointer.kind, pointer.ordinal)
                );
                if pointer.ordinal == 0
                    || pointer.deposit_revision == 0
                    || deposit_key_timestamp(&pointer.deposit_key).is_none()
                    || deposit_key_ordinal(&pointer.deposit_key)
                        .is_some_and(|ordinal| ordinal != pointer.ordinal)
                    || encoded_len.is_some_and(|len| len == 0 || len > MAX_SINGLE_DEPOSIT_BYTES)
                    || explicit_kind.is_some_and(|kind| kind != pointer.kind)
                    || expected_subject != message.subject.as_str()
                {
                    return Err(SubstrateError::InvalidDeposit {
                        reason: "JetStream recent index contains an invalid deposit pointer"
                            .to_string(),
                    });
                }
                if let Some((existing_revision, existing_kind)) = pointers.insert(
                    pointer.deposit_key.clone(),
                    (pointer.deposit_revision, pointer.kind),
                ) && (existing_revision != pointer.deposit_revision
                    || existing_kind != pointer.kind)
                {
                    return Err(SubstrateError::InvalidDeposit {
                        reason: format!(
                            "JetStream recent index identifies conflicting metadata for deposit key `{}`",
                            pointer.deposit_key
                        ),
                    });
                }
            }
        }

        // Scope derivation authenticates the referenced signed deposit. Drain
        // the bounded pointer snapshot first, then perform those independent
        // reads with fixed concurrency so moderate per-read latency does not
        // multiply across as many as 254 evidence/control pointers.
        let permits = Arc::new(tokio::sync::Semaphore::new(
            RECENT_DEPOSIT_SCOPE_READ_CONCURRENCY,
        ));
        let mut scope_reads = tokio::task::JoinSet::new();
        for (key, (revision, kind)) in pointers {
            let permit_pool = Arc::clone(&permits);
            let store = connection.store.clone();
            let admission_control = self.admission_control.clone();
            let verified_deposit_cache = Arc::clone(&self.verified_deposit_cache);
            let bucket = self.bucket.clone();
            scope_reads.spawn(async move {
                let _permit =
                    permit_pool
                        .acquire_owned()
                        .await
                        .map_err(|_| SubstrateError::Nats {
                            operation: "load recent-deposit pointer metadata",
                            reason: "recent-deposit scope semaphore closed".to_string(),
                        })?;
                let (suppression_scope_digest, observed_encoded_len) =
                    Self::recent_deposit_pointer_metadata(
                        store,
                        admission_control,
                        verified_deposit_cache,
                        bucket,
                        &key,
                        revision,
                        kind,
                    )
                    .await?;
                Ok::<_, SubstrateError>(SelectedDepositKey {
                    expected_encoded_len: observed_encoded_len,
                    key,
                    kind: Some(kind),
                    expected_revision: Some(revision),
                    suppression_scope_digest,
                })
            });
        }
        let mut selected = Vec::with_capacity(scope_reads.len());
        while let Some(result) = scope_reads.join_next().await {
            selected.push(result.map_err(|error| SubstrateError::Nats {
                operation: "load recent-deposit pointer metadata",
                reason: error.to_string(),
            })??);
        }
        Ok(select_recent_deposit_keys_within_byte_limit(selected))
    }

    #[cfg(feature = "nats")]
    async fn refresh_deposit_key_filter(
        &self,
        connection: &JetStreamConnection,
        key_filter: &str,
        threat_class: &ThreatClass,
        partition: &mut DepositKeyPartitionIndex,
        layout: DepositKeyLayout,
        bounds: DepositKeyRefreshBounds,
    ) -> Result<(), SubstrateError> {
        let (cursor_initialized, cursor_last_sequence) = match layout {
            DepositKeyLayout::Current => (
                partition.current_layout.initialized,
                partition.current_layout.last_sequence,
            ),
            DepositKeyLayout::Legacy => (
                partition.legacy_layout.initialized,
                partition.legacy_layout.last_sequence,
            ),
            DepositKeyLayout::LegacyCustomCurrent => (
                partition.legacy_custom_current_layout.initialized,
                partition.legacy_custom_current_layout.last_sequence,
            ),
            DepositKeyLayout::LegacyCustomLegacy => (
                partition.legacy_custom_legacy_layout.initialized,
                partition.legacy_custom_legacy_layout.last_sequence,
            ),
        };
        if cursor_initialized && bounds.high_water <= cursor_last_sequence {
            return Ok(());
        }
        let deliver_policy = if cursor_initialized {
            async_nats::jetstream::consumer::DeliverPolicy::ByStartSequence {
                start_sequence: cursor_last_sequence.saturating_add(1),
            }
        } else {
            async_nats::jetstream::consumer::DeliverPolicy::LastPerSubject
        };
        let consumer = connection
            .store
            .stream
            .create_consumer(async_nats::jetstream::consumer::push::OrderedConfig {
                deliver_subject: connection.client.new_inbox(),
                description: Some("bounded pheromone deposit index".to_string()),
                filter_subject: format!("{}{}", connection.store.prefix, key_filter),
                replay_policy: async_nats::jetstream::consumer::ReplayPolicy::Instant,
                deliver_policy,
                ..Default::default()
            })
            .await
            .map_err(|error| nats_error("create bounded deposit consumer", error))?;

        if consumer.cached_info().num_pending == 0 {
            let cursor = match layout {
                DepositKeyLayout::Current => &mut partition.current_layout,
                DepositKeyLayout::Legacy => &mut partition.legacy_layout,
                DepositKeyLayout::LegacyCustomCurrent => {
                    &mut partition.legacy_custom_current_layout
                }
                DepositKeyLayout::LegacyCustomLegacy => &mut partition.legacy_custom_legacy_layout,
            };
            cursor.initialized = true;
            cursor.last_sequence = cursor.last_sequence.max(bounds.high_water);
            return Ok(());
        }

        let mut observed_sequence = cursor_last_sequence;
        let mut messages = consumer
            .messages()
            .await
            .map_err(|error| nats_error("subscribe bounded deposit consumer", error))?;
        while let Some(message) = messages.next().await {
            let message =
                message.map_err(|error| nats_error("stream bounded deposit keys", error))?;
            let info = message
                .info()
                .map_err(|error| nats_error("parse bounded deposit metadata", error))?;
            // The ordered consumer is live. Under sustained matching writes,
            // `pending` can remain non-zero forever. Never process beyond the
            // stream boundary captured before consumer creation; a later
            // refresh starts at high_water + 1 and observes those writes.
            if info.stream_sequence > bounds.high_water {
                break;
            }
            observed_sequence = observed_sequence.max(info.stream_sequence);
            let key = message
                .subject
                .strip_prefix(&connection.store.prefix)
                .map(ToString::to_string)
                .unwrap_or_else(|| message.subject.to_string());
            let removed = message
                .message
                .headers
                .as_ref()
                .and_then(|headers| headers.get("KV-Operation"))
                .is_some_and(|operation| matches!(operation.as_str(), "DEL" | "PURGE"));

            if removed {
                let orphaned = partition
                    .remove_key(&key)
                    .map(|entry| partition.remove_evidence_orphaned_by_feedback(&entry))
                    .unwrap_or_default();
                // Delete markers on unique deposit subjects would otherwise
                // remain visible to every future LastPerSubject bootstrap.
                self.purge_deposit_key(connection, &key).await?;
                for entry in orphaned {
                    self.purge_deposit_key(connection, &entry.key).await?;
                }
            } else {
                let location = format!("jetstream://{}/{}", self.bucket, key);
                let deposit = decode_deposit_payload(&message.message.payload, location)?;
                self.admission_control
                    .validate_deposit_admission(&deposit)?;
                if &deposit.threat_class != threat_class
                    && layout.allows_colliding_legacy_custom_class()
                {
                    if info.stream_sequence == bounds.high_water || info.pending == 0 {
                        break;
                    }
                    continue;
                }
                if &deposit.threat_class != threat_class {
                    return Err(SubstrateError::InvalidDeposit {
                        reason: format!(
                            "JetStream deposit key `{key}` threat class does not match its signed payload"
                        ),
                    });
                }
                let kind = deposit_kind(&deposit);
                if let Some(key_kind) = deposit_key_kind(&key)
                    && key_kind != kind
                {
                    return Err(SubstrateError::InvalidDeposit {
                        reason: format!(
                            "JetStream deposit key `{key}` class does not match its signed payload"
                        ),
                    });
                }
                let expired = match (
                    bounds.retention_now,
                    bounds.retention_half_life_secs,
                    bounds.retention_evaporation_threshold,
                ) {
                    (Some(now), Some(half_life_secs), Some(evaporation_threshold)) => {
                        is_retention_expired(&deposit, now, half_life_secs, evaporation_threshold)
                    }
                    _ => false,
                };
                if expired {
                    let orphaned = partition
                        .remove_key(&key)
                        .map(|entry| partition.remove_evidence_orphaned_by_feedback(&entry))
                        .unwrap_or_default();
                    self.purge_deposit_key(connection, &key).await?;
                    for entry in orphaned {
                        self.purge_deposit_key(connection, &entry.key).await?;
                    }
                } else {
                    self.verified_deposit_cache
                        .lock()
                        .map_err(|_| SubstrateError::PoisonedLock)?
                        .insert(key.clone(), info.stream_sequence, deposit.clone());
                    let indexed = IndexedDepositKey {
                        timestamp: deposit.timestamp,
                        key,
                        encoded_len: deposit.encoded_len(),
                        suppression_key: deposit_suppression_key(&deposit),
                        feedback_marker: feedback_suppression_marker(&deposit)
                            .map(|(key, state, order)| IndexedFeedbackMarker { key, state, order }),
                    };
                    let replacement_orphans = partition
                        .remove_key(&indexed.key)
                        .map(|entry| partition.remove_evidence_orphaned_by_feedback(&entry))
                        .unwrap_or_default();
                    let evicted = partition.insert_bounded(indexed, kind, bounds.partition_limit);
                    for related in replacement_orphans {
                        self.purge_deposit_key(connection, &related.key).await?;
                    }
                    for entry in &evicted {
                        let shadowed_by_newer_eviction =
                            entry.feedback_marker.as_ref().is_some_and(|marker| {
                                evicted.iter().any(|candidate| {
                                    candidate.feedback_marker.as_ref().is_some_and(
                                        |candidate_marker| {
                                            candidate_marker.key == marker.key
                                                && (candidate_marker.order > marker.order
                                                    || (candidate_marker.order == marker.order
                                                        && candidate.key > entry.key))
                                        },
                                    )
                                })
                            });
                        let orphaned = if shadowed_by_newer_eviction {
                            Vec::new()
                        } else {
                            partition.remove_evidence_orphaned_by_feedback(entry)
                        };
                        self.purge_deposit_key(connection, &entry.key).await?;
                        for related in orphaned {
                            self.purge_deposit_key(connection, &related.key).await?;
                        }
                    }
                }
            }

            if info.stream_sequence == bounds.high_water || info.pending == 0 {
                break;
            }
        }
        let cursor = match layout {
            DepositKeyLayout::Current => &mut partition.current_layout,
            DepositKeyLayout::Legacy => &mut partition.legacy_layout,
            DepositKeyLayout::LegacyCustomCurrent => &mut partition.legacy_custom_current_layout,
            DepositKeyLayout::LegacyCustomLegacy => &mut partition.legacy_custom_legacy_layout,
        };
        cursor.initialized = true;
        cursor.last_sequence = cursor
            .last_sequence
            .max(bounds.high_water)
            .max(observed_sequence);
        Ok(())
    }

    #[cfg(feature = "nats")]
    async fn indexed_deposit_keys(
        &self,
        connection: &JetStreamConnection,
        threat_class: &ThreatClass,
        retention_now: Option<i64>,
        retention_policy: Option<&ThreatClassPolicy>,
        partition_limit: usize,
    ) -> Result<Vec<String>, SubstrateError> {
        let segment = threat_class_segment(threat_class);
        let legacy_segment = legacy_threat_class_segment(threat_class);
        // One high-water read covers both the current and migration layouts.
        // Advancing an empty filter only to this pre-consumer boundary is
        // race-safe: a matching write after the snapshot is necessarily read
        // from high_water + 1 on this or the next refresh.
        let bounds = DepositKeyRefreshBounds {
            high_water: connection
                .store
                .stream
                .get_info()
                .await
                .map_err(|error| nats_error("read deposit stream high-water", error))?
                .state
                .last_sequence,
            retention_now,
            retention_half_life_secs: retention_policy.map(|policy| policy.half_life_secs),
            retention_evaporation_threshold: retention_policy
                .map(|policy| policy.evaporation_threshold),
            partition_limit,
        };
        let mut indexes = self.deposit_key_indexes.lock().await;
        indexes.make_room_for(&segment);
        {
            let partition = indexes.partitions.entry(segment.clone()).or_default();
            self.refresh_deposit_key_filter(
                connection,
                &format!("{GC_KEY_PREFIX}.*.{segment}.>"),
                threat_class,
                partition,
                DepositKeyLayout::Current,
                bounds,
            )
            .await?;
            self.refresh_deposit_key_filter(
                connection,
                &format!("{segment}.>"),
                threat_class,
                partition,
                DepositKeyLayout::Legacy,
                bounds,
            )
            .await?;
            if legacy_segment != segment {
                // Releases before collision-resistant custom segments used a
                // lossy sanitized namespace. Replay both old layouts into the
                // new class-specific partition, but skip signed payloads for a
                // different custom class that shared that legacy namespace.
                self.refresh_deposit_key_filter(
                    connection,
                    &format!("{GC_KEY_PREFIX}.*.{legacy_segment}.>"),
                    threat_class,
                    partition,
                    DepositKeyLayout::LegacyCustomCurrent,
                    bounds,
                )
                .await?;
                self.refresh_deposit_key_filter(
                    connection,
                    &format!("{legacy_segment}.>"),
                    threat_class,
                    partition,
                    DepositKeyLayout::LegacyCustomLegacy,
                    bounds,
                )
                .await?;
            }
        }
        indexes.enforce_global_byte_bound(&segment);
        let Some(partition) = indexes.partitions.get(&segment) else {
            return Err(SubstrateError::Nats {
                operation: "maintain bounded deposit index",
                reason: format!("active threat-class partition `{segment}` was not retained"),
            });
        };

        debug_assert!(partition.total_bytes() <= MAX_ACTIVE_DEPOSIT_BYTES);
        Ok(partition
            .controls
            .iter()
            .chain(&partition.evidence)
            .map(|entry| entry.key.clone())
            .collect())
    }

    #[cfg(not(feature = "nats"))]
    async fn ensure_connected(&self) -> Result<(), SubstrateError> {
        Err(unsupported_backend())
    }

    #[cfg(feature = "nats")]
    async fn load_deposits(
        &self,
        threat_class: Option<&ThreatClass>,
        since_timestamp: Option<i64>,
        retention_now: Option<i64>,
    ) -> Result<Vec<VerifiedDeposit>, SubstrateError> {
        self.load_deposits_bounded(
            threat_class,
            since_timestamp,
            retention_now,
            MAX_ACTIVE_DEPOSITS,
            false,
        )
        .await
    }

    #[cfg(feature = "nats")]
    async fn load_deposits_bounded(
        &self,
        threat_class: Option<&ThreatClass>,
        since_timestamp: Option<i64>,
        retention_now: Option<i64>,
        partition_limit: usize,
        use_recent_index: bool,
    ) -> Result<Vec<VerifiedDeposit>, SubstrateError> {
        let connection = self.ensure_connected().await?;
        let retention_policy = if let (Some(threat_class), Some(_)) = (threat_class, retention_now)
        {
            let threat_class_config = self.load_threat_class_config(threat_class).await?;
            Some(
                self.config
                    .resolve_threat_class_policy(threat_class_config.as_ref()),
            )
        } else {
            None
        };
        let selected_keys = if let Some(threat_class) = threat_class {
            self.indexed_deposit_keys(
                connection,
                threat_class,
                retention_now,
                retention_policy.as_ref(),
                partition_limit,
            )
            .await?
            .into_iter()
            .map(|key| SelectedDepositKey {
                kind: deposit_key_kind(&key),
                key,
                expected_revision: None,
                expected_encoded_len: None,
                suppression_scope_digest: None,
            })
            .collect()
        } else if use_recent_index {
            // The dispatcher calls this branch every tick. Read only the
            // fixed-size server-side ring populated during deposit admission;
            // never enumerate the lifetime KV subject set on this hot path.
            self.indexed_recent_deposit_keys(connection).await?
        } else {
            // Operator/API queries retain full compatibility with deposits
            // created before the bounded recent index existed. This path is
            // not used by the runtime's periodic dispatcher.
            let mut keys = connection
                .store
                .keys()
                .await
                .map_err(|error| nats_error("list unscoped deposit keys", error))?;
            let mut evidence_key_window = BTreeSet::new();
            let mut control_key_window = BTreeSet::new();
            while let Some(entry) = keys.next().await {
                let key =
                    entry.map_err(|error| nats_error("stream unscoped deposit keys", error))?;
                if is_non_deposit_key(&key) {
                    continue;
                }
                if retention_now.is_some_and(|now| {
                    key_gc_page(&key).is_some_and(|page| page <= gc_sweep_page(now))
                }) {
                    continue;
                }
                let Some(kind) = self.classify_deposit_key(connection, &key).await? else {
                    continue;
                };
                retain_newest_partitioned_deposit_key_as(
                    &mut evidence_key_window,
                    &mut control_key_window,
                    key,
                    kind,
                    partition_limit,
                );
            }
            evidence_key_window
                .into_iter()
                .chain(control_key_window)
                .map(|(_, key)| SelectedDepositKey {
                    kind: deposit_key_kind(&key),
                    key,
                    expected_revision: None,
                    expected_encoded_len: None,
                    suppression_scope_digest: None,
                })
                .collect()
        };

        let mut deposits = Vec::with_capacity(selected_keys.len());
        let mut deposit_bytes = 0usize;
        for selected in selected_keys {
            let expected_kind = selected.kind;
            let expected_suppression_scope_digest = selected.suppression_scope_digest;
            let key = selected.key;
            let entry = match selected.expected_revision {
                Some(revision) => connection.store.entry_for_revision(&key, revision).await,
                None => connection.store.entry(&key).await,
            }
            .map_err(|error| nats_error("get entry", error))?;
            let Some(entry) = entry else {
                continue;
            };
            if let Some(expected_revision) = selected.expected_revision
                && expected_revision != entry.revision
            {
                return Err(SubstrateError::InvalidDeposit {
                    reason: format!(
                        "JetStream recent index revision {expected_revision} does not match revision {} for deposit key `{key}`",
                        entry.revision
                    ),
                });
            }
            if let Some(expected_encoded_len) = selected.expected_encoded_len
                && expected_encoded_len != entry.value.len()
            {
                return Err(SubstrateError::InvalidDeposit {
                    reason: format!(
                        "JetStream recent index encoded length {expected_encoded_len} does not match {} bytes for deposit key `{key}`",
                        entry.value.len()
                    ),
                });
            }
            if matches!(
                entry.operation,
                async_nats::jetstream::kv::Operation::Delete
                    | async_nats::jetstream::kv::Operation::Purge
            ) {
                self.verified_deposit_cache
                    .lock()
                    .map_err(|_| SubstrateError::PoisonedLock)?
                    .remove(&key);
                continue;
            }

            let cached = self
                .verified_deposit_cache
                .lock()
                .map_err(|_| SubstrateError::PoisonedLock)?
                .get(&key, entry.revision);
            let deposit = if let Some(deposit) = cached {
                deposit
            } else {
                let location = format!("jetstream://{}/{}", self.bucket, key);
                let deposit = decode_deposit_payload(&entry.value, location)?;
                self.verified_deposit_cache
                    .lock()
                    .map_err(|_| SubstrateError::PoisonedLock)?
                    .insert(key.clone(), entry.revision, deposit.clone());
                deposit
            };
            self.admission_control
                .validate_deposit_admission(&deposit)?;

            if let Some(expected_scope) = expected_suppression_scope_digest.as_deref()
                && suppression_scope_digest(&deposit)?.as_deref() != Some(expected_scope)
            {
                return Err(SubstrateError::InvalidDeposit {
                    reason: format!(
                        "JetStream recent index suppression scope does not match signed deposit `{key}`"
                    ),
                });
            }

            if expected_kind.is_some_and(|kind| kind != deposit_kind(&deposit)) {
                return Err(SubstrateError::InvalidDeposit {
                    reason: format!(
                        "JetStream recent index class does not match signed deposit `{key}`"
                    ),
                });
            }

            if let Some(key_kind) = deposit_key_kind(&key)
                && key_kind != deposit_kind(&deposit)
            {
                return Err(SubstrateError::InvalidDeposit {
                    reason: format!(
                        "JetStream deposit key `{key}` class does not match its signed payload"
                    ),
                });
            }

            if let Some(threat_class) = threat_class
                && &deposit.threat_class != threat_class
            {
                continue;
            }
            if let Some(since_timestamp) = since_timestamp
                && deposit.timestamp < since_timestamp
            {
                continue;
            }
            if let (Some(now), Some(policy)) = (retention_now, retention_policy.as_ref())
                && is_retention_expired(
                    &deposit,
                    now,
                    policy.half_life_secs,
                    policy.evaporation_threshold,
                )
            {
                continue;
            }
            let next_bytes = deposit_bytes.saturating_add(deposit.encoded_len());
            if next_bytes > MAX_ACTIVE_DEPOSIT_BYTES {
                return Err(SubstrateError::InvalidDeposit {
                    reason: format!(
                        "bounded JetStream deposit scan exceeds the {MAX_ACTIVE_DEPOSIT_BYTES}-byte aggregate limit"
                    ),
                });
            }

            deposit_bytes = next_bytes;
            deposits.push(deposit);
        }

        Ok(deposits)
    }

    #[cfg(feature = "nats")]
    fn classify_legacy_deposit_payload(
        &self,
        key: &str,
        payload: &[u8],
    ) -> Result<DepositKeyKind, SubstrateError> {
        let location = format!("jetstream://{}/{}", self.bucket, key);
        let raw = serde_json::from_slice::<serde_json::Value>(payload)
            .map_err(|source| SubstrateError::Decode { location, source })?;
        let confidence = raw
            .get("confidence")
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(|| SubstrateError::InvalidDeposit {
                reason: format!(
                    "legacy JetStream deposit key `{key}` has no numeric confidence field"
                ),
            })?;
        Ok(if confidence == 0.0 {
            DepositKeyKind::Control
        } else {
            DepositKeyKind::Evidence
        })
    }

    #[cfg(feature = "nats")]
    async fn classify_deposit_key(
        &self,
        connection: &JetStreamConnection,
        key: &str,
    ) -> Result<Option<DepositKeyKind>, SubstrateError> {
        if let Some(kind) = deposit_key_kind(key) {
            return Ok(Some(kind));
        }

        // Keys written before the partitioned layout do not encode whether a
        // record is positive evidence or a zero-strength control. Read only
        // the numeric classification field while selecting the bounded
        // migration window; full structural and Ed25519 verification still
        // occurs below for every selected payload.
        let Some(entry) = connection
            .store
            .entry(key)
            .await
            .map_err(|error| nats_error("classify legacy entry", error))?
        else {
            return Ok(None);
        };
        if matches!(
            entry.operation,
            async_nats::jetstream::kv::Operation::Delete
                | async_nats::jetstream::kv::Operation::Purge
        ) {
            return Ok(None);
        }
        self.classify_legacy_deposit_payload(key, &entry.value)
            .map(Some)
    }

    #[cfg(feature = "nats")]
    async fn deposit_count(&self) -> Result<usize, SubstrateError> {
        let connection = self.ensure_connected().await?;
        let mut keys = connection
            .store
            .keys()
            .await
            .map_err(|error| nats_error("list keys", error))?;
        let mut count = 0usize;
        while let Some(entry) = keys.next().await {
            let key = entry.map_err(|error| nats_error("stream keys", error))?;
            if is_non_deposit_key(&key) {
                continue;
            }
            count = count.saturating_add(1);
        }
        Ok(count)
    }

    #[cfg(feature = "nats")]
    async fn load_threat_class_config(
        &self,
        threat_class: &ThreatClass,
    ) -> Result<Option<ThreatClassConfig>, SubstrateError> {
        let connection = self.ensure_connected().await?;
        let current_key = threat_class_config_key(threat_class);
        let legacy_key = legacy_threat_class_config_key(threat_class);
        for key in [current_key, legacy_key] {
            let Some(payload) = connection
                .store
                .get(&key)
                .await
                .map_err(|error| nats_error("get value", error))?
            else {
                continue;
            };
            let location = format!("jetstream://{}/{}", self.bucket, key);
            let record = serde_json::from_slice::<ThreatClassConfig>(&payload)
                .map_err(|source| SubstrateError::Decode { location, source })?;
            if &record.threat_class == threat_class {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }

    #[cfg(feature = "nats")]
    async fn load_threat_class_configs(&self) -> Result<Vec<ThreatClassConfig>, SubstrateError> {
        let connection = self.ensure_connected().await?;
        let mut keys = connection
            .store
            .keys()
            .await
            .map_err(|error| nats_error("list keys", error))?;
        let mut configs = BTreeMap::<ThreatClass, (bool, ThreatClassConfig)>::new();

        while let Some(entry) = keys.next().await {
            let key = entry.map_err(|error| nats_error("stream keys", error))?;
            if !is_policy_key(&key) {
                continue;
            }

            let Some(payload) = connection
                .store
                .get(&key)
                .await
                .map_err(|error| nats_error("get value", error))?
            else {
                continue;
            };

            let location = format!("jetstream://{}/{}", self.bucket, key);
            let record = serde_json::from_slice::<ThreatClassConfig>(&payload)
                .map_err(|source| SubstrateError::Decode { location, source })?;
            let is_current = key == threat_class_config_key(&record.threat_class);
            match configs.entry(record.threat_class.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert((is_current, record));
                }
                std::collections::btree_map::Entry::Occupied(mut entry)
                    if is_current && !entry.get().0 =>
                {
                    entry.insert((true, record));
                }
                std::collections::btree_map::Entry::Occupied(_) => {}
            }
        }
        Ok(configs.into_values().map(|(_, config)| config).collect())
    }

    #[cfg(feature = "nats")]
    async fn load_threat_intel_entry(
        &self,
        indicator_type: &ThreatIntelIndicatorType,
        value: &str,
        now: i64,
    ) -> Result<Option<ThreatIntelEntry>, SubstrateError> {
        let connection = self.ensure_connected().await?;
        let key = threat_intel_key(indicator_type, value);
        let Some(payload) = connection
            .store
            .get(&key)
            .await
            .map_err(|error| nats_error("get value", error))?
        else {
            return Ok(None);
        };

        let location = format!("jetstream://{}/{}", self.bucket, key);
        let entry = serde_json::from_slice::<ThreatIntelEntry>(&payload)
            .map_err(|source| SubstrateError::Decode { location, source })?;
        if entry.expires_at <= now {
            return Ok(None);
        }
        Ok(Some(entry))
    }

    #[cfg(feature = "nats")]
    async fn load_behavioral_baseline_snapshot(
        &self,
        strategy_id: &str,
    ) -> Result<Option<SignedStateEnvelope<BehavioralBaselineSnapshot>>, SubstrateError> {
        let connection = self.ensure_connected().await?;
        let key = behavioral_baseline_key(strategy_id);
        let Some(payload) = connection
            .store
            .get(&key)
            .await
            .map_err(|error| nats_error("get value", error))?
        else {
            return Ok(None);
        };

        let location = format!("jetstream://{}/{}", self.bucket, key);
        let snapshot =
            serde_json::from_slice::<SignedStateEnvelope<BehavioralBaselineSnapshot>>(&payload)
                .map_err(|source| SubstrateError::Decode { location, source })?;
        Ok(Some(snapshot))
    }

    #[cfg(feature = "nats")]
    async fn load_behavioral_baseline_sequence(
        &self,
        strategy_id: &str,
    ) -> Result<Option<u64>, SubstrateError> {
        let connection = self.ensure_connected().await?;
        let key = behavioral_baseline_sequence_key(strategy_id);
        let Some(payload) = connection
            .store
            .get(&key)
            .await
            .map_err(|error| nats_error("get value", error))?
        else {
            return Ok(None);
        };

        let location = format!("jetstream://{}/{}", self.bucket, key);
        serde_json::from_slice::<u64>(&payload)
            .map(Some)
            .map_err(|source| SubstrateError::Decode { location, source })
    }

    #[cfg(feature = "nats")]
    async fn load_escalations(
        &self,
        since_timestamp: i64,
    ) -> Result<Vec<EscalationRecord>, SubstrateError> {
        let connection = self.ensure_connected().await?;
        let mut keys = connection
            .store
            .keys()
            .await
            .map_err(|error| nats_error("list keys", error))?;
        let mut escalations = Vec::new();

        while let Some(entry) = keys.next().await {
            let key = entry.map_err(|error| nats_error("stream keys", error))?;
            if !is_escalation_key(&key) {
                continue;
            }

            let Some(payload) = connection
                .store
                .get(&key)
                .await
                .map_err(|error| nats_error("get value", error))?
            else {
                continue;
            };

            let location = format!("jetstream://{}/{}", self.bucket, key);
            let record = serde_json::from_slice::<EscalationRecord>(&payload)
                .map_err(|source| SubstrateError::Decode { location, source })?;
            if record.timestamp >= since_timestamp {
                escalations.push(record);
            }
        }

        Ok(filter_escalations(&escalations, since_timestamp))
    }

    #[cfg(feature = "nats")]
    fn note_gc_page(&self, page: i64) {
        let mut guard = self
            .gc_page_cursor
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *guard = Some(match *guard {
            Some(current) => current.min(page),
            None => page,
        });
    }

    #[cfg(feature = "nats")]
    async fn gc_evaporated_legacy(&self, now: i64) -> Result<usize, SubstrateError> {
        if *self
            .legacy_gc_complete
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
        {
            return Ok(0);
        }

        let connection = self.ensure_connected().await?;
        let mut keys = connection
            .store
            .keys()
            .await
            .map_err(|error| nats_error("list keys", error))?;
        let mut removed = 0usize;
        let mut saw_legacy_key = false;

        while let Some(entry) = keys.next().await {
            let key = entry.map_err(|error| nats_error("stream keys", error))?;
            if is_non_deposit_key(&key) {
                continue;
            }
            if key_gc_page(&key).is_some() {
                continue;
            }
            saw_legacy_key = true;

            let Some(payload) = connection
                .store
                .get(&key)
                .await
                .map_err(|error| nats_error("get value", error))?
            else {
                continue;
            };

            let location = format!("jetstream://{}/{}", self.bucket, key);
            let deposit = decode_deposit_payload(&payload, location)?;
            if is_retention_expired(
                &deposit,
                now,
                self.config.default_half_life_secs,
                self.config.evaporation_threshold,
            ) {
                connection
                    .store
                    .delete(&key)
                    .await
                    .map_err(|error| nats_error("delete value", error))?;
                self.verified_deposit_cache
                    .lock()
                    .map_err(|_| SubstrateError::PoisonedLock)?
                    .remove(&key);
                removed = removed.saturating_add(1);
            }
        }

        if !saw_legacy_key {
            let mut guard = self
                .legacy_gc_complete
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            *guard = true;
        }

        Ok(removed)
    }

    #[cfg(feature = "nats")]
    async fn oldest_gc_page(&self) -> Result<Option<i64>, SubstrateError> {
        let connection = self.ensure_connected().await?;
        let mut keys = connection
            .store
            .keys()
            .await
            .map_err(|error| nats_error("list keys", error))?;
        let mut oldest: Option<i64> = None;

        while let Some(entry) = keys.next().await {
            let key = entry.map_err(|error| nats_error("stream keys", error))?;
            let Some(page) = key_gc_page(&key).or_else(|| intent_key_gc_page(&key)) else {
                continue;
            };
            oldest = Some(match oldest {
                Some(current) => current.min(page),
                None => page,
            });
        }

        Ok(oldest)
    }

    #[cfg(feature = "nats")]
    async fn gc_page_keys(
        &self,
        connection: &JetStreamConnection,
        page: i64,
    ) -> Result<Vec<String>, SubstrateError> {
        let mut keys = Vec::new();
        for filter in [gc_page_subject(page), intent_gc_page_subject(page)] {
            let consumer = connection
                .store
                .stream
                .create_consumer(async_nats::jetstream::consumer::push::OrderedConfig {
                    deliver_subject: connection.client.new_inbox(),
                    description: Some("kv gc page consumer".to_string()),
                    filter_subject: format!("{}{}", connection.store.prefix, filter),
                    headers_only: true,
                    replay_policy: async_nats::jetstream::consumer::ReplayPolicy::Instant,
                    deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::LastPerSubject,
                    ..Default::default()
                })
                .await
                .map_err(|error| nats_error("create gc page consumer", error))?;
            if consumer.cached_info().num_pending == 0 {
                continue;
            }
            let mut messages = consumer
                .messages()
                .await
                .map_err(|error| nats_error("subscribe gc page consumer", error))?;
            while let Some(message) = messages.next().await {
                let message =
                    message.map_err(|error| nats_error("stream gc page consumer", error))?;
                let key = message
                    .subject
                    .strip_prefix(&connection.store.prefix)
                    .map(ToString::to_string)
                    .unwrap_or_else(|| message.subject.to_string());
                if connection
                    .store
                    .get(&key)
                    .await
                    .map_err(|error| nats_error("get value", error))?
                    .is_some()
                {
                    keys.push(key);
                }
                let info = message
                    .info()
                    .map_err(|error| nats_error("parse gc page metadata", error))?;
                if info.pending == 0 {
                    break;
                }
            }
        }

        Ok(keys)
    }

    #[cfg(feature = "nats")]
    async fn gc_evaporated_by_page(&self, now: i64) -> Result<usize, SubstrateError> {
        let current_page = gc_sweep_page(now);
        let cached_cursor = *self
            .gc_page_cursor
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let start_page = match cached_cursor {
            Some(page) => page,
            None => match self.oldest_gc_page().await? {
                Some(page) => page,
                None => return Ok(0),
            },
        };

        if start_page > current_page {
            return Ok(0);
        }

        let end_page = start_page
            .saturating_add(self.gc_page_size.saturating_sub(1) as i64)
            .min(current_page);
        let connection = self.ensure_connected().await?;
        let mut removed = 0usize;

        for page in start_page..=end_page {
            for key in self.gc_page_keys(connection, page).await? {
                connection
                    .store
                    .delete(&key)
                    .await
                    .map_err(|error| nats_error("delete value", error))?;
                self.verified_deposit_cache
                    .lock()
                    .map_err(|_| SubstrateError::PoisonedLock)?
                    .remove(&key);
                removed = removed.saturating_add(1);
            }
        }

        let mut guard = self
            .gc_page_cursor
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *guard = if end_page == current_page {
            None
        } else {
            Some(end_page.saturating_add(1))
        };

        Ok(removed)
    }

    #[cfg(feature = "nats")]
    async fn gc_expired_idempotent_intents(
        &self,
        connection: &JetStreamConnection,
        now: i64,
    ) -> Result<usize, SubstrateError> {
        use async_nats::jetstream::kv::Operation;

        let mut keys = connection
            .store
            .keys()
            .await
            .map_err(|error| nats_error("list idempotent intents", error))?;
        let sweep_page = gc_sweep_page(now);
        let mut removed = 0usize;
        while let Some(entry) = keys.next().await {
            let key = entry.map_err(|error| nats_error("stream idempotent intent keys", error))?;
            if !is_idempotent_deposit_intent_key(&key) {
                continue;
            }
            let Some(entry) = connection
                .store
                .entry(&key)
                .await
                .map_err(|error| nats_error("get idempotent intent for GC", error))?
                .filter(|entry| !matches!(entry.operation, Operation::Delete | Operation::Purge))
            else {
                continue;
            };
            let intent = serde_json::from_slice::<IdempotentDepositIntent>(&entry.value).map_err(
                |source| SubstrateError::Decode {
                    location: format!("jetstream://{}/{}", self.bucket, key),
                    source,
                },
            )?;
            let page =
                key_gc_page(&intent.deposit_key).ok_or_else(|| SubstrateError::InvalidDeposit {
                    reason: format!("idempotent intent `{key}` contains an unscoped deposit key"),
                })?;
            if page <= sweep_page
                && !self
                    .idempotent_intent_referenced_deposit_is_live(connection, &key, &intent, now)
                    .await?
            {
                connection
                    .store
                    .delete_expect_revision(&key, Some(entry.revision))
                    .await
                    .map_err(|error| nats_error("delete expired idempotent intent", error))?;
                removed = removed.saturating_add(1);
            }
        }
        Ok(removed)
    }

    #[cfg(feature = "nats")]
    async fn idempotent_intent_referenced_deposit_is_live(
        &self,
        connection: &JetStreamConnection,
        intent_key: &str,
        intent: &IdempotentDepositIntent,
        now: i64,
    ) -> Result<bool, SubstrateError> {
        use async_nats::jetstream::kv::Operation;

        let Some(entry) = connection
            .store
            .entry(&intent.deposit_key)
            .await
            .map_err(|error| nats_error("get idempotent intent deposit for GC", error))?
            .filter(|entry| !matches!(entry.operation, Operation::Delete | Operation::Purge))
        else {
            return Ok(false);
        };
        if intent
            .committed_deposit_revision
            .is_some_and(|revision| revision != entry.revision)
            || hash_prefix(&entry.value, 64) != intent.payload_digest
            || deposit_key_ordinal(&intent.deposit_key)
                .is_some_and(|ordinal| ordinal != intent.ordinal)
            || deposit_key_kind(&intent.deposit_key) != Some(intent.kind)
            || deposit_key_encoded_len(&intent.deposit_key) != Some(entry.value.len())
        {
            return Err(SubstrateError::InvalidDeposit {
                reason: format!(
                    "idempotent intent `{intent_key}` does not bind its referenced deposit"
                ),
            });
        }

        let location = format!("jetstream://{}/{}", self.bucket, intent.deposit_key);
        let deposit = decode_deposit_payload(&entry.value, location)?;
        self.admission_control
            .validate_deposit_admission(&deposit)?;
        if deposit_kind(&deposit) != intent.kind
            || deposit_operation_id(&deposit)?.as_deref() != Some(intent.operation_id.as_str())
            || deposit_key_timestamp(&intent.deposit_key) != Some(deposit.timestamp)
        {
            return Err(SubstrateError::InvalidDeposit {
                reason: format!(
                    "idempotent intent `{intent_key}` identifies a conflicting signed deposit"
                ),
            });
        }

        let threat_class_config = self.load_threat_class_config(&deposit.threat_class).await?;
        let policy = self
            .config
            .resolve_threat_class_policy(threat_class_config.as_ref());
        Ok(!is_retention_expired(
            &deposit,
            now,
            policy.half_life_secs,
            policy.evaporation_threshold,
        ))
    }

    #[cfg(feature = "nats")]
    async fn gc_evaporated_with_policy_scan(&self, now: i64) -> Result<usize, SubstrateError> {
        let threat_class_configs = self
            .load_threat_class_configs()
            .await?
            .into_iter()
            .map(|config| (config.threat_class.clone(), config))
            .collect::<BTreeMap<_, _>>();
        if threat_class_configs.is_empty() {
            return Ok(0);
        }

        let connection = self.ensure_connected().await?;
        let mut keys = connection
            .store
            .keys()
            .await
            .map_err(|error| nats_error("list keys", error))?;
        let mut removed = 0usize;

        while let Some(entry) = keys.next().await {
            let key = entry.map_err(|error| nats_error("stream keys", error))?;
            if is_idempotent_deposit_intent_key(&key) {
                continue;
            }
            if is_non_deposit_key(&key) {
                continue;
            }

            let Some(payload) = connection
                .store
                .get(&key)
                .await
                .map_err(|error| nats_error("get value", error))?
            else {
                continue;
            };

            let location = format!("jetstream://{}/{}", self.bucket, key);
            let deposit = decode_deposit_payload(&payload, location)?;
            let policy = self
                .config
                .resolve_threat_class_policy(threat_class_configs.get(&deposit.threat_class));
            if !is_retention_expired(
                &deposit,
                now,
                policy.half_life_secs,
                policy.evaporation_threshold,
            ) {
                continue;
            }

            connection
                .store
                .delete(&key)
                .await
                .map_err(|error| nats_error("delete value", error))?;
            self.verified_deposit_cache
                .lock()
                .map_err(|_| SubstrateError::PoisonedLock)?
                .remove(&key);
            removed = removed.saturating_add(1);
        }

        Ok(removed)
    }
}

#[cfg(feature = "nats")]
#[async_trait]
impl PheromoneSubstrate for JetStreamPheromoneSubstrate {
    async fn deposit(&self, deposit: PheromoneDeposit) -> Result<(), SubstrateError> {
        use async_nats::jetstream::kv::{CreateErrorKind, Operation};

        // Apply the same signature and hard encoded-size admission used by
        // every read path before a value can become durable. Otherwise an
        // oversized but validly signed value poisons all later scans.
        let deposit = VerifiedDeposit::admit(deposit)?;
        self.admission_control
            .validate_deposit_admission(&deposit)?;
        let threat_class_config = self.load_threat_class_config(&deposit.threat_class).await?;
        let policy = self
            .config
            .resolve_threat_class_policy(threat_class_config.as_ref());
        validate_deposit_policy(&deposit, policy.half_life_secs)?;
        let trusted_now = trusted_system_unix_seconds()?;
        validate_deposit_retention(
            &deposit,
            trusted_now,
            policy.half_life_secs,
            policy.evaporation_threshold,
            Some(trusted_now),
        )?;
        let connection = self.ensure_connected().await?;
        self.ensure_recent_deposit_index_initialized(connection)
            .await?;
        let payload = serde_json::to_vec(&*deposit).map_err(|source| SubstrateError::Encode {
            context: "jetstream pheromone deposit".to_string(),
            source,
        })?;
        let gc_page = expiration_gc_page(
            &deposit,
            policy.half_life_secs,
            policy.evaporation_threshold,
        );
        let kind = deposit_kind(&deposit);
        let operation_id = deposit_operation_id(&deposit)?;
        if let Some(operation_id) = operation_id.as_deref() {
            for _ in 0..MAX_RECENT_DEPOSIT_INDEX_CAS_ATTEMPTS {
                let stored = self
                    .resolve_idempotent_deposit_intent(
                        connection,
                        &deposit,
                        &payload,
                        operation_id,
                        kind,
                        (policy.half_life_secs, policy.evaporation_threshold),
                    )
                    .await?;
                if stored.intent.committed_deposit_revision.is_some() {
                    return Ok(());
                }

                let key = stored.intent.deposit_key.clone();
                let revision = loop {
                    match connection
                        .store
                        .entry(&key)
                        .await
                        .map_err(|error| nats_error("read idempotent deposit", error))?
                        .filter(|entry| {
                            !matches!(entry.operation, Operation::Delete | Operation::Purge)
                        }) {
                        Some(existing) => {
                            if existing.value.as_ref() != payload.as_slice() {
                                return Err(SubstrateError::InvalidDeposit {
                                    reason: "idempotent Providence deposit key contains a conflicting payload"
                                        .to_string(),
                                });
                            }
                            break existing.revision;
                        }
                        None => match connection.store.create(&key, payload.clone().into()).await {
                            Ok(revision) => {
                                break revision;
                            }
                            Err(error) if error.kind() == CreateErrorKind::AlreadyExists => {
                                continue;
                            }
                            Err(error) => {
                                return Err(nats_error("create idempotent deposit", error));
                            }
                        },
                    }
                };
                let pointer = RecentDepositPointer {
                    ordinal: stored.intent.ordinal,
                    kind,
                    deposit_key: key.clone(),
                    deposit_revision: revision,
                };
                let pointer_write = match self
                    .write_recent_deposit_pointer(connection, &pointer)
                    .await
                {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        // Keep the operation-scoped value. Another exact
                        // retry may already have published its pointer and
                        // committed the shared intent before this failed
                        // writer observed the pointer error. Purging here
                        // could therefore delete a committed deposit. The
                        // stable intent/key pair lets every later retry
                        // reconcile this value safely.
                        return Err(nats_error("put recent-deposit pointer", error));
                    }
                };
                if pointer_write == RecentDepositPointerWrite::Superseded {
                    // This attempt crashed or stalled for longer than an
                    // entire ring rotation before its pointer became durable.
                    // Refresh only the uncommitted ordinal under CAS and retry
                    // against the stable operation-scoped deposit key.
                    self.refresh_uncommitted_deposit_intent_ordinal(connection, &stored)
                        .await?;
                    continue;
                }
                if !self
                    .commit_idempotent_deposit_intent(connection, &stored, revision)
                    .await?
                {
                    continue;
                }
                self.verified_deposit_cache
                    .lock()
                    .map_err(|_| SubstrateError::PoisonedLock)?
                    .insert(key, revision, deposit);
                self.note_gc_page(gc_page);
                return Ok(());
            }
            return Err(SubstrateError::Nats {
                operation: "commit idempotent deposit",
                reason: format!(
                    "compare-and-swap contention exceeded {MAX_RECENT_DEPOSIT_INDEX_CAS_ATTEMPTS} attempts"
                ),
            });
        }

        let ordinal = self
            .allocate_recent_deposit_ordinal(connection, kind)
            .await?;
        let key = deposit_key(
            &deposit,
            &payload,
            policy.half_life_secs,
            policy.evaporation_threshold,
            ordinal,
        );
        let revision = connection
            .store
            .put(key.clone(), payload.into())
            .await
            .map_err(|error| nats_error("put value", error))?;
        let pointer = RecentDepositPointer {
            ordinal,
            kind,
            deposit_key: key.clone(),
            deposit_revision: revision,
        };
        if let Err(error) = self
            .write_recent_deposit_pointer(connection, &pointer)
            .await
        {
            // Admission is not successful unless both the durable value and
            // its bounded global replay pointer are visible. Remove the exact
            // unique deposit subject before returning the indexing failure so
            // a caller retry cannot leave an unindexed durable orphan.
            self.purge_deposit_key(connection, &key).await?;
            return Err(nats_error("put recent-deposit pointer", error));
        }
        self.verified_deposit_cache
            .lock()
            .map_err(|_| SubstrateError::PoisonedLock)?
            .insert(key, revision, deposit);
        self.note_gc_page(gc_page);
        Ok(())
    }

    async fn record_escalation(&self, record: EscalationRecord) -> Result<(), SubstrateError> {
        let connection = self.ensure_connected().await?;
        let payload = serde_json::to_vec(&record).map_err(|source| SubstrateError::Encode {
            context: "jetstream escalation record".to_string(),
            source,
        })?;
        let key = escalation_key(&record, &payload);
        connection
            .store
            .put(key, payload.into())
            .await
            .map_err(|error| nats_error("put value", error))?;
        Ok(())
    }

    async fn store_threat_class_config(
        &self,
        config: ThreatClassConfig,
    ) -> Result<(), SubstrateError> {
        let connection = self.ensure_connected().await?;
        let threat_class_segment = threat_class_segment(&config.threat_class);
        let payload = serde_json::to_vec(&config).map_err(|source| SubstrateError::Encode {
            context: "jetstream threat class config".to_string(),
            source,
        })?;
        let key = threat_class_config_key(&config.threat_class);
        connection
            .store
            .put(key, payload.into())
            .await
            .map_err(|error| nats_error("put value", error))?;
        // GC pages are admission-time hints, not durable expiry authority.
        // A policy update must force a policy-aware replay so deposits that
        // remain live under a lower threshold cannot be discarded by an old
        // encoded page.
        self.deposit_key_indexes
            .lock()
            .await
            .partitions
            .remove(&threat_class_segment);
        Ok(())
    }

    async fn store_threat_intel_entry(
        &self,
        entry: ThreatIntelEntry,
    ) -> Result<(), SubstrateError> {
        let connection = self.ensure_connected().await?;
        let entry = ThreatIntelEntry {
            value: normalize_threat_intel_value(&entry.indicator_type, &entry.value),
            ..entry
        };
        let payload = serde_json::to_vec(&entry).map_err(|source| SubstrateError::Encode {
            context: "jetstream threat intel entry".to_string(),
            source,
        })?;
        let key = threat_intel_key(&entry.indicator_type, &entry.value);
        connection
            .store
            .put(key, payload.into())
            .await
            .map_err(|error| nats_error("put value", error))?;
        Ok(())
    }

    async fn store_behavioral_baseline_snapshot(
        &self,
        snapshot: BehavioralBaselineSnapshot,
        signer_agent_id: &AgentId,
        signing_key: &SigningKey,
    ) -> Result<(), SubstrateError> {
        let connection = self.ensure_connected().await?;
        let key = behavioral_baseline_key(&snapshot.strategy_id);
        let sequence_key = behavioral_baseline_sequence_key(&snapshot.strategy_id);
        let current_sequence = self
            .load_behavioral_baseline_sequence(&snapshot.strategy_id)
            .await?
            .unwrap_or(0);
        let envelope = SignedStateEnvelope::sign(
            BEHAVIORAL_BASELINE_STATE_KIND,
            snapshot.strategy_id.clone(),
            signer_agent_id.clone(),
            current_sequence.saturating_add(1),
            snapshot,
            signing_key,
        )
        .map_err(|source| SubstrateError::InvalidBehavioralBaseline {
            strategy_id: key.clone(),
            source,
        })?;
        let payload = serde_json::to_vec(&envelope).map_err(|source| SubstrateError::Encode {
            context: "jetstream behavioral baseline snapshot".to_string(),
            source,
        })?;
        connection
            .store
            .put(key, payload.into())
            .await
            .map_err(|error| nats_error("put value", error))?;
        let sequence_payload =
            serde_json::to_vec(&envelope.sequence()).map_err(|source| SubstrateError::Encode {
                context: "jetstream behavioral baseline sequence".to_string(),
                source,
            })?;
        connection
            .store
            .put(sequence_key, sequence_payload.into())
            .await
            .map_err(|error| nats_error("put value", error))?;
        Ok(())
    }

    async fn query_concentration(
        &self,
        threat_class: &ThreatClass,
        now: i64,
    ) -> Result<PheromoneConcentration, SubstrateError> {
        let threat_class_config = self.load_threat_class_config(threat_class).await?;
        let policy = self
            .config
            .resolve_threat_class_policy(threat_class_config.as_ref());
        let deposits = self
            .load_deposits(Some(threat_class), None, Some(now))
            .await?;
        Ok(concentration_for(&deposits, threat_class, now, &policy))
    }

    async fn query_deposits(
        &self,
        query: DepositQuery,
    ) -> Result<Vec<PheromoneDeposit>, SubstrateError> {
        let deposits = self
            .load_deposits(query.threat_class.as_ref(), query.since_timestamp, None)
            .await?;
        Ok(filter_deposits(&deposits, query))
    }

    async fn recent_deposits(&self, limit: usize) -> Result<Vec<PheromoneDeposit>, SubstrateError> {
        let deposits = self
            .load_deposits_bounded(
                None,
                None,
                None,
                MAX_RECENT_DEPOSIT_INDEX_SLOTS as usize,
                true,
            )
            .await?;
        let visible = filter_deposits(&deposits, DepositQuery::recent(0));
        Ok(balance_recent_deposit_results(visible, limit))
    }

    async fn query_escalations(
        &self,
        since_timestamp: i64,
    ) -> Result<Vec<EscalationRecord>, SubstrateError> {
        self.load_escalations(since_timestamp).await
    }

    async fn query_threat_class_config(
        &self,
        threat_class: &ThreatClass,
    ) -> Result<Option<ThreatClassConfig>, SubstrateError> {
        self.load_threat_class_config(threat_class).await
    }

    async fn query_threat_class_configs(&self) -> Result<Vec<ThreatClassConfig>, SubstrateError> {
        self.load_threat_class_configs().await
    }

    async fn query_threat_intel_entry(
        &self,
        indicator_type: &ThreatIntelIndicatorType,
        value: &str,
        now: i64,
    ) -> Result<Option<ThreatIntelEntry>, SubstrateError> {
        self.load_threat_intel_entry(indicator_type, value, now)
            .await
    }

    async fn query_behavioral_baseline_snapshot(
        &self,
        strategy_id: &str,
        expected_signer_agent_id: &AgentId,
    ) -> Result<Option<BehavioralBaselineSnapshot>, SubstrateError> {
        let Some(envelope) = self.load_behavioral_baseline_snapshot(strategy_id).await? else {
            return Ok(None);
        };
        let accepted_sequence = self.load_behavioral_baseline_sequence(strategy_id).await?;
        let statement = envelope
            .verify(SignedStateExpectation {
                state_kind: BEHAVIORAL_BASELINE_STATE_KIND,
                stream_id: strategy_id,
                expected_signer_agent_id: Some(expected_signer_agent_id),
                accepted_sequence,
            })
            .map_err(|source| SubstrateError::InvalidBehavioralBaseline {
                strategy_id: strategy_id.to_string(),
                source,
            })?;
        if accepted_sequence.is_none_or(|sequence| sequence < statement.sequence) {
            let connection = self.ensure_connected().await?;
            let payload = serde_json::to_vec(&statement.sequence).map_err(|source| {
                SubstrateError::Encode {
                    context: "jetstream behavioral baseline sequence".to_string(),
                    source,
                }
            })?;
            connection
                .store
                .put(
                    behavioral_baseline_sequence_key(strategy_id),
                    payload.into(),
                )
                .await
                .map_err(|error| nats_error("put value", error))?;
        }
        Ok(Some(statement.payload))
    }

    async fn gc_evaporated(&self, now: i64) -> Result<usize, SubstrateError> {
        let connection = self.ensure_connected().await?;
        if self.load_threat_class_configs().await?.is_empty() {
            let mut removed = 0usize;
            removed = removed.saturating_add(self.gc_evaporated_legacy(now).await?);
            removed = removed.saturating_add(self.gc_evaporated_by_page(now).await?);
            removed =
                removed.saturating_add(self.gc_expired_idempotent_intents(connection, now).await?);
            return Ok(removed);
        }

        let mut removed = 0usize;
        removed = removed.saturating_add(self.gc_evaporated_with_policy_scan(now).await?);
        removed =
            removed.saturating_add(self.gc_expired_idempotent_intents(connection, now).await?);
        Ok(removed)
    }

    async fn gc_expired_threat_intel(&self, now: i64) -> Result<usize, SubstrateError> {
        let connection = self.ensure_connected().await?;
        let mut keys = connection
            .store
            .keys()
            .await
            .map_err(|error| nats_error("list keys", error))?;
        let mut purged = 0usize;

        while let Some(entry) = keys.next().await {
            let key = entry.map_err(|error| nats_error("stream keys", error))?;
            if !is_threat_intel_key(&key) {
                continue;
            }

            let Some(payload) = connection
                .store
                .get(&key)
                .await
                .map_err(|error| nats_error("get value", error))?
            else {
                continue;
            };

            let location = format!("jetstream://{}/{}", self.bucket, key);
            let intel_entry = serde_json::from_slice::<ThreatIntelEntry>(&payload)
                .map_err(|source| SubstrateError::Decode { location, source })?;

            if intel_entry.expires_at <= now {
                connection
                    .store
                    .delete(&key)
                    .await
                    .map_err(|error| nats_error("delete value", error))?;
                purged = purged.saturating_add(1);
            }
        }

        if purged > 0 {
            tracing::info!(purged, "gc_expired_threat_intel complete");
        } else {
            tracing::debug!(purged, "gc_expired_threat_intel complete");
        }
        Ok(purged)
    }

    async fn health(&self) -> Result<SubstrateHealth, SubstrateError> {
        match self.ensure_connected().await {
            Ok(connection) => {
                let ready = connection.client.connection_state()
                    == async_nats::connection::State::Connected;
                let deposit_count = match self.deposit_count().await {
                    Ok(count) => count,
                    Err(error) => {
                        return Ok(SubstrateHealth {
                            backend: "jetstream".to_string(),
                            durable: true,
                            ready: false,
                            details: format!(
                                "JetStream bucket `{}` at {} is reachable, but key listing failed: {error}",
                                self.bucket, self.url
                            ),
                            deposit_count: 0,
                        });
                    }
                };

                Ok(SubstrateHealth {
                    backend: "jetstream".to_string(),
                    durable: true,
                    ready,
                    details: format!("JetStream KV bucket `{}` at {}", self.bucket, self.url),
                    deposit_count,
                })
            }
            Err(error) => Ok(SubstrateHealth {
                backend: "jetstream".to_string(),
                durable: true,
                ready: false,
                details: format!("JetStream unavailable: {error}"),
                deposit_count: 0,
            }),
        }
    }
}

#[cfg(not(feature = "nats"))]
#[async_trait]
impl PheromoneSubstrate for JetStreamPheromoneSubstrate {
    async fn deposit(&self, _deposit: PheromoneDeposit) -> Result<(), SubstrateError> {
        Err(unsupported_backend())
    }

    async fn record_escalation(&self, _record: EscalationRecord) -> Result<(), SubstrateError> {
        Err(unsupported_backend())
    }

    async fn store_threat_class_config(
        &self,
        _config: ThreatClassConfig,
    ) -> Result<(), SubstrateError> {
        Err(unsupported_backend())
    }

    async fn store_threat_intel_entry(
        &self,
        _entry: ThreatIntelEntry,
    ) -> Result<(), SubstrateError> {
        Err(unsupported_backend())
    }

    async fn store_behavioral_baseline_snapshot(
        &self,
        _snapshot: BehavioralBaselineSnapshot,
        _signer_agent_id: &AgentId,
        _signing_key: &SigningKey,
    ) -> Result<(), SubstrateError> {
        Err(unsupported_backend())
    }

    async fn query_concentration(
        &self,
        _threat_class: &ThreatClass,
        _now: i64,
    ) -> Result<PheromoneConcentration, SubstrateError> {
        Err(unsupported_backend())
    }

    async fn query_deposits(
        &self,
        _query: DepositQuery,
    ) -> Result<Vec<PheromoneDeposit>, SubstrateError> {
        Err(unsupported_backend())
    }

    async fn query_escalations(
        &self,
        _since_timestamp: i64,
    ) -> Result<Vec<EscalationRecord>, SubstrateError> {
        Err(unsupported_backend())
    }

    async fn query_threat_class_config(
        &self,
        _threat_class: &ThreatClass,
    ) -> Result<Option<ThreatClassConfig>, SubstrateError> {
        Err(unsupported_backend())
    }

    async fn query_threat_class_configs(&self) -> Result<Vec<ThreatClassConfig>, SubstrateError> {
        Err(unsupported_backend())
    }

    async fn query_threat_intel_entry(
        &self,
        _indicator_type: &ThreatIntelIndicatorType,
        _value: &str,
        _now: i64,
    ) -> Result<Option<ThreatIntelEntry>, SubstrateError> {
        Err(unsupported_backend())
    }

    async fn query_behavioral_baseline_snapshot(
        &self,
        _strategy_id: &str,
        _expected_signer_agent_id: &AgentId,
    ) -> Result<Option<BehavioralBaselineSnapshot>, SubstrateError> {
        Err(unsupported_backend())
    }

    async fn gc_evaporated(&self, _now: i64) -> Result<usize, SubstrateError> {
        Err(unsupported_backend())
    }

    async fn gc_expired_threat_intel(&self, _now: i64) -> Result<usize, SubstrateError> {
        Err(unsupported_backend())
    }

    async fn health(&self) -> Result<SubstrateHealth, SubstrateError> {
        Ok(SubstrateHealth {
            backend: "jetstream".to_string(),
            durable: true,
            ready: false,
            details: "backend compiled without `nats` feature".to_string(),
            deposit_count: 0,
        })
    }
}

#[cfg(feature = "nats")]
async fn ensure_kv_bucket(
    jetstream: &async_nats::jetstream::Context,
    bucket: &str,
) -> Result<async_nats::jetstream::kv::Store, SubstrateError> {
    match jetstream.get_key_value(bucket).await {
        Ok(store) => {
            let configured_max_bytes = store.stream.cached_info().config.max_bytes;
            if configured_max_bytes > 0 && configured_max_bytes <= MAX_JETSTREAM_BUCKET_BYTES {
                return Ok(store);
            }
            let mut config = store.stream.cached_info().config.clone();
            config.max_bytes = MAX_JETSTREAM_BUCKET_BYTES;
            jetstream
                .update_stream(config)
                .await
                .map_err(|error| nats_error("bound existing kv bucket", error))?;
            jetstream
                .get_key_value(bucket)
                .await
                .map_err(|error| nats_error("reopen bounded kv bucket", error))
        }
        Err(_) => jetstream
            .create_key_value(async_nats::jetstream::kv::Config {
                bucket: bucket.to_string(),
                history: 1,
                max_bytes: MAX_JETSTREAM_BUCKET_BYTES,
                ..Default::default()
            })
            .await
            .map_err(|error| nats_error("create kv bucket", error)),
    }
}

#[cfg(feature = "nats")]
fn deposit_key(
    deposit: &PheromoneDeposit,
    payload: &[u8],
    policy_half_life_secs: f64,
    evaporation_threshold: f64,
    ordinal: u64,
) -> String {
    let gc_page = expiration_gc_page(deposit, policy_half_life_secs, evaporation_threshold);
    let threat_class = threat_class_segment(&deposit.threat_class);
    let kind = match deposit_kind(deposit) {
        DepositKeyKind::Evidence => "evidence",
        DepositKeyKind::Control => "control",
    };
    let agent_hash = hash_prefix(deposit.agent_id.0.as_bytes(), 12);
    let deposit_hash = hash_prefix(payload, 12);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "{GC_KEY_PREFIX}.{gc_page:020}.{threat_class}.{kind}.{:020}.o{ordinal:020}-l{:020}-{}-{deposit_hash}-{nonce}",
        deposit.timestamp.max(0),
        payload.len(),
        agent_hash
    )
}

#[cfg(feature = "nats")]
fn idempotent_deposit_key(
    deposit: &PheromoneDeposit,
    payload: &[u8],
    policy_half_life_secs: f64,
    evaporation_threshold: f64,
    operation_id: &str,
) -> String {
    let gc_page = expiration_gc_page(deposit, policy_half_life_secs, evaporation_threshold);
    let threat_class = threat_class_segment(&deposit.threat_class);
    let kind = match deposit_kind(deposit) {
        DepositKeyKind::Evidence => "evidence",
        DepositKeyKind::Control => "control",
    };
    let agent_hash = hash_prefix(deposit.agent_id.0.as_bytes(), 12);
    let deposit_hash = hash_prefix(payload, 12);
    let operation_hash = hash_prefix(operation_id.as_bytes(), 64);
    format!(
        "{GC_KEY_PREFIX}.{gc_page:020}.{threat_class}.{kind}.{:020}.i{operation_hash}-l{:020}-{agent_hash}-{deposit_hash}",
        deposit.timestamp.max(0),
        payload.len(),
    )
}

#[cfg(feature = "nats")]
fn deposit_kind(deposit: &PheromoneDeposit) -> DepositKeyKind {
    if deposit.confidence == 0.0 {
        DepositKeyKind::Control
    } else {
        DepositKeyKind::Evidence
    }
}

#[cfg(feature = "nats")]
fn suppression_scope_digest(deposit: &VerifiedDeposit) -> Result<Option<String>, SubstrateError> {
    // Zero-strength deposits are replay controls, but only an authenticated
    // Providence feedback marker can suppress evidence. Do not make ordinary
    // zero-strength observations consume the governed evidence pair budget.
    if deposit_kind(deposit) == DepositKeyKind::Control
        && feedback_suppression_marker(deposit).is_none()
    {
        return Ok(None);
    }
    let Some(event_id) = deposit
        .indicator
        .get("event_id")
        .and_then(serde_json::Value::as_str)
    else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&(&deposit.threat_class, event_id)).map_err(|source| {
        SubstrateError::Encode {
            context: "pheromone suppression scope".to_string(),
            source,
        }
    })?;
    Ok(Some(hash_prefix(&encoded, 64)))
}

#[cfg(feature = "nats")]
fn recent_deposit_index_key(kind: DepositKeyKind, ordinal: u64) -> String {
    let kind = match kind {
        DepositKeyKind::Evidence => "evidence",
        DepositKeyKind::Control => "control",
    };
    format!(
        "{RECENT_DEPOSIT_INDEX_KEY_PREFIX}.{kind}.{:03}",
        ordinal % MAX_RECENT_DEPOSIT_INDEX_SLOTS
    )
}

#[cfg(feature = "nats")]
fn recent_deposit_index_state_key(kind: DepositKeyKind) -> String {
    let kind = match kind {
        DepositKeyKind::Evidence => "evidence",
        DepositKeyKind::Control => "control",
    };
    format!("{RECENT_DEPOSIT_INDEX_STATE_KEY_PREFIX}.{kind}")
}

#[cfg(feature = "nats")]
fn migration_recent_deposit_pointers(
    kind: DepositKeyKind,
    pointers: Vec<(String, u64)>,
    boundary_stream_sequence: u64,
    existing: &[RecentDepositPointer],
) -> Result<(Vec<RecentDepositPointer>, u64), SubstrateError> {
    let selected_pointers = pointers.clone();
    let mut current_by_slot = BTreeMap::<u64, RecentDepositPointer>::new();
    let mut legacy = Vec::new();

    for (deposit_key, deposit_revision) in pointers {
        if let Some(ordinal) = deposit_key_ordinal(&deposit_key) {
            if ordinal == 0 || ordinal > boundary_stream_sequence {
                return Err(SubstrateError::InvalidDeposit {
                    reason: format!(
                        "JetStream migration key `{deposit_key}` carries ordinal {ordinal} outside boundary {boundary_stream_sequence}"
                    ),
                });
            }
            let pointer = RecentDepositPointer {
                ordinal,
                kind,
                deposit_key,
                deposit_revision,
            };
            let slot = ordinal % MAX_RECENT_DEPOSIT_INDEX_SLOTS;
            match current_by_slot.get(&slot) {
                Some(existing) if existing.ordinal == ordinal && existing != &pointer => {
                    return Err(SubstrateError::InvalidDeposit {
                        reason: format!(
                            "JetStream migration ordinal {ordinal} identifies conflicting current-layout deposits"
                        ),
                    });
                }
                Some(existing) if existing.ordinal >= ordinal => {}
                _ => {
                    current_by_slot.insert(slot, pointer);
                }
            }
        } else {
            legacy.push((deposit_key, deposit_revision));
        }
    }

    let first_candidate = boundary_stream_sequence
        .saturating_sub(MAX_RECENT_DEPOSIT_INDEX_SLOTS.saturating_sub(1))
        .max(1);
    let mut available_ordinals = (first_candidate..=boundary_stream_sequence)
        .filter(|ordinal| {
            !current_by_slot.contains_key(&(ordinal % MAX_RECENT_DEPOSIT_INDEX_SLOTS))
        })
        .collect::<Vec<_>>();
    if legacy.len() > available_ordinals.len() {
        return Err(SubstrateError::InvalidDeposit {
            reason: "JetStream migration window has more legacy deposits than free ring slots"
                .to_string(),
        });
    }
    // Keep the newest available ordinal range. The legacy input is already
    // ordered oldest-to-newest, so this is deterministic across concurrent
    // initializers and preserves relative replay order without aliasing an
    // embedded current-layout slot.
    let retained_start = available_ordinals.len().saturating_sub(legacy.len());
    available_ordinals.drain(..retained_start);

    let mut output = current_by_slot.into_values().collect::<Vec<_>>();
    output.extend(legacy.into_iter().zip(available_ordinals).map(
        |((deposit_key, deposit_revision), ordinal)| RecentDepositPointer {
            ordinal,
            kind,
            deposit_key,
            deposit_revision,
        },
    ));
    output.sort_by_key(|pointer| pointer.ordinal);

    let selected_count =
        u64::try_from(selected_pointers.len()).map_err(|_| SubstrateError::InvalidDeposit {
            reason: "JetStream migration window exceeds the supported ordinal range".to_string(),
        })?;
    let mut prior_boundary = None;
    for existing_pointer in existing {
        let Some((index, _)) = selected_pointers
            .iter()
            .enumerate()
            .find(|(_, (key, revision))| {
                key == &existing_pointer.deposit_key
                    && revision == &existing_pointer.deposit_revision
            })
        else {
            continue;
        };
        if output.iter().any(|candidate| candidate == existing_pointer) {
            continue;
        }
        let index = u64::try_from(index).map_err(|_| SubstrateError::InvalidDeposit {
            reason: "JetStream migration window exceeds the supported ordinal range".to_string(),
        })?;
        let remaining = selected_count.saturating_sub(index.saturating_add(1));
        let inferred = existing_pointer.ordinal.checked_add(remaining).ok_or_else(|| {
            SubstrateError::InvalidDeposit {
                reason: "JetStream previous-version migration boundary overflows the supported ordinal range"
                    .to_string(),
            }
        })?;
        match prior_boundary {
            Some(boundary) if boundary != inferred => {
                return Err(SubstrateError::InvalidDeposit {
                    reason:
                        "JetStream migration found inconsistent previous-version partial mappings"
                            .to_string(),
                });
            }
            _ => prior_boundary = Some(inferred),
        }
    }

    let Some(prior_boundary) = prior_boundary else {
        return Ok((output, boundary_stream_sequence));
    };
    let first_ordinal = prior_boundary
        .saturating_sub(selected_count)
        .saturating_add(1);
    let prior_mapping = selected_pointers
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, (deposit_key, deposit_revision))| {
            let index = u64::try_from(index).map_err(|_| SubstrateError::InvalidDeposit {
                reason: "JetStream migration window exceeds the supported ordinal range"
                    .to_string(),
            })?;
            Ok(RecentDepositPointer {
                ordinal: first_ordinal.saturating_add(index),
                kind,
                deposit_key,
                deposit_revision,
            })
        })
        .collect::<Result<Vec<_>, SubstrateError>>()?;
    let previous_version_stop = prior_mapping
        .iter()
        .position(|pointer| {
            deposit_key_ordinal(&pointer.deposit_key)
                .is_some_and(|embedded| embedded != pointer.ordinal)
        })
        .unwrap_or(prior_mapping.len());
    for existing_pointer in existing {
        if output.iter().any(|candidate| candidate == existing_pointer) {
            continue;
        }
        let prior_index = prior_mapping.iter().position(|candidate| {
            candidate.deposit_key == existing_pointer.deposit_key
                && candidate.deposit_revision == existing_pointer.deposit_revision
        });
        if prior_index.is_some_and(|index| {
            index >= previous_version_stop || &prior_mapping[index] != existing_pointer
        }) {
            return Err(SubstrateError::InvalidDeposit {
                reason: "JetStream migration found a partial mapping that cannot converge with the previous-version boundary"
                    .to_string(),
            });
        }
    }

    // The previous implementation stops before writing a current-layout key
    // whose embedded ordinal differs from its independently captured dense
    // mapping. Preserve the prefix it could have written, preserve all
    // immutable current-layout ordinals, and deterministically fill only the
    // remaining legacy slots. This converges even when old and new binaries
    // overlap during a rolling deployment.
    let mut fixed_by_slot = BTreeMap::<u64, RecentDepositPointer>::new();
    let insert_fixed = |fixed: &mut BTreeMap<u64, RecentDepositPointer>,
                        pointer: RecentDepositPointer| {
        let slot = pointer.ordinal % MAX_RECENT_DEPOSIT_INDEX_SLOTS;
        match fixed.get(&slot) {
            Some(current) if current.ordinal == pointer.ordinal && current != &pointer => {
                Err(SubstrateError::InvalidDeposit {
                    reason: format!(
                        "JetStream migration ordinal {} identifies conflicting fixed deposits",
                        pointer.ordinal
                    ),
                })
            }
            Some(current) if current.ordinal >= pointer.ordinal => Ok(()),
            _ => {
                fixed.insert(slot, pointer);
                Ok(())
            }
        }
    };
    for pointer in prior_mapping.iter().take(previous_version_stop).cloned() {
        insert_fixed(&mut fixed_by_slot, pointer)?;
    }
    for ((deposit_key, deposit_revision), current_pointer) in
        selected_pointers.iter().zip(&prior_mapping)
    {
        if let Some(ordinal) = deposit_key_ordinal(deposit_key) {
            insert_fixed(
                &mut fixed_by_slot,
                RecentDepositPointer {
                    ordinal,
                    kind,
                    deposit_key: deposit_key.clone(),
                    deposit_revision: *deposit_revision,
                },
            )?;
        } else if existing.iter().any(|pointer| {
            pointer.deposit_key == current_pointer.deposit_key
                && pointer.deposit_revision == current_pointer.deposit_revision
                && output.iter().any(|candidate| candidate == pointer)
        }) {
            let existing_pointer = existing
                .iter()
                .find(|pointer| {
                    pointer.deposit_key == current_pointer.deposit_key
                        && pointer.deposit_revision == current_pointer.deposit_revision
                        && output.iter().any(|candidate| candidate == *pointer)
                })
                .cloned()
                .ok_or_else(|| SubstrateError::InvalidDeposit {
                    reason: "JetStream migration lost an existing fixed pointer during planning"
                        .to_string(),
                })?;
            insert_fixed(&mut fixed_by_slot, existing_pointer)?;
        }
    }

    let mut remaining_legacy = selected_pointers
        .iter()
        .enumerate()
        .filter(|(index, (key, revision))| {
            *index >= previous_version_stop
                && deposit_key_ordinal(key).is_none()
                && !fixed_by_slot.values().any(|pointer| {
                    pointer.deposit_key == *key && pointer.deposit_revision == *revision
                })
        })
        .map(|(_, pointer)| pointer.clone())
        .collect::<Vec<_>>();
    let effective_boundary = fixed_by_slot
        .values()
        .map(|pointer| pointer.ordinal)
        .max()
        .unwrap_or(0)
        .max(boundary_stream_sequence)
        .max(prior_boundary);
    let first_candidate = effective_boundary
        .saturating_sub(MAX_RECENT_DEPOSIT_INDEX_SLOTS.saturating_sub(1))
        .max(1);
    let mut available_ordinals = (first_candidate..=effective_boundary)
        .filter(|ordinal| !fixed_by_slot.contains_key(&(ordinal % MAX_RECENT_DEPOSIT_INDEX_SLOTS)))
        .collect::<Vec<_>>();
    if remaining_legacy.len() > available_ordinals.len() {
        return Err(SubstrateError::InvalidDeposit {
            reason:
                "JetStream mixed-version migration has more legacy deposits than free ring slots"
                    .to_string(),
        });
    }
    let retained_start = available_ordinals
        .len()
        .saturating_sub(remaining_legacy.len());
    available_ordinals.drain(..retained_start);
    for ((deposit_key, deposit_revision), ordinal) in
        remaining_legacy.drain(..).zip(available_ordinals)
    {
        insert_fixed(
            &mut fixed_by_slot,
            RecentDepositPointer {
                ordinal,
                kind,
                deposit_key,
                deposit_revision,
            },
        )?;
    }
    let mut converged = fixed_by_slot.into_values().collect::<Vec<_>>();
    converged.sort_by_key(|pointer| pointer.ordinal);
    Ok((converged, effective_boundary))
}

#[cfg(feature = "nats")]
fn escalation_key(record: &EscalationRecord, payload: &[u8]) -> String {
    let threat_class = threat_class_segment(&record.threat_class);
    let record_hash = hash_prefix(payload, 12);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "{ESCALATION_KEY_PREFIX}.{:020}.{}.{}-{record_hash}-{nonce}",
        record.timestamp.max(0),
        mode_segment(record.mode),
        threat_class
    )
}

#[cfg(feature = "nats")]
fn threat_class_segment(threat_class: &ThreatClass) -> String {
    match threat_class {
        ThreatClass::LateralMovement => "lateral_movement".to_string(),
        ThreatClass::DataExfiltration => "data_exfiltration".to_string(),
        ThreatClass::PrivilegeEscalation => "privilege_escalation".to_string(),
        ThreatClass::CommandAndControl => "command_and_control".to_string(),
        ThreatClass::InitialAccess => "initial_access".to_string(),
        ThreatClass::Persistence => "persistence".to_string(),
        ThreatClass::SupplyChain => "supply_chain".to_string(),
        ThreatClass::DefenseEvasion => "defense_evasion".to_string(),
        ThreatClass::CredentialAccess => "credential_access".to_string(),
        ThreatClass::Discovery => "discovery".to_string(),
        ThreatClass::Execution => "execution".to_string(),
        ThreatClass::Impact => "impact".to_string(),
        ThreatClass::Custom(name) => format!(
            "custom_{}_{}",
            sanitize_segment(name).chars().take(64).collect::<String>(),
            hash_prefix(name.as_bytes(), 32)
        ),
    }
}

#[cfg(feature = "nats")]
fn legacy_threat_class_segment(threat_class: &ThreatClass) -> String {
    match threat_class {
        ThreatClass::Custom(name) => format!("custom_{}", sanitize_segment(name)),
        _ => threat_class_segment(threat_class),
    }
}

#[cfg(feature = "nats")]
fn mode_segment(mode: swarm_core::agent::SwarmMode) -> &'static str {
    match mode {
        swarm_core::agent::SwarmMode::Normal => "normal",
        swarm_core::agent::SwarmMode::Alert => "alert",
        swarm_core::agent::SwarmMode::Incident => "incident",
    }
}

#[cfg(feature = "nats")]
fn sanitize_segment(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();

    if sanitized.trim_matches('_').is_empty() {
        "custom".to_string()
    } else {
        sanitized
    }
}

#[cfg(feature = "nats")]
fn hash_prefix(bytes: &[u8], prefix_len: usize) -> String {
    let digest = Sha256::digest(bytes);
    let encoded = hex::encode(digest);
    let prefix_len = prefix_len.min(encoded.len());
    encoded[..prefix_len].to_string()
}

#[cfg(feature = "nats")]
fn legacy_idempotent_deposit_intent_key(operation_id: &str) -> String {
    format!(
        "{RECENT_DEPOSIT_INTENT_KEY_PREFIX}.{}",
        hash_prefix(operation_id.as_bytes(), 64)
    )
}

#[cfg(feature = "nats")]
fn idempotent_deposit_intent_key(operation_id: &str) -> String {
    format!(
        "{RECENT_DEPOSIT_INTENT_KEY_PREFIX}.v2.{}",
        hash_prefix(operation_id.as_bytes(), 64)
    )
}

#[cfg(feature = "nats")]
fn is_idempotent_deposit_intent_key(key: &str) -> bool {
    key.starts_with(&format!("{RECENT_DEPOSIT_INTENT_KEY_PREFIX}."))
}

#[cfg(feature = "nats")]
fn idempotent_deposit_intent_slot_keys(operation_id: &str) -> impl Iterator<Item = String> {
    let digest = Sha256::digest(operation_id.as_bytes());
    (0..IDEMPOTENT_DEPOSIT_INTENT_SLOT_CHOICES).map(move |choice| {
        let offset = choice * 8;
        let hash_word = digest[offset..offset + 8]
            .iter()
            .fold(0_u64, |word, byte| (word << 8) | u64::from(*byte));
        let slot = hash_word % MAX_IDEMPOTENT_DEPOSIT_INTENT_SLOTS;
        format!("{RECENT_DEPOSIT_INTENT_KEY_PREFIX}.s{slot:06}")
    })
}

#[cfg(feature = "nats")]
fn deposit_key_timestamp(key: &str) -> Option<i64> {
    if let Some(stripped) = key.strip_prefix(&format!("{GC_KEY_PREFIX}.")) {
        let mut parts = stripped.split('.');
        let _page = parts.next()?;
        let _threat_class = parts.next()?;
        let kind_or_timestamp = parts.next()?;
        return if matches!(kind_or_timestamp, "evidence" | "control") {
            parts.next()?.parse().ok()
        } else {
            kind_or_timestamp.parse().ok()
        };
    }

    key.split('.').nth(1)?.parse().ok()
}

#[cfg(feature = "nats")]
fn deposit_key_ordinal(key: &str) -> Option<u64> {
    let stripped = key.strip_prefix(&format!("{GC_KEY_PREFIX}."))?;
    let mut parts = stripped.split('.');
    let _page = parts.next()?;
    let _threat_class = parts.next()?;
    let kind = parts.next()?;
    if !matches!(kind, "evidence" | "control") {
        return None;
    }
    let _timestamp = parts.next()?;
    parts
        .next()?
        .split('-')
        .next()?
        .strip_prefix('o')?
        .parse()
        .ok()
}

#[cfg(feature = "nats")]
fn deposit_key_encoded_len(key: &str) -> Option<usize> {
    let stripped = key.strip_prefix(&format!("{GC_KEY_PREFIX}."))?;
    let mut parts = stripped.split('.');
    let _page = parts.next()?;
    let _threat_class = parts.next()?;
    let kind = parts.next()?;
    if !matches!(kind, "evidence" | "control") {
        return None;
    }
    let _timestamp = parts.next()?;
    parts
        .next()?
        .split('-')
        .nth(1)?
        .strip_prefix('l')?
        .parse()
        .ok()
}

#[cfg(feature = "nats")]
fn deposit_key_kind(key: &str) -> Option<DepositKeyKind> {
    let stripped = key.strip_prefix(&format!("{GC_KEY_PREFIX}."))?;
    match stripped.split('.').nth(2)? {
        "evidence" => Some(DepositKeyKind::Evidence),
        "control" => Some(DepositKeyKind::Control),
        _ => None,
    }
}

#[cfg(feature = "nats")]
fn is_escalation_key(key: &str) -> bool {
    key.starts_with(&format!("{ESCALATION_KEY_PREFIX}."))
}

#[cfg(feature = "nats")]
fn is_policy_key(key: &str) -> bool {
    key.starts_with(&format!("{THREAT_CLASS_CONFIG_KEY_PREFIX}."))
}

#[cfg(feature = "nats")]
fn is_threat_intel_key(key: &str) -> bool {
    key.starts_with(&format!("{THREAT_INTEL_KEY_PREFIX}."))
}

#[cfg(feature = "nats")]
fn is_behavioral_baseline_key(key: &str) -> bool {
    key.starts_with(&format!("{BEHAVIORAL_BASELINE_KEY_PREFIX}."))
}

#[cfg(feature = "nats")]
fn is_recent_deposit_index_key(key: &str) -> bool {
    key == RECENT_DEPOSIT_COMPATIBILITY_STATE_KEY
        || key == RECENT_DEPOSIT_MIGRATION_STATE_KEY
        || key.starts_with(&format!("{RECENT_DEPOSIT_INTENT_KEY_PREFIX}."))
        || key.starts_with(&format!("{RECENT_DEPOSIT_INDEX_STATE_KEY_PREFIX}."))
        || key.starts_with(&format!("{RECENT_DEPOSIT_INDEX_KEY_PREFIX}."))
}

#[cfg(feature = "nats")]
fn is_non_deposit_key(key: &str) -> bool {
    is_escalation_key(key)
        || is_policy_key(key)
        || is_threat_intel_key(key)
        || is_behavioral_baseline_key(key)
        || is_recent_deposit_index_key(key)
}

#[cfg(feature = "nats")]
fn threat_class_config_key(threat_class: &ThreatClass) -> String {
    format!(
        "{THREAT_CLASS_CONFIG_KEY_PREFIX}.{}",
        threat_class_segment(threat_class)
    )
}

#[cfg(feature = "nats")]
fn legacy_threat_class_config_key(threat_class: &ThreatClass) -> String {
    format!(
        "{THREAT_CLASS_CONFIG_KEY_PREFIX}.{}",
        legacy_threat_class_segment(threat_class)
    )
}

#[cfg(feature = "nats")]
fn threat_intel_key(indicator_type: &ThreatIntelIndicatorType, value: &str) -> String {
    let normalized = normalize_threat_intel_value(indicator_type, value);
    format!(
        "{THREAT_INTEL_KEY_PREFIX}.{}.{}",
        threat_intel_indicator_segment(indicator_type),
        hash_prefix(normalized.as_bytes(), 64)
    )
}

#[cfg(feature = "nats")]
fn behavioral_baseline_key(strategy_id: &str) -> String {
    format!(
        "{BEHAVIORAL_BASELINE_KEY_PREFIX}.{}",
        sanitize_segment(strategy_id)
    )
}

#[cfg(feature = "nats")]
fn behavioral_baseline_sequence_key(strategy_id: &str) -> String {
    format!(
        "{BEHAVIORAL_BASELINE_KEY_PREFIX}.sequence.{}",
        sanitize_segment(strategy_id)
    )
}

#[cfg(feature = "nats")]
fn threat_intel_indicator_segment(indicator_type: &ThreatIntelIndicatorType) -> &'static str {
    match indicator_type {
        ThreatIntelIndicatorType::IpAddress => "ip_address",
        ThreatIntelIndicatorType::Domain => "domain",
        ThreatIntelIndicatorType::FileHash => "file_hash",
        ThreatIntelIndicatorType::Url => "url",
    }
}

#[cfg(feature = "nats")]
fn expiration_gc_page(
    deposit: &PheromoneDeposit,
    policy_half_life_secs: f64,
    evaporation_threshold: f64,
) -> i64 {
    let deadline = evaporation_deadline(deposit, policy_half_life_secs, evaporation_threshold);
    div_ceil_i64(deadline.max(0), GC_PAGE_SPAN_SECS)
}

#[cfg(feature = "nats")]
fn evaporation_deadline(
    deposit: &PheromoneDeposit,
    policy_half_life_secs: f64,
    evaporation_threshold: f64,
) -> i64 {
    let initial_strength = retention_initial_strength(deposit);
    if initial_strength <= evaporation_threshold || deposit.decay_half_life <= 0.0 {
        return deposit.timestamp;
    }

    let elapsed_until_evaporation = deposit.decay_half_life.min(policy_half_life_secs)
        * (initial_strength / evaporation_threshold).log2();
    deposit
        .timestamp
        .saturating_add(elapsed_until_evaporation.ceil() as i64)
}

#[cfg(feature = "nats")]
fn gc_sweep_page(now: i64) -> i64 {
    now.max(0).div_euclid(GC_PAGE_SPAN_SECS)
}

#[cfg(feature = "nats")]
fn div_ceil_i64(value: i64, divisor: i64) -> i64 {
    let quotient = value.div_euclid(divisor);
    let remainder = value.rem_euclid(divisor);
    if remainder == 0 {
        quotient
    } else {
        quotient.saturating_add(1)
    }
}

#[cfg(feature = "nats")]
fn key_gc_page(key: &str) -> Option<i64> {
    let stripped = key.strip_prefix(&format!("{GC_KEY_PREFIX}."))?;
    stripped.split('.').next()?.parse().ok()
}

#[cfg(feature = "nats")]
fn intent_key_gc_page(key: &str) -> Option<i64> {
    key.strip_prefix(&format!("{RECENT_DEPOSIT_INTENT_KEY_PREFIX}.p"))?
        .split('.')
        .next()?
        .parse()
        .ok()
}

#[cfg(feature = "nats")]
fn gc_page_subject(page: i64) -> String {
    format!("{GC_KEY_PREFIX}.{page:020}.>")
}

#[cfg(feature = "nats")]
fn intent_gc_page_subject(page: i64) -> String {
    format!("{RECENT_DEPOSIT_INTENT_KEY_PREFIX}.p{page:020}.>")
}

#[cfg(not(feature = "nats"))]
fn unsupported_backend() -> SubstrateError {
    SubstrateError::UnsupportedBackend {
        backend: "jetstream",
        reason: "swarm-pheromone was compiled without `nats` support".to_string(),
    }
}

#[cfg(feature = "nats")]
fn nats_error(operation: &'static str, error: impl fmt::Display) -> SubstrateError {
    SubstrateError::Nats {
        operation,
        reason: error.to_string(),
    }
}

#[cfg(all(test, feature = "nats"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        DEFAULT_JETSTREAM_GC_PAGE_SIZE, DEFAULT_NATS_CONNECT_TIMEOUT_MS, DepositKeyIndexes,
        DepositKeyKind, DepositKeyPartitionIndex, IndexedDepositKey, IndexedFeedbackMarker,
        JetStreamPheromoneSubstrate, MAX_DEPOSIT_KEY_INDEX_PARTITIONS,
        MAX_RECENT_DEPOSIT_INDEX_SLOTS, MAX_VERIFIED_DEPOSIT_CACHE_ENTRIES, NatsAuthentication,
        RecentDepositPointer, RecentDepositPointerCasHook, RecentDepositPointerWrite,
        SelectedDepositKey, VerifiedDepositCache, deposit_key_encoded_len, deposit_key_kind,
        deposit_key_ordinal, deposit_key_timestamp, evaporation_deadline, expiration_gc_page,
        gc_sweep_page, legacy_threat_class_segment, migration_recent_deposit_pointers,
        parse_nats_endpoint, recent_deposit_index_key, retain_newest_deposit_key,
        retain_newest_partitioned_deposit_key_as, select_recent_deposit_keys_within_byte_limit,
        threat_class_segment,
    };
    use crate::{
        PheromoneSubstrate,
        substrate::{
            MAX_ACTIVE_DEPOSIT_BYTES, MAX_SINGLE_DEPOSIT_BYTES, VerifiedDeposit,
            deposit_suppression_key, feedback_suppression_marker,
        },
    };
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use swarm_core::agent::SwarmMode;
    use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig, ResponsePlaybookConfig};
    use swarm_core::pheromone::{
        EscalationRecord, PheromoneDeposit, ThreatClass, ThreatClassConfig, ThreatIntelEntry,
        ThreatIntelIndicatorType,
    };
    use swarm_core::types::{AgentId, SWARM_PROVIDENCE_FEEDBACK_SCHEMA, Severity};
    use tokio_stream::StreamExt as _;

    fn substrate_config() -> PheromoneConfig {
        PheromoneConfig {
            default_half_life_secs: 3600.0,
            evaporation_threshold: 0.01,
            min_sources_for_escalation: 2,
            alert_threshold: 2.0,
            incident_threshold: 5.0,
            deescalation_cooldown_secs: 300,
            response_playbook: ResponsePlaybookConfig::default(),
            backend: PheromoneBackendConfig::JetStream {
                url: nats_url(),
                connect_timeout_ms: DEFAULT_NATS_CONNECT_TIMEOUT_MS,
                gc_page_size: DEFAULT_JETSTREAM_GC_PAGE_SIZE,
            },
        }
    }

    fn now_timestamp() -> i64 {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock before unix epoch")
                .as_secs(),
        )
        .expect("unix timestamp exceeds i64")
    }

    fn signing_key_for_label(label: &str) -> SigningKey {
        let digest = Sha256::digest(label.as_bytes());
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&digest);
        SigningKey::from_bytes(&seed)
    }

    fn sample_deposit(agent_id: &str, timestamp: i64, confidence: f64) -> PheromoneDeposit {
        let key = signing_key_for_label(agent_id);
        let derived_agent_id = AgentId::from_verifying_key(&key.verifying_key());
        let mut deposit = PheromoneDeposit {
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator: serde_json::json!({"signal": "jetstream-test"}),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence,
            timestamp,
            decay_half_life: 3600.0,
            agent_id: derived_agent_id.clone(),
            agent_identity: derived_agent_id.0,
            agent_role: None,
            signature: Vec::new(),
            agent_key: Vec::new(),
        };
        let signing_bytes = crate::substrate::signing_payload_bytes_for_deposit(&deposit).unwrap();
        deposit.signature = key.sign(&signing_bytes).to_bytes().to_vec();
        deposit.agent_key = key.verifying_key().to_bytes().to_vec();
        deposit
    }

    fn verified_sample_deposit() -> VerifiedDeposit {
        let key = SigningKey::from_bytes(&[92_u8; 32]);
        let mut deposit = sample_deposit("placeholder", 100, 0.9);
        deposit.agent_id = AgentId::from_verifying_key(&key.verifying_key());
        deposit.agent_identity = deposit.agent_id.0.clone();
        let signing_bytes = crate::substrate::signing_payload_bytes_for_deposit(&deposit).unwrap();
        deposit.signature = key.sign(&signing_bytes).to_bytes().to_vec();
        deposit.agent_key = key.verifying_key().to_bytes().to_vec();
        VerifiedDeposit::admit(deposit).unwrap()
    }

    fn resign_sample_deposit(
        label: &str,
        mut deposit: PheromoneDeposit,
        indicator: serde_json::Value,
    ) -> PheromoneDeposit {
        let key = signing_key_for_label(label);
        let derived_agent_id = AgentId::from_verifying_key(&key.verifying_key());
        deposit.indicator = indicator;
        deposit.agent_id = derived_agent_id.clone();
        deposit.agent_identity = derived_agent_id.0;
        deposit.signature.clear();
        deposit.agent_key.clear();
        let signing_bytes = crate::substrate::signing_payload_bytes_for_deposit(&deposit).unwrap();
        deposit.signature = key.sign(&signing_bytes).to_bytes().to_vec();
        deposit.agent_key = key.verifying_key().to_bytes().to_vec();
        deposit
    }

    fn indexed_deposit(key: &str, deposit: PheromoneDeposit) -> IndexedDepositKey {
        let deposit = VerifiedDeposit::admit(deposit).unwrap();
        IndexedDepositKey {
            timestamp: deposit.timestamp,
            key: key.to_string(),
            encoded_len: deposit.encoded_len(),
            suppression_key: deposit_suppression_key(&deposit),
            feedback_marker: feedback_suppression_marker(&deposit)
                .map(|(key, state, order)| IndexedFeedbackMarker { key, state, order }),
        }
    }

    #[test]
    fn custom_threat_class_segments_bind_the_unsanitized_name() {
        let slash = ThreatClass::Custom("Foo/Bar".to_string());
        let question = ThreatClass::Custom("foo?bar".to_string());

        assert_eq!(
            legacy_threat_class_segment(&slash),
            legacy_threat_class_segment(&question),
            "the compatibility fixture must reproduce the historical collision"
        );
        assert_ne!(
            threat_class_segment(&slash),
            threat_class_segment(&question)
        );
        assert!(threat_class_segment(&slash).starts_with("custom_foo_bar_"));
        assert!(
            threat_class_segment(&ThreatClass::Custom("x".repeat(10_000))).len()
                <= "custom_".len() + 64 + 1 + 32
        );
    }

    #[test]
    fn recent_deposit_ring_uses_every_fixed_slot_for_consecutive_ordinals() {
        let slots = (1..=MAX_RECENT_DEPOSIT_INDEX_SLOTS)
            .map(|ordinal| recent_deposit_index_key(DepositKeyKind::Evidence, ordinal))
            .collect::<BTreeSet<_>>();
        assert_eq!(slots.len() as u64, MAX_RECENT_DEPOSIT_INDEX_SLOTS);
    }

    #[test]
    fn verified_deposit_cache_requires_an_exact_revision_and_stays_bounded() {
        let deposit = verified_sample_deposit();
        let mut cache = VerifiedDepositCache::default();

        assert!(cache.get("deposit-a", 41).is_none());
        cache.insert("deposit-a".to_string(), 41, deposit.clone());
        assert!(cache.get("deposit-a", 41).is_some());
        assert!(cache.get("deposit-a", 42).is_none());

        cache.insert("deposit-a".to_string(), 42, deposit.clone());
        assert!(cache.get("deposit-a", 41).is_none());
        assert!(cache.get("deposit-a", 42).is_some());

        for index in 0..=MAX_VERIFIED_DEPOSIT_CACHE_ENTRIES {
            cache.insert(format!("deposit-{index:05}"), index as u64, deposit.clone());
        }
        assert_eq!(cache.entries.len(), MAX_VERIFIED_DEPOSIT_CACHE_ENTRIES);
        assert!(cache.encoded_bytes <= MAX_ACTIVE_DEPOSIT_BYTES);

        let large = resign_sample_deposit(
            "large-cache-entry",
            sample_deposit("large-cache-entry", 101, 0.9),
            serde_json::json!({"padding": "x".repeat(200 * 1024)}),
        );
        let large = VerifiedDeposit::admit(large).unwrap();
        for index in 0..200 {
            cache.insert(format!("large-{index:05}"), index, large.clone());
        }
        assert!(cache.entries.len() < 200);
        assert!(cache.encoded_bytes <= MAX_ACTIVE_DEPOSIT_BYTES);
        assert_eq!(
            cache.encoded_bytes,
            cache
                .entries
                .values()
                .map(|entry| entry.deposit.encoded_len())
                .sum::<usize>()
        );
    }

    #[test]
    fn bounded_control_eviction_drops_related_evidence_when_final_feedback_is_lost() {
        let evidence = resign_sample_deposit(
            "evidence",
            sample_deposit("evidence", 100, 0.9),
            serde_json::json!({"event_id": "event-dismissed"}),
        );
        let dismissal = resign_sample_deposit(
            "reviewer",
            sample_deposit("reviewer", 200, 0.0),
            serde_json::json!({
                "schema": SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
                "event_id": "event-dismissed",
                "action": "dismiss"
            }),
        );
        let unrelated_control = resign_sample_deposit(
            "control",
            sample_deposit("control", 300, 0.0),
            serde_json::json!({"event_id": "unrelated-control"}),
        );
        let mut index = DepositKeyPartitionIndex::default();
        assert!(
            index
                .insert_bounded(
                    indexed_deposit("evidence", evidence),
                    DepositKeyKind::Evidence,
                    1,
                )
                .is_empty()
        );
        assert!(
            index
                .insert_bounded(
                    indexed_deposit("dismissal", dismissal),
                    DepositKeyKind::Control,
                    1,
                )
                .is_empty()
        );
        let evicted = index.insert_bounded(
            indexed_deposit("unrelated-control", unrelated_control),
            DepositKeyKind::Control,
            1,
        );
        assert_eq!(evicted.len(), 1);
        let orphaned = index.remove_evidence_orphaned_by_feedback(&evicted[0]);
        assert_eq!(orphaned.len(), 1);
        assert_eq!(orphaned[0].key, "evidence");
        assert!(index.evidence.is_empty());
        assert_eq!(index.controls.len(), 1);
    }

    #[test]
    fn bounded_feedback_eviction_preserves_confirmed_evidence() {
        let evidence = resign_sample_deposit(
            "confirmed-evidence",
            sample_deposit("confirmed-evidence", 100, 0.9),
            serde_json::json!({"event_id": "event-confirmed"}),
        );
        let confirmation = resign_sample_deposit(
            "reviewer-confirm",
            sample_deposit("reviewer-confirm", 200, 1.0),
            serde_json::json!({
                "schema": SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
                "event_id": "event-confirmed",
                "action": "confirm",
                "observed_at_ms": 200_100,
                "feedback_id": "confirm-200100"
            }),
        );
        let mut index = DepositKeyPartitionIndex::default();
        assert!(
            index
                .insert_bounded(
                    indexed_deposit("confirmed-evidence", evidence),
                    DepositKeyKind::Evidence,
                    10,
                )
                .is_empty()
        );
        assert!(
            index
                .insert_bounded(
                    indexed_deposit("confirmation", confirmation),
                    DepositKeyKind::Evidence,
                    10,
                )
                .is_empty()
        );

        let removed = index.remove_key("confirmation").unwrap();
        assert!(
            index
                .remove_evidence_orphaned_by_feedback(&removed)
                .is_empty()
        );
        assert!(
            index
                .evidence
                .iter()
                .any(|entry| entry.key == "confirmed-evidence")
        );
    }

    #[test]
    fn bounded_feedback_eviction_respects_governed_evidence_timestamp() {
        let governed = resign_sample_deposit(
            "governed-evidence",
            sample_deposit("governed-evidence", 100, 0.9),
            serde_json::json!({"event_id": "event-scoped"}),
        );
        let other = resign_sample_deposit(
            "other-evidence",
            sample_deposit("other-evidence", 101, 0.9),
            serde_json::json!({"event_id": "event-scoped"}),
        );
        let dismissal = resign_sample_deposit(
            "scoped-dismissal",
            sample_deposit("scoped-dismissal", 200, 0.0),
            serde_json::json!({
                "schema": SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
                "event_id": "event-scoped",
                "action": "dismiss",
                "observed_at_ms": 200_100,
                "feedback_id": "dismiss-scoped",
                "governed_evidence_timestamp": 100
            }),
        );
        let mut index = DepositKeyPartitionIndex::default();
        for (key, deposit, kind) in [
            ("governed", governed, DepositKeyKind::Evidence),
            ("other", other, DepositKeyKind::Evidence),
            ("dismissal", dismissal, DepositKeyKind::Control),
        ] {
            assert!(
                index
                    .insert_bounded(indexed_deposit(key, deposit), kind, 10)
                    .is_empty()
            );
        }
        let removed = index.remove_key("dismissal").unwrap();
        let orphaned = index.remove_evidence_orphaned_by_feedback(&removed);
        assert_eq!(
            orphaned
                .iter()
                .map(|entry| entry.key.as_str())
                .collect::<Vec<_>>(),
            vec!["governed"]
        );
        assert!(index.evidence.iter().any(|entry| entry.key == "other"));
    }

    #[test]
    fn evicting_an_older_dismissal_cannot_override_a_newer_confirmation() {
        let evidence = resign_sample_deposit(
            "reviewed-evidence",
            sample_deposit("reviewed-evidence", 100, 0.9),
            serde_json::json!({"event_id": "event-reviewed"}),
        );
        let dismissal = resign_sample_deposit(
            "reviewer-dismiss",
            sample_deposit("reviewer-dismiss", 200, 0.0),
            serde_json::json!({
                "schema": SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
                "event_id": "event-reviewed",
                "action": "dismiss",
                "observed_at_ms": 200_100,
                "feedback_id": "dismiss-200100"
            }),
        );
        let confirmation = resign_sample_deposit(
            "reviewer-confirm-later",
            sample_deposit("reviewer-confirm-later", 200, 1.0),
            serde_json::json!({
                "schema": SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
                "event_id": "event-reviewed",
                "action": "confirm",
                "observed_at_ms": 200_900,
                "feedback_id": "confirm-200900"
            }),
        );
        let mut index = DepositKeyPartitionIndex::default();
        for (key, deposit, kind) in [
            ("reviewed-evidence", evidence, DepositKeyKind::Evidence),
            ("dismissal", dismissal, DepositKeyKind::Control),
            ("confirmation", confirmation, DepositKeyKind::Evidence),
        ] {
            assert!(
                index
                    .insert_bounded(indexed_deposit(key, deposit), kind, 10)
                    .is_empty()
            );
        }

        let removed = index.remove_key("dismissal").unwrap();
        assert!(
            index
                .remove_evidence_orphaned_by_feedback(&removed)
                .is_empty()
        );
        assert_eq!(index.evidence.len(), 2);
    }

    #[test]
    fn evicting_a_terminal_confirmation_removes_the_superseded_dismissal() {
        let evidence = resign_sample_deposit(
            "reviewed-evidence",
            sample_deposit("reviewed-evidence", 100, 0.9),
            serde_json::json!({"event_id": "event-reviewed"}),
        );
        let dismissal = resign_sample_deposit(
            "reviewer-dismiss",
            sample_deposit("reviewer-dismiss", 200, 0.0),
            serde_json::json!({
                "schema": SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
                "event_id": "event-reviewed",
                "action": "dismiss",
                "observed_at_ms": 200_100,
                "feedback_id": "dismiss-200100"
            }),
        );
        let confirmation = resign_sample_deposit(
            "reviewer-confirm-later",
            sample_deposit("reviewer-confirm-later", 200, 1.0),
            serde_json::json!({
                "schema": SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
                "event_id": "event-reviewed",
                "action": "confirm",
                "observed_at_ms": 200_900,
                "feedback_id": "confirm-200900"
            }),
        );
        let mut index = DepositKeyPartitionIndex::default();
        for (key, deposit, kind) in [
            ("reviewed-evidence", evidence, DepositKeyKind::Evidence),
            ("dismissal", dismissal, DepositKeyKind::Control),
            ("confirmation", confirmation, DepositKeyKind::Evidence),
        ] {
            assert!(
                index
                    .insert_bounded(indexed_deposit(key, deposit), kind, 10)
                    .is_empty()
            );
        }

        let removed = index.remove_key("confirmation").unwrap();
        let superseded = index.remove_evidence_orphaned_by_feedback(&removed);
        assert_eq!(
            superseded
                .iter()
                .map(|entry| entry.key.as_str())
                .collect::<Vec<_>>(),
            vec!["dismissal"]
        );
        assert!(index.controls.is_empty());
        assert_eq!(
            index
                .evidence
                .iter()
                .map(|entry| entry.key.as_str())
                .collect::<Vec<_>>(),
            vec!["reviewed-evidence"]
        );
    }

    #[test]
    fn bounded_index_enforces_the_aggregate_encoded_byte_limit() {
        let large = resign_sample_deposit(
            "large-index-entry",
            sample_deposit("large-index-entry", 100, 0.9),
            serde_json::json!({"padding": "x".repeat(200 * 1024)}),
        );
        let mut index = DepositKeyPartitionIndex::default();
        let mut evicted = 0usize;
        for sequence in 0..200 {
            let mut deposit = large.clone();
            deposit.timestamp = 100 + sequence;
            deposit = resign_sample_deposit("large-index-entry", deposit, large.indicator.clone());
            evicted = evicted.saturating_add(
                index
                    .insert_bounded(
                        indexed_deposit(&format!("large-index-{sequence:05}"), deposit),
                        DepositKeyKind::Evidence,
                        MAX_VERIFIED_DEPOSIT_CACHE_ENTRIES,
                    )
                    .len(),
            );
        }
        assert!(evicted > 0);
        assert!(index.evidence.len() < 200);
        assert!(index.total_bytes() <= MAX_ACTIVE_DEPOSIT_BYTES);
        assert_eq!(
            index.total_bytes(),
            index
                .evidence
                .iter()
                .chain(&index.controls)
                .map(|entry| entry.encoded_len)
                .sum::<usize>()
        );
    }

    #[test]
    fn deposit_indexes_bound_partitions_and_aggregate_bytes_globally() {
        let mut indexes = DepositKeyIndexes::default();
        for index in 0..MAX_DEPOSIT_KEY_INDEX_PARTITIONS {
            indexes.partitions.insert(
                format!("partition-{index:03}"),
                DepositKeyPartitionIndex::default(),
            );
        }
        indexes.make_room_for("current");
        indexes
            .partitions
            .insert("current".to_string(), DepositKeyPartitionIndex::default());
        assert_eq!(indexes.partitions.len(), MAX_DEPOSIT_KEY_INDEX_PARTITIONS);
        assert!(indexes.partitions.contains_key("current"));

        indexes
            .partitions
            .get_mut("current")
            .unwrap()
            .evidence_bytes = 20 * 1024 * 1024;
        indexes
            .partitions
            .insert("other".to_string(), DepositKeyPartitionIndex::default());
        indexes.partitions.get_mut("other").unwrap().control_bytes = 20 * 1024 * 1024;
        indexes.enforce_global_byte_bound("current");
        assert!(indexes.partitions.contains_key("current"));
        assert!(!indexes.partitions.contains_key("other"));
        assert!(
            indexes
                .partitions
                .values()
                .map(DepositKeyPartitionIndex::total_bytes)
                .sum::<usize>()
                <= MAX_ACTIVE_DEPOSIT_BYTES
        );
    }

    #[test]
    fn nats_endpoint_credentials_are_decoded_for_authentication_and_redacted_from_debug() {
        let endpoint = parse_nats_endpoint("nats://runtime:p%40ss@127.0.0.1:4222").unwrap();
        assert_eq!(endpoint.server_url, "nats://127.0.0.1:4222");
        match endpoint.authentication {
            NatsAuthentication::UserPassword { username, password } => {
                assert_eq!(username, "runtime");
                assert_eq!(password, "p@ss");
            }
            _ => panic!("expected user/password authentication"),
        }

        let substrate = JetStreamPheromoneSubstrate::with_bucket(
            substrate_config(),
            "nats://runtime:p%40ss@127.0.0.1:4222",
            "debug-redaction",
        );
        let debug = format!("{substrate:?}");
        assert!(debug.contains("nats://127.0.0.1:4222"));
        assert!(!debug.contains("runtime"));
        assert!(!debug.contains("p%40ss"));
        assert!(!debug.contains("p@ss"));
    }

    #[test]
    fn nats_endpoint_supports_token_authentication_and_rejects_non_nats_schemes() {
        let endpoint = parse_nats_endpoint("nats://opaque-token@127.0.0.1:4222").unwrap();
        assert!(matches!(
            endpoint.authentication,
            NatsAuthentication::Token(token) if token == "opaque-token"
        ));
        assert!(parse_nats_endpoint("https://127.0.0.1:4222").is_err());
    }

    #[test]
    fn deposit_key_timestamp_supports_current_and_legacy_layouts() {
        assert_eq!(
            deposit_key_timestamp(
                "exp.00000000000000000042.execution.evidence.00000000000000000123.o00000000000000000077-l00000000000000000456-agent"
            ),
            Some(123)
        );
        assert_eq!(
            deposit_key_timestamp(
                "exp.00000000000000000042.execution.evidence.00000000000000000123.agent"
            ),
            Some(123)
        );
        assert_eq!(
            deposit_key_timestamp("exp.00000000000000000042.execution.00000000000000000123.agent"),
            Some(123)
        );
        assert_eq!(
            deposit_key_timestamp("execution.00000000000000000456.agent"),
            Some(456)
        );
        assert_eq!(deposit_key_timestamp("exp.invalid.execution.agent"), None);
        assert_eq!(deposit_key_timestamp("execution.invalid.agent"), None);
    }

    #[test]
    fn deposit_key_ordinal_is_explicit_only_for_ordinal_layout() {
        assert_eq!(
            deposit_key_ordinal(
                "exp.00000000000000000042.execution.evidence.00000000000000000123.o00000000000000000077-l00000000000000000456-agent"
            ),
            Some(77)
        );
        assert_eq!(
            deposit_key_ordinal(
                "exp.00000000000000000042.execution.evidence.00000000000000000123.agent"
            ),
            None
        );
        assert_eq!(
            deposit_key_ordinal("exp.00000000000000000042.execution.00000000000000000123.agent"),
            None
        );
        assert_eq!(
            deposit_key_ordinal("execution.00000000000000000456.agent"),
            None
        );
    }

    #[test]
    fn recent_index_state_defaults_compatibility_fields_from_prior_schema() {
        let state =
            serde_json::from_str::<super::RecentDepositIndexState>(r#"{"last_ordinal":42}"#)
                .unwrap();
        assert_eq!(state.last_ordinal, 42);
        assert_eq!(state.last_compatibility_revision, 0);
        assert_eq!(state.last_compatibility_key, None);
        assert_eq!(state.last_compatibility_ordinal, 0);
        assert_eq!(state.pending_compatibility_pointer, None);
    }

    #[test]
    fn legacy_intent_slots_remain_bounded_and_new_keys_are_policy_independent() {
        for operation in 0..10_000_u64 {
            let operation_id = format!("operation-{operation}");
            let keys =
                super::idempotent_deposit_intent_slot_keys(&operation_id).collect::<Vec<_>>();
            assert_eq!(keys.len(), super::IDEMPOTENT_DEPOSIT_INTENT_SLOT_CHOICES);
            for key in keys {
                let slot = key
                    .strip_prefix(&format!("{}.s", super::RECENT_DEPOSIT_INTENT_KEY_PREFIX))
                    .unwrap()
                    .parse::<u64>()
                    .unwrap();
                assert!(slot < super::MAX_IDEMPOTENT_DEPOSIT_INTENT_SLOTS);
            }
            let current = super::idempotent_deposit_intent_key(&operation_id);
            assert_eq!(super::intent_key_gc_page(&current), None);
            assert!(super::is_idempotent_deposit_intent_key(&current));
            assert!(current.ends_with(&super::hash_prefix(operation_id.as_bytes(), 64)));
        }
    }

    #[test]
    fn deposit_key_encoded_len_is_bound_only_by_the_compatible_suffix() {
        assert_eq!(
            deposit_key_encoded_len(
                "exp.00000000000000000042.execution.evidence.00000000000000000123.o00000000000000000077-l00000000000000000456-agent"
            ),
            Some(456)
        );
        assert_eq!(
            deposit_key_encoded_len(
                "exp.00000000000000000042.execution.evidence.00000000000000000123.agent"
            ),
            None
        );
        assert_eq!(
            deposit_key_encoded_len("execution.00000000000000000456.agent"),
            None
        );
        assert_eq!(
            deposit_key_encoded_len(
                "exp.00000000000000000042.execution.control.00000000000000000123.iabc-l00000000000000000456-agent"
            ),
            Some(456)
        );
        assert_eq!(
            deposit_key_ordinal(
                "exp.00000000000000000042.execution.control.00000000000000000123.iabc-l00000000000000000456-agent"
            ),
            None
        );
    }

    #[test]
    fn recent_ring_preselects_keys_under_the_aggregate_byte_ceiling() {
        let selected = (0..200_i64)
            .map(|timestamp| SelectedDepositKey {
                key: format!("exp.00000000000000000042.execution.evidence.{timestamp:020}.current"),
                kind: Some(DepositKeyKind::Evidence),
                expected_revision: Some(u64::try_from(timestamp + 1).unwrap()),
                expected_encoded_len: Some(MAX_SINGLE_DEPOSIT_BYTES),
                suppression_scope_digest: None,
            })
            .collect::<Vec<_>>();
        let selected = select_recent_deposit_keys_within_byte_limit(selected);
        assert_eq!(
            selected.len(),
            MAX_ACTIVE_DEPOSIT_BYTES / MAX_SINGLE_DEPOSIT_BYTES
        );
        assert_eq!(
            deposit_key_timestamp(&selected[0].key),
            Some(199),
            "the newest bounded candidate must be loaded first"
        );
        assert!(
            selected
                .iter()
                .map(|candidate| candidate.expected_encoded_len.unwrap())
                .sum::<usize>()
                <= MAX_ACTIVE_DEPOSIT_BYTES
        );

        let legacy = (0..200_i64)
            .map(|timestamp| SelectedDepositKey {
                key: format!("execution.{timestamp:020}.legacy"),
                kind: None,
                expected_revision: None,
                expected_encoded_len: None,
                suppression_scope_digest: None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            select_recent_deposit_keys_within_byte_limit(legacy).len(),
            MAX_ACTIVE_DEPOSIT_BYTES / MAX_SINGLE_DEPOSIT_BYTES,
            "unknown prior-layout lengths must be charged at the hard maximum"
        );
    }

    #[test]
    fn recent_pointer_wire_format_remains_rolling_upgrade_compatible() {
        let pointer = RecentDepositPointer {
            ordinal: 7,
            kind: DepositKeyKind::Evidence,
            deposit_key: "exp.00000000000000000042.execution.evidence.00000000000000000123.o00000000000000000007-l00000000000000000456-current".to_string(),
            deposit_revision: 19,
        };

        assert_eq!(
            serde_json::to_string(&pointer).unwrap(),
            r#"{"ordinal":7,"kind":"evidence","deposit_key":"exp.00000000000000000042.execution.evidence.00000000000000000123.o00000000000000000007-l00000000000000000456-current","deposit_revision":19}"#
        );
        assert_eq!(
            serde_json::from_str::<RecentDepositPointer>(
                r#"{"ordinal":7,"kind":"evidence","deposit_key":"exp.00000000000000000042.execution.evidence.00000000000000000123.o00000000000000000007-l00000000000000000456-current","deposit_revision":19}"#
            )
            .unwrap(),
            pointer
        );
    }

    #[test]
    fn suppression_scope_pairs_only_authenticated_feedback_controls() {
        let evidence = VerifiedDeposit::admit(resign_sample_deposit(
            "scope-evidence",
            sample_deposit("scope-evidence", 100, 0.9),
            serde_json::json!({"event_id": "event-paired"}),
        ))
        .unwrap();
        let dismissal = VerifiedDeposit::admit(resign_sample_deposit(
            "scope-dismissal",
            sample_deposit("scope-dismissal", 200, 0.0),
            serde_json::json!({
                "schema": SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
                "feedback_id": "scope-dismissal",
                "event_id": "event-paired",
                "action": "dismiss",
                "observed_at_ms": 200_000,
            }),
        ))
        .unwrap();
        let ordinary_control = VerifiedDeposit::admit(resign_sample_deposit(
            "scope-ordinary-control",
            sample_deposit("scope-ordinary-control", 300, 0.0),
            serde_json::json!({"event_id": "event-paired"}),
        ))
        .unwrap();

        assert_eq!(
            super::suppression_scope_digest(&evidence).unwrap(),
            super::suppression_scope_digest(&dismissal).unwrap()
        );
        assert_eq!(
            super::suppression_scope_digest(&ordinary_control).unwrap(),
            None
        );
    }

    #[test]
    fn recent_ring_prioritizes_dismissal_controls_at_the_byte_boundary() {
        let timestamp = 1_700_000_000_i64;
        let future_evidence_timestamp = timestamp + 300;
        let mut selected = (0..(MAX_ACTIVE_DEPOSIT_BYTES / MAX_SINGLE_DEPOSIT_BYTES))
            .map(|index| SelectedDepositKey {
                key: format!(
                    "exp.00000000000000000042.execution.evidence.{future_evidence_timestamp:020}.o{index:020}-l{MAX_SINGLE_DEPOSIT_BYTES:020}-evidence-{index}"
                ),
                kind: Some(DepositKeyKind::Evidence),
                expected_revision: Some(u64::try_from(index + 1).unwrap()),
                expected_encoded_len: Some(MAX_SINGLE_DEPOSIT_BYTES),
                suppression_scope_digest: Some("scope-a".to_string()),
            })
            .collect::<Vec<_>>();
        let dismissal_key = format!(
            "exp.00000000000000000042.execution.control.{timestamp:020}.o00000000000000000099-l{MAX_SINGLE_DEPOSIT_BYTES:020}-dismissal"
        );
        selected.push(SelectedDepositKey {
            key: dismissal_key.clone(),
            kind: Some(DepositKeyKind::Control),
            expected_revision: Some(100),
            expected_encoded_len: Some(MAX_SINGLE_DEPOSIT_BYTES),
            suppression_scope_digest: Some("scope-a".to_string()),
        });

        let selected = select_recent_deposit_keys_within_byte_limit(selected);
        assert_eq!(
            selected.len(),
            MAX_ACTIVE_DEPOSIT_BYTES / MAX_SINGLE_DEPOSIT_BYTES
        );
        assert_eq!(selected[0].key, dismissal_key);
        assert!(selected.iter().any(|candidate| {
            deposit_key_kind(&candidate.key) == Some(DepositKeyKind::Control)
        }));
    }

    #[test]
    fn recent_ring_does_not_let_unrelated_controls_starve_evidence() {
        let timestamp = 1_700_000_000_i64;
        let mut selected = (0..(MAX_ACTIVE_DEPOSIT_BYTES / MAX_SINGLE_DEPOSIT_BYTES))
            .map(|index| SelectedDepositKey {
                key: format!(
                    "exp.00000000000000000042.execution.control.{timestamp:020}.o{index:020}-l{MAX_SINGLE_DEPOSIT_BYTES:020}-control-{index}"
                ),
                kind: Some(DepositKeyKind::Control),
                expected_revision: Some(u64::try_from(index + 1).unwrap()),
                expected_encoded_len: Some(MAX_SINGLE_DEPOSIT_BYTES),
                suppression_scope_digest: Some(format!("unrelated-{index}")),
            })
            .collect::<Vec<_>>();
        let evidence_key = format!(
            "exp.00000000000000000042.execution.evidence.{timestamp:020}.o00000000000000000099-l{MAX_SINGLE_DEPOSIT_BYTES:020}-evidence"
        );
        selected.push(SelectedDepositKey {
            key: evidence_key.clone(),
            kind: Some(DepositKeyKind::Evidence),
            expected_revision: Some(100),
            expected_encoded_len: Some(MAX_SINGLE_DEPOSIT_BYTES),
            suppression_scope_digest: Some("evidence-scope".to_string()),
        });

        let selected = select_recent_deposit_keys_within_byte_limit(selected);
        assert_eq!(
            selected.len(),
            MAX_ACTIVE_DEPOSIT_BYTES / MAX_SINGLE_DEPOSIT_BYTES
        );
        assert!(
            selected
                .iter()
                .any(|candidate| candidate.key == evidence_key)
        );
        assert_eq!(
            selected
                .iter()
                .filter(|candidate| {
                    deposit_key_kind(&candidate.key) == Some(DepositKeyKind::Control)
                })
                .count(),
            MAX_ACTIVE_DEPOSIT_BYTES / MAX_SINGLE_DEPOSIT_BYTES - 1
        );
    }

    #[test]
    fn recent_result_limit_reserves_capacity_for_evidence() {
        let mut deposits = (0..100)
            .map(|index| sample_deposit(&format!("control-{index}"), 10_000 + index, 0.0))
            .chain((0..100).map(|index| sample_deposit(&format!("evidence-{index}"), index, 0.9)))
            .collect::<Vec<_>>();
        deposits.sort_by_key(|deposit| std::cmp::Reverse(deposit.timestamp));

        let selected = super::balance_recent_deposit_results(deposits, 100);

        assert_eq!(selected.len(), 100);
        assert_eq!(
            selected
                .iter()
                .filter(|deposit| deposit.confidence == 0.0)
                .count(),
            50
        );
        assert_eq!(
            selected
                .iter()
                .filter(|deposit| deposit.confidence > 0.0)
                .count(),
            50
        );
        assert!(
            selected
                .windows(2)
                .all(|window| window[0].timestamp >= window[1].timestamp)
        );
    }

    #[test]
    fn migration_ordinals_preserve_current_keys_and_stably_fill_legacy_slots() {
        let current_key = "exp.00000000000000000042.execution.evidence.00000000000000000123.o00000000000000000077-l00000000000000000456-current".to_string();
        let inputs = vec![
            (
                "exp.00000000000000000042.execution.evidence.00000000000000000121.legacy-a"
                    .to_string(),
                120,
            ),
            (current_key.clone(), 121),
            (
                "exp.00000000000000000042.execution.evidence.00000000000000000124.legacy-b"
                    .to_string(),
                122,
            ),
        ];

        let (first, first_boundary) =
            migration_recent_deposit_pointers(DepositKeyKind::Evidence, inputs.clone(), 200, &[])
                .unwrap();
        let (second, second_boundary) =
            migration_recent_deposit_pointers(DepositKeyKind::Evidence, inputs, 200, &[]).unwrap();
        assert_eq!(first, second);
        assert_eq!(first_boundary, 200);
        assert_eq!(second_boundary, 200);
        assert_eq!(
            first
                .iter()
                .find(|pointer| pointer.deposit_key == current_key)
                .unwrap()
                .ordinal,
            77
        );
        let slots = first
            .iter()
            .map(|pointer| pointer.ordinal % MAX_RECENT_DEPOSIT_INDEX_SLOTS)
            .collect::<BTreeSet<_>>();
        assert_eq!(slots.len(), first.len());
    }

    #[test]
    fn migration_resumes_previous_version_partial_mapping_at_its_boundary() {
        let first_key =
            "exp.00000000000000000042.execution.00000000000000000121.legacy-a".to_string();
        let second_key =
            "exp.00000000000000000042.execution.00000000000000000122.legacy-b".to_string();
        let inputs = vec![(first_key.clone(), 120), (second_key.clone(), 121)];
        let existing = vec![RecentDepositPointer {
            ordinal: 200,
            kind: DepositKeyKind::Evidence,
            deposit_key: first_key,
            deposit_revision: 120,
        }];

        let (pointers, effective_boundary) =
            migration_recent_deposit_pointers(DepositKeyKind::Evidence, inputs, 200, &existing)
                .unwrap();

        assert_eq!(effective_boundary, 201);
        assert_eq!(pointers.len(), 2);
        assert_eq!(pointers[0], existing[0]);
        assert_eq!(pointers[1].ordinal, 201);
        assert_eq!(pointers[1].deposit_key, second_key);
    }

    #[test]
    fn migration_converges_a_previous_version_prefix_before_a_current_layout_stop() {
        let legacy_a =
            "exp.00000000000000000042.execution.00000000000000000121.legacy-a".to_string();
        let current = "exp.00000000000000000042.execution.evidence.00000000000000000122.o00000000000000000077-l00000000000000000456-current".to_string();
        let legacy_b =
            "exp.00000000000000000042.execution.00000000000000000123.legacy-b".to_string();
        let inputs = vec![
            (legacy_a.clone(), 120),
            (current.clone(), 121),
            (legacy_b.clone(), 122),
        ];
        let previous_prefix = RecentDepositPointer {
            ordinal: 200,
            kind: DepositKeyKind::Evidence,
            deposit_key: legacy_a.clone(),
            deposit_revision: 120,
        };

        let (pointers, effective_boundary) = migration_recent_deposit_pointers(
            DepositKeyKind::Evidence,
            inputs,
            200,
            std::slice::from_ref(&previous_prefix),
        )
        .unwrap();

        assert_eq!(effective_boundary, 202);
        assert!(pointers.contains(&previous_prefix));
        assert!(
            pointers
                .iter()
                .any(|pointer| { pointer.deposit_key == current && pointer.ordinal == 77 })
        );
        assert!(
            pointers
                .iter()
                .any(|pointer| { pointer.deposit_key == legacy_b && pointer.ordinal == 202 })
        );
        let slots = pointers
            .iter()
            .map(|pointer| pointer.ordinal % MAX_RECENT_DEPOSIT_INDEX_SLOTS)
            .collect::<BTreeSet<_>>();
        assert_eq!(slots.len(), pointers.len());
    }

    #[test]
    fn deposit_key_kind_is_explicit_for_new_keys_and_absent_for_legacy_keys() {
        assert_eq!(
            deposit_key_kind(
                "exp.00000000000000000042.execution.evidence.00000000000000000123.agent"
            ),
            Some(DepositKeyKind::Evidence)
        );
        assert_eq!(
            deposit_key_kind(
                "exp.00000000000000000042.execution.control.00000000000000000124.agent"
            ),
            Some(DepositKeyKind::Control)
        );
        assert_eq!(
            deposit_key_kind("exp.00000000000000000042.execution.00000000000000000123.agent"),
            None
        );
    }

    #[test]
    fn jetstream_deposit_scan_retains_a_deterministic_newest_window() {
        let mut window = BTreeSet::new();
        let oldest = "exp.00000000000000000001.execution.00000000000000000100.oldest";
        let newest = "exp.00000000000000000003.execution.00000000000000000300.newest";
        let middle = "exp.00000000000000000002.execution.00000000000000000200.middle";

        retain_newest_deposit_key(&mut window, newest.to_string(), 2);
        retain_newest_deposit_key(&mut window, oldest.to_string(), 2);
        retain_newest_deposit_key(&mut window, middle.to_string(), 2);

        assert_eq!(
            window.into_iter().collect::<Vec<_>>(),
            vec![(200, middle.to_string()), (300, newest.to_string())]
        );

        let mut malformed_window = BTreeSet::new();
        retain_newest_deposit_key(&mut malformed_window, "malformed".to_string(), 1);
        retain_newest_deposit_key(&mut malformed_window, newest.to_string(), 1);
        assert_eq!(
            malformed_window.into_iter().collect::<Vec<_>>(),
            vec![(300, newest.to_string())]
        );

        let mut full_window = BTreeSet::new();
        for timestamp in 0..=MAX_VERIFIED_DEPOSIT_CACHE_ENTRIES {
            retain_newest_deposit_key(
                &mut full_window,
                format!("execution.{timestamp:020}.agent"),
                MAX_VERIFIED_DEPOSIT_CACHE_ENTRIES,
            );
        }
        assert_eq!(full_window.len(), MAX_VERIFIED_DEPOSIT_CACHE_ENTRIES);
        assert_eq!(
            full_window.first().map(|(timestamp, _)| *timestamp),
            Some(1)
        );
        assert_eq!(
            full_window.last().map(|(timestamp, _)| *timestamp),
            Some(i64::try_from(MAX_VERIFIED_DEPOSIT_CACHE_ENTRIES).unwrap())
        );
    }

    #[test]
    fn jetstream_deposit_scan_partitions_control_records_before_bounding() {
        let mut evidence_window = BTreeSet::new();
        let mut control_window = BTreeSet::new();
        let evidence = "exp.00000000000000000042.execution.evidence.00000000000000000100.live";

        retain_newest_partitioned_deposit_key_as(
            &mut evidence_window,
            &mut control_window,
            evidence.to_string(),
            deposit_key_kind(evidence).unwrap(),
            2,
        );
        for timestamp in 200..203 {
            let key =
                format!("exp.00000000000000000042.execution.control.{timestamp:020}.inactive");
            let kind = deposit_key_kind(&key).unwrap();
            retain_newest_partitioned_deposit_key_as(
                &mut evidence_window,
                &mut control_window,
                key,
                kind,
                2,
            );
        }

        assert_eq!(
            evidence_window.into_iter().collect::<Vec<_>>(),
            vec![(100, evidence.to_string())]
        );
        assert_eq!(control_window.len(), 2);
        assert_eq!(
            control_window.first().map(|(timestamp, _)| *timestamp),
            Some(201)
        );
    }

    #[test]
    fn zero_strength_control_records_are_not_assigned_to_an_immediate_gc_page() {
        let deposit = sample_deposit("control", 100, 0.0);
        let deadline = evaporation_deadline(&deposit, 3_600.0, 0.01);

        assert!(deadline > deposit.timestamp);
        assert!(expiration_gc_page(&deposit, 3_600.0, 0.01) > gc_sweep_page(deposit.timestamp));
    }

    fn sample_escalation(mode: SwarmMode, timestamp: i64) -> EscalationRecord {
        EscalationRecord {
            mode,
            threat_class: ThreatClass::Execution,
            total_strength: 2.8,
            distinct_sources: 2,
            peak_confidence: 0.95,
            timestamp,
        }
    }

    fn sample_threat_class_config() -> ThreatClassConfig {
        ThreatClassConfig {
            threat_class: ThreatClass::Execution,
            half_life_secs: 180.0,
            evaporation_threshold: 0.05,
            alert_threshold: 1.2,
            incident_threshold: 3.4,
        }
    }

    fn sample_threat_intel_entry() -> ThreatIntelEntry {
        ThreatIntelEntry {
            indicator_type: ThreatIntelIndicatorType::Domain,
            value: "Example.COM.".to_string(),
            source: "operator".to_string(),
            indicator_id: None,
            confidence: 0.91,
            expires_at: 1_700_000_000_100,
        }
    }

    fn nats_url() -> String {
        std::env::var("SWARM_NATS_RUNTIME_URL")
            .or_else(|_| std::env::var("NATS_URL"))
            .unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string())
    }

    fn unique_bucket(label: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        format!("swarm-pheromone-{label}-{}-{nanos}", std::process::id())
    }

    async fn connect_for_test(label: &str) -> Option<(String, JetStreamPheromoneSubstrate)> {
        let bucket = unique_bucket(label);
        let url = nats_url();
        match JetStreamPheromoneSubstrate::connect_with_bucket(
            substrate_config(),
            url.clone(),
            bucket.clone(),
        )
        .await
        {
            Ok(substrate) => Some((bucket, substrate)),
            Err(error) => {
                assert!(
                    std::env::var_os("SWARM_NATS_HARNESS_SCRATCH").is_none(),
                    "repository-owned NATS harness failed to materialize JetStream test: {error}"
                );
                eprintln!("NATS server not available at {url}, skipping JetStream test: {error}");
                None
            }
        }
    }

    async fn wait_until<F, Fut>(mut condition: F)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if condition().await {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "condition was not satisfied before timeout"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    #[tokio::test]
    async fn jetstream_rejects_valid_oversized_deposit_before_connecting() {
        let substrate = JetStreamPheromoneSubstrate::with_bucket(
            substrate_config(),
            "nats://127.0.0.1:1",
            unique_bucket("oversized-prewrite"),
        );
        let key = SigningKey::from_bytes(&[91_u8; 32]);
        let mut deposit = sample_deposit("placeholder", 100, 0.9);
        deposit.agent_id = AgentId::from_verifying_key(&key.verifying_key());
        deposit.agent_identity = deposit.agent_id.0.clone();
        deposit.indicator["oversized"] =
            serde_json::Value::String("x".repeat(crate::substrate::MAX_SINGLE_DEPOSIT_BYTES));
        let signing_bytes = crate::substrate::signing_payload_bytes_for_deposit(&deposit).unwrap();
        deposit.signature = key.sign(&signing_bytes).to_bytes().to_vec();
        deposit.agent_key = key.verifying_key().to_bytes().to_vec();
        crate::substrate::validate_deposit_signature(&deposit).unwrap();

        assert!(matches!(
            substrate.deposit(deposit).await,
            Err(crate::SubstrateError::InvalidDeposit { reason })
                if reason.contains("hard limit")
        ));
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_recovers_deposits_after_reconnect() {
        let Some((bucket, substrate)) = connect_for_test("restart").await else {
            return;
        };
        let base = now_timestamp() - 2;
        substrate
            .deposit(sample_deposit("whisker-a", base, 0.9))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit("whisker-b", base + 1, 0.8))
            .await
            .unwrap();
        wait_until(|| async { substrate.recent_deposits(10).await.unwrap().len() == 2 }).await;
        drop(substrate);

        let reopened = JetStreamPheromoneSubstrate::connect_with_bucket(
            substrate_config(),
            nats_url(),
            bucket,
        )
        .await
        .unwrap();
        let deposits = reopened.recent_deposits(10).await.unwrap();
        assert_eq!(deposits.len(), 2);
        assert_eq!(deposits[0].timestamp, base + 1);
        assert_eq!(deposits[1].timestamp, base);

        let health = reopened.health().await.unwrap();
        assert!(health.ready);
        assert!(health.durable);
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_concurrent_initializers_share_boundary_and_preserve_current_ordinals() {
        let Some((bucket, substrate)) = connect_for_test("migration-boundary").await else {
            return;
        };
        let connection = substrate.ensure_connected().await.unwrap();
        for index in 0..80_u64 {
            connection
                .store
                .put(
                    format!("unrelated.migration-boundary-noise.{index}"),
                    b"noise".as_slice().into(),
                )
                .await
                .unwrap();
        }
        let now = now_timestamp();
        let current = sample_deposit("migration-current", now - 1, 0.9);
        let current_payload = serde_json::to_vec(&current).unwrap();
        let current_key = format!(
            "exp.{:020}.execution.evidence.{:020}.o{:020}-l{:020}-migration-current",
            expiration_gc_page(&current, 3_600.0, 0.01),
            current.timestamp,
            77,
            current_payload.len()
        );
        connection
            .store
            .put(current_key.clone(), current_payload.into())
            .await
            .unwrap();
        let legacy = sample_deposit("migration-legacy", now, 0.8);
        let legacy_key = format!(
            "exp.{:020}.execution.evidence.{:020}.migration-legacy",
            expiration_gc_page(&legacy, 3_600.0, 0.01),
            legacy.timestamp
        );
        connection
            .store
            .put(legacy_key, serde_json::to_vec(&legacy).unwrap().into())
            .await
            .unwrap();

        let reopened = JetStreamPheromoneSubstrate::connect_with_bucket(
            substrate_config(),
            nats_url(),
            bucket,
        )
        .await
        .unwrap();
        let (boundary_a, boundary_b) = tokio::join!(
            substrate.recent_deposit_migration_boundary(connection),
            reopened.recent_deposit_migration_boundary(connection)
        );
        assert_eq!(boundary_a.unwrap(), boundary_b.unwrap());

        let (recent_a, recent_b) =
            tokio::join!(substrate.recent_deposits(10), reopened.recent_deposits(10));
        assert_eq!(recent_a.unwrap().len(), 2);
        assert_eq!(recent_b.unwrap().len(), 2);
        let pointer_entry = connection
            .store
            .entry(&recent_deposit_index_key(DepositKeyKind::Evidence, 77))
            .await
            .unwrap()
            .unwrap();
        let pointer =
            serde_json::from_slice::<super::RecentDepositPointer>(&pointer_entry.value).unwrap();
        assert_eq!(pointer.ordinal, 77);
        assert_eq!(pointer.deposit_key, current_key);
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_migration_completes_a_previous_version_partial_mapping() {
        let Some((_bucket, substrate)) = connect_for_test("migration-previous-partial").await
        else {
            return;
        };
        let connection = substrate.ensure_connected().await.unwrap();
        let now = now_timestamp();
        let first = sample_deposit("migration-previous-a", now - 2, 0.9);
        let first_key = format!(
            "exp.{:020}.execution.{:020}.migration-previous-a",
            expiration_gc_page(&first, 3_600.0, 0.01),
            first.timestamp
        );
        let first_revision = connection
            .store
            .put(
                first_key.clone(),
                serde_json::to_vec(&first).unwrap().into(),
            )
            .await
            .unwrap();
        let second = sample_deposit("migration-previous-b", now - 1, 0.8);
        let second_key = format!(
            "exp.{:020}.execution.{:020}.migration-previous-b",
            expiration_gc_page(&second, 3_600.0, 0.01),
            second.timestamp
        );
        let second_revision = connection
            .store
            .put(
                second_key.clone(),
                serde_json::to_vec(&second).unwrap().into(),
            )
            .await
            .unwrap();

        let shared_boundary = substrate
            .recent_deposit_migration_boundary(connection)
            .await
            .unwrap();
        assert_eq!(shared_boundary, second_revision);
        let previous_version_boundary = connection
            .store
            .stream
            .get_info()
            .await
            .unwrap()
            .state
            .last_sequence;
        assert!(previous_version_boundary > shared_boundary);
        let previous_first_ordinal = previous_version_boundary - 1;
        substrate
            .write_recent_deposit_pointer(
                connection,
                &RecentDepositPointer {
                    ordinal: previous_first_ordinal,
                    kind: DepositKeyKind::Evidence,
                    deposit_key: first_key.clone(),
                    deposit_revision: first_revision,
                },
            )
            .await
            .unwrap();

        let recent = substrate.recent_deposits(10).await.unwrap();
        assert_eq!(recent.len(), 2);
        let first_pointer = connection
            .store
            .entry(&recent_deposit_index_key(
                DepositKeyKind::Evidence,
                previous_first_ordinal,
            ))
            .await
            .unwrap()
            .unwrap();
        let first_pointer =
            serde_json::from_slice::<RecentDepositPointer>(&first_pointer.value).unwrap();
        assert_eq!(first_pointer.deposit_key, first_key);
        assert_eq!(first_pointer.ordinal, previous_first_ordinal);
        let second_pointer = connection
            .store
            .entry(&recent_deposit_index_key(
                DepositKeyKind::Evidence,
                previous_version_boundary,
            ))
            .await
            .unwrap()
            .unwrap();
        let second_pointer =
            serde_json::from_slice::<RecentDepositPointer>(&second_pointer.value).unwrap();
        assert_eq!(second_pointer.deposit_key, second_key);
        assert_eq!(second_pointer.ordinal, previous_version_boundary);
        assert_eq!(second_pointer.deposit_revision, second_revision);
        let compatibility = connection
            .store
            .entry(super::RECENT_DEPOSIT_COMPATIBILITY_STATE_KEY)
            .await
            .unwrap()
            .unwrap();
        let compatibility =
            serde_json::from_slice::<super::RecentDepositCompatibilityState>(&compatibility.value)
                .unwrap();
        assert_eq!(
            compatibility.last_stream_sequence, shared_boundary,
            "synthetic previous-version ordinals must never advance the JetStream cursor"
        );
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_recent_reads_use_only_the_fixed_server_side_ring() {
        let Some((_bucket, substrate)) = connect_for_test("recent-ring").await else {
            return;
        };
        let now = now_timestamp();
        let connection = substrate.ensure_connected().await.unwrap();
        for index in 0..127_i64 {
            connection
                .store
                .put(
                    format!("unrelated.pre-index-noise.{index}"),
                    b"not-json".as_slice().into(),
                )
                .await
                .unwrap();
            let deposit = sample_deposit(&format!("pre-index-{index}"), now - 500 + index, 0.9);
            let payload = serde_json::to_vec(&deposit).unwrap();
            connection
                .store
                .put(
                    format!(
                        "exp.{:020}.execution.evidence.{:020}.pre-index-{index}",
                        expiration_gc_page(&deposit, 3_600.0, 0.01),
                        deposit.timestamp
                    ),
                    payload.into(),
                )
                .await
                .unwrap();
        }
        assert_eq!(
            substrate.recent_deposits(100).await.unwrap().len(),
            100,
            "sparse historical revisions must migrate into distinct dense ring slots"
        );

        let mixed_version = sample_deposit("mixed-version-a", now - 150, 0.9);
        connection
            .store
            .put(
                format!(
                    "exp.{:020}.execution.evidence.{:020}.mixed-version-a",
                    expiration_gc_page(&mixed_version, 3_600.0, 0.01),
                    mixed_version.timestamp
                ),
                serde_json::to_vec(&mixed_version).unwrap().into(),
            )
            .await
            .unwrap();
        let mixed_recent = substrate.recent_deposits(10).await.unwrap();
        assert!(
            mixed_recent
                .iter()
                .any(|deposit| deposit.agent_id == mixed_version.agent_id),
            "a prior-layout writer must remain visible after index initialization"
        );

        let reopened = JetStreamPheromoneSubstrate::connect_with_bucket(
            substrate_config(),
            nats_url(),
            substrate.bucket.clone(),
        )
        .await
        .unwrap();
        let mixed_version_after_reopen = sample_deposit("mixed-version-b", now - 149, 0.9);
        connection
            .store
            .put(
                format!(
                    "exp.{:020}.execution.evidence.{:020}.mixed-version-b",
                    expiration_gc_page(&mixed_version_after_reopen, 3_600.0, 0.01),
                    mixed_version_after_reopen.timestamp
                ),
                serde_json::to_vec(&mixed_version_after_reopen)
                    .unwrap()
                    .into(),
            )
            .await
            .unwrap();
        let reopened_recent = reopened.recent_deposits(10).await.unwrap();
        assert!(
            reopened_recent
                .iter()
                .any(|deposit| deposit.agent_id == mixed_version_after_reopen.agent_id),
            "the persisted compatibility cursor must resume across substrate instances"
        );
        assert!(
            connection
                .store
                .entry(super::RECENT_DEPOSIT_COMPATIBILITY_STATE_KEY)
                .await
                .unwrap()
                .is_some()
        );

        let mixed_version_concurrent = sample_deposit("mixed-version-concurrent", now - 148, 0.9);
        connection
            .store
            .put(
                format!(
                    "exp.{:020}.execution.evidence.{:020}.mixed-version-concurrent",
                    expiration_gc_page(&mixed_version_concurrent, 3_600.0, 0.01),
                    mixed_version_concurrent.timestamp
                ),
                serde_json::to_vec(&mixed_version_concurrent)
                    .unwrap()
                    .into(),
            )
            .await
            .unwrap();
        let evidence_state_key = super::recent_deposit_index_state_key(DepositKeyKind::Evidence);
        let state_before = connection
            .store
            .entry(&evidence_state_key)
            .await
            .unwrap()
            .unwrap();
        let state_before =
            serde_json::from_slice::<super::RecentDepositIndexState>(&state_before.value).unwrap();
        let concurrent_a = substrate.clone();
        let concurrent_b = reopened.clone();
        let (recent_a, recent_b) = tokio::join!(
            concurrent_a.recent_deposits(10),
            concurrent_b.recent_deposits(10)
        );
        assert!(
            recent_a
                .unwrap()
                .iter()
                .any(|deposit| { deposit.agent_id == mixed_version_concurrent.agent_id })
        );
        assert!(
            recent_b
                .unwrap()
                .iter()
                .any(|deposit| { deposit.agent_id == mixed_version_concurrent.agent_id })
        );
        let state_after = connection
            .store
            .entry(&evidence_state_key)
            .await
            .unwrap()
            .unwrap();
        let state_after =
            serde_json::from_slice::<super::RecentDepositIndexState>(&state_after.value).unwrap();
        assert_eq!(
            state_after.last_ordinal,
            state_before.last_ordinal + 1,
            "concurrent refreshers must assign one dense ordinal to one prior-layout deposit"
        );

        let compatibility_before = connection
            .store
            .entry(super::RECENT_DEPOSIT_COMPATIBILITY_STATE_KEY)
            .await
            .unwrap()
            .unwrap();
        substrate.recent_deposits(10).await.unwrap();
        let compatibility_after = connection
            .store
            .entry(super::RECENT_DEPOSIT_COMPATIBILITY_STATE_KEY)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            compatibility_after.revision, compatibility_before.revision,
            "a read-only refresh must not chase its own compatibility-state write"
        );

        for index in 0..130_i64 {
            // Bucket-wide stream revisions are deliberately perturbed. Ring
            // placement must depend only on the CAS-allocated deposit ordinal.
            connection
                .store
                .put(
                    format!("unrelated.noise.{index}"),
                    b"not-json".as_slice().into(),
                )
                .await
                .unwrap();
            substrate
                .deposit(sample_deposit(
                    &format!("recent-ring-{index}"),
                    now - 129 + index,
                    0.9,
                ))
                .await
                .unwrap();
        }
        connection
            .store
            .put("unrelated.noise.final", b"not-json".as_slice().into())
            .await
            .unwrap();

        let recent = substrate.recent_deposits(100).await.unwrap();
        assert_eq!(recent.len(), 100);
        assert_eq!(recent[0].timestamp, now);
        assert_eq!(recent[99].timestamp, now - 99);

        let writers = (0..64)
            .map(|index| {
                let substrate = substrate.clone();
                tokio::spawn(async move {
                    substrate
                        .deposit(sample_deposit(
                            &format!("concurrent-recent-ring-{index}"),
                            now,
                            0.9,
                        ))
                        .await
                })
            })
            .collect::<Vec<_>>();
        for writer in writers {
            writer.await.unwrap().unwrap();
        }
        assert_eq!(substrate.recent_deposits(100).await.unwrap().len(), 100);

        let stop = Arc::new(AtomicBool::new(false));
        let writes = Arc::new(AtomicUsize::new(0));
        let live_substrate = substrate.clone();
        let live_stop = Arc::clone(&stop);
        let live_writes = Arc::clone(&writes);
        let live_writer = tokio::spawn(async move {
            let mut index = 0_u64;
            while !live_stop.load(Ordering::Relaxed) {
                live_substrate
                    .deposit(sample_deposit(
                        &format!("snapshot-overwrite-{index}"),
                        now,
                        0.9,
                    ))
                    .await
                    .unwrap();
                index = index.saturating_add(1);
                live_writes.fetch_add(1, Ordering::Relaxed);
            }
        });
        wait_until(|| {
            let writes = Arc::clone(&writes);
            async move { writes.load(Ordering::Relaxed) >= 4 }
        })
        .await;
        let concurrent_snapshot =
            tokio::time::timeout(Duration::from_secs(5), substrate.recent_deposits(100))
                .await
                .expect("recent ring snapshot chased live slot overwrites")
                .unwrap();
        stop.store(true, Ordering::Relaxed);
        live_writer.await.unwrap();
        assert!(!concurrent_snapshot.is_empty());
        assert!(concurrent_snapshot.len() <= 100);

        let mut keys = connection.store.keys().await.unwrap();
        let mut recent_index_keys = 0_u64;
        while let Some(key) = keys.next().await {
            if key
                .unwrap()
                .starts_with(&format!("{}.", super::RECENT_DEPOSIT_INDEX_KEY_PREFIX))
            {
                recent_index_keys = recent_index_keys.saturating_add(1);
            }
        }
        assert_eq!(recent_index_keys, MAX_RECENT_DEPOSIT_INDEX_SLOTS);
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_compatibility_state_repairs_a_pointer_write_crash() {
        let Some((_bucket, substrate)) = connect_for_test("compatibility-pointer-crash").await
        else {
            return;
        };
        let connection = substrate.ensure_connected().await.unwrap();
        substrate
            .ensure_recent_deposit_index_initialized(connection)
            .await
            .unwrap();
        let now = now_timestamp();
        let first = sample_deposit("compatibility-crash-first", now - 2, 0.9);
        let first_key = format!(
            "exp.{:020}.execution.evidence.{:020}.compatibility-crash-first",
            expiration_gc_page(&first, 3_600.0, 0.01),
            first.timestamp
        );
        let first_revision = connection
            .store
            .put(
                first_key.clone(),
                serde_json::to_vec(&first).unwrap().into(),
            )
            .await
            .unwrap();
        let second = sample_deposit("compatibility-crash-second", now - 1, 0.9);
        let second_key = format!(
            "exp.{:020}.execution.evidence.{:020}.compatibility-crash-second",
            expiration_gc_page(&second, 3_600.0, 0.01),
            second.timestamp
        );
        let second_revision = connection
            .store
            .put(
                second_key.clone(),
                serde_json::to_vec(&second).unwrap().into(),
            )
            .await
            .unwrap();

        let state_key = super::recent_deposit_index_state_key(DepositKeyKind::Evidence);
        let state_entry = connection.store.entry(&state_key).await.unwrap().unwrap();
        let mut state =
            serde_json::from_slice::<super::RecentDepositIndexState>(&state_entry.value).unwrap();
        let second_ordinal = state.last_ordinal + 2;
        state.last_ordinal = second_ordinal;
        state.last_compatibility_revision = second_revision;
        state.last_compatibility_key = Some(second_key.clone());
        state.last_compatibility_ordinal = second_ordinal;
        state.pending_compatibility_pointer = None;
        connection
            .store
            .update(
                &state_key,
                serde_json::to_vec(&state).unwrap().into(),
                state_entry.revision,
            )
            .await
            .unwrap();

        // This is the exact old crash state: the revision cursor advanced,
        // then the process stopped before either ring pointer was durable.
        substrate
            .ensure_compatibility_deposit_pointer(
                connection,
                DepositKeyKind::Evidence,
                &first_key,
                first_revision,
            )
            .await
            .unwrap();
        substrate
            .ensure_compatibility_deposit_pointer(
                connection,
                DepositKeyKind::Evidence,
                &second_key,
                second_revision,
            )
            .await
            .unwrap();
        let pointers = substrate
            .existing_recent_deposit_pointers(connection, DepositKeyKind::Evidence)
            .await
            .unwrap();
        assert!(pointers.iter().any(|pointer| {
            pointer.deposit_revision == first_revision && pointer.deposit_key == first_key
        }));
        assert!(pointers.iter().any(|pointer| {
            pointer.deposit_revision == second_revision && pointer.deposit_key == second_key
        }));
        let committed = connection.store.entry(&state_key).await.unwrap().unwrap();
        let committed =
            serde_json::from_slice::<super::RecentDepositIndexState>(&committed.value).unwrap();
        assert_eq!(committed.last_compatibility_revision, second_revision);
        assert_eq!(committed.pending_compatibility_pointer, None);

        let third = sample_deposit("compatibility-crash-third", now, 0.9);
        let third_key = format!(
            "exp.{:020}.execution.evidence.{:020}.compatibility-crash-third",
            expiration_gc_page(&third, 3_600.0, 0.01),
            third.timestamp
        );
        let third_revision = connection
            .store
            .put(
                third_key.clone(),
                serde_json::to_vec(&third).unwrap().into(),
            )
            .await
            .unwrap();
        let state_entry = connection.store.entry(&state_key).await.unwrap().unwrap();
        let mut pending_state =
            serde_json::from_slice::<super::RecentDepositIndexState>(&state_entry.value).unwrap();
        let third_ordinal = pending_state.last_ordinal + 1;
        pending_state.last_ordinal = third_ordinal;
        pending_state.pending_compatibility_pointer = Some(super::RecentDepositPointer {
            ordinal: third_ordinal,
            kind: DepositKeyKind::Evidence,
            deposit_key: third_key.clone(),
            deposit_revision: third_revision,
        });
        connection
            .store
            .update(
                &state_key,
                serde_json::to_vec(&pending_state).unwrap().into(),
                state_entry.revision,
            )
            .await
            .unwrap();

        // This is the new two-phase crash state: the durable reservation exists
        // but neither the pointer nor its committed revision does. Any helper
        // must finish that exact intent before processing later records.
        substrate
            .ensure_compatibility_deposit_pointer(
                connection,
                DepositKeyKind::Evidence,
                &third_key,
                third_revision,
            )
            .await
            .unwrap();
        let pointers = substrate
            .existing_recent_deposit_pointers(connection, DepositKeyKind::Evidence)
            .await
            .unwrap();
        assert!(pointers.iter().any(|pointer| {
            pointer.deposit_revision == third_revision && pointer.deposit_key == third_key
        }));
        let committed = connection.store.entry(&state_key).await.unwrap().unwrap();
        let committed =
            serde_json::from_slice::<super::RecentDepositIndexState>(&committed.value).unwrap();
        assert_eq!(committed.last_compatibility_revision, third_revision);
        assert_eq!(committed.last_compatibility_ordinal, third_ordinal);
        assert_eq!(committed.pending_compatibility_pointer, None);
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_providence_feedback_deposit_is_idempotent_across_retries() {
        let Some((_bucket, substrate)) = connect_for_test("feedback-idempotency").await else {
            return;
        };
        let timestamp = now_timestamp();
        let deposit = resign_sample_deposit(
            "feedback-idempotency",
            sample_deposit("feedback-idempotency", timestamp, 0.0),
            serde_json::json!({
                "schema": SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
                "feedback_id": "feedback-idempotency-operation",
                "event_id": "event-idempotency",
                "action": "dismiss",
                "observed_at_ms": timestamp.saturating_mul(1_000),
            }),
        );
        let operation_id = crate::substrate::deposit_operation_id(&deposit)
            .unwrap()
            .unwrap();
        substrate.deposit(deposit.clone()).await.unwrap();
        substrate.deposit(deposit.clone()).await.unwrap();
        let connection = substrate.ensure_connected().await.unwrap();
        assert_eq!(
            connection.store.stream.cached_info().config.max_bytes,
            super::MAX_JETSTREAM_BUCKET_BYTES,
            "the shared KV stream must enforce a hard storage ceiling"
        );
        assert!(
            connection
                .store
                .entry(&super::legacy_idempotent_deposit_intent_key(&operation_id))
                .await
                .unwrap()
                .is_none(),
            "new intents must never grow the legacy per-operation subject namespace"
        );
        let policy = substrate.config.resolve_threat_class_policy(None);
        assert!(
            connection
                .store
                .entry(&super::idempotent_deposit_intent_key(&operation_id))
                .await
                .unwrap()
                .is_some(),
            "new intents must use the policy-independent digest namespace"
        );
        let matches = substrate
            .recent_deposits(10)
            .await
            .unwrap()
            .into_iter()
            .filter(|deposit| {
                deposit
                    .indicator
                    .get("feedback_id")
                    .and_then(serde_json::Value::as_str)
                    == Some("feedback-idempotency-operation")
            })
            .count();
        assert_eq!(matches, 1);

        let stable_intent_key = super::idempotent_deposit_intent_key(&operation_id);
        let stable_intent_revision = connection
            .store
            .entry(&stable_intent_key)
            .await
            .unwrap()
            .unwrap()
            .revision;
        let extended_evaporation_threshold = policy.evaporation_threshold / 10.0;
        substrate
            .store_threat_class_config(ThreatClassConfig {
                threat_class: deposit.threat_class.clone(),
                half_life_secs: deposit.decay_half_life,
                evaporation_threshold: extended_evaporation_threshold,
                alert_threshold: 1.2,
                incident_threshold: 3.4,
            })
            .await
            .unwrap();
        substrate.deposit(deposit.clone()).await.unwrap();
        assert_eq!(
            connection
                .store
                .entry(&stable_intent_key)
                .await
                .unwrap()
                .unwrap()
                .revision,
            stable_intent_revision,
            "an exact retry must resolve the original intent after a retention-policy change"
        );
        let original_deadline = super::evaporation_deadline(
            &deposit,
            policy.half_life_secs,
            policy.evaporation_threshold,
        );
        let extended_deadline = super::evaporation_deadline(
            &deposit,
            deposit.decay_half_life,
            extended_evaporation_threshold,
        );
        let original_sweep = super::expiration_gc_page(
            &deposit,
            policy.half_life_secs,
            policy.evaporation_threshold,
        )
        .saturating_mul(super::GC_PAGE_SPAN_SECS);
        assert!(original_sweep >= original_deadline);
        assert!(original_sweep < extended_deadline);
        substrate.gc_evaporated(original_sweep).await.unwrap();
        let retained_intent = connection
            .store
            .entry(&stable_intent_key)
            .await
            .unwrap()
            .unwrap();
        let retained_intent =
            serde_json::from_slice::<super::IdempotentDepositIntent>(&retained_intent.value)
                .unwrap();
        assert!(
            connection
                .store
                .get(&retained_intent.deposit_key)
                .await
                .unwrap()
                .is_some(),
            "the extended policy must retain the signed deposit"
        );
        substrate.deposit(deposit.clone()).await.unwrap();
        assert_eq!(
            substrate
                .recent_deposits(10)
                .await
                .unwrap()
                .into_iter()
                .filter(|candidate| {
                    candidate
                        .indicator
                        .get("feedback_id")
                        .and_then(serde_json::Value::as_str)
                        == Some("feedback-idempotency-operation")
                })
                .count(),
            1,
            "GC under an extended policy must not permit a duplicate exact retry"
        );

        let crash_window = resign_sample_deposit(
            "feedback-idempotency-crash-window",
            sample_deposit("feedback-idempotency-crash-window", timestamp, 0.0),
            serde_json::json!({
                "schema": SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
                "feedback_id": "feedback-idempotency-crash-window-operation",
                "event_id": "event-idempotency-crash-window",
                "action": "dismiss",
                "observed_at_ms": timestamp.saturating_mul(1_000),
            }),
        );
        let crash_payload = serde_json::to_vec(&crash_window).unwrap();
        let crash_operation_id = crate::substrate::deposit_operation_id(&crash_window)
            .unwrap()
            .unwrap();
        let uncommitted = substrate
            .resolve_idempotent_deposit_intent(
                connection,
                &crash_window,
                &crash_payload,
                &crash_operation_id,
                DepositKeyKind::Control,
                (policy.half_life_secs, policy.evaporation_threshold),
            )
            .await
            .unwrap();
        assert_eq!(uncommitted.intent.committed_deposit_revision, None);

        let superseding_ordinal = uncommitted
            .intent
            .ordinal
            .saturating_add(MAX_RECENT_DEPOSIT_INDEX_SLOTS);
        let superseding_deposit = sample_deposit(
            "feedback-idempotency-ring-superseding-deposit",
            timestamp,
            0.0,
        );
        let superseding_payload = serde_json::to_vec(&superseding_deposit).unwrap();
        let superseding_key = super::deposit_key(
            &superseding_deposit,
            &superseding_payload,
            policy.half_life_secs,
            policy.evaporation_threshold,
            superseding_ordinal,
        );
        let superseding_revision = connection
            .store
            .put(superseding_key.clone(), superseding_payload.into())
            .await
            .unwrap();
        assert_eq!(
            substrate
                .write_recent_deposit_pointer(
                    connection,
                    &RecentDepositPointer {
                        ordinal: superseding_ordinal,
                        kind: DepositKeyKind::Control,
                        deposit_key: superseding_key,
                        deposit_revision: superseding_revision,
                    },
                )
                .await
                .unwrap(),
            super::RecentDepositPointerWrite::Indexed
        );
        substrate
            .publish_recent_deposit_index_state_at_least(
                connection,
                DepositKeyKind::Control,
                superseding_ordinal,
            )
            .await
            .unwrap();
        let superseding_pointer = connection
            .store
            .entry(&super::recent_deposit_index_key(
                DepositKeyKind::Control,
                uncommitted.intent.ordinal,
            ))
            .await
            .unwrap()
            .unwrap();
        let superseding_pointer =
            serde_json::from_slice::<RecentDepositPointer>(&superseding_pointer.value).unwrap();
        assert_eq!(superseding_pointer.ordinal, superseding_ordinal);
        substrate.deposit(crash_window).await.unwrap();
        let recovered = substrate
            .resolve_idempotent_deposit_intent(
                connection,
                &serde_json::from_slice(&crash_payload).unwrap(),
                &crash_payload,
                &crash_operation_id,
                DepositKeyKind::Control,
                (policy.half_life_secs, policy.evaporation_threshold),
            )
            .await
            .unwrap();
        assert!(recovered.intent.ordinal > uncommitted.intent.ordinal);
        assert!(recovered.intent.committed_deposit_revision.is_some());
        assert!(
            substrate
                .recent_deposits(100)
                .await
                .unwrap()
                .iter()
                .any(|deposit| {
                    deposit
                        .indicator
                        .get("feedback_id")
                        .and_then(serde_json::Value::as_str)
                        == Some("feedback-idempotency-crash-window-operation")
                })
        );
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_custom_class_collisions_are_isolated_and_legacy_readable() {
        let Some((_bucket, substrate)) = connect_for_test("custom-collision").await else {
            return;
        };
        let now = now_timestamp();
        let slash_class = ThreatClass::Custom("Foo/Bar".to_string());
        let question_class = ThreatClass::Custom("foo?bar".to_string());

        let mut slash = sample_deposit("custom-slash", now - 3, 0.9);
        slash.threat_class = slash_class.clone();
        let slash = resign_sample_deposit(
            "custom-slash",
            slash,
            serde_json::json!({"signal": "slash"}),
        );
        let mut question = sample_deposit("custom-question", now - 2, 0.8);
        question.threat_class = question_class.clone();
        let question = resign_sample_deposit(
            "custom-question",
            question,
            serde_json::json!({"signal": "question"}),
        );
        substrate.deposit(slash).await.unwrap();
        substrate.deposit(question).await.unwrap();

        let connection = substrate.ensure_connected().await.unwrap();
        let mut legacy_slash = sample_deposit("legacy-custom-slash", now - 1, 0.7);
        legacy_slash.threat_class = slash_class.clone();
        let legacy_slash = resign_sample_deposit(
            "legacy-custom-slash",
            legacy_slash,
            serde_json::json!({"signal": "legacy-slash"}),
        );
        let mut legacy_question = sample_deposit("legacy-custom-question", now, 0.6);
        legacy_question.threat_class = question_class.clone();
        let legacy_question = resign_sample_deposit(
            "legacy-custom-question",
            legacy_question,
            serde_json::json!({"signal": "legacy-question"}),
        );
        let legacy_segment = legacy_threat_class_segment(&slash_class);
        assert_eq!(legacy_segment, legacy_threat_class_segment(&question_class));
        for (suffix, deposit) in [("slash", legacy_slash), ("question", legacy_question)] {
            let payload = serde_json::to_vec(&deposit).unwrap();
            connection
                .store
                .put(
                    format!(
                        "exp.{:020}.{legacy_segment}.evidence.{:020}.legacy-{suffix}",
                        expiration_gc_page(&deposit, 3_600.0, 0.01),
                        deposit.timestamp
                    ),
                    payload.into(),
                )
                .await
                .unwrap();
        }

        let slash = substrate
            .query_deposits(crate::DepositQuery {
                threat_class: Some(slash_class.clone()),
                since_timestamp: None,
                host_id: None,
                limit: 10,
            })
            .await
            .unwrap();
        let question = substrate
            .query_deposits(crate::DepositQuery {
                threat_class: Some(question_class.clone()),
                since_timestamp: None,
                host_id: None,
                limit: 10,
            })
            .await
            .unwrap();
        assert_eq!(slash.len(), 2);
        assert!(
            slash
                .iter()
                .all(|deposit| deposit.threat_class == slash_class)
        );
        assert_eq!(question.len(), 2);
        assert!(
            question
                .iter()
                .all(|deposit| deposit.threat_class == question_class)
        );
        assert_ne!(
            threat_class_segment(&slash_class),
            threat_class_segment(&question_class)
        );
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_index_refresh_stops_at_its_captured_high_water() {
        let Some((_bucket, substrate)) = connect_for_test("captured-high-water").await else {
            return;
        };
        let now = now_timestamp();
        let deposit = sample_deposit("continuous-writer", now, 0.9);
        let payload = serde_json::to_vec(&deposit).unwrap();
        let page = expiration_gc_page(&deposit, 3_600.0, 0.01);
        let connection = substrate.ensure_connected().await.unwrap();
        for index in 0..256_u64 {
            connection
                .store
                .put(
                    format!("exp.{page:020}.execution.evidence.{now:020}.backlog-{index:020}"),
                    payload.clone().into(),
                )
                .await
                .unwrap();
        }

        let stop = Arc::new(AtomicBool::new(false));
        let writer_stop = Arc::clone(&stop);
        let writer_store = connection.store.clone();
        let writer_payload = payload.clone();
        let writer = tokio::spawn(async move {
            let mut index = 0_u64;
            while !writer_stop.load(Ordering::Relaxed) {
                writer_store
                    .put(
                        format!("exp.{page:020}.execution.evidence.{now:020}.live-{index:020}"),
                        writer_payload.clone().into(),
                    )
                    .await
                    .unwrap();
                index = index.saturating_add(1);
            }
            index
        });

        let refresh = tokio::time::timeout(
            Duration::from_secs(5),
            substrate.load_deposits_bounded(
                Some(&ThreatClass::Execution),
                None,
                Some(now),
                8,
                false,
            ),
        )
        .await;
        stop.store(true, Ordering::Relaxed);
        let writes_while_refreshing = writer.await.unwrap();
        assert!(
            writes_while_refreshing > 0,
            "the producer must overlap the refresh"
        );
        let deposits = refresh
            .expect("refresh chased writes beyond its captured high-water")
            .unwrap();
        assert!(!deposits.is_empty());
        assert!(deposits.len() <= 8);
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_bounded_scan_filters_expired_keys_and_partitions_control_records() {
        let Some((_bucket, substrate)) = connect_for_test("partitioned-scan").await else {
            return;
        };
        let now = now_timestamp();
        substrate
            .deposit(sample_deposit("live-evidence", now, 0.9))
            .await
            .unwrap();
        let connection = substrate.ensure_connected().await.unwrap();
        let legacy_evidence = sample_deposit("legacy-live-evidence", now - 1, 0.8);
        let mut legacy_records = vec![legacy_evidence];
        legacy_records.extend((1..=4).map(|offset| {
            sample_deposit(
                &format!("legacy-inactive-control-{offset}"),
                now + offset,
                0.0,
            )
        }));
        let mut legacy_control_keys = Vec::new();
        for (index, deposit) in legacy_records.into_iter().enumerate() {
            let payload = serde_json::to_vec(&deposit).unwrap();
            let key = format!(
                "exp.{:020}.execution.{:020}.legacy-{index}",
                expiration_gc_page(&deposit, 3_600.0, 0.01),
                deposit.timestamp
            );
            if deposit.confidence == 0.0 {
                legacy_control_keys.push(key.clone());
            }
            connection.store.put(key, payload.into()).await.unwrap();
        }

        // The live concentration index uses server-side threat-class filters;
        // malformed values outside that filter are neither enumerated nor
        // decoded on the hot path.
        connection
            .store
            .put("unrelated.noise", b"not-json".as_slice().into())
            .await
            .unwrap();

        // The admission-time page says this record expired under threshold
        // 0.5, but the active operator override lowers the threshold to 0.001.
        // The page is only a candidate: signed payload plus current policy are
        // authoritative, so the record remains queryable and is not purged.
        let policy_sensitive = sample_deposit("policy-sensitive", now - 5_000, 0.9);
        let policy_sensitive_payload = serde_json::to_vec(&policy_sensitive).unwrap();
        let policy_sensitive_key = format!(
            "exp.{:020}.execution.evidence.{:020}.policy-sensitive",
            expiration_gc_page(&policy_sensitive, 3_600.0, 0.5),
            policy_sensitive.timestamp
        );
        connection
            .store
            .put(
                policy_sensitive_key.clone(),
                policy_sensitive_payload.into(),
            )
            .await
            .unwrap();
        substrate
            .store_threat_class_config(ThreatClassConfig {
                threat_class: ThreatClass::Execution,
                half_life_secs: 3_600.0,
                evaporation_threshold: 0.001,
                alert_threshold: 1.2,
                incident_threshold: 3.4,
            })
            .await
            .unwrap();

        let deposits = substrate
            .load_deposits_bounded(Some(&ThreatClass::Execution), None, Some(now + 4), 3, false)
            .await
            .unwrap();
        assert_eq!(deposits.len(), 6);
        assert_eq!(
            deposits
                .iter()
                .filter(|deposit| deposit.confidence > 0.0)
                .count(),
            3
        );
        assert!(deposits.iter().any(|deposit| deposit.agent_id
            == AgentId::from_verifying_key(
                &signing_key_for_label("live-evidence").verifying_key()
            )));
        assert!(deposits.iter().any(|deposit| deposit.agent_id
            == AgentId::from_verifying_key(
                &signing_key_for_label("legacy-live-evidence").verifying_key()
            )));
        assert!(deposits.iter().any(|deposit| deposit.agent_id
            == AgentId::from_verifying_key(
                &signing_key_for_label("policy-sensitive").verifying_key()
            )));
        assert!(
            connection
                .store
                .entry(&policy_sensitive_key)
                .await
                .unwrap()
                .is_some(),
            "an old GC page must not override the current retention policy"
        );
        assert!(
            connection
                .store
                .entry(&legacy_control_keys[0])
                .await
                .unwrap()
                .is_none(),
            "the oldest over-limit control subject must be destructively purged"
        );
        assert!(
            connection
                .store
                .entry("unrelated.noise")
                .await
                .unwrap()
                .is_some(),
            "filtered compaction must not purge an unrelated KV subject"
        );
        {
            let indexes = substrate.deposit_key_indexes.lock().await;
            let execution = indexes.partitions.get("execution").unwrap();
            assert!(execution.current_layout.initialized);
            assert!(execution.legacy_layout.initialized);
            assert_eq!(execution.evidence.len(), 3);
            assert_eq!(execution.controls.len(), 3);
            assert!(execution.total_bytes() <= MAX_ACTIVE_DEPOSIT_BYTES);
        }

        // With no intervening stream revision, the next monitor read is served
        // from the bounded local index and exact KV gets; no history consumer
        // is recreated and no whole-bucket enumeration occurs.
        assert_eq!(
            substrate
                .load_deposits_bounded(
                    Some(&ThreatClass::Execution),
                    None,
                    Some(now + 4),
                    3,
                    false,
                )
                .await
                .unwrap()
                .len(),
            6
        );

        let mismatched = sample_deposit("mismatched-control", now + 4, 0.0);
        let mismatched_payload = serde_json::to_vec(&mismatched).unwrap();
        let mismatched_key = format!(
            "exp.{:020}.execution.evidence.{:020}.mismatched",
            expiration_gc_page(&mismatched, 3_600.0, 0.01),
            mismatched.timestamp
        );
        connection
            .store
            .put(mismatched_key, mismatched_payload.into())
            .await
            .unwrap();
        assert!(matches!(
            substrate
                .load_deposits_bounded(
                    Some(&ThreatClass::Execution),
                    None,
                    Some(now + 4),
                    10,
                    false,
                )
                .await,
            Err(crate::SubstrateError::InvalidDeposit { reason })
                if reason.contains("class does not match its signed payload")
        ));
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_control_eviction_cannot_resurrect_dismissed_evidence() {
        let Some((_bucket, substrate)) = connect_for_test("feedback-window").await else {
            return;
        };
        let now = now_timestamp();
        let evidence = resign_sample_deposit(
            "feedback-evidence",
            sample_deposit("feedback-evidence", now - 10, 0.9),
            serde_json::json!({"event_id": "event-dismissed"}),
        );
        let dismissal = resign_sample_deposit(
            "feedback-reviewer",
            sample_deposit("feedback-reviewer", now - 5, 0.0),
            serde_json::json!({
                "schema": SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
                "feedback_id": "feedback-dismiss-event",
                "event_id": "event-dismissed",
                "action": "dismiss",
                "observed_at_ms": now.saturating_sub(5).saturating_mul(1_000),
            }),
        );
        let unrelated_control = resign_sample_deposit(
            "feedback-control",
            sample_deposit("feedback-control", now, 0.0),
            serde_json::json!({"event_id": "unrelated-control"}),
        );
        substrate.deposit(evidence).await.unwrap();
        substrate.deposit(dismissal).await.unwrap();

        let connection = substrate.ensure_connected().await.unwrap();
        let evidence_pointer = substrate
            .existing_recent_deposit_pointers(connection, DepositKeyKind::Evidence)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let dismissal_pointer = substrate
            .existing_recent_deposit_pointers(connection, DepositKeyKind::Control)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let unrelated_ordinal = dismissal_pointer
            .ordinal
            .saturating_add(MAX_RECENT_DEPOSIT_INDEX_SLOTS);
        let unrelated_payload = serde_json::to_vec(&unrelated_control).unwrap();
        let policy = substrate.config.resolve_threat_class_policy(None);
        let unrelated_key = super::deposit_key(
            &unrelated_control,
            &unrelated_payload,
            policy.half_life_secs,
            policy.evaporation_threshold,
            unrelated_ordinal,
        );
        let unrelated_revision = connection
            .store
            .put(unrelated_key.clone(), unrelated_payload.into())
            .await
            .unwrap();
        assert_eq!(
            substrate
                .write_recent_deposit_pointer(
                    connection,
                    &RecentDepositPointer {
                        ordinal: unrelated_ordinal,
                        kind: DepositKeyKind::Control,
                        deposit_key: unrelated_key,
                        deposit_revision: unrelated_revision,
                    },
                )
                .await
                .unwrap(),
            super::RecentDepositPointerWrite::Indexed
        );
        substrate
            .publish_recent_deposit_index_state_at_least(
                connection,
                DepositKeyKind::Control,
                unrelated_ordinal,
            )
            .await
            .unwrap();

        assert!(
            substrate
                .existing_recent_deposit_pointers(connection, DepositKeyKind::Evidence)
                .await
                .unwrap()
                .iter()
                .all(|pointer| pointer != &evidence_pointer),
            "rotating away the last dismissal must remove the governed evidence pointer"
        );
        assert!(
            connection
                .store
                .get(&evidence_pointer.deposit_key)
                .await
                .unwrap()
                .is_none(),
            "rotating away the last dismissal must purge the governed evidence value"
        );

        let retained = substrate
            .load_deposits_bounded(Some(&ThreatClass::Execution), None, Some(now), 1, false)
            .await
            .unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].confidence, 0.0);
        assert_eq!(substrate.deposit_count().await.unwrap(), 1);
        let concentration = substrate
            .query_concentration(&ThreatClass::Execution, now)
            .await
            .unwrap();
        assert_eq!(concentration.total_strength, 0.0);
        assert_eq!(concentration.distinct_sources, 0);
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn losing_control_pointer_cas_cannot_purge_concurrently_confirmed_evidence() {
        let Some((_bucket, substrate)) = connect_for_test("feedback-cas-confirmation").await else {
            return;
        };
        let now = now_timestamp();
        let evidence = resign_sample_deposit(
            "feedback-cas-evidence",
            sample_deposit("feedback-cas-evidence", now - 10, 0.9),
            serde_json::json!({"event_id": "event-cas-reviewed"}),
        );
        let dismissal = resign_sample_deposit(
            "feedback-cas-dismissal",
            sample_deposit("feedback-cas-dismissal", now - 5, 0.0),
            serde_json::json!({
                "schema": SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
                "feedback_id": "feedback-cas-dismissal",
                "event_id": "event-cas-reviewed",
                "action": "dismiss",
                "observed_at_ms": now.saturating_sub(5).saturating_mul(1_000),
            }),
        );
        substrate.deposit(evidence).await.unwrap();
        substrate.deposit(dismissal).await.unwrap();

        let connection = substrate.ensure_connected().await.unwrap();
        let evidence_pointer = substrate
            .existing_recent_deposit_pointers(connection, DepositKeyKind::Evidence)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let dismissal_pointer = substrate
            .existing_recent_deposit_pointers(connection, DepositKeyKind::Control)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let policy = substrate.config.resolve_threat_class_policy(None);

        let losing_ordinal = dismissal_pointer
            .ordinal
            .saturating_add(MAX_RECENT_DEPOSIT_INDEX_SLOTS);
        let losing_control = resign_sample_deposit(
            "feedback-cas-loser",
            sample_deposit("feedback-cas-loser", now, 0.0),
            serde_json::json!({"event_id": "unrelated-control"}),
        );
        let losing_payload = serde_json::to_vec(&losing_control).unwrap();
        let losing_key = super::deposit_key(
            &losing_control,
            &losing_payload,
            policy.half_life_secs,
            policy.evaporation_threshold,
            losing_ordinal,
        );
        let losing_revision = connection
            .store
            .put(losing_key.clone(), losing_payload.into())
            .await
            .unwrap();
        let losing_pointer = RecentDepositPointer {
            ordinal: losing_ordinal,
            kind: DepositKeyKind::Control,
            deposit_key: losing_key,
            deposit_revision: losing_revision,
        };

        let winning_ordinal = losing_ordinal.saturating_add(MAX_RECENT_DEPOSIT_INDEX_SLOTS);
        let confirmation = resign_sample_deposit(
            "feedback-cas-confirmation",
            sample_deposit("feedback-cas-confirmation", now, 0.0),
            serde_json::json!({
                "schema": SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
                "feedback_id": "feedback-cas-confirmation",
                "event_id": "event-cas-reviewed",
                "action": "confirm",
                "observed_at_ms": now.saturating_mul(1_000),
            }),
        );
        let confirmation_payload = serde_json::to_vec(&confirmation).unwrap();
        let confirmation_key = super::deposit_key(
            &confirmation,
            &confirmation_payload,
            policy.half_life_secs,
            policy.evaporation_threshold,
            winning_ordinal,
        );
        let confirmation_revision = connection
            .store
            .put(confirmation_key.clone(), confirmation_payload.into())
            .await
            .unwrap();
        let confirmation_pointer = RecentDepositPointer {
            ordinal: winning_ordinal,
            kind: DepositKeyKind::Control,
            deposit_key: confirmation_key,
            deposit_revision: confirmation_revision,
        };

        let hook = RecentDepositPointerCasHook::new();
        let losing_write = substrate.write_recent_deposit_pointer_with_hook(
            connection,
            &losing_pointer,
            Some(&hook),
        );
        let winning_write = async {
            hook.reached.wait().await;
            let outcome = substrate
                .write_recent_deposit_pointer(connection, &confirmation_pointer)
                .await;
            hook.release.wait().await;
            outcome
        };
        let (losing_outcome, winning_outcome) = tokio::join!(losing_write, winning_write);
        assert_eq!(winning_outcome.unwrap(), RecentDepositPointerWrite::Indexed);
        assert_eq!(
            losing_outcome.unwrap(),
            RecentDepositPointerWrite::Superseded
        );
        assert!(
            substrate
                .existing_recent_deposit_pointers(connection, DepositKeyKind::Evidence)
                .await
                .unwrap()
                .iter()
                .any(|pointer| pointer == &evidence_pointer),
            "the losing writer must not purge evidence retained by the winning confirmation"
        );
        assert!(
            connection
                .store
                .get(&evidence_pointer.deposit_key)
                .await
                .unwrap()
                .is_some(),
            "the confirmed evidence value must remain durable"
        );
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_gc_removes_evaporated_deposits() {
        let Some((_bucket, substrate)) = connect_for_test("gc").await else {
            return;
        };
        let now = now_timestamp();
        substrate
            .deposit(sample_deposit("whisker-a", now - 1, 0.1))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit("whisker-b", now, 0.9))
            .await
            .unwrap();
        wait_until(|| async { substrate.recent_deposits(10).await.unwrap().len() == 2 }).await;

        let deposits = substrate.recent_deposits(10).await.unwrap();
        assert_eq!(deposits.len(), 2);

        let concentration = substrate
            .query_concentration(&ThreatClass::Execution, now + 14_000)
            .await
            .unwrap();
        assert_eq!(concentration.distinct_sources, 1);
        assert!(concentration.total_strength > substrate_config().evaporation_threshold);

        let removed = substrate.gc_evaporated(now + 14_000).await.unwrap();
        assert_eq!(
            removed, 0,
            "the scoped concentration index eagerly purges certainly expired GC pages"
        );

        let deposits = substrate.recent_deposits(10).await.unwrap();
        assert_eq!(deposits.len(), 1);
        assert_eq!(
            deposits[0].agent_id,
            AgentId::from_verifying_key(&signing_key_for_label("whisker-b").verifying_key())
        );
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_gc_pages_expired_entries_for_large_buckets() {
        let mut config = substrate_config();
        config.backend = PheromoneBackendConfig::JetStream {
            url: nats_url(),
            connect_timeout_ms: DEFAULT_NATS_CONNECT_TIMEOUT_MS,
            gc_page_size: 1,
        };
        let bucket = unique_bucket("gc-pages");
        let substrate =
            JetStreamPheromoneSubstrate::connect_with_bucket(config, nats_url(), bucket)
                .await
                .unwrap();

        let now = now_timestamp();
        substrate
            .deposit(sample_deposit("whisker-a", now - 2, 0.1))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit("whisker-b", now - 1, 0.2))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit("whisker-c", now, 0.9))
            .await
            .unwrap();

        let mut removed = 0;
        for _ in 0..64 {
            let batch = substrate.gc_evaporated(now + 18_000).await.unwrap();
            assert!(batch <= 1, "one-page GC exceeded its configured page bound");
            removed += batch;
            if removed == 2 {
                break;
            }
        }
        assert_eq!(removed, 2);

        let deposits = substrate.recent_deposits(10).await.unwrap();
        assert_eq!(deposits.len(), 1);
        assert_eq!(
            deposits[0].agent_id,
            AgentId::from_verifying_key(&signing_key_for_label("whisker-c").verifying_key())
        );
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_recovers_escalations_after_reconnect() {
        let Some((bucket, substrate)) = connect_for_test("escalations").await else {
            return;
        };
        substrate
            .record_escalation(sample_escalation(SwarmMode::Alert, 100))
            .await
            .unwrap();
        substrate
            .record_escalation(sample_escalation(SwarmMode::Incident, 200))
            .await
            .unwrap();
        wait_until(|| async { substrate.query_escalations(0).await.unwrap().len() == 2 }).await;
        drop(substrate);

        let reopened = JetStreamPheromoneSubstrate::connect_with_bucket(
            substrate_config(),
            nats_url(),
            bucket,
        )
        .await
        .unwrap();
        let escalations = reopened.query_escalations(0).await.unwrap();
        assert_eq!(escalations.len(), 2);
        assert_eq!(escalations[0].mode, SwarmMode::Alert);
        assert_eq!(escalations[1].mode, SwarmMode::Incident);
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_recovers_threat_class_configs_after_reconnect() {
        let Some((bucket, substrate)) = connect_for_test("threat-class-configs").await else {
            return;
        };
        substrate
            .store_threat_class_config(sample_threat_class_config())
            .await
            .unwrap();
        wait_until(|| async { substrate.query_threat_class_configs().await.unwrap().len() == 1 })
            .await;
        drop(substrate);

        let reopened = JetStreamPheromoneSubstrate::connect_with_bucket(
            substrate_config(),
            nats_url(),
            bucket,
        )
        .await
        .unwrap();
        let configs = reopened.query_threat_class_configs().await.unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].threat_class, ThreatClass::Execution);
        assert_eq!(configs[0].half_life_secs, 180.0);
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_recovers_threat_intel_entries_after_reconnect() {
        let Some((bucket, substrate)) = connect_for_test("threat-intel").await else {
            return;
        };
        substrate
            .store_threat_intel_entry(sample_threat_intel_entry())
            .await
            .unwrap();
        wait_until(|| async {
            substrate
                .query_threat_intel_entry(
                    &ThreatIntelIndicatorType::Domain,
                    "example.com",
                    1_700_000_000_000,
                )
                .await
                .unwrap()
                .is_some()
        })
        .await;
        drop(substrate);

        let reopened = JetStreamPheromoneSubstrate::connect_with_bucket(
            substrate_config(),
            nats_url(),
            bucket,
        )
        .await
        .unwrap();
        let stored = reopened
            .query_threat_intel_entry(
                &ThreatIntelIndicatorType::Domain,
                "example.com",
                1_700_000_000_000,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.value, "example.com");
        assert_eq!(stored.confidence, 0.91);

        let expired = reopened
            .query_threat_intel_entry(
                &ThreatIntelIndicatorType::Domain,
                "example.com",
                1_700_000_000_100,
            )
            .await
            .unwrap();
        assert!(expired.is_none());
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_gc_expired_threat_intel_removes_expired_entries() {
        let Some((_bucket, substrate)) = connect_for_test("gc-threat-intel").await else {
            return;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_secs() as i64;

        // Store one expired and one active threat-intel entry
        substrate
            .store_threat_intel_entry(ThreatIntelEntry {
                indicator_type: ThreatIntelIndicatorType::Domain,
                value: "expired.example.com".to_string(),
                source: "operator".to_string(),
                indicator_id: None,
                confidence: 0.9,
                expires_at: now - 100,
            })
            .await
            .unwrap();
        substrate
            .store_threat_intel_entry(ThreatIntelEntry {
                indicator_type: ThreatIntelIndicatorType::IpAddress,
                value: "10.0.0.1".to_string(),
                source: "operator".to_string(),
                indicator_id: None,
                confidence: 0.8,
                expires_at: now + 100_000,
            })
            .await
            .unwrap();

        wait_until(|| {
            let sub = substrate.clone();
            async move {
                sub.query_threat_intel_entry(&ThreatIntelIndicatorType::IpAddress, "10.0.0.1", now)
                    .await
                    .unwrap()
                    .is_some()
            }
        })
        .await;

        let purged = substrate.gc_expired_threat_intel(now).await.unwrap();
        assert_eq!(purged, 1);

        // Expired entry should be gone
        let expired = substrate
            .query_threat_intel_entry(&ThreatIntelIndicatorType::Domain, "expired.example.com", 0)
            .await
            .unwrap();
        assert!(expired.is_none());

        // Active entry should remain
        let active = substrate
            .query_threat_intel_entry(&ThreatIntelIndicatorType::IpAddress, "10.0.0.1", now)
            .await
            .unwrap();
        assert!(active.is_some());
    }
}
