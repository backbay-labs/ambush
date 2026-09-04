//! The telemetry publisher: one tick, four frames, no `h` tag.
//!
//! Separate from the pacer for the reason the pacer exists. The pacer drains
//! the EVIDENCE spool one durable record at a time, restamps a frame that aged
//! past the relay's timestamp window, and rewinds a cursor on refusal — because
//! an evidence record that is lost is unrecoverable. None of that applies here:
//! a telemetry frame is a statement about NOW, and a replayed one is a lie
//! about now. So a refused frame is counted and dropped, never retried, and
//! the next tick supersedes it.
//!
//! # Why these frames carry no `h` tag
//!
//! `26000`-`26003` are community-global. They describe the colony, not a
//! channel, and scoping them to one would make the Watchfloor a per-channel
//! view of a whole-colony state. That globality is exactly why every payload
//! here is aggregates only: a global frame reaches every member, so a host
//! identifier or a raw detector string on one is a disclosure to everybody.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use swarm_runtime::runtime_events::RuntimeEvent;
use tokio::sync::watch;

use crate::coalesce::tick_frames;
use crate::error::BridgeError;
use crate::identity::IdentityTable;
use crate::metrics::BridgeMetrics;
use crate::pacer::{Frame, FramePublisher};
use crate::spool::SpoolSet;
use crate::stream::Stream;
use swarm_core::config::PerchBridgeConfig;

/// Everything the telemetry loop needs.
pub struct TelemetryDrainer<P: FramePublisher> {
    /// The spool set; only the telemetry slots and the ingest window are read.
    pub spools: Arc<Mutex<SpoolSet>>,
    /// The identity table, for the telemetry slot's keys and issuer index.
    pub identities: Arc<IdentityTable>,
    /// The `perch` config block.
    pub config: PerchBridgeConfig,
    /// Where frames go.
    pub publisher: P,
    /// The bridge's metrics.
    pub metrics: BridgeMetrics,
    /// The process-wide shutdown watch.
    pub shutdown: watch::Receiver<bool>,
}

/// The telemetry slot key whose put count is `26001`'s `coalesced_from`.
const CONCENTRATION_SLOT: &str = "26001";

/// Publish the colony's telemetry, once per tick, until shutdown.
///
/// # Errors
///
/// [`BridgeError::InvalidConfig`] when the identity table has no telemetry
/// slot. A per-tick publish failure is counted and never propagated: this is
/// the only telemetry drain, and a task that exited on one refused frame would
/// silently stop the Watchfloor for the life of the daemon.
pub async fn run<P: FramePublisher>(drainer: TelemetryDrainer<P>) -> Result<(), BridgeError> {
    let TelemetryDrainer {
        spools,
        identities,
        config,
        mut publisher,
        metrics,
        mut shutdown,
    } = drainer;

    // The telemetry slot signs 26000-26005 (identity.rs). Resolved by name so
    // a table without it fails loudly at startup rather than signing colony
    // telemetry with the alarm key.
    let issuer_idx = identities
        .index_of(&crate::identity::Slot::Telemetry)
        .ok_or_else(|| BridgeError::InvalidConfig {
            reason: "the perch identity table has no telemetry slot".to_string(),
        })?;
    let entry = identities
        .get(issuer_idx)
        .ok_or_else(|| BridgeError::InvalidConfig {
            reason: "the perch telemetry slot has no identity".to_string(),
        })?;
    let keys = entry.keys.clone();
    let issuer = keys.public_key().to_hex();

    // Per-kind sequence counters, outliving every tick: a gap in one kind's run
    // is how a console detects a dropped frame, so a counter reset per tick
    // would hide exactly what it exists to reveal.
    let mut seqs: BTreeMap<u16, u64> = BTreeMap::new();

    let mut interval = tokio::time::interval(Duration::from_millis(config.publish_tick_ms.max(1)));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;

            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    tracing::info!(module = module_path!(), "perch telemetry publisher stopping");
                    return Ok(());
                }
            }

            _ = interval.tick() => {
                let now_ms = chrono::Utc::now().timestamp_millis();
                if let Err(error) = publish_tick(
                    &spools,
                    &mut publisher,
                    &metrics,
                    &keys,
                    &issuer,
                    issuer_idx,
                    &mut seqs,
                    now_ms,
                )
                .await
                {
                    tracing::warn!(
                        module = module_path!(),
                        reason = %error,
                        "perch telemetry tick failed; the next tick supersedes it"
                    );
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn publish_tick<P: FramePublisher>(
    spools: &Arc<Mutex<SpoolSet>>,
    publisher: &mut P,
    metrics: &BridgeMetrics,
    keys: &nostr::Keys,
    issuer: &str,
    issuer_idx: crate::spool::IssuerIdx,
    seqs: &mut BTreeMap<u16, u64>,
    now_ms: i64,
) -> Result<(), BridgeError> {
    // The lock is held for the drain only. Decoding and signing happen outside
    // it, because the receive loop takes the same lock on every event and its
    // head room is what protects evidence.
    let (ingest, drained) = {
        let mut guard = spools.lock().unwrap_or_else(PoisonError::into_inner);
        let ingest = guard.drain_ingest_window();
        let drained = guard.telemetry().drain_with_counts();
        (ingest, drained)
    };

    let mut events = Vec::with_capacity(drained.len());
    let mut coalesced_from = 0u32;
    for (key, record, puts) in drained {
        if key == CONCENTRATION_SLOT {
            coalesced_from = puts;
        }
        match serde_json::from_slice::<RuntimeEvent>(&record.payload) {
            Ok(event) => events.push(event),
            // A record that does not decode is counted and skipped rather than
            // failing the tick: one malformed slot must not cost the other
            // three frames, and the count is what makes the loss visible.
            Err(_) => metrics.dropped_event(Stream::Telemetry, "telemetry_decode_failed"),
        }
    }

    let frames = tick_frames(
        ingest,
        &events,
        coalesced_from,
        issuer,
        now_ms,
        &mut |kind| {
            let next = seqs.entry(kind).or_insert(0);
            *next += 1;
            *next
        },
    )?;

    for pending in frames {
        let content = serde_json::to_string(&pending.value)
            .map_err(|error| BridgeError::Encode(error.to_string()))?;
        // No tags at all. These are community-global: an `h` would scope a
        // whole-colony state to one channel, and a `p` would page someone.
        let signed = nostr::EventBuilder::new(nostr::Kind::Custom(pending.kind), content)
            .custom_created_at(nostr::Timestamp::from((now_ms / 1_000).max(0) as u64))
            .sign_with_keys(keys)
            .map_err(|error| BridgeError::Encode(error.to_string()))?;
        let frame = Frame {
            identity: issuer_idx,
            channel: None,
            event_id: signed.id.to_hex(),
            signed,
            // Telemetry discharges no spool record: the slots are already
            // drained and a replayed ephemeral is a lie about now.
            covers: (issuer_idx, 0),
            created_at_secs: now_ms / 1_000,
        };
        let outcome = publisher.publish(&frame).await?;
        if outcome.is_success() {
            metrics.source_events_published(Stream::Telemetry);
        } else {
            // Counted and dropped, never retried. The next tick's frame is the
            // current truth; a retried one would assert a past moment as now.
            metrics.admission_rejection(outcome.reason());
            metrics.dropped_event(Stream::Telemetry, "relay_refused");
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "telemetry_tests.rs"]
mod tests;
