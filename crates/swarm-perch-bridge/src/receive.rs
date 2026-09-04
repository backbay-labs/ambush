//! THE receive loop. `recv()`, classify, append. Nothing else, ever.
//!
//! # Import discipline, and why it is a rule rather than a preference
//!
//! This module may import [`crate::stream`], [`crate::spool`] and [`crate::metrics`]. It may not
//! name the publisher, the pacer, the channel provisioner, the identity table or the WebSocket
//! client — the test at the bottom of this file scans the production half of this source for
//! each of those names and fails if one appears. The 281 ms head room computed in the crate docs
//! is not defended by any timing test; a relay write added here would pass CI and lose evidence
//! silently in production. The module boundary is the defence.
//!
//! The issuer of a record is therefore supplied as a closure rather than looked up: the loop
//! needs one byte from a table it must not be able to name.

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, PoisonError};

use swarm_runtime::runtime_events::RuntimeEvent;
use tokio::sync::{broadcast, watch};

use crate::error::BridgeError;
use crate::metrics::BridgeMetrics;
use crate::spool::{GapCause, IssuerIdx, Record, SpoolSet};
use crate::stream;

/// Maps an event to the identity slot whose key signs the card built from it.
///
/// A boxed closure, not a table reference: see the module docs.
pub type IssuerOf = Arc<dyn Fn(&RuntimeEvent) -> IssuerIdx + Send + Sync>;

/// Runs until shutdown or `RecvError::Closed`.
///
/// `biased;` on the `select!` puts shutdown first so a draining daemon is never starved by a hot
/// broadcast — at 3,645 events/sec an unbiased select can leave the shutdown arm unpolled for a
/// long time.
///
/// # Errors
///
/// [`BridgeError::SpoolIo`] when a spool append fails for a reason that is not the alarm budget;
/// [`BridgeError::Encode`] when an event does not serialize. An
/// [`BridgeError::AlarmSpoolFull`] is counted and the loop continues, because alarm work is
/// refused rather than shed and the refusal must not block `recv()`.
pub async fn run(
    mut rx: broadcast::Receiver<RuntimeEvent>,
    spools: Arc<Mutex<SpoolSet>>,
    metrics: BridgeMetrics,
    issuer_of: IssuerOf,
    stall: Arc<AtomicU64>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), BridgeError> {
    loop {
        // A debug-only hook that lets an integration test hold the loop off `recv()` long enough
        // to overrun the broadcast on purpose. Compiled out of a release daemon entirely, and its
        // HTTP route is not registered there either.
        #[cfg(debug_assertions)]
        {
            let ms = stall.swap(0, std::sync::atomic::Ordering::AcqRel);
            if ms > 0 {
                tracing::warn!(
                    module = module_path!(),
                    ms,
                    "perch bridge receive loop stalled on request (test hook)"
                );
                tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
            }
        }
        #[cfg(not(debug_assertions))]
        let _ = &stall;

        tokio::select! {
            biased;

            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    tracing::info!(module = module_path!(), "perch bridge receive loop stopping");
                    return Ok(());
                }
            }

            result = rx.recv() => match result {
                Ok(mut event) => {
                    let stripped = stream::redact_in_place(&mut event);
                    if stripped > 0 {
                        metrics.redacted_library_loads(stripped);
                    }
                    let class = stream::classify(&event);
                    metrics.ingested(class);
                    let issuer = issuer_of(&event);
                    let record = Record::from_event(&event, issuer)?;
                    // Target <= 2 ms. Page-cache write, no fsync (the segment fsyncs on roll).
                    let mut guard = spools.lock().unwrap_or_else(PoisonError::into_inner);
                    match guard.append(class, record) {
                        Ok(_) => {}
                        // Alarm work is never shed, so a full alarm spool refuses the append.
                        // Counted here and never propagated: a refusal that killed the loop would
                        // turn a bounded alarm backlog into total evidence loss.
                        Err(BridgeError::AlarmSpoolFull { bytes, max_bytes }) => {
                            drop(guard);
                            metrics.alarm_spool_full();
                            tracing::error!(
                                module = module_path!(),
                                bytes,
                                max_bytes,
                                "alarm spool is full; refusing new alarm work"
                            );
                        }
                        Err(error) => {
                            drop(guard);
                            return Err(error);
                        }
                    }
                }

                // THE ONE CASE BOTH SHIPPED SUBSCRIBERS THROW AWAY.
                //
                // `swarm-ingest-runtime/src/ingest/demo.rs` (serving GET /v1/events/stream) and
                // `.../platform_api.rs` (serving GET /v2/api/stream/findings) both write:
                //
                //     let Ok(event) = result else { return None; };
                //
                // and `rg 'Lagged|RecvError'` over `crates/` returns zero matches. A dropped
                // evidence event is unrecoverable: the relay never had it, the daemon does not
                // retain it, `/v1/events/stream` has no Last-Event-ID resumption, and the bridge
                // holds no key with which to ask for it because it never saw the event.
                //
                // So it is counted, and the count reaches the operator as a gap row.
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    metrics.broadcast_lagged(count);
                    tracing::warn!(
                        module = module_path!(),
                        count,
                        "runtime event broadcast lagged; events were lost before the bridge saw them"
                    );
                    // A lag is not attributable to a stream: the events are gone and the bridge
                    // never saw their discriminants. Recorded against EVERY disk-spooled stream,
                    // because any of them may have lost content, with NO seq range -- no seq was
                    // ever assigned to what was never received, and saying so is the honest
                    // rendering.
                    spools
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .mark_gap_all_disk_spooled(GapCause::BroadcastLagged { count });
                }

                Err(broadcast::error::RecvError::Closed) => {
                    tracing::info!(module = module_path!(), "runtime event broadcast closed");
                    return Ok(());
                }
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::spool::Spool;

    fn finding_event(index: usize) -> RuntimeEvent {
        serde_json::from_value(serde_json::json!({
            "event_type": "finding", "emitted_at_ms": 1_700_000_000_000i64 + index as i64,
            "host_id": "web-04",
            "finding": {"schema": "swarm_finding", "finding_id": format!("f{index}"),
                        "event_id": format!("e{index}"), "strategy_id": "dns_exfil_beaconing",
                        "threat_class": "data_exfiltration", "severity": "HIGH",
                        "confidence": 0.82, "evidence": {}}
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn a_lagged_receiver_marks_a_gap_on_every_disk_spooled_stream() {
        let dir = tempfile::tempdir().unwrap();
        let spools = Arc::new(Mutex::new(
            SpoolSet::open(dir.path(), "c", 1 << 20, 8 << 20).unwrap(),
        ));
        let (tx, rx) = broadcast::channel::<RuntimeEvent>(4);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (metrics, _registry) = BridgeMetrics::new();
        // Overrun the 4-slot buffer BEFORE the loop polls it: six sends, two lost.
        for i in 0..6 {
            tx.send(finding_event(i)).unwrap();
        }
        let handle = tokio::spawn(run(
            rx,
            Arc::clone(&spools),
            metrics,
            Arc::new(|_| 0),
            Arc::new(AtomicU64::new(0)),
            shutdown_rx,
        ));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
        let mut spools = spools.lock().unwrap();
        assert_eq!(
            spools.evidence().take_gaps(),
            vec![GapCause::BroadcastLagged { count: 2 }]
        );
        assert_eq!(
            spools.alarm().take_gaps(),
            vec![GapCause::BroadcastLagged { count: 2 }]
        );
        assert_eq!(
            spools.evidence().peek(usize::MAX).unwrap().len(),
            4,
            "the four that survived were spooled"
        );
    }

    #[tokio::test]
    async fn every_event_lands_in_the_stream_its_classification_chose() {
        let dir = tempfile::tempdir().unwrap();
        let spools = Arc::new(Mutex::new(
            SpoolSet::open(dir.path(), "c", 1 << 20, 8 << 20).unwrap(),
        ));
        let (tx, rx) = broadcast::channel::<RuntimeEvent>(64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (metrics, _registry) = BridgeMetrics::new();
        let handle = tokio::spawn(run(
            rx,
            Arc::clone(&spools),
            metrics,
            Arc::new(|_| 0),
            Arc::new(AtomicU64::new(0)),
            shutdown_rx,
        ));
        tx.send(finding_event(1)).unwrap();
        tx.send(
            serde_json::from_value(serde_json::json!({
                "event_type": "mode_transition", "emitted_at_ms": 2, "from": "normal",
                "to": "incident", "triggering_threat_class": null, "reason": "test"
            }))
            .unwrap(),
        )
        .unwrap();
        tx.send(
            serde_json::from_value(serde_json::json!({
                "event_type": "agent_action", "emitted_at_ms": 3, "agent_id": "whisker-1",
                "role": "whisker", "action_kind": "deposit", "hunt_id": null,
                "details": {"payload": "adversary-shaped"}
            }))
            .unwrap(),
        )
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();

        let mut spools = spools.lock().unwrap();
        assert_eq!(spools.evidence().peek(usize::MAX).unwrap().len(), 1);
        assert_eq!(spools.alarm().peek(usize::MAX).unwrap().len(), 1);
        assert_eq!(spools.telemetry().len(), 1, "last-wins slot for telemetry");
        // The redaction ran before the append: the adversary-shaped payload is gone from disk.
        let stored = spools.telemetry().drain();
        let event: RuntimeEvent = serde_json::from_slice(&stored[0].1.payload).unwrap();
        assert!(matches!(
            event,
            RuntimeEvent::AgentAction { ref details, .. } if details.is_null()
        ));
    }

    /// T-9's sibling: the module boundary, asserted from the source.
    ///
    /// The scan covers the PRODUCTION half only — everything above this test module — because
    /// the forbidden names have to appear somewhere to be searched for, and that somewhere is
    /// here. Splitting on the attribute below is what keeps the assertion from failing on its
    /// own needles.
    #[test]
    fn the_receive_loop_imports_only_stream_spool_and_metrics() {
        let src = include_str!("receive.rs");
        let split = "#[cfg(te".to_string() + "st)]";
        let production = src
            .split(&split)
            .next()
            .expect("split always yields a first part");
        assert!(
            production.len() > 1_000,
            "the production half must be what was scanned"
        );
        for forbidden in [
            "crate::publish",
            "crate::pacer",
            "crate::channels",
            "crate::identity",
            "crate::alarm",
            "ambush_ws_client",
            "nostr::",
            "reqwest",
        ] {
            assert!(
                !production.contains(forbidden),
                "receive.rs must not name {forbidden}"
            );
        }
    }
}
