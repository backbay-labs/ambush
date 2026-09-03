//! THE receive loop. `recv()`, classify, append. Nothing else, ever.
//!
//! # Import discipline, and why it is a rule rather than a preference
//!
//! This module may import [`crate::stream`], [`crate::spool`] and [`crate::metrics`]. It may not
//! import [`crate::publish`], [`crate::pacer`], [`crate::channels`], [`crate::identity`] or
//! [`crate::ws`]. The 281 ms head room computed in the crate docs is not defended by any test —
//! a relay write added here would pass CI and lose evidence silently in production. The module
//! boundary is the defence.

use swarm_runtime::runtime_events::RuntimeEvent;
use tokio::sync::{broadcast, watch};

use crate::error::BridgeError;
use crate::metrics::BridgeMetrics;
use crate::spool::{GapCause, Record, SpoolSet};
use crate::stream;

/// Runs until shutdown or `RecvError::Closed`.
///
/// `biased;` on the `select!` puts shutdown first so a draining daemon is never starved by a hot
/// broadcast — at 3,645 events/sec an unbiased select can leave the shutdown arm unpolled for a
/// long time.
pub async fn run(
    mut rx: broadcast::Receiver<RuntimeEvent>,
    mut spools: SpoolSet,
    metrics: BridgeMetrics,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), BridgeError> {
    loop {
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
                    stream::redact_in_place(&mut event);
                    let class = stream::classify(&event);
                    metrics.ingested(class);
                    // Target <= 2 ms. Page-cache write, no fsync (spool::segment fsyncs on roll).
                    spools.append(class, Record::from_event(&event))?;
                }

                // THE ONE CASE BOTH SHIPPED SUBSCRIBERS THROW AWAY.
                //
                // `swarm-ingest-runtime/src/ingest/demo.rs:1688-1691` (serving
                // GET /v1/events/stream) and `.../platform_api.rs:1387-1390` (serving
                // GET /v2/api/stream/findings) both write:
                //
                //     let Ok(event) = result else { return None; };
                //
                // and `rg 'Lagged|RecvError'` over `crates/` returns zero matches. A dropped
                // evidence event is unrecoverable: the relay never had it, the daemon does not
                // retain it, `/v1/events/stream` has no Last-Event-ID resumption
                // (`demo.rs:1703` sets `.id(emitted_at_ms)`, which collides at 10 Hz), and the
                // bridge holds no key with which to ask for it because it never saw the event.
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
                    spools.mark_gap_all_disk_spooled(GapCause::BroadcastLagged { count });
                }

                Err(broadcast::error::RecvError::Closed) => {
                    tracing::info!(module = module_path!(), "runtime event broadcast closed");
                    return Ok(());
                }
            },
        }
    }
}
