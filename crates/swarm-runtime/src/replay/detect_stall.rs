//! TEST-ONLY SEAM. Compiled out of every non-test build by `#[cfg(test)]` on the
//! module declaration in `replay/mod.rs`.
//!
//! Why this exists: the load-differential regression test has to run the *real*
//! verification path twice over identical inputs and make the detect stage
//! genuinely slow on the second pass, so that the real measurement code
//! (`Instant::now()` .. `elapsed()` in `service::runtime_service`) records a
//! wall-clock delta far past the corpus latency budget. Nothing about the
//! candidate, the corpus, or the scenarios changes -- only how long the detect
//! stage takes.
//!
//! It is deliberately NOT a hook inside the live critical lane. The stall is a
//! decorator around the candidate detector that the offline replay harness
//! substitutes for itself in `run_loaded_scenario`; `RuntimeDetector`,
//! `detection::pipeline`, and `service::runtime_service` are untouched.
//!
//! `RuntimeDetector` is cheap to clone and its stateful variants keep their
//! state behind `Arc<Mutex<_>>` / `Arc<RwLock<_>>`, so the clone held here
//! shares detector state with the original rather than forking it. `as_any`
//! delegates to the inner detector so the pipeline's
//! `downcast_ref::<RuntimeDetector>()` hydration/persistence hooks still fire.

use crate::detector_factory::RuntimeDetector;
use std::cell::Cell;
use std::time::Duration;
use swarm_whisker::{DetectionFinding, DetectionStrategy, TelemetryEvent};

thread_local! {
    static REMAINING: Cell<u32> = const { Cell::new(0) };
    static STALL: Cell<Duration> = const { Cell::new(Duration::ZERO) };
}

/// Arms the detect-stage stall for the current thread and disarms it on drop.
///
/// `#[tokio::test]` runs on a current-thread runtime, so the harness executes
/// on the same thread that armed the guard, and the thread-local keeps the
/// stall from leaking into any other test.
pub(crate) struct DetectStallGuard;

impl DetectStallGuard {
    /// The next `count` detect-stage evaluations on this thread sleep for
    /// `stall` before delegating to the real detector.
    pub(crate) fn arm(count: u32, stall: Duration) -> Self {
        REMAINING.with(|remaining| remaining.set(count));
        STALL.with(|configured| configured.set(stall));
        Self
    }
}

impl Drop for DetectStallGuard {
    fn drop(&mut self) {
        REMAINING.with(|remaining| remaining.set(0));
        STALL.with(|configured| configured.set(Duration::ZERO));
    }
}

fn take_stall() -> Option<Duration> {
    REMAINING.with(|remaining| {
        let left = remaining.get();
        if left == 0 {
            return None;
        }
        remaining.set(left - 1);
        Some(STALL.with(|configured| configured.get()))
    })
}

/// Delegating detector that burns wall-clock time inside the detect stage when
/// a `DetectStallGuard` is armed. Behaviourally identical to the wrapped
/// detector in every other respect.
#[derive(Debug)]
pub(crate) struct StallingDetector {
    inner: RuntimeDetector,
}

impl StallingDetector {
    pub(crate) fn new(inner: RuntimeDetector) -> Self {
        Self { inner }
    }
}

impl DetectionStrategy for StallingDetector {
    fn as_any(&self) -> &dyn std::any::Any {
        self.inner.as_any()
    }

    fn id(&self) -> &str {
        self.inner.id()
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        if let Some(stall) = take_stall() {
            std::thread::sleep(stall);
        }
        self.inner.evaluate(event)
    }
}
