//! Tiny in-memory bounded dead-letter queue for failed SIEM exports.
//!
//! When a [`crate::SiemSink`] rejects a rendered batch, the payload is parked here. The queue is
//! bounded by `max_capacity`; when full, the oldest entry is dropped to make room and a dropped
//! counter is incremented. This prevents unbounded memory growth during a sustained sink outage
//! without depending on a logging facade.

use std::collections::VecDeque;

/// A rendered export payload that could not be delivered.
#[derive(Debug, Clone)]
pub struct FailedExport {
    /// Wire format the payload was rendered in (e.g. `"cef"`, `"ocsf-ndjson"`).
    pub format: String,
    /// The rendered batch body that failed to deliver.
    pub body: String,
    /// Human-readable description of the delivery error.
    pub error: String,
}

/// A bounded dead-letter queue for failed SIEM exports.
#[derive(Debug, Clone)]
pub struct DeadLetterQueue {
    inner: VecDeque<FailedExport>,
    max_capacity: usize,
    dropped: u64,
}

impl DeadLetterQueue {
    /// Default maximum capacity.
    pub const DEFAULT_CAPACITY: usize = 1000;

    /// Create a queue with the given maximum capacity.
    #[must_use]
    pub fn new(max_capacity: usize) -> Self {
        Self {
            inner: VecDeque::new(),
            max_capacity,
            dropped: 0,
        }
    }

    /// Push a failed export onto the queue.
    ///
    /// If the queue is at capacity, the oldest entry is dropped (and counted) before the new
    /// entry is inserted. A capacity of `0` drops every entry.
    pub fn push(&mut self, item: FailedExport) {
        if self.max_capacity == 0 {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        if self.inner.len() >= self.max_capacity && self.inner.pop_front().is_some() {
            self.dropped = self.dropped.saturating_add(1);
        }
        self.inner.push_back(item);
    }

    /// Current number of buffered entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Total number of entries dropped due to capacity pressure.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Drain all buffered entries.
    pub fn drain(&mut self) -> Vec<FailedExport> {
        self.inner.drain(..).collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn entry(tag: &str) -> FailedExport {
        FailedExport {
            format: "cef".to_string(),
            body: format!("body-{tag}"),
            error: "boom".to_string(),
        }
    }

    #[test]
    fn drops_oldest_when_over_capacity() {
        let mut dlq = DeadLetterQueue::new(2);
        dlq.push(entry("a"));
        dlq.push(entry("b"));
        dlq.push(entry("c"));

        assert_eq!(dlq.len(), 2);
        assert_eq!(dlq.dropped(), 1);
        let drained = dlq.drain();
        assert_eq!(drained[0].body, "body-b");
        assert_eq!(drained[1].body, "body-c");
        assert!(dlq.is_empty());
    }

    #[test]
    fn zero_capacity_drops_everything() {
        let mut dlq = DeadLetterQueue::new(0);
        dlq.push(entry("a"));
        assert!(dlq.is_empty());
        assert_eq!(dlq.dropped(), 1);
    }
}
