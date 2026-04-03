//! Stream processing runtime for Whisker agents.
//!
//! Whiskers operate as Flink-style streaming agents: long-running,
//! stateful, event-triggered. They subscribe to telemetry NATS subjects
//! and process events continuously.

// TODO: Implement streaming runtime
// - Subscribe to telemetry NATS subjects
// - Apply DetectionStrategy pipeline per event
// - Deposit pheromones on match
// - Maintain sliding window state for temporal correlation
