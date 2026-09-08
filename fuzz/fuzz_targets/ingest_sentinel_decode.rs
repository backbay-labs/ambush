//! Phase 287 FUZZ-01: the untrusted Sentinel (Prometheus text-exposition)
//! telemetry-parse boundary.
//!
//! `SentinelBridge::poll` (`crates/swarm-ingest-sentinel/src/lib.rs`) scrapes
//! an HTTP endpoint and hands the raw response body to `parse_prometheus_text`
//! -- a private, hand-rolled parser for the Prometheus text-exposition format
//! (metric name, optional `{label="value",...}` set, a float value, one
//! sample per line, `#`-comments and blank lines skipped). That function
//! itself is not `pub` (its `ScrapedMetrics` return type is crate-private, and
//! leaking a private type through a public signature is denied by this
//! workspace's `-D warnings` clippy gate), so
//! `swarm_ingest_sentinel::parse_prometheus_text_for_fuzz` is the exposed
//! entry point: it calls the exact same production parser and only erases
//! the success type. Re-verified at HEAD.
//!
//! An `Err(String)` (bad token, non-numeric value, unterminated label set, no
//! samples at all) is an expected, ordinary rejection. Only a panic or other
//! UB is a finding.
#![no_main]

use libfuzzer_sys::fuzz_target;
use swarm_ingest_sentinel::parse_prometheus_text_for_fuzz;

fuzz_target!(|data: &[u8]| {
    // The real call site reads the scrape body via `reqwest::Response::text`,
    // which already requires valid UTF-8 (or lossy-decodes it) before this
    // parser ever sees a `&str`; invalid UTF-8 never reaches
    // `parse_prometheus_text` in production.
    let Ok(body) = std::str::from_utf8(data) else {
        return;
    };

    let _ = parse_prometheus_text_for_fuzz(body);
});
