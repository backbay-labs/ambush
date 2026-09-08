//! Phase 287 FUZZ-01: the untrusted JSON telemetry-parse boundary.
//!
//! Calls the REAL entry point untrusted JSON telemetry bytes hit first:
//! `swarm_ingest_json::JsonRecordSource::from_str` (re-exported from
//! `crates/swarm-ingest-json/src/source.rs`, verified at HEAD). It accepts a
//! JSON object, a JSON array of objects, or a JSON-Lines stream of objects
//! and queues each as an untyped record for a bridge's field-mapping layer
//! to consume later; that later mapping step needs a `FieldMappingConfig`
//! this fuzz target does not have, so this harness stops at the boundary
//! that is actually shared by every JSON-sourced bridge (auditd, sysmon,
//! CloudTrail, Kubernetes audit, generic_json): turning arbitrary bytes into
//! a `VecDeque<serde_json::Value>` without panicking.
//!
//! A decode/parse error is `Err(JsonRecordSourceError)` and is expected,
//! frequent, and fine -- `JsonRecordSource::from_str` returns it rather than
//! panicking. Only a panic or other UB is a finding.
#![no_main]

use libfuzzer_sys::fuzz_target;
use swarm_ingest_json::JsonRecordSource;

fuzz_target!(|data: &[u8]| {
    // The real call sites (`JsonRecordSource::from_path` -> `fs::read_to_string`)
    // only ever hand `from_str` a value that already survived a UTF-8 read;
    // invalid UTF-8 never reaches this parser in production, so treat it the
    // same way a real caller would and skip rather than force a lossy
    // conversion the decoder was never asked to handle.
    let Ok(body) = std::str::from_utf8(data) else {
        return;
    };

    // Ok(_): parsed to at least one JSON object, queued for later mapping.
    // Err(_): malformed JSON, a non-object top level, or an empty stream --
    // all real, expected rejections. Either way, no panic.
    let _ = JsonRecordSource::from_str("fuzz", body);
});
