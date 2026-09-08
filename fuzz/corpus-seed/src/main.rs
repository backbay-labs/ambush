//! Phase 287 FUZZ-02: converts `scenarios/*.yaml` and `rulesets/*.yaml` into
//! each fuzz target's real wire format and writes the result into that
//! target's `fuzz/corpus/<target>/` directory.
//!
//! Run via `tools/seed-fuzz-corpus.sh`, never directly -- see that script for
//! the invocation this binary expects (it passes no arguments; the fixture
//! and corpus paths below are derived from `CARGO_MANIFEST_DIR`, which
//! `cargo run` sets to this crate's own directory regardless of the caller's
//! working directory).
//!
//! Per-target conversion, and why:
//!
//! - `ruleset_yaml_parse`: every fixture, copied byte-for-byte. Raw YAML text
//!   IS this target's wire format (`swarm_runtime::config::parse_config_unresolved`
//!   takes a `&str` of YAML directly) -- a scenario fixture that does not
//!   happen to satisfy `SwarmConfig`'s schema is still a real YAML document
//!   the parser must survive, not an invalid conversion.
//! - `ingest_json_decode`: each scenario event (`input.events[*].event`) is
//!   already exactly a `TelemetryEvent` in YAML; re-serialized to JSON, that
//!   IS a JSON event body, matching `JsonRecordSource::from_str`'s expected
//!   input verbatim.
//! - `ingest_sentinel_decode`: no fixture contains Prometheus text-exposition
//!   data (no scenario carries a `sentinel`-shaped payload; see phase 287
//!   Task B's re-verification). Each scenario event instead contributes one
//!   synthetic-but-syntactically-real exposition sample, parameterized by
//!   that event's own `host_id` and `timestamp` (deterministic, no RNG) so
//!   the corpus still has one entry per fixture rather than one fixed blob
//!   repeated.
//! - `ingest_tetragon_decode`: each scenario event whose payload is a real
//!   `process_start` is encoded as a `GetEventsResponse { event: Some(
//!   ProcessExec(..)) }` protobuf message via the SAME `prost` derive the
//!   production decoder decodes with, so the corpus contains genuinely
//!   valid wire-format seeds, not a hand-built byte pattern.
use std::fs;
use std::path::{Path, PathBuf};

use prost::Message;
use prost_types::Timestamp;
use serde_yaml::Value as YamlValue;
use swarm_ingest_tetragon::client::proto;

fn main() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fuzz_dir = manifest_dir
        .parent()
        .expect("fuzz/corpus-seed always has a parent directory (fuzz/)");
    let repo_root = fuzz_dir
        .parent()
        .expect("fuzz/ always has a parent directory (the repo root)");

    let mut fixtures = yaml_files_in(&repo_root.join("scenarios"));
    fixtures.extend(yaml_files_in(&repo_root.join("rulesets")));
    fixtures.sort();

    if fixtures.is_empty() {
        eprintln!(
            "no scenarios/*.yaml or rulesets/*.yaml fixtures found under {}; refusing to seed an empty corpus silently",
            repo_root.display()
        );
        std::process::exit(1);
    }

    let json_dir = corpus_dir(fuzz_dir, "ingest_json_decode");
    let sentinel_dir = corpus_dir(fuzz_dir, "ingest_sentinel_decode");
    let tetragon_dir = corpus_dir(fuzz_dir, "ingest_tetragon_decode");
    let ruleset_dir = corpus_dir(fuzz_dir, "ruleset_yaml_parse");

    let mut json_count = 0usize;
    let mut sentinel_count = 0usize;
    let mut tetragon_count = 0usize;
    let mut ruleset_count = 0usize;

    for path in &fixtures {
        let raw = fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("failed to read fixture {}: {error}", path.display()));
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("fixture");

        // ruleset_yaml_parse: raw YAML text is the wire format, full stop.
        write_corpus_entry(&ruleset_dir, &format!("{stem}.yaml"), raw.as_bytes());
        ruleset_count += 1;

        let Ok(doc) = serde_yaml::from_str::<YamlValue>(&raw) else {
            // Not valid YAML at all -- still seeded above (a parser must
            // survive malformed YAML too), nothing further to convert.
            continue;
        };

        for (index, event) in scenario_events(&doc).into_iter().enumerate() {
            if let Some(body) = telemetry_event_json(&event) {
                write_corpus_entry(&json_dir, &format!("{stem}-event-{index}.json"), &body);
                json_count += 1;
            }

            write_corpus_entry(
                &sentinel_dir,
                &format!("{stem}-event-{index}.prom"),
                telemetry_event_prometheus(&event).as_bytes(),
            );
            sentinel_count += 1;

            if let Some(body) = telemetry_event_tetragon(&event) {
                write_corpus_entry(&tetragon_dir, &format!("{stem}-event-{index}.pb"), &body);
                tetragon_count += 1;
            }
        }
    }

    println!("fixtures scanned: {}", fixtures.len());
    println!("ingest_json_decode: {json_count} corpus entries");
    println!("ingest_sentinel_decode: {sentinel_count} corpus entries");
    println!("ingest_tetragon_decode: {tetragon_count} corpus entries");
    println!("ruleset_yaml_parse: {ruleset_count} corpus entries");
}

/// Non-recursive `*.yaml` listing, matching the shell glob `dir/*.yaml` the
/// requirement (FUZZ-02) names -- `rulesets/evasion/*.yaml` and
/// `rulesets/safety/*.yaml` are deliberately excluded, same as the glob.
fn yaml_files_in(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "yaml"))
        .collect();
    files.sort();
    files
}

fn corpus_dir(fuzz_dir: &Path, target: &str) -> PathBuf {
    let dir = fuzz_dir.join("corpus").join(target);
    fs::create_dir_all(&dir)
        .unwrap_or_else(|error| panic!("failed to create corpus dir {}: {error}", dir.display()));
    dir
}

fn write_corpus_entry(dir: &Path, name: &str, body: &[u8]) {
    let path = dir.join(name);
    fs::write(&path, body)
        .unwrap_or_else(|error| panic!("failed to write corpus entry {}: {error}", path.display()));
}

/// Extracts `input.events[*].event` -- the `TelemetryEvent`-shaped YAML
/// sub-document each scenario fixture carries per event. Rulesets carry no
/// `input.events`, so this returns empty for them without treating that as
/// an error.
fn scenario_events(doc: &YamlValue) -> Vec<YamlValue> {
    let Some(events) = doc
        .get("input")
        .and_then(|input| input.get("events"))
        .and_then(YamlValue::as_sequence)
    else {
        return Vec::new();
    };

    events
        .iter()
        .filter_map(|item| item.get("event").cloned())
        .collect()
}

/// A scenario event is already exactly a `TelemetryEvent` in YAML form; this
/// only changes encoding (YAML -> JSON), not shape, so it round-trips through
/// `serde_yaml::Value`'s `Serialize` impl into `serde_json::Value` and back
/// out as bytes -- matching `JsonRecordSource::from_str`'s expected input.
fn telemetry_event_json(event: &YamlValue) -> Option<Vec<u8>> {
    let as_json: serde_json::Value = serde_json::to_value(event).ok()?;
    serde_json::to_vec(&as_json).ok()
}

/// Synthesizes one Prometheus text-exposition sample from a scenario event's
/// own (deterministic) fields -- no fixture actually carries this wire
/// format, so this is a derived-but-real sample of the grammar
/// `parse_prometheus_text` accepts: a `# HELP`/`# TYPE` comment pair, a
/// blank line, labeled and unlabeled samples, an integer and a float value.
fn telemetry_event_prometheus(event: &YamlValue) -> String {
    let node = event
        .get("host_id")
        .and_then(YamlValue::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("fuzz-seed-node");
    let node = sanitize_label_value(node);
    let timestamp = event
        .get("timestamp")
        .and_then(YamlValue::as_i64)
        .unwrap_or(0);
    let cpu_percent = (timestamp.rem_euclid(100)) as f64 + 0.5;
    let rx_bytes = timestamp.rem_euclid(1_000_000).unsigned_abs();

    format!(
        "# HELP sentinel_cpu_usage_percent CPU utilization percent\n\
         # TYPE sentinel_cpu_usage_percent gauge\n\
         \n\
         sentinel_cpu_usage_percent{{node=\"{node}\"}} {cpu_percent}\n\
         sentinel_memory_usage_percent{{node=\"{node}\",instance=\"{node}:9100\"}} 61\n\
         sentinel_disk_usage_percent{{node=\"{node}\"}} 30\n\
         sentinel_network_rx_bytes_total{{node=\"{node}\"}} {rx_bytes}\n\
         sentinel_cpu_temperature_celsius{{node=\"{node}\"}} 55.5\n"
    )
}

fn sanitize_label_value(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch == '"' || ch == '\\' { '_' } else { ch })
        .collect()
}

/// Encodes a `process_start` scenario event as a real
/// `GetEventsResponse { event: Some(ProcessExec(..)) }` message, the exact
/// shape `ingest_tetragon_decode` decodes. Returns `None` for every other
/// payload kind (DNS, network, registry, ...): those have no Tetragon
/// `ProcessExec` analog to convert into, and inventing one would not be a
/// conversion of the fixture, just an unrelated fabricated seed.
fn telemetry_event_tetragon(event: &YamlValue) -> Option<Vec<u8>> {
    let payload = event.get("payload")?;
    if payload.get("kind").and_then(YamlValue::as_str) != Some("process_start") {
        return None;
    }

    let process_name = payload.get("process_name").and_then(YamlValue::as_str)?;
    let command_line = payload
        .get("command_line")
        .and_then(YamlValue::as_str)
        .unwrap_or(process_name);
    let parent_process = payload.get("parent_process").and_then(YamlValue::as_str);
    let user = payload.get("user").and_then(YamlValue::as_str);
    let event_id = event
        .get("event_id")
        .and_then(YamlValue::as_str)
        .unwrap_or("fuzz-seed-event");
    let host_id = event
        .get("host_id")
        .and_then(YamlValue::as_str)
        .unwrap_or_default();
    let timestamp = event.get("timestamp").and_then(YamlValue::as_i64);

    let process = proto::Process {
        exec_id: event_id.to_string(),
        binary: process_name.to_string(),
        arguments: command_line.to_string(),
        uid: user.and_then(|value| value.parse::<u32>().ok()),
        start_time: timestamp.map(|seconds| Timestamp {
            // Scenario timestamps are milliseconds since the epoch;
            // Tetragon's `start_time` is a `google.protobuf.Timestamp`
            // (seconds + nanos), same conversion `mapper.rs` assumes.
            seconds: seconds / 1000,
            nanos: 0,
        }),
        ..Default::default()
    };

    let parent = parent_process.map(|binary| proto::Process {
        binary: binary.to_string(),
        ..Default::default()
    });

    let response = proto::GetEventsResponse {
        node_name: host_id.to_string(),
        event: Some(proto::get_events_response::Event::ProcessExec(
            proto::ProcessExec {
                process: Some(process),
                parent,
                ancestors: Vec::new(),
            },
        )),
        ..Default::default()
    };

    Some(response.encode_to_vec())
}
