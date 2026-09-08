//! Phase 287 FUZZ-01: the untrusted ruleset (repository-owned runtime
//! config) YAML-parse boundary.
//!
//! `swarm_runtime::config::parse_config_unresolved` is the real ruleset
//! loader body: YAML deserialize into `YamlValue`, schema migration
//! (`migrate_config_value`), deserialize into `SwarmConfig`, then structural
//! and detector-profile validation -- the exact sequence
//! `load_config_unresolved` runs after it reads a file, minus the file I/O
//! and Ed25519 signature check. Re-verified at HEAD (`crates/swarm-runtime/
//! src/config.rs`); it was made `pub` for this fuzz target (previously
//! private to the module, called only by `load_config_unresolved` -- a
//! visibility widening, not a behaviour change: same body, same call graph).
//!
//! Deliberately NOT `parse_config`/`load_config`: those additionally call
//! `resolve_outbound_secrets`, which walks `@secret:` string references
//! against `secret_dir` on the real filesystem and against environment
//! variables. Fuzzing that path would make the harness's behaviour depend on
//! the machine it runs on (secrets present or absent, `secret_dir` set or
//! not) rather than purely on the input bytes, and risks resolving into
//! whatever the fuzzing host happens to have on disk. `rulesets/default.yaml`
//! documents the exact same `@secret:file-name` shape this parse path
//! accepts as an untouched literal string.
//!
//! An `Err(RuntimeConfigError)` (malformed YAML, an unknown field under
//! `#[serde(deny_unknown_fields)]`, a failed migration, or a structural/
//! detector-profile validation failure) is an expected, frequent rejection.
//! Only a panic or other UB is a finding.
#![no_main]

use libfuzzer_sys::fuzz_target;
use swarm_runtime::config::parse_config_unresolved;

fuzz_target!(|data: &[u8]| {
    let Ok(yaml) = std::str::from_utf8(data) else {
        return;
    };

    let _ = parse_config_unresolved(yaml, "fuzz".to_string());
});
