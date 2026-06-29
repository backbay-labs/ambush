// Adapted from ClawdStrike/Arc (Apache-2.0)
//! Shared library for the Ambush engine fuzz crate. Re-exports the
//! structure-aware canonical-JSON mutator so `fuzz_targets/*.rs` binaries can
//! import it as `swarm_fuzz::canonical_json::canonical_json_mutate`.

#[path = "../mutators/canonical_json.rs"]
pub mod canonical_json;
