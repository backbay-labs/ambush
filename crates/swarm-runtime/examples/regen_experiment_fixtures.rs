//! Regenerate the repo-owned detector experiment fixtures through the compiled
//! `DetectorExperimentManifest` schema.
//!
//! The "pinned schema version" is the compiled `DetectorExperimentManifest` at
//! the commit under test. There is no `schema_version` marker in the manifest
//! type, and the type is `#[serde(deny_unknown_fields)]`, so one could not be
//! added to the fixtures without a production schema change. Deserializing
//! through that type IS the schema pin: a fixture carrying a field the current
//! detector types do not accept fails here rather than at test time -- which is
//! exactly the drift that removed 137 fixtures in `e93d521`.
//!
//! Re-serializing normalizes the fixture to the canonical `serde_yaml` rendering
//! of the parsed value, so `tools/check-fixture-freshness.sh` can diff a
//! regeneration against the committed bytes.
//!
//! Usage: `cargo run -p swarm-runtime --example regen_experiment_fixtures -- <out-dir>`

use std::error::Error;
use std::path::PathBuf;
use swarm_runtime::replay::DetectorExperimentManifest;

/// Every `experiments/*.yaml` reachable from a `swarm-runtime` test.
///
/// Measured with:
/// `grep -rn 'join("experiments' crates/swarm-runtime/src | grep -o 'experiments/[a-z-]*\.yaml' | sort -u`
const FIXTURES: [&str; 3] = [
    "office-baseline-control.yaml",
    "office-conservative-control.yaml",
    "office-python-parent-broadening.yaml",
];

fn repo_root() -> PathBuf {
    // `crates/swarm-runtime` -> `crates` -> repo root.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest_dir.parent().and_then(|crates| crates.parent()) {
        Some(root) => root.to_path_buf(),
        None => manifest_dir,
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let out_dir = match std::env::args().nth(1) {
        Some(value) => PathBuf::from(value),
        None => {
            return Err(
                "usage: cargo run -p swarm-runtime --example regen_experiment_fixtures -- <out-dir>"
                    .into(),
            );
        }
    };

    let source_dir = repo_root().join("experiments");
    std::fs::create_dir_all(&out_dir)?;

    for name in FIXTURES {
        let source = source_dir.join(name);
        let raw = std::fs::read_to_string(&source)
            .map_err(|error| format!("failed to read {}: {error}", source.display()))?;
        // The schema gate. `DetectorExperimentManifest` is
        // `#[serde(deny_unknown_fields)]`, so a fixture carrying a field the
        // current detector types no longer accept fails HERE.
        let _validated: DetectorExperimentManifest =
            serde_yaml::from_str(&raw).map_err(|error| {
                format!(
                    "{} does not match the current schema: {error}",
                    source.display()
                )
            })?;

        // The canonical form is rendered from the YAML VALUE, not from the typed
        // struct. Serializing the struct would materialize every
        // `#[serde(default)]` field the author deliberately omitted -- including
        // `candidate.profile.command_line_normalization`, whose absence from
        // these fixtures FIXTURE-02 asserts. Value round-tripping normalizes
        // formatting (indentation, key quoting) and nothing else.
        let value: serde_yaml::Value = serde_yaml::from_str(&raw)?;
        let rendered = serde_yaml::to_string(&value)?;
        std::fs::write(out_dir.join(name), rendered)?;
    }

    Ok(())
}
