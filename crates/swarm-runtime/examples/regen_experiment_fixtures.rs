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
//! # Which fixtures
//!
//! This binary does NOT decide. It used to carry a hardcoded
//! `const FIXTURES: [&str; 3]`, which made the freshness gate see three named
//! files instead of the directory -- so a fourth, parser-rejected fixture
//! dropped into `experiments/` was invisible to it. That is the precise failure
//! mode FIXTURE-03 exists to prevent ("a 'sync generated artifacts' commit can
//! never again check in fixtures the parser rejects"), and the historic
//! incident `a840fd8` checked in 137 NEW files, none of which any such array
//! would have named.
//!
//! The caller passes the fixture list, and the single caller
//! (`tools/regen-kitten-fixtures.sh`) derives it from git, which is the
//! authority on what is actually committed.
//!
//! Usage:
//!   `cargo run -p swarm-runtime --example regen_experiment_fixtures -- <out-dir> <fixture>...`
//! where each `<fixture>` is a path relative to the repository root.

use std::error::Error;
use std::path::PathBuf;
use swarm_runtime::replay::DetectorExperimentManifest;

const USAGE: &str = "usage: cargo run -p swarm-runtime --example regen_experiment_fixtures -- \
<out-dir> <repo-relative-fixture-path>...";

fn repo_root() -> PathBuf {
    // `crates/swarm-runtime` -> `crates` -> repo root.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest_dir.parent().and_then(|crates| crates.parent()) {
        Some(root) => root.to_path_buf(),
        None => manifest_dir,
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let out_dir = match args.next() {
        Some(value) => PathBuf::from(value),
        None => return Err(USAGE.into()),
    };

    let fixtures: Vec<String> = args.collect();
    // An empty list is drift, not a no-op: the caller enumerates a directory
    // that is never legitimately empty, so "nothing to check" means the
    // enumeration broke and the gate would silently pass.
    if fixtures.is_empty() {
        return Err(format!("no fixtures given; {USAGE}").into());
    }

    let root = repo_root();
    std::fs::create_dir_all(&out_dir)?;

    for relative in &fixtures {
        let source = root.join(relative);
        let name = source
            .file_name()
            .ok_or_else(|| format!("{relative} has no file name"))?
            .to_owned();
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
