//! Wave 0 corpus contract for the collective hypothesis graph benchmark.
//!
//! The first test is intentionally small: the adjudicated corpus must exist
//! before any graph implementation can make the benchmark appear green.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("swarm-runtime has a workspace parent")
        .parent()
        .expect("workspace has a repository parent")
        .to_path_buf()
}

#[test]
fn benchmark_manifest_is_strict() {
    let path = repo_root().join("scenarios/collective-hypothesis-graph/manifest.yaml");
    assert!(
        path.is_file(),
        "the independent collective-hypothesis-graph manifest must exist at {}",
        path.display()
    );
}
