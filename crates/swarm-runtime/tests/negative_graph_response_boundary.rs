//! Mutation-proven authority boundary for collective reasoning modules.
//!
//! A hypothesis graph may rank simulation-only containment options. It cannot
//! import response execution, policy, governance, leases, receipts, dispatcher
//! admission, or any API that can turn a theory into a live action.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

const FORBIDDEN_CODE: &[&str] = &[
    "use swarm_response",
    "swarm_response::",
    "use swarm_policy",
    "swarm_policy::",
    "use swarm_governance",
    "swarm_governance::",
    "use swarm_consensus",
    "swarm_consensus::",
    "ResponseExecutor",
    "DispatchingExecutor",
    "CapabilityLease",
    "ContainmentLease",
    "GovernanceAuthority",
    "ActionRequest",
    "ResponseReceipt",
    "ResponseAction",
    "authorize_and_execute",
    "audit_rehearse_authorize_and_execute",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundaryViolation {
    path: PathBuf,
    token: &'static str,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("swarm-runtime has a crates parent")
        .parent()
        .expect("crates has a repository parent")
        .to_path_buf()
}

fn strip_comments_and_strings(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = vec![b' '; bytes.len()];
    let mut index = 0;
    let mut block_depth = 0_u32;
    let mut line_comment = false;
    let mut string = false;
    let mut escaped = false;
    let mut raw_hashes: Option<usize> = None;

    while index < bytes.len() {
        if line_comment {
            if bytes[index] == b'\n' {
                line_comment = false;
                output[index] = b'\n';
            }
            index += 1;
            continue;
        }
        if block_depth > 0 {
            if bytes.get(index..index + 2) == Some(b"/*") {
                block_depth += 1;
                index += 2;
            } else if bytes.get(index..index + 2) == Some(b"*/") {
                block_depth -= 1;
                index += 2;
            } else {
                if bytes[index] == b'\n' {
                    output[index] = b'\n';
                }
                index += 1;
            }
            continue;
        }
        if let Some(hash_count) = raw_hashes {
            if bytes[index] == b'"'
                && bytes
                    .get(index + 1..index + 1 + hash_count)
                    .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
            {
                index += 1 + hash_count;
                raw_hashes = None;
            } else {
                if bytes[index] == b'\n' {
                    output[index] = b'\n';
                }
                index += 1;
            }
            continue;
        }
        if string {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                string = false;
            } else if bytes[index] == b'\n' {
                output[index] = b'\n';
            }
            index += 1;
            continue;
        }
        if bytes.get(index..index + 2) == Some(b"//") {
            line_comment = true;
            index += 2;
            continue;
        }
        if bytes.get(index..index + 2) == Some(b"/*") {
            block_depth = 1;
            index += 2;
            continue;
        }
        if bytes[index] == b'r' {
            let mut cursor = index + 1;
            while bytes.get(cursor) == Some(&b'#') {
                cursor += 1;
            }
            if bytes.get(cursor) == Some(&b'"') {
                raw_hashes = Some(cursor - index - 1);
                index = cursor + 1;
                continue;
            }
        }
        if bytes[index] == b'"' {
            string = true;
            index += 1;
            continue;
        }
        output[index] = bytes[index];
        index += 1;
    }

    String::from_utf8(output).expect("source bytes remain valid UTF-8")
}

fn collect_rust_files(path: &Path, files: &mut Vec<PathBuf>) {
    if path.is_file() {
        if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path.to_path_buf());
        }
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        collect_rust_files(&entry.path(), files);
    }
}

fn scan_roots(roots: &[PathBuf]) -> Vec<BoundaryViolation> {
    let mut files = Vec::new();
    for root in roots {
        collect_rust_files(root, &mut files);
    }
    files.sort();
    files.dedup();

    let mut violations = Vec::new();
    for path in files {
        let source = fs::read_to_string(&path).expect("Rust source must be readable");
        let code = strip_comments_and_strings(&source);
        for token in FORBIDDEN_CODE {
            if code.contains(token) {
                violations.push(BoundaryViolation {
                    path: path.clone(),
                    token,
                });
            }
        }
    }
    violations
}

fn production_graph_roots() -> Vec<PathBuf> {
    let root = repo_root();
    vec![
        root.join("crates/swarm-core/src/hypothesis_graph.rs"),
        root.join("crates/swarm-spine/src/hypothesis_graph_store.rs"),
        root.join("crates/swarm-spine/src/strategy_memory.rs"),
        root.join("crates/swarm-runtime/src/hypothesis_graph"),
    ]
}

fn run_owned_temp_root() -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "ambush-cog-boundary-{}-{sequence}",
        std::process::id()
    ))
}

#[test]
fn boundary_checker_rejects_broken_fixture() {
    let temp_root = run_owned_temp_root();
    fs::create_dir(&temp_root).expect("run-owned fixture root must be created once");
    let clean = temp_root.join("clean.rs");
    let broken = temp_root.join("broken.rs");
    fs::write(
        &clean,
        r#"
        // use swarm_response::ResponseExecutor; comments do not grant authority.
        const DOCUMENTATION: &str = "ActionRequest ResponseReceipt";
        pub struct SimulationOnlyPlan;
        "#,
    )
    .unwrap();
    fs::write(
        &broken,
        "use swarm_response::ResponseExecutor;\npub struct Broken;\n",
    )
    .unwrap();

    let clean_result = scan_roots(std::slice::from_ref(&clean));
    assert!(
        clean_result.is_empty(),
        "clean fixture must pass lexical sanitization: {clean_result:?}"
    );
    let broken_result = scan_roots(std::slice::from_ref(&broken));
    assert!(
        broken_result.iter().any(|violation| {
            violation.token == "use swarm_response"
                || violation.token == "swarm_response::"
                || violation.token == "ResponseExecutor"
        }),
        "deliberately broken fixture must be rejected: {broken_result:?}"
    );

    fs::remove_dir_all(&temp_root).expect("run-owned fixture root must be removable");

    let production_result = scan_roots(&production_graph_roots());
    assert!(
        production_result.is_empty(),
        "collective reasoning imported live-action authority: {production_result:?}"
    );
}
