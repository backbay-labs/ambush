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
    "From<ContainmentSimulation>",
    "Into<ResponseAction>",
    "into_response",
    "to_response",
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

fn collect_rust_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    if path.is_file() {
        if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path.to_path_buf());
        }
        return Ok(());
    }
    if !path.is_dir() {
        return Err(format!(
            "mandated boundary root is missing: {}",
            path.display()
        ));
    }
    let entries = fs::read_dir(path)
        .map_err(|error| format!("cannot read boundary root {}: {error}", path.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!("cannot enumerate boundary root {}: {error}", path.display())
        })?;
        collect_rust_files(&entry.path(), files)?;
    }
    Ok(())
}

fn scan_roots(roots: &[PathBuf]) -> Result<Vec<BoundaryViolation>, String> {
    if roots.is_empty() {
        return Err("boundary scanner requires a non-empty root inventory".to_string());
    }
    let mut files = Vec::new();
    for root in roots {
        collect_rust_files(root, &mut files)?;
    }
    files.sort();
    files.dedup();
    if files.is_empty() {
        return Err("boundary scanner found no Rust files in its root inventory".to_string());
    }

    let mut violations = Vec::new();
    for path in files {
        let source = fs::read_to_string(&path).map_err(|error| {
            format!(
                "cannot read scanned Rust source {}: {error}",
                path.display()
            )
        })?;
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
    Ok(violations)
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

    let clean_result =
        scan_roots(std::slice::from_ref(&clean)).expect("clean fixture root must scan");
    assert!(
        clean_result.is_empty(),
        "clean fixture must pass lexical sanitization: {clean_result:?}"
    );
    let broken_result =
        scan_roots(std::slice::from_ref(&broken)).expect("broken fixture root must scan");
    assert!(
        broken_result.iter().any(|violation| {
            violation.token == "use swarm_response"
                || violation.token == "swarm_response::"
                || violation.token == "ResponseExecutor"
        }),
        "deliberately broken fixture must be rejected: {broken_result:?}"
    );

    fs::remove_dir_all(&temp_root).expect("run-owned fixture root must be removable");

    let production_result = scan_roots(&production_graph_roots())
        .expect("mandated production roots must exist and be readable");
    assert!(
        production_result.is_empty(),
        "collective reasoning imported live-action authority: {production_result:?}"
    );
}

#[test]
fn boundary_scanner_fails_closed_for_missing_or_unreadable_roots() {
    let temp_root = run_owned_temp_root();
    fs::create_dir(&temp_root).expect("run-owned fixture root must be created once");
    assert!(
        scan_roots(&[]).is_err(),
        "an empty mandated root slice must fail closed"
    );
    let empty_directory = temp_root.join("empty");
    fs::create_dir(&empty_directory).expect("empty directory fixture must be created");
    assert!(
        scan_roots(std::slice::from_ref(&empty_directory)).is_err(),
        "an empty mandated directory must fail closed"
    );
    let missing = temp_root.join("missing");
    assert!(
        scan_roots(std::slice::from_ref(&missing)).is_err(),
        "a deleted mandated root must fail closed"
    );

    let unreadable = temp_root.join("invalid-utf8.rs");
    fs::write(&unreadable, [0xff, 0xfe]).expect("unreadable fixture must be writable");
    assert!(
        scan_roots(std::slice::from_ref(&unreadable)).is_err(),
        "an unreadable mandated source must fail closed"
    );
    fs::remove_dir_all(&temp_root).expect("run-owned fixture root must be removable");
}

#[test]
fn production_boundary_root_inventory_is_exact_and_nonempty() {
    let roots = production_graph_roots();
    assert_eq!(
        roots,
        vec![
            repo_root().join("crates/swarm-core/src/hypothesis_graph.rs"),
            repo_root().join("crates/swarm-spine/src/hypothesis_graph_store.rs"),
            repo_root().join("crates/swarm-spine/src/strategy_memory.rs"),
            repo_root().join("crates/swarm-runtime/src/hypothesis_graph"),
        ]
    );
    assert!(!roots.is_empty());
    let files = scan_roots(&roots).expect("exact production roots must scan");
    assert!(files.is_empty(), "production roots must be authority-clean");
}

#[test]
fn containment_core_option_mutations_fail_closed() {
    let target = swarm_core::hypothesis_graph::GraphNodeId::new("node:real");
    let mut score_mutation = swarm_core::hypothesis_graph::ContainmentOption::new(
        swarm_core::hypothesis_graph::ContainmentOptionKind::IsolateAsset,
        [target.clone()],
        100,
        9_000,
        8_000,
        swarm_core::hypothesis_graph::ApprovalClass::Analyst,
        true,
    )
    .expect("the control option must be valid");
    score_mutation.predicted_blast_radius_basis_points = 101;
    assert!(
        score_mutation.validate().is_err(),
        "a score mutation with the original option ID must fail"
    );

    let mut kind_mutation = swarm_core::hypothesis_graph::ContainmentOption::new(
        swarm_core::hypothesis_graph::ContainmentOptionKind::IsolateAsset,
        [target.clone()],
        100,
        9_000,
        8_000,
        swarm_core::hypothesis_graph::ApprovalClass::Analyst,
        true,
    )
    .expect("the control option must be valid");
    kind_mutation.kind = swarm_core::hypothesis_graph::ContainmentOptionKind::RestrictNetwork;
    assert!(
        kind_mutation.validate().is_err(),
        "an option-kind translation must fail"
    );

    let mut target_mutation = swarm_core::hypothesis_graph::ContainmentOption::new(
        swarm_core::hypothesis_graph::ContainmentOptionKind::IsolateAsset,
        [target],
        100,
        9_000,
        8_000,
        swarm_core::hypothesis_graph::ApprovalClass::Analyst,
        true,
    )
    .expect("the control option must be valid");
    target_mutation.target_node_ids =
        std::collections::BTreeSet::from([swarm_core::hypothesis_graph::GraphNodeId::new(
            "node:synthetic",
        )]);
    assert!(
        target_mutation.validate().is_err(),
        "a target translation must fail"
    );
}

#[test]
fn boundary_checker_rejects_direct_response_conversion_fixture() {
    let temp_root = run_owned_temp_root();
    fs::create_dir(&temp_root).expect("run-owned fixture root must be created once");
    let broken = temp_root.join("broken-conversion.rs");
    fs::write(
        &broken,
        "impl From<ContainmentSimulation> for ResponseAction { fn from(_: ContainmentSimulation) -> Self { todo!() } }\n",
    )
    .expect("broken conversion fixture must be writable");

    let result =
        scan_roots(std::slice::from_ref(&broken)).expect("broken conversion root must scan");
    assert!(
        result.iter().any(|violation| {
            violation.token == "From<ContainmentSimulation>" || violation.token == "ResponseAction"
        }),
        "direct response conversion must be rejected: {result:?}"
    );
    fs::remove_dir_all(&temp_root).expect("run-owned fixture root must be removable");
}
