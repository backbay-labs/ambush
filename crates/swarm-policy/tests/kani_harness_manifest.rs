//! KANI-04: the Kani harness manifest lists every `#[kani::proof]` and nothing
//! else.
//!
//! This runs in the NORMAL `cargo test` lane — it needs no Kani. It reads the
//! harness source and `formal/kani/swarm-policy-harnesses.toml` as TEXT (via
//! `include_str!`, so it sees the `#[cfg(kani)]`-gated module's source even in
//! an ordinary build) and fails the build if the set of `#[kani::proof]`
//! functions and the set of manifest `name = "…"` rows differ in either
//! direction: a harness added without a manifest row, or a row whose harness was
//! renamed or removed. That is the KANI-04 guard against silent drift between
//! the proofs and the runner's work-list.
//!
//! It is deliberately a small text scanner, not a TOML/`syn` parser, so it adds
//! no dependency to `swarm-policy` (the decision-core boundary gate forbids one)
//! and cannot itself drag a crate into the TCB graph.

const HARNESS_SRC: &str = include_str!("../src/kani_public_harnesses.rs");
const MANIFEST: &str = include_str!("../../../formal/kani/swarm-policy-harnesses.toml");

/// Every `#[kani::proof]` function name in the harness source, in sorted order.
/// A proof is a `fn …(` whose nearest preceding attribute run contains
/// `#[kani::proof]` (an optional `#[kani::unwind(N)]` may sit between them).
fn proofs_in_source() -> Vec<String> {
    let mut names = Vec::new();
    let mut pending_proof = false;
    for line in HARNESS_SRC.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("#[kani::proof]") {
            pending_proof = true;
        } else if pending_proof && trimmed.starts_with("fn ") {
            let name = trimmed
                .trim_start_matches("fn ")
                .split('(')
                .next()
                .unwrap_or("")
                .trim();
            if !name.is_empty() {
                names.push(name.to_string());
            }
            pending_proof = false;
        }
    }
    names.sort();
    names
}

/// Every `name = "…"` value in the manifest, in sorted order.
fn names_in_manifest() -> Vec<String> {
    let mut names = Vec::new();
    for line in MANIFEST.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("name = \"")
            && let Some(name) = rest.strip_suffix('"')
        {
            names.push(name.to_string());
        }
    }
    names.sort();
    names
}

#[test]
fn every_kani_proof_is_listed_in_the_manifest_exactly_once() {
    let proofs = proofs_in_source();
    let manifest = names_in_manifest();

    assert!(
        !proofs.is_empty(),
        "no #[kani::proof] harness found in the source — the scanner is broken, \
         not the manifest"
    );

    // Every proof has a manifest row.
    for proof in &proofs {
        assert!(
            manifest.contains(proof),
            "kani harness `{proof}` has no row in \
             formal/kani/swarm-policy-harnesses.toml (KANI-04): add it, with its \
             lane and property, so scripts/run-kani-swarm-policy.sh runs it."
        );
    }

    // Every manifest row names a real proof.
    for entry in &manifest {
        assert!(
            proofs.contains(entry),
            "formal/kani/swarm-policy-harnesses.toml lists `{entry}` but no \
             #[kani::proof] fn by that name exists (KANI-04): it was renamed or \
             removed — update the manifest."
        );
    }

    // No duplicate rows, and the two sets are identical.
    let mut deduped = manifest.clone();
    deduped.dedup();
    assert_eq!(
        deduped, manifest,
        "duplicate harness rows in formal/kani/swarm-policy-harnesses.toml"
    );
    assert_eq!(
        proofs, manifest,
        "the #[kani::proof] set and the manifest disagree"
    );
}
