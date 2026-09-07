//! ARMSCI-02 / ARMSCI-03: the Rust-side companion to
//! `tools/check-red-swarm-no-execution-authority.sh`.
//!
//! WHAT THE SHELL GATE DOES
//!   That script scans the red lane's own source -- everything under
//!   `crates/swarm-runtime/src/red_swarm/` plus `crates/swarm-cli/src/
//!   red_swarm_cmd.rs` -- for four names this codebase treats as
//!   response-authority symbols: `execute_response`, `ResponseAdapter`,
//!   `PolicyDecision::Authorize`, and `live_response`. Phase 291's isolation
//!   claim is structural, not aspirational: the red lane generates
//!   adversarial telemetry and scores detectors (phases 288-290), and it
//!   must never grow a path to response authority, so a name from that list
//!   appearing anywhere in its source is a build failure, not a review note.
//!
//! WHY A SECOND, INDEPENDENT IMPLEMENTATION
//!   One check is one point of failure: if the shell script is ever
//!   skipped, miswired, or quietly broken, nothing else notices. This module
//!   runs the SAME rule over the SAME two source locations at `cargo test`
//!   time, from inside the crate the gate protects, so `cargo test -p
//!   swarm-runtime` alone still catches a violation even if the CI step
//!   never ran. The two implementations are independent code -- one bash,
//!   one Rust -- sharing one rule: strip pure `//`/`//!`/`///` comment
//!   lines, then look for the four names as plain substrings in what is
//!   left. Compare [`forbidden_symbol_in_text`] below with that script's
//!   `scan_forbidden_symbols`.
//!
//! WHY COMMENTS ARE EXCLUDED
//!   `pattern_db.rs`'s module doc says, in prose, that nothing in that file
//!   resolves to these names -- a true claim about its imports and call
//!   graph, expressible only by naming the very symbols it says are absent.
//!   A comment does not compile and cannot reach response authority, so
//!   [`is_pure_comment_line`] excludes it before the forbidden-name check
//!   runs. It is a per-line rule, not a tokenizer: a forbidden name arriving
//!   as a trailing comment after real code on the same line is still
//!   (deliberately, conservatively) scanned.
//!
//! WHY THIS FILE IS EXCLUDED FROM ITS OWN SCAN
//!   ARMSCI-03 needs a counterexample that WOULD trip the gate, to prove the
//!   check is not vacuous -- and [`FORBIDDEN_SYMBOLS`] has to spell out the
//!   four names as literal text for either scan to look for them at all.
//!   Both requirements collide with where this file has to live: the brief
//!   puts the Rust companion inside `crates/swarm-runtime/src/red_swarm/`,
//!   which is exactly the directory the shell gate scans byte-for-byte, and
//!   [`red_swarm_source_files`]'s own walk below is the same directory. A
//!   lexical scan cannot tell "the ban list, written down so the scan has
//!   something to look for", or "a fixture proving the scan works", from "a
//!   real violation" -- all three are, textually, just the forbidden name.
//!   An earlier version of this file tried to dodge that by building the
//!   ban list and the counterexample from split literals (`["execute_",
//!   "response"].concat()`); it still missed one -- a label string used only
//!   in an assertion message -- and failed its own scan, which is exactly
//!   the kind of one-literal-at-a-time bookkeeping this module should not
//!   have to get right forever.
//!
//!   So both scans instead name this ONE file, by its exact path, and skip
//!   it: `EXCLUDED_FILES` in the shell script, and the `file_name` check in
//!   [`collect_rs_files`] below. Every OTHER file under `red_swarm/`,
//!   including every other test module, is still scanned exactly as before
//!   -- this is narrower than excluding a directory or a whole
//!   `#[cfg(test)]` span. The exclusion fails loudly rather than silently if
//!   it ever drifts: renaming this file without updating the shell script
//!   makes the shell gate scan (and fail on) this file's own ban list on the
//!   very next run; renaming it without updating `collect_rs_files` makes
//!   `red_swarm_sources_carry_no_forbidden_response_authority_symbol` below
//!   fail on itself the same way, and
//!   `red_swarm_source_files_excludes_this_file_from_the_walk_it_performs`
//!   pins the exclusion directly so a drift is caught even before that.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

/// The four names ARMSCI-02 forbids in red-swarm source, verbatim from
/// `.planning/REQUIREMENTS.md` and mirrored in `FORBIDDEN` in
/// `tools/check-red-swarm-no-execution-authority.sh`. Kept in one place so a
/// fifth name is added to both scans in the same commit, not just one of
/// them.
const FORBIDDEN_SYMBOLS: [&str; 4] = [
    "execute_response",
    "ResponseAdapter",
    "PolicyDecision::Authorize",
    "live_response",
];

/// This file's own name. [`collect_rs_files`] skips any entry named this,
/// and the shell gate's `EXCLUDED_FILES` names this file's full repo-relative
/// path for the same reason -- see "WHY THIS FILE IS EXCLUDED FROM ITS OWN
/// SCAN" above.
const SELF_FILE_NAME: &str = "isolation_gate.rs";

/// True when `line`, ignoring leading whitespace, begins with `//`. Covers
/// `//!` module docs, `///` item docs, and plain `//` line comments -- the
/// only comment form this tree uses; there are no `/* */` blocks under
/// `red_swarm/` or in `red_swarm_cmd.rs`. Mirrors the shell gate's own
/// comment rule exactly (see this module's doc).
fn is_pure_comment_line(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

/// Returns the first forbidden symbol found in `text`, or `None`.
/// Comment-only lines (per [`is_pure_comment_line`]) are skipped; every
/// other line is checked for all four names in [`FORBIDDEN_SYMBOLS`] as
/// plain substrings, the same test the shell gate's `grep -F` performs.
fn forbidden_symbol_in_text(text: &str) -> Option<&'static str> {
    for line in text.lines() {
        if is_pure_comment_line(line) {
            continue;
        }
        for symbol in FORBIDDEN_SYMBOLS {
            if line.contains(symbol) {
                return Some(symbol);
            }
        }
    }
    None
}

/// Recursively collects every `*.rs` file under `dir` into `out`, except
/// this file itself (see the module doc's "WHY THIS FILE IS EXCLUDED FROM
/// ITS OWN SCAN").
///
/// Panics on any IO error rather than skipping the entry: a directory this
/// walk cannot read is a directory it cannot vouch for, and silently
/// shrinking the file list is exactly the "an empty scan and a broken needle
/// must never look identical" failure the shell gate's header warns against.
/// Panicking here is in bounds -- this function exists only under
/// `#[cfg(test)]` (see the `mod isolation_gate` declaration in
/// `red_swarm/mod.rs`) -- and `#![allow(clippy::expect_used)]` above covers
/// the crate-wide `unwrap_used`/`expect_used` deny for this whole file.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|err| panic!("failed to read {}: {err}", dir.display()));
    for entry in entries {
        let path = entry.expect("directory entry should be readable").path();
        if path.is_dir() {
            collect_rs_files(&path, out);
            continue;
        }
        if path.file_name() == Some(OsStr::new(SELF_FILE_NAME)) {
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// The same two locations `tools/check-red-swarm-no-execution-authority.sh`
/// scans: every `*.rs` file under this crate's own `red_swarm/` source
/// directory (this file excluded), plus the red-swarm CLI verbs in the
/// sibling `swarm-cli` crate. Resolved from `CARGO_MANIFEST_DIR`, so the test
/// finds the real tree regardless of the working directory `cargo test` is
/// invoked from.
fn red_swarm_source_files() -> Vec<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect_rs_files(&manifest_dir.join("src/red_swarm"), &mut files);
    files.push(manifest_dir.join("../swarm-cli/src/red_swarm_cmd.rs"));
    files
}

/// A broken walk that silently returns nothing would make the "no forbidden
/// symbol" assertion below pass over zero files -- the same vacuous-pass
/// shape the shell gate's own header exists to refuse. This pins a floor: at
/// the time this test was written the red lane held 17 other `*.rs` files
/// under `red_swarm/` (this file excluded, per the module doc) plus the CLI
/// module, for 18 total, so a collapse to single digits means a broken walk,
/// not a shrinking red lane.
const MIN_EXPECTED_SOURCE_FILES: usize = 10;

#[test]
fn red_swarm_sources_carry_no_forbidden_response_authority_symbol() {
    let files = red_swarm_source_files();
    assert!(
        files.len() >= MIN_EXPECTED_SOURCE_FILES,
        "expected at least {MIN_EXPECTED_SOURCE_FILES} red-swarm source files, found {}; \
         the file walk is likely broken, which would make a clean scan vacuous",
        files.len()
    );

    for file in &files {
        let text = fs::read_to_string(file)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", file.display()));
        assert!(
            forbidden_symbol_in_text(&text).is_none(),
            "{} names a forbidden response-authority symbol -- the red lane must never reach \
             execution, authorization, or live response",
            file.display()
        );
    }
}

/// Direct proof that [`red_swarm_source_files`] excludes this file from the
/// very walk it performs -- see the module doc's "WHY THIS FILE IS EXCLUDED
/// FROM ITS OWN SCAN". Without this, a drift between `SELF_FILE_NAME` and
/// this file's real name would surface only as the OTHER test in this module
/// failing on its own ban list, which points a future reader at the wrong
/// file first.
#[test]
fn red_swarm_source_files_excludes_this_file_from_the_walk_it_performs() {
    let files = red_swarm_source_files();
    assert!(
        !files
            .iter()
            .any(|file| file.file_name() == Some(OsStr::new(SELF_FILE_NAME))),
        "the walk must exclude {SELF_FILE_NAME} itself -- it legitimately contains the ban list \
         `red_swarm_sources_carry_no_forbidden_response_authority_symbol` checks for"
    );
}

/// ARMSCI-03's documented counterexample. Every name in [`FORBIDDEN_SYMBOLS`]
/// -- the SAME ban list the real scan above uses, not a separate copy -- is
/// planted as a real code line and fed through the exact function that test
/// uses. If any failed to trip it, `forbidden_symbol_in_text` would be
/// vacuously permissive on the real tree too -- passing not because the red
/// lane is clean, but because the check cannot see anything. Looping over
/// [`FORBIDDEN_SYMBOLS`] rather than a hand-copied list also means a fifth
/// forbidden name gets a counterexample for free the moment it is added
/// there.
#[test]
fn forbidden_symbol_scan_catches_a_planted_counterexample_for_every_forbidden_name() {
    for symbol in FORBIDDEN_SYMBOLS {
        let source = format!("fn planted_violation() {{ let _ = {symbol}; }}\n");
        assert_eq!(
            forbidden_symbol_in_text(&source),
            Some(symbol),
            "planting `{symbol}` in a source line should have tripped the scan -- the check \
             would be vacuous if it did not"
        );
    }
}

/// The mirror image of the counterexample above: a name mentioned ONLY in a
/// comment must NOT trip the scan, or `pattern_db.rs`'s module doc -- which
/// names three of these symbols in prose, to say it resolves to none of them
/// -- would fail this exact gate for saying so.
#[test]
fn forbidden_symbol_scan_ignores_a_forbidden_name_mentioned_only_in_a_comment() {
    let source = format!("//! nothing here resolves to `{}`.\n", FORBIDDEN_SYMBOLS[0]);
    assert_eq!(
        forbidden_symbol_in_text(&source),
        None,
        "a name mentioned only in a comment does not compile and must not trip the scan"
    );
}
