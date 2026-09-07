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
//!   left. Compare `forbidden_symbol_in_text` below with that script's
//!   `scan_forbidden_symbols`.
//!
//! WHY COMMENTS ARE EXCLUDED
//!   `pattern_db.rs`'s module doc says, in prose, that nothing in that file
//!   resolves to these names -- a true claim about its imports and call
//!   graph, expressible only by naming the very symbols it says are absent.
//!   A comment does not compile and cannot reach response authority, so
//!   `is_pure_comment_line` excludes it before the forbidden-name check
//!   runs. It is a per-line rule, not a tokenizer: a forbidden name arriving
//!   as a trailing comment after real code on the same line is still
//!   (deliberately, conservatively) scanned.
//!
//!   NOT RECOGNIZED: a `/* ... */` block comment. Neither this rule nor the
//!   shell gate's identical one sees anything but a line starting with `//`
//!   (after leading whitespace), so a forbidden name inside a block comment
//!   would be scanned and FLAGGED rather than excluded. That is the safe
//!   direction for a security gate to be wrong in -- a spurious build
//!   failure over dead comment text, never a missed real violation -- and
//!   there are no `/* */` blocks under `red_swarm/` or in `red_swarm_cmd.rs`
//!   today (confirmed by grepping both scan targets for `/*`; every hit is a
//!   `///` doc-comment line or a glob pattern such as `*.yaml` written
//!   inside one), so this is disclosed rather than fixed.
//!
//! WHY THIS FILE IS EXCLUDED FROM ITS OWN SCAN
//!   ARMSCI-03 needs a counterexample that WOULD trip the gate, to prove the
//!   check is not vacuous -- and `FORBIDDEN_SYMBOLS` has to spell out the
//!   four names as literal text for either scan to look for them at all.
//!   Both requirements collide with where this file has to live: the brief
//!   puts the Rust companion inside `crates/swarm-runtime/src/red_swarm/`,
//!   which is exactly the directory the shell gate scans byte-for-byte, and
//!   `red_swarm_source_files`'s own walk below is the same directory. A
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
//!   it: `EXCLUDED_FILES` in the shell script (an exact string-equal match on
//!   the full repo-relative path), and the `path == excluded` comparison in
//!   `collect_rs_files` below, against `SELF_RELATIVE_PATH` resolved from
//!   `CARGO_MANIFEST_DIR`. Every OTHER file under `red_swarm/`, including
//!   every other test module, is still scanned exactly as before -- this is
//!   narrower than excluding a directory or a whole `#[cfg(test)]` span.
//!
//!   FIX ROUND 1 (review finding, Important): the exclusion used to compare
//!   `path.file_name()` against a bare `"isolation_gate.rs"`, which excluded
//!   ANY file with that name anywhere in the recursive walk -- a real
//!   divergence from the shell gate's exact full-path match, since a second
//!   file coincidentally named `isolation_gate.rs` under, say,
//!   `red_swarm/operators/`, containing a real forbidden call, would have
//!   been silently dropped from this walk while the shell gate still caught
//!   it. Fixed by comparing the full path instead, exactly like the shell
//!   side; `collect_rs_files_does_not_exclude_a_same_named_file_at_a_different_path`
//!   pins it directly (RED under the bare-name comparison, GREEN under the
//!   full-path one), and
//!   `red_swarm_source_files_excludes_this_file_from_the_walk_it_performs`
//!   was updated to check the same full path rather than re-asserting the
//!   bug's own predicate.
//!
//!   The exclusion still fails loudly rather than silently if it drifts:
//!   renaming this file without updating the shell script makes the shell
//!   gate scan (and fail on) this file's own ban list on the very next run;
//!   renaming it without updating `SELF_RELATIVE_PATH` makes
//!   `red_swarm_sources_carry_no_forbidden_response_authority_symbol` below
//!   fail on itself the same way.
//!
//! WHY EVERYTHING BELOW LIVES INSIDE `mod tests`
//!   `rng.rs`'s `no_entropy_path_exists_in_the_red_lane` treats everything
//!   in a `red_swarm/` file BEFORE its first literal `#[cfg(test)]` as
//!   production code (see that test's `production_code` helper) -- a
//!   convention every other file in this directory follows by keeping its
//!   tests in one trailing `#[cfg(test)] mod tests`. An earlier version of
//!   this file instead made the whole module test-only from OUTSIDE, via
//!   `#[cfg(test)] mod isolation_gate;` in `red_swarm/mod.rs`, with no
//!   `#[cfg(test)]` marker inside the file itself -- which reads as ALL
//!   production code to that unrelated entropy scan, and its `SystemTime`
//!   use (for a unique temp-fixture directory name, added in FIX ROUND 1)
//!   failed it. Declaring this module unconditionally instead, with its
//!   content inside `mod tests` like every sibling file, satisfies both
//!   gates without either needing to know about the other.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// The four names ARMSCI-02 forbids in red-swarm source, verbatim from
    /// `.planning/REQUIREMENTS.md` and mirrored in `FORBIDDEN` in
    /// `tools/check-red-swarm-no-execution-authority.sh`. Kept in one place
    /// so a fifth name is added to both scans in the same commit, not just
    /// one of them.
    const FORBIDDEN_SYMBOLS: [&str; 4] = [
        "execute_response",
        "ResponseAdapter",
        "PolicyDecision::Authorize",
        "live_response",
    ];

    /// This file's own path, relative to `CARGO_MANIFEST_DIR`.
    /// `collect_rs_files` excludes ONLY the file at exactly this path -- not
    /// any file sharing its bare name -- and the shell gate's
    /// `EXCLUDED_FILES` names the equivalent full repo-relative path for the
    /// same reason. See the module doc's "WHY THIS FILE IS EXCLUDED FROM ITS
    /// OWN SCAN", including FIX ROUND 1.
    const SELF_RELATIVE_PATH: &str = "src/red_swarm/isolation_gate.rs";

    /// True when `line`, ignoring leading whitespace, begins with `//`.
    /// Covers `//!` module docs, `///` item docs, and plain `//` line
    /// comments -- the only comment form this tree uses. Does NOT recognize
    /// a `/* */` block comment; see the module doc's "WHY COMMENTS ARE
    /// EXCLUDED" for why that is disclosed rather than handled. Mirrors the
    /// shell gate's own comment rule exactly.
    fn is_pure_comment_line(line: &str) -> bool {
        line.trim_start().starts_with("//")
    }

    /// Returns the first forbidden symbol found in `text`, or `None`.
    /// Comment-only lines (per `is_pure_comment_line`) are skipped; every
    /// other line is checked for all four names in `FORBIDDEN_SYMBOLS` as
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
    /// a file whose path is exactly equal to `excluded` (see the module
    /// doc's "WHY THIS FILE IS EXCLUDED FROM ITS OWN SCAN"). Deliberately a
    /// full `Path` comparison, not a bare file-name one: a file that merely
    /// SHARES this file's name at some other location under `dir` is a
    /// normal red-swarm source file and must still be walked and scanned --
    /// `collect_rs_files_does_not_exclude_a_same_named_file_at_a_different_path`
    /// pins exactly that.
    ///
    /// Panics on any IO error rather than skipping the entry: a directory
    /// this walk cannot read is a directory it cannot vouch for, and
    /// silently shrinking the file list is exactly the "an empty scan and a
    /// broken needle must never look identical" failure the shell gate's
    /// header warns against. Panicking here is in bounds -- this function
    /// exists only inside this `#[cfg(test)] mod tests`, and the `#[allow]`
    /// on that declaration covers the crate-wide `unwrap_used`/
    /// `expect_used` deny for everything in it.
    fn collect_rs_files(dir: &Path, excluded: &Path, out: &mut Vec<PathBuf>) {
        let entries = fs::read_dir(dir)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", dir.display()));
        for entry in entries {
            let path = entry.expect("directory entry should be readable").path();
            if path.is_dir() {
                collect_rs_files(&path, excluded, out);
                continue;
            }
            if path == excluded {
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }

    /// The same two locations `tools/check-red-swarm-no-execution-authority.sh`
    /// scans: every `*.rs` file under this crate's own `red_swarm/` source
    /// directory (this file excluded, by its full path -- see
    /// `SELF_RELATIVE_PATH`), plus the red-swarm CLI verbs in the sibling
    /// `swarm-cli` crate. Resolved from `CARGO_MANIFEST_DIR`, so the test
    /// finds the real tree regardless of the working directory `cargo test`
    /// is invoked from.
    fn red_swarm_source_files() -> Vec<PathBuf> {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let excluded = manifest_dir.join(SELF_RELATIVE_PATH);
        let mut files = Vec::new();
        collect_rs_files(&manifest_dir.join("src/red_swarm"), &excluded, &mut files);
        files.push(manifest_dir.join("../swarm-cli/src/red_swarm_cmd.rs"));
        files
    }

    /// A broken walk that silently returns nothing would make the "no
    /// forbidden symbol" assertion below pass over zero files -- the same
    /// vacuous-pass shape the shell gate's own header exists to refuse. This
    /// pins a floor: at the time this test was written the red lane held 17
    /// other `*.rs` files under `red_swarm/` (this file excluded, per the
    /// module doc) plus the CLI module, for 18 total, so a collapse to
    /// single digits means a broken walk, not a shrinking red lane.
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
                "{} names a forbidden response-authority symbol -- the red lane must never \
                 reach execution, authorization, or live response",
                file.display()
            );
        }
    }

    /// Direct proof that `red_swarm_source_files` excludes this file, by its
    /// full path, from the very walk it performs -- see the module doc's
    /// "WHY THIS FILE IS EXCLUDED FROM ITS OWN SCAN". Compares the same full
    /// `manifest_dir.join(SELF_RELATIVE_PATH)` value `collect_rs_files` is
    /// given, not a bare file name -- checking a bare name here would just
    /// re-assert FIX ROUND 1's bug instead of catching it (a review finding:
    /// the pre-fix version of this test used `file_name()` and so could not
    /// tell the too-broad exclusion from the correct one; see
    /// `collect_rs_files_does_not_exclude_a_same_named_file_at_a_different_path`
    /// for the test that actually pins the distinction).
    #[test]
    fn red_swarm_source_files_excludes_this_file_from_the_walk_it_performs() {
        let files = red_swarm_source_files();
        let self_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(SELF_RELATIVE_PATH);
        assert!(
            !files.contains(&self_path),
            "the walk must exclude {} itself -- it legitimately contains the ban list \
             `red_swarm_sources_carry_no_forbidden_response_authority_symbol` checks for",
            self_path.display()
        );
    }

    /// RAII cleanup for the temp fixture directory the test below builds --
    /// the Rust-side equivalent of the shell gate's `trap 'rm -rf
    /// "$fixture"' EXIT`. Runs on a panic (assertion failure) as well as on
    /// a normal return, so a failing run does not leave fixture directories
    /// behind in the OS temp dir.
    struct TempDirGuard(PathBuf);

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// FIX ROUND 1's pinning test (review finding, Important): a file that
    /// shares this file's bare NAME at a DIFFERENT path must NOT be excluded
    /// -- only the one real file at `SELF_RELATIVE_PATH` is. Builds a
    /// throwaway directory tree under the OS temp dir with two files sharing
    /// one name -- `<root>/isolation_gate.rs` (playing the role of the real
    /// self-file, named as the `excluded` argument) and
    /// `<root>/operators/isolation_gate.rs` (a same-named file at a
    /// DIFFERENT path, planted with a real forbidden call, playing the role
    /// of a coincidental collision such as
    /// `red_swarm/operators/isolation_gate.rs`) -- and calls
    /// `collect_rs_files` directly against it.
    ///
    /// Under the bare `file_name()` comparison this test's own history had
    /// (see FIX ROUND 1 in the module doc), BOTH files would have matched
    /// the bare name and the colliding file would have been silently dropped
    /// from `out` -- this test would have failed RED against that code.
    /// Under the full-path comparison, only the file exactly at `excluded`
    /// is dropped; the colliding file is walked normally and its planted
    /// forbidden symbol is still detectable in its content, proving the fix
    /// closes the gap end to end, not just in the file list.
    #[test]
    fn collect_rs_files_does_not_exclude_a_same_named_file_at_a_different_path() {
        let file_name = Path::new(SELF_RELATIVE_PATH)
            .file_name()
            .expect("SELF_RELATIVE_PATH should name a file");

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should read after the Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "ambush-isolation-gate-fixture-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("operators"))
            .expect("temp fixture directory should be creatable");
        let _guard = TempDirGuard(root.clone());

        // Plays the role of the real self-file: excluded by being named
        // exactly as the `excluded` argument below.
        let self_like = root.join(file_name);
        fs::write(
            &self_like,
            "//! stands in for the real self-file in this fixture.\n",
        )
        .expect("temp fixture file should be writable");

        // Plays the role of a coincidental same-named file elsewhere under
        // `red_swarm/` -- e.g. `red_swarm/operators/isolation_gate.rs` --
        // with a real forbidden call planted in it.
        let colliding = root.join("operators").join(file_name);
        fs::write(
            &colliding,
            "fn planted_violation() { let _ = execute_response; }\n",
        )
        .expect("temp fixture file should be writable");

        let mut files = Vec::new();
        collect_rs_files(&root, &self_like, &mut files);

        assert!(
            !files.contains(&self_like),
            "the file at the configured excluded path must still be excluded"
        );
        assert!(
            files.contains(&colliding),
            "a same-named file at a DIFFERENT path must NOT be excluded -- the walk must match \
             the excluded file by its full path, exactly like the shell gate's exact-path \
             comparison, not by a bare file name"
        );

        let colliding_text =
            fs::read_to_string(&colliding).expect("temp fixture file should be readable");
        assert_eq!(
            forbidden_symbol_in_text(&colliding_text),
            Some("execute_response"),
            "the planted forbidden symbol in the colliding file must still be detectable -- a \
             same-named file elsewhere under red_swarm/ is a normal source file, not a fixture"
        );
    }

    /// ARMSCI-03's documented counterexample. Every name in
    /// `FORBIDDEN_SYMBOLS` -- the SAME ban list the real scan above uses,
    /// not a separate copy -- is planted as a real code line and fed through
    /// the exact function that test uses. If any failed to trip it,
    /// `forbidden_symbol_in_text` would be vacuously permissive on the real
    /// tree too -- passing not because the red lane is clean, but because
    /// the check cannot see anything. Looping over `FORBIDDEN_SYMBOLS`
    /// rather than a hand-copied list also means a fifth forbidden name gets
    /// a counterexample for free the moment it is added there.
    #[test]
    fn forbidden_symbol_scan_catches_a_planted_counterexample_for_every_forbidden_name() {
        for symbol in FORBIDDEN_SYMBOLS {
            let source = format!("fn planted_violation() {{ let _ = {symbol}; }}\n");
            assert_eq!(
                forbidden_symbol_in_text(&source),
                Some(symbol),
                "planting `{symbol}` in a source line should have tripped the scan -- the \
                 check would be vacuous if it did not"
            );
        }
    }

    /// The mirror image of the counterexample above: a name mentioned ONLY
    /// in a comment must NOT trip the scan, or `pattern_db.rs`'s module doc
    /// -- which names three of these symbols in prose, to say it resolves to
    /// none of them -- would fail this exact gate for saying so.
    #[test]
    fn forbidden_symbol_scan_ignores_a_forbidden_name_mentioned_only_in_a_comment() {
        let source = format!("//! nothing here resolves to `{}`.\n", FORBIDDEN_SYMBOLS[0]);
        assert_eq!(
            forbidden_symbol_in_text(&source),
            None,
            "a name mentioned only in a comment does not compile and must not trip the scan"
        );
    }
}
