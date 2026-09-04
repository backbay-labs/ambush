//! A case-pinned shell's working directory and environment.
//!
//! Split out of `terminal_runtime.rs` when that file crossed the 1000-line
//! ratchet. It is a natural seam: nothing here touches a PTY, and the whole
//! module is a pure function plus its slug rule, which is exactly what the
//! TypeScript side mirrors.

use std::path::{Path, PathBuf};

/// A case-pinned shell's working directory and environment.
///
/// Mirrors `src/features/terminal/terminalCaseScope.ts` exactly: same
/// directory shape, same three variable names, same slug rule. The two are
/// tested against one table so a change on either side that the other does not
/// follow fails a test rather than producing a shell the console describes
/// wrongly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CaseTerminalScope {
    pub(crate) cwd: PathBuf,
    pub(crate) env: [(&'static str, String); 3],
}

/// Where case-scoped shells live. Under the app's own data directory, so a
/// case's artifacts sit beside the rest of this community's state and are
/// removed with it.
pub(crate) fn state_root_for_cases(app: &tauri::AppHandle) -> PathBuf {
    use tauri::Manager as _;
    app.path()
        .app_data_dir()
        .unwrap_or_else(|_| std::env::temp_dir())
        .join("perch")
}

/// A slug is accepted only if it is entirely safe: leading alphanumeric, then
/// alphanumerics, dots, dashes and underscores, at most 64 characters.
fn slug_is_safe(slug: &str) -> bool {
    let mut chars = slug.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    if slug.chars().count() > 64 {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

/// swarmctl's `--*-results-dir` flags default to RELATIVE `data/…` paths, so
/// pinning the working directory scopes every default at once without
/// injecting flags, and every artifact is attributable to the case by path.
pub(crate) fn case_terminal_scope(
    state_root: &Path,
    case_id: &str,
    case_slug: Option<&str>,
) -> CaseTerminalScope {
    let cwd = state_root.join("cases").join(case_id);
    let slug = match case_slug {
        Some(slug) if slug_is_safe(slug) => slug.to_string(),
        _ => case_id.to_string(),
    };
    let cwd_string = cwd.to_string_lossy().into_owned();
    CaseTerminalScope {
        env: [
            ("AMBUSH_CASE_ID", case_id.to_string()),
            ("AMBUSH_CASE", slug),
            ("SWARM_RESULTS_ROOT", cwd_string),
        ],
        cwd,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact table `src/features/terminal/terminalCaseScope.test.mjs`
    /// asserts. If either side changes its shape, one of the two fails.
    const CASE_ID: &str = "27799e23-ab25-4659-b381-3de47ea7ca4d";

    #[test]
    fn a_case_pin_is_a_working_directory_plus_three_env_vars() {
        let scope = case_terminal_scope(
            Path::new("/var/lib/ambush/perch"),
            CASE_ID,
            Some("case-0042"),
        );
        assert_eq!(
            scope.cwd,
            PathBuf::from("/var/lib/ambush/perch/cases/27799e23-ab25-4659-b381-3de47ea7ca4d")
        );
        assert_eq!(
            scope.env,
            [
                ("AMBUSH_CASE_ID", CASE_ID.to_string()),
                ("AMBUSH_CASE", "case-0042".to_string()),
                (
                    "SWARM_RESULTS_ROOT",
                    "/var/lib/ambush/perch/cases/27799e23-ab25-4659-b381-3de47ea7ca4d".to_string()
                ),
            ]
        );
    }

    #[test]
    fn an_unsafe_slug_is_replaced_by_the_id_never_interpolated() {
        for slug in [
            "",
            "-leading-dash",
            ".leading-dot",
            "has space",
            "has/slash",
            "back`tick`",
            "semi;colon",
            "new\nline",
            "$(rm -rf /)",
            "\u{fc}ber",
        ] {
            let scope = case_terminal_scope(Path::new("/root"), CASE_ID, Some(slug));
            assert_eq!(
                scope.env[1].1, CASE_ID,
                "slug {slug:?} must not reach the shell"
            );
        }
        assert_eq!(
            case_terminal_scope(Path::new("/root"), CASE_ID, Some(&"a".repeat(65))).env[1].1,
            CASE_ID
        );
        assert_eq!(
            case_terminal_scope(Path::new("/root"), CASE_ID, Some(&"a".repeat(64))).env[1].1,
            "a".repeat(64)
        );
    }

    #[test]
    fn an_absent_slug_falls_back_to_the_id() {
        let scope = case_terminal_scope(Path::new("/root"), CASE_ID, None);
        assert_eq!(scope.env[1].1, CASE_ID);
    }

    #[test]
    fn the_results_root_is_the_cwd_and_not_a_second_computation() {
        let scope = case_terminal_scope(Path::new("/root"), CASE_ID, Some("case-1"));
        assert_eq!(scope.env[2].1, scope.cwd.to_string_lossy());
    }
}
