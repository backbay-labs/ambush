//! Collision-proof fixture paths for this crate's unit tests.
//!
//! Every test in `swarm-response` that needs a dead-letter journal or a lease
//! store writes it into the shared system temp directory. That directory is
//! shared with every other process on the machine, including other copies of
//! this same test binary, so the file name has to be unique per *process* and
//! per *call* -- not merely per wall-clock instant.
//!
//! Naming a fixture by millisecond identity alone is not enough. Twelve
//! concurrent copies of the `swarm_response` test binary collided on
//! `notify-rate-limit-<current_time_ms()>.jsonl`: two runs started inside the
//! same millisecond, appended interleaved JSONL to one file, and the reader
//! failed with `ReadDeadLetter { .. Error("expected `:`", line: 1, column: 17) }`.
//!
//! The identity here is `<pid>-<nanos>-<counter>`:
//!
//! - the pid separates concurrent processes,
//! - the process-local counter separates concurrent calls inside one process
//!   (nanosecond readings are not guaranteed distinct, and the OS clock is not
//!   guaranteed monotonic across them),
//! - the nanosecond reading separates runs that a recycled pid would otherwise
//!   alias onto a leftover file from an earlier run.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique `<label>` stem: `swarm-response-<label>-<pid>-<nanos>-<counter>`.
fn unique_stem(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let counter = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "swarm-response-{label}-{}-{nanos}-{counter}",
        std::process::id()
    )
}

/// A unique `.jsonl` path under the system temp directory. Never returned twice,
/// in this process or any other.
pub(crate) fn temp_jsonl_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{}.jsonl", unique_stem(label)))
}

/// [`temp_jsonl_path`] as a `String`, for the config fields that hold paths as
/// strings.
pub(crate) fn temp_jsonl_path_string(label: &str) -> String {
    temp_jsonl_path(label).display().to_string()
}

/// A unique directory path under the system temp directory. The directory is
/// not created; callers that need it on disk create it themselves.
pub(crate) fn temp_dir_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(unique_stem(label))
}

#[cfg(test)]
mod tests {
    use super::{temp_dir_path, temp_jsonl_path, unique_stem};

    #[test]
    fn repeated_calls_never_return_the_same_path() {
        // The collision this module exists to prevent is two callers agreeing on
        // one name. A loop tight enough to land inside a single nanosecond
        // reading is the direct construction of that condition.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1_000 {
            assert!(
                seen.insert(temp_jsonl_path("uniqueness")),
                "temp_jsonl_path returned a duplicate path"
            );
            assert!(
                seen.insert(temp_dir_path("uniqueness")),
                "temp_dir_path returned a duplicate path"
            );
        }
    }

    #[test]
    fn paths_carry_the_process_identity() {
        // Concurrent copies of this binary are separated by the pid alone, so
        // the pid has to actually be in the name.
        let path = temp_jsonl_path("pid").display().to_string();
        assert!(
            path.contains(&format!("-{}-", std::process::id())),
            "fixture path {path} does not carry the pid"
        );
    }

    /// The nanosecond component is the defence against a RECYCLED pid aliasing
    /// onto a leftover file from an earlier run, and it was the one of the
    /// three that nothing pinned: deleting `{nanos}` from the format string
    /// left both other tests passing, because within a single process the pid
    /// is constant and the counter alone keeps paths distinct.
    ///
    /// Asserting it is present is not enough either -- a literal would satisfy
    /// that. This pins that the reading actually VARIES with the clock, which
    /// is the property a recycled pid needs.
    #[test]
    fn the_stem_carries_a_clock_reading_that_advances() {
        let first = unique_stem("drift");
        // A monotone wait, not a timing assertion: loop until the nanosecond
        // reading changes rather than sleeping for a duration and hoping.
        let mut second = unique_stem("drift");
        let mut spins = 0;
        while nanos_of(&second) == nanos_of(&first) && spins < 1_000_000 {
            second = unique_stem("drift");
            spins += 1;
        }
        assert_ne!(
            nanos_of(&first),
            nanos_of(&second),
            "the stem's clock component never advanced over {spins} calls, so a \
             recycled pid could alias onto a previous run's file"
        );
    }

    /// Pull the `<nanos>` field out of `swarm-response-<label>-<pid>-<nanos>-<counter>`.
    fn nanos_of(stem: &str) -> &str {
        let parts: Vec<&str> = stem.rsplitn(3, '-').collect();
        // rsplitn yields [counter, nanos, rest]
        parts[1]
    }
}
