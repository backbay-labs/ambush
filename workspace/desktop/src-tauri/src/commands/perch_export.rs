//! Writing an evidence bundle to disk.
//!
//! LOCAL FILESYSTEM WORK. It issues no request to any host, so it sits outside
//! INV-01 with the verifier and the sidecar commands.
//!
//! The renderer plans the bundle and hashes it — `planExportFiles` and
//! `buildExportManifest` in `exportBundle.ts` — because the bytes it carries
//! are the daemon's and the relay's VERBATIM, and re-serializing them here
//! would change the digest of a signed record and turn a verifiable artifact
//! into this console's paraphrase of one. This side only writes what it is
//! handed, and refuses to write anywhere it was not pointed.

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

/// One file, with its bytes already chosen by the renderer.
#[derive(Debug, Clone, Deserialize)]
pub struct PerchExportFile {
    /// Relative, inside the bundle. Never absolute and never climbing.
    pub path: String,
    /// Base64, because a `Vec<u8>` across IPC is a JSON array of numbers and a
    /// twelve-megabyte bundle would be a hundred megabytes of digits.
    pub bytes_b64: String,
}

/// What was written, so the caller reports the truth rather than its intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PerchExportOutcome {
    /// The directory the bundle was written into.
    pub directory: String,
    /// Paths written, in the order given.
    pub written: Vec<String>,
    /// Total bytes written.
    pub bytes: u64,
}

/// Reject a bundle-relative path that is not one.
///
/// Absolute paths, `..`, drive prefixes and root components are all refused
/// rather than sanitised. A "cleaned" path that still resolves somewhere
/// unexpected is the shape of every traversal bug, and this function's caller
/// is a webview: the only safe answer to a path it should not have sent is no.
fn safe_relative(path: &str) -> Result<PathBuf, String> {
    if path.is_empty() {
        return Err("a bundle path must not be empty".to_string());
    }
    let candidate = Path::new(path);
    for component in candidate.components() {
        match component {
            Component::Normal(_) => {}
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "bundle path {path:?} must be relative and must not climb"
                ));
            }
        }
    }
    Ok(candidate.to_path_buf())
}

/// Write the bundle into `directory`.
///
/// Pure of Tauri so the path rules are testable without an app handle.
pub fn write_bundle(
    directory: &Path,
    files: &[(PathBuf, Vec<u8>)],
) -> Result<PerchExportOutcome, String> {
    let mut written = Vec::with_capacity(files.len());
    let mut bytes = 0u64;
    for (relative, content) in files {
        let target = directory.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
        }
        std::fs::write(&target, content)
            .map_err(|error| format!("could not write {}: {error}", target.display()))?;
        bytes += content.len() as u64;
        written.push(relative.to_string_lossy().into_owned());
    }
    Ok(PerchExportOutcome {
        directory: directory.to_string_lossy().into_owned(),
        written,
        bytes,
    })
}

fn decode_base64(value: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|error| format!("a bundle file's bytes are not base64: {error}"))
}

/// Write an evidence bundle into a directory the operator chose.
///
/// The directory comes from the renderer, which got it from the OS picker, and
/// is used as given — the operator chose it and this process has their rights.
/// The paths INSIDE the bundle are the ones checked, because those are the
/// part a compromised webview would control.
#[tauri::command]
pub async fn perch_export_bundle(
    directory: String,
    files: Vec<PerchExportFile>,
) -> Result<PerchExportOutcome, String> {
    if files.is_empty() {
        // An empty bundle is a bundle that answers nothing. Writing one would
        // hand an operator a directory that looks like evidence.
        return Err("an export with no files would be a bundle that answers nothing".to_string());
    }
    let mut decoded = Vec::with_capacity(files.len());
    for file in &files {
        decoded.push((safe_relative(&file.path)?, decode_base64(&file.bytes_b64)?));
    }
    // Every path is validated before anything is written: a bundle that failed
    // halfway would leave a partial directory an operator might ship.
    write_bundle(Path::new(&directory), &decoded)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "perch_export_tests.rs"]
mod tests;
