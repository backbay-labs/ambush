//! Two-phase boot-time sentinel wipe.
//!
//! **Phase 1** (`write_sentinel`) — called by `sign_out`: writes a durable
//! reset-intent file outside every path that will be wiped.
//!
//! **Phase 2** (`run_boot_reset`) — called at the very top of `setup()` in
//! `lib.rs`, before migrations and identity resolution: if the sentinel is
//! present the wipe runs atomically and the app falls through into clean
//! onboarding.
//!
//! The sentinel lives at `<app_data_dir's parent>/.<bundle_id>.reset-pending`
//! and survives the app-data wipe because the wipe targets the exact
//! app-data dir, not its parent.
//!
//! Idempotency: if the process crashes mid-wipe the sentinel is still present
//! on next boot and the wipe retries from the top.

use std::path::{Path, PathBuf};

// ── Sentinel helpers ──────────────────────────────────────────────────────────

/// Sentinel path: `<app_data_dir.parent>/.<bundle_id>.reset-pending`
/// where `bundle_id` is the file-name component of `app_data_dir`
/// (e.g. `com.backbay.ambush.app` or `com.backbay.ambush.app.dev`).
pub(crate) fn sentinel_path(app_data_dir: &Path) -> PathBuf {
    let bundle_id = app_data_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("ambush");
    let name = format!(".{bundle_id}.reset-pending");
    match app_data_dir.parent() {
        Some(parent) => parent.join(name),
        None => PathBuf::from(&name),
    }
}

/// Atomically write the sentinel file. Content is intentionally empty —
/// existence is the signal.
pub(crate) fn write_sentinel(app_data_dir: &Path) -> Result<(), String> {
    use atomic_write_file::AtomicWriteFile;

    let path = sentinel_path(app_data_dir);
    let parent = path
        .parent()
        .ok_or_else(|| format!("sentinel {} has no parent", path.display()))?;
    let parent_metadata = std::fs::symlink_metadata(parent)
        .map_err(|error| format!("inspect sentinel parent {}: {error}", parent.display()))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(format!(
            "sentinel parent {} is not a regular directory",
            parent.display()
        ));
    }
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Err(format!("sentinel {} is not a regular file", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect sentinel {}: {error}", path.display())),
    }
    AtomicWriteFile::open(&path)
        .and_then(AtomicWriteFile::commit)
        .map_err(|error| format!("write sentinel {}: {error}", path.display()))
}

/// Return whether an exact regular sentinel exists. Corrupt or linked markers
/// fail closed so identity resolution cannot bypass an armed reset.
pub(crate) fn check_sentinel(app_data_dir: &Path) -> Result<bool, String> {
    let path = sentinel_path(app_data_dir);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata)
            if metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() == 0 =>
        {
            Ok(true)
        }
        Ok(_) => Err(format!(
            "sentinel {} is not an exact regular marker",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("inspect sentinel {}: {error}", path.display())),
    }
}

/// Remove the sentinel file. A missing file is not an error.
pub(crate) fn delete_sentinel(app_data_dir: &Path) -> Result<(), String> {
    let path = sentinel_path(app_data_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("delete sentinel {}: {e}", path.display())),
    }
}

// ── Keychain abstraction (enables unit testing) ───────────────────────────────

/// Keychain operations needed by the boot-time reset.
/// Implemented for `SecretStore`; a fake is used in tests.
pub(crate) trait ResetKeychain {
    /// Delete the blob + all per-key legacy entries.
    fn delete_all_with_legacy(&self) -> Result<(), String>;
    /// Return `true` when all keychain shapes (main blob, DPK blob, per-key
    /// entries) that `migrate_legacy_key` can consume are absent.
    fn verify_fully_wiped(&self) -> bool;
}

impl ResetKeychain for crate::secret_store::SecretStore {
    fn delete_all_with_legacy(&self) -> Result<(), String> {
        self.delete_all_with_legacy_cleanup()
    }

    fn verify_fully_wiped(&self) -> bool {
        self.verify_fully_wiped()
    }
}

// ── Result type ───────────────────────────────────────────────────────────────

/// Outcome of the boot-time reset check.
#[derive(Debug, Default)]
pub(crate) struct ResetOutcome {
    /// Wipe completed successfully this boot — suppress nest migrations.
    pub completed: bool,
    /// Wipe was attempted but verification failed — surface error state.
    pub failed: bool,
}

// ── Boot-time reset ───────────────────────────────────────────────────────────

/// Wipe parameters assembled by `lib.rs` and passed into `run_boot_reset_with_keychain`.
pub(crate) struct ResetContext<'a> {
    pub app_data_dir: &'a Path,
    /// Legacy App Support dirs for this build (Buzz and Sprout import sources).
    /// Existing sources are wiped alongside `app_data_dir` to prevent
    /// `migrate_legacy_app_data_dir` from restoring the old identity.
    pub legacy_app_data_dirs: Vec<PathBuf>,
    /// Nest dir (`~/.ambush` or `~/.ambush-dev`) scoped to this build's variant,
    /// injected so unit tests can override without touching the global OnceLock.
    pub nest_dir: Option<PathBuf>,
    pub keychain: &'a dyn ResetKeychain,
    /// Exact predecessor services that can resurrect identity or agent keys.
    pub predecessor_keychains: Vec<&'a dyn ResetKeychain>,
    pub home_dir: Option<PathBuf>,
    pub is_dev: bool,
}

/// Entry point called from `lib.rs` setup (before migrations).
///
/// Constructs a `SecretStore` for the running build's keyring service and
/// delegates to `run_boot_reset_with_keychain` for testable wipe logic.
pub(crate) fn run_boot_reset(app_data_dir: &Path) -> ResetOutcome {
    match check_sentinel(app_data_dir) {
        Ok(false) => return ResetOutcome::default(),
        Ok(true) => {}
        Err(error) => {
            eprintln!("ambush-desktop reset: {error}");
            return ResetOutcome {
                completed: false,
                failed: true,
            };
        }
    }

    let is_dev = app_data_dir
        .file_name()
        .and_then(|n| n.to_str())
        .map(crate::migration::is_dev_data_dir_name)
        .unwrap_or(false);

    let lineage =
        match crate::migration::keyring_service_lineage(crate::app_state::keyring_service()) {
            Ok(lineage) => lineage,
            Err(error) => {
                eprintln!("ambush-desktop reset: invalid keyring lineage: {error}");
                return ResetOutcome {
                    completed: false,
                    failed: true,
                };
            }
        };
    let stores = lineage
        .iter()
        .map(crate::secret_store::SecretStore::keyring)
        .collect::<Vec<_>>();
    let home_dir = dirs::home_dir();
    let legacy_dirs = match crate::migration::app_data_migration_sources(app_data_dir) {
        Ok(dirs) => dirs,
        Err(error) => {
            eprintln!("ambush-desktop reset: invalid app-data lineage: {error}");
            return ResetOutcome {
                completed: false,
                failed: true,
            };
        }
    };
    let nest_dir = crate::managed_agents::nest_dir();

    let ctx = ResetContext {
        app_data_dir,
        legacy_app_data_dirs: legacy_dirs,
        nest_dir,
        keychain: &stores[0],
        predecessor_keychains: stores[1..]
            .iter()
            .map(|store| store as &dyn ResetKeychain)
            .collect(),
        home_dir,
        is_dev,
    };

    run_boot_reset_with_keychain(ctx)
}

/// Deterministic trash path: `<original>.reset-trash`. Unlike PID-based names,
/// any boot can discover and clean trash from a prior crashed attempt.
fn trash_path(original: &Path) -> PathBuf {
    original.with_file_name(format!(
        "{}.reset-trash",
        original
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("ambush")
    ))
}

/// Remove an existing reset-trash directory if present (from a prior crashed
/// attempt), then rename `src` into the deterministic trash path. Returns
/// `Ok(trash_path)` on success.
fn rename_to_trash(src: &Path) -> Result<PathBuf, String> {
    let dst = trash_path(src);
    // Clear prior trash before renaming so a collision doesn't fail the rename.
    if dst.exists() {
        let _ = std::fs::remove_dir_all(&dst);
    }
    std::fs::rename(src, &dst)
        .map_err(|e| format!("rename {} → {}: {e}", src.display(), dst.display()))?;
    Ok(dst)
}

fn stage_directory<F>(
    src: &Path,
    rename: &mut F,
    staged: &mut Vec<(PathBuf, PathBuf)>,
) -> Result<(), String>
where
    F: FnMut(&Path) -> Result<PathBuf, String>,
{
    let trash = if src.exists() {
        rename(src)?
    } else {
        // Keep deterministic trash from an interrupted prior boot in the same
        // transaction: restore it on failure or sweep it on success.
        trash_path(src)
    };
    staged.push((src.to_path_buf(), trash));
    Ok(())
}

fn restore_staged_directories(staged: &[(PathBuf, PathBuf)]) {
    for (original, trash) in staged.iter().rev() {
        if !original.exists() && trash.exists() {
            if let Err(error) = std::fs::rename(trash, original) {
                eprintln!(
                    "ambush-desktop reset: restore {} from {}: {error}",
                    original.display(),
                    trash.display()
                );
            }
        }
    }
}

fn path_is_absent(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

/// Core wipe logic — separated for testing.
pub(crate) fn run_boot_reset_with_keychain(ctx: ResetContext<'_>) -> ResetOutcome {
    run_boot_reset_with_keychain_and_rename(ctx, rename_to_trash)
}

fn run_boot_reset_with_keychain_and_rename<F>(ctx: ResetContext<'_>, mut rename: F) -> ResetOutcome
where
    F: FnMut(&Path) -> Result<PathBuf, String>,
{
    run_boot_reset_with_keychain_and_ops(ctx, &mut rename, delete_sentinel)
}

fn run_boot_reset_with_keychain_and_ops<F, D>(
    ctx: ResetContext<'_>,
    mut rename: F,
    delete_reset_sentinel: D,
) -> ResetOutcome
where
    F: FnMut(&Path) -> Result<PathBuf, String>,
    D: FnOnce(&Path) -> Result<(), String>,
{
    let app_data_dir = ctx.app_data_dir;

    // Stage every directory that can restore identity, agent credentials, or
    // old application state. Nothing is irreversibly removed until every
    // keychain deletion has committed; failures restore the complete set.
    let mut directories = vec![app_data_dir.to_path_buf()];
    directories.extend(ctx.legacy_app_data_dirs.iter().cloned());

    // WebKit and agent-owned directories are part of the same rollback set.
    if let Some(ref home) = ctx.home_dir {
        let bundle_id = app_data_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("ambush");
        directories.push(home.join("Library").join("WebKit").join(bundle_id));
    }

    // Add the current and predecessor agent credential directories.
    if let Some(ref nest) = ctx.nest_dir {
        directories.push(nest.clone());
    }
    if let Some(ref home) = ctx.home_dir {
        directories.push(home.join(".sprout"));
        directories.push(home.join(".config").join("ambush-agent"));
    }
    let mut unique_directories = Vec::with_capacity(directories.len());
    for directory in directories {
        if !unique_directories.contains(&directory) {
            unique_directories.push(directory);
        }
    }

    // Move every existing directory into deterministic reset trash.
    let mut staged = Vec::with_capacity(unique_directories.len());
    for directory in &unique_directories {
        if let Err(error) = stage_directory(directory, &mut rename, &mut staged) {
            eprintln!("ambush-desktop reset: {error}");
            restore_staged_directories(&staged);
            return ResetOutcome {
                completed: false,
                failed: true,
            };
        }
    }

    // Delete keychains only after every directory is safely staged.
    let mut keychain_delete_error = None;
    for keychain in std::iter::once(ctx.keychain).chain(ctx.predecessor_keychains.iter().copied()) {
        if let Err(error) = keychain.delete_all_with_legacy() {
            keychain_delete_error.get_or_insert(error);
        }
    }
    if let Some(e) = keychain_delete_error {
        eprintln!("ambush-desktop reset: keychain delete: {e}");
        restore_staged_directories(&staged);
        return ResetOutcome {
            completed: false,
            failed: true,
        };
    }

    // Keychains have committed. Remove the CLI link and sweep every staged
    // directory, including deterministic trash from a crashed prior boot.
    let cli_link = ctx.home_dir.as_ref().map(|home| {
        home.join(".local")
            .join("bin")
            .join(crate::managed_agents::cli_link_name(ctx.is_dev))
    });
    if let Some(ref link) = cli_link {
        match std::fs::remove_file(link) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                eprintln!(
                    "ambush-desktop reset: delete CLI link {}: {error}",
                    link.display()
                );
                return ResetOutcome {
                    completed: false,
                    failed: true,
                };
            }
        }
    }
    for (_, trash) in &staged {
        let _ = std::fs::remove_dir_all(trash);
    }

    // Verify both halves of the move-and-sweep transaction plus all keychains.
    let keychain_ok = std::iter::once(ctx.keychain)
        .chain(ctx.predecessor_keychains.iter().copied())
        .all(ResetKeychain::verify_fully_wiped);
    let originals_gone = staged.iter().all(|(original, _)| path_is_absent(original));
    let trash_gone = staged.iter().all(|(_, trash)| path_is_absent(trash));
    let cli_link_gone = cli_link
        .as_ref()
        .map(|path| path_is_absent(path))
        .unwrap_or(true);

    if !keychain_ok || !originals_gone || !trash_gone || !cli_link_gone {
        eprintln!(
            "ambush-desktop reset: verification failed (keychain_wiped={keychain_ok}, \
             originals_gone={originals_gone}, trash_gone={trash_gone}, \
             cli_link_gone={cli_link_gone})"
        );
        return ResetOutcome {
            completed: false,
            failed: true,
        };
    }

    // ── Step 7: delete sentinel → success ────────────────────────────────────
    if let Err(e) = delete_reset_sentinel(app_data_dir) {
        eprintln!("ambush-desktop reset: delete sentinel: {e}");
        return ResetOutcome {
            completed: false,
            failed: true,
        };
    }

    ResetOutcome {
        completed: true,
        failed: false,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
