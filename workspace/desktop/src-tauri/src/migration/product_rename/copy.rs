use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";
const BACKUP_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) fn merge_tree_no_clobber(src: &Path, dst: &Path) -> Result<(), String> {
    validate_sibling_roots(src, dst)?;
    preflight_directory(src, dst)?;
    ensure_directory(dst)?;
    merge_directory(src, dst)
}

pub(super) fn merge_tree_no_clobber_unrelated(src: &Path, dst: &Path) -> Result<(), String> {
    validate_regular_roots(src, dst)?;
    preflight_directory(src, dst)?;
    ensure_directory(dst)?;
    merge_directory(src, dst)
}

fn preflight_directory(src: &Path, dst: &Path) -> Result<(), String> {
    for entry in std::fs::read_dir(src)
        .map_err(|error| format!("read source directory {}: {error}", src.display()))?
    {
        let entry = entry.map_err(|error| format!("read source entry: {error}"))?;
        if entry.file_name() == super::KEYRING_MIGRATION_MARKER {
            continue;
        }
        let source = entry.path();
        let destination = dst.join(entry.file_name());
        let source_metadata = std::fs::symlink_metadata(&source)
            .map_err(|error| format!("inspect source {}: {error}", source.display()))?;
        if source_metadata.file_type().is_symlink() {
            return Err(format!(
                "refusing migration source symlink {}",
                source.display()
            ));
        }
        if !source_metadata.is_dir() && !source_metadata.is_file() {
            return Err(format!(
                "refusing non-regular migration source {}",
                source.display()
            ));
        }
        match std::fs::symlink_metadata(&destination) {
            Ok(destination_metadata) => {
                if destination_metadata.file_type().is_symlink() {
                    return Err(format!(
                        "refusing destination symlink {}",
                        destination.display()
                    ));
                }
                if (!destination_metadata.is_dir() && !destination_metadata.is_file())
                    || source_metadata.is_dir() != destination_metadata.is_dir()
                {
                    return Err(format!(
                        "migration type collision at {}",
                        destination.display()
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "inspect destination {}: {error}",
                    destination.display()
                ));
            }
        }
        if source_metadata.is_dir() {
            preflight_directory(&source, &destination)?;
        } else {
            let _ = is_sqlite_sidecar(&source)?;
        }
    }
    Ok(())
}

fn validate_sibling_roots(src: &Path, dst: &Path) -> Result<(), String> {
    validate_regular_roots(src, dst)?;
    let source_parent = src
        .parent()
        .ok_or_else(|| format!("source {} has no parent", src.display()))?
        .canonicalize()
        .map_err(|error| format!("resolve source parent: {error}"))?;
    let destination_parent = dst
        .parent()
        .ok_or_else(|| format!("destination {} has no parent", dst.display()))?
        .canonicalize()
        .map_err(|error| format!("resolve destination parent: {error}"))?;
    if source_parent != destination_parent {
        return Err("migration source and destination must share one canonical parent".to_string());
    }
    Ok(())
}

fn validate_regular_roots(src: &Path, dst: &Path) -> Result<(), String> {
    let source_metadata = std::fs::symlink_metadata(src)
        .map_err(|error| format!("inspect source {}: {error}", src.display()))?;
    if !source_metadata.file_type().is_dir() || source_metadata.file_type().is_symlink() {
        return Err(format!(
            "source {} is not a regular directory",
            src.display()
        ));
    }

    let destination_parent = dst
        .parent()
        .ok_or_else(|| format!("destination {} has no parent", dst.display()))?;
    // Knowledge-only nest migration can be the first writer of the current
    // nest. Create exactly that missing parent while retaining the no-symlink
    // check; recursive creation would make unvalidated ancestors part of the
    // migration boundary.
    ensure_directory(destination_parent)?;
    match std::fs::symlink_metadata(dst) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => {
            return Err(format!(
                "destination {} is not a regular directory",
                dst.display()
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect destination {}: {error}", dst.display())),
    }
    Ok(())
}

fn ensure_directory(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(format!("{} is not a regular directory", path.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            std::fs::create_dir(path)
                .map_err(|error| format!("create directory {}: {error}", path.display()))?;
            sync_parent(path)
        }
        Err(error) => Err(format!("inspect directory {}: {error}", path.display())),
    }
}

fn merge_directory(src: &Path, dst: &Path) -> Result<(), String> {
    for (kind, path) in [("source", src), ("destination", dst)] {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| format!("inspect {kind} directory {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "{kind} {} is not a regular directory",
                path.display()
            ));
        }
    }
    for entry in std::fs::read_dir(src)
        .map_err(|error| format!("read source directory {}: {error}", src.display()))?
    {
        let entry = entry.map_err(|error| format!("read source entry: {error}"))?;
        if entry.file_name() == super::KEYRING_MIGRATION_MARKER {
            continue;
        }
        let source = entry.path();
        let destination = dst.join(entry.file_name());
        let metadata = std::fs::symlink_metadata(&source)
            .map_err(|error| format!("inspect source {}: {error}", source.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "refusing migration source symlink {}",
                source.display()
            ));
        }
        if metadata.is_dir() {
            ensure_directory(&destination)?;
            merge_directory(&source, &destination)?;
        } else if metadata.is_file() {
            if is_sqlite_sidecar(&source)? {
                continue;
            }
            copy_file_no_clobber(&source, &destination, &metadata)?;
        } else {
            return Err(format!(
                "refusing non-regular migration source {}",
                source.display()
            ));
        }
    }
    Ok(())
}

fn copy_file_no_clobber(
    src: &Path,
    dst: &Path,
    source_metadata: &std::fs::Metadata,
) -> Result<(), String> {
    match std::fs::symlink_metadata(dst) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(format!("refusing destination symlink {}", dst.display()));
        }
        Ok(metadata) if metadata.is_file() => return Ok(()),
        Ok(_) => {
            return Err(format!(
                "destination {} is not a regular file",
                dst.display()
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect destination {}: {error}", dst.display())),
    }

    if has_sqlite_header(src)? {
        backup_sqlite_no_clobber(src, dst)?;
    } else {
        copy_regular_no_clobber(src, dst, source_metadata)?;
    }
    Ok(())
}

fn copy_regular_no_clobber(
    src: &Path,
    dst: &Path,
    source_metadata: &std::fs::Metadata,
) -> Result<(), String> {
    let mut source = open_source_nofollow(src)?;
    let parent = dst
        .parent()
        .ok_or_else(|| format!("destination {} has no parent", dst.display()))?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".ambush-migrate-")
        .tempfile_in(parent)
        .map_err(|error| format!("create temporary file in {}: {error}", parent.display()))?;
    io::copy(&mut source, &mut temporary)
        .map_err(|error| format!("copy {}: {error}", src.display()))?;
    temporary
        .as_file()
        .set_permissions(source_metadata.permissions())
        .map_err(|error| format!("set migrated permissions: {error}"))?;
    temporary
        .as_file_mut()
        .flush()
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|error| format!("sync migrated file {}: {error}", dst.display()))?;
    persist_no_clobber(temporary, dst)
}

fn backup_sqlite_no_clobber(src: &Path, dst: &Path) -> Result<(), String> {
    let parent = dst
        .parent()
        .ok_or_else(|| format!("destination {} has no parent", dst.display()))?;
    let temporary = tempfile::Builder::new()
        .prefix(".ambush-migrate-sqlite-")
        .tempfile_in(parent)
        .map_err(|error| format!("create SQLite backup file: {error}"))?;
    let temporary_path = temporary.into_temp_path();
    // SQLite's NOFOLLOW flag rejects symlinks in any path component. Resolve
    // trusted, preflighted roots first (notably macOS `/var` -> `/private/var`)
    // so the flag protects the database leaf without rejecting the OS temp
    // directory's canonical ancestor.
    let canonical_source = src
        .canonicalize()
        .map_err(|error| format!("resolve SQLite source {}: {error}", src.display()))?;
    let canonical_temporary = temporary_path
        .canonicalize()
        .map_err(|error| format!("resolve SQLite backup {}: {error}", dst.display()))?;

    let source = rusqlite::Connection::open_with_flags(
        &canonical_source,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|error| format!("open SQLite source {}: {error}", src.display()))?;
    let mut destination = rusqlite::Connection::open_with_flags(
        &canonical_temporary,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|error| format!("open SQLite backup {}: {error}", dst.display()))?;
    let backup = rusqlite::backup::Backup::new(&source, &mut destination)
        .map_err(|error| format!("start SQLite backup {}: {error}", src.display()))?;
    let deadline = Instant::now() + BACKUP_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out backing up live SQLite {}",
                src.display()
            ));
        }
        match backup
            .step(128)
            .map_err(|error| format!("back up SQLite {}: {error}", src.display()))?
        {
            rusqlite::backup::StepResult::Done => break,
            rusqlite::backup::StepResult::More => {}
            rusqlite::backup::StepResult::Busy | rusqlite::backup::StepResult::Locked => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                return Err(format!(
                    "unexpected SQLite backup state for {}",
                    src.display()
                ))
            }
        }
    }
    drop(backup);
    destination
        .close()
        .map_err(|(_, error)| format!("close SQLite backup {}: {error}", dst.display()))?;
    drop(source);
    // Windows refuses `FlushFileBuffers` on a read-only handle (os error 5),
    // so the durable flush opens the backup for write; the temporary file is
    // owner-only and nothing else holds it once both connections are closed.
    OpenOptions::new()
        .write(true)
        .open(&temporary_path)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("sync SQLite backup {}: {error}", dst.display()))?;
    match temporary_path.persist_noclobber(dst) {
        Ok(()) => sync_parent(dst),
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(format!(
            "commit SQLite backup {}: {}",
            dst.display(),
            error.error
        )),
    }
}

fn persist_no_clobber(temporary: tempfile::NamedTempFile, dst: &Path) -> Result<(), String> {
    match temporary.persist_noclobber(dst) {
        Ok(file) => {
            file.sync_all()
                .map_err(|error| format!("sync committed file {}: {error}", dst.display()))?;
            sync_parent(dst)
        }
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(format!(
            "commit migrated file {}: {}",
            dst.display(),
            error.error
        )),
    }
}

fn has_sqlite_header(path: &Path) -> Result<bool, String> {
    let mut file = open_source_nofollow(path)?;
    let mut header = [0_u8; SQLITE_HEADER.len()];
    match file.read_exact(&mut header) {
        Ok(()) => Ok(&header == SQLITE_HEADER),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(format!("read source header {}: {error}", path.display())),
    }
}

fn is_sqlite_sidecar(path: &Path) -> Result<bool, String> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("non-UTF-8 migration filename {}", path.display()))?;
    let Some(base) = ["-wal", "-shm", "-journal"]
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix))
    else {
        return Ok(false);
    };
    let database = path.with_file_name(base);
    match std::fs::symlink_metadata(&database) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            if has_sqlite_header(&database)? {
                Ok(true)
            } else {
                Err(format!(
                    "refusing sidecar {} without a valid SQLite database",
                    path.display()
                ))
            }
        }
        _ => Err(format!("refusing orphan SQLite sidecar {}", path.display())),
    }
}

fn open_source_nofollow(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .map_err(|error| format!("open source {}: {error}", path.display()))
}

fn sync_parent(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .ok_or_else(|| format!("{} has no parent", path.display()))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("sync directory {}: {error}", parent.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_is_no_clobber_and_retries_after_stale_temporary_file() {
        let root = tempfile::tempdir().unwrap();
        let src = root.path().join("source");
        let dst = root.path().join("destination");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("current.txt"), "legacy").unwrap();
        std::fs::write(dst.join("current.txt"), "current").unwrap();
        std::fs::write(src.join("retry.txt"), "complete").unwrap();
        std::fs::write(dst.join(".ambush-migrate-killed"), "partial").unwrap();

        merge_tree_no_clobber(&src, &dst).unwrap();

        assert_eq!(
            std::fs::read_to_string(dst.join("current.txt")).unwrap(),
            "current"
        );
        assert_eq!(
            std::fs::read_to_string(dst.join("retry.txt")).unwrap(),
            "complete"
        );
    }

    #[test]
    fn live_wal_database_is_backed_up_consistently_without_sidecars() {
        let root = tempfile::tempdir().unwrap();
        let src = root.path().join("source");
        let dst = root.path().join("destination");
        std::fs::create_dir_all(&src).unwrap();
        let connection = rusqlite::Connection::open(src.join("state.db")).unwrap();
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .unwrap();
        connection
            .pragma_update(None, "wal_autocheckpoint", 0)
            .unwrap();
        connection
            .execute_batch("CREATE TABLE state(value TEXT); INSERT INTO state VALUES ('wal-row');")
            .unwrap();

        merge_tree_no_clobber(&src, &dst).unwrap();

        assert!(!dst.join("state.db-wal").exists());
        assert!(!dst.join("state.db-shm").exists());
        let migrated = rusqlite::Connection::open(dst.join("state.db")).unwrap();
        let value: String = migrated
            .query_row("SELECT value FROM state", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, "wal-row");
    }

    #[cfg(unix)]
    #[test]
    fn migration_rejects_source_and_destination_symlinks() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let src = root.path().join("source");
        let dst = root.path().join("destination");
        let outside = root.path().join("outside");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        symlink(outside.join("secret"), src.join("escape")).unwrap();
        assert!(merge_tree_no_clobber(&src, &dst)
            .unwrap_err()
            .contains("source symlink"));

        std::fs::remove_file(src.join("escape")).unwrap();
        symlink(&outside, &dst).unwrap();
        assert!(merge_tree_no_clobber(&src, &dst)
            .unwrap_err()
            .contains("destination"));
    }
}
