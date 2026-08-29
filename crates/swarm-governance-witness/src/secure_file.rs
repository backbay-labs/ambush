use rustix::fs::{FileType, Mode, OFlags, Stat, fstat, lstat, open};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

const PRIVATE_MODE_MASK: u32 = 0o177;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StableFilePolicyV1 {
    Private,
    Public,
}

#[derive(Debug, thiserror::Error)]
pub enum StableFileErrorV1 {
    #[error("stable file path or metadata is invalid")]
    Metadata,
    #[error("stable file exceeds its configured bound")]
    Bounds,
    #[error("stable file changed while it was read")]
    Changed,
    #[error("stable file read failed")]
    Read,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StableReadStageV1 {
    AfterOpen,
    AfterFirstRead,
    BetweenReads,
    AfterSecondRead,
}

fn same_identity(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
        && left.st_mode == right.st_mode
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_nlink == right.st_nlink
}

fn validate_metadata(
    metadata: &Stat,
    maximum: usize,
    policy: StableFilePolicyV1,
) -> Result<(), StableFileErrorV1> {
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_nlink != 1
        || metadata.st_size <= 0
        || usize::try_from(metadata.st_size)
            .ok()
            .is_none_or(|size| size > maximum)
    {
        return Err(StableFileErrorV1::Metadata);
    }
    if policy == StableFilePolicyV1::Private
        && (metadata.st_uid != rustix::process::geteuid().as_raw()
            || (metadata.st_mode as u32 & PRIVATE_MODE_MASK) != 0)
    {
        return Err(StableFileErrorV1::Metadata);
    }
    Ok(())
}

pub(crate) fn read_stable_file(
    path: impl AsRef<Path>,
    maximum: usize,
    policy: StableFilePolicyV1,
) -> Result<Zeroizing<Vec<u8>>, StableFileErrorV1> {
    read_stable_file_inner(path.as_ref(), maximum, policy, |_| {})
}

fn read_stable_file_inner<F>(
    path: &Path,
    maximum: usize,
    policy: StableFilePolicyV1,
    mut at_stage: F,
) -> Result<Zeroizing<Vec<u8>>, StableFileErrorV1>
where
    F: FnMut(StableReadStageV1),
{
    if maximum == 0 {
        return Err(StableFileErrorV1::Bounds);
    }
    let before = lstat(path).map_err(|_| StableFileErrorV1::Metadata)?;
    validate_metadata(&before, maximum, policy)?;
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| StableFileErrorV1::Metadata)?;
    let opened = fstat(&descriptor).map_err(|_| StableFileErrorV1::Metadata)?;
    validate_metadata(&opened, maximum, policy)?;
    if !same_identity(&before, &opened) {
        return Err(StableFileErrorV1::Changed);
    }
    at_stage(StableReadStageV1::AfterOpen);
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(opened.st_size).map_err(|_| StableFileErrorV1::Bounds)?,
    ));
    let limit = u64::try_from(maximum)
        .map_err(|_| StableFileErrorV1::Bounds)?
        .checked_add(1)
        .ok_or(StableFileErrorV1::Bounds)?;
    let mut file = File::from(descriptor);
    (&mut file)
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| StableFileErrorV1::Read)?;
    at_stage(StableReadStageV1::AfterFirstRead);
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(StableFileErrorV1::Bounds);
    }
    let after_read = fstat(&file).map_err(|_| StableFileErrorV1::Changed)?;
    validate_metadata(&after_read, maximum, policy).map_err(|_| StableFileErrorV1::Changed)?;
    if !same_identity(&opened, &after_read) {
        return Err(StableFileErrorV1::Changed);
    }
    at_stage(StableReadStageV1::BetweenReads);
    let after_descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| StableFileErrorV1::Changed)?;
    let after_open = fstat(&after_descriptor).map_err(|_| StableFileErrorV1::Changed)?;
    validate_metadata(&after_open, maximum, policy).map_err(|_| StableFileErrorV1::Changed)?;
    if !same_identity(&opened, &after_open) {
        return Err(StableFileErrorV1::Changed);
    }
    let mut reopened = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut reopened_file = File::from(after_descriptor);
    (&mut reopened_file)
        .take(limit)
        .read_to_end(&mut reopened)
        .map_err(|_| StableFileErrorV1::Read)?;
    at_stage(StableReadStageV1::AfterSecondRead);
    if reopened.is_empty() || reopened.len() > maximum {
        return Err(StableFileErrorV1::Bounds);
    }
    let after_reopened_read = fstat(&reopened_file).map_err(|_| StableFileErrorV1::Changed)?;
    validate_metadata(&after_reopened_read, maximum, policy)
        .map_err(|_| StableFileErrorV1::Changed)?;
    let after_path = lstat(path).map_err(|_| StableFileErrorV1::Changed)?;
    if bytes.as_slice() != reopened.as_slice()
        || !same_identity(&opened, &after_reopened_read)
        || !same_identity(&opened, &after_path)
    {
        return Err(StableFileErrorV1::Changed);
    }
    Ok(bytes)
}

#[cfg(test)]
fn read_stable_file_with_hook<F>(
    path: impl AsRef<Path>,
    maximum: usize,
    policy: StableFilePolicyV1,
    at_stage: F,
) -> Result<Zeroizing<Vec<u8>>, StableFileErrorV1>
where
    F: FnMut(StableReadStageV1),
{
    read_stable_file_inner(path.as_ref(), maximum, policy, at_stage)
}

pub(crate) fn validate_stable_public_file(
    path: impl AsRef<Path>,
    maximum: usize,
) -> Result<(), StableFileErrorV1> {
    read_stable_file(path, maximum, StableFilePolicyV1::Public).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, FileTimes, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_ROOT: AtomicUsize = AtomicUsize::new(0);

    fn must<T, E: std::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error:?}"),
        }
    }

    fn test_root(label: &str) -> Result<std::path::PathBuf, std::io::Error> {
        let root = std::env::temp_dir().join(format!(
            "phase285-r1b-secure-file-{}-{label}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&root)?;
        Ok(root)
    }

    fn create_private(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    #[test]
    fn private_reader_is_nofollow_bounded_and_mode_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = test_root("baseline")?;
        let private = root.join("private.json");
        create_private(&private, b"secret")?;
        assert_eq!(
            read_stable_file(&private, 6, StableFilePolicyV1::Private)?.as_slice(),
            b"secret"
        );
        assert!(read_stable_file(&private, 5, StableFilePolicyV1::Private).is_err());
        fs::set_permissions(&private, fs::Permissions::from_mode(0o640))?;
        assert!(read_stable_file(&private, 6, StableFilePolicyV1::Private).is_err());
        fs::set_permissions(&private, fs::Permissions::from_mode(0o600))?;
        let alias = root.join("alias.json");
        symlink(&private, &alias)?;
        assert!(read_stable_file(&alias, 6, StableFilePolicyV1::Private).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn hardlinks_nonregular_files_and_wrong_owner_metadata_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("metadata")?;
        let private = root.join("private.json");
        create_private(&private, b"secret")?;
        let hardlink = root.join("hardlink.json");
        fs::hard_link(&private, &hardlink)?;
        assert!(matches!(
            read_stable_file(&private, 6, StableFilePolicyV1::Private),
            Err(StableFileErrorV1::Metadata)
        ));
        assert!(matches!(
            read_stable_file(&root, 4_096, StableFilePolicyV1::Public),
            Err(StableFileErrorV1::Metadata)
        ));
        let fifo_path = root.join("nonregular.fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo_path)
                .status()?
                .success()
        );
        assert!(matches!(
            read_stable_file(&fifo_path, 4_096, StableFilePolicyV1::Public),
            Err(StableFileErrorV1::Metadata)
        ));

        let mut synthetic = lstat(&private)?;
        synthetic.st_nlink = 1;
        synthetic.st_uid = synthetic.st_uid.wrapping_add(1);
        assert!(validate_metadata(&synthetic, 6, StableFilePolicyV1::Private).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn post_read_descriptor_check_rejects_growth() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("growth")?;
        let private = root.join("private.json");
        create_private(&private, b"secret")?;
        let growing = private.clone();
        let result =
            read_stable_file_with_hook(&private, 16, StableFilePolicyV1::Private, move |stage| {
                if stage == StableReadStageV1::AfterFirstRead {
                    let mut file = must(
                        OpenOptions::new().append(true).open(&growing),
                        "open growing file",
                    );
                    must(file.write_all(b"-growth"), "append growth");
                    must(file.sync_all(), "sync growth");
                }
            });
        assert!(matches!(result, Err(StableFileErrorV1::Changed)));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn path_replacement_between_reads_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("replacement")?;
        let private = root.join("private.json");
        create_private(&private, b"secret")?;
        let replaced = private.clone();
        let backup = root.join("original.json");
        let result =
            read_stable_file_with_hook(&private, 6, StableFilePolicyV1::Private, move |stage| {
                if stage == StableReadStageV1::BetweenReads {
                    must(fs::rename(&replaced, &backup), "rename original");
                    must(create_private(&replaced, b"secret"), "create replacement");
                }
            });
        assert!(matches!(result, Err(StableFileErrorV1::Changed)));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn in_place_rewrite_between_reads_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("rewrite")?;
        let private = root.join("private.json");
        create_private(&private, b"secret")?;
        let original_modified = fs::metadata(&private)?.modified()?;
        let rewritten = private.clone();
        let result =
            read_stable_file_with_hook(&private, 6, StableFilePolicyV1::Private, move |stage| {
                if stage == StableReadStageV1::BetweenReads {
                    let mut file = must(
                        OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .open(&rewritten),
                        "open rewritten file",
                    );
                    must(file.write_all(b"public"), "rewrite file");
                    must(file.sync_all(), "sync rewrite");
                    must(
                        file.set_times(FileTimes::new().set_modified(original_modified)),
                        "restore original mtime",
                    );
                }
            });
        assert!(matches!(result, Err(StableFileErrorV1::Changed)));
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
