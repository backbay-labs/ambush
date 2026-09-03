use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

const DEV_SERVICE: &str = "ambush-desktop-dev";
const REGISTRY_DIR: &str = "keyring-services-v1";
const REGISTRY_MARKER: &[u8] = b"1\n";
const MAX_REGISTERED_SERVICES: usize = 256;

pub(crate) fn register_current_dev_service(service: &str) -> Result<(), String> {
    let Some(home) = dirs::home_dir() else {
        return Err("cannot resolve home directory for dev keyring registry".to_string());
    };
    register_at(&home, service)
}

fn validate_service(service: &str) -> Result<(), String> {
    if service == DEV_SERVICE {
        return Ok(());
    }
    let scope = service
        .strip_prefix(&format!("{DEV_SERVICE}."))
        .ok_or_else(|| format!("refusing non-Ambush dev keyring service {service:?}"))?;
    if !crate::migration::valid_instance_scope(scope) {
        return Err(format!("invalid Ambush dev keyring service {service:?}"));
    }
    Ok(())
}

fn ensure_regular_directory(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(format!("{} is not a regular directory", path.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => match std::fs::create_dir(path) {
            Ok(()) => {
                let parent = path.parent().ok_or_else(|| {
                    format!("registry directory {} has no parent", path.display())
                })?;
                sync_directory(parent)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                ensure_regular_directory(path)
            }
            Err(error) => Err(format!(
                "create registry directory {}: {error}",
                path.display()
            )),
        },
        Err(error) => Err(format!(
            "inspect registry directory {}: {error}",
            path.display()
        )),
    }
}

fn registry_marker_is_exact(path: &Path) -> Result<bool, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|error| format!("safely open registry marker {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect open registry marker {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() != REGISTRY_MARKER.len() as u64 {
        return Ok(false);
    }
    let mut contents = Vec::with_capacity(REGISTRY_MARKER.len() + 1);
    file.take(REGISTRY_MARKER.len() as u64 + 1)
        .read_to_end(&mut contents)
        .map_err(|error| format!("read registry marker {}: {error}", path.display()))?;
    Ok(contents == REGISTRY_MARKER)
}

fn register_at(home: &Path, service: &str) -> Result<(), String> {
    validate_service(service)?;
    let nest = home.join(".ambush-dev");
    ensure_regular_directory(&nest)?;
    let registry = nest.join(REGISTRY_DIR);
    ensure_regular_directory(&registry)?;

    let entries = std::fs::read_dir(&registry)
        .map_err(|error| format!("read keyring service registry: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("read keyring service registry entry: {error}"))?;
    if entries.len() > MAX_REGISTERED_SERVICES
        || (entries.len() == MAX_REGISTERED_SERVICES
            && !entries.iter().any(|entry| entry.file_name() == service))
    {
        return Err(format!(
            "keyring service registry exceeds {MAX_REGISTERED_SERVICES} entries"
        ));
    }
    for entry in &entries {
        let registered_service = entry
            .file_name()
            .into_string()
            .map_err(|_| "keyring service registry contains a non-UTF-8 name".to_string())?;
        validate_service(&registered_service)?;
        let entry_path = entry.path();
        let metadata = std::fs::symlink_metadata(&entry_path)
            .map_err(|error| format!("inspect registry marker: {error}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || !registry_marker_is_exact(&entry_path)?
        {
            return Err(format!(
                "registry marker {} is not an exact regular marker",
                entry_path.display()
            ));
        }
    }

    let marker = registry.join(service);
    match std::fs::symlink_metadata(&marker) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            if registry_marker_is_exact(&marker)? {
                return Ok(());
            }
            return Err(format!(
                "registry marker {} has invalid contents",
                marker.display()
            ));
        }
        Ok(_) => {
            return Err(format!(
                "registry marker {} is not regular",
                marker.display()
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect registry marker: {error}")),
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&marker)
        .map_err(|error| format!("create registry marker {}: {error}", marker.display()))?;
    file.write_all(REGISTRY_MARKER)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("sync registry marker {}: {error}", marker.display()))?;
    sync_directory(&registry)?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync registry directory {}: {error}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn registry(home: &Path) -> PathBuf {
        home.join(".ambush-dev").join(REGISTRY_DIR)
    }

    #[test]
    fn records_exact_services_idempotently_and_rejects_prefix_collisions() {
        let home = tempfile::tempdir().unwrap();
        register_at(home.path(), "ambush-desktop-dev.tree-deadbeef").unwrap();
        register_at(home.path(), "ambush-desktop-dev.tree-deadbeef").unwrap();
        assert_eq!(
            std::fs::read(registry(home.path()).join("ambush-desktop-dev.tree-deadbeef")).unwrap(),
            REGISTRY_MARKER
        );
        assert!(register_at(home.path(), "ambush-desktop-devil.tree").is_err());
        assert!(register_at(home.path(), "ambush-desktop-dev../escape").is_err());
    }

    #[test]
    fn registry_is_bounded_and_fails_closed_on_corrupt_or_linked_markers() {
        let home = tempfile::tempdir().unwrap();
        let registry_path = registry(home.path());
        std::fs::create_dir_all(&registry_path).unwrap();
        for index in 0..MAX_REGISTERED_SERVICES {
            std::fs::write(
                registry_path.join(format!("ambush-desktop-dev.existing-{index}")),
                REGISTRY_MARKER,
            )
            .unwrap();
        }
        assert!(register_at(home.path(), "ambush-desktop-dev.new")
            .unwrap_err()
            .contains("exceeds"));

        let corrupt_home = tempfile::tempdir().unwrap();
        let corrupt_registry = registry(corrupt_home.path());
        std::fs::create_dir_all(&corrupt_registry).unwrap();
        std::fs::write(corrupt_registry.join(DEV_SERVICE), "bad\n").unwrap();
        assert!(register_at(corrupt_home.path(), DEV_SERVICE).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let linked_home = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            std::fs::create_dir(linked_home.path().join(".ambush-dev")).unwrap();
            symlink(outside.path(), registry(linked_home.path())).unwrap();
            assert!(register_at(linked_home.path(), DEV_SERVICE).is_err());

            let linked_marker_home = tempfile::tempdir().unwrap();
            let linked_marker_registry = registry(linked_marker_home.path());
            std::fs::create_dir_all(&linked_marker_registry).unwrap();
            let outside_marker = outside.path().join("marker");
            std::fs::write(&outside_marker, REGISTRY_MARKER).unwrap();
            symlink(
                &outside_marker,
                linked_marker_registry.join("ambush-desktop-dev.linked"),
            )
            .unwrap();
            assert!(register_at(linked_marker_home.path(), DEV_SERVICE).is_err());
        }
    }
}
