//! Startup bridge for the Sprout -> Buzz -> Ambush product rename chain.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tauri::Manager;

const AMBUSH_RELEASE_IDENTIFIER: &str = "com.backbay.ambush.app";
const AMBUSH_DEV_IDENTIFIER: &str = "com.backbay.ambush.app.dev";
const BUZZ_RELEASE_IDENTIFIER: &str = "xyz.block.buzz.app";
const BUZZ_DEV_IDENTIFIER: &str = "xyz.block.buzz.app.dev";
const SPROUT_RELEASE_IDENTIFIER: &str = "xyz.block.sprout.app";
const SPROUT_DEV_IDENTIFIER: &str = "xyz.block.sprout.app.dev";
const KEYRING_MIGRATION_MARKER: &str = ".ambush-product-keyring-migrated-v1";

fn push_unique<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn dev_scope(name: &str) -> Option<&str> {
    if name == AMBUSH_DEV_IDENTIFIER {
        Some("")
    } else {
        name.strip_prefix(AMBUSH_DEV_IDENTIFIER)?.strip_prefix('.')
    }
}

fn scoped(base: &str, scope: &str) -> String {
    if scope.is_empty() {
        base.to_string()
    } else {
        format!("{base}.{scope}")
    }
}

/// Shipped predecessor data directories with the same instance suffix.
#[cfg(test)]
pub(super) fn legacy_app_data_dirs(current: &Path) -> Vec<PathBuf> {
    app_data_sources_for_scopes(current, None, None)
}

pub(crate) fn app_data_migration_sources(current: &Path) -> Vec<PathBuf> {
    app_data_sources_for_scopes(
        current,
        std::env::var("AMBUSH_WORKTREE_PATH_SLUG").ok().as_deref(),
        std::env::var("AMBUSH_LEGACY_BRANCH_SLUG").ok().as_deref(),
    )
}

fn app_data_sources_for_scopes(
    current: &Path,
    worktree_scope: Option<&str>,
    branch_scope: Option<&str>,
) -> Vec<PathBuf> {
    let Some(parent) = current.parent() else {
        return Vec::new();
    };
    let Some(name) = current.file_name().and_then(|value| value.to_str()) else {
        return Vec::new();
    };
    if name == AMBUSH_RELEASE_IDENTIFIER {
        return vec![
            parent.join(BUZZ_RELEASE_IDENTIFIER),
            parent.join(SPROUT_RELEASE_IDENTIFIER),
        ];
    }
    let Some(current_scope) = dev_scope(name) else {
        return Vec::new();
    };

    let mut sources = Vec::new();
    if !current_scope.is_empty() {
        if let Some(scope) = worktree_scope.filter(|scope| !scope.is_empty()) {
            push_unique(
                &mut sources,
                parent.join(scoped(AMBUSH_DEV_IDENTIFIER, scope)),
            );
        }
        if let Some(scope) = branch_scope.filter(|scope| !scope.is_empty()) {
            push_unique(
                &mut sources,
                parent.join(scoped(BUZZ_DEV_IDENTIFIER, scope)),
            );
        }
    }
    push_unique(
        &mut sources,
        parent.join(scoped(BUZZ_DEV_IDENTIFIER, current_scope)),
    );
    if !current_scope.is_empty() {
        if let Some(scope) = branch_scope.filter(|scope| !scope.is_empty()) {
            push_unique(
                &mut sources,
                parent.join(scoped(SPROUT_DEV_IDENTIFIER, scope)),
            );
        }
    }
    push_unique(
        &mut sources,
        parent.join(scoped(SPROUT_DEV_IDENTIFIER, current_scope)),
    );
    sources
}

/// Ordered predecessor services. The immediately previous Buzz service wins
/// over Sprout; current Ambush entries win over every predecessor.
pub(super) fn legacy_keyring_services(
    current_service: &str,
    worktree_scope: Option<&str>,
    branch_scope: Option<&str>,
) -> Vec<String> {
    if current_service == "ambush-desktop" {
        return vec!["buzz-desktop".to_string(), "sprout-desktop".to_string()];
    }
    if current_service == "ambush-desktop-dev" {
        return vec![
            "buzz-desktop-dev".to_string(),
            "sprout-desktop-dev".to_string(),
        ];
    }
    let Some(current_scope) = current_service.strip_prefix("ambush-desktop-dev.") else {
        return Vec::new();
    };

    let mut services = Vec::new();
    if let Some(scope) = worktree_scope.filter(|scope| !scope.is_empty()) {
        push_unique(&mut services, format!("ambush-desktop-dev.{scope}"));
    }
    if let Some(scope) = branch_scope.filter(|scope| !scope.is_empty()) {
        push_unique(&mut services, format!("buzz-desktop-dev.{scope}"));
    }
    push_unique(&mut services, format!("buzz-desktop-dev.{current_scope}"));
    if let Some(scope) = branch_scope.filter(|scope| !scope.is_empty()) {
        push_unique(&mut services, format!("sprout-desktop-dev.{scope}"));
    }
    push_unique(&mut services, format!("sprout-desktop-dev.{current_scope}"));
    services
}

pub(super) fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        if entry.file_name() == KEYRING_MIGRATION_MARKER {
            continue;
        }
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let metadata = std::fs::symlink_metadata(&src_path)?;
        if metadata.file_type().is_symlink() {
            #[cfg(unix)]
            {
                if dst_path.exists() || dst_path.is_symlink() {
                    continue;
                }
                let target = std::fs::read_link(&src_path)?;
                crate::util::create_symlink(&target, &dst_path)?;
            }
            #[cfg(not(unix))]
            {
                continue;
            }
        } else if metadata.is_dir() {
            copy_dir_all(&src_path, &dst_path)?;
        } else if metadata.is_file() {
            if let Some(parent) = dst_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            if !dst_path.exists() {
                std::fs::copy(&src_path, &dst_path)?;
            }
        }
    }
    Ok(())
}

pub(super) trait KeyringMigrationStore {
    fn load_all_readonly(&self) -> Result<Option<HashMap<String, String>>, String>;
    fn store_all(&self, entries: &HashMap<String, String>) -> Result<(), String>;
    fn verify_stored_raw(&self, key: &str, expected: &str) -> Result<bool, String>;
}

impl KeyringMigrationStore for crate::secret_store::SecretStore {
    fn load_all_readonly(&self) -> Result<Option<HashMap<String, String>>, String> {
        crate::secret_store::SecretStore::load_all_readonly(self)
    }

    fn store_all(&self, entries: &HashMap<String, String>) -> Result<(), String> {
        crate::secret_store::SecretStore::store_all(self, entries)
    }

    fn verify_stored_raw(&self, key: &str, expected: &str) -> Result<bool, String> {
        crate::secret_store::SecretStore::verify_stored_raw(self, key, expected)
    }
}

/// Copy only absent entries and verify the durable keyring, so a migration
/// cannot replace an established Ambush identity or silently claim success.
pub(super) fn migrate_keyring_entries(
    source: &impl KeyringMigrationStore,
    target: &impl KeyringMigrationStore,
) -> Result<usize, String> {
    let Some(source_entries) = source.load_all_readonly()? else {
        return Ok(0);
    };
    let target_entries = target.load_all_readonly()?.unwrap_or_default();
    let additions = source_entries
        .into_iter()
        .filter(|(key, _)| !target_entries.contains_key(key))
        .collect::<HashMap<_, _>>();
    if additions.is_empty() {
        return Ok(0);
    }

    target.store_all(&additions)?;
    for (key, expected) in &additions {
        if !target.verify_stored_raw(key, expected)? {
            return Err(format!(
                "read-back verification failed for migrated key {key}"
            ));
        }
    }
    Ok(additions.len())
}

fn write_keyring_migration_marker(current_dir: &Path) -> Result<(), String> {
    use atomic_write_file::AtomicWriteFile;
    use std::io::Write;

    std::fs::create_dir_all(current_dir).map_err(|error| {
        format!(
            "cannot create app data directory {} for keyring migration marker: {error}",
            current_dir.display()
        )
    })?;
    let marker = current_dir.join(KEYRING_MIGRATION_MARKER);
    let mut file = AtomicWriteFile::open(&marker).map_err(|error| {
        format!(
            "cannot open keyring migration marker {}: {error}",
            marker.display()
        )
    })?;
    file.write_all(b"complete\n").map_err(|error| {
        format!(
            "cannot write keyring migration marker {}: {error}",
            marker.display()
        )
    })?;
    file.commit().map_err(|error| {
        format!(
            "cannot commit keyring migration marker {}: {error}",
            marker.display()
        )
    })
}

pub(super) fn migrate_legacy_keyring_data(current_dir: &Path) -> Result<(), String> {
    let has_legacy_data = app_data_migration_sources(current_dir)
        .iter()
        .any(|path| path.exists());
    if !has_legacy_data {
        return Ok(());
    }

    #[cfg(feature = "system-keyring")]
    {
        // The predecessor directories are intentionally retained, so bind
        // successful keyring completion to the current app-data directory.
        // Without this marker, a later corrupt/unavailable legacy service
        // could block an already-migrated Ambush identity on every launch.
        let marker = current_dir.join(KEYRING_MIGRATION_MARKER);
        if marker.is_file() {
            return Ok(());
        }
        if marker.exists() {
            return Err(format!(
                "keyring migration marker {} is not a regular file",
                marker.display()
            ));
        }

        let current_service = crate::app_state::keyring_service();
        let worktree_scope = std::env::var("AMBUSH_WORKTREE_PATH_SLUG").ok();
        let branch_scope = std::env::var("AMBUSH_LEGACY_BRANCH_SLUG").ok();
        let services = legacy_keyring_services(
            current_service,
            worktree_scope.as_deref(),
            branch_scope.as_deref(),
        );
        let target = crate::secret_store::SecretStore::shared(current_service);
        for service in services {
            let source = crate::secret_store::SecretStore::keyring(&service);
            let migrated = migrate_keyring_entries(&source, target)
                .map_err(|error| format!("{service} -> {current_service}: {error}"))?;
            if migrated > 0 {
                eprintln!(
                    "ambush-desktop: keyring-migration: copied {migrated} entries from {service} to {current_service}"
                );
            }
        }
        write_keyring_migration_marker(current_dir)?;
    }
    Ok(())
}

fn migrate_legacy_app_data_dirs_at(current_dir: &Path) -> Result<usize, String> {
    let mut migrated = 0;
    for legacy_dir in app_data_migration_sources(current_dir) {
        if !legacy_dir.exists() {
            continue;
        }
        copy_dir_all(&legacy_dir, current_dir).map_err(|error| {
            format!(
                "failed to copy {} to {}: {error}",
                legacy_dir.display(),
                current_dir.display()
            )
        })?;
        eprintln!(
            "ambush-desktop: app-data-migration: copied legacy data from {} to {}",
            legacy_dir.display(),
            current_dir.display()
        );
        migrated += 1;
    }
    Ok(migrated)
}

/// Copy app state before any current-product disk read. Existing destination
/// files are retained; Buzz fills gaps before older Sprout data is considered.
pub(super) fn migrate_legacy_app_data_dir(app: &tauri::AppHandle) -> Result<(), String> {
    let current_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("cannot resolve app data dir: {error}"))?;
    migrate_legacy_app_data_dirs_at(&current_dir)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct FakeKeyringMigrationStore {
        entries: RefCell<Option<HashMap<String, String>>>,
        load_error: Option<String>,
        fail_verification_for: Option<String>,
    }

    impl FakeKeyringMigrationStore {
        fn with_entries(entries: &[(&str, &str)]) -> Self {
            Self {
                entries: RefCell::new(Some(
                    entries
                        .iter()
                        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                        .collect(),
                )),
                ..Self::default()
            }
        }

        fn snapshot(&self) -> HashMap<String, String> {
            self.entries.borrow().clone().unwrap_or_default()
        }
    }

    impl KeyringMigrationStore for FakeKeyringMigrationStore {
        fn load_all_readonly(&self) -> Result<Option<HashMap<String, String>>, String> {
            if let Some(error) = &self.load_error {
                return Err(error.clone());
            }
            Ok(self.entries.borrow().clone())
        }

        fn store_all(&self, entries: &HashMap<String, String>) -> Result<(), String> {
            self.entries
                .borrow_mut()
                .get_or_insert_default()
                .extend(entries.clone());
            Ok(())
        }

        fn verify_stored_raw(&self, key: &str, expected: &str) -> Result<bool, String> {
            if self.fail_verification_for.as_deref() == Some(key) {
                return Ok(false);
            }
            Ok(self
                .entries
                .borrow()
                .as_ref()
                .and_then(|entries| entries.get(key))
                .is_some_and(|value| value == expected))
        }
    }

    #[test]
    fn release_sources_prefer_buzz_before_sprout() {
        let current = PathBuf::from("/data/com.backbay.ambush.app");
        assert_eq!(
            legacy_app_data_dirs(&current),
            vec![
                PathBuf::from("/data/xyz.block.buzz.app"),
                PathBuf::from("/data/xyz.block.sprout.app"),
            ]
        );
        assert_eq!(
            legacy_keyring_services("ambush-desktop", None, None),
            vec!["buzz-desktop", "sprout-desktop"]
        );
    }

    #[test]
    fn scoped_sources_cover_pre_hash_ambush_and_branch_scoped_predecessors() {
        let current = PathBuf::from("/data/com.backbay.ambush.app.dev.tree-ab12cd34");
        assert_eq!(
            app_data_sources_for_scopes(&current, Some("tree"), Some("feature-card")),
            vec![
                PathBuf::from("/data/com.backbay.ambush.app.dev.tree"),
                PathBuf::from("/data/xyz.block.buzz.app.dev.feature-card"),
                PathBuf::from("/data/xyz.block.buzz.app.dev.tree-ab12cd34"),
                PathBuf::from("/data/xyz.block.sprout.app.dev.feature-card"),
                PathBuf::from("/data/xyz.block.sprout.app.dev.tree-ab12cd34"),
            ]
        );
        assert_eq!(
            legacy_keyring_services(
                "ambush-desktop-dev.tree-ab12cd34",
                Some("tree"),
                Some("feature-card"),
            ),
            vec![
                "ambush-desktop-dev.tree",
                "buzz-desktop-dev.feature-card",
                "buzz-desktop-dev.tree-ab12cd34",
                "sprout-desktop-dev.feature-card",
                "sprout-desktop-dev.tree-ab12cd34",
            ]
        );
    }

    #[test]
    fn keyring_migration_preserves_current_identity_and_copies_agent_keys() {
        let source = FakeKeyringMigrationStore::with_entries(&[
            ("identity", "buzz-identity"),
            ("agent:alice", "buzz-agent-key"),
        ]);
        let target = FakeKeyringMigrationStore::with_entries(&[
            ("identity", "ambush-identity"),
            ("agent:bob", "ambush-agent-key"),
        ]);

        assert_eq!(migrate_keyring_entries(&source, &target).unwrap(), 1);
        let migrated = target.snapshot();
        assert_eq!(migrated.get("identity").unwrap(), "ambush-identity");
        assert_eq!(migrated.get("agent:alice").unwrap(), "buzz-agent-key");
        assert_eq!(migrated.get("agent:bob").unwrap(), "ambush-agent-key");
    }

    #[test]
    fn keyring_migration_fails_closed_on_read_or_verification_failure() {
        let unavailable = FakeKeyringMigrationStore {
            load_error: Some("keyring unavailable".to_string()),
            ..FakeKeyringMigrationStore::default()
        };
        assert!(
            migrate_keyring_entries(&unavailable, &FakeKeyringMigrationStore::default())
                .unwrap_err()
                .contains("keyring unavailable")
        );

        let source = FakeKeyringMigrationStore::with_entries(&[("identity", "buzz-identity")]);
        let target = FakeKeyringMigrationStore {
            fail_verification_for: Some("identity".to_string()),
            ..FakeKeyringMigrationStore::default()
        };
        assert!(migrate_keyring_entries(&source, &target)
            .unwrap_err()
            .contains("read-back verification failed"));
    }

    #[test]
    fn app_data_merge_keeps_buzz_precedence_and_surfaces_partial_copy() {
        let root = tempfile::tempdir().unwrap();
        let current = root.path().join(AMBUSH_RELEASE_IDENTIFIER);
        let buzz = root.path().join(BUZZ_RELEASE_IDENTIFIER);
        let sprout = root.path().join(SPROUT_RELEASE_IDENTIFIER);
        std::fs::create_dir_all(&buzz).unwrap();
        std::fs::create_dir_all(&sprout).unwrap();
        std::fs::write(buzz.join("identity.key"), "buzz").unwrap();
        std::fs::write(sprout.join("identity.key"), "sprout").unwrap();
        std::fs::write(sprout.join("sprout-only.json"), "retained").unwrap();
        std::fs::write(buzz.join(KEYRING_MIGRATION_MARKER), "stale\n").unwrap();

        assert_eq!(migrate_legacy_app_data_dirs_at(&current).unwrap(), 2);
        assert_eq!(
            std::fs::read_to_string(current.join("identity.key")).unwrap(),
            "buzz"
        );
        assert_eq!(
            std::fs::read_to_string(current.join("sprout-only.json")).unwrap(),
            "retained"
        );
        assert!(
            !current.join(KEYRING_MIGRATION_MARKER).exists(),
            "a predecessor marker must not suppress migration into a new keyring service"
        );

        let broken_current = root.path().join("broken/com.backbay.ambush.app");
        let broken_buzz = root.path().join("broken/xyz.block.buzz.app");
        std::fs::create_dir_all(broken_buzz.join("agents")).unwrap();
        std::fs::create_dir_all(&broken_current).unwrap();
        std::fs::write(broken_current.join("agents"), "collision").unwrap();
        std::fs::write(broken_buzz.join("agents/managed-agents.json"), "[]").unwrap();
        assert!(migrate_legacy_app_data_dirs_at(&broken_current)
            .unwrap_err()
            .contains("failed to copy"));
    }

    #[test]
    fn keyring_migration_marker_is_atomic_and_fails_closed_on_collision() {
        let root = tempfile::tempdir().unwrap();
        write_keyring_migration_marker(root.path()).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.path().join(KEYRING_MIGRATION_MARKER)).unwrap(),
            "complete\n"
        );

        let blocked = root.path().join("blocked");
        std::fs::create_dir_all(blocked.join(KEYRING_MIGRATION_MARKER)).unwrap();
        assert!(write_keyring_migration_marker(&blocked)
            .unwrap_err()
            .contains(KEYRING_MIGRATION_MARKER));
    }
}
