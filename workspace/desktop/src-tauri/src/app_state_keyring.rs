/// Service name for the desktop OS keyring. Debug builds default to a distinct
/// service, while standalone worktree launches may request a scoped dev service.
fn dev_keyring_service(configured: Option<String>) -> String {
    match configured {
        None => "ambush-desktop-dev".to_string(),
        Some(service)
            if service
                .strip_prefix("ambush-desktop-dev.")
                .is_some_and(crate::migration::valid_instance_scope) =>
        {
            service
        }
        Some(service) => panic!("invalid AMBUSH_DEV_KEYRING_SERVICE {service:?}"),
    }
}

pub(crate) fn keyring_service() -> &'static str {
    if cfg!(debug_assertions) {
        static DEV_SERVICE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        DEV_SERVICE
            .get_or_init(|| dev_keyring_service(std::env::var("AMBUSH_DEV_KEYRING_SERVICE").ok()))
            .as_str()
    } else {
        "ambush-desktop"
    }
}

pub(super) fn migration_marker_name(service: &str, default_name: &str) -> String {
    if service == "ambush-desktop" || service == "ambush-desktop-dev" {
        default_name.to_string()
    } else {
        format!("identity.{service}.migrated")
    }
}

#[cfg(test)]
mod tests {
    use super::{dev_keyring_service, migration_marker_name};

    #[test]
    fn standalone_scope_must_remain_under_dev_service() {
        assert_eq!(
            dev_keyring_service(Some("ambush-desktop-dev.example".to_string())),
            "ambush-desktop-dev.example"
        );
        for invalid in [
            "ambush-desktop",
            "ambush-desktop-dev../escape",
            "ambush-desktop-devil.example",
        ] {
            assert!(std::panic::catch_unwind(|| {
                dev_keyring_service(Some(invalid.to_string()))
            })
            .is_err());
        }
    }

    #[test]
    fn standalone_scope_uses_its_own_migration_marker() {
        assert_eq!(
            migration_marker_name("ambush-desktop", "identity.migrated"),
            "identity.migrated"
        );
        assert_eq!(
            migration_marker_name("ambush-desktop-dev", "identity.migrated"),
            "identity.migrated"
        );
        assert_eq!(
            migration_marker_name("ambush-desktop-dev.example", "identity.migrated"),
            "identity.ambush-desktop-dev.example.migrated"
        );
    }
}
