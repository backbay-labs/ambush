use super::*;

use std::cell::Cell;
use tempfile::TempDir;

// ── Fake keychain ─────────────────────────────────────────────────────────

struct FakeKeychain {
    delete_result: Result<(), String>,
    /// Tracks number of times delete was called.
    delete_calls: Cell<u32>,
    /// Whether `verify_fully_wiped` returns true after a successful delete.
    wiped_after_delete: bool,
    /// When true, verify_fully_wiped always returns false regardless of
    /// delete outcome — simulates a transient/unknown keychain error
    /// during verification that cannot confirm absence.
    verify_always_fails: bool,
}

impl FakeKeychain {
    fn ok() -> Self {
        FakeKeychain {
            delete_result: Ok(()),
            delete_calls: Cell::new(0),
            wiped_after_delete: true,
            verify_always_fails: false,
        }
    }

    fn fail(msg: &str) -> Self {
        FakeKeychain {
            delete_result: Err(msg.to_string()),
            delete_calls: Cell::new(0),
            wiped_after_delete: false,
            verify_always_fails: false,
        }
    }

    fn ok_but_not_wiped() -> Self {
        FakeKeychain {
            delete_result: Ok(()),
            delete_calls: Cell::new(0),
            wiped_after_delete: false,
            verify_always_fails: false,
        }
    }

    /// Delete succeeds but verify returns false — simulates a transient
    /// unknown error during verification (e.g. keyring constructor failure
    /// or unclassified read error that cannot confirm absence).
    fn ok_but_verify_fails() -> Self {
        FakeKeychain {
            delete_result: Ok(()),
            delete_calls: Cell::new(0),
            wiped_after_delete: true,
            verify_always_fails: true,
        }
    }
}

impl ResetKeychain for FakeKeychain {
    fn delete_all_with_legacy(&self) -> Result<(), String> {
        self.delete_calls.set(self.delete_calls.get() + 1);
        self.delete_result.clone()
    }

    fn verify_fully_wiped(&self) -> bool {
        if self.verify_always_fails {
            return false;
        }
        self.wiped_after_delete && self.delete_calls.get() > 0
    }
}

fn make_app_data(tmp: &TempDir) -> PathBuf {
    let dir = tmp
        .path()
        .join("Application Support")
        .join("com.backbay.ambush.app");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn make_ctx<'a>(
    app_data_dir: &'a Path,
    keychain: &'a dyn ResetKeychain,
    is_dev: bool,
) -> ResetContext<'a> {
    ResetContext {
        app_data_dir,
        legacy_app_data_dirs: vec![],
        nest_dir: None,
        keychain,
        predecessor_keychains: vec![],
        home_dir: None, // skip nest/sprout/CLI ops in unit tests
        is_dev,
    }
}

// ── Test 1: no sentinel ───────────────────────────────────────────────────

#[test]
fn test_no_sentinel_returns_no_op() {
    let tmp = TempDir::new().unwrap();
    let app_data = make_app_data(&tmp);
    let kc = FakeKeychain::ok();

    let outcome = run_boot_reset(app_data.as_path());
    assert!(!outcome.completed, "no sentinel → not completed");
    assert!(!outcome.failed, "no sentinel → not failed");
    assert_eq!(kc.delete_calls.get(), 0, "keychain not touched");
    assert!(app_data.exists(), "app-data dir untouched");
}

#[test]
fn corrupt_reset_sentinel_fails_closed_before_identity_resolution() {
    let tmp = TempDir::new().unwrap();
    let app_data = make_app_data(&tmp);
    let sentinel = sentinel_path(&app_data);
    std::fs::write(&sentinel, b"corrupt").unwrap();
    let outcome = run_boot_reset(&app_data);
    assert!(outcome.failed);
    assert!(!outcome.completed);
    assert!(app_data.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        std::fs::remove_file(&sentinel).unwrap();
        let outside = tmp.path().join("outside");
        std::fs::write(&outside, b"").unwrap();
        symlink(&outside, &sentinel).unwrap();
        let outcome = run_boot_reset(&app_data);
        assert!(outcome.failed);
        assert!(!outcome.completed);
        assert_eq!(std::fs::read(&outside).unwrap(), b"");
    }
}

// ── Test 2: full wipe succeeds ────────────────────────────────────────────

#[test]
fn test_sentinel_present_full_wipe_succeeds() {
    let tmp = TempDir::new().unwrap();
    let app_data = make_app_data(&tmp);

    // Also create both legacy App Support dirs (Buzz and Sprout sources).
    let buzz_dir = tmp
        .path()
        .join("Application Support")
        .join("xyz.block.buzz.app");
    let sprout_dir = tmp
        .path()
        .join("Application Support")
        .join("xyz.block.sprout.app");
    std::fs::create_dir_all(&buzz_dir).unwrap();
    std::fs::create_dir_all(&sprout_dir).unwrap();
    std::fs::write(buzz_dir.join("identity.key"), b"buzz-identity").unwrap();
    std::fs::write(sprout_dir.join("identity.key"), b"sprout-identity").unwrap();

    write_sentinel(&app_data).unwrap();
    let kc = FakeKeychain::ok();

    let ctx = ResetContext {
        app_data_dir: &app_data,
        legacy_app_data_dirs: vec![buzz_dir.clone(), sprout_dir.clone()],
        nest_dir: None,
        keychain: &kc,
        predecessor_keychains: vec![],
        home_dir: None,
        is_dev: false,
    };

    let outcome = run_boot_reset_with_keychain(ctx);

    assert!(outcome.completed, "should complete");
    assert!(!outcome.failed, "should not fail");
    assert!(!app_data.exists(), "app-data must be gone");
    assert!(!buzz_dir.exists(), "Buzz app-data must be gone");
    assert!(!sprout_dir.exists(), "Sprout app-data must be gone");
    assert!(!sentinel_path(&app_data).exists(), "sentinel must be gone");
    assert_eq!(kc.delete_calls.get(), 1, "keychain deleted once");
}

#[test]
fn reset_deletes_and_verifies_every_predecessor_keychain() {
    let tmp = TempDir::new().unwrap();
    let app_data = make_app_data(&tmp);
    write_sentinel(&app_data).unwrap();
    let current = FakeKeychain::ok();
    let buzz = FakeKeychain::ok();
    let sprout = FakeKeychain::ok();
    let outcome = run_boot_reset_with_keychain(ResetContext {
        app_data_dir: &app_data,
        legacy_app_data_dirs: vec![],
        nest_dir: None,
        keychain: &current,
        predecessor_keychains: vec![&buzz, &sprout],
        home_dir: None,
        is_dev: false,
    });
    assert!(outcome.completed);
    assert_eq!(current.delete_calls.get(), 1);
    assert_eq!(buzz.delete_calls.get(), 1);
    assert_eq!(sprout.delete_calls.get(), 1);

    let failed_app_data = make_app_data(&tmp);
    write_sentinel(&failed_app_data).unwrap();
    let current = FakeKeychain::ok();
    let predecessor = FakeKeychain::ok_but_verify_fails();
    let outcome = run_boot_reset_with_keychain(ResetContext {
        app_data_dir: &failed_app_data,
        legacy_app_data_dirs: vec![],
        nest_dir: None,
        keychain: &current,
        predecessor_keychains: vec![&predecessor],
        home_dir: None,
        is_dev: false,
    });
    assert!(outcome.failed);
    assert!(sentinel_path(&failed_app_data).exists());
}

// ── NIP-49: the boot wipe destroys the app-managed key backup ─────────────

#[test]
fn test_wipe_removes_app_managed_key_backup() {
    let tmp = TempDir::new().unwrap();
    let app_data = make_app_data(&tmp);
    let backup = crate::key_backup::backup_file_path(&app_data);
    std::fs::write(&backup, b"encrypted-backup-bytes").unwrap();

    write_sentinel(&app_data).unwrap();
    let kc = FakeKeychain::ok();
    let outcome = run_boot_reset_with_keychain(make_ctx(&app_data, &kc, false));

    assert!(outcome.completed);
    assert!(
        !backup.exists(),
        "sign-out wipe must destroy the app-managed key backup"
    );
}

// ── Test 3: keychain failure keeps sentinel ────────────────────────────────

#[test]
fn test_sentinel_present_keychain_failure_keeps_sentinel() {
    let tmp = TempDir::new().unwrap();
    let app_data = make_app_data(&tmp);
    write_sentinel(&app_data).unwrap();
    let kc = FakeKeychain::fail("keychain unavailable");
    let ctx = make_ctx(&app_data, &kc, false);

    let outcome = run_boot_reset_with_keychain(ctx);

    assert!(!outcome.completed);
    assert!(outcome.failed);
    assert!(
        sentinel_path(&app_data).exists(),
        "sentinel must be preserved on failure"
    );
}

// ── Test 4: app-data rename works but verify fails ────────────────────────

#[test]
fn test_sentinel_present_verify_failure_keeps_sentinel() {
    let tmp = TempDir::new().unwrap();
    let app_data = make_app_data(&tmp);
    write_sentinel(&app_data).unwrap();
    // Keychain delete "succeeds" but verify_fully_wiped still returns false.
    let kc = FakeKeychain::ok_but_not_wiped();
    let ctx = make_ctx(&app_data, &kc, false);

    let outcome = run_boot_reset_with_keychain(ctx);

    assert!(!outcome.completed);
    assert!(outcome.failed);
    assert!(sentinel_path(&app_data).exists(), "sentinel preserved");
}

// ── Test 5: crash-then-retry completes ───────────────────────────────────

#[test]
fn test_crash_then_retry_completes() {
    let tmp = TempDir::new().unwrap();
    let app_data = make_app_data(&tmp);
    write_sentinel(&app_data).unwrap();

    // First run — keychain fails (simulates a crash mid-wipe).
    let kc1 = FakeKeychain::fail("transient error");
    let ctx1 = make_ctx(&app_data, &kc1, false);
    let first = run_boot_reset_with_keychain(ctx1);
    assert!(first.failed);
    assert!(
        sentinel_path(&app_data).exists(),
        "sentinel must survive first attempt"
    );

    // Second run — keychain succeeds. App-data dir was renamed but we need
    // to recreate it for the test (the wipe tried to rename it).
    // In production the dir would already be gone; here it was renamed to
    // .trash-<pid> and then not cleaned up (keychain failed before cleanup).
    // Create a fresh app-data dir to simulate a reboot where app recreated it.
    std::fs::create_dir_all(&app_data).unwrap();

    let kc2 = FakeKeychain::ok();
    let ctx2 = make_ctx(&app_data, &kc2, false);
    let second = run_boot_reset_with_keychain(ctx2);
    assert!(second.completed, "second attempt must complete");
    assert!(!second.failed);
    assert!(
        !sentinel_path(&app_data).exists(),
        "sentinel cleared on success"
    );
}

// ── Test 6: dev build wipes dev nest, leaves prod nest intact ────────────

#[test]
fn test_dev_build_wipes_dev_nest_not_prod() {
    let tmp = TempDir::new().unwrap();

    // Create both nests.
    let dev_nest = tmp.path().join(".ambush-dev");
    let prod_nest = tmp.path().join(".ambush");
    std::fs::create_dir_all(&dev_nest).unwrap();
    std::fs::create_dir_all(&prod_nest).unwrap();

    let app_data = tmp
        .path()
        .join("Application Support")
        .join("com.backbay.ambush.app.dev");
    std::fs::create_dir_all(&app_data).unwrap();
    write_sentinel(&app_data).unwrap();

    let kc = FakeKeychain::ok();
    let ctx = ResetContext {
        app_data_dir: &app_data,
        legacy_app_data_dirs: vec![],
        nest_dir: Some(dev_nest.clone()),
        keychain: &kc,
        predecessor_keychains: vec![],
        home_dir: None,
        is_dev: true,
    };

    let outcome = run_boot_reset_with_keychain(ctx);

    assert!(outcome.completed, "wipe must complete");
    assert!(!dev_nest.exists(), "dev nest must be wiped");
    assert!(prod_nest.exists(), "prod nest must survive");
}

// ── Test 7: prod build wipes prod nest, leaves dev nest intact ───────────

#[test]
fn test_prod_build_wipes_prod_nest_not_dev() {
    let tmp = TempDir::new().unwrap();

    // Create both nests.
    let dev_nest = tmp.path().join(".ambush-dev");
    let prod_nest = tmp.path().join(".ambush");
    std::fs::create_dir_all(&dev_nest).unwrap();
    std::fs::create_dir_all(&prod_nest).unwrap();

    let app_data = tmp
        .path()
        .join("Application Support")
        .join("com.backbay.ambush.app");
    std::fs::create_dir_all(&app_data).unwrap();
    write_sentinel(&app_data).unwrap();

    let kc = FakeKeychain::ok();
    let ctx = ResetContext {
        app_data_dir: &app_data,
        legacy_app_data_dirs: vec![],
        nest_dir: Some(prod_nest.clone()),
        keychain: &kc,
        predecessor_keychains: vec![],
        home_dir: None,
        is_dev: false,
    };

    let outcome = run_boot_reset_with_keychain(ctx);

    assert!(outcome.completed, "wipe must complete");
    assert!(!prod_nest.exists(), "prod nest must be wiped");
    assert!(dev_nest.exists(), "dev nest must survive");
}

// ── Test 8: legacy app-data removed on reset ──────────────────────────────

#[test]
fn test_legacy_app_data_removed_on_reset() {
    let tmp = TempDir::new().unwrap();
    let app_data = make_app_data(&tmp);

    // Seed a legacy sprout dir with data that would be re-imported.
    let legacy_dir = tmp
        .path()
        .join("Application Support")
        .join("xyz.block.sprout.app");
    std::fs::create_dir_all(legacy_dir.join("agents")).unwrap();
    std::fs::write(legacy_dir.join("identity.key"), b"sprout-nsec").unwrap();

    write_sentinel(&app_data).unwrap();
    let kc = FakeKeychain::ok();
    let ctx = ResetContext {
        app_data_dir: &app_data,
        legacy_app_data_dirs: vec![legacy_dir.clone()],
        nest_dir: None,
        keychain: &kc,
        predecessor_keychains: vec![],
        home_dir: None,
        is_dev: false,
    };

    let outcome = run_boot_reset_with_keychain(ctx);

    assert!(outcome.completed, "reset must complete");
    assert!(!legacy_dir.exists(), "legacy app-data dir must be removed");
}

// ── Test 9: unknown error during delete → failed, sentinel kept ────────

#[test]
fn test_unknown_delete_error_keeps_sentinel() {
    let tmp = TempDir::new().unwrap();
    let app_data = make_app_data(&tmp);
    write_sentinel(&app_data).unwrap();
    // Simulates an unclassified/transient keychain error during delete.
    let kc = FakeKeychain::fail("unknown transient keychain error");
    let ctx = make_ctx(&app_data, &kc, false);

    let outcome = run_boot_reset_with_keychain(ctx);

    assert!(outcome.failed, "unknown delete error must fail");
    assert!(!outcome.completed, "must not complete on delete error");
    assert!(
        sentinel_path(&app_data).exists(),
        "sentinel must survive unknown delete error"
    );
}

// ── Test 10: unknown error during verify → failed, sentinel kept ─────

#[test]
fn test_unknown_verify_error_keeps_sentinel() {
    let tmp = TempDir::new().unwrap();
    let app_data = make_app_data(&tmp);
    write_sentinel(&app_data).unwrap();
    // Delete succeeds but verification fails — simulates a transient
    // keychain error (e.g. constructor failure, unclassified read error)
    // that cannot confirm absence. The sentinel must survive.
    let kc = FakeKeychain::ok_but_verify_fails();
    let ctx = make_ctx(&app_data, &kc, false);

    let outcome = run_boot_reset_with_keychain(ctx);

    assert!(outcome.failed, "unknown verify error must fail");
    assert!(!outcome.completed, "must not complete on verify error");
    assert!(
        sentinel_path(&app_data).exists(),
        "sentinel must survive unknown verify error"
    );
}

// ── Test 11: completed dev reset suppresses dev repos-dir migration ────
// Behavioral test at the composed seam: exercises real filesystem effects
// through maybe_migrate_dev_repos_dir, not just the boolean predicate.

#[test]
fn test_completed_dev_reset_suppresses_dev_repos_dir_migration() {
    let tmp = TempDir::new().unwrap();
    let app_data = tmp
        .path()
        .join("Application Support")
        .join("com.backbay.ambush.app.dev");
    std::fs::create_dir_all(&app_data).unwrap();
    write_sentinel(&app_data).unwrap();

    // Seed prod ~/.ambush/.repos-dir so the migration has something to copy.
    let home = tmp.path().join("home");
    let prod_nest = home.join(".ambush");
    std::fs::create_dir_all(&prod_nest).unwrap();
    std::fs::write(prod_nest.join(".repos-dir"), "/some/workspace").unwrap();

    let dev_nest = tmp.path().join(".ambush-dev");

    // Run a real reset and take the REAL outcome.completed.
    let kc = FakeKeychain::ok();
    let ctx = ResetContext {
        app_data_dir: &app_data,
        legacy_app_data_dirs: vec![],
        nest_dir: Some(dev_nest.clone()),
        keychain: &kc,
        predecessor_keychains: vec![],
        home_dir: None,
        is_dev: true,
    };
    let outcome = run_boot_reset_with_keychain(ctx);
    assert!(outcome.completed, "reset must complete");

    // Arm 1: completed dev reset → dev nest must NOT get .repos-dir.
    crate::migration::maybe_migrate_dev_repos_dir(true, outcome.completed, &home, &dev_nest);
    assert!(
        !dev_nest.join(".repos-dir").exists(),
        "completed dev reset must suppress .repos-dir import into dev nest"
    );

    // Arm 2 (positive control): non-reset dev boot → dev nest IS created
    // with .repos-dir copied. This proves the test would have caught the
    // pass-3 resurrection live.
    let dev_nest_2 = tmp.path().join(".ambush-dev-control");
    crate::migration::maybe_migrate_dev_repos_dir(true, false, &home, &dev_nest_2);
    assert!(
        dev_nest_2.join(".repos-dir").exists(),
        "non-reset dev boot must import .repos-dir into dev nest"
    );
    assert_eq!(
        std::fs::read_to_string(dev_nest_2.join(".repos-dir")).unwrap(),
        "/some/workspace",
        ".repos-dir content must match prod source"
    );

    // Arm 3: prod build (is_dev=false) → nothing created regardless.
    let dev_nest_3 = tmp.path().join(".ambush-dev-prod");
    crate::migration::maybe_migrate_dev_repos_dir(false, false, &home, &dev_nest_3);
    assert!(
        !dev_nest_3.join(".repos-dir").exists(),
        "prod builds must never run dev repos-dir migration"
    );
}

// ── Test 12: crash-after-rename retry cleans prior trash ─────────────

#[test]
fn test_crash_retry_cleans_prior_deterministic_trash() {
    let tmp = TempDir::new().unwrap();
    let app_support = tmp.path().join("Application Support");
    let app_data = app_support.join("com.backbay.ambush.app");
    std::fs::create_dir_all(&app_data).unwrap();
    write_sentinel(&app_data).unwrap();

    // Simulate a prior crashed boot: originals absent, deterministic trash
    // present from the crash (as if the process renamed then died).
    let trash_app_dir = app_support.join("com.backbay.ambush.app.reset-trash");
    std::fs::create_dir_all(&trash_app_dir).unwrap();
    std::fs::write(trash_app_dir.join("identity.key"), b"old-key").unwrap();

    // Original is gone (crashed mid-wipe), so remove it for the retry.
    std::fs::remove_dir_all(&app_data).unwrap();

    let kc = FakeKeychain::ok();
    let ctx = make_ctx(&app_data, &kc, false);

    let outcome = run_boot_reset_with_keychain(ctx);
    assert!(outcome.completed, "retry must complete");
    assert!(
        !trash_app_dir.exists(),
        "prior crash trash must be cleaned by retry"
    );
    assert!(
        !sentinel_path(&app_data).exists(),
        "sentinel must be cleared"
    );
}

#[test]
fn test_legacy_rename_failure_restores_prior_moves_before_keychain_delete() {
    let tmp = TempDir::new().unwrap();
    let app_support = tmp.path().join("Application Support");
    let app_data = app_support.join("com.backbay.ambush.app");
    let buzz = app_support.join("xyz.block.buzz.app");
    let sprout = app_support.join("xyz.block.sprout.app");
    for path in [&app_data, &buzz, &sprout] {
        std::fs::create_dir_all(path).unwrap();
    }
    write_sentinel(&app_data).unwrap();

    // Inject the failure after app-data and Buzz have already moved. A
    // destination-file collision is not portable: Windows may replace it.
    let kc = FakeKeychain::ok();
    let outcome = run_boot_reset_with_keychain_and_rename(
        ResetContext {
            app_data_dir: &app_data,
            legacy_app_data_dirs: vec![buzz.clone(), sprout.clone()],
            nest_dir: None,
            keychain: &kc,
            predecessor_keychains: vec![],
            home_dir: None,
            is_dev: false,
        },
        |path| {
            if path == sprout.as_path() {
                Err("injected legacy rename failure".to_string())
            } else {
                rename_to_trash(path)
            }
        },
    );

    assert!(outcome.failed);
    assert!(app_data.exists(), "app-data must be restored");
    assert!(buzz.exists(), "an earlier legacy move must be restored");
    assert!(sprout.exists(), "the failed legacy source stays in place");
    assert!(
        sentinel_path(&app_data).exists(),
        "the reset remains retryable"
    );
    assert_eq!(kc.delete_calls.get(), 0, "keychain must remain untouched");
}

// ── Test 13: keychain-fail restores all dirs, retry cleans trash ──────

#[test]
fn keychain_failure_restores_agent_and_credential_directories() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let app_data = home
        .join("Library")
        .join("Application Support")
        .join("com.backbay.ambush.app");
    let nest = home.join(".ambush");
    let sprout = home.join(".sprout");
    let agent_config = home.join(".config").join("ambush-agent");
    for (path, marker) in [
        (&app_data, "app"),
        (&nest, "nest"),
        (&sprout, "sprout"),
        (&agent_config, "agent"),
    ] {
        std::fs::create_dir_all(path).unwrap();
        std::fs::write(path.join("marker"), marker).unwrap();
    }
    write_sentinel(&app_data).unwrap();

    let keychain = FakeKeychain::fail("keychain unavailable");
    let outcome = run_boot_reset_with_keychain(ResetContext {
        app_data_dir: &app_data,
        legacy_app_data_dirs: vec![],
        nest_dir: Some(nest.clone()),
        keychain: &keychain,
        predecessor_keychains: vec![],
        home_dir: Some(home.clone()),
        is_dev: false,
    });

    assert!(outcome.failed);
    assert!(!outcome.completed);
    for (path, marker) in [
        (&app_data, "app"),
        (&nest, "nest"),
        (&sprout, "sprout"),
        (&agent_config, "agent"),
    ] {
        assert_eq!(
            std::fs::read_to_string(path.join("marker")).unwrap(),
            marker
        );
    }
}

#[test]
fn credential_directory_rename_failure_rolls_back_before_keychain_delete() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let app_data = home
        .join("Library")
        .join("Application Support")
        .join("com.backbay.ambush.app");
    let nest = home.join(".ambush");
    let sprout = home.join(".sprout");
    let agent_config = home.join(".config").join("ambush-agent");
    for path in [&app_data, &nest, &sprout, &agent_config] {
        std::fs::create_dir_all(path).unwrap();
    }
    write_sentinel(&app_data).unwrap();

    let keychain = FakeKeychain::ok();
    let outcome = run_boot_reset_with_keychain_and_rename(
        ResetContext {
            app_data_dir: &app_data,
            legacy_app_data_dirs: vec![],
            nest_dir: Some(nest.clone()),
            keychain: &keychain,
            predecessor_keychains: vec![],
            home_dir: Some(home),
            is_dev: false,
        },
        |path| {
            if path == sprout.as_path() {
                Err("injected credential directory failure".to_string())
            } else {
                rename_to_trash(path)
            }
        },
    );

    assert!(outcome.failed);
    assert!(!outcome.completed);
    for path in [&app_data, &nest, &sprout, &agent_config] {
        assert!(path.exists(), "{} must remain available", path.display());
    }
    assert_eq!(keychain.delete_calls.get(), 0);
}

#[test]
fn sentinel_delete_failure_never_reports_reset_complete() {
    let tmp = TempDir::new().unwrap();
    let app_data = make_app_data(&tmp);
    write_sentinel(&app_data).unwrap();
    let keychain = FakeKeychain::ok();

    let outcome = run_boot_reset_with_keychain_and_ops(
        make_ctx(&app_data, &keychain, false),
        rename_to_trash,
        |_| Err("injected sentinel delete failure".to_string()),
    );

    assert!(outcome.failed);
    assert!(!outcome.completed);
    assert!(sentinel_path(&app_data).exists());
}

#[test]
fn test_keychain_fail_restores_all_then_retry_cleans() {
    let tmp = TempDir::new().unwrap();
    let app_support = tmp.path().join("Application Support");
    let app_data = app_support.join("com.backbay.ambush.app");
    std::fs::create_dir_all(&app_data).unwrap();
    std::fs::write(app_data.join("config.json"), b"{}").unwrap();

    let legacy = app_support.join("xyz.block.sprout.app");
    std::fs::create_dir_all(&legacy).unwrap();
    std::fs::write(legacy.join("identity.key"), b"sprout-key").unwrap();

    write_sentinel(&app_data).unwrap();

    // First attempt: keychain fails → dirs restored.
    let kc1 = FakeKeychain::fail("keychain locked");
    let ctx1 = ResetContext {
        app_data_dir: &app_data,
        legacy_app_data_dirs: vec![legacy.clone()],
        nest_dir: None,
        keychain: &kc1,
        predecessor_keychains: vec![],
        home_dir: Some(tmp.path().to_path_buf()),
        is_dev: false,
    };
    let first = run_boot_reset_with_keychain(ctx1);
    assert!(first.failed, "first attempt must fail");
    assert!(
        app_data.exists(),
        "app-data must be restored after keychain fail"
    );
    assert!(
        legacy.exists(),
        "legacy dir must be restored after keychain fail"
    );
    assert!(sentinel_path(&app_data).exists(), "sentinel survives");

    // Second attempt: keychain succeeds → everything cleaned including
    // any residual trash from prior attempts.
    let kc2 = FakeKeychain::ok();
    let ctx2 = ResetContext {
        app_data_dir: &app_data,
        legacy_app_data_dirs: vec![legacy.clone()],
        nest_dir: None,
        keychain: &kc2,
        predecessor_keychains: vec![],
        home_dir: Some(tmp.path().to_path_buf()),
        is_dev: false,
    };
    let second = run_boot_reset_with_keychain(ctx2);
    assert!(second.completed, "second attempt must complete");
    assert!(!app_data.exists(), "app-data must be gone");
    assert!(!legacy.exists(), "legacy must be gone");
    // No trash directories should remain.
    let trash_app = app_support.join("com.backbay.ambush.app.reset-trash");
    let trash_legacy = app_support.join("xyz.block.sprout.app.reset-trash");
    assert!(!trash_app.exists(), "app trash must be cleaned");
    assert!(!trash_legacy.exists(), "legacy trash must be cleaned");
}
