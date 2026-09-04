use super::*;

#[test]
fn a_sidecar_that_is_stopped_reports_stopped_and_its_group_is_reaped() {
    // `sh -c 'sleep 30'` stands in for swarm_detect: same spawn path, same
    // group kill, and it outlives the assertions unless the kill works.
    let sidecar = PerchSidecar::new();
    let status = sidecar
        .spawn_for_tests(vec!["sh".into(), "-c".into(), "sleep 30".into()])
        .expect("a spawned sidecar");
    assert_eq!(status.healthz, Healthz::Starting);
    assert!(sidecar.is_running());

    #[cfg(unix)]
    let pgid = sidecar.pgid().expect("a process group");
    #[cfg(unix)]
    assert_eq!(kill_probe(pgid), Ok(()), "the group must exist before stop");

    sidecar.stop().expect("stop");
    assert_eq!(
        sidecar.status().expect("a status").healthz,
        Healthz::Stopped
    );
    assert!(!sidecar.is_running());

    #[cfg(unix)]
    assert_eq!(
        kill_probe(pgid),
        Err(libc::ESRCH),
        "the whole group must be gone, not just the direct child",
    );
}

#[test]
fn the_seeds_never_cross_ipc() {
    let status = SidecarStatus {
        pid: 1,
        started_at_ms: 0,
        healthz: Healthz::Ready,
        profile_path: "/x".into(),
        seeds_present: SeedsPresent {
            nostr: true,
            spine: true,
        },
    };
    let json = serde_json::to_string(&status).expect("serialised");
    assert!(
        !json.to_ascii_uppercase().contains("SEED_"),
        "presence only, never a value: {json}"
    );
    assert!(json.contains("\"nostr\":true"));
}

#[test]
fn never_started_is_not_stopped() {
    // The settings panel must not offer a stop control for a process that does
    // not exist, and must not report a daemon as stopped that never ran.
    let sidecar = PerchSidecar::new();
    assert!(sidecar.status().is_none());
    assert!(!sidecar.is_running());
}

#[test]
fn stopping_twice_is_not_an_error() {
    let sidecar = PerchSidecar::new();
    sidecar
        .spawn_for_tests(vec!["sh".into(), "-c".into(), "sleep 30".into()])
        .expect("a spawned sidecar");
    sidecar.stop().expect("first stop");
    sidecar.stop().expect("second stop must be a no-op");
    assert_eq!(
        sidecar.status().expect("a status").healthz,
        Healthz::Stopped
    );
}

#[test]
fn a_late_health_poll_cannot_resurrect_a_stopped_sidecar() {
    let sidecar = PerchSidecar::new();
    sidecar
        .spawn_for_tests(vec!["sh".into(), "-c".into(), "sleep 30".into()])
        .expect("a spawned sidecar");
    sidecar.stop().expect("stop");
    // The 5 s poll can land after stop. If it wrote Ready, the panel would
    // offer a stop control for a process that is already gone.
    sidecar.observe_health(Healthz::Ready);
    assert_eq!(
        sidecar.status().expect("a status").healthz,
        Healthz::Stopped
    );
}

#[test]
fn a_second_start_is_refused_rather_than_orphaning_the_first() {
    let sidecar = PerchSidecar::new();
    sidecar
        .spawn_for_tests(vec!["sh".into(), "-c".into(), "sleep 30".into()])
        .expect("a spawned sidecar");
    let second = sidecar.start_at(
        std::path::Path::new("/bin/sh"),
        &SidecarProfile::default(),
        SeedsPresent {
            nostr: false,
            spine: false,
        },
    );
    assert!(second.is_err(), "a second start would lose the first child");
    sidecar.stop().expect("stop");
}

#[test]
fn the_default_profile_binds_loopback() {
    // A daemon bound to 0.0.0.0 on a laptop is an unauthenticated operator API
    // on whatever network that laptop joins next.
    assert_eq!(SidecarProfile::default().bind, "127.0.0.1:9090");
}
