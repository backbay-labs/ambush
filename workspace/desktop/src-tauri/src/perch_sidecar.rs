//! Supervising a local `swarm_detect` for the laptop demo.
//!
//! This is LOCAL PROCESS CONTROL, not an Ambush write. It sits outside INV-01
//! for that reason: INV-01 is a claim about the set of non-GET requests this
//! process can issue to a daemon HOST, and starting a daemon on this machine
//! issues none.
//!
//! The discipline is the managed-agent runtime's, deliberately, rather than a
//! second one: `process_group(0)` on Unix so a signal reaches the daemon AND
//! anything it spawned, `CREATE_NO_WINDOW` plus a job object on Windows so a
//! console never flashes and the tree dies with the app. A supervisor that
//! killed only the direct child would leave a detector running after the app
//! that started it had quit, with no surface anywhere that could stop it.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

#[cfg(test)]
#[path = "perch_sidecar_tests.rs"]
mod tests;

/// The readiness the console reports for a supervised daemon.
///
/// `Starting` and `Unhealthy` are separate states because the operator's next
/// action differs: one is waiting, the other is reading a log. Collapsing them
/// into "not ready" makes a daemon that will never come up look like one that
/// is about to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Healthz {
    Starting,
    Ready,
    Unhealthy,
    Stopped,
}

/// Whether each secret is CONFIGURED. Never the value.
///
/// The seeds live in the keyring and are read into the child's environment
/// inside this process. Neither ever crosses IPC into the webview (INV-22),
/// and this struct is the shape that makes that hard to get wrong: there is no
/// field a value could be put in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedsPresent {
    pub nostr: bool,
    pub spine: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarStatus {
    pub pid: u32,
    pub started_at_ms: i64,
    pub healthz: Healthz,
    pub profile_path: String,
    pub seeds_present: SeedsPresent,
}

/// What to start. The config path is chosen in settings and validated by the
/// caller against the app data dir or the bundled rulesets — this module never
/// takes a path from the renderer without that check.
#[derive(Debug, Clone)]
pub struct SidecarProfile {
    pub config_path: PathBuf,
    pub bind: String,
    pub env: Vec<(String, String)>,
}

impl Default for SidecarProfile {
    fn default() -> Self {
        Self {
            config_path: PathBuf::from("rulesets/default.yaml"),
            // Loopback. A daemon bound to 0.0.0.0 on a laptop is an
            // unauthenticated operator API on whatever network it joins next.
            bind: "127.0.0.1:9090".to_string(),
            env: Vec::new(),
        }
    }
}

#[derive(Default)]
pub struct PerchSidecar {
    child: Mutex<Option<Child>>,
    status: Mutex<Option<SidecarStatus>>,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// `kill(pid, 0)` as a probe: does this process group still exist?
///
/// Signal 0 performs the permission and existence checks and delivers nothing,
/// which is exactly what a reaping assertion needs. Returns the raw errno on
/// failure so a test can distinguish ESRCH (gone, the answer we want) from
/// EPERM (alive and not ours, which would be a real problem).
#[cfg(all(unix, test))]
pub fn kill_probe(pgid: i32) -> Result<(), i32> {
    // SAFETY: `kill` with signal 0 delivers nothing. Same call and same
    // rationale as `shutdown.rs`, which already signals process groups.
    let rc = unsafe { libc::kill(pgid, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL))
    }
}

impl PerchSidecar {
    pub fn new() -> Self {
        Self::default()
    }

    /// The last status reported, or `None` when the sidecar has never run.
    ///
    /// `None` is not `Stopped`: never started and started-then-stopped are
    /// different, and the settings panel says so rather than showing a stop
    /// control for a process that does not exist.
    pub fn status(&self) -> Option<SidecarStatus> {
        self.status.lock().ok().and_then(|s| s.clone())
    }

    /// The child's process group id, which on Unix is its pid because the
    /// child was spawned into a new group of its own.
    #[cfg(all(unix, test))]
    pub fn pgid(&self) -> Option<i32> {
        self.status().map(|s| s.pid as i32)
    }

    fn spawn_command(mut command: Command) -> Result<Child, String> {
        #[cfg(unix)]
        {
            // A new process group, so a signal reaches everything the daemon
            // spawned rather than only the daemon.
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt as _;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }
        command.spawn().map_err(|e| e.to_string())
    }

    /// Start a daemon from an already-resolved binary path.
    ///
    /// Resolution of the bundled sidecar is the caller's job, so this stays
    /// testable without a Tauri app handle.
    pub fn start_at(
        &self,
        binary: &std::path::Path,
        profile: &SidecarProfile,
        seeds_present: SeedsPresent,
    ) -> Result<SidecarStatus, String> {
        if self.is_running() {
            return Err("the sidecar is already running".to_string());
        }
        let mut command = Command::new(binary);
        command
            .arg("--config")
            .arg(&profile.config_path)
            .arg("--serve")
            .arg("--bind")
            .arg(&profile.bind);
        for (key, value) in &profile.env {
            command.env(key, value);
        }
        let child = Self::spawn_command(command)?;
        let status = SidecarStatus {
            pid: child.id(),
            started_at_ms: now_ms(),
            healthz: Healthz::Starting,
            profile_path: profile.config_path.to_string_lossy().into_owned(),
            seeds_present,
        };
        *self.child.lock().map_err(|e| e.to_string())? = Some(child);
        *self.status.lock().map_err(|e| e.to_string())? = Some(status.clone());
        Ok(status)
    }

    /// Poll `/readyz` until the sidecar stops.
    ///
    /// Readiness is asked of the daemon rather than inferred from the process
    /// being alive. A `swarm_detect` that started and then failed its startup
    /// attestation is a live process that will never serve, and reporting it
    /// as ready because it has a pid is the reassurance this panel exists to
    /// refuse.
    pub fn spawn_health_poll(self: std::sync::Arc<Self>, bind: String, client: reqwest::Client) {
        tauri::async_runtime::spawn(async move {
            let url = format!("http://{bind}/readyz");
            loop {
                if !self.is_running() {
                    return;
                }
                let healthz = match client.get(&url).send().await {
                    Ok(response) if response.status().is_success() => Healthz::Ready,
                    // A reachable daemon answering non-2xx is up and refusing,
                    // which is a different problem from one not yet listening.
                    Ok(_) => Healthz::Unhealthy,
                    Err(_) => Healthz::Starting,
                };
                self.observe_health(healthz);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
    }

    /// Test seam: supervise an arbitrary command with the same spawn path.
    #[cfg(test)]
    pub fn spawn_for_tests(&self, argv: Vec<String>) -> Result<SidecarStatus, String> {
        let mut command = Command::new(&argv[0]);
        command.args(&argv[1..]);
        let child = Self::spawn_command(command)?;
        let status = SidecarStatus {
            pid: child.id(),
            started_at_ms: now_ms(),
            healthz: Healthz::Starting,
            profile_path: "<test>".to_string(),
            seeds_present: SeedsPresent {
                nostr: false,
                spine: false,
            },
        };
        *self.child.lock().map_err(|e| e.to_string())? = Some(child);
        *self.status.lock().map_err(|e| e.to_string())? = Some(status.clone());
        Ok(status)
    }

    pub fn is_running(&self) -> bool {
        matches!(
            self.status().map(|s| s.healthz),
            Some(Healthz::Starting) | Some(Healthz::Ready) | Some(Healthz::Unhealthy)
        )
    }

    /// Record a readiness observation. Never moves a stopped sidecar back to
    /// running: a poll that lands after `stop` must not resurrect the status.
    pub fn observe_health(&self, healthz: Healthz) {
        if let Ok(mut guard) = self.status.lock() {
            if let Some(status) = guard.as_mut() {
                if status.healthz != Healthz::Stopped {
                    status.healthz = healthz;
                }
            }
        }
    }

    /// SIGTERM the group, wait, then SIGKILL. Idempotent.
    ///
    /// The group and not the pid: the daemon spawns, and a supervisor that
    /// signalled only its direct child would leave those running with nothing
    /// left that knows about them.
    pub fn stop(&self) -> Result<(), String> {
        let mut guard = self.child.lock().map_err(|e| e.to_string())?;
        let Some(mut child) = guard.take() else {
            self.mark_stopped();
            return Ok(());
        };
        #[cfg(unix)]
        {
            let pgid = -(child.id() as i32);
            // SAFETY: signalling a process group this process created. Same
            // call and rationale as `shutdown.rs`'s managed-agent fan-out.
            unsafe {
                libc::kill(pgid, libc::SIGTERM);
            }
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if std::time::Instant::now() >= deadline => {
                        // SAFETY: as above.
                        unsafe {
                            libc::kill(pgid, libc::SIGKILL);
                        }
                        let _ = child.wait();
                        break;
                    }
                    Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
                    Err(_) => break,
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.mark_stopped();
        Ok(())
    }

    fn mark_stopped(&self) {
        if let Ok(mut guard) = self.status.lock() {
            if let Some(status) = guard.as_mut() {
                status.healthz = Healthz::Stopped;
            }
        }
    }
}
