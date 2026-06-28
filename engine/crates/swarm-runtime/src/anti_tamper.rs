use crate::ingest::IngestState;
use crate::runtime_events::{RuntimeEvent, now_ms};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::Duration;
use swarm_core::config::{RuntimeAntiTamperConfig, RuntimeMode};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiTamperReport {
    pub enabled: bool,
    pub supported: bool,
    pub required: bool,
    pub ready: bool,
    pub checked_at_ms: i64,
    pub status: String,
    pub details: String,
    pub debugger_attached: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracer_pid: Option<u32>,
    #[serde(default)]
    pub unexpected_library_loads: Vec<String>,
    pub baseline_library_count: usize,
    pub fail_closed_live_response: bool,
}

impl AntiTamperReport {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            supported: cfg!(target_os = "linux"),
            required: false,
            ready: true,
            checked_at_ms: now_ms(),
            status: "disabled".to_string(),
            details: "runtime anti-tamper monitoring disabled by config".to_string(),
            debugger_attached: false,
            tracer_pid: None,
            unexpected_library_loads: Vec::new(),
            baseline_library_count: 0,
            fail_closed_live_response: false,
        }
    }

    pub fn effective_ready(&self) -> bool {
        self.ready || !self.required
    }

    pub fn tamper_detected(&self) -> bool {
        self.debugger_attached || !self.unexpected_library_loads.is_empty()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("runtime anti-tamper monitoring failed closed: {summary}")]
pub struct AntiTamperFailure {
    summary: String,
}

impl AntiTamperFailure {
    pub fn new(report: &AntiTamperReport) -> Self {
        Self {
            summary: report.details.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiTamperSnapshot {
    tracer_pid: Option<u32>,
    libraries: BTreeSet<String>,
}

pub trait AntiTamperProbe: Send + Sync + 'static {
    fn supported(&self) -> bool;
    fn snapshot(&self) -> Result<AntiTamperSnapshot, String>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ProcfsAntiTamperProbe;

impl AntiTamperProbe for ProcfsAntiTamperProbe {
    fn supported(&self) -> bool {
        cfg!(target_os = "linux")
    }

    fn snapshot(&self) -> Result<AntiTamperSnapshot, String> {
        #[cfg(target_os = "linux")]
        {
            let status = std::fs::read_to_string("/proc/self/status")
                .map_err(|error| format!("failed to read /proc/self/status: {error}"))?;
            let maps = std::fs::read_to_string("/proc/self/maps")
                .map_err(|error| format!("failed to read /proc/self/maps: {error}"))?;
            Ok(AntiTamperSnapshot {
                tracer_pid: parse_tracer_pid(&status)?,
                libraries: collect_mapped_libraries(&maps),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("runtime anti-tamper monitoring is only supported on Linux".to_string())
        }
    }
}

pub struct AntiTamperMonitor<P = ProcfsAntiTamperProbe> {
    probe: P,
    baseline_libraries: BTreeSet<String>,
    last_alert_fingerprint: Option<String>,
}

impl Default for AntiTamperMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl AntiTamperMonitor {
    pub fn new() -> Self {
        Self::from_probe(ProcfsAntiTamperProbe)
    }
}

impl<P: AntiTamperProbe> AntiTamperMonitor<P> {
    fn from_probe(probe: P) -> Self {
        let baseline_libraries = probe
            .snapshot()
            .map(|snapshot| snapshot.libraries)
            .unwrap_or_default();
        Self {
            probe,
            baseline_libraries,
            last_alert_fingerprint: None,
        }
    }

    pub fn evaluate(
        &self,
        settings: &RuntimeAntiTamperConfig,
        mode: RuntimeMode,
    ) -> AntiTamperReport {
        if !settings.enabled {
            return AntiTamperReport::disabled();
        }

        let supported = self.probe.supported();
        let required = supported
            && settings.fail_closed_live_response
            && matches!(mode, RuntimeMode::LiveResponse);
        if !supported {
            return AntiTamperReport {
                enabled: true,
                supported: false,
                required: false,
                ready: false,
                checked_at_ms: now_ms(),
                status: "unsupported".to_string(),
                details: "runtime anti-tamper monitoring is only supported on Linux".to_string(),
                debugger_attached: false,
                tracer_pid: None,
                unexpected_library_loads: Vec::new(),
                baseline_library_count: self.baseline_libraries.len(),
                fail_closed_live_response: settings.fail_closed_live_response,
            };
        }

        match self.probe.snapshot() {
            Ok(snapshot) => self.report_from_snapshot(settings, required, snapshot),
            Err(error) => AntiTamperReport {
                enabled: true,
                supported: true,
                required,
                ready: false,
                checked_at_ms: now_ms(),
                status: "error".to_string(),
                details: error,
                debugger_attached: false,
                tracer_pid: None,
                unexpected_library_loads: Vec::new(),
                baseline_library_count: self.baseline_libraries.len(),
                fail_closed_live_response: settings.fail_closed_live_response,
            },
        }
    }

    pub async fn run_until_shutdown(
        mut self,
        state: IngestState,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        loop {
            let settings = state.current_anti_tamper_config();
            let mode = state.current_runtime_mode();
            let report = self.evaluate(&settings, mode);
            state.update_anti_tamper_report(report.clone());

            if report.tamper_detected() {
                let fingerprint = self.alert_fingerprint(&report);
                if self.last_alert_fingerprint.as_ref() != Some(&fingerprint) {
                    tracing::warn!(
                        debugger_attached = report.debugger_attached,
                        tracer_pid = report.tracer_pid,
                        unexpected_library_loads = ?report.unexpected_library_loads,
                        fail_closed = report.required,
                        "runtime anti-tamper detection triggered"
                    );
                    state.publish_runtime_event(RuntimeEvent::TamperAlert {
                        emitted_at_ms: report.checked_at_ms,
                        debugger_attached: report.debugger_attached,
                        tracer_pid: report.tracer_pid,
                        unexpected_library_loads: report.unexpected_library_loads.clone(),
                        fail_closed: report.required,
                        details: report.details.clone(),
                    });
                    self.last_alert_fingerprint = Some(fingerprint);
                }
            } else {
                self.last_alert_fingerprint = None;
            }

            if report.required && !report.ready {
                tracing::error!(
                    status = %report.status,
                    details = %report.details,
                    "runtime anti-tamper monitor requested fail-closed shutdown"
                );
                state.begin_drain();
                state.request_shutdown();
                break;
            }

            let sleep =
                tokio::time::sleep(Duration::from_millis(settings.check_interval_ms.max(1)));
            tokio::pin!(sleep);
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                _ = &mut sleep => {}
            }
        }
    }

    fn report_from_snapshot(
        &self,
        settings: &RuntimeAntiTamperConfig,
        required: bool,
        snapshot: AntiTamperSnapshot,
    ) -> AntiTamperReport {
        let unexpected_library_loads = snapshot
            .libraries
            .iter()
            .filter(|path| {
                !self.baseline_libraries.contains(*path)
                    && !settings
                        .allowed_library_prefixes
                        .iter()
                        .any(|prefix| path.starts_with(prefix))
            })
            .cloned()
            .collect::<Vec<_>>();
        let debugger_attached = snapshot.tracer_pid.unwrap_or_default() > 0;
        let ready = !debugger_attached && unexpected_library_loads.is_empty();
        let details = if ready {
            format!(
                "checked TracerPid and {} mapped libraries against the startup baseline",
                snapshot.libraries.len()
            )
        } else {
            let mut reasons = Vec::new();
            if debugger_attached {
                reasons.push(format!(
                    "debugger attached via TracerPid={}",
                    snapshot.tracer_pid.unwrap_or_default()
                ));
            }
            if !unexpected_library_loads.is_empty() {
                reasons.push(format!(
                    "{} unexpected library load(s)",
                    unexpected_library_loads.len()
                ));
            }
            reasons.join("; ")
        };

        AntiTamperReport {
            enabled: true,
            supported: true,
            required,
            ready,
            checked_at_ms: now_ms(),
            status: if ready {
                "ok".to_string()
            } else {
                "tampered".to_string()
            },
            details,
            debugger_attached,
            tracer_pid: snapshot.tracer_pid.filter(|pid| *pid > 0),
            unexpected_library_loads,
            baseline_library_count: self.baseline_libraries.len(),
            fail_closed_live_response: settings.fail_closed_live_response,
        }
    }

    fn alert_fingerprint(&self, report: &AntiTamperReport) -> String {
        format!(
            "debugger:{}|tracer:{:?}|libs:{}",
            report.debugger_attached,
            report.tracer_pid,
            report.unexpected_library_loads.join(",")
        )
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_tracer_pid(raw: &str) -> Result<Option<u32>, String> {
    let line = raw
        .lines()
        .find(|line| line.starts_with("TracerPid:"))
        .ok_or_else(|| "missing TracerPid field in /proc/self/status".to_string())?;
    let value = line
        .split_once(':')
        .map(|(_, value)| value.trim())
        .ok_or_else(|| "failed to parse TracerPid field".to_string())?;
    let tracer_pid = value
        .parse::<u32>()
        .map_err(|error| format!("invalid TracerPid value `{value}`: {error}"))?;
    Ok(Some(tracer_pid))
}

#[cfg(any(target_os = "linux", test))]
fn collect_mapped_libraries(raw: &str) -> BTreeSet<String> {
    raw.lines()
        .filter_map(|line| {
            let path = line.split_whitespace().nth(5)?;
            let path = path.strip_suffix(" (deleted)").unwrap_or(path);
            if !path.starts_with('/') || !path.contains(".so") {
                return None;
            }
            Some(path.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        AntiTamperFailure, AntiTamperMonitor, AntiTamperProbe, AntiTamperSnapshot,
        collect_mapped_libraries, parse_tracer_pid,
    };
    use std::collections::BTreeSet;
    use swarm_core::config::{RuntimeAntiTamperConfig, RuntimeMode};

    #[derive(Clone)]
    struct StaticProbe {
        supported: bool,
        snapshot: Result<AntiTamperSnapshot, String>,
    }

    impl AntiTamperProbe for StaticProbe {
        fn supported(&self) -> bool {
            self.supported
        }

        fn snapshot(&self) -> Result<AntiTamperSnapshot, String> {
            self.snapshot.clone()
        }
    }

    fn anti_tamper_settings() -> RuntimeAntiTamperConfig {
        RuntimeAntiTamperConfig {
            enabled: true,
            check_interval_ms: 1_000,
            fail_closed_live_response: false,
            allowed_library_prefixes: vec!["/usr/lib".to_string()],
        }
    }

    #[test]
    fn tracer_pid_parser_reads_linux_status_field() {
        let status = "Name:\tswarm_detect\nTracerPid:\t42\n";
        assert_eq!(parse_tracer_pid(status).unwrap(), Some(42));
    }

    #[test]
    fn mapped_library_parser_filters_non_shared_objects() {
        let maps = "\
7f0f94000000-7f0f94021000 r--p 00000000 08:01 123 /usr/lib/libssl.so.3\n\
7f0f94021000-7f0f94022000 rw-p 00000000 00:00 0 [heap]\n\
7ffd12345000-7ffd12347000 r-xp 00000000 00:00 0 [vdso]\n\
";
        let libraries = collect_mapped_libraries(maps);
        assert_eq!(libraries.len(), 1);
        assert!(libraries.contains("/usr/lib/libssl.so.3"));
    }

    #[test]
    fn live_response_report_can_fail_closed_on_debugger_attach() {
        let baseline: BTreeSet<String> = ["/usr/lib/libssl.so.3".to_string()].into_iter().collect();
        let monitor = AntiTamperMonitor {
            probe: StaticProbe {
                supported: true,
                snapshot: Ok(AntiTamperSnapshot {
                    tracer_pid: Some(88),
                    libraries: baseline.clone(),
                }),
            },
            baseline_libraries: baseline,
            last_alert_fingerprint: None,
        };
        let mut settings = anti_tamper_settings();
        settings.fail_closed_live_response = true;
        let report = monitor.evaluate(&settings, RuntimeMode::LiveResponse);

        assert!(!report.ready);
        assert!(report.required);
        assert!(!report.effective_ready());
        assert!(report.debugger_attached);
        assert!(
            AntiTamperFailure::new(&report)
                .to_string()
                .contains("debugger attached")
        );
    }

    #[test]
    fn detect_only_mode_does_not_fail_closed_when_not_required() {
        let baseline: BTreeSet<String> = ["/usr/lib/libssl.so.3".to_string()].into_iter().collect();
        let monitor = AntiTamperMonitor {
            probe: StaticProbe {
                supported: true,
                snapshot: Ok(AntiTamperSnapshot {
                    tracer_pid: Some(12),
                    libraries: baseline.clone(),
                }),
            },
            baseline_libraries: baseline,
            last_alert_fingerprint: None,
        };
        let mut settings = anti_tamper_settings();
        settings.fail_closed_live_response = true;
        let report = monitor.evaluate(&settings, RuntimeMode::DetectOnly);

        assert!(!report.ready);
        assert!(!report.required);
        assert!(report.effective_ready());
    }

    #[test]
    fn unexpected_library_outside_allowlist_is_reported() {
        let baseline = ["/usr/lib/libssl.so.3".to_string()].into_iter().collect();
        let monitor = AntiTamperMonitor {
            probe: StaticProbe {
                supported: true,
                snapshot: Ok(AntiTamperSnapshot {
                    tracer_pid: Some(0),
                    libraries: [
                        "/usr/lib/libssl.so.3".to_string(),
                        "/tmp/rogue.so".to_string(),
                    ]
                    .into_iter()
                    .collect(),
                }),
            },
            baseline_libraries: baseline,
            last_alert_fingerprint: None,
        };
        let report = monitor.evaluate(&anti_tamper_settings(), RuntimeMode::LiveResponse);

        assert_eq!(
            report.unexpected_library_loads,
            vec!["/tmp/rogue.so".to_string()]
        );
        assert!(report.tamper_detected());
    }

    #[test]
    fn new_library_under_allowed_prefix_is_not_reported() {
        let baseline = BTreeSet::new();
        let monitor = AntiTamperMonitor {
            probe: StaticProbe {
                supported: true,
                snapshot: Ok(AntiTamperSnapshot {
                    tracer_pid: Some(0),
                    libraries: ["/usr/lib/libcrypto.so.3".to_string()]
                        .into_iter()
                        .collect(),
                }),
            },
            baseline_libraries: baseline,
            last_alert_fingerprint: None,
        };
        let report = monitor.evaluate(&anti_tamper_settings(), RuntimeMode::LiveResponse);

        assert!(report.ready);
        assert!(report.unexpected_library_loads.is_empty());
    }

    #[test]
    fn unsupported_probe_surfaces_non_blocking_report() {
        let monitor = AntiTamperMonitor {
            probe: StaticProbe {
                supported: false,
                snapshot: Err("unsupported".to_string()),
            },
            baseline_libraries: BTreeSet::new(),
            last_alert_fingerprint: None,
        };
        let mut settings = anti_tamper_settings();
        settings.fail_closed_live_response = true;
        let report = monitor.evaluate(&settings, RuntimeMode::LiveResponse);

        assert_eq!(report.status, "unsupported");
        assert!(!report.ready);
        assert!(!report.required);
        assert!(report.effective_ready());
    }
}
