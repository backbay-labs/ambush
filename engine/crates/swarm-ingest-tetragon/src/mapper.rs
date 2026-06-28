use crate::client::proto;
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::{ProcessStartEvent, TelemetryEvent, TelemetryPayload};

pub fn map_process_exec(exec: &proto::ProcessExec, node_name: &str) -> Option<TelemetryEvent> {
    let process = exec.process.as_ref()?;
    let process_name = process.binary.clone();
    let command_line = format!("{} {}", process.binary, process.arguments)
        .trim()
        .to_string();
    let parent_process = exec
        .parent
        .as_ref()
        .map(|parent| parent.binary.clone())
        .filter(|binary| !binary.trim().is_empty())
        .unwrap_or_else(|| "<none>".to_string());
    let event_id = if node_name.is_empty() {
        format!("tetragon:{}", process.exec_id)
    } else {
        format!("tetragon:{node_name}:{}", process.exec_id)
    };

    Some(TelemetryEvent {
        source: "tetragon".to_string(),
        event_id,
        timestamp: process
            .start_time
            .as_ref()
            .map(|timestamp| timestamp.seconds)
            .unwrap_or_else(current_unix_timestamp),
        host_id: (!node_name.is_empty()).then(|| node_name.to_string()),
        payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
            parent_process,
            process_name,
            command_line,
            user: process.uid.map(|uid| uid.to_string()),
            executable_path: Some(process.binary.clone()),
            signer: None,
            signature_valid: None,
        }),
    })
}

fn current_unix_timestamp() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i64,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::map_process_exec;
    use crate::client::proto;
    use prost_types::Timestamp;
    use swarm_core::TelemetryPayload;

    fn make_process(
        exec_id: &str,
        binary: &str,
        arguments: &str,
        uid: Option<u32>,
        start_time_seconds: Option<i64>,
    ) -> proto::Process {
        proto::Process {
            exec_id: exec_id.to_string(),
            binary: binary.to_string(),
            arguments: arguments.to_string(),
            uid,
            start_time: start_time_seconds.map(|seconds| Timestamp { seconds, nanos: 0 }),
            ..Default::default()
        }
    }

    #[test]
    fn valid_process_exec_maps_to_process_start_telemetry() {
        let exec = proto::ProcessExec {
            process: Some(make_process(
                "exec-1",
                "/usr/bin/bash",
                "-lc whoami",
                Some(1000),
                Some(42),
            )),
            parent: Some(make_process(
                "parent-1",
                "/usr/bin/sshd",
                "",
                Some(0),
                Some(41),
            )),
            ancestors: Vec::new(),
        };

        let event = map_process_exec(&exec, "node-a").expect("event should map");
        assert_eq!(event.source, "tetragon");
        assert_eq!(event.event_id, "tetragon:node-a:exec-1");
        assert_eq!(event.host_id.as_deref(), Some("node-a"));
        assert_eq!(event.timestamp, 42);

        match event.payload {
            TelemetryPayload::ProcessStart(process) => {
                assert_eq!(process.process_name, "/usr/bin/bash");
                assert_eq!(process.command_line, "/usr/bin/bash -lc whoami");
                assert_eq!(process.parent_process, "/usr/bin/sshd");
                assert_eq!(process.user.as_deref(), Some("1000"));
            }
            _ => panic!("expected process_start payload"),
        }
    }

    #[test]
    fn missing_parent_maps_to_sentinel() {
        let exec = proto::ProcessExec {
            process: Some(make_process(
                "exec-2",
                "/bin/sh",
                "-c id",
                Some(1001),
                Some(84),
            )),
            parent: None,
            ancestors: Vec::new(),
        };

        let event = map_process_exec(&exec, "node-b").expect("event should map");
        match event.payload {
            TelemetryPayload::ProcessStart(process) => {
                assert_eq!(process.parent_process, "<none>");
            }
            _ => panic!("expected process_start payload"),
        }
    }

    #[test]
    fn empty_binary_parent_maps_to_sentinel() {
        let exec = proto::ProcessExec {
            process: Some(make_process(
                "exec-6",
                "/usr/bin/systemd",
                "--system",
                Some(1),
                Some(1),
            )),
            parent: Some(proto::Process {
                binary: "".to_string(),
                ..Default::default()
            }),
            ancestors: Vec::new(),
        };
        let event = map_process_exec(&exec, "node-f").expect("event should map");
        match event.payload {
            TelemetryPayload::ProcessStart(process) => {
                assert_eq!(process.parent_process, "<none>");
            }
            _ => panic!("expected process_start payload"),
        }
    }

    #[test]
    fn missing_process_returns_none() {
        let exec = proto::ProcessExec {
            process: None,
            parent: None,
            ancestors: Vec::new(),
        };

        assert!(map_process_exec(&exec, "node-c").is_none());
    }

    #[test]
    fn empty_binary_still_maps_without_panicking() {
        let exec = proto::ProcessExec {
            process: Some(make_process("exec-3", "", "--flag", None, Some(99))),
            parent: None,
            ancestors: Vec::new(),
        };

        let event = map_process_exec(&exec, "node-d").expect("event should map");
        match event.payload {
            TelemetryPayload::ProcessStart(process) => {
                assert_eq!(process.process_name, "");
                assert_eq!(process.command_line, "--flag");
            }
            _ => panic!("expected process_start payload"),
        }
    }

    #[test]
    fn empty_node_name_omits_host_id() {
        let exec = proto::ProcessExec {
            process: Some(make_process(
                "exec-4",
                "/usr/bin/python",
                "script.py",
                Some(1002),
                Some(123),
            )),
            parent: None,
            ancestors: Vec::new(),
        };

        let event = map_process_exec(&exec, "").expect("event should map");
        assert_eq!(event.event_id, "tetragon:exec-4");
        assert!(event.host_id.is_none());
    }

    #[test]
    fn missing_start_time_falls_back_to_current_time() {
        let exec = proto::ProcessExec {
            process: Some(make_process("exec-5", "/bin/echo", "hello", None, None)),
            parent: None,
            ancestors: Vec::new(),
        };

        let event = map_process_exec(&exec, "node-e").expect("event should map");
        assert!(event.timestamp > 0);
    }
}
