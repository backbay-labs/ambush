//! Map an OpenKnowledge MCP tool call to a swarm-governor AgentAction so the real guards govern it.
//!
//! Reads map to FileAccess (forbidden_path applies); writes to FileWrite (forbidden_path +
//! secret_leak); destructive verbs to their canonical shell equivalent so the shell_command guard
//! governs them honestly. Unknown tools hard-deny (fail-closed) while still synthesizing an action
//! so a *signed* deny-context receipt is produced.

use swarm_governor::AgentAction;

pub enum Mapping {
    Action(AgentAction),
    HardDeny { action: AgentAction, reason: String },
}

pub fn map_tool(tool: &str, args: &serde_json::Value, vault: &str) -> Mapping {
    let path = extract(args, &["path", "note", "target", "file", "name"]).unwrap_or_else(|| vault.to_string());
    let content = extract(args, &["content", "text", "body", "markdown"]).unwrap_or_default();
    match tool {
        "search" | "links" | "history" | "config" | "palette" => {
            Mapping::Action(AgentAction::FileAccess { path })
        }
        "write" | "edit" => Mapping::Action(AgentAction::FileWrite { path, content }),
        "checkpoint" => Mapping::Action(AgentAction::ShellCommand {
            command: format!("git -C {vault} commit -am checkpoint"),
        }),
        "workflow" => Mapping::Action(AgentAction::ShellCommand {
            command: format!("ok workflow run {}", extract(args, &["name", "workflow"]).unwrap_or_default()),
        }),
        "skills" => Mapping::Action(AgentAction::ShellCommand {
            command: format!("ok skills run {}", extract(args, &["name", "skill"]).unwrap_or_default()),
        }),
        "move" => {
            let from = extract(args, &["from", "source", "src", "path"]).unwrap_or_default();
            let to = extract(args, &["to", "dest", "target"]).unwrap_or_default();
            Mapping::Action(AgentAction::ShellCommand { command: format!("mv {from} {to}") })
        }
        "delete" => Mapping::Action(AgentAction::ShellCommand { command: format!("rm -rf {path}") }),
        "exec" => Mapping::Action(AgentAction::ShellCommand { command: extract_command(args) }),
        other => {
            let action = AgentAction::ShellCommand { command: format!("{other} {}", compact(args)) };
            if std::env::var("AMBUSH_GATE_ALLOW_UNKNOWN").ok().as_deref() == Some("1") {
                Mapping::Action(action)
            } else {
                Mapping::HardDeny { action, reason: format!("unknown OpenKnowledge tool '{other}' (fail-closed)") }
            }
        }
    }
}

fn extract(args: &serde_json::Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(s) = args.get(k).and_then(|v| v.as_str()) {
            return Some(s.to_string());
        }
    }
    None
}

fn extract_command(args: &serde_json::Value) -> String {
    let base = extract(args, &["command", "cmd"]).unwrap_or_default();
    if let Some(arr) = args.get("args").and_then(|v| v.as_array()) {
        let parts: Vec<String> = arr.iter().filter_map(|v| v.as_str().map(String::from)).collect();
        if !parts.is_empty() {
            return format!("{base} {}", parts.join(" ")).trim().to_string();
        }
    }
    base
}

fn compact(args: &serde_json::Value) -> String {
    serde_json::to_string(args).unwrap_or_default().chars().take(120).collect()
}
