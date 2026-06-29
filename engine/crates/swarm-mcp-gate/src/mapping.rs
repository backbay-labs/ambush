//! Map an OpenKnowledge MCP tool call to a swarm-governor AgentAction so the real guards govern it.
//!
//! Reads map to FileAccess (forbidden_path applies); writes to FileWrite (forbidden_path +
//! secret_leak); destructive verbs that have a *genuine* shell semantic map to their canonical
//! shell equivalent so the shell_command guard governs them honestly. Every other tool call is a
//! real MCP invocation with no filesystem/shell semantics, so it maps honestly to
//! `AgentAction::McpTool { tool, args }` — governed by the `mcp_tool` guard (deny-by-default) —
//! instead of being coerced into a fabricated shell-command string. Unknown tools additionally
//! hard-deny (fail-closed) unless `AMBUSH_GATE_ALLOW_UNKNOWN=1`, while still carrying the honest
//! McpTool action so a *signed* deny-context receipt reflects what was actually attempted.

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
            // No genuine shell/filesystem semantic: represent the call honestly as the MCP tool it
            // actually is, so the mcp_tool guard governs it and the receipt records the truth.
            let action = AgentAction::McpTool { tool: other.to_string(), args: args.clone() };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destructive_verbs_keep_genuine_shell_semantics() {
        let args = serde_json::json!({ "path": "/vault/note.md" });
        match map_tool("delete", &args, "/vault") {
            Mapping::Action(AgentAction::ShellCommand { command }) => {
                assert_eq!(command, "rm -rf /vault/note.md");
            }
            _ => panic!("delete should map to a genuine shell command"),
        }
    }

    #[test]
    fn reads_and_writes_keep_filesystem_semantics() {
        let args = serde_json::json!({ "path": "/vault/a.md", "content": "hi" });
        assert!(matches!(
            map_tool("search", &args, "/vault"),
            Mapping::Action(AgentAction::FileAccess { .. })
        ));
        assert!(matches!(
            map_tool("write", &args, "/vault"),
            Mapping::Action(AgentAction::FileWrite { .. })
        ));
    }

    #[test]
    fn unknown_tool_maps_honestly_to_mcp_tool_carried_in_hard_deny() {
        let args = serde_json::json!({ "foo": "bar" });
        // Fail-closed hard-deny, but the carried action is the honest McpTool (so the signed
        // deny-context receipt records the real tool + args) rather than a fabricated shell string.
        // This assertion holds regardless of AMBUSH_GATE_ALLOW_UNKNOWN: both branches carry McpTool.
        let action = match map_tool("teleport", &args, "/vault") {
            Mapping::Action(action) | Mapping::HardDeny { action, .. } => action,
        };
        match action {
            AgentAction::McpTool { tool, args: carried } => {
                assert_eq!(tool, "teleport");
                assert_eq!(carried, args);
            }
            _ => panic!("unknown tool must map to an honest McpTool action"),
        }
    }
}
