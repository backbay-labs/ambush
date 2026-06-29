// Adapted from ClawdStrike/Arc (Apache-2.0)
//! MCP tool guard — restricts tool invocations crossing the MCP trust boundary.

use std::collections::HashSet;
use std::io;

use serde::{Deserialize, Serialize};

use crate::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// Default behavior when a tool is not explicitly allowed/blocked.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum McpDefaultAction {
    Allow,
    #[default]
    #[serde(alias = "deny")]
    Block,
}

/// Configuration for [`McpToolGuard`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpToolConfig {
    /// Enable/disable this guard.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Allowed tool names (if empty, all are allowed except blocked).
    #[serde(default)]
    pub allow: Vec<String>,
    /// Blocked tool names (takes precedence).
    #[serde(default, alias = "deny")]
    pub block: Vec<String>,
    /// Tools that require confirmation.
    #[serde(default)]
    pub require_confirmation: Vec<String>,
    /// Default action when not explicitly matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_action: Option<McpDefaultAction>,
    /// Maximum arguments size (bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_args_size: Option<usize>,
    /// Additional allowed tools when merging.
    #[serde(default)]
    pub additional_allow: Vec<String>,
    /// Tools to remove from allow list when merging.
    #[serde(default)]
    pub remove_allow: Vec<String>,
    /// Additional blocked tools when merging.
    #[serde(default)]
    pub additional_block: Vec<String>,
    /// Tools to remove from block list when merging.
    #[serde(default)]
    pub remove_block: Vec<String>,
}

impl Default for McpToolConfig {
    fn default() -> Self {
        Self::with_defaults()
    }
}

fn default_enabled() -> bool {
    true
}

fn default_max_args_size() -> usize {
    1024 * 1024 // 1MB
}

fn json_size_bytes(value: &serde_json::Value) -> Result<usize, serde_json::Error> {
    struct CountingWriter {
        count: usize,
    }

    impl io::Write for CountingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.count += buf.len();
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut writer = CountingWriter { count: 0 };
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.count)
}

impl McpToolConfig {
    fn resolve_lists(
        base_allow: &[String],
        base_block: &[String],
        overlay: &Self,
    ) -> (Vec<String>, Vec<String>) {
        let mut allow = base_allow.to_vec();
        let mut block = base_block.to_vec();

        for tool in &overlay.additional_allow {
            if !allow.contains(tool) {
                allow.push(tool.clone());
            }
        }
        for tool in &overlay.additional_block {
            if !block.contains(tool) {
                block.push(tool.clone());
            }
        }

        allow.retain(|tool| !overlay.remove_allow.contains(tool));
        block.retain(|tool| !overlay.remove_block.contains(tool));

        if !overlay.allow.is_empty() {
            allow = overlay.allow.clone();
        }
        if !overlay.block.is_empty() {
            block = overlay.block.clone();
        }

        (allow, block)
    }

    /// Return the standalone allowlist after applying merge-time modifiers.
    pub fn effective_allow_tools(&self) -> Vec<String> {
        let (allow, _) = Self::resolve_lists(&[], &[], self);
        allow
    }

    /// Return the standalone blocklist after applying merge-time modifiers.
    pub fn effective_block_tools(&self) -> Vec<String> {
        let (_, block) = Self::resolve_lists(&[], &[], self);
        block
    }

    /// Create config with default blocked/confirm tools and a deny-by-default posture.
    pub fn with_defaults() -> Self {
        Self {
            enabled: true,
            allow: vec![],
            block: vec![
                // Dangerous shell operations.
                "shell_exec".to_string(),
                "run_command".to_string(),
                // Direct file system access that bypasses guards.
                "raw_file_write".to_string(),
                "raw_file_delete".to_string(),
            ],
            require_confirmation: vec![
                "file_write".to_string(),
                "file_delete".to_string(),
                "git_push".to_string(),
            ],
            default_action: Some(McpDefaultAction::Block),
            max_args_size: Some(default_max_args_size()),
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        }
    }

    /// Merge this config with a child config.
    pub fn merge_with(&self, child: &Self) -> Self {
        let (allow, block) = Self::resolve_lists(&self.allow, &self.block, child);
        let mut require_confirmation = self.require_confirmation.clone();
        if !child.require_confirmation.is_empty() {
            require_confirmation = child.require_confirmation.clone();
        }

        Self {
            enabled: child.enabled,
            allow,
            block,
            require_confirmation,
            default_action: child.default_action.or(self.default_action),
            max_args_size: child.max_args_size.or(self.max_args_size),
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        }
    }
}

/// Guard that controls MCP tool invocations.
pub struct McpToolGuard {
    name: String,
    enabled: bool,
    config: McpToolConfig,
    allow_set: HashSet<String>,
    block_set: HashSet<String>,
    confirm_set: HashSet<String>,
}

impl McpToolGuard {
    /// Create with default configuration.
    pub fn new() -> Self {
        Self::with_config(McpToolConfig::with_defaults())
    }

    /// Create with custom configuration.
    pub fn with_config(config: McpToolConfig) -> Self {
        let enabled = config.enabled;
        let allow_set: HashSet<_> = config.effective_allow_tools().into_iter().collect();
        let block_set: HashSet<_> = config.effective_block_tools().into_iter().collect();
        let confirm_set: HashSet<_> = config.require_confirmation.iter().cloned().collect();

        Self {
            name: "mcp_tool".to_string(),
            enabled,
            config,
            allow_set,
            block_set,
            confirm_set,
        }
    }

    /// Decide whether a tool name is allowed.
    pub fn is_allowed(&self, tool_name: &str) -> ToolDecision {
        // Blocked takes precedence.
        if self.block_set.contains(tool_name) {
            return ToolDecision::Block;
        }

        // Check if it requires confirmation.
        if self.confirm_set.contains(tool_name) {
            return ToolDecision::RequireConfirmation;
        }

        // Allowlist mode: only allowed tools pass.
        if !self.allow_set.is_empty() {
            if self.allow_set.contains(tool_name) {
                return ToolDecision::Allow;
            } else {
                return ToolDecision::Block;
            }
        }

        // Default action.
        if self.config.default_action.unwrap_or_default() == McpDefaultAction::Block {
            ToolDecision::Block
        } else {
            ToolDecision::Allow
        }
    }
}

impl Default for McpToolGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Decision for a tool invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolDecision {
    Allow,
    Block,
    RequireConfirmation,
}

impl Guard for McpToolGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        self.enabled && matches!(action, GuardAction::McpTool(_, _))
    }

    fn check(&self, action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        if !self.enabled {
            return GuardResult::allow(&self.name);
        }

        let (tool_name, args) = match action {
            GuardAction::McpTool(name, args) => (*name, *args),
            _ => return GuardResult::allow(&self.name),
        };

        // Check args size.
        let args_size = match json_size_bytes(args) {
            Ok(bytes) => bytes,
            Err(e) => {
                return GuardResult::block(
                    &self.name,
                    Severity::Error,
                    format!("failed to serialize tool args: {e}"),
                );
            }
        };

        let max_args_size = self.config.max_args_size.unwrap_or_else(default_max_args_size);
        if args_size > max_args_size {
            return GuardResult::block(
                &self.name,
                Severity::Error,
                format!("tool arguments too large: {args_size} bytes (max: {max_args_size})"),
            );
        }

        match self.is_allowed(tool_name) {
            ToolDecision::Allow => GuardResult::allow(&self.name),
            ToolDecision::Block => GuardResult::block(
                &self.name,
                Severity::Error,
                format!("tool '{tool_name}' is blocked by policy"),
            )
            .with_details(serde_json::json!({
                "tool": tool_name,
                "reason": "blocked_by_policy",
            })),
            ToolDecision::RequireConfirmation => GuardResult::block(
                &self.name,
                Severity::Error,
                format!("tool '{tool_name}' requires confirmation"),
            )
            .with_details(serde_json::json!({
                "tool": tool_name,
                "requires_confirmation": true,
                "reason": "approval_required",
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Guard;

    #[test]
    fn default_blocks_dangerous_tools() {
        let guard = McpToolGuard::new();
        assert_eq!(guard.is_allowed("shell_exec"), ToolDecision::Block);
        assert_eq!(guard.is_allowed("run_command"), ToolDecision::Block);
    }

    #[test]
    fn default_blocks_unknown_tools() {
        let guard = McpToolGuard::new();
        assert_eq!(guard.is_allowed("read_file"), ToolDecision::Block);
        assert_eq!(guard.is_allowed("list_directory"), ToolDecision::Block);
    }

    #[test]
    fn require_confirmation_tools() {
        let guard = McpToolGuard::new();
        assert_eq!(
            guard.is_allowed("file_write"),
            ToolDecision::RequireConfirmation
        );
        assert_eq!(
            guard.is_allowed("git_push"),
            ToolDecision::RequireConfirmation
        );
    }

    #[test]
    fn allowlist_mode() {
        let config = McpToolConfig {
            allow: vec!["safe_tool".to_string()],
            block: vec![],
            require_confirmation: vec![],
            default_action: Some(McpDefaultAction::Block),
            max_args_size: Some(1024),
            ..Default::default()
        };
        let guard = McpToolGuard::with_config(config);
        assert_eq!(guard.is_allowed("safe_tool"), ToolDecision::Allow);
        assert_eq!(guard.is_allowed("other_tool"), ToolDecision::Block);
    }

    #[test]
    fn standalone_effective_lists_apply_merge_time_modifiers() {
        let config = McpToolConfig {
            enabled: true,
            allow: vec![],
            block: vec![],
            require_confirmation: vec![],
            default_action: Some(McpDefaultAction::Block),
            max_args_size: Some(1024),
            additional_allow: vec!["safe_tool".to_string()],
            remove_allow: vec![],
            additional_block: vec!["danger_tool".to_string()],
            remove_block: vec![],
        };

        assert_eq!(config.effective_allow_tools(), vec!["safe_tool".to_string()]);
        assert_eq!(
            config.effective_block_tools(),
            vec!["danger_tool".to_string()]
        );

        let guard = McpToolGuard::with_config(config);
        assert_eq!(guard.is_allowed("safe_tool"), ToolDecision::Allow);
        assert_eq!(guard.is_allowed("danger_tool"), ToolDecision::Block);
        assert_eq!(guard.is_allowed("other_tool"), ToolDecision::Block);
    }

    #[test]
    fn handles_only_mcp_tool_actions() {
        let guard = McpToolGuard::new();
        let args = serde_json::json!({});
        assert!(guard.handles(&GuardAction::McpTool("read_file", &args)));
        assert!(!guard.handles(&GuardAction::FileAccess("/tmp/file")));
    }

    #[test]
    fn check_blocks_unknown_and_dangerous_tools() {
        let guard = McpToolGuard::new();
        let context = GuardContext::new();
        let args = serde_json::json!({ "path": "/app/file.txt" });

        assert!(
            !guard
                .check(&GuardAction::McpTool("read_file", &args), &context)
                .allowed
        );
        assert!(
            !guard
                .check(&GuardAction::McpTool("shell_exec", &args), &context)
                .allowed
        );
    }

    #[test]
    fn check_allows_allowlisted_tool() {
        let config = McpToolConfig {
            allow: vec!["search".to_string()],
            block: vec![],
            require_confirmation: vec![],
            default_action: Some(McpDefaultAction::Block),
            max_args_size: Some(1024),
            ..Default::default()
        };
        let guard = McpToolGuard::with_config(config);
        let context = GuardContext::new();
        let args = serde_json::json!({ "q": "hello" });

        let result = guard.check(&GuardAction::McpTool("search", &args), &context);
        assert!(result.allowed);
    }

    #[test]
    fn confirmation_required_blocks_until_approved() {
        let guard = McpToolGuard::new();
        let context = GuardContext::new();
        let args = serde_json::json!({ "path": "/app/file.txt" });

        let result = guard.check(&GuardAction::McpTool("git_push", &args), &context);
        assert!(!result.allowed);
        assert_eq!(result.severity, Severity::Error);
        assert_eq!(
            result
                .details
                .as_ref()
                .and_then(|details| details["reason"].as_str()),
            Some("approval_required")
        );
    }

    #[test]
    fn args_size_limit_is_enforced() {
        let config = McpToolConfig {
            max_args_size: Some(100),
            ..Default::default()
        };
        let guard = McpToolGuard::with_config(config);
        let context = GuardContext::new();
        let large_args = serde_json::json!({ "data": "x".repeat(200) });

        let result = guard.check(&GuardAction::McpTool("some_tool", &large_args), &context);
        assert!(!result.allowed);
    }
}
