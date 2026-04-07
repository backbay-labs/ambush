//! Guard pipeline for response and filesystem safety checks.

pub mod egress_allowlist;
pub mod forbidden_path;
pub mod path_normalization;
pub mod secret_leak;
pub mod shell_command;

use std::panic::{AssertUnwindSafe, catch_unwind};

use serde::{Deserialize, Serialize};
use swarm_core::types::ResponseAction;

pub use egress_allowlist::{DefaultAction, EgressAllowlistConfig, EgressAllowlistGuard};
pub use forbidden_path::{ForbiddenPathConfig, ForbiddenPathGuard};
pub use secret_leak::{SecretLeakConfig, SecretLeakGuard, SecretPattern};
pub use shell_command::{ShellCommandConfig, ShellCommandGuard};

/// Severity level for guard outcomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Result of one guard check.
#[must_use]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardResult {
    pub allowed: bool,
    pub guard: String,
    pub severity: Severity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl GuardResult {
    pub fn allow(guard: impl Into<String>) -> Self {
        Self {
            allowed: true,
            guard: guard.into(),
            severity: Severity::Info,
            message: "Allowed".to_string(),
            details: None,
        }
    }

    pub fn block(guard: impl Into<String>, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            allowed: false,
            guard: guard.into(),
            severity,
            message: message.into(),
            details: None,
        }
    }

    pub fn warn(guard: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            allowed: true,
            guard: guard.into(),
            severity: Severity::Warning,
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// Context available to guards during evaluation.
#[derive(Clone, Debug, Default)]
pub struct GuardContext {
    pub agent_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

impl GuardContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// Action kinds that can be inspected by guards.
#[derive(Clone, Debug)]
pub enum GuardAction<'a> {
    FileAccess(&'a str),
    FileWrite(&'a str, &'a [u8]),
    ShellCommand(&'a str),
    NetworkEgress(&'a str, u16),
    ResponseAction(&'a ResponseAction),
}

/// Synchronous guard trait.
pub trait Guard: Send + Sync {
    fn name(&self) -> &str;
    fn handles(&self, action: &GuardAction<'_>) -> bool;
    fn check(&self, action: &GuardAction<'_>, context: &GuardContext) -> GuardResult;
}

/// Ordered guard pipeline that fails closed on rejection or panic.
pub struct GuardPipeline {
    guards: Vec<Box<dyn Guard>>,
}

impl GuardPipeline {
    pub fn new(guards: Vec<Box<dyn Guard>>) -> Self {
        Self { guards }
    }

    pub fn evaluate(&self, action: &GuardAction<'_>, context: &GuardContext) -> GuardResult {
        for guard in &self.guards {
            if !guard.handles(action) {
                continue;
            }

            let result = match catch_unwind(AssertUnwindSafe(|| guard.check(action, context))) {
                Ok(result) => result,
                Err(_) => {
                    return GuardResult::block(
                        guard.name(),
                        Severity::Critical,
                        format!("guard `{}` panicked during evaluation", guard.name()),
                    );
                }
            };

            if result.guard.is_empty() {
                return GuardResult::block(
                    guard.name(),
                    Severity::Critical,
                    format!("guard `{}` returned an invalid result", guard.name()),
                );
            }

            if !result.allowed {
                return result;
            }
        }

        GuardResult::allow("pipeline")
    }
}

/// Convenience constructor for the default four-guard pipeline.
pub fn default_pipeline() -> GuardPipeline {
    GuardPipeline::new(vec![
        Box::new(ForbiddenPathGuard::new()),
        Box::new(ShellCommandGuard::new()),
        Box::new(SecretLeakGuard::new()),
        Box::new(EgressAllowlistGuard::new()),
    ])
}

#[cfg(test)]
mod tests {
    use super::{
        EgressAllowlistGuard, ForbiddenPathGuard, Guard, GuardAction, GuardContext, GuardPipeline,
        GuardResult, SecretLeakGuard, Severity, ShellCommandGuard, default_pipeline,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use swarm_core::types::{ResponseAction, Severity as CoreSeverity};

    struct StaticGuard {
        name: &'static str,
        handles: bool,
        result: GuardResult,
        calls: Arc<AtomicUsize>,
    }

    impl Guard for StaticGuard {
        fn name(&self) -> &str {
            self.name
        }

        fn handles(&self, _action: &GuardAction<'_>) -> bool {
            self.handles
        }

        fn check(&self, _action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result.clone()
        }
    }

    struct PanicGuard;

    impl Guard for PanicGuard {
        fn name(&self) -> &str {
            "panic"
        }

        fn handles(&self, _action: &GuardAction<'_>) -> bool {
            true
        }

        fn check(&self, _action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
            panic!("boom")
        }
    }

    #[test]
    fn guard_result_helpers_have_expected_defaults() {
        let allow = GuardResult::allow("test");
        assert!(allow.allowed);
        assert_eq!(allow.severity, Severity::Info);

        let block = GuardResult::block("test", Severity::Critical, "blocked");
        assert!(!block.allowed);
        assert_eq!(block.message, "blocked");

        let warn = GuardResult::warn("test", "careful");
        assert!(warn.allowed);
        assert_eq!(warn.severity, Severity::Warning);
    }

    #[test]
    fn pipeline_with_no_guards_allows() {
        let pipeline = GuardPipeline::new(Vec::new());
        let result = pipeline.evaluate(
            &GuardAction::ShellCommand("echo hello"),
            &GuardContext::new(),
        );

        assert!(result.allowed);
        assert_eq!(result.guard, "pipeline");
    }

    #[test]
    fn pipeline_returns_first_blocking_result() {
        let calls = Arc::new(AtomicUsize::new(0));
        let second_calls = Arc::new(AtomicUsize::new(0));
        let pipeline = GuardPipeline::new(vec![
            Box::new(StaticGuard {
                name: "allow",
                handles: true,
                result: GuardResult::allow("allow"),
                calls: Arc::clone(&calls),
            }),
            Box::new(StaticGuard {
                name: "block",
                handles: true,
                result: GuardResult::block("block", Severity::Critical, "nope"),
                calls: Arc::clone(&second_calls),
            }),
        ]);

        let result = pipeline.evaluate(
            &GuardAction::ShellCommand("echo hello"),
            &GuardContext::new(),
        );
        assert!(!result.allowed);
        assert_eq!(result.guard, "block");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(second_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn pipeline_short_circuits_after_block() {
        let block_calls = Arc::new(AtomicUsize::new(0));
        let skipped_calls = Arc::new(AtomicUsize::new(0));
        let pipeline = GuardPipeline::new(vec![
            Box::new(StaticGuard {
                name: "block",
                handles: true,
                result: GuardResult::block("block", Severity::Critical, "nope"),
                calls: Arc::clone(&block_calls),
            }),
            Box::new(StaticGuard {
                name: "skipped",
                handles: true,
                result: GuardResult::allow("skipped"),
                calls: Arc::clone(&skipped_calls),
            }),
        ]);

        let result = pipeline.evaluate(
            &GuardAction::ShellCommand("echo hello"),
            &GuardContext::new(),
        );
        assert!(!result.allowed);
        assert_eq!(block_calls.load(Ordering::SeqCst), 1);
        assert_eq!(skipped_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn pipeline_fails_closed_on_panic() {
        let pipeline = GuardPipeline::new(vec![Box::new(PanicGuard)]);
        let result = pipeline.evaluate(
            &GuardAction::ShellCommand("echo hello"),
            &GuardContext::new(),
        );

        assert!(!result.allowed);
        assert_eq!(result.severity, Severity::Critical);
    }

    #[test]
    fn response_action_variant_wraps_swarm_core_response_action() {
        let action = ResponseAction::Escalate {
            summary: "needs review".to_string(),
            urgency: CoreSeverity::High,
        };
        let guard_action = GuardAction::ResponseAction(&action);

        match guard_action {
            GuardAction::ResponseAction(ResponseAction::Escalate { summary, .. }) => {
                assert_eq!(summary, "needs review");
            }
            _ => panic!("unexpected action variant"),
        }
    }

    #[test]
    fn concrete_guards_are_constructible() {
        let _ = ForbiddenPathGuard::new();
        let _ = ShellCommandGuard::new();
        let _ = SecretLeakGuard::new();
        let _ = EgressAllowlistGuard::new();
    }

    #[test]
    fn default_pipeline_blocks_secret_file_write() {
        let pipeline = default_pipeline();
        let result = pipeline.evaluate(
            &GuardAction::FileWrite("/tmp/secrets.txt", b"AKIA1234567890ABCDEF"),
            &GuardContext::new(),
        );

        assert!(!result.allowed);
        assert_eq!(result.guard, "secret_leak");
    }

    #[test]
    fn default_pipeline_blocks_dangerous_shell_command() {
        let pipeline = default_pipeline();
        let result =
            pipeline.evaluate(&GuardAction::ShellCommand("rm -rf /"), &GuardContext::new());

        assert!(!result.allowed);
        assert_eq!(result.guard, "shell_command");
    }

    #[test]
    fn default_pipeline_blocks_off_allowlist_egress() {
        let pipeline = default_pipeline();
        let result = pipeline.evaluate(
            &GuardAction::NetworkEgress("evil.com", 443),
            &GuardContext::new(),
        );

        assert!(!result.allowed);
        assert_eq!(result.guard, "egress_allowlist");
    }

    #[test]
    fn default_pipeline_blocks_forbidden_file_access() {
        let pipeline = default_pipeline();
        let result = pipeline.evaluate(
            &GuardAction::FileAccess("/etc/shadow"),
            &GuardContext::new(),
        );

        assert!(!result.allowed);
        assert_eq!(result.guard, "forbidden_path");
    }

    #[test]
    fn default_pipeline_allows_safe_file_access() {
        let pipeline = default_pipeline();
        let result = pipeline.evaluate(
            &GuardAction::FileAccess("/app/main.rs"),
            &GuardContext::new(),
        );

        assert!(result.allowed);
        assert_eq!(result.guard, "pipeline");
    }
}
