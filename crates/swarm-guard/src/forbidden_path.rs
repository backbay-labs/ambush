//! Guard that blocks access to sensitive filesystem paths.

use glob::Pattern;
use serde::{Deserialize, Serialize};

use crate::path_normalization::normalize_path_for_policy;
use crate::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// Configuration for [`ForbiddenPathGuard`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForbiddenPathConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patterns: Option<Vec<String>>,
    #[serde(default)]
    pub exceptions: Vec<String>,
}

impl Default for ForbiddenPathConfig {
    fn default() -> Self {
        Self::with_defaults()
    }
}

fn default_enabled() -> bool {
    true
}

fn default_forbidden_patterns() -> Vec<String> {
    vec![
        "**/.ssh/**".to_string(),
        "**/id_rsa*".to_string(),
        "**/id_ed25519*".to_string(),
        "**/id_ecdsa*".to_string(),
        "**/.aws/**".to_string(),
        "**/.env".to_string(),
        "**/.env.*".to_string(),
        "**/.git-credentials".to_string(),
        "**/.gitconfig".to_string(),
        "**/.gnupg/**".to_string(),
        "**/.kube/**".to_string(),
        "**/.docker/**".to_string(),
        "**/.npmrc".to_string(),
        "**/.password-store/**".to_string(),
        "/etc/shadow".to_string(),
        "/etc/passwd".to_string(),
        "/etc/sudoers".to_string(),
    ]
}

impl ForbiddenPathConfig {
    pub fn with_defaults() -> Self {
        Self {
            enabled: true,
            patterns: None,
            exceptions: Vec::new(),
        }
    }

    pub fn effective_patterns(&self) -> Vec<String> {
        self.patterns
            .clone()
            .unwrap_or_else(default_forbidden_patterns)
    }
}

/// Guard that blocks access to configured sensitive paths.
pub struct ForbiddenPathGuard {
    name: String,
    enabled: bool,
    patterns: Vec<Pattern>,
    exceptions: Vec<Pattern>,
}

impl ForbiddenPathGuard {
    pub fn new() -> Self {
        Self::with_config(ForbiddenPathConfig::with_defaults())
    }

    pub fn with_config(config: ForbiddenPathConfig) -> Self {
        let patterns = config
            .effective_patterns()
            .iter()
            .filter_map(|pattern| Pattern::new(pattern).ok())
            .collect();
        let exceptions = config
            .exceptions
            .iter()
            .filter_map(|pattern| Pattern::new(pattern).ok())
            .collect();

        Self {
            name: "forbidden_path".to_string(),
            enabled: config.enabled,
            patterns,
            exceptions,
        }
    }

    /// Return `true` when a path matches the forbidden set and not an exception.
    pub fn is_forbidden(&self, path: &str) -> bool {
        let normalized = normalize_path_for_policy(path);

        if self
            .exceptions
            .iter()
            .any(|exception| exception.matches(&normalized))
        {
            return false;
        }

        self.patterns
            .iter()
            .any(|pattern| pattern.matches(&normalized))
    }
}

impl Default for ForbiddenPathGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for ForbiddenPathGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        self.enabled
            && matches!(
                action,
                GuardAction::FileAccess(_) | GuardAction::FileWrite(_, _)
            )
    }

    fn check(&self, action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        if !self.enabled {
            return GuardResult::allow(&self.name);
        }

        let path = match action {
            GuardAction::FileAccess(path) => *path,
            GuardAction::FileWrite(path, _) => *path,
            _ => return GuardResult::allow(&self.name),
        };

        if self.is_forbidden(path) {
            GuardResult::block(
                &self.name,
                Severity::Critical,
                format!("access to forbidden path: {path}"),
            )
            .with_details(serde_json::json!({
                "path": path,
                "reason": "matches_forbidden_pattern",
            }))
        } else {
            GuardResult::allow(&self.name)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ForbiddenPathConfig, ForbiddenPathGuard};
    use crate::{Guard, GuardAction};

    #[test]
    fn blocks_sensitive_default_paths() {
        let guard = ForbiddenPathGuard::new();

        assert!(guard.is_forbidden("/home/user/.ssh/id_rsa"));
        assert!(guard.is_forbidden("/home/user/.aws/credentials"));
        assert!(guard.is_forbidden("/etc/shadow"));
        assert!(guard.is_forbidden("/app/.env"));
        assert!(guard.is_forbidden("/app/.env.local"));
    }

    #[test]
    fn passes_benign_paths() {
        let guard = ForbiddenPathGuard::new();

        assert!(!guard.is_forbidden("/app/src/main.rs"));
        assert!(!guard.is_forbidden("/home/user/project/README.md"));
    }

    #[test]
    fn exceptions_allow_specific_paths() {
        let guard = ForbiddenPathGuard::with_config(ForbiddenPathConfig {
            enabled: true,
            patterns: Some(vec!["/etc/**".to_string()]),
            exceptions: vec!["/etc/hosts".to_string()],
        });

        assert!(guard.is_forbidden("/etc/shadow"));
        assert!(!guard.is_forbidden("/etc/hosts"));
    }

    #[test]
    fn handles_only_file_actions() {
        let guard = ForbiddenPathGuard::new();
        assert!(guard.handles(&GuardAction::FileAccess("/etc/shadow")));
        assert!(guard.handles(&GuardAction::FileWrite("/etc/shadow", b"bad")));
        assert!(!guard.handles(&GuardAction::ShellCommand("cat /etc/shadow")));
    }
}
