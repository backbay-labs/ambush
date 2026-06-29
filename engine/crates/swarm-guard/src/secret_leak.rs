//! Guard that detects common credential and secret patterns.

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// Pattern definition for one detected secret class.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretPattern {
    pub name: String,
    pub pattern: String,
    pub severity: Severity,
}

/// Configuration for [`SecretLeakGuard`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretLeakConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_redact")]
    pub redact: bool,
    #[serde(default = "default_severity_threshold")]
    pub severity_threshold: Severity,
    #[serde(default = "default_patterns")]
    pub patterns: Vec<SecretPattern>,
}

impl Default for SecretLeakConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            redact: true,
            severity_threshold: Severity::Error,
            patterns: default_patterns(),
        }
    }
}

fn default_enabled() -> bool {
    true
}

fn default_redact() -> bool {
    true
}

fn default_severity_threshold() -> Severity {
    Severity::Error
}

fn default_patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "aws_access_key".to_string(),
            pattern: r"AKIA[0-9A-Z]{16}".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "aws_secret_key".to_string(),
            pattern:
                r#"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['"]?\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}"#
                    .to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "github_token".to_string(),
            pattern: r"gh[ps]_[A-Za-z0-9]{36}".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "github_pat".to_string(),
            pattern: r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "openai_key".to_string(),
            pattern: r"sk-[A-Za-z0-9]{48}".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "anthropic_key".to_string(),
            pattern: r"sk-ant-[A-Za-z0-9\-]{95}".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "private_key".to_string(),
            pattern: r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "npm_token".to_string(),
            pattern: r"npm_[A-Za-z0-9]{36}".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "slack_token".to_string(),
            pattern: r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "stripe_secret_key".to_string(),
            pattern: r"sk_live_[A-Za-z0-9]{24,}".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "generic_api_key".to_string(),
            pattern: r#"(?i)(api[_\-]?key|apikey)[\x27"]?\s*[:=]\s*[\x27"]?[A-Za-z0-9]{32,}"#
                .to_string(),
            severity: Severity::Warning,
        },
        SecretPattern {
            name: "generic_secret".to_string(),
            pattern:
                r#"(?i)(secret|password|passwd|pwd)['"]?\s*[:=]\s*['"]?[A-Za-z0-9!@#$%^&*]{8,}"#
                    .to_string(),
            severity: Severity::Warning,
        },
    ]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretMatch {
    pub pattern_name: String,
    pub severity: Severity,
    pub offset: usize,
    pub length: usize,
    pub redacted: String,
}

struct CompiledPattern {
    name: String,
    regex: Regex,
    severity: Severity,
}

/// Guard that blocks content containing configured secret patterns.
pub struct SecretLeakGuard {
    name: String,
    enabled: bool,
    redact: bool,
    severity_threshold: Severity,
    patterns: Vec<CompiledPattern>,
}

impl SecretLeakGuard {
    pub fn new() -> Self {
        Self::with_config(SecretLeakConfig::default())
    }

    pub fn with_config(config: SecretLeakConfig) -> Self {
        let patterns = config
            .patterns
            .iter()
            .filter_map(|pattern| {
                Regex::new(&pattern.pattern)
                    .ok()
                    .map(|regex| CompiledPattern {
                        name: pattern.name.clone(),
                        regex,
                        severity: pattern.severity,
                    })
            })
            .collect();

        Self {
            name: "secret_leak".to_string(),
            enabled: config.enabled,
            redact: config.redact,
            severity_threshold: config.severity_threshold,
            patterns,
        }
    }

    pub fn scan(&self, content: &[u8]) -> Vec<SecretMatch> {
        let content = String::from_utf8_lossy(content);
        let mut matches = Vec::new();

        for pattern in &self.patterns {
            for capture in pattern.regex.find_iter(&content) {
                let matched = capture.as_str();
                matches.push(SecretMatch {
                    pattern_name: pattern.name.clone(),
                    severity: pattern.severity,
                    offset: capture.start(),
                    length: capture.len(),
                    redacted: if self.redact {
                        self.mask_value(matched)
                    } else {
                        matched.to_string()
                    },
                });
            }
        }

        matches
    }

    fn mask_value(&self, value: &str) -> String {
        if value.len() <= 8 {
            return "*".repeat(value.len());
        }
        let first = &value[..4];
        let last = &value[value.len() - 4..];
        format!("{first}{}{last}", "*".repeat(value.len() - 8))
    }

    fn severity_rank(severity: Severity) -> u8 {
        match severity {
            Severity::Info => 0,
            Severity::Warning => 1,
            Severity::Error => 2,
            Severity::Critical => 3,
        }
    }
}

impl Default for SecretLeakGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for SecretLeakGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        self.enabled
            && matches!(
                action,
                GuardAction::FileWrite(_, _) | GuardAction::ResponseAction(_) | GuardAction::Patch(_, _)
            )
    }

    fn check(&self, action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        if !self.enabled {
            return GuardResult::allow(&self.name);
        }

        let patch_added;
        let matches = match action {
            GuardAction::FileWrite(_, content) => self.scan(content),
            GuardAction::ResponseAction(action) => {
                self.scan(serde_json::to_string(action).unwrap_or_default().as_bytes())
            }
            // A patch can introduce a secret on an added line just like a FileWrite — scan the
            // `+` lines of the diff (excluding the `+++` file header).
            GuardAction::Patch(_, diff) => {
                patch_added = diff
                    .lines()
                    .filter(|l| l.starts_with('+') && !l.starts_with("+++"))
                    .map(|l| &l[1..])
                    .collect::<Vec<_>>()
                    .join("\n");
                self.scan(patch_added.as_bytes())
            }
            _ => return GuardResult::allow(&self.name),
        };

        let highest = matches
            .iter()
            .max_by_key(|item| Self::severity_rank(item.severity));

        let Some(highest) = highest else {
            return GuardResult::allow(&self.name);
        };

        if Self::severity_rank(highest.severity) >= Self::severity_rank(self.severity_threshold) {
            GuardResult::block(
                &self.name,
                highest.severity,
                format!("potential secret leak detected: {}", highest.pattern_name),
            )
            .with_details(serde_json::json!({
                "pattern_name": highest.pattern_name,
                "redacted": highest.redacted,
                "match_count": matches.len(),
            }))
        } else {
            GuardResult::warn(
                &self.name,
                format!(
                    "low-severity secret pattern detected: {}",
                    highest.pattern_name
                ),
            )
            .with_details(serde_json::json!({
                "pattern_name": highest.pattern_name,
                "redacted": highest.redacted,
                "match_count": matches.len(),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SecretLeakConfig, SecretLeakGuard};
    use crate::{Guard, GuardAction, Severity};
    use swarm_core::types::{ResponseAction, Severity as CoreSeverity};

    #[test]
    fn scan_detects_high_value_patterns() {
        let guard = SecretLeakGuard::new();

        assert_eq!(guard.scan(b"AKIA1234567890ABCDEF").len(), 1);
        assert_eq!(
            guard
                .scan(b"ghp_abcdefghijklmnopqrstuvwxyz1234567890")
                .len(),
            1
        );
        assert_eq!(
            guard
                .scan(b"github_pat_abcdefghijklmnopqrstuv_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567")
                .len(),
            1
        );
        assert_eq!(
            guard
                .scan(b"sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV")
                .len(),
            1
        );
        assert_eq!(
            guard
                .scan(b"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----")
                .len(),
            1
        );
    }

    #[test]
    fn clean_content_has_no_matches() {
        let guard = SecretLeakGuard::new();
        assert!(guard.scan(b"hello world").is_empty());
    }

    #[test]
    fn check_blocks_matching_file_write() {
        let guard = SecretLeakGuard::new();
        let result = guard.check(
            &GuardAction::FileWrite("/tmp/test.txt", b"AKIA1234567890ABCDEF"),
            &Default::default(),
        );

        assert!(!result.allowed);
        assert_eq!(result.guard, "secret_leak");
    }

    #[test]
    fn check_allows_clean_file_write() {
        let guard = SecretLeakGuard::new();
        let result = guard.check(
            &GuardAction::FileWrite("/tmp/test.txt", b"no secrets here"),
            &Default::default(),
        );

        assert!(result.allowed);
    }

    #[test]
    fn handles_only_file_writes_and_response_actions() {
        let guard = SecretLeakGuard::new();
        assert!(guard.handles(&GuardAction::FileWrite("/tmp/test.txt", b"hello")));
        assert!(
            guard.handles(&GuardAction::ResponseAction(&ResponseAction::Escalate {
                summary: "AKIA1234567890ABCDEF".to_string(),
                urgency: CoreSeverity::Critical,
            }))
        );
        assert!(!guard.handles(&GuardAction::FileAccess("/tmp/test.txt")));
        assert!(!guard.handles(&GuardAction::ShellCommand("echo hello")));
    }

    #[test]
    fn redaction_masks_middle_of_secret() {
        let guard = SecretLeakGuard::new();
        let matches = guard.scan(b"AKIA1234567890ABCDEF");

        assert_eq!(matches[0].redacted, "AKIA************CDEF");
    }

    #[test]
    fn severity_threshold_allows_warning_patterns_when_threshold_is_error() {
        let guard = SecretLeakGuard::with_config(SecretLeakConfig {
            enabled: true,
            redact: true,
            severity_threshold: Severity::Error,
            patterns: super::default_patterns(),
        });
        let result = guard.check(
            &GuardAction::FileWrite("/tmp/test.txt", b"password=hunter22"),
            &Default::default(),
        );

        assert!(result.allowed);
        assert_eq!(result.severity, Severity::Warning);
    }
}
