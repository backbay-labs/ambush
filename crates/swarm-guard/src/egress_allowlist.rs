//! Guard that controls outbound network destinations.

use serde::{Deserialize, Serialize};

use crate::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// Default behavior when no domain pattern matches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultAction {
    Allow,
    #[default]
    Block,
}

/// Configuration for [`EgressAllowlistGuard`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressAllowlistConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_allow")]
    pub allow: Vec<String>,
    #[serde(default)]
    pub block: Vec<String>,
    #[serde(default)]
    pub default_action: DefaultAction,
}

impl Default for EgressAllowlistConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow: default_allow(),
            block: Vec::new(),
            default_action: DefaultAction::Block,
        }
    }
}

fn default_enabled() -> bool {
    true
}

fn default_allow() -> Vec<String> {
    vec![
        "*.openai.com".to_string(),
        "*.anthropic.com".to_string(),
        "api.github.com".to_string(),
        "registry.npmjs.org".to_string(),
        "pypi.org".to_string(),
        "crates.io".to_string(),
        "static.crates.io".to_string(),
    ]
}

/// Guard that enforces a domain allowlist.
pub struct EgressAllowlistGuard {
    name: String,
    config: EgressAllowlistConfig,
}

impl EgressAllowlistGuard {
    pub fn new() -> Self {
        Self::with_config(EgressAllowlistConfig::default())
    }

    pub fn with_config(config: EgressAllowlistConfig) -> Self {
        Self {
            name: "egress_allowlist".to_string(),
            config,
        }
    }

    pub fn matches_domain(pattern: &str, domain: &str) -> bool {
        let pattern = pattern.trim().to_ascii_lowercase();
        let domain = domain.trim().to_ascii_lowercase();
        if pattern.is_empty() || domain.is_empty() {
            return false;
        }

        if let Some(suffix) = pattern.strip_prefix("*.") {
            return domain.ends_with(&format!(".{suffix}"));
        }

        pattern == domain
    }

    pub fn is_allowed(&self, domain: &str) -> bool {
        let domain = domain.trim().to_ascii_lowercase();
        if domain.is_empty() {
            return false;
        }

        if self
            .config
            .block
            .iter()
            .any(|pattern| Self::matches_domain(pattern, &domain))
        {
            return false;
        }

        if self
            .config
            .allow
            .iter()
            .any(|pattern| Self::matches_domain(pattern, &domain))
        {
            return true;
        }

        matches!(self.config.default_action, DefaultAction::Allow)
    }
}

impl Default for EgressAllowlistGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for EgressAllowlistGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        self.config.enabled && matches!(action, GuardAction::NetworkEgress(_, _))
    }

    fn check(&self, action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        if !self.config.enabled {
            return GuardResult::allow(&self.name);
        }

        let GuardAction::NetworkEgress(host, port) = action else {
            return GuardResult::allow(&self.name);
        };

        if self.is_allowed(host) {
            GuardResult::allow(&self.name)
        } else {
            GuardResult::block(
                &self.name,
                Severity::Error,
                format!("network destination not on allowlist: {host}"),
            )
            .with_details(serde_json::json!({
                "host": host,
                "port": port,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DefaultAction, EgressAllowlistConfig, EgressAllowlistGuard};
    use crate::{Guard, GuardAction};

    #[test]
    fn default_config_allows_expected_domains() {
        let guard = EgressAllowlistGuard::new();

        assert!(guard.is_allowed("api.openai.com"));
        assert!(guard.is_allowed("console.anthropic.com"));
        assert!(guard.is_allowed("api.github.com"));
        assert!(guard.is_allowed("registry.npmjs.org"));
        assert!(guard.is_allowed("crates.io"));
    }

    #[test]
    fn default_config_blocks_unknown_domains() {
        let guard = EgressAllowlistGuard::new();

        assert!(!guard.is_allowed("evil.com"));
        assert!(!guard.is_allowed("random-site.org"));
    }

    #[test]
    fn custom_allowlist_and_blocklist_work() {
        let guard = EgressAllowlistGuard::with_config(EgressAllowlistConfig {
            enabled: true,
            allow: vec!["*.example.com".to_string()],
            block: vec!["blocked.example.com".to_string()],
            default_action: DefaultAction::Block,
        });

        assert!(guard.is_allowed("sub.example.com"));
        assert!(!guard.is_allowed("example.com"));
        assert!(!guard.is_allowed("blocked.example.com"));
    }

    #[test]
    fn handles_only_network_egress() {
        let guard = EgressAllowlistGuard::new();
        assert!(guard.handles(&GuardAction::NetworkEgress("api.openai.com", 443)));
        assert!(!guard.handles(&GuardAction::FileAccess("/tmp/file")));
    }
}
