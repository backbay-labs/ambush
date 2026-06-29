// Adapted from ClawdStrike/Arc (Apache-2.0)
//! Input injection capability guard — controls input injection types and postcondition probes.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// Configuration for [`InputInjectionCapabilityGuard`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputInjectionCapabilityConfig {
    /// Enable/disable this guard.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Allowed input types (e.g. "keyboard", "mouse", "touch").
    #[serde(default = "default_allowed_input_types")]
    pub allowed_input_types: Vec<String>,
    /// Whether a postcondition probe hash is required in the action data.
    #[serde(default)]
    pub require_postcondition_probe: bool,
}

fn default_enabled() -> bool {
    true
}

fn default_allowed_input_types() -> Vec<String> {
    vec![
        "keyboard".to_string(),
        "mouse".to_string(),
        "touch".to_string(),
    ]
}

impl Default for InputInjectionCapabilityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_input_types: default_allowed_input_types(),
            require_postcondition_probe: false,
        }
    }
}

/// Guard that controls input injection capabilities.
///
/// Handles `GuardAction::Custom("input.inject", _)` and validates:
/// - The input type (from the data's `input_type` field) is in the allowed list.
/// - If `require_postcondition_probe` is true, the data must carry a `postcondition_probe_hash`.
pub struct InputInjectionCapabilityGuard {
    name: String,
    enabled: bool,
    allowed_types: HashSet<String>,
    require_postcondition_probe: bool,
}

impl InputInjectionCapabilityGuard {
    /// Create with default configuration.
    pub fn new() -> Self {
        Self::with_config(InputInjectionCapabilityConfig::default())
    }

    /// Create with custom configuration.
    pub fn with_config(config: InputInjectionCapabilityConfig) -> Self {
        let enabled = config.enabled;
        let require_postcondition_probe = config.require_postcondition_probe;
        let allowed_types: HashSet<_> = config.allowed_input_types.into_iter().collect();

        Self {
            name: "input_injection_capability".to_string(),
            enabled,
            allowed_types,
            require_postcondition_probe,
        }
    }
}

impl Default for InputInjectionCapabilityGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for InputInjectionCapabilityGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        self.enabled && matches!(action, GuardAction::Custom("input.inject", _))
    }

    fn check(&self, action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        if !self.enabled {
            return GuardResult::allow(&self.name);
        }

        let data = match action {
            GuardAction::Custom("input.inject", data) => *data,
            _ => return GuardResult::allow(&self.name),
        };

        // Check input type — must be present and in the allowed list (fail-closed).
        // Accept both snake_case and camelCase since the CUA pipeline may use either.
        if let Some(input_type) = data
            .get("input_type")
            .or_else(|| data.get("inputType"))
            .and_then(|v| v.as_str())
        {
            if !self.allowed_types.contains(input_type) {
                return GuardResult::block(
                    &self.name,
                    Severity::Error,
                    format!("input type '{input_type}' is not allowed by policy"),
                )
                .with_details(serde_json::json!({
                    "input_type": input_type,
                    "allowed_types": self.allowed_types.iter().collect::<Vec<_>>(),
                    "reason": "input_type_not_allowed",
                }));
            }
        } else {
            // Missing input_type must deny (fail-closed).
            return GuardResult::block(
                &self.name,
                Severity::Error,
                "missing required input_type field for input injection action",
            )
            .with_details(serde_json::json!({
                "reason": "missing_input_type",
                "allowed_types": self.allowed_types.iter().collect::<Vec<_>>(),
            }));
        }

        // Check postcondition probe requirement.
        if self.require_postcondition_probe {
            let has_probe = data
                .get("postcondition_probe_hash")
                .or_else(|| data.get("postconditionProbeHash"))
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty());

            if !has_probe {
                return GuardResult::block(
                    &self.name,
                    Severity::Error,
                    "postcondition probe hash is required but not provided",
                )
                .with_details(serde_json::json!({
                    "reason": "missing_postcondition_probe",
                    "require_postcondition_probe": true,
                }));
            }
        }

        GuardResult::allow(&self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Guard;

    #[test]
    fn handles_input_inject_only() {
        let guard = InputInjectionCapabilityGuard::new();
        let data = serde_json::json!({});
        assert!(guard.handles(&GuardAction::Custom("input.inject", &data)));
        assert!(!guard.handles(&GuardAction::Custom("remote.clipboard", &data)));
        assert!(!guard.handles(&GuardAction::FileAccess("/tmp/file")));
    }

    #[test]
    fn allows_known_input_type() {
        let guard = InputInjectionCapabilityGuard::new();
        let data = serde_json::json!({ "input_type": "keyboard" });
        let result = guard.check(&GuardAction::Custom("input.inject", &data), &GuardContext::new());
        assert!(result.allowed);
    }

    #[test]
    fn denies_unknown_input_type() {
        let guard = InputInjectionCapabilityGuard::new();
        let data = serde_json::json!({ "input_type": "gamepad" });
        let result = guard.check(&GuardAction::Custom("input.inject", &data), &GuardContext::new());
        assert!(!result.allowed);
        assert_eq!(result.guard, "input_injection_capability");
    }

    #[test]
    fn denies_missing_input_type_fail_closed() {
        let guard = InputInjectionCapabilityGuard::new();
        let data = serde_json::json!({ "action": "click" });
        let result = guard.check(&GuardAction::Custom("input.inject", &data), &GuardContext::new());
        assert!(!result.allowed);
    }

    #[test]
    fn requires_postcondition_probe_when_configured() {
        let config = InputInjectionCapabilityConfig {
            require_postcondition_probe: true,
            ..Default::default()
        };
        let guard = InputInjectionCapabilityGuard::with_config(config);

        let data = serde_json::json!({ "input_type": "keyboard" });
        let result = guard.check(&GuardAction::Custom("input.inject", &data), &GuardContext::new());
        assert!(!result.allowed);

        let data = serde_json::json!({
            "input_type": "keyboard",
            "postcondition_probe_hash": "sha256:abc123"
        });
        let result = guard.check(&GuardAction::Custom("input.inject", &data), &GuardContext::new());
        assert!(result.allowed);
    }
}
