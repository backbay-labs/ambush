// Adapted from ClawdStrike/Arc (Apache-2.0)
//! Remote desktop side channel guard — controls clipboard, file transfer, audio, drive mapping,
//! printing, and session sharing.

use serde::{Deserialize, Serialize};

use crate::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// Configuration for [`RemoteDesktopSideChannelGuard`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteDesktopSideChannelConfig {
    /// Enable/disable this guard.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Whether clipboard operations are allowed.
    #[serde(default = "default_enabled")]
    pub clipboard_enabled: bool,
    /// Whether file transfer operations are allowed.
    #[serde(default = "default_enabled")]
    pub file_transfer_enabled: bool,
    /// Whether session sharing is allowed.
    #[serde(default = "default_enabled")]
    pub session_share_enabled: bool,
    /// Whether remote audio channel is allowed.
    #[serde(default = "default_enabled")]
    pub audio_enabled: bool,
    /// Whether remote drive mapping channel is allowed.
    #[serde(default = "default_enabled")]
    pub drive_mapping_enabled: bool,
    /// Whether remote printing channel is allowed.
    #[serde(default = "default_enabled")]
    pub printing_enabled: bool,
    /// Maximum transfer size in bytes (for file_transfer). `None` means unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_transfer_size_bytes: Option<u64>,
}

fn default_enabled() -> bool {
    true
}

impl Default for RemoteDesktopSideChannelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            clipboard_enabled: true,
            file_transfer_enabled: true,
            session_share_enabled: true,
            audio_enabled: true,
            drive_mapping_enabled: true,
            printing_enabled: true,
            max_transfer_size_bytes: None,
        }
    }
}

/// Guard that controls remote desktop side channels.
///
/// Handles [`GuardAction::Custom`] where the custom type is one of:
/// `"remote.clipboard"`, `"remote.file_transfer"`, `"remote.audio"`, `"remote.drive_mapping"`,
/// `"remote.printing"`, `"remote.session_share"` (and any other `remote.*` that is not a session
/// lifecycle event, which is denied fail-closed).
pub struct RemoteDesktopSideChannelGuard {
    name: String,
    enabled: bool,
    config: RemoteDesktopSideChannelConfig,
}

impl RemoteDesktopSideChannelGuard {
    /// Create with default configuration.
    pub fn new() -> Self {
        Self::with_config(RemoteDesktopSideChannelConfig::default())
    }

    /// Create with custom configuration.
    pub fn with_config(config: RemoteDesktopSideChannelConfig) -> Self {
        let enabled = config.enabled;
        Self {
            name: "remote_desktop_side_channel".to_string(),
            enabled,
            config,
        }
    }
}

impl Default for RemoteDesktopSideChannelGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for RemoteDesktopSideChannelGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        self.enabled
            && matches!(action, GuardAction::Custom(ct, _) if is_remote_side_channel_candidate(ct))
    }

    fn check(&self, action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        if !self.enabled {
            return GuardResult::allow(&self.name);
        }

        let (custom_type, data) = match action {
            GuardAction::Custom(ct, data) => (*ct, *data),
            _ => return GuardResult::allow(&self.name),
        };

        match custom_type {
            "remote.clipboard" => {
                if !self.config.clipboard_enabled {
                    GuardResult::block(
                        &self.name,
                        Severity::Error,
                        "clipboard operations are disabled by policy",
                    )
                    .with_details(serde_json::json!({
                        "channel": "clipboard",
                        "reason": "channel_disabled",
                    }))
                } else {
                    GuardResult::allow(&self.name)
                }
            }
            "remote.file_transfer" => {
                if !self.config.file_transfer_enabled {
                    return GuardResult::block(
                        &self.name,
                        Severity::Error,
                        "file transfer operations are disabled by policy",
                    )
                    .with_details(serde_json::json!({
                        "channel": "file_transfer",
                        "reason": "channel_disabled",
                    }));
                }

                if let Some(max_size) = self.config.max_transfer_size_bytes {
                    let transfer_size_value = data
                        .get("transfer_size")
                        .or_else(|| data.get("transferSize"));
                    let transfer_size = match transfer_size_value {
                        Some(value) => match value.as_u64() {
                            Some(size) => size,
                            None => {
                                return GuardResult::block(
                                    &self.name,
                                    Severity::Error,
                                    "file transfer size must be an unsigned integer in bytes",
                                )
                                .with_details(serde_json::json!({
                                    "channel": "file_transfer",
                                    "reason": "invalid_transfer_size_type",
                                }));
                            }
                        },
                        None => {
                            return GuardResult::block(
                                &self.name,
                                Severity::Error,
                                "file transfer size is required when max_transfer_size_bytes is configured",
                            )
                            .with_details(serde_json::json!({
                                "channel": "file_transfer",
                                "reason": "missing_transfer_size",
                            }));
                        }
                    };

                    if transfer_size > max_size {
                        return GuardResult::block(
                            &self.name,
                            Severity::Error,
                            format!(
                                "file transfer size {transfer_size} bytes exceeds maximum {max_size} bytes"
                            ),
                        )
                        .with_details(serde_json::json!({
                            "channel": "file_transfer",
                            "reason": "transfer_size_exceeded",
                            "transfer_size": transfer_size,
                            "max_size": max_size,
                        }));
                    }
                }

                GuardResult::allow(&self.name)
            }
            "remote.session_share" => {
                if !self.config.session_share_enabled {
                    GuardResult::block(
                        &self.name,
                        Severity::Error,
                        "session sharing is disabled by policy",
                    )
                    .with_details(serde_json::json!({
                        "channel": "session_share",
                        "reason": "channel_disabled",
                    }))
                } else {
                    GuardResult::allow(&self.name)
                }
            }
            "remote.audio" => {
                if !self.config.audio_enabled {
                    GuardResult::block(
                        &self.name,
                        Severity::Error,
                        "remote audio channel is disabled by policy",
                    )
                    .with_details(serde_json::json!({
                        "channel": "audio",
                        "reason": "channel_disabled",
                    }))
                } else {
                    GuardResult::allow(&self.name)
                }
            }
            "remote.drive_mapping" => {
                if !self.config.drive_mapping_enabled {
                    GuardResult::block(
                        &self.name,
                        Severity::Error,
                        "drive mapping is disabled by policy",
                    )
                    .with_details(serde_json::json!({
                        "channel": "drive_mapping",
                        "reason": "channel_disabled",
                    }))
                } else {
                    GuardResult::allow(&self.name)
                }
            }
            "remote.printing" => {
                if !self.config.printing_enabled {
                    GuardResult::block(
                        &self.name,
                        Severity::Error,
                        "remote printing is disabled by policy",
                    )
                    .with_details(serde_json::json!({
                        "channel": "printing",
                        "reason": "channel_disabled",
                    }))
                } else {
                    GuardResult::allow(&self.name)
                }
            }
            _ => GuardResult::block(
                &self.name,
                Severity::Error,
                format!("unknown side channel type '{custom_type}' denied by fail-closed policy"),
            )
            .with_details(serde_json::json!({
                "channel": custom_type,
                "reason": "unknown_channel_type",
            })),
        }
    }
}

fn is_remote_side_channel_candidate(custom_type: &str) -> bool {
    if !custom_type.starts_with("remote.") {
        return false;
    }

    !matches!(
        custom_type,
        "remote.session.connect" | "remote.session.disconnect" | "remote.session.reconnect"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Guard;

    #[test]
    fn handles_side_channel_actions() {
        let guard = RemoteDesktopSideChannelGuard::new();
        let data = serde_json::json!({});

        assert!(guard.handles(&GuardAction::Custom("remote.clipboard", &data)));
        assert!(guard.handles(&GuardAction::Custom("remote.file_transfer", &data)));
        assert!(guard.handles(&GuardAction::Custom("remote.audio", &data)));
        assert!(guard.handles(&GuardAction::Custom("remote.drive_mapping", &data)));
        assert!(guard.handles(&GuardAction::Custom("remote.printing", &data)));
        assert!(guard.handles(&GuardAction::Custom("remote.session_share", &data)));
        assert!(guard.handles(&GuardAction::Custom("remote.webrtc", &data)));
    }

    #[test]
    fn does_not_handle_session_lifecycle_or_other_actions() {
        let guard = RemoteDesktopSideChannelGuard::new();
        let data = serde_json::json!({});

        assert!(!guard.handles(&GuardAction::Custom("remote.session.connect", &data)));
        assert!(!guard.handles(&GuardAction::Custom("input.inject", &data)));
        assert!(!guard.handles(&GuardAction::FileAccess("/tmp/file")));
    }

    #[test]
    fn allows_when_all_channels_enabled() {
        let guard = RemoteDesktopSideChannelGuard::new();
        let ctx = GuardContext::new();
        let data = serde_json::json!({});

        for channel in [
            "remote.clipboard",
            "remote.file_transfer",
            "remote.session_share",
            "remote.audio",
            "remote.drive_mapping",
            "remote.printing",
        ] {
            assert!(
                guard
                    .check(&GuardAction::Custom(channel, &data), &ctx)
                    .allowed,
                "{channel} should be allowed by default"
            );
        }
    }

    #[test]
    fn denies_clipboard_when_disabled() {
        let config = RemoteDesktopSideChannelConfig {
            clipboard_enabled: false,
            ..Default::default()
        };
        let guard = RemoteDesktopSideChannelGuard::with_config(config);
        let data = serde_json::json!({});
        let result = guard.check(&GuardAction::Custom("remote.clipboard", &data), &GuardContext::new());
        assert!(!result.allowed);
        assert_eq!(result.guard, "remote_desktop_side_channel");
    }

    #[test]
    fn denies_file_transfer_exceeding_size() {
        let config = RemoteDesktopSideChannelConfig {
            max_transfer_size_bytes: Some(1024),
            ..Default::default()
        };
        let guard = RemoteDesktopSideChannelGuard::with_config(config);
        let data = serde_json::json!({ "transfer_size": 2048 });
        let result =
            guard.check(&GuardAction::Custom("remote.file_transfer", &data), &GuardContext::new());
        assert!(!result.allowed);
    }

    #[test]
    fn allows_camel_case_transfer_size_within_limit() {
        let config = RemoteDesktopSideChannelConfig {
            max_transfer_size_bytes: Some(4096),
            ..Default::default()
        };
        let guard = RemoteDesktopSideChannelGuard::with_config(config);
        let data = serde_json::json!({ "transferSize": 1024 });
        let result =
            guard.check(&GuardAction::Custom("remote.file_transfer", &data), &GuardContext::new());
        assert!(result.allowed);
    }

    #[test]
    fn denies_invalid_transfer_size_type() {
        let config = RemoteDesktopSideChannelConfig {
            max_transfer_size_bytes: Some(4096),
            ..Default::default()
        };
        let guard = RemoteDesktopSideChannelGuard::with_config(config);
        let data = serde_json::json!({ "transfer_size": "1024" });
        let result =
            guard.check(&GuardAction::Custom("remote.file_transfer", &data), &GuardContext::new());
        assert!(!result.allowed);
    }

    #[test]
    fn denies_unknown_remote_side_channel_fail_closed() {
        let guard = RemoteDesktopSideChannelGuard::new();
        let data = serde_json::json!({});
        assert!(guard.handles(&GuardAction::Custom("remote.webrtc", &data)));
        let result = guard.check(&GuardAction::Custom("remote.webrtc", &data), &GuardContext::new());
        assert!(!result.allowed);
    }
}
