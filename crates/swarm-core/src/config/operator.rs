use super::*;
use std::path::PathBuf;

/// Local authenticated operator-surface settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorSurfaceConfig {
    /// Whether the local HTTP operator surface is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Local socket address the surface listens on.
    #[serde(default = "default_operator_bind_addr")]
    pub bind_addr: String,
    /// Runtime HTTP base URL the live demo dashboard reads from.
    #[serde(default = "default_operator_runtime_base_url")]
    pub runtime_base_url: String,
    /// Public HTTP base URL external systems use for operator drilldown links.
    #[serde(default = "default_operator_public_base_url")]
    pub public_base_url: String,
    /// Additional origins allowed to embed the minimal Providence widget.
    #[serde(default)]
    pub allowed_embed_origins: Vec<String>,
    /// Maximum records returned from list endpoints.
    #[serde(default = "default_operator_max_list_results")]
    pub max_list_results: usize,
    /// Lifetime for Providence widget context tokens.
    #[serde(default = "default_operator_widget_token_ttl_secs")]
    pub widget_token_ttl_secs: u64,
    /// Per-source rate limiting for authenticated operator routes.
    #[serde(default)]
    pub rate_limit: HttpRateLimitConfig,
    /// Bearer-token auth configuration for the local surface.
    #[serde(default)]
    pub auth: OperatorAuthConfig,
}

/// Versioned detect-server platform API settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformApiConfig {
    /// Configured API keys allowed to read `/v2/api/*`.
    #[serde(default)]
    pub keys: Vec<PlatformApiKeyConfig>,
    /// Per-source rate limiting for `/v2/api/*` routes.
    #[serde(default)]
    pub rate_limit: HttpRateLimitConfig,
}

/// Shared TLS settings for the detect and operator HTTP servers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// PEM-encoded server certificate chain.
    pub cert_path: String,
    /// PEM-encoded private key matching `cert_path`.
    pub key_path: String,
    /// Optional PEM-encoded client CA bundle enabling mTLS.
    #[serde(default)]
    pub client_ca_cert: Option<String>,
}

/// One scoped platform API key entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformApiKeyConfig {
    /// Human-readable name attached to authenticated requests.
    pub name: String,
    /// Lowercase or uppercase SHA-256 hex digest of the raw key material.
    pub key_hash: String,
    /// Scopes granted to this key.
    pub scopes: Vec<PlatformApiScope>,
}

/// Platform API scopes supported by the current detect-server read surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformApiScope {
    Read,
}

/// Operator scopes supported by the authenticated operator and platform surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorScope {
    Read,
    Rehearse,
    Approve,
    Maintenance,
}

/// Per-source HTTP rate limiting applied to protected API surfaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRateLimitConfig {
    /// Maximum requests allowed in the short burst window.
    #[serde(default = "default_http_rate_limit_burst_max_requests")]
    pub burst_max_requests: usize,
    /// Sliding window for burst protection.
    #[serde(default = "default_http_rate_limit_burst_window_ms")]
    pub burst_window_ms: u64,
    /// Maximum requests allowed in the broader sustained window.
    #[serde(default = "default_http_rate_limit_sustained_max_requests")]
    pub sustained_max_requests: usize,
    /// Sliding window for sustained protection.
    #[serde(default = "default_http_rate_limit_sustained_window_ms")]
    pub sustained_window_ms: u64,
    /// Honor `X-Forwarded-For` / `X-Real-IP` / `Forwarded` headers as the rate-limit
    /// source key. Only safe when the detect server sits behind a trusted proxy that
    /// overwrites client-supplied values; otherwise clients can rotate header values
    /// to bypass the limiter.
    #[serde(default)]
    pub trust_forwarded_headers: bool,
}

/// One scoped operator principal entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorPrincipalConfig {
    /// Logical operator principal attached to authenticated requests.
    pub operator_id: String,
    /// Environment variable name that carries the bearer token for this principal.
    pub token_env: String,
    /// Optional unix timestamp in milliseconds after which the bearer token is rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_expires_at_ms: Option<i64>,
    /// Scopes granted to this principal.
    #[serde(default)]
    pub scopes: Vec<OperatorScope>,
    /// The operator's Nostr public key (64 lowercase hex), used by the swarm bridge to
    /// `p`-tag held actions and hold alarms so they reach this principal's console.
    /// Optional: without it no hold can be addressed to this principal (00-DECISIONS D1;
    /// 01-DESIGN §6 B0). It is configured, not proven -- see ADR 0016.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nostr_pubkey: Option<String>,
}

/// Authentication settings for the local operator surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorAuthConfig {
    /// Environment variable name used to sign read-only Providence context tokens.
    #[serde(default = "default_operator_context_token_env")]
    pub context_token_env: String,
    /// Supported multi-principal operator auth contract.
    #[serde(default)]
    pub principals: Vec<OperatorPrincipalConfig>,
    /// Logical operator principal attached to authenticated requests.
    #[serde(default = "default_operator_id")]
    pub operator_id: String,
    /// Environment variable name that carries the bearer token.
    #[serde(default = "default_operator_token_env")]
    pub token_env: String,
    /// Optional unix timestamp in milliseconds after which the legacy single-principal bearer token is rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_expires_at_ms: Option<i64>,
    /// The legacy single principal's Nostr public key (64 lowercase hex); see
    /// [`OperatorPrincipalConfig::nostr_pubkey`]. Ignored when `principals` is non-empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nostr_pubkey: Option<String>,
}

impl OperatorAuthConfig {
    /// The principals this surface authenticates: `principals` when configured, otherwise
    /// one synthesized from the legacy single-principal fields with every scope granted.
    pub fn effective_principals(&self) -> Vec<OperatorPrincipalConfig> {
        if !self.principals.is_empty() {
            return self.principals.clone();
        }
        vec![OperatorPrincipalConfig {
            operator_id: self.operator_id.clone(),
            token_env: self.token_env.clone(),
            token_expires_at_ms: self.token_expires_at_ms,
            scopes: vec![
                OperatorScope::Read,
                OperatorScope::Rehearse,
                OperatorScope::Approve,
                OperatorScope::Maintenance,
            ],
            nostr_pubkey: self.nostr_pubkey.clone(),
        }]
    }

    pub fn context_token_env(&self) -> &str {
        self.context_token_env.trim()
    }
}

impl OperatorPrincipalConfig {
    /// Whether this principal's bearer token has passed its configured expiry.
    pub fn token_is_expired(&self, now_ms: i64) -> bool {
        self.token_expires_at_ms
            .is_some_and(|expires_at_ms| now_ms > expires_at_ms)
    }

    /// Validate this principal's self-contained fields.
    ///
    /// Today that is the optional [`nostr_pubkey`](Self::nostr_pubkey), which must be
    /// exactly 64 lowercase hex characters when present. Cross-principal rules (unique
    /// ids, unique token environments, at least one `read` scope) and the positional
    /// checks belong to `SwarmConfig::validate`, which calls this for every effective
    /// principal.
    ///
    /// Crate-internal like its `PlatformApiConfig` and `TlsConfig` siblings: the loader is
    /// its only caller, and the phase-282 visibility baseline keeps it that way.
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        if let Some(key) = self.nostr_pubkey.as_deref()
            && !is_nostr_pubkey_hex(key)
        {
            return Err(ConfigValidationError::InvalidField {
                field: "operator_surface.auth.principals.nostr_pubkey",
                reason: format!(
                    "principal `{}` nostr_pubkey must be exactly 64 lowercase hex characters",
                    self.operator_id.trim()
                ),
            });
        }
        Ok(())
    }

    /// The configured Nostr public key decoded to its 32 raw bytes.
    ///
    /// `None` when no key is configured or when the value would fail
    /// [`validate`](Self::validate); a malformed key never decodes to a partial array.
    pub fn nostr_pubkey_bytes(&self) -> Option<[u8; 32]> {
        let key = self.nostr_pubkey.as_deref()?;
        if !is_nostr_pubkey_hex(key) {
            return None;
        }
        hex::decode(key).ok()?.try_into().ok()
    }
}

/// Exactly 64 lowercase hex characters: the canonical NIP-01 public-key encoding.
fn is_nostr_pubkey_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

impl PlatformApiConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        let mut names = BTreeSet::new();
        let mut hashes = BTreeSet::new();

        for (index, key) in self.keys.iter().enumerate() {
            let name = key.name.trim();
            if name.is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "platform_api.keys",
                    reason: format!("key {index} name must not be empty"),
                });
            }
            if !names.insert(name.to_string()) {
                return Err(ConfigValidationError::InvalidField {
                    field: "platform_api.keys",
                    reason: format!("duplicate key name `{name}`"),
                });
            }

            let key_hash = key.key_hash.trim();
            if key_hash.len() != 64 || !key_hash.chars().all(|ch| ch.is_ascii_hexdigit()) {
                return Err(ConfigValidationError::InvalidField {
                    field: "platform_api.keys.key_hash",
                    reason: format!(
                        "key {index} key_hash must be a 64-character SHA-256 hex digest"
                    ),
                });
            }
            if !hashes.insert(key_hash.to_ascii_lowercase()) {
                return Err(ConfigValidationError::InvalidField {
                    field: "platform_api.keys.key_hash",
                    reason: format!("duplicate key hash for key `{name}`"),
                });
            }

            if key.scopes.is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "platform_api.keys.scopes",
                    reason: format!("key {index} must grant at least one scope"),
                });
            }
        }

        Ok(())
    }
}

impl Default for HttpRateLimitConfig {
    fn default() -> Self {
        Self {
            burst_max_requests: default_http_rate_limit_burst_max_requests(),
            burst_window_ms: default_http_rate_limit_burst_window_ms(),
            sustained_max_requests: default_http_rate_limit_sustained_max_requests(),
            sustained_window_ms: default_http_rate_limit_sustained_window_ms(),
            trust_forwarded_headers: false,
        }
    }
}

impl TlsConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.cert_path.trim().is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "tls.cert_path",
                reason: "must not be empty when TLS is configured".to_string(),
            });
        }
        if self.key_path.trim().is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "tls.key_path",
                reason: "must not be empty when TLS is configured".to_string(),
            });
        }
        if self
            .client_ca_cert
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(ConfigValidationError::InvalidField {
                field: "tls.client_ca_cert",
                reason: "must not be empty when configured".to_string(),
            });
        }
        Ok(())
    }
}

impl Default for OperatorSurfaceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_addr: default_operator_bind_addr(),
            runtime_base_url: default_operator_runtime_base_url(),
            public_base_url: default_operator_public_base_url(),
            allowed_embed_origins: Vec::new(),
            max_list_results: default_operator_max_list_results(),
            widget_token_ttl_secs: default_operator_widget_token_ttl_secs(),
            rate_limit: HttpRateLimitConfig::default(),
            auth: OperatorAuthConfig::default(),
        }
    }
}

impl Default for OperatorAuthConfig {
    fn default() -> Self {
        Self {
            context_token_env: default_operator_context_token_env(),
            principals: Vec::new(),
            operator_id: default_operator_id(),
            token_env: default_operator_token_env(),
            token_expires_at_ms: None,
            nostr_pubkey: None,
        }
    }
}

/// Result directories the authenticated operator surface reads artifacts from.
///
/// # Placement (SPLIT-02, phase 282)
///
/// This lives in `swarm-core`, beside [`OperatorSurfaceConfig`], and NOT in the
/// operator HTTP module, because it has two consumers that must not depend on each
/// other. `http` (heading for its own transport crate) needs it to build every
/// artifact harness; `workbench`/`review_workbench` (heading for a different crate)
/// needs it for `DefaultReviewWorkbenchHarness::from_paths`. `http` already imports
/// `crate::review_workbench` types in non-test code, so had `workbench` kept
/// importing this type back out of `http`, extracting the two would have produced a
/// Cargo circular dependency and a hard build failure.
///
/// `swarm-core` is the lowest crate both already depend on, and the type earns its
/// place here on its own merits: 29 `String`/`PathBuf` fields, no behaviour and no
/// transport in sight -- a repo layout contract of exactly the kind this module
/// holds. Unlike its neighbours it is not `Serialize`/`Deserialize`: callers build
/// it programmatically rather than parsing it out of the config file, which is why
/// it carries no `serde` attributes.
#[derive(Debug, Clone)]
pub struct OperatorSurfacePaths {
    pub evidence_signer_id: String,
    pub evidence_signing_key_env: String,
    pub verification_results_dir: PathBuf,
    pub shadow_results_dir: PathBuf,
    pub promotion_review_results_dir: PathBuf,
    pub canary_results_dir: PathBuf,
    pub promotion_results_dir: PathBuf,
    pub evolution_ranking_results_dir: PathBuf,
    pub evolution_selection_results_dir: PathBuf,
    pub evolution_portfolio_results_dir: PathBuf,
    pub evolution_governance_review_packet_results_dir: PathBuf,
    pub evolution_packet_set_results_dir: PathBuf,
    pub strategy_memory_results_dir: PathBuf,
    pub evolution_portfolio_history_results_dir: PathBuf,
    pub operator_maintenance_results_dir: PathBuf,
    pub evidence_results_dir: PathBuf,
    pub evidence_verification_results_dir: PathBuf,
    pub promotion_evidence_results_dir: PathBuf,
    pub review_session_results_dir: PathBuf,
    pub review_session_export_results_dir: PathBuf,
    pub review_session_readiness_results_dir: PathBuf,
    pub review_session_handoff_results_dir: PathBuf,
    pub review_capsule_results_dir: PathBuf,
    pub review_capsule_import_results_dir: PathBuf,
    pub review_delegation_results_dir: PathBuf,
    pub approval_set_results_dir: PathBuf,
    pub approval_ledger_results_dir: PathBuf,
    pub approval_verdict_results_dir: PathBuf,
    pub approval_receipt_pack_results_dir: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_without_nostr_pubkey_still_loads() {
        let yaml = "operator_id: ops\ntoken_env: SWARM_OPERATOR_TOKEN\nscopes: [approve]\n";
        let p: OperatorPrincipalConfig =
            serde_yaml::from_str(yaml).unwrap_or_else(|e| panic!("{e}"));
        assert!(p.nostr_pubkey.is_none());
        assert!(p.validate().is_ok());
        assert!(p.nostr_pubkey_bytes().is_none());
    }

    #[test]
    fn principal_with_nostr_pubkey_round_trips_and_validates() {
        let hex = "a".repeat(64);
        let yaml =
            format!("operator_id: ops\ntoken_env: T\nscopes: [approve]\nnostr_pubkey: {hex}\n");
        let p: OperatorPrincipalConfig =
            serde_yaml::from_str(&yaml).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(p.nostr_pubkey.as_deref(), Some(hex.as_str()));
        assert!(p.validate().is_ok());
        assert_eq!(p.nostr_pubkey_bytes().map(|b| b.len()), Some(32));
        assert_eq!(p.nostr_pubkey_bytes(), Some([0xaa; 32]));

        let rendered = serde_yaml::to_string(&p).unwrap_or_else(|e| panic!("{e}"));
        assert!(rendered.contains(&format!("nostr_pubkey: {hex}")));
        let back: OperatorPrincipalConfig =
            serde_yaml::from_str(&rendered).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(back.nostr_pubkey, p.nostr_pubkey);
    }

    #[test]
    fn malformed_nostr_pubkey_is_rejected_at_validation() {
        for bad in [
            "npub1abc",
            &"A".repeat(64),
            &"a".repeat(63),
            &"a".repeat(65),
            "",
        ] {
            let p = OperatorPrincipalConfig {
                operator_id: "o".into(),
                token_env: "T".into(),
                token_expires_at_ms: None,
                scopes: vec![OperatorScope::Approve],
                nostr_pubkey: Some(bad.to_string()),
            };
            let Err(error) = p.validate() else {
                panic!("{bad}: expected the malformed key to be rejected");
            };
            assert!(
                error
                    .to_string()
                    .starts_with("invalid field `operator_surface.auth.principals.nostr_pubkey`:"),
                "{bad}: {error}"
            );
            assert!(p.nostr_pubkey_bytes().is_none(), "{bad}");
        }
    }

    #[test]
    fn legacy_single_principal_form_carries_the_pubkey_through() {
        let auth = OperatorAuthConfig {
            nostr_pubkey: Some("b".repeat(64)),
            ..OperatorAuthConfig::default()
        };
        assert_eq!(
            auth.effective_principals()[0].nostr_pubkey.as_deref(),
            Some("b".repeat(64).as_str())
        );

        let bare = OperatorAuthConfig::default();
        assert!(bare.effective_principals()[0].nostr_pubkey.is_none());
    }

    #[test]
    fn absent_nostr_pubkey_is_omitted_from_serialized_principals() {
        let p = OperatorPrincipalConfig {
            operator_id: "ops".into(),
            token_env: "T".into(),
            token_expires_at_ms: None,
            scopes: vec![OperatorScope::Read],
            nostr_pubkey: None,
        };
        let rendered = serde_yaml::to_string(&p).unwrap_or_else(|e| panic!("{e}"));
        assert!(!rendered.contains("nostr_pubkey"), "{rendered}");
        let auth =
            serde_yaml::to_string(&OperatorAuthConfig::default()).unwrap_or_else(|e| panic!("{e}"));
        assert!(!auth.contains("nostr_pubkey"), "{auth}");
    }
}
