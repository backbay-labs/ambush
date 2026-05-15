use super::*;

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
}

impl OperatorAuthConfig {
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
        }]
    }

    pub fn context_token_env(&self) -> &str {
        self.context_token_env.trim()
    }
}

impl OperatorPrincipalConfig {
    pub fn token_is_expired(&self, now_ms: i64) -> bool {
        self.token_expires_at_ms
            .is_some_and(|expires_at_ms| now_ms > expires_at_ms)
    }
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
        }
    }
}
