pub use swarm_core::config::{
    CircuitBreakerConfig, HttpEdrConfig, NotificationChannelConfig, NotificationRateLimitConfig,
    NotificationRoutingConfig, QuietHoursConfig, ResponseAdapterConfig, RetryConfig, RoutingRule,
    SiemForwardConfig, WebhookConfig,
};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        CircuitBreakerConfig, HttpEdrConfig, ResponseAdapterConfig, RetryConfig, WebhookConfig,
    };

    #[test]
    fn sandbox_roundtrips_through_json() {
        let config = ResponseAdapterConfig::Sandbox;
        let raw = serde_json::to_string(&config).unwrap();
        let decoded: ResponseAdapterConfig = serde_json::from_str(&raw).unwrap();
        assert_eq!(decoded, ResponseAdapterConfig::Sandbox);
    }

    #[test]
    fn http_edr_roundtrips_through_json() {
        let config = ResponseAdapterConfig::HttpEdr {
            config: HttpEdrConfig {
                endpoint: "http://localhost:9000/edr".to_string(),
                auth_token: "secret".to_string(),
                timeout_ms: 42,
                retry: RetryConfig::default(),
                circuit_breaker: CircuitBreakerConfig::default(),
                dead_letter_path: "./dead-letter.jsonl".to_string(),
            },
        };
        let raw = serde_json::to_string(&config).unwrap();
        let decoded: ResponseAdapterConfig = serde_json::from_str(&raw).unwrap();
        assert_eq!(decoded, config);
    }

    #[test]
    fn webhook_roundtrips_through_json() {
        let config = ResponseAdapterConfig::Webhook {
            config: WebhookConfig {
                url: "http://localhost:9000/webhook".to_string(),
                timeout_ms: 99,
                channel: Some("#soc".to_string()),
                auth_token: Some("secret".to_string()),
                retry: RetryConfig::default(),
                circuit_breaker: CircuitBreakerConfig::default(),
                dead_letter_path: "./dead-letter.jsonl".to_string(),
            },
        };
        let raw = serde_json::to_string(&config).unwrap();
        let decoded: ResponseAdapterConfig = serde_json::from_str(&raw).unwrap();
        assert_eq!(decoded, config);
    }

    #[test]
    fn empty_endpoint_is_rejected() {
        let config = ResponseAdapterConfig::HttpEdr {
            config: HttpEdrConfig {
                endpoint: "   ".to_string(),
                auth_token: "secret".to_string(),
                timeout_ms: 5_000,
                retry: RetryConfig::default(),
                circuit_breaker: CircuitBreakerConfig::default(),
                dead_letter_path: "./dead-letter.jsonl".to_string(),
            },
        };

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `response_adapter.endpoint`: must not be empty"
        );
    }

    #[test]
    fn timeout_defaults_to_five_seconds() {
        let raw = serde_json::json!({
            "kind": "webhook",
            "url": "http://localhost:9000/webhook"
        });
        let decoded: ResponseAdapterConfig = serde_json::from_value(raw).unwrap();
        match decoded {
            ResponseAdapterConfig::Webhook { config } => {
                assert_eq!(config.timeout_ms, 5_000);
                assert_eq!(config.channel, None);
                assert_eq!(config.auth_token, None);
                assert_eq!(config.retry.max_retries, 3);
                assert_eq!(config.circuit_breaker.threshold, 5);
                assert_eq!(config.dead_letter_path, "./dead-letter.jsonl");
            }
            other => panic!("expected webhook config, got {other:?}"),
        }
    }
}
