//! FALSIFY-02 negative-falsifiability test for `ResponseHttpEdrEndpointRequired`
//! (docs/assurance/MAPPING.md).
//!
//! `HttpEdrAdapter::new` (crates/swarm-response/src/http_edr.rs:23-28) denies
//! constructing (and thereby ever dispatching through) an HTTP EDR adapter
//! whose configured endpoint URL is empty or whitespace-only. `new` is
//! `pub`, so this test calls it directly.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use swarm_response::config::{CircuitBreakerConfig, HttpEdrConfig, RetryConfig};
use swarm_response::http_edr::HttpEdrAdapter;

/// A deliberately broken re-implementation of `HttpEdrAdapter::new`'s
/// endpoint guard (crates/swarm-response/src/http_edr.rs:24-29) with the
/// empty/whitespace check removed: an adapter is constructed regardless of
/// whether it has anywhere to send a request.
fn broken_endpoint_check_permits(_endpoint: &str) -> bool {
    true
}

#[test]
fn negative_response_http_edr_endpoint_required() {
    let config = HttpEdrConfig {
        endpoint: "   ".to_string(),
        auth_token: "secret".to_string().into(),
        timeout_ms: 5_000,
        retry: RetryConfig::default(),
        circuit_breaker: CircuitBreakerConfig::default(),
        dead_letter_path: "./dead-letter.jsonl".to_string(),
    };

    // 1. The REAL constructor denies a blank endpoint.
    let real_result = HttpEdrAdapter::new(config);
    assert!(
        real_result.is_err(),
        "real HttpEdrAdapter::new must reject a blank endpoint"
    );

    // 2. The broken variant permits the identical endpoint value.
    assert!(
        broken_endpoint_check_permits("   "),
        "broken variant is expected to (wrongly) accept the blank endpoint"
    );
}
