//! FALSIFY-02 negative-falsifiability test for
//! `ResponseCrowdStrikeRtrBaseUrlRequired` (docs/assurance/MAPPING.md).
//!
//! `CrowdStrikeRtrAdapter::new` (crates/swarm-response/src/crowdstrike_rtr.rs:35-40)
//! denies constructing a CrowdStrike RTR adapter whose configured
//! `base_url` is empty or whitespace-only. `new` is `pub`, so this test
//! calls it directly.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use swarm_response::config::{CircuitBreakerConfig, CrowdStrikeRtrConfig, RetryConfig};
use swarm_response::crowdstrike_rtr::CrowdStrikeRtrAdapter;

/// A deliberately broken re-implementation of `CrowdStrikeRtrAdapter::new`'s
/// base_url guard (crates/swarm-response/src/crowdstrike_rtr.rs:36-41) with
/// the empty/whitespace check removed.
fn broken_base_url_check_permits(_base_url: &str) -> bool {
    true
}

#[test]
fn negative_response_crowdstrike_rtr_base_url_required() {
    let config = CrowdStrikeRtrConfig {
        base_url: "   ".to_string(),
        client_id: "client-id".to_string().into(),
        client_secret: "client-secret".to_string().into(),
        timeout_ms: 5_000,
        retry: RetryConfig::default(),
        circuit_breaker: CircuitBreakerConfig::default(),
        dead_letter_path: "./dead-letter.jsonl".to_string(),
    };

    // 1. The REAL constructor denies a blank base_url.
    let real_result = CrowdStrikeRtrAdapter::new(config);
    assert!(
        real_result.is_err(),
        "real CrowdStrikeRtrAdapter::new must reject a blank base_url"
    );

    // 2. The broken variant permits the identical base_url value.
    assert!(
        broken_base_url_check_permits("   "),
        "broken variant is expected to (wrongly) accept the blank base_url"
    );
}
