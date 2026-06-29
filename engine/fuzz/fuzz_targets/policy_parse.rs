// Adapted from ClawdStrike/Arc (Apache-2.0)
//! Trust-boundary fuzz target for policy / ruleset parse + compile.
//!
//! The deterministic approval gate is only fail-closed if untrusted ruleset
//! and request JSON can be deserialized and compiled without panicking. This
//! target drives the full ruleset config parse (`SwarmConfig` / `PolicyConfig`),
//! gate construction, and a policy evaluation over a fuzzed request. Every
//! outcome must be a `Result`/verdict, never a crash.

#![no_main]

use libfuzzer_sys::{fuzz_mutator, fuzz_target};
use swarm_core::config::{PolicyConfig, SwarmConfig};
use swarm_fuzz::canonical_json::canonical_json_mutate;
use swarm_policy::configurable_gate::ConfigurableApprovalGate;
use swarm_policy::{ActionRequest, ApprovalContext, ApprovalGate};

fuzz_target!(|data: &[u8]| {
    // Whole-config (ruleset) parse: deny_unknown_fields + nested enums make
    // this a dense decode surface. Must not panic.
    let _ = serde_json::from_slice::<SwarmConfig>(data);

    // Policy ruleset parse + compile: on a structurally valid `PolicyConfig`,
    // build the gate (the "compile" step) and evaluate a request.
    if let Ok(policy) = serde_json::from_slice::<PolicyConfig>(data) {
        let gate = ConfigurableApprovalGate::from_config(&policy);

        // If the same bytes also deserialize as a request, drive evaluation.
        // The gate is fail-closed: any verdict (Allow/Deny/RequireHuman) or
        // `Err` is acceptable; a panic is a finding.
        if let Ok(request) = serde_json::from_slice::<ActionRequest>(data) {
            let context = ApprovalContext {
                live_mode: false,
                receipt_chain: Vec::new(),
                correlation_id: None,
                now_ms: 0,
            };
            let _ = gate.evaluate(&request, &context);
            let _ = gate.issue_lease(&request, &context);
        }
    }
});

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    canonical_json_mutate(data, size, max_size, seed)
});
