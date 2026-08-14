use swarm_runtime::dispatcher::{DispatcherPolicyPermit, RoutedActionRequest};

fn main() {
    fn forge(permit: DispatcherPolicyPermit) -> RoutedActionRequest {
        RoutedActionRequest {
            permit,
            verified_governance_receipt: None,
            verified_human_approval: None,
        }
    }

    let _ = forge;
}
