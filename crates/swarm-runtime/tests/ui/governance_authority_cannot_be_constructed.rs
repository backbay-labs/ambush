use std::sync::Arc;
use swarm_governance::{GovernanceAuthority, GovernancePolicy};

fn main() {
    let policy = Arc::new(GovernancePolicy::default());
    let _forged = GovernanceAuthority { policy };
}
