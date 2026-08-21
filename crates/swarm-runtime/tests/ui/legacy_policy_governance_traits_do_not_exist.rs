use swarm_policy::governance::{
    GovernanceAuthority,
    sealed::SealedGovernanceAuthority,
};

struct Fake;

impl SealedGovernanceAuthority for Fake {}
impl GovernanceAuthority for Fake {}

fn main() {}
