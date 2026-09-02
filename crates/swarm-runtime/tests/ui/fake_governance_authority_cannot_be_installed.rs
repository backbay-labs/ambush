use std::sync::Arc;
use swarm_ingest_runtime::ingest::IngestState;
use swarm_response::rollback::RollbackReceipt;
use swarm_runtime::containment::{ContainmentSweep, verify_release_attestation};
use swarm_runtime::dispatcher::{
    AgentDispatcher, HumanApprovalResumeDispatcher, RequestResponseRouter,
};

struct Fake;

fn install_dispatcher(dispatcher: AgentDispatcher, fake: Fake) {
    let _dispatcher = dispatcher.with_governance_authority(fake);
}

fn install_ingest(state: IngestState, fake: Fake) {
    let _state = state.with_governance_authority(fake);
}

fn install_containment(sweep: ContainmentSweep, fake: Fake) {
    let _sweep = sweep.with_governance_authority(fake);
}

fn install_human_resume(fake: Fake, router: Arc<dyn RequestResponseRouter>) {
    let _resume = HumanApprovalResumeDispatcher::new(
        fake,
        router,
        vec!["configured-approver".to_string()],
        swarm_runtime::approval::ThresholdRule::AtLeast { required: 1 },
    );
}

fn pass_release_verifier(receipt: &RollbackReceipt, fake: &Fake) {
    let authority: &swarm_governance::GovernanceAuthority = fake;
    let _result = verify_release_attestation(receipt, Some(authority));
}

fn main() {}
