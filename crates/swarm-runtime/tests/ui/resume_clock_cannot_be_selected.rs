use swarm_runtime::approval::ApprovalReceiptPackReport;
use swarm_runtime::dispatcher::HumanApprovalResumeDispatcher;

fn main() {
    fn attacker_selects_validation_time(
        dispatcher: &HumanApprovalResumeDispatcher,
        pack: ApprovalReceiptPackReport,
    ) {
        let _ = dispatcher.resume(pack, 0);
    }

    let _ = attacker_selects_validation_time;
}
