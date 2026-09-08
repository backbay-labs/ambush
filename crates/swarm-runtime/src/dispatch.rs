//! The one external-effect boundary for both runtime authorization entry points.
//!
//! An authorization intent is persisted before the adapter future is polled.
//! Completion is a separate fact: cancellation or an ambiguous adapter error
//! never makes the reserved request eligible for retransmission.

use swarm_policy::{ActionRequest, CapabilityLease};
use swarm_response::{ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt};

use crate::SwarmRuntime;

pub(super) struct DispatchOutcome {
    pub result: Result<ResponseReceipt, ResponseError>,
    pub attempted: bool,
    pub completion_error: Option<ResponseError>,
}

impl<P, E: ResponseExecutor> SwarmRuntime<P, E> {
    pub(super) async fn dispatch_once(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
        mode: ExecutionMode,
        now_ms: i64,
    ) -> DispatchOutcome {
        if mode == ExecutionMode::DryRun {
            return DispatchOutcome {
                result: self.response.execute(request, lease, mode).await,
                attempted: true,
                completion_error: None,
            };
        }

        // INVARIANT: RuntimeDispatchIntentRequired
        let Some(journal) = &self.dispatch_journal else {
            return refused(
                request,
                mode,
                "durable dispatch journal is not configured".into(),
                false,
            );
        };
        // No await separates the reservation from its durable acknowledgement.
        // Every path to an enforced adapter invocation crosses this reservation.
        let dispatch_id = match journal.reserve(request, lease, now_ms) {
            Ok(id) => id,
            Err(error) => {
                return refused(
                    request,
                    mode,
                    error.to_string(),
                    error.has_prior_reservation(),
                );
            }
        };
        tracing::info!(
            module = module_path!(),
            %dispatch_id,
            hunt_id = %request.hunt_id.0,
            action = request.action.kind(),
            "durable dispatch intent recorded before execution"
        );

        let result = self.response.execute(request, lease, mode).await;
        if let Err(error) = journal.complete(&dispatch_id, &result) {
            tracing::error!(
                module = module_path!(),
                %dispatch_id,
                reason = %error,
                "response attempted but completion could not be recorded; retransmission refused"
            );
            return DispatchOutcome {
                completion_error: Some(ResponseError::execution_failed(
                    format!("dispatch-unrecorded:{dispatch_id}"),
                    request.action.kind(),
                    mode,
                    format!("response attempted but completion was not durably recorded: {error}"),
                    serde_json::json!({
                        "status": "dispatch_outcome_unknown",
                        "dispatch_intent_id": dispatch_id,
                        "response_attempted": true,
                        "adapter_result": result,
                        "retry_permitted": false,
                    }),
                )),
                result,
                attempted: true,
            };
        }
        DispatchOutcome {
            result,
            attempted: true,
            completion_error: None,
        }
    }
}

fn refused(
    request: &ActionRequest,
    mode: ExecutionMode,
    reason: String,
    prior_reservation: bool,
) -> DispatchOutcome {
    tracing::warn!(
        module = module_path!(),
        hunt_id = %request.hunt_id.0,
        action = request.action.kind(),
        %reason,
        prior_reservation,
        "response dispatch refused"
    );
    DispatchOutcome {
        result: Err(ResponseError::execution_failed(
            format!(
                "dispatch-refused:{}:{}",
                request.hunt_id.0,
                request.action.kind()
            ),
            request.action.kind(),
            mode,
            format!("dispatch refused: {reason}"),
            serde_json::json!({
                "status": "dispatch_refused",
                "response_attempted": false,
                "prior_reservation": prior_reservation,
                "retry_permitted": false,
                "reason": reason,
            }),
        )),
        attempted: false,
        completion_error: None,
    }
}
