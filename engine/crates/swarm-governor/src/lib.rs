//! The real governance oracle — the kernel of the Chio reunification.
//!
//! Ambush's control-plane "Chio" shells out to a `chio` binary that does not exist and fails OPEN.
//! This evaluates an agent action through the REAL, fail-closed `swarm-guard` pipeline (forbidden
//! paths, dangerous shell commands, secret leaks, egress allowlist) and emits a cryptographically
//! signed verdict receipt (the `SignedReceipt` primitive harvested from hush-core). It is the
//! genuine ALLOW/DENY + signed receipt the shim only pretended to produce.

use serde::{Deserialize, Serialize};
use swarm_crypto::{Keypair, Receipt, Result as CryptoResult, SignedReceipt, Verdict, sha256};
use swarm_guard::{GuardAction, GuardContext, GuardResult, default_pipeline};
use swarm_metering::{CostMetadata, MeteringRequest};

/// Schema tag stamped into the receipt metadata.
pub const VERDICT_SCHEMA: &str = "ambush.governance.verdict.v1";

/// Gate id stamped on the verdict when an action is denied by per-lane budget
/// metering (the guard pipeline would have allowed it, but the lane is over budget).
pub const LANE_BUDGET_GATE: &str = "lane_budget";

/// An agent action submitted for governance, mapped onto a [`GuardAction`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentAction {
    FileAccess { path: String },
    FileWrite { path: String, content: String },
    ShellCommand { command: String },
    NetworkEgress { host: String, port: u16 },
    /// An MCP tool invocation that has no honest filesystem/shell semantics: governed by the
    /// `mcp_tool` guard against its tool name and JSON arguments (deny-by-default).
    McpTool {
        tool: String,
        args: serde_json::Value,
    },
}

impl AgentAction {
    fn as_guard_action(&self) -> GuardAction<'_> {
        match self {
            Self::FileAccess { path } => GuardAction::FileAccess(path),
            Self::FileWrite { path, content } => GuardAction::FileWrite(path, content.as_bytes()),
            Self::ShellCommand { command } => GuardAction::ShellCommand(command),
            Self::NetworkEgress { host, port } => GuardAction::NetworkEgress(host, *port),
            Self::McpTool { tool, args } => GuardAction::McpTool(tool, args),
        }
    }
}

/// The outcome of governing one action: the verdict, the raw guard result, and the signed receipt.
///
/// `allowed` is authoritative: it is the AND of the guard verdict and (when a
/// [`MeteringRequest`] is supplied) the per-lane budget check. `guard_result`
/// reflects only the guard pipeline, so a budget-denied action can have
/// `guard_result.allowed == true` while `allowed == false`.
pub struct GovernedVerdict {
    pub allowed: bool,
    pub guard_result: GuardResult,
    pub receipt: SignedReceipt,
}

/// Evaluate an action through the fail-closed guard pipeline and sign a verdict receipt with
/// `signer`. The receipt binds the SHA-256 of the canonical action, the deciding guard, and the
/// verdict; verification is via the standard `SignedReceipt` path.
///
/// This is the un-metered entry point: equivalent to [`evaluate_metered`] with no
/// [`MeteringRequest`]. Callers that enforce per-lane budgets call `evaluate_metered`.
pub fn evaluate(
    action: &AgentAction,
    agent_id: Option<&str>,
    signer: &Keypair,
) -> CryptoResult<GovernedVerdict> {
    evaluate_metered(action, agent_id, signer, None)
}

/// Evaluate an action through the fail-closed guard pipeline **and** an optional per-lane budget,
/// then sign the verdict receipt.
///
/// The action is allowed only if the guard pipeline allows it AND the lane is within budget. An
/// over-budget action is DENIED even when the guard would have allowed it (the cost doom-loop
/// lever), and — matching the existing fail-closed pattern — the denial is still a fully signed,
/// verifiable receipt. The draft spend is recorded against the lane only on a fully-allowed action
/// (post-spend). When `metering` is supplied, a [`CostMetadata`] record rides the receipt metadata
/// slot under the `"cost"` key.
pub fn evaluate_metered(
    action: &AgentAction,
    agent_id: Option<&str>,
    signer: &Keypair,
    metering: Option<MeteringRequest<'_>>,
) -> CryptoResult<GovernedVerdict> {
    let pipeline = default_pipeline();
    let mut ctx = GuardContext::new();
    if let Some(id) = agent_id {
        ctx = ctx.with_agent_id(id);
    }
    let result = pipeline.evaluate(&action.as_guard_action(), &ctx);
    let guard_allowed = result.allowed;

    // Per-lane budget metering. Fail closed: an over-budget action is denied even when the guard
    // pipeline would allow it. Record the spend only on a fully-allowed action (post-spend).
    let mut cost_value: Option<serde_json::Value> = None;
    let (allowed, gate_id) = match metering {
        Some(MeteringRequest { lane, draft, enforcer }) => {
            let check = enforcer.check(&lane, &draft);
            let budget_ok = check.is_ok();
            let allowed = guard_allowed && budget_ok;
            if allowed {
                enforcer.record(&lane, &draft);
            }
            let lane_spent = enforcer.spent(&lane);
            let gate = if !guard_allowed {
                result.guard.clone()
            } else if !budget_ok {
                LANE_BUDGET_GATE.to_string()
            } else {
                result.guard.clone()
            };
            cost_value =
                Some(CostMetadata::new(lane, draft, lane_spent, budget_ok, check.err()).to_value());
            (allowed, gate)
        }
        None => (guard_allowed, result.guard.clone()),
    };

    let canonical = swarm_crypto::canonical_json_string(action)?;
    let content_hash = sha256(canonical.as_bytes());
    let verdict = if allowed {
        Verdict::pass_with_gate(gate_id)
    } else {
        Verdict::fail_with_gate(gate_id)
    };
    let mut metadata = serde_json::json!({
        "schema": VERDICT_SCHEMA,
        "action": action,
        "guard": result.guard,
        "severity": result.severity,
        "message": result.message,
        "agent_id": agent_id,
    });
    if let Some(cost) = cost_value
        && let Some(obj) = metadata.as_object_mut()
    {
        obj.insert("cost".to_string(), cost);
    }
    let receipt = Receipt::new(content_hash, verdict).with_metadata(metadata);
    let receipt = SignedReceipt::sign(receipt, signer)?;

    Ok(GovernedVerdict {
        allowed,
        guard_result: result,
        receipt,
    })
}

/// Derive a deterministic signing keypair from secret material (sha256 -> 32-byte seed), matching
/// `Ed25519Signer::from_secret_material` so a caller can recompute the public key for pinning.
pub fn keypair_from_secret(secret: &str) -> Keypair {
    let seed = sha256(secret.as_bytes());
    Keypair::from_seed(seed.as_bytes())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use swarm_crypto::PublicKeySet;

    fn shell(cmd: &str) -> AgentAction {
        AgentAction::ShellCommand { command: cmd.to_string() }
    }

    #[test]
    fn safe_command_is_allowed_and_receipt_verifies() {
        let signer = Keypair::generate();
        let v = evaluate(&shell("cargo test"), Some("vec-01"), &signer).unwrap();
        assert!(v.allowed);
        assert!(v.receipt.receipt.verdict.passed);
        // the signed verdict verifies under the signer's key
        let keys = PublicKeySet::new(signer.public_key());
        assert!(v.receipt.verify(&keys).valid);
    }

    #[test]
    fn dangerous_command_is_denied_with_signed_receipt() {
        let signer = Keypair::generate();
        let v = evaluate(&shell("rm -rf /"), Some("vec-02"), &signer).unwrap();
        assert!(!v.allowed);
        assert_eq!(v.guard_result.guard, "shell_command");
        assert!(!v.receipt.receipt.verdict.passed);
        assert_eq!(v.receipt.receipt.verdict.gate_id.as_deref(), Some("shell_command"));
        // a DENY is still a signed, verifiable receipt (non-repudiation of the refusal)
        let keys = PublicKeySet::new(signer.public_key());
        assert!(v.receipt.verify(&keys).valid);
    }

    #[test]
    fn forbidden_path_is_denied() {
        let signer = Keypair::generate();
        let v = evaluate(
            &AgentAction::FileAccess { path: "/etc/shadow".into() },
            None,
            &signer,
        )
        .unwrap();
        assert!(!v.allowed);
        assert_eq!(v.guard_result.guard, "forbidden_path");
    }

    #[test]
    fn secret_write_is_denied() {
        let signer = Keypair::generate();
        let v = evaluate(
            &AgentAction::FileWrite {
                path: "/tmp/x".into(),
                content: "AKIA1234567890ABCDEF".into(),
            },
            None,
            &signer,
        )
        .unwrap();
        assert!(!v.allowed);
        assert_eq!(v.guard_result.guard, "secret_leak");
    }

    #[test]
    fn deterministic_key_from_secret_is_stable() {
        let a = keypair_from_secret("operation-nightfall-key");
        let b = keypair_from_secret("operation-nightfall-key");
        assert_eq!(a.public_key().to_hex(), b.public_key().to_hex());
    }

    #[test]
    fn tampered_receipt_fails_verification() {
        let signer = Keypair::generate();
        let mut v = evaluate(&shell("echo hi"), None, &signer).unwrap();
        // flip the verdict after signing -> the signature must no longer verify
        v.receipt.receipt.verdict.passed = false;
        let keys = PublicKeySet::new(signer.public_key());
        assert!(!v.receipt.verify(&keys).valid);
    }

    #[test]
    fn under_budget_action_is_allowed_recorded_and_carries_cost_metadata() {
        use swarm_metering::{AggregateSpend, BudgetEnforcer, BudgetLimit, MeteringRequest};
        let signer = Keypair::generate();
        let mut enforcer = BudgetEnforcer::new(BudgetLimit::default().with_max_tokens(1_000));

        let v = evaluate_metered(
            &shell("cargo test"),
            Some("vec-budget"),
            &signer,
            Some(MeteringRequest {
                lane: "research".to_string(),
                draft: AggregateSpend::with_tokens(900),
                enforcer: &mut enforcer,
            }),
        )
        .unwrap();

        assert!(v.allowed);
        assert!(v.receipt.receipt.verdict.passed);
        // post-spend recorded against the lane
        assert_eq!(enforcer.spent("research").tokens, 900);
        // cost metadata rides in the receipt metadata slot
        let cost = v
            .receipt
            .receipt
            .metadata
            .as_ref()
            .unwrap()
            .get("cost")
            .unwrap();
        assert_eq!(cost.get("allowed").unwrap(), &serde_json::json!(true));
        assert_eq!(cost.get("lane").unwrap(), &serde_json::json!("research"));
    }

    #[test]
    fn over_budget_action_is_denied_with_signed_receipt() {
        use swarm_metering::{AggregateSpend, BudgetEnforcer, BudgetLimit, MeteringRequest};
        let signer = Keypair::generate();
        let mut enforcer = BudgetEnforcer::new(BudgetLimit::default().with_max_tokens(1_000));

        // first call is under budget -> allowed + recorded (900 tokens)
        let v1 = evaluate_metered(
            &shell("cargo test"),
            Some("vec-budget"),
            &signer,
            Some(MeteringRequest {
                lane: "research".to_string(),
                draft: AggregateSpend::with_tokens(900),
                enforcer: &mut enforcer,
            }),
        )
        .unwrap();
        assert!(v1.allowed);

        // second call would push the lane to 1_100 > 1_000 -> denied, even though
        // the guard pipeline allows "cargo test".
        let v2 = evaluate_metered(
            &shell("cargo test"),
            Some("vec-budget"),
            &signer,
            Some(MeteringRequest {
                lane: "research".to_string(),
                draft: AggregateSpend::with_tokens(200),
                enforcer: &mut enforcer,
            }),
        )
        .unwrap();

        assert!(!v2.allowed);
        // the guard itself was happy; the denial came from the lane budget
        assert!(v2.guard_result.allowed);
        assert!(!v2.receipt.receipt.verdict.passed);
        assert_eq!(v2.receipt.receipt.verdict.gate_id.as_deref(), Some("lane_budget"));
        // a budget DENY is still a signed, verifiable receipt (non-repudiation)
        let keys = PublicKeySet::new(signer.public_key());
        assert!(v2.receipt.verify(&keys).valid);
        // the over-budget draft was NOT recorded; the lane is still at 900
        assert_eq!(enforcer.spent("research").tokens, 900);
        // the violation rides in the cost metadata
        let cost = v2
            .receipt
            .receipt
            .metadata
            .as_ref()
            .unwrap()
            .get("cost")
            .unwrap();
        assert_eq!(cost.get("allowed").unwrap(), &serde_json::json!(false));
        assert_eq!(
            cost.pointer("/violation/dimension").unwrap(),
            &serde_json::json!("tokens")
        );
    }
}
