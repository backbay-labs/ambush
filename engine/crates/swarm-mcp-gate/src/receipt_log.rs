//! The gate decision (map -> evaluate -> signed receipt envelope) and the cross-process receipt log.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;

use fs2::FileExt;
use swarm_crypto::Keypair;
use swarm_governor::evaluate_metered;
use swarm_metering::{AggregateSpend, BudgetEnforcer, MeteringRequest};

use crate::mapping::{Mapping, map_tool};

/// Append-only JSONL receipt log shared across the per-Vector gate processes (cross-process locked).
pub struct ReceiptLog {
    file: Mutex<File>,
}

impl ReceiptLog {
    pub fn open(path: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file: Mutex::new(file) })
    }

    pub fn append(&self, line: &str) {
        if let Ok(mut f) = self.file.lock() {
            let locked = FileExt::lock_exclusive(&*f).is_ok();
            let _ = writeln!(f, "{line}");
            let _ = f.flush();
            if locked {
                let _ = FileExt::unlock(&*f);
            }
        }
    }
}

pub struct GateCtx {
    pub keypair: Keypair,
    pub agent_id: Option<String>,
    pub server_id: String,
    pub vault: String,
    pub log: ReceiptLog,
    /// Optional per-lane request budget: when set, each tools/call charges 1 request and an
    /// over-budget call is denied (gate_id `lane_budget`) even when the guards would allow it.
    pub budget: Option<Mutex<BudgetEnforcer>>,
    /// Lane id the budget is metered against (the Vector id, or "default").
    pub lane: String,
}

pub struct GateOutcome {
    pub allow: bool,
    pub code: String,
    pub reason: String,
    pub receipt_id: String,
}

impl GateCtx {
    /// Map the tool to an action, evaluate it through the real guards, append a signed receipt
    /// envelope, and return the gate decision. Fail-closed on evaluation error.
    pub fn decide(&self, tool: &str, args: &serde_json::Value) -> GateOutcome {
        let mapping = map_tool(tool, args, &self.vault);
        let (action, hard_deny, hard_reason) = match mapping {
            Mapping::Action(a) => (a, false, String::new()),
            Mapping::HardDeny { action, reason } => (action, true, reason),
        };

        // Per-lane request metering: when a budget is configured, charge 1 request per tools/call,
        // so an over-budget lane is DENIED (gate_id `lane_budget`) even when the guards would allow
        // it, with the cost riding the receipt. Otherwise the metered path with no budget (None).
        let eval = match &self.budget {
            Some(budget) => match budget.lock() {
                Ok(mut enforcer) => evaluate_metered(
                    &action,
                    self.agent_id.as_deref(),
                    &self.keypair,
                    Some(MeteringRequest {
                        lane: self.lane.clone(),
                        draft: AggregateSpend::with_requests(1),
                        enforcer: &mut enforcer,
                    }),
                ),
                Err(_) => {
                    // Budget mutex poisoned: fail CLOSED rather than silently skip the cap.
                    let code = "urn:ambush:gate:denied:lane_budget".to_string();
                    let reason = "lane budget unavailable (poisoned lock) — fail-closed".to_string();
                    self.log.append(&minimal_envelope(tool, &self.server_id, &code, &reason));
                    return GateOutcome { allow: false, code, reason, receipt_id: String::new() };
                }
            },
            None => evaluate_metered(&action, self.agent_id.as_deref(), &self.keypair, None),
        };
        let verdict = match eval {
            Ok(v) => v,
            Err(e) => {
                let code = "urn:ambush:gate:denied:internal".to_string();
                let reason = format!("evaluation error: {e}");
                self.log.append(&minimal_envelope(tool, &self.server_id, &code, &reason));
                return GateOutcome { allow: false, code, reason, receipt_id: String::new() };
            }
        };

        let gate_allow = verdict.allowed && !hard_deny;
        let guard = verdict.guard_result.guard.clone();
        let code = if gate_allow {
            String::new()
        } else if hard_deny {
            "urn:ambush:gate:denied:policy".to_string()
        } else {
            format!("urn:ambush:gate:denied:{guard}")
        };
        let reason = if hard_deny { hard_reason } else { verdict.guard_result.message.clone() };
        let receipt_id = verdict.receipt.receipt.content_hash.to_hex();
        let receipt_val = serde_json::to_value(&verdict.receipt).unwrap_or(serde_json::Value::Null);
        let action_val = serde_json::to_value(&action).unwrap_or(serde_json::Value::Null);

        let envelope = serde_json::json!({
            "schema": "ambush.mcp-gate.receipt.v1",
            "id": receipt_id,
            "timestamp": verdict.receipt.receipt.timestamp,
            "server": self.server_id,
            "tool": tool,
            "verdict": if gate_allow { "ALLOW" } else { "DENY" },
            "guard": guard,
            "policy_hash": guard,
            "gate_reason": if gate_allow { serde_json::Value::Null } else { serde_json::Value::String(reason.clone()) },
            "agent_id": self.agent_id,
            "action": action_val,
            "receipt": receipt_val,
        });
        if let Ok(line) = serde_json::to_string(&envelope) {
            self.log.append(&line);
        }

        GateOutcome { allow: gate_allow, code, reason, receipt_id }
    }

    /// Hard-deny a side-effecting, non-allowlisted MCP method fail-closed: append a deny envelope to
    /// the audit log and return the JSON-RPC error for the agent. Nothing reaches the inner server.
    pub fn deny_method(&self, id: &serde_json::Value, method: &str) -> String {
        let code = "urn:ambush:gate:denied:method".to_string();
        let reason = format!("MCP method '{method}' is not permitted by the gate (fail-closed)");
        self.log.append(&minimal_envelope(method, &self.server_id, &code, &reason));
        serde_json::to_string(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32601,
                "message": reason,
                "data": { "ambush_code": code, "method": method }
            }
        }))
        .unwrap_or_else(|_| "{}".into())
    }
}

fn minimal_envelope(tool: &str, server: &str, code: &str, reason: &str) -> String {
    serde_json::to_string(&serde_json::json!({
        "schema": "ambush.mcp-gate.receipt.v1",
        "server": server,
        "tool": tool,
        "verdict": "DENY",
        "policy_hash": "internal",
        "gate_reason": reason,
        "ambush_code": code,
    }))
    .unwrap_or_else(|_| "{}".into())
}

/// A JSON-RPC error frame for a denied tools/call.
pub fn json_rpc_error(id: &serde_json::Value, tool: &str, outcome: &GateOutcome) -> String {
    serde_json::to_string(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32001,
            "message": outcome.reason,
            "data": {
                "ambush_code": outcome.code,
                "tool": tool,
                "receipt_id": outcome.receipt_id,
            }
        }
    }))
    .unwrap_or_else(|_| "{}".into())
}

/// A JSON-RPC error frame for a malformed inbound frame.
pub fn json_rpc_invalid() -> String {
    serde_json::to_string(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": serde_json::Value::Null,
        "error": {
            "code": -32700,
            "message": "malformed JSON-RPC frame",
            "data": { "ambush_code": "urn:ambush:gate:invalid-request" }
        }
    }))
    .unwrap_or_else(|_| "{}".into())
}
