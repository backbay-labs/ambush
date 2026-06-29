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

/// Schema tag stamped into the receipt metadata.
pub const VERDICT_SCHEMA: &str = "ambush.governance.verdict.v1";

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
pub struct GovernedVerdict {
    pub allowed: bool,
    pub guard_result: GuardResult,
    pub receipt: SignedReceipt,
}

/// Evaluate an action through the fail-closed guard pipeline and sign a verdict receipt with
/// `signer`. The receipt binds the SHA-256 of the canonical action, the deciding guard, and the
/// verdict; verification is via the standard `SignedReceipt` path.
pub fn evaluate(
    action: &AgentAction,
    agent_id: Option<&str>,
    signer: &Keypair,
) -> CryptoResult<GovernedVerdict> {
    let pipeline = default_pipeline();
    let mut ctx = GuardContext::new();
    if let Some(id) = agent_id {
        ctx = ctx.with_agent_id(id);
    }
    let result = pipeline.evaluate(&action.as_guard_action(), &ctx);

    let canonical = swarm_crypto::canonical_json_string(action)?;
    let content_hash = sha256(canonical.as_bytes());
    let verdict = if result.allowed {
        Verdict::pass_with_gate(result.guard.clone())
    } else {
        Verdict::fail_with_gate(result.guard.clone())
    };
    let receipt = Receipt::new(content_hash, verdict).with_metadata(serde_json::json!({
        "schema": VERDICT_SCHEMA,
        "action": action,
        "guard": result.guard,
        "severity": result.severity,
        "message": result.message,
        "agent_id": agent_id,
    }));
    let receipt = SignedReceipt::sign(receipt, signer)?;

    Ok(GovernedVerdict {
        allowed: result.allowed,
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
}
