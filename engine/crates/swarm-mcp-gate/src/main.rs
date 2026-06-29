//! `swarm-mcp-gate [--server-id <id>] [--vault <path>] -- <inner MCP argv...>`
//!
//! Spawns the inner MCP server and proxies stdio JSON-RPC both ways, gating every `tools/call`
//! through swarm-governor and appending a signed receipt to `AMBUSH_RECEIPT_LOG`. The signing key
//! comes from `SWARM_GOVERNOR_KEY`; the governed agent's id/vault arrive via `AMBUSH_VECTOR_ID` /
//! `AMBUSH_VAULT` (already injected into the PTY env by the orchestrator). Fail-closed: missing key
//! or log path aborts rather than running ungoverned.

mod mapping;
mod proxy;
mod receipt_log;

use std::io::{self, BufReader, BufWriter};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use receipt_log::{GateCtx, ReceiptLog};
use swarm_governor::keypair_from_secret;
use swarm_metering::{BudgetEnforcer, BudgetLimit};

fn fail(msg: &str) -> ! {
    eprintln!("swarm-mcp-gate: {msg}");
    std::process::exit(2);
}

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let Some(sep) = raw.iter().position(|a| a == "--") else {
        fail("usage: swarm-mcp-gate [--server-id <id>] [--vault <path>] -- <inner argv...>");
    };
    let flags = &raw[..sep];
    let inner_argv = &raw[sep + 1..];
    if inner_argv.is_empty() {
        fail("no inner MCP server command after --");
    }

    let mut server_id = "open-knowledge".to_string();
    let mut vault = std::env::var("AMBUSH_VAULT").unwrap_or_default();
    let mut i = 0;
    while i < flags.len() {
        match flags[i].as_str() {
            "--server-id" => {
                i += 1;
                if let Some(v) = flags.get(i) {
                    server_id = v.clone();
                }
            }
            "--vault" => {
                i += 1;
                if let Some(v) = flags.get(i) {
                    vault = v.clone();
                }
            }
            _ => {}
        }
        i += 1;
    }
    if vault.is_empty() {
        vault = std::env::current_dir()
            .ok()
            .and_then(|p| p.to_str().map(String::from))
            .unwrap_or_else(|| ".".to_string());
    }

    let secret = match std::env::var("SWARM_GOVERNOR_KEY") {
        Ok(s) if !s.is_empty() => s,
        _ => fail("SWARM_GOVERNOR_KEY unset — refusing to run ungoverned (fail-closed)"),
    };
    let log_path = match std::env::var("AMBUSH_RECEIPT_LOG") {
        Ok(s) if !s.is_empty() => s,
        _ => fail("AMBUSH_RECEIPT_LOG unset (fail-closed)"),
    };
    let keypair = keypair_from_secret(&secret);
    let agent_id = std::env::var("AMBUSH_VECTOR_ID")
        .ok()
        .or_else(|| std::env::var("SWARM_AGENT_ID").ok());
    // Optional per-lane request budget: AMBUSH_LANE_BUDGET_REQUESTS=N caps governed tool calls
    // for this Vector; over budget denies at the `lane_budget` gate (the cost doom-loop lever).
    let lane = agent_id.clone().unwrap_or_else(|| "default".to_string());
    let budget = std::env::var("AMBUSH_LANE_BUDGET_REQUESTS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .map(|n| Mutex::new(BudgetEnforcer::new(BudgetLimit::default().with_max_requests(n))));
    let log = match ReceiptLog::open(&log_path) {
        Ok(l) => l,
        Err(e) => fail(&format!("cannot open receipt log {log_path}: {e}")),
    };

    let mut child = match Command::new(&inner_argv[0])
        .args(&inner_argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => fail(&format!("cannot spawn inner MCP server {}: {e}", inner_argv[0])),
    };
    let Some(inner_stdin) = child.stdin.take() else { fail("inner stdin unavailable") };
    let Some(inner_stdout) = child.stdout.take() else { fail("inner stdout unavailable") };

    let agent_out = Arc::new(Mutex::new(io::stdout()));
    let gate = GateCtx { keypair, agent_id, server_id, vault, log, budget, lane };

    // Thread B: inner -> agent (verbatim).
    let b_out = Arc::clone(&agent_out);
    let pump_b = thread::spawn(move || proxy::pump_inner_to_agent(BufReader::new(inner_stdout), b_out));

    // Thread A: agent -> inner (gated) on this thread. Dropping the writer on return closes inner stdin.
    {
        let stdin = io::stdin();
        proxy::pump_agent_to_inner(stdin.lock(), BufWriter::new(inner_stdin), Arc::clone(&agent_out), &gate);
    }

    let _ = child.wait();
    let _ = pump_b.join();
}
