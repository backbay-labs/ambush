//! `swarm-governor` — evaluate one agent action through the real fail-closed guard pipeline and
//! emit a signed verdict receipt.
//!
//! Reads an action as JSON from `--action <json>` or stdin, e.g.:
//!   {"kind":"shell_command","command":"rm -rf /"}
//!   {"kind":"file_access","path":"/etc/shadow"}
//!   {"kind":"network_egress","host":"evil.com","port":443}
//! Signs the verdict with a key derived from `SWARM_GOVERNOR_KEY` (deterministic) or an ephemeral
//! key, prints the signed receipt JSON to stdout, and exits 0 (allow) / 1 (deny) / 2 (error).

use std::io::Read;

use swarm_crypto::Keypair;
use swarm_governor::{AgentAction, evaluate_metered, keypair_from_secret};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let input = if let Some(pos) = args.iter().position(|a| a == "--action") {
        match args.get(pos + 1) {
            Some(s) => s.clone(),
            None => {
                eprintln!("--action requires a JSON value");
                std::process::exit(2);
            }
        }
    } else {
        let mut buf = String::new();
        if std::io::stdin().read_to_string(&mut buf).is_err() {
            eprintln!("failed to read action JSON from stdin");
            std::process::exit(2);
        }
        buf
    };

    let action: AgentAction = match serde_json::from_str(input.trim()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("invalid action JSON: {e}");
            std::process::exit(2);
        }
    };

    let signer = match std::env::var("SWARM_GOVERNOR_KEY") {
        Ok(secret) if !secret.is_empty() => keypair_from_secret(&secret),
        _ => Keypair::generate(),
    };
    eprintln!("governor signer pubkey: {}", signer.public_key().to_hex());

    let agent_id = std::env::var("SWARM_AGENT_ID").ok();
    match evaluate_metered(&action, agent_id.as_deref(), &signer, None) {
        Ok(v) => {
            match v.receipt.to_json() {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    eprintln!("failed to serialize receipt: {e}");
                    std::process::exit(2);
                }
            }
            eprintln!(
                "VERDICT: {} (guard: {})",
                if v.allowed { "ALLOW" } else { "DENY" },
                v.guard_result.guard
            );
            std::process::exit(if v.allowed { 0 } else { 1 });
        }
        Err(e) => {
            eprintln!("evaluation error: {e}");
            std::process::exit(2);
        }
    }
}
