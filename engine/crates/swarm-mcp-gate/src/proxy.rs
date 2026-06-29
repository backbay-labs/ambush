//! Transparent bidirectional stdio JSON-RPC proxy with a gate on the agent->inner `tools/call` path.
//!
//! MCP stdio is newline-delimited JSON-RPC (no Content-Length). The inner server owns the
//! `initialize` handshake and id-correlation; this proxy forwards everything verbatim except
//! `tools/call`, which it gates: ALLOW forwards the original frame, DENY synthesizes a JSON-RPC
//! error and never forwards. Both directions run on their own thread.

use std::io::{self, BufRead, ErrorKind, Stdout, Write};
use std::sync::{Arc, Mutex};

use crate::receipt_log::{GateCtx, json_rpc_error, json_rpc_invalid};

/// Max agent->inner request frame. Requests are small; an oversize one is suspicious.
const MAX_FRAME_BYTES: usize = 1024 * 1024;
/// Max inner->agent reply frame. Tool results (large file reads) can be big, so this is larger and
/// the pump recovers from an over-cap frame rather than dying.
const MAX_INNER_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Discard bytes from `reader` up to and including the next newline (recover after an oversize frame).
fn drain_to_newline<R: BufRead>(reader: &mut R) {
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        if available.is_empty() {
            return; // EOF
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            reader.consume(pos + 1);
            return;
        }
        let len = available.len();
        reader.consume(len);
    }
}

/// Read one newline-delimited frame, bounded to `max` bytes (fail-closed on oversize). Returns the
/// line with trailing CR/LF stripped, or None at EOF.
pub fn read_bounded_line<R: BufRead>(reader: &mut R, max: usize) -> io::Result<Option<String>> {
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            break;
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            buf.extend_from_slice(&available[..=pos]);
            reader.consume(pos + 1);
            break;
        }
        let len = available.len();
        buf.extend_from_slice(available);
        reader.consume(len);
        if buf.len() > max {
            return Err(io::Error::new(ErrorKind::InvalidData, "frame exceeds max size"));
        }
    }
    while matches!(buf.last(), Some(b'\n' | b'\r')) {
        buf.pop();
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

fn write_locked(out: &Arc<Mutex<Stdout>>, line: &str) {
    if let Ok(mut o) = out.lock() {
        let _ = writeln!(o, "{line}");
        let _ = o.flush();
    }
}

/// inner -> agent: copy every frame verbatim to our stdout (tools/call results, initialize, etc.).
/// Resilient: an over-cap frame is drained (not fatal) so the pump never dies and wedges the agent.
pub fn pump_inner_to_agent<R: BufRead>(mut inner: R, agent: Arc<Mutex<Stdout>>) {
    loop {
        match read_bounded_line(&mut inner, MAX_INNER_FRAME_BYTES) {
            Ok(Some(line)) => write_locked(&agent, &line),
            Ok(None) => break, // EOF
            Err(e) if e.kind() == ErrorKind::InvalidData => drain_to_newline(&mut inner), // oversize
            Err(_) => break,   // hard IO error
        }
    }
}

/// agent -> inner: forward everything; gate `tools/call`. `inner` is consumed and dropped on return
/// (agent EOF), closing the inner server's stdin.
pub fn pump_agent_to_inner<R: BufRead, W: Write>(
    mut agent_in: R,
    mut inner: W,
    agent_out: Arc<Mutex<Stdout>>,
    gate: &GateCtx,
) {
    loop {
        let line = match read_bounded_line(&mut agent_in, MAX_FRAME_BYTES) {
            Ok(Some(l)) => l,
            Ok(None) => break,                                                  // EOF
            Err(e) if e.kind() == ErrorKind::InvalidData => {
                drain_to_newline(&mut agent_in); // oversize request: drop + recover, do not die
                continue;
            }
            Err(_) => break, // hard IO error
        };
        if line.trim().is_empty() {
            continue;
        }
        let frame: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                write_locked(&agent_out, &json_rpc_invalid());
                continue;
            }
        };
        // Fail closed on non-object frames (JSON-RPC batch arrays, primitives): there is no single
        // method to gate, so an array wrapping a `tools/call` must NOT slip through ungoverned.
        if !frame.is_object() {
            write_locked(&agent_out, &json_rpc_invalid());
            continue;
        }
        let id = frame.get("id").cloned().unwrap_or(serde_json::Value::Null);
        // Distinguish an ABSENT method (a response to a server-initiated request -> passthrough) from
        // a PRESENT-but-non-string method (malformed -> fail closed); collapsing both to "" let a
        // `{"method":[...]}` frame pass ungated.
        let method = match frame.get("method") {
            None => "",
            Some(serde_json::Value::String(s)) => s.as_str(),
            Some(_) => {
                write_locked(&agent_out, &json_rpc_invalid());
                continue;
            }
        };

        // Deny-by-default on method. A frame with no method is a response to a server-initiated
        // request; inert handshake/list/notification methods pass verbatim; `tools/call` is gated;
        // every OTHER (side-effecting) method — resources/read, prompts/get, sampling/*, … — is
        // denied fail-closed so nothing reaches the inner server without a guard decision + receipt.
        if method.is_empty() || is_passthrough_method(method) {
            let _ = writeln!(inner, "{line}");
            let _ = inner.flush();
            continue;
        }
        if method != "tools/call" {
            write_locked(&agent_out, &gate.deny_method(&id, method));
            continue;
        }
        let params = frame.get("params").cloned().unwrap_or(serde_json::Value::Null);
        let tool = params.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
        let args = params.get("arguments").cloned().unwrap_or(serde_json::Value::Null);

        let outcome = gate.decide(&tool, &args);
        if outcome.allow {
            let _ = writeln!(inner, "{line}");
            let _ = inner.flush();
        } else {
            write_locked(&agent_out, &json_rpc_error(&id, &tool, &outcome));
        }
    }
}

/// Inert MCP methods that carry no agent action: the handshake, capability listing, notifications,
/// and log-level — safe to forward verbatim. Everything else is gated or denied.
fn is_passthrough_method(method: &str) -> bool {
    method.starts_with("notifications/")
        || matches!(
            method,
            "initialize"
                | "ping"
                | "tools/list"
                | "resources/list"
                | "resources/templates/list"
                | "prompts/list"
                | "logging/setLevel"
        )
}
