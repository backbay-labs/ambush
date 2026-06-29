//! Transparent bidirectional stdio JSON-RPC proxy with a gate on the agent->inner `tools/call` path.
//!
//! MCP stdio is newline-delimited JSON-RPC (no Content-Length). The inner server owns the
//! `initialize` handshake and id-correlation; this proxy forwards everything verbatim except
//! `tools/call`, which it gates: ALLOW forwards the original frame, DENY synthesizes a JSON-RPC
//! error and never forwards. Both directions run on their own thread.

use std::io::{self, BufRead, ErrorKind, Stdout, Write};
use std::sync::{Arc, Mutex};

use crate::receipt_log::{GateCtx, json_rpc_error, json_rpc_invalid};

const MAX_FRAME_BYTES: usize = 1024 * 1024;

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
pub fn pump_inner_to_agent<R: BufRead>(mut inner: R, agent: Arc<Mutex<Stdout>>) {
    while let Ok(Some(line)) = read_bounded_line(&mut inner, MAX_FRAME_BYTES) {
        write_locked(&agent, &line);
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
    while let Ok(Some(line)) = read_bounded_line(&mut agent_in, MAX_FRAME_BYTES) {
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
        let method = frame.get("method").and_then(|m| m.as_str()).unwrap_or("");
        if method != "tools/call" {
            let _ = writeln!(inner, "{line}");
            let _ = inner.flush();
            continue;
        }
        let id = frame.get("id").cloned().unwrap_or(serde_json::Value::Null);
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
