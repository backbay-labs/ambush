//! `ambush-siem [--format ocsf|ocsf-array|cef|hec] [receipts.jsonl]`
//!
//! Reads the governed-gate receipt log (JSONL of receipt-log envelopes, each carrying a full
//! swarm-crypto `SignedReceipt` under `receipt`; a bare receipt per line is also accepted) and
//! renders every verdict as SIEM events in OCSF 1.3.0 (default), CEF, or Splunk-HEC JSON to stdout.
//! The network send is intentionally NOT here — emitting to stdout lets the control plane (or a
//! cron) pipe the audit trail into any SIEM sink. Reads from stdin when no path is given.

use std::io::Read;

use swarm_crypto::SignedReceipt;
use swarm_siem::{ExportFormat, SiemEvent, render_batch};

fn fail(msg: &str) -> ! {
    eprintln!("ambush-siem: {msg}");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut format = ExportFormat::OcsfNdjson;
    let mut path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--format" => {
                i += 1;
                format = match args.get(i).map(String::as_str) {
                    Some("ocsf") | Some("ocsf-ndjson") => ExportFormat::OcsfNdjson,
                    Some("ocsf-array") => ExportFormat::OcsfJsonArray,
                    Some("cef") => ExportFormat::Cef,
                    Some("hec") => ExportFormat::HecJson,
                    other => fail(&format!("unknown --format {other:?} (ocsf|ocsf-array|cef|hec)")),
                };
            }
            other => path = Some(other.to_string()),
        }
        i += 1;
    }

    let raw = match &path {
        Some(p) => match std::fs::read_to_string(p) {
            Ok(s) => s,
            Err(e) => fail(&format!("cannot read {p}: {e}")),
        },
        None => {
            let mut s = String::new();
            if std::io::stdin().read_to_string(&mut s).is_err() {
                fail("cannot read stdin");
            }
            s
        }
    };

    let mut events = Vec::new();
    let mut skipped = 0u64;
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            skipped += 1;
            continue;
        };
        // Envelope carries the full SignedReceipt under "receipt"; accept a bare receipt too.
        let receipt_value = value.get("receipt").cloned().unwrap_or(value);
        match serde_json::from_value::<SignedReceipt>(receipt_value) {
            Ok(receipt) => events.push(SiemEvent::from_receipt(receipt)),
            Err(_) => skipped += 1,
        }
    }

    match render_batch(&events, format) {
        Ok(out) => {
            print!("{out}");
            if !out.ends_with('\n') {
                println!();
            }
            if skipped > 0 {
                eprintln!("ambush-siem: {} event(s) rendered, {skipped} line(s) skipped", events.len());
            }
        }
        Err(e) => fail(&format!("render failed: {e}")),
    }
}
