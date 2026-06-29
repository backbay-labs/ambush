//! CEF (Common Event Format) text formatter for Ambush receipt audit events.
//!
//! CEF is the text SIEM line format shipped alongside the OCSF JSON mapper. This module formats
//! one CEF v0 event per [`SiemEvent`]. Transport is owned by the control plane's [`crate::SiemSink`].

use crate::event::{ReceiptOutcome, SiemEvent, epoch_millis};

/// Static device identity stamped into the CEF header.
#[derive(Debug, Clone)]
pub struct CefConfig {
    /// CEF `Device Vendor`.
    pub device_vendor: String,
    /// CEF `Device Product`.
    pub device_product: String,
    /// CEF `Device Version`.
    pub device_version: String,
}

impl Default for CefConfig {
    fn default() -> Self {
        Self {
            device_vendor: "Backbay Labs".to_string(),
            device_product: "Ambush".to_string(),
            device_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Formats [`SiemEvent`]s into CEF v0 text lines.
#[derive(Debug, Clone, Default)]
pub struct CefFormatter {
    config: CefConfig,
}

impl CefFormatter {
    /// Construct a formatter with the given device identity.
    #[must_use]
    pub fn new(config: CefConfig) -> Self {
        Self { config }
    }

    /// Format a batch of events into one CEF line each.
    #[must_use]
    pub fn format_events(&self, events: &[SiemEvent]) -> Vec<String> {
        events.iter().map(|event| self.format_event(event)).collect()
    }

    /// Format a single event into a CEF v0 line.
    #[must_use]
    pub fn format_event(&self, event: &SiemEvent) -> String {
        let outcome = event.outcome;
        let rt_ms = epoch_millis(event.timestamp()).unwrap_or(0);
        let signature = signature_id(event);
        let name = event_name(outcome);
        let severity = severity(outcome);
        let reason = event.reason().unwrap_or_else(|| outcome.as_str());

        let header = format!(
            "CEF:0|{}|{}|{}|{}|{}|{}|",
            escape_header(&self.config.device_vendor),
            escape_header(&self.config.device_product),
            escape_header(&self.config.device_version),
            escape_header(signature),
            escape_header(name),
            severity,
        );

        let mut extension: Vec<(&str, String)> = vec![
            ("rt", rt_ms.to_string()),
            ("msg", reason.to_string()),
            ("act", outcome.as_str().to_string()),
            ("outcome", event.result.clone()),
        ];
        if let Some(guard) = event.primary_guard() {
            extension.push(("guard", guard.to_string()));
        }
        extension.push(("dvc", event.provider().unwrap_or("ambush-engine").to_string()));
        extension.push(("cs1Label", "receipt_id".to_string()));
        extension.push(("cs1", event.uid()));
        extension.push(("cs2Label", "content_hash".to_string()));
        extension.push(("cs2", event.content_hash_hex()));
        extension.push(("cs3Label", "policy_hash".to_string()));
        extension.push(("cs3", event.policy_hash_hex().unwrap_or_default()));
        extension.push(("cs4Label", "ruleset".to_string()));
        extension.push(("cs4", event.ruleset().unwrap_or("").to_string()));
        extension.push(("cs5Label", "gate_id".to_string()));
        extension.push(("cs5", event.gate_id().unwrap_or("").to_string()));
        extension.push(("cs6Label", "engine_version".to_string()));
        extension.push(("cs6", event.engine_version().unwrap_or("").to_string()));
        extension.push(("verdictPassed", event.passed().to_string()));
        extension.push(("result", event.result.clone()));

        let extension = extension
            .into_iter()
            .map(|(key, value)| format!("{key}={}", escape_extension(&value)))
            .collect::<Vec<String>>()
            .join(" ");

        format!("{header}{extension}")
    }
}

fn signature_id(event: &SiemEvent) -> &str {
    match event.outcome {
        ReceiptOutcome::Allow => "ambush.allow",
        ReceiptOutcome::Deny => event
            .primary_guard()
            .or_else(|| event.gate_id())
            .unwrap_or("ambush.deny"),
    }
}

fn event_name(outcome: ReceiptOutcome) -> &'static str {
    match outcome {
        ReceiptOutcome::Allow => "Ambush gate allow",
        ReceiptOutcome::Deny => "Ambush gate deny",
    }
}

fn severity(outcome: ReceiptOutcome) -> u8 {
    // CEF severity is 0..=10.
    match outcome {
        ReceiptOutcome::Allow => 2,
        ReceiptOutcome::Deny => 8,
    }
}

fn escape_header(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '\\' => "\\\\".chars().collect::<Vec<char>>(),
            '|' => "\\|".chars().collect::<Vec<char>>(),
            '\n' | '\r' => " ".chars().collect::<Vec<char>>(),
            other => vec![other],
        })
        .collect()
}

fn escape_extension(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '\\' => "\\\\".chars().collect::<Vec<char>>(),
            '=' => "\\=".chars().collect::<Vec<char>>(),
            '\n' | '\r' => " ".chars().collect::<Vec<char>>(),
            other => vec![other],
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::test_support::{allow_receipt, deny_receipt};

    #[test]
    fn escapes_header_separator() {
        assert_eq!(escape_header("a|b"), "a\\|b");
    }

    #[test]
    fn escapes_extension_equals() {
        assert_eq!(escape_extension("a=b"), "a\\=b");
    }

    #[test]
    fn deny_receipt_renders_stable_cef_line() {
        let event = SiemEvent::from_receipt(deny_receipt());
        let cef = CefFormatter::default().format_event(&event);

        let zeros = "0".repeat(64);
        let expected = format!(
            "CEF:0|Backbay Labs|Ambush|0.1.0|ForbiddenPathGuard|Ambush gate deny|8|\
rt=1767225600000 msg=forbidden path act=deny outcome=Denied guard=ForbiddenPathGuard \
dvc=local cs1Label=receipt_id cs1=rcpt-deny-001 cs2Label=content_hash cs2={zeros} \
cs3Label=policy_hash cs3={zeros} cs4Label=ruleset cs4=code-agent cs5Label=gate_id \
cs5=path-guard cs6Label=engine_version cs6=0.1.0 verdictPassed=false result=Denied"
        );

        assert_eq!(cef, expected);
    }

    #[test]
    fn allow_receipt_renders_distinctly() {
        let allow = CefFormatter::default().format_event(&SiemEvent::from_receipt(allow_receipt()));
        let deny = CefFormatter::default().format_event(&SiemEvent::from_receipt(deny_receipt()));

        assert!(allow.contains("|ambush.allow|Ambush gate allow|2|"));
        assert!(allow.contains("act=allow"));
        assert!(allow.contains("outcome=Allowed"));
        assert!(allow.contains("verdictPassed=true"));
        assert!(!allow.contains("guard="));
        assert_ne!(allow, deny);
    }
}
