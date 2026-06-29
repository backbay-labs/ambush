//! Export orchestration: render a batch into a wire format, deliver it through a control-plane
//! [`SiemSink`], and park failures in a [`DeadLetterQueue`].
//!
//! swarm-siem performs no network I/O. The actual HTTP/TLS send is a trait the control plane
//! implements later; this module only renders bytes and routes delivery outcomes.

use serde_json::Value;

use crate::cef::CefFormatter;
use crate::dlq::{DeadLetterQueue, FailedExport};
use crate::error::SiemResult;
use crate::event::SiemEvent;
use crate::hec::format_hec_line;
use crate::ocsf::siem_event_to_ocsf;

/// Wire format for a rendered export batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// OCSF 1.3.0 Authorization events, newline-delimited JSON (one object per line).
    OcsfNdjson,
    /// OCSF 1.3.0 Authorization events, a single JSON array.
    OcsfJsonArray,
    /// CEF v0 text lines (one per event).
    Cef,
    /// Splunk-HEC-shaped JSON envelopes, newline-delimited (one object per line).
    HecJson,
}

impl ExportFormat {
    /// Stable identifier for the format (used as the DLQ `format` tag).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OcsfNdjson => "ocsf-ndjson",
            Self::OcsfJsonArray => "ocsf-json-array",
            Self::Cef => "cef",
            Self::HecJson => "hec-json",
        }
    }
}

/// The wire-delivery boundary implemented by the control plane.
///
/// swarm-siem hands a fully rendered batch body to [`SiemSink::send`]; the implementer owns the
/// HTTP client, TLS, auth, retries, and egress policy.
pub trait SiemSink {
    /// Stable name of this sink (for diagnostics).
    fn name(&self) -> &str;

    /// Deliver a rendered batch body.
    ///
    /// # Errors
    /// Returns [`crate::SiemError::Sink`] (or a serialization error surfaced from rendering)
    /// when the payload cannot be delivered.
    fn send(&mut self, payload: &str) -> SiemResult<()>;
}

/// Render a batch of events into a single wire body for `format`.
///
/// Line formats ([`ExportFormat::Cef`], [`ExportFormat::HecJson`], [`ExportFormat::OcsfNdjson`])
/// emit one line per event joined by `\n`; [`ExportFormat::OcsfJsonArray`] emits a single JSON
/// array.
///
/// # Errors
/// Returns [`crate::SiemError::Serialization`] when a JSON format fails to serialize.
pub fn render_batch(events: &[SiemEvent], format: ExportFormat) -> SiemResult<String> {
    match format {
        ExportFormat::Cef => {
            let formatter = CefFormatter::default();
            Ok(formatter
                .format_events(events)
                .join("\n"))
        }
        ExportFormat::HecJson => {
            let mut lines = Vec::with_capacity(events.len());
            for event in events {
                lines.push(format_hec_line(event)?);
            }
            Ok(lines.join("\n"))
        }
        ExportFormat::OcsfNdjson => {
            let mut lines = Vec::with_capacity(events.len());
            for event in events {
                lines.push(serde_json::to_string(&siem_event_to_ocsf(event))?);
            }
            Ok(lines.join("\n"))
        }
        ExportFormat::OcsfJsonArray => {
            let mapped: Vec<Value> = events.iter().map(siem_event_to_ocsf).collect();
            Ok(serde_json::to_string(&mapped)?)
        }
    }
}

/// Render `events` in `format`, deliver through `sink`, and park the payload in `dlq` on failure.
///
/// Returns the number of events delivered on success. On a render or send failure the rendered
/// body (when available) is pushed to the DLQ and the error is returned.
///
/// # Errors
/// Propagates rendering ([`crate::SiemError::Serialization`]) and delivery
/// ([`crate::SiemError::Sink`]) failures after recording them in the DLQ.
pub fn export_batch(
    events: &[SiemEvent],
    format: ExportFormat,
    sink: &mut dyn SiemSink,
    dlq: &mut DeadLetterQueue,
) -> SiemResult<usize> {
    if events.is_empty() {
        return Ok(0);
    }

    let body = match render_batch(events, format) {
        Ok(body) => body,
        Err(error) => {
            dlq.push(FailedExport {
                format: format.as_str().to_string(),
                body: String::new(),
                error: error.to_string(),
            });
            return Err(error);
        }
    };

    match sink.send(&body) {
        Ok(()) => Ok(events.len()),
        Err(error) => {
            dlq.push(FailedExport {
                format: format.as_str().to_string(),
                body,
                error: error.to_string(),
            });
            Err(error)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::error::SiemError;
    use crate::test_support::{allow_receipt, deny_receipt};

    struct CollectingSink {
        sent: Vec<String>,
    }

    impl SiemSink for CollectingSink {
        fn name(&self) -> &str {
            "collecting"
        }
        fn send(&mut self, payload: &str) -> SiemResult<()> {
            self.sent.push(payload.to_string());
            Ok(())
        }
    }

    struct FailingSink;

    impl SiemSink for FailingSink {
        fn name(&self) -> &str {
            "failing"
        }
        fn send(&mut self, _payload: &str) -> SiemResult<()> {
            Err(SiemError::Sink("connection refused".to_string()))
        }
    }

    fn events() -> Vec<SiemEvent> {
        vec![
            SiemEvent::from_receipt(deny_receipt()),
            SiemEvent::from_receipt(allow_receipt()),
        ]
    }

    #[test]
    fn ndjson_render_has_one_line_per_event() {
        let body = render_batch(&events(), ExportFormat::OcsfNdjson).unwrap();
        assert_eq!(body.lines().count(), 2);
        for line in body.lines() {
            let value: Value = serde_json::from_str(line).unwrap();
            assert_eq!(value["class_uid"], 3002);
        }
    }

    #[test]
    fn json_array_render_is_single_array() {
        let body = render_batch(&events(), ExportFormat::OcsfJsonArray).unwrap();
        let value: Value = serde_json::from_str(&body).unwrap();
        assert!(value.is_array());
        assert_eq!(value.as_array().map(Vec::len), Some(2));
    }

    #[test]
    fn successful_export_delivers_and_skips_dlq() {
        let mut sink = CollectingSink { sent: Vec::new() };
        let mut dlq = DeadLetterQueue::new(8);
        let delivered = export_batch(&events(), ExportFormat::Cef, &mut sink, &mut dlq).unwrap();
        assert_eq!(delivered, 2);
        assert_eq!(sink.sent.len(), 1);
        assert!(dlq.is_empty());
    }

    #[test]
    fn failed_send_lands_in_dlq() {
        let mut sink = FailingSink;
        let mut dlq = DeadLetterQueue::new(8);
        let result = export_batch(&events(), ExportFormat::Cef, &mut sink, &mut dlq);
        assert!(result.is_err());
        assert_eq!(dlq.len(), 1);
        let parked = dlq.drain();
        assert_eq!(parked[0].format, "cef");
        assert!(parked[0].error.contains("connection refused"));
        assert!(parked[0].body.contains("Ambush gate deny"));
    }

    #[test]
    fn empty_batch_is_noop() {
        let mut sink = FailingSink;
        let mut dlq = DeadLetterQueue::new(8);
        let delivered = export_batch(&[], ExportFormat::HecJson, &mut sink, &mut dlq).unwrap();
        assert_eq!(delivered, 0);
        assert!(dlq.is_empty());
    }
}
