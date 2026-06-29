//! swarm-siem — the SIEM export connector for Ambush attestation receipts.
//!
//! Carved — not copied — from the upstream `chio-siem` connector (Arc/Chio, Apache-2.0) and
//! rewritten around Ambush's own attestation primitive: a [`swarm_crypto::SignedReceipt`] (its
//! [`swarm_crypto::Verdict`] and [`swarm_crypto::Provenance`]). It maps a receipt into the
//! compliance lingua franca — an OCSF 1.3.0 Authorization event (`class_uid` 3002) — and also
//! serializes the CEF text line format and a generic Splunk-HEC-shaped JSON/webhook envelope.
//!
//! This crate is a **pure transform plus a tiny in-memory bounded DLQ**. It performs no network
//! I/O and opens no database: the upstream rusqlite source and the live HTTP senders are
//! intentionally out of scope. The actual wire delivery is expressed as the [`sink::SiemSink`]
//! trait that the control plane implements later; [`sink::export_batch`] renders a batch, hands
//! it to the sink, and parks any failed payload in the [`dlq::DeadLetterQueue`].
//!
//! ## Mapping summary (Ambush `SignedReceipt` -> OCSF)
//!
//! | swarm-crypto field            | OCSF field                                              |
//! |-------------------------------|---------------------------------------------------------|
//! | `receipt_id` / `content_hash` | `metadata.uid`, `api.request.uid`                       |
//! | `timestamp` (RFC-3339)        | `time` (epoch millis) + `time_dt` (ISO string)          |
//! | `verdict.passed`              | `status_id`/`status`, `severity_id`/`severity`          |
//! | `verdict.gate_id`             | `api.operation`, observable `ambush.gate.id`            |
//! | `provenance.provider`         | `api.service.name`                                      |
//! | `provenance.policy_hash`      | `policy.uid`, `actor.authorizations[*].policy.uid`      |
//! | `provenance.ruleset`          | `policy.name`                                           |
//! | `provenance.violations[*]`    | `enrichments[*]`, observables, `status_detail` (deny)   |
//! | full `SignedReceipt` JSON     | `raw_data`                                              |

pub mod cef;
pub mod dlq;
pub mod error;
pub mod event;
pub mod hec;
pub mod ocsf;
pub mod sink;

pub use cef::{CefConfig, CefFormatter};
pub use dlq::{DeadLetterQueue, FailedExport};
pub use error::{SiemError, SiemResult};
pub use event::{ReceiptOutcome, SiemEvent};
pub use hec::{DEFAULT_HEC_SOURCETYPE, format_hec_line, hec_envelope};
pub use ocsf::{
    OCSF_CLASS_UID, OCSF_PRODUCT_NAME, OCSF_SCHEMA_VERSION, receipt_to_ocsf, siem_event_to_ocsf,
};
pub use sink::{ExportFormat, SiemSink, export_batch, render_batch};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub(crate) mod test_support {
    //! Deterministic receipt fixtures shared across the crate's unit tests.

    use swarm_crypto::{
        Hash, Keypair, Provenance, Receipt, RECEIPT_SCHEMA_VERSION, SignedReceipt, Verdict,
        ViolationRef,
    };

    /// A signed DENY receipt with fully fixed fields (stable CEF/OCSF golden source).
    pub(crate) fn deny_receipt() -> SignedReceipt {
        let verdict = Verdict {
            passed: false,
            gate_id: Some("path-guard".to_string()),
            scores: None,
            threshold: None,
        };
        let provenance = Provenance {
            engine_version: Some("0.1.0".to_string()),
            provider: Some("local".to_string()),
            policy_hash: Some(Hash::zero()),
            ruleset: Some("code-agent".to_string()),
            violations: vec![ViolationRef {
                guard: "ForbiddenPathGuard".to_string(),
                severity: "high".to_string(),
                message: "forbidden path".to_string(),
                action: Some("blocked".to_string()),
            }],
        };
        let receipt = Receipt {
            version: RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_id: Some("rcpt-deny-001".to_string()),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            content_hash: Hash::zero(),
            verdict,
            provenance: Some(provenance),
            metadata: None,
        };
        let keypair = Keypair::generate();
        SignedReceipt::sign(receipt, &keypair).unwrap()
    }

    /// A signed ALLOW receipt with fully fixed fields.
    pub(crate) fn allow_receipt() -> SignedReceipt {
        let verdict = Verdict {
            passed: true,
            gate_id: Some("quality-gate".to_string()),
            scores: None,
            threshold: None,
        };
        let provenance = Provenance {
            engine_version: Some("0.1.0".to_string()),
            provider: Some("local".to_string()),
            policy_hash: Some(Hash::zero()),
            ruleset: Some("code-agent".to_string()),
            violations: vec![],
        };
        let receipt = Receipt {
            version: RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_id: Some("rcpt-allow-001".to_string()),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            content_hash: Hash::zero(),
            verdict,
            provenance: Some(provenance),
            metadata: None,
        };
        let keypair = Keypair::generate();
        SignedReceipt::sign(receipt, &keypair).unwrap()
    }
}
