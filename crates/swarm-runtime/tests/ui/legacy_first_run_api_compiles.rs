#![allow(deprecated)]

use std::path::PathBuf;
use swarm_ingest_runtime::control::{FirstRunWizardOptions, FirstRunWizardPaths};

fn main() {
    let root = PathBuf::from("legacy-approval-artifacts");
    let options = FirstRunWizardOptions {
        scenario_path: Some(PathBuf::from("scenario.json")),
        pace_ms: 25,
        voter_signing_key_env: "SWARM_VOTER_SIGNING_KEY".to_string(),
        evidence_signer_id: "legacy-evidence-signer".to_string(),
        evidence_signing_key_env: "SWARM_EVIDENCE_SIGNING_KEY".to_string(),
        paths: FirstRunWizardPaths {
            approval_verdict_results_dir: root.join("verdicts"),
            approval_receipt_pack_results_dir: root.join("receipt-packs"),
            approval_set_results_dir: root.join("sets"),
            approval_ledger_results_dir: root.join("ledgers"),
        },
    };

    assert_eq!(options.pace_ms, 25);
}
