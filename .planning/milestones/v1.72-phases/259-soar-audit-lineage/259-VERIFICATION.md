# Phase 259 Verification

status: passed

## Commands

- `CARGO_TARGET_DIR=target-v172-soar cargo test -p swarm-runtime --lib soar_verdict -- --nocapture`
- `CARGO_TARGET_DIR=target-v172-soar cargo test -p swarm-spine file_store_appends_feedback_audit_and_persists_it --lib -- --nocapture`

## Verified Behaviors

- Accepted SOAR verdicts persist durable lineage on both incident audit entries and normalized false-positive measurements.
- Duplicate and incomplete SOAR verdicts fail closed, persist explicit rejection audit entries, and leave false-positive measurements unchanged.
- The incident store still persists and reloads feedback audit entries after the lineage field addition.
