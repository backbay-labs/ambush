# Phase 212 Plan 01 Summary

## Delivered

- Expanded the shared `ResponseAction` catalog in `crates/swarm-core/src/types.rs`
  from the original minimal set to fifteen concrete action types, adding
  DNS sinkhole, user-session termination, EDR scan trigger, firewall rule
  injection, file quarantine, process kill and suspend, user disable, password
  reset, and scheduled-task removal without introducing a parallel playbook
  action representation.
- Extended the policy and governance seams in
  `crates/swarm-core/src/config.rs`,
  `crates/swarm-policy/src/static_gate.rs`,
  `crates/swarm-runtime/src/dispatcher.rs`, and
  `crates/swarm-runtime/src/tom_agent.rs` so the expanded action catalog keeps
  the same typed validation, scope derivation, rate limiting, governance-receipt
  requirements, and destructive-action handling as the pre-existing response
  path.
- Broadened adapter execution support in `crates/swarm-response`: sandbox now
  executes the expanded catalog for dry-run and test flows, HTTP EDR now builds
  concrete payloads for the new host and network actions, and webhook now fails
  closed with an explicit failed receipt when asked to execute unsupported live
  actions instead of implicitly pretending success.
- Added focused proof in `crates/swarm-response/src/dispatch.rs` and
  `crates/swarm-runtime/tests/dispatch_integration.rs` that a new concrete
  action routes through the normal approval and execution lane and that an
  unsupported adapter returns a failed receipt through the same runtime-owned
  audit path.

## Notes

- Phase 212 intentionally stops at action-surface expansion. New actions return
  `UnsupportedAction` from rehearsal preview construction in
  `crates/swarm-runtime/src/service.rs` so Phase 213 can add typed blast-radius
  and rollback contracts without pretending that work is already complete.
- The action support matrix is now explicit: `sandbox` supports the expanded
  catalog for dry-run and bounded testing, `http_edr` supports the concrete host
  and network execution set, and `webhook` remains limited to escalation and
  decoy-style handoff actions.
