# SAFEP-05 — Apalache negative falsifiability

Each entry is a deliberately-broken variant of `PartitionContingency.tla` with
ONE guard removed, so Apalache reports a VIOLATION of a named invariant. This is
the TLA+ analog of the phase-285 negative registry (`negative_*.rs`): a property
you cannot break is a property you have not checked. `scripts/check-apalache-negatives.sh`
proves every clean invariant holds AND every broken variant violates (non-vacuous);
it fails if a "negative" no longer violates (the model drifted) or does not parse.

Each variant names the Rust runtime regression test that pins the SAME defect, so
the model and the code fail closed on the identical class of bug.

| Variant (`formal/tla/negative/…`) | Defect | Violated invariant | Runtime regression test |
|---|---|---|---|
| `NoCapGuard.tla` | `Redeem` drops the `redeemedCount < BlastRadiusCap` guard | `BlastRadiusNeverExceeded` | swarm-policy `formal_core::lease_redeem_fails_closed_on_mismatch_expiry_and_cap` |
| `NoExpiryGuard.tla` | `Redeem` drops the `clock < leaseExpiry` guard | `NoRedemptionAfterExpiry` | swarm-policy `formal_core::lease_can_redeem_denies_an_expired_lease` |
| `NoReceiptRequired.tla` | `IssueLease` sets `leaseHasReceipt := FALSE` | `OverrideRequiresReceipt` | swarm-agents `keyless_policy_reloaded_into_a_partition_refuses_persisted_leases` |
