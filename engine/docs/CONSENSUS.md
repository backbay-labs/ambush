# Governance And Consensus Contract

This document is part of the active contract set defined in
`docs/REFERENCE-STATUS.md`.

It describes the bounded governance model that ships today: local policy,
receipt-backed destructive response, registry-backed identity admission, and
fail-closed partition handling.

## Executive Summary

Swarm Team Six now ships a real governance lane, but it is deliberately narrow.

The runtime does not require consensus for every action. Most roles observe,
investigate, correlate, remember, or evolve without entering the governance
path. Governance applies when the runtime crosses a trust boundary:

- a destructive response action is about to execute
- a runtime identity must be trusted to participate
- partition-era emergency authority must be staged or redeemed

Everything else should remain outside the governance path unless a later
milestone explicitly promotes it.

## Governance Modes

The active runtime uses four governance modes.

| Mode | What it covers | What is required |
| --- | --- | --- |
| Observation | Detection, investigation, correlation, memory, deception, status publication | No governance receipt; standard signed deposits and audit only |
| Guarded response | Non-destructive response actions such as escalation or decoy deployment | Policy validation and ordinary audit trail |
| Receipt-backed response | Destructive response actions such as `BlockEgress`, `IsolateHost`, and `RevokeCredential` | Signed governance receipt, policy validation, and optional human approval |
| Partition contingency | Destructive response while quorum is partitioned | Valid staged contingency lease plus partition authorization and later reconciliation |
| Maintenance-only | Local operator review, export, replay, and bounded maintenance actions | Authenticated operator access and maintenance audit, but no widened destructive authority |

This is the shipped contract. It is not a general-purpose distributed control
plane.

## What Requires A Governance Receipt

The dispatcher currently requires a valid signed governance receipt for these
destructive actions:

- `BlockEgress`
- `IsolateHost`
- `RevokeCredential`

For those actions:

1. `Pouncer` asks `Tom` policy whether the action can proceed.
2. `Tom` either returns an approval receipt, returns a veto, or attaches a
   contingency lease if the request is occurring during partition.
3. The dispatcher re-validates the receipt before the request reaches the
   runtime response router.
4. The response adapter still runs under the existing policy and lease checks.

Non-destructive actions remain guarded and audited, but they do not require a
governance receipt in the current runtime.

## Approval And Receipt Lineage

The active receipt chain is:

1. An admitted runtime agent proposes or routes a response.
2. Policy validation evaluates the request and severity.
3. `Tom` governance either approves, vetoes, or stages partition-time fallback
   evidence.
4. The dispatcher verifies destructive-governance evidence before runtime
   routing.
5. Human approval applies when severity crosses `policy.human_gate_severity`.
6. Final execution and audit artifacts persist the request, decision, and
   outcome lineage.

This contract keeps one vocabulary across demo approval, live response, and
operator review: request, receipt, approval, audit, and evidence.

## Human Approval Boundary

Human approval is a separate boundary layered on top of receipt-backed
governance.

`policy.human_gate_severity` defines the severity at or above which destructive
actions are held for human confirmation even when the runtime has otherwise
authorized the request.

Current implications:

- a destructive request can be policy-authorized and still stop at the human
  gate
- human approval does not replace the governance receipt
- demo approval and live operator approval reuse the same bounded approval
  vocabulary rather than defining a second governance model

## Identity Admission Contract

Every runtime-owned agent identity follows the same admission path:

- keys persist under `identity.agent_key_dir`
- stable identities are derived from the Ed25519 public key
- registry snapshots and continuity proofs persist under
  `identity.registry_dir`
- unadmitted identities do not join the dispatcher or deposit trusted
  pheromones

Rotation is continuity-preserving rather than anonymous replacement. The active
contract is:

- identities are durable
- admission is explicit
- rotation preserves trust lineage
- retired keys remain available for historical verification

This is stronger than an in-memory allowlist and narrower than a full external
PKI or multi-tenant operator system.

## Identity Rotation And Verification

Rotation is part of the active contract, not a manual side note.

- `swarmctl identity rotate` preserves continuity from the retired key to the
  new key
- registry state retains enough historical material to verify older receipts and
  deposits
- governance and deposit validation fail closed for identities that are not
  admitted through the current registry state
- runtime registration and substrate admission both consume the same admitted
  identity set

## Governance Health States

The governance policy persists and reports four runtime states:

| State | Meaning |
| --- | --- |
| `healthy` | Quorum is available and partition-era activity is not active |
| `degraded` | Enough governors remain for quorum, but one or more are unhealthy |
| `partitioned` | Quorum is unavailable; destructive actions fail closed unless a valid contingency lease exists |
| `healing` | Quorum has returned and the runtime is reconciling partition-era activity |

These states are not abstract theory. They are persisted, emitted as runtime
events, and surfaced through `/healthz` and `/readyz`.

## Partition And Recovery Rules

The active partition contract is:

| State | Destructive response | Observability | Recovery expectation |
| --- | --- | --- | --- |
| `healthy` | Allowed through normal receipt-backed governance | Full health and runtime visibility | Stage bounded contingency leases for later emergency use |
| `degraded` | Still allowed if quorum remains available | Full visibility, degraded state reported | Repair unhealthy governors before the system trends into partition |
| `partitioned` | Denied unless a valid staged contingency lease authorizes the exact action | Full visibility remains available | Persist every authorized and unauthorized partition-era attempt |
| `healing` | Normal quorum is back, but partition-era activity is being reconciled | Full visibility plus reconciliation markers | Review reconciliation output before treating the incident as closed |

This rule is intentional:

- destructive authority fails closed when quorum disappears
- health, metrics, and operator visibility remain available
- contingency leases are narrow emergency exceptions
- healing is a first-class state, not an implicit return to healthy

## Contingency Lease Contract

Contingency leases are staged while the system is healthy and redeemed only
under partition.

The active contract is intentionally narrow:

- leases authorize only a specific destructive action kind
- leases may be scoped to one host or other action scope
- leases carry a blast-radius cap
- leases expire after a bounded TTL
- redemption is persisted for later reconciliation

Contingency leases are an emergency exception inside the existing governance
model. They are not an alternate control plane.

## Reconciliation Markers

When the runtime transitions from `partitioned` back toward quorum, it persists
and emits reconciliation artifacts that distinguish:

- partition-authorized actions
- unauthorized partition-era attempts
- the last reconciliation report identifier
- the latest partition-state transition time

Operators should treat these markers as part of the auditable response chain,
not as optional debug output.

## Observability And Operator Surfaces

Operators should expect governance state in these surfaces:

- `/healthz` and `/readyz` governance component details
- runtime events for partition transitions and reconciliation
- audit evidence attached to response execution
- persisted governance state on disk for restart-safe recovery
- reconciliation report identifiers and active contingency-lease counts in the
  serve-mode governance component

The platform and operator surfaces consume this governance data, but they do not
change the underlying authorization semantics.

## Config Keys That Define The Contract

The active governance contract is anchored by these repo-owned settings:

- `policy.human_gate_severity`
- `policy.lease_ttl_ms`
- `runtime.governance_degraded_tick_threshold`
- `runtime.partition_contingency_lease_ttl_ms`
- `runtime.partition_contingency_blast_radius_cap`
- `identity.agent_key_dir`
- `identity.registry_dir`
- `tls.*` and `platform_api.keys[*]` for the authenticated serve surfaces that
  expose governance state
- `operator_surface.*` for the bounded local operator and maintenance surface
  that inspects, but does not replace, governance evidence

Use `docs/CONFIGURATION.md` for field-level examples and endpoint notes.

## Explicit Boundaries

The active governance contract explicitly does not include:

- automatic governance over every swarm action
- internet-exposed or multi-tenant operator governance
- independent external consensus clusters beyond the bounded shipped runtime
- unrestricted partition-time destructive authority
- a second trust vocabulary separate from persisted identities, receipts, and
  approval artifacts

Use `docs/ARCHITECTURE.md` for the lane map and `docs/AGENTS.md` for current
Tom and Pouncer role boundaries.
