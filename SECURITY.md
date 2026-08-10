# Security Policy

Ambush is security-critical infrastructure. It ingests production telemetry, authorizes
destructive response actions against live hosts, and signs the receipts that prove what it did.
We take vulnerabilities seriously and appreciate the work of researchers who report them
responsibly.

This document is the coordinated vulnerability disclosure policy. For the runtime trust model and
the boundaries the governance lane enforces, see [docs/CONSENSUS.md](docs/CONSENSUS.md) and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Reporting a vulnerability

Please report security vulnerabilities privately. Do not open a public issue, pull request, or
discussion for a suspected vulnerability.

Email **[security@backbay.io](mailto:security@backbay.io)** with the details. If you would like to
encrypt your report, say so in an initial message and we will arrange a secure channel.

Please include as much of the following as you can:

- A description of the vulnerability and its impact.
- The affected component or surface (for example a detector, the policy gate, the pheromone
  substrate, a telemetry bridge, a response adapter, or the receipt chain).
- Step-by-step reproduction instructions, including a minimal proof of concept where possible.
  A recorded scenario under `scenarios/` is the clearest possible repro.
- The version, commit, or release you tested against, and your environment.
- Any suggested mitigation or fix, if you have one.

## What we consider high severity

The following classes get priority triage, because each one breaks a guarantee the runtime is
built to make:

- **Authorization bypass.** Any path that executes a destructive action without a valid signed
  governance receipt, or that survives dispatcher revalidation with a forged, replayed, or
  expired one.
- **Receipt forgery or omission.** Any way to produce a receipt the runtime did not sign, to alter
  one after the fact without detection, or to execute an action that leaves no receipt.
- **Identity admission bypass.** Any way for an unadmitted identity to join the dispatcher, deposit
  trusted pheromones, or participate in governance.
- **Fail-open behavior.** Any input, config, or partition condition that causes the runtime to
  permit a destructive action it should have denied, including contingency-lease misuse and
  blast-radius cap evasion.
- **Detection evasion by construction.** Evasion that defeats a detector family generically rather
  than falling into a gap already declared in
  `rulesets/evasion/attack-technique-catalog.yaml`.
- **Telemetry-driven compromise.** Any crash, panic, resource exhaustion, or code execution
  reachable from attacker-influenced telemetry through a bridge or the ingest endpoint.

Declared coverage gaps in the evasion catalog are known and documented limitations, not
vulnerabilities. If you think a declared gap is materially worse than its stated rationale, tell
us and we will re-evaluate it.

## What to expect

- **Acknowledgement:** we aim to acknowledge your report within 3 business days.
- **Triage:** we aim to provide an initial assessment, including a severity estimate and whether
  we accept the report, within 10 business days.
- **Progress:** we will keep you informed as we work on a fix and will coordinate a disclosure
  timeline with you.
- **Credit:** with your permission, we are happy to credit you in the release notes or advisory.
  Let us know how you would like to be named, or if you prefer to remain anonymous.

We ask that you give us a reasonable opportunity to remediate an issue before any public
disclosure, and that you avoid privacy violations, data destruction, and service degradation while
researching.

## Supported versions

Ambush is pre-release. Security fixes are made against the latest release and the `main`
branch. We cannot guarantee backported fixes for older pre-release builds. Once the project
reaches a stable release line, this section will be updated with a concrete support window.

## Operating safely

If you run this in live-response mode, two settings carry most of the risk. Keep
`require_durable_live_response` set to `true`, so the runtime refuses to take destructive action
on a substrate that cannot survive a restart. Keep `policy.human_gate_severity` set to the lowest
severity your operations can absorb. Both are documented in
[docs/CONFIGURATION.md](docs/CONFIGURATION.md), and recovery procedure is in
[docs/DR-RUNBOOK.md](docs/DR-RUNBOOK.md).

## Safe harbor

We will not pursue or support legal action against researchers who, in good faith:

- make a reasonable effort to follow this policy,
- report through the private channel above,
- avoid privacy violations, data destruction, and interruption or degradation of services beyond
  what is necessary to demonstrate a vulnerability, and
- give us a reasonable time to remediate before any public disclosure.

Activity conducted consistent with this policy is considered authorized, and we will work with you
to understand and resolve the issue quickly. If in doubt about whether a specific test is
acceptable, contact us first at [security@backbay.io](mailto:security@backbay.io).
