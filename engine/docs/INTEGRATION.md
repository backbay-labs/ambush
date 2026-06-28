# Swarm Team Six: Integration Status

Status: historical reference only.

This file preserves context from the earlier mixed Rust/Python integration plan.
It does not define the runtime that ships today.

## Why This Document Is Historical

The previous integration story assumed:

- a Python control plane
- a PyO3 bridge between warm-path Python agents and Rust hot-path components
- near-term runtime dependence on external upstream kernels

That is no longer the active contract. The live repo now ships a Rust-first
runtime under `crates/`, repo-owned YAML config under `rulesets/`, and active
agent, governance, evolution, and operator surfaces in the runtime itself.

## What Is Active Today Instead

- Telemetry ingress is owned by Rust runtime and bridge crates such as
  `swarm-ingest-tetragon`, `swarm-ingest-json`, and `swarm-ingest-sentinel`.
- Detection, stigmergic state, governance checks, response routing, and audit
  receipts all execute inside the Rust runtime contract.
- Async investigation, correlation, memory, deception, and evolution are
  runtime-owned optional lanes, enabled through repo-owned config.
- Upstream systems are sources of copied ideas and adapted code, not live
  runtime dependencies.

## Historical Material That Is Still Useful

Even though this document is not canonical, some themes remain useful as
background:

- ClawdStrike influenced receipts, signing, policy, and audit-envelope ideas.
- Cyntra influenced scheduler, dispatcher, and memory patterns.
- Hellcat influenced replay pressure, adversarial evaluation, and evolution
  terminology.

Those influences should now be read as inspiration for the Rust runtime, not as
evidence of a live cross-language architecture.

## Use These Documents For The Active Contract

- `docs/ARCHITECTURE.md` for the current runtime shape and lane boundaries
- `docs/AGENTS.md` for current runtime agent roles and config gates
- `docs/CONSENSUS.md` for active governance and receipt-backed response rules
- `docs/EVOLUTION.md` for the current evolution and rollout contract
- `docs/CONFIGURATION.md` for the live YAML surface and serve endpoints
- `docs/REFERENCE-STATUS.md` for the canonical active-versus-historical split
