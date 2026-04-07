---
phase: 115-persistence-and-supply-chain-integration-proof
type: context
created_at: 2026-04-07
depends_on: [113, 114]
---

# Phase 115 Context

## Goal

Prove persistence and supply-chain findings end to end, update operator-facing docs, and close the milestone with verification evidence.

## Why This Phase Exists

The new detector families touch shared telemetry contracts, hot-path runtime selection, replay, canary, and promotion plumbing. The milestone should only close once synthetic telemetry proves the new payload variants can reach both detectors, emit ATT&CK-tagged findings, and convert cleanly into pheromone deposits.

## What Is Already True

- Existing integration tests already drive hot-path scenarios through supported detectors and assert on findings.
- `findings_to_deposits` is the shared deposit conversion path for detector findings.
- The ruleset and docs already enumerate supported detector strategies and profile overrides for the shipped families.

## Constraints

- Keep verification focused and deterministic with synthetic telemetry; no external telemetry source dependency is required.
- Preserve existing strategies while expanding supported detector lists and docs.
- Close the milestone only after tests and docs both reflect the new families.

## Decisions

- Use one integration-focused phase to prove both detector families rather than scattering the proof across the implementation phases.
- Update `rulesets/default.yaml` and configuration docs once the runtime strategy strings are final.
- Verification should include focused whisker tests plus runtime tests and strict clippy/build coverage.

## Phase Direction

- Add end-to-end synthetic telemetry coverage for persistence and supply-chain deposits.
- Update default config and docs for the new strategies and profiles.
- Finish with milestone verification and planning closeout.
