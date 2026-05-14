# Phase 261 Context

## Goal

Restore recruited thresholds back toward baseline once escalation resolves so the runtime does not stay permanently over-sensitized.

## Repo State

- Phase 260 is intended to introduce positive-feedback recruitment on top of trusted pheromone state.
- The runtime already persists escalation, replay, and learned-state artifacts across restart.
- No inhibitory reset path currently narrows any recruited threshold state after an escalation clears.

## Phase Focus

- Emit or derive one bounded inhibitory signal from escalation resolution.
- Ensure the reset path composes with the same trusted state used for recruitment.
- Avoid leaving stale recruited thresholds behind after restart or replay.

## Verification Target

- Repo-owned tests proving resolved escalation reduces or clears recruitment pressure for the affected threat class.
- Restart or persistence proof showing the runtime does not retain a stale recruited state after resolution.
