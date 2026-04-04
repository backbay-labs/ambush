# Phase 52 Context

## Goal

Expose packet-set and portfolio-history review flows through the existing repo-owned CLI.

## Inputs

- Packet-set and history artifacts now exist as durable repo-owned records.
- `swarmctl` already exposes the surrounding evolution, rollout, and governance-prep lanes.
- Operators needed stable-ID reload and list/filter review flows without opening raw JSON store files.

## Constraints

- Keep review surfaces CLI-first and repo-owned; HTTP/TUI remains deferred.
- Reuse the existing `swarmctl` global results-dir model so temp-dir and CI flows stay simple.
- Document how packet sets and history extend governance prep without introducing quorum voting.
