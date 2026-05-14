# Phase 233 Context

Date: 2026-04-13
Requirement: `STATESIG-02`

## Goal

Sign persisted Sphinx knowledge-graph state and verify that signature on restore.

## Scope

- Make the signed snapshot the authoritative persisted Sphinx graph state.
- Keep `index.json`, `nodes/`, and `edges/` as derived mirrors.
- Bind restart to the trusted signer derived from the Sphinx signing key.

## Key Decisions

- The authoritative snapshot lives at `snapshot.signed.json`.
- A sidecar `snapshot.sequence.json` tracks the newest accepted graph sequence.
- Restart rejects tampered or replayed graph state before any memory is rehydrated.
