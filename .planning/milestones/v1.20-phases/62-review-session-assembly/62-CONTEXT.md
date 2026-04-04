# Phase 62 Context

- Goal: create durable local review sessions from existing evidence and promotion artifact stable IDs.
- Scope: repo-owned session artifact store, session assembly service, stable reload, and operator/CLI wiring.
- Constraints: stay on the existing bearer-auth boundary, reuse stable IDs, and avoid introducing rollout or governance writes.
