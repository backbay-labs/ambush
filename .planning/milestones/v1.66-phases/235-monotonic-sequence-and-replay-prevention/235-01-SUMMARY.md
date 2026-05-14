# Phase 235 Summary

Completed: 2026-04-13

- Every signed learned-state artifact now carries a monotonic `sequence` inside the signed statement.
- Behavioral baseline, Sphinx graph, evolution population, and evolution episode stores all persist the newest accepted sequence beside the signed artifact.
- Restore and reopen paths now reject replayed older state once a newer accepted sequence exists for that stream.
- Added shared signed-state replay tests plus store-level replay tests for behavioral baseline, Sphinx graph, population state, and episode reports.
