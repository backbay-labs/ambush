# Phase 35 Context

The runtime now has a reviewed proposal queue and a durable bridge into bounded canary, but proposal creation is still operator-invented. Replay regressions, verification drift, and rollout-memory gaps already exist as durable evidence; the next step is to turn those into repo-owned pressure signals that explain why a new proposal draft should exist.
