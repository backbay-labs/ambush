---
phase: 111-dedup-rate-limit-and-notification-dead-letter-replay
type: context
created_at: 2026-04-07
depends_on: [110]
---

# Phase 111 Context

## Goal

Add notification deduplication, per-channel rate limiting, dead-letter replay through the operator API, and the verification/docs needed to ship the milestone.

## Why This Phase Exists

Routing raw findings is not enough for production alerting. Bursty detections need deduplication, noisy channels need in-memory rate limiting, and suppressed alerts need durable dead-letter inspection plus replay so operators can recover visibility without losing the hot path.

## What Is Already True

- `DeadLetterJournal` already persists JSONL failure records for resilient response adapters.
- The operator HTTP surface already authenticates and exposes repo-owned runtime and artifact routes under one local control plane.
- `Severity`, `ThreatClass`, and `strategy_id` already provide stable keys for deduplication.
- `v1.35` added a production runbook and lifecycle verification pattern that this milestone can extend for delivery-specific docs and closeout.

## Constraints

- Deduplication and rate limiting must stay in memory and bounded; no external queueing system belongs in this milestone.
- Suppressed alerts must remain inspectable and replayable without introducing a second unauthenticated API surface.
- The operator API should replay the original stored notification payload instead of rebuilding a different message shape.
- Milestone closeout still requires focused verification, docs, and planning sync after the runtime work lands.

## Decisions

- Deduplication will key on `strategy_id` plus `ThreatClass`, with a shared configurable `dedup_window_ms`.
- Per-channel rate limiting will record suppression into a channel-specific `DeadLetterJournal` entry with the stored notification payload.
- The protected operator surface will expose list and replay operations under `/v1/notifications/dead-letter/{channel}`.
- Documentation and milestone verification should land in this phase so `v1.36` closes with its delivery and operational surfaces aligned.

## Phase Direction

- Implement dedup, rate limiting, and journal replay first, then add the operator API and docs/verification closeout.
- Keep replay scoped to previously suppressed notifications only; it should not become a general arbitrary message send surface.
