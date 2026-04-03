# Phase 32 Context

The runtime now has durable evolution proposals with proof status and operator review state, but `accepted_for_canary` is only a label. Operators still need to manually restate experiment, verification, and shadow metadata when moving from queue review into the existing canary lane.

This phase creates the missing artifact bridge: a queue-to-canary handoff packet that binds one accepted proposal to one passed shadow artifact and preserves all rollout-relevant references in one durable record.
