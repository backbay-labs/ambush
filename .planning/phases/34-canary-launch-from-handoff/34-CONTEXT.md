# Phase 34 Context

Once a handoff packet exists, operators should be able to launch the bounded canary lane without manually restating experiment, verification, or shadow inputs. That keeps the rollout path aligned with the reviewed queue artifact and removes copy-paste error from the canary entry step.

This phase exposes handoff reload and canary launch through `swarmctl` and preserves the resulting canary-run reference on the durable handoff record.
