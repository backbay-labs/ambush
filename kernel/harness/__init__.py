"""Swarm harness — the runtime that wires everything together.

Not a framework you assemble; a harness you extend.
Provides isolation, transport, verification, and coordination
out of the box, with extension points for custom detection logic.

Middleware pipeline (ordered):
1. IdentityVerification    (Ed25519 delegation token)
2. TierAuthorization       (autonomy level enforcement)
3. PheromoneInjection      (load relevant NATS trails)
4. ContextCompression      (token-aware summarization)
5. GuardPipeline           (ClawdStrike guard evaluation)
6. ToolBoundary            (action-specific access control)
7. ConsensusGate           (BFT for response actions)
8. EvidenceCollection      (receipt signing, audit trail)
9. EvolutionTracking       (strategy mutation logging)
"""
