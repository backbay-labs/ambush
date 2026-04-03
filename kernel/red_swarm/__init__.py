"""Red swarm — adversarial pressure engine adapted from Hellcat.

Provides the co-evolutionary arms race opponent for the blue swarm.
Red swarm operators probe, evade, and adapt; blue swarm detects,
investigates, and evolves. Both sides get smarter.

Adapted from Hellcat's:
- Attack operators (recon, injection, auth, evasion, etc.)
- OPSEC / noise monitoring
- TargetGraph (attack surface model)
- AttackPlanner (scoring, chain analysis)
- Proof validation gates (L1-L4)
- Prompt genome evolution (Pareto selection)
- AttackPatternDB (cross-engagement learning)
"""
