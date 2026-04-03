"""Tom archetype — governance agent.

Enforces policy, manages agent lifecycle, runs BFT consensus.
- Sets autonomy tiers for each archetype
- Validates receipts and evidence chains
- Manages rotating consensus committee (VRF-based)
- Veto authority on false-positive-prone strategies
- Posture state machine (normal -> alert -> incident)
"""
