"""Blue swarm agent archetypes.

Each archetype is a behavioral specialization with distinct
capabilities, tools, and autonomy tiers.

Archetypes:
- stalker: Investigation — follows leads, reconstructs timelines
- weaver:  Correlation — connects signals into attack narratives
- kitten:  Evolution — mutates and tests detection strategies
- sphinx:  Memory — maintains long-term threat knowledge graph
- calico:  Deception — deploys honeypots and canary tokens
- tom:     Governance — enforces policy, manages BFT consensus

Note: Whisker (detection) is implemented in Rust (crates/swarm-whisker)
for hot-path performance. It does not have a Python archetype.
"""
