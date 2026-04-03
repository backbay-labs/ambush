"""Multi-graph threat memory system.

MAGMA-inspired architecture with four orthogonal graphs:
- Temporal: attack timeline ordering
- Causal: kill chain / dependency relationships
- Entity: adversary infrastructure (IPs, domains, tools)
- Semantic: TTP pattern similarity (embedding-based)

Adapted from Cyntra's cognition/memory with threat-specific
memory types: pattern, failure, dynamic, context, playbook, frontier.

Backed by knowledge graph (pluggable: in-memory, SQLite, Neo4j/KuzuDB).
"""
