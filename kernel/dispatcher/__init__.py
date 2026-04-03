"""Agent dispatcher — lifecycle management, archetype routing, health monitoring.

Adapted from Cyntra kernel's dispatcher patterns:
- Spawn agents into isolated investigation contexts
- Route tasks to appropriate archetypes
- Monitor execution (timeouts, health checks)
- Collect results (findings + signed receipts)
"""
