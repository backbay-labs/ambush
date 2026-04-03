"""Hunt scheduler — prioritizes investigations, computes ready set, finds critical path.

Adapted from Cyntra kernel's scheduling patterns:
- Ready-set computation (tasks with satisfied dependencies)
- Critical path analysis (longest chain weighted by threat severity)
- Lane packing (parallel investigations within resource budget)
- Memory-informed priority adjustment
"""
