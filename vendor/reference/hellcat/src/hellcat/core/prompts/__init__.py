"""
Prompt engine for Hellcat operator prompt building.

Loads prompt templates, processes @include() directives, interpolates
variables, and injects dynamic Hellcat context (TargetGraph state, prior
findings, evasion context, OPSEC constraints).
"""

from hellcat.core.prompts.engine import PromptEngine

__all__ = ["PromptEngine"]
