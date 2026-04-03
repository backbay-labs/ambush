"""Quality gate validation.

Runs quality gates, compares candidates, vote selection.
"""

from cyntra.core.verifier.verifier import (
    VerificationResult,
    Verifier,
)

__all__ = [
    "Verifier",
    "VerificationResult",
]
