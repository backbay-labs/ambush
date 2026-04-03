"""
Proof validation subsystem for Hellcat.

Provides the L1-L4 evidence gate pipeline that validates security
findings from operator executions before recording them to the
TargetGraph.
"""

from hellcat.offensive.proof.evidence import (
    EVIDENCE_REQUIREMENTS,
    EvidenceLevel,
    EvidenceRequirement,
    ReproductionResult,
    SecurityProof,
)
from hellcat.offensive.proof.reproducer import ExploitReproducer, ReproducerConfig
from hellcat.offensive.proof.validator import (
    GateResult,
    ProofValidator,
    ValidationResult,
)

__all__ = [
    "EVIDENCE_REQUIREMENTS",
    "EvidenceLevel",
    "EvidenceRequirement",
    "ExploitReproducer",
    "GateResult",
    "ProofValidator",
    "ReproducerConfig",
    "ReproductionResult",
    "SecurityProof",
    "ValidationResult",
]
