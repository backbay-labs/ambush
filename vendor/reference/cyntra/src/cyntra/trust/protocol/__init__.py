"""
Aegis Net verification protocol.

Provides:
- Task protocol: OPEN -> CLAIMED -> SUBMITTED -> FINALIZED state machine
- Work products: Tier-dependent verification deliverables
- Quality control: Random re-verification with mismatch penalties
- Challenges: Challenge economics and flow
"""

from cyntra.trust.protocol.challenges import (
    Challenge,
    ChallengeConfig,
    ChallengeRegistry,
    ChallengeStatus,
)
from cyntra.trust.protocol.qc import (
    MismatchType,
    QCResult,
    QualityController,
    ReVerificationConfig,
)
from cyntra.trust.protocol.task_protocol import (
    TaskRegistry,
    TaskState,
    TaskStateError,
    Verdict,
    VerdictOutcome,
    VerificationTask,
)
from cyntra.trust.protocol.work_products import (
    GateReplayResult,
    Tier0WorkProduct,
    Tier1WorkProduct,
    Tier2WorkProduct,
    WorkProductValidator,
)

__all__ = [
    # Task protocol
    "TaskState",
    "VerificationTask",
    "Verdict",
    "VerdictOutcome",
    "TaskRegistry",
    "TaskStateError",
    # Work products
    "Tier0WorkProduct",
    "Tier1WorkProduct",
    "Tier2WorkProduct",
    "GateReplayResult",
    "WorkProductValidator",
    # QC
    "ReVerificationConfig",
    "QualityController",
    "QCResult",
    "MismatchType",
    # Challenges
    "ChallengeConfig",
    "Challenge",
    "ChallengeStatus",
    "ChallengeRegistry",
]
