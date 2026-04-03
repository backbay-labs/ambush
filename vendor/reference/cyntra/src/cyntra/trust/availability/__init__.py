"""
Data Availability layer for Aegis Net verification market.

Provides:
- AvailabilityObligation: Bundle availability requirements with bonds
- Multi-fetcher availability checking
- DA bond tracking and slash detection
- Fail-closed settlement blocking on DA failure
"""

from cyntra.trust.availability.checker import (
    MultiFetcherChecker,
    check_availability_obligation,
)
from cyntra.trust.availability.obligation import (
    AvailabilityCheck,
    AvailabilityObligation,
    AvailabilityStatus,
    DABondRegistry,
    FetcherResult,
)

__all__ = [
    "AvailabilityObligation",
    "AvailabilityCheck",
    "AvailabilityStatus",
    "FetcherResult",
    "DABondRegistry",
    "MultiFetcherChecker",
    "check_availability_obligation",
]
