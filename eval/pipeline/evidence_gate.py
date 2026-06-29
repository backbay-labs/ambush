"""The evidence/oracle gate -- the heart of the slop-filter.

A cluster PASSES iff it has enough corroboration (support >= k) AND carries
machine-verifiable evidence that actually verified (a PoC that reproduced, a test
that passed, an independent Semgrep hit on the same sink). Lone, unverifiable
findings are QUARANTINED as suspected slop -- not silently dropped -- so the count
of quarantined slop is itself a measurable product behavior (the demo's right column).
"""

from __future__ import annotations

from config import DEFAULT_K
from schema import Cluster


def apply_gate(
    clusters: list[Cluster],
    k: int = DEFAULT_K,
    require_evidence: bool = True,
) -> list[Cluster]:
    """Mark each cluster passed_gate / quarantined in place and return the list.

    PASS  = support >= k AND (not require_evidence OR has verifying evidence)
    A cluster that fails only the evidence test but is otherwise lone/weak is
    flagged quarantined (suspected slop).
    """
    for c in clusters:
        enough_support = c.support >= k
        verified = (not require_evidence) or c.has_verifying_evidence()
        c.passed_gate = enough_support and verified
        c.quarantined = (not c.passed_gate) and (not verified or c.support < k)
    return clusters


def passed(clusters: list[Cluster]) -> list[Cluster]:
    return [c for c in clusters if c.passed_gate]


def quarantined(clusters: list[Cluster]) -> list[Cluster]:
    return [c for c in clusters if c.quarantined]
