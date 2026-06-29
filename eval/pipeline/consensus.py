"""Consensus / corroboration clustering.

Clusters lane findings on the consensus key K = (normalized_file, cwe_class,
sink_or_symbol), merging findings whose line ranges overlap within +/- LINE_TOLERANCE.
`support` = distinct lanes in a cluster; `family_support` = distinct model families
(the anti-correlation lever -- 3 lanes from one family is NOT 3 independent votes).
"""

from __future__ import annotations

from config import LINE_TOLERANCE
from schema import Finding, Cluster


def cluster(findings: list[Finding], line_tolerance: int = LINE_TOLERANCE) -> list[Cluster]:
    """Group findings into corroboration clusters.

    Two findings join the same cluster iff they share the coarse bucket key
    (file, cwe-class, sink/symbol) AND at least one pair of their members' line
    ranges overlap within the tolerance. Within a bucket we do single-linkage
    agglomeration on line overlap so a chain of nearby reports merges.
    """
    buckets: dict[tuple[str, str, str], list[Finding]] = {}
    for f in findings:
        buckets.setdefault(f.bucket_key(), []).append(f)

    clusters: list[Cluster] = []
    for key, items in buckets.items():
        # single-linkage by line overlap
        groups: list[list[Finding]] = []
        for f in items:
            placed = False
            for g in groups:
                if any(f.location.overlaps(other.location, line_tolerance) for other in g):
                    g.append(f)
                    placed = True
                    break
            if not placed:
                groups.append([f])
        # merge groups that became transitively connected
        groups = _merge_connected(groups, line_tolerance)
        for g in groups:
            clusters.append(Cluster(key=key, findings=g))
    return clusters


def _merge_connected(groups: list[list[Finding]], tol: int) -> list[list[Finding]]:
    """Union groups whose any members overlap (handles ordering effects)."""
    merged = True
    while merged:
        merged = False
        for i in range(len(groups)):
            for j in range(i + 1, len(groups)):
                if _groups_overlap(groups[i], groups[j], tol):
                    groups[i].extend(groups[j])
                    del groups[j]
                    merged = True
                    break
            if merged:
                break
    return groups


def _groups_overlap(a: list[Finding], b: list[Finding], tol: int) -> bool:
    return any(x.location.overlaps(y.location, tol) for x in a for y in b)
