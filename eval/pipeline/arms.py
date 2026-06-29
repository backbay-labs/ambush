"""The seven arms. Each composes the pipeline primitives into a comparable
"emitted set of clusters" for a single task, so every arm can be scored with the
same matcher/metrics. A0/A1 are baselines; A4 is the actual product pipeline.

Every arm returns list[Cluster]. For single-finding arms each finding is wrapped in
a singleton cluster so the matcher treats everything uniformly.
"""

from __future__ import annotations

from config import DEFAULT_K
from schema import Finding, Cluster
from pipeline.consensus import cluster as cluster_findings
from pipeline.evidence_gate import apply_gate, passed


def _singletons(findings: list[Finding]) -> list[Cluster]:
    out = []
    for f in findings:
        c = Cluster(key=f.bucket_key(), findings=[f], passed_gate=True)
        out.append(c)
    return out


def _best_lane(lane_findings: dict[str, list[Finding]]) -> list[Finding]:
    """A0's 'single best agent' = the lane that emits the most verifying evidence
    (ties broken by finding count). Deterministic given the inputs."""
    if not lane_findings:
        return []
    def score(items: list[Finding]) -> tuple[int, int]:
        return (sum(1 for f in items if f.has_verifying_evidence()), len(items))
    best = max(lane_findings.items(), key=lambda kv: score(kv[1]))
    return best[1]


def arm_A0(lane_findings: dict[str, list[Finding]], semgrep: list[Finding] | None = None) -> list[Cluster]:
    return _singletons(_best_lane(lane_findings))


def arm_A1(lane_findings: dict[str, list[Finding]], semgrep: list[Finding] | None = None) -> list[Cluster]:
    base = _best_lane(lane_findings) + (semgrep or [])
    # dedup via consensus so "strong agent + semgrep on the same sink" counts once
    return cluster_findings(base)


def arm_A2(lane_findings: dict[str, list[Finding]], semgrep: list[Finding] | None = None) -> list[Cluster]:
    allf = [f for items in lane_findings.values() for f in items]
    cs = cluster_findings(allf)
    for c in cs:
        c.passed_gate = True  # raw union emits everything
    return cs


def arm_A3(lane_findings: dict[str, list[Finding]], semgrep: list[Finding] | None = None,
           k: int = DEFAULT_K) -> list[Cluster]:
    allf = [f for items in lane_findings.values() for f in items]
    cs = cluster_findings(allf)
    apply_gate(cs, k=k, require_evidence=False)  # consensus only
    return passed(cs)


def arm_A4(lane_findings: dict[str, list[Finding]], semgrep: list[Finding] | None = None,
           k: int = DEFAULT_K) -> list[Cluster]:
    allf = [f for items in lane_findings.values() for f in items]
    cs = cluster_findings(allf)
    apply_gate(cs, k=k, require_evidence=True)   # THE PRODUCT
    return passed(cs)


def arm_A5(lane_findings: dict[str, list[Finding]], semgrep: list[Finding] | None = None) -> list[Cluster]:
    return _singletons(semgrep or [])


def arm_A6(lane_findings: dict[str, list[Finding]], semgrep: list[Finding] | None = None,
           k: int = DEFAULT_K) -> list[Cluster]:
    a4 = arm_A4(lane_findings, semgrep, k=k)
    # union with semgrep, re-clustered so overlapping sinks merge
    merged = [f for c in a4 for f in c.findings] + (semgrep or [])
    cs = cluster_findings(merged)
    for c in cs:
        c.passed_gate = True
    return cs


ARM_FUNCS = {
    "A0": arm_A0, "A1": arm_A1, "A2": arm_A2, "A3": arm_A3,
    "A4": arm_A4, "A5": arm_A5, "A6": arm_A6,
}


def run_arm(name: str, lane_findings: dict[str, list[Finding]],
            semgrep: list[Finding] | None = None, **kw) -> list[Cluster]:
    fn = ARM_FUNCS[name]
    try:
        return fn(lane_findings, semgrep, **kw)
    except TypeError:
        return fn(lane_findings, semgrep)
