from schema import Finding, Location, Evidence, Cluster
from pipeline.evidence_gate import apply_gate, passed, quarantined


def finding(lane, model, verified):
    ev = [Evidence("taint_path", "x", "none")]
    if verified:
        ev.append(Evidence("poc", "curl", "exploit_oracle", verified=True))
    return Finding(task_id="t", lane_id=lane, model=model, title="x", cwe="CWE-89",
                   location=Location("a.js", 1, 2, sink="q"), evidence=ev)


def test_pass_requires_support_and_verified_evidence():
    c = Cluster(key=("a.js", "injection", "q"),
                findings=[finding("l1", "claude", True), finding("l2", "gpt-5", True)])
    apply_gate([c], k=2, require_evidence=True)
    assert c.passed_gate and not c.quarantined


def test_lone_unverified_is_quarantined_not_passed():
    c = Cluster(key=("a.js", "injection", "q"), findings=[finding("l1", "claude", False)])
    apply_gate([c], k=2, require_evidence=True)
    assert not c.passed_gate
    assert c.quarantined  # suspected slop, shown in the demo's right column


def test_corroborated_but_unverified_blocked_by_evidence_gate():
    # support is enough, but nothing machine-verified -> A4 must NOT pass it
    c = Cluster(key=("a.js", "injection", "q"),
                findings=[finding("l1", "claude", False), finding("l2", "claude", False)])
    apply_gate([c], k=2, require_evidence=True)
    assert not c.passed_gate


def test_consensus_only_ignores_evidence():
    c = Cluster(key=("a.js", "injection", "q"),
                findings=[finding("l1", "claude", False), finding("l2", "gpt-5", False)])
    apply_gate([c], k=2, require_evidence=False)  # A3 behavior
    assert c.passed_gate
