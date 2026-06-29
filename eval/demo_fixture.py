"""Synthetic dataset for `python run_eval.py --demo` and for tests.

Three tasks: two real planted vulns and one Tier-D negative control. The lane scripts
are rigged to demonstrate the harness's whole point:
 - heterogeneous lanes corroborate the TRUE vulns with verifying PoCs (A4 passes),
 - a homogeneous (all-Claude) panel PROMOTES a correlated false positive on the
   negative-control file -- the 'consensus is theater' nightmare the eval must catch,
   while the heterogeneous panel does not.
No API keys, fully deterministic.
"""

from __future__ import annotations

from schema import Finding, Evidence, Location, GroundTruth
from runner.lane_runner import Task, FakeLaneRunner


def _f(task, model, cwe, file, s, e, sink, verified=False):
    ev = [Evidence("taint_path", f"src->{sink}", "none")]
    if verified:
        ev.append(Evidence("poc", "curl '...'", "exploit_oracle", verified=True))
    return Finding(task_id=task, lane_id="tmp", model=model, title=cwe, cwe=cwe,
                   location=Location(file, s, e, sink=sink), evidence=ev, lane_confidence=0.85)


def demo_tasks_and_runner():
    tasks = [
        Task("t1-sqli", repo_path="corpora/_demo/t1", language="js"),
        Task("t2-xss", repo_path="corpora/_demo/t2", language="js"),
        Task("t3-negative", repo_path="corpora/_demo/t3", language="js"),
    ]
    ground_truth = {
        "t1-sqli": [GroundTruth("t1-sqli", "app/orders.js", "CWE-89", [(40, 46)], "injection")],
        "t2-xss": [GroundTruth("t2-xss", "app/profile.js", "CWE-79", [(10, 12)], "xss")],
        "t3-negative": [GroundTruth("t3-negative", "lib/safe.js", "", [], is_negative=True)],
    }

    M_CLAUDE, M_GPT, M_GEM, M_QWEN = "claude-opus-4-8", "gpt-5", "gemini-2.5-pro", "qwen-coder"
    script: dict[tuple[str, str, str], list[Finding]] = {}

    # --- TRUE vuln t1 (SQLi): corroborated across families with verifying PoCs ---
    for (model, persona) in [(M_CLAUDE, "injection"), (M_GPT, "injection")]:
        script[("t1-sqli", model, persona)] = [
            _f("t1-sqli", model, "CWE-89", "app/orders.js", 42, 44, "db.query", verified=True)]

    # --- TRUE vuln t2 (XSS): corroborated across families ---
    for (model, persona) in [(M_CLAUDE, "authz"), (M_GEM, "authz")]:
        script[("t2-xss", model, persona)] = [
            _f("t2-xss", model, "CWE-79", "app/profile.js", 11, 11, "res.send", verified=True)]

    # --- FALSE positive on the negative control, only from Claude/recon ---
    # HOMO_6 has two claude/recon lanes -> the false cluster reaches support 2 (PROMOTED).
    # HETERO_6 has NO claude/recon lane (its recon lanes are gpt & qwen) -> not promoted.
    script[("t3-negative", M_CLAUDE, "recon")] = [
        _f("t3-negative", M_CLAUDE, "CWE-89", "lib/safe.js", 20, 22, "db.query", verified=False)]

    return tasks, ground_truth, FakeLaneRunner(script)
