"""Semgrep arm: run Semgrep and map its SARIF output into the Finding schema so the
static-analyzer baselines (A1, A5, A6) are scored by the identical matcher/metrics.

The SARIF->Finding mapping is deterministic and unit-tested; the subprocess call is
guarded so the module imports without semgrep installed. Match the Semgrep config to
the corpus language (strong on JS/TS/Py, weak on C) -- see corpora/README.md.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

from schema import Finding, Evidence, Location

# CWE often appears in rule metadata as "CWE-89: ..." -- pull the id out.
import re
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


def sarif_to_findings(sarif: dict[str, Any], task_id: str) -> list[Finding]:
    """Map a SARIF document (semgrep --sarif) to Finding objects.

    Each SARIF result becomes a Finding with a verified `sast_corro` evidence item
    (Semgrep flagged it, so the corroboration is real for gate purposes)."""
    out: list[Finding] = []
    runs = sarif.get("runs", [])
    for run in runs:
        rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            rule_id = res.get("ruleId", "semgrep")
            cwe = _extract_cwe(res, rules.get(rule_id, {}))
            for loc in res.get("locations", []) or [{}]:
                phys = loc.get("physicalLocation", {})
                art = phys.get("artifactLocation", {})
                region = phys.get("region", {})
                out.append(Finding(
                    task_id=task_id,
                    lane_id="semgrep",
                    model="semgrep",
                    title=res.get("message", {}).get("text", rule_id)[:160],
                    cwe=cwe or "",
                    location=Location(
                        file=art.get("uri", ""),
                        start_line=int(region.get("startLine", 0) or 0),
                        end_line=int(region.get("endLine", region.get("startLine", 0)) or 0),
                        sink=rule_id,
                    ),
                    severity=_sev(res.get("level", "warning")),
                    evidence=[Evidence(type="sast_corro", value=rule_id,
                                       verifier="semgrep", verified=True)],
                    lane_confidence=0.7,
                ))
    return out


def _extract_cwe(result: dict, rule: dict) -> str:
    blobs = [json.dumps(result.get("properties", {})), json.dumps(rule.get("properties", {})),
             rule.get("fullDescription", {}).get("text", "") if isinstance(rule.get("fullDescription"), dict) else ""]
    for b in blobs:
        m = _CWE_RE.search(b or "")
        if m:
            return m.group(0).upper()
    return ""


def _sev(level: str) -> str:
    return {"error": "high", "warning": "medium", "note": "low"}.get(level, "medium")


def run_semgrep(repo_path: str, configs: tuple[str, ...] = ("p/default", "p/owasp-top-ten"),
                task_id: str = "") -> list[Finding]:
    """Invoke semgrep and return Findings. Requires `semgrep` on PATH; returns [] with a
    clear message if it is unavailable (so arms degrade rather than crash)."""
    cmd = ["semgrep", "scan", "--sarif", "--quiet"]
    for c in configs:
        cmd += ["--config", c]
    cmd.append(repo_path)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:  # pragma: no cover
        print(f"[semgrep_arm] semgrep unavailable or timed out: {e}")
        return []
    if not proc.stdout.strip():
        return []
    return sarif_to_findings(json.loads(proc.stdout), task_id or repo_path)
