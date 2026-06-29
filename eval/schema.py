"""The structured Finding schema -- this IS the product spec.

Today Ambush lanes write freeform `findings/<id>.md` and `consolidate()` merely
concatenates them (src/main/swarm/swarm-orchestrator.ts:286). This eval defines the
structured per-finding JSONL that lanes must additionally emit, the consensus key,
and the evidence model. The schema validated here becomes the spec for the product's
real `Consolidate` pipeline.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

from config import family_of

# --- CWE equivalence classes -----------------------------------------------------
# Matching is by *class*, not exact CWE, because a lane may report CWE-89 where the
# label says CWE-943 (both injection). Keep this conservative and auditable.
_CWE_CLASSES: dict[str, set[str]] = {
    "injection": {"CWE-89", "CWE-943", "CWE-564", "CWE-90", "CWE-91", "CWE-943"},
    "command-injection": {"CWE-78", "CWE-77", "CWE-88"},
    "xss": {"CWE-79", "CWE-80", "CWE-83"},
    "path-traversal": {"CWE-22", "CWE-23", "CWE-36", "CWE-73"},
    "deserialization": {"CWE-502"},
    "ssrf": {"CWE-918"},
    "auth": {"CWE-287", "CWE-306", "CWE-862", "CWE-863", "CWE-285"},
    "crypto": {"CWE-327", "CWE-328", "CWE-326", "CWE-916"},
    "memory": {"CWE-119", "CWE-120", "CWE-125", "CWE-787", "CWE-416", "CWE-415", "CWE-476"},
    "secrets": {"CWE-798", "CWE-321", "CWE-259"},
    "xxe": {"CWE-611"},
    "redirect": {"CWE-601"},
    "csrf": {"CWE-352"},
}
_CWE_TO_CLASS: dict[str, str] = {cwe: cls for cls, cwes in _CWE_CLASSES.items() for cwe in cwes}


def cwe_class(cwe: Optional[str]) -> str:
    """Normalize a CWE id to its equivalence class; unknown CWEs map to themselves."""
    if not cwe:
        return "unknown"
    cwe = cwe.strip().upper()
    if not cwe.startswith("CWE-"):
        cwe = "CWE-" + cwe.lstrip("CWE").lstrip("-")
    return _CWE_TO_CLASS.get(cwe, cwe)


def normalize_path(path: str) -> str:
    """Normalize a file path for cross-lane comparison (lowercase, forward slashes,
    strip leading ./ and a leading repo root segment is NOT stripped on purpose)."""
    p = path.strip().replace("\\", "/").lstrip("./")
    p = re.sub(r"/+", "/", p)
    return p.lower()


@dataclass
class Location:
    file: str
    start_line: int = 0
    end_line: int = 0
    symbol: Optional[str] = None
    sink: Optional[str] = None

    def overlaps(self, other: "Location", tol: int) -> bool:
        if normalize_path(self.file) != normalize_path(other.file):
            return False
        a0, a1 = min(self.start_line, self.end_line), max(self.start_line, self.end_line)
        b0, b1 = min(other.start_line, other.end_line), max(other.start_line, other.end_line)
        # ranges overlap if expanded by tol they intersect
        return (a0 - tol) <= b1 and (b0 - tol) <= a1


@dataclass
class Evidence:
    type: str                       # poc | taint_path | test | sast_corro | citation
    value: str
    verifier: str = "none"          # exploit_oracle | pytest | jest | semgrep | none
    verified: Optional[bool] = None  # did the verifier actually confirm it? None = not run


@dataclass
class Finding:
    task_id: str
    lane_id: str
    model: str
    title: str
    cwe: str
    location: Location
    severity: str = "medium"
    evidence: list[Evidence] = field(default_factory=list)
    data_flow: Optional[dict[str, Any]] = None
    lane_confidence: float = 0.0
    raw_md_ref: Optional[str] = None
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    @property
    def family(self) -> str:
        return family_of(self.model)

    @property
    def cwe_klass(self) -> str:
        return cwe_class(self.cwe)

    def bucket_key(self) -> tuple[str, str, str]:
        """The coarse consensus identity (file, cwe-class, sink-or-symbol). Line
        overlap is checked separately so nearby reports of the same bug cluster."""
        sos = (self.location.sink or self.location.symbol or "").strip().lower()
        return (normalize_path(self.location.file), self.cwe_klass, sos)

    def has_verifying_evidence(self) -> bool:
        from config import VERIFYING_VERIFIERS
        return any(
            e.verifier in VERIFYING_VERIFIERS and e.verified is True for e in self.evidence
        )


@dataclass
class GroundTruth:
    task_id: str
    file: str
    cwe: str
    patched_hunks: list[tuple[int, int]] = field(default_factory=list)
    vuln_class: Optional[str] = None
    symbol: Optional[str] = None
    is_negative: bool = False        # Tier-D negative control: correct answer is "no finding"

    @property
    def cwe_klass(self) -> str:
        return cwe_class(self.cwe)


@dataclass
class Cluster:
    """A corroboration cluster of findings sharing a consensus key."""
    key: tuple[str, str, str]
    findings: list[Finding] = field(default_factory=list)
    passed_gate: bool = False
    quarantined: bool = False
    label: Optional[str] = None      # set by the matcher: TP | FP | near_miss

    @property
    def support(self) -> int:
        return len({f.lane_id for f in self.findings})

    @property
    def family_support(self) -> int:
        return len({f.family for f in self.findings})

    @property
    def representative(self) -> Finding:
        # the finding with the most verifying evidence, then highest confidence
        return max(
            self.findings,
            key=lambda f: (sum(1 for e in f.evidence if e.verified), f.lane_confidence),
        )

    def has_verifying_evidence(self) -> bool:
        return any(f.has_verifying_evidence() for f in self.findings)


# --- (de)serialization -----------------------------------------------------------
def finding_from_dict(d: dict[str, Any]) -> Finding:
    loc = d.get("location", {}) or {}
    ev = [Evidence(**e) for e in d.get("evidence", [])]
    return Finding(
        task_id=d["task_id"],
        lane_id=d["lane_id"],
        model=d["model"],
        title=d.get("title", ""),
        cwe=d.get("cwe", ""),
        location=Location(
            file=loc.get("file", ""),
            start_line=int(loc.get("start_line", 0) or 0),
            end_line=int(loc.get("end_line", 0) or 0),
            symbol=loc.get("symbol"),
            sink=loc.get("sink"),
        ),
        severity=d.get("severity", "medium"),
        evidence=ev,
        data_flow=d.get("data_flow"),
        lane_confidence=float(d.get("lane_confidence", 0.0) or 0.0),
        raw_md_ref=d.get("raw_md_ref"),
        finding_id=d.get("finding_id", str(uuid.uuid4())),
    )


def finding_to_dict(f: Finding) -> dict[str, Any]:
    return asdict(f)


def load_findings_jsonl(path: str) -> list[Finding]:
    out: list[Finding] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(finding_from_dict(json.loads(line)))
    return out


def dump_findings_jsonl(findings: list[Finding], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for f in findings:
            fh.write(json.dumps(finding_to_dict(f)) + "\n")
