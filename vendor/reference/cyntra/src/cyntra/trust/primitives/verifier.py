"""Bundle and receipt verification utilities.

Provides verification of run directories/bundles including:
- Receipt JSON schema validation
- Hash recomputation and consistency checks
- Absolute path detection in attested artifacts
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from cyntra.trust.primitives.canonical_json import canonicalize as canonicalize_json


class VerificationSeverity(Enum):
    """Severity levels for verification issues."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class VerificationIssue:
    """A single verification issue found during bundle verification."""

    severity: VerificationSeverity
    category: str
    message: str
    file_path: str | None = None
    field: str | None = None
    expected: str | None = None
    actual: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "severity": self.severity.value,
            "category": self.category,
            "message": self.message,
        }
        if self.file_path:
            result["file_path"] = self.file_path
        if self.field:
            result["field"] = self.field
        if self.expected:
            result["expected"] = self.expected
        if self.actual:
            result["actual"] = self.actual
        return result


@dataclass
class VerificationResult:
    """Result of bundle verification."""

    valid: bool
    run_dir: str
    issues: list[VerificationIssue] = field(default_factory=list)
    computed_hashes: dict[str, str] = field(default_factory=dict)
    receipt_hashes: dict[str, str | None] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "run_dir": self.run_dir,
            "issues": [issue.to_dict() for issue in self.issues],
            "computed_hashes": self.computed_hashes,
            "receipt_hashes": self.receipt_hashes,
            "error_count": sum(1 for i in self.issues if i.severity == VerificationSeverity.ERROR),
            "warning_count": sum(1 for i in self.issues if i.severity == VerificationSeverity.WARNING),
        }


# Load JSON schemas lazily
_SCHEMAS: dict[str, dict] = {}


def _get_schema(schema_name: str) -> dict:
    """Load JSON schema from kernel/schemas/cyntra/."""
    if schema_name not in _SCHEMAS:
        schema_dir = Path(__file__).parent.parent.parent.parent.parent / "schemas" / "cyntra"
        schema_path = schema_dir / schema_name
        if not schema_path.exists():
            raise FileNotFoundError(f"Schema not found: {schema_path}")
        with open(schema_path, encoding="utf-8") as f:
            _SCHEMAS[schema_name] = json.load(f)
    return _SCHEMAS[schema_name]


def _hash_file(path: Path) -> str:
    """Compute SHA256 hash of a file, returning 0x-prefixed hex."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return "0x" + hasher.hexdigest()


def _hash_json_canonical(data: dict) -> str:
    """Compute SHA256 hash of canonical JSON representation."""
    canonical = canonicalize_json(data)
    return "0x" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# Patterns for absolute path detection
_ABSOLUTE_PATH_PATTERNS = [
    re.compile(r'(?<=["\s,:\[])(/[a-zA-Z][a-zA-Z0-9_\-./]+)(?=["\s,:\]])'),  # Unix paths
    re.compile(r'(?<=["\s,:\[])[A-Za-z]:\\[^"]*(?=["\s,:\]])'),  # Windows paths
    re.compile(r'"(/Users/[^"]+)"'),  # macOS user paths
    re.compile(r'"(/home/[^"]+)"'),  # Linux user paths
    re.compile(r'"(/tmp/[^"]+)"'),  # Temp paths
    re.compile(r'"/var/[^"]+"'),  # Var paths
]


def _find_absolute_paths(content: str, file_path: str) -> list[VerificationIssue]:
    """Find absolute paths in file content."""
    issues: list[VerificationIssue] = []
    seen: set[str] = set()

    for pattern in _ABSOLUTE_PATH_PATTERNS:
        for match in pattern.finditer(content):
            path_str = match.group(1) if match.lastindex else match.group(0)
            path_str = path_str.strip('"')

            # Skip common false positives
            if path_str in seen:
                continue
            if path_str.startswith("/dev/") or path_str == "/":
                continue
            # Skip URL-like patterns
            if "://" in path_str:
                continue
            # Skip short paths that are likely not absolute file paths
            if len(path_str) < 5:
                continue

            seen.add(path_str)
            issues.append(VerificationIssue(
                severity=VerificationSeverity.WARNING,
                category="absolute_path",
                message=f"Absolute path found in attested artifact: {path_str}",
                file_path=file_path,
            ))

    return issues


def _validate_schema(
    data: dict,
    schema: dict,
    file_path: str,
    issues: list[VerificationIssue],
) -> bool:
    """Validate data against JSON schema (basic validation without jsonschema library)."""
    valid = True

    # Check required fields
    required = schema.get("required", [])
    for field_name in required:
        if field_name not in data:
            issues.append(VerificationIssue(
                severity=VerificationSeverity.ERROR,
                category="schema",
                message=f"Missing required field: {field_name}",
                file_path=file_path,
                field=field_name,
            ))
            valid = False

    # Check property types and patterns
    properties = schema.get("properties", {})
    for field_name, field_value in data.items():
        if field_name not in properties:
            if schema.get("additionalProperties") is False:
                issues.append(VerificationIssue(
                    severity=VerificationSeverity.WARNING,
                    category="schema",
                    message=f"Unknown field: {field_name}",
                    file_path=file_path,
                    field=field_name,
                ))
            continue

        field_schema = properties[field_name]
        field_type = field_schema.get("type")

        # Type checking
        if field_type == "string" and not isinstance(field_value, str):
            issues.append(VerificationIssue(
                severity=VerificationSeverity.ERROR,
                category="schema",
                message=f"Field {field_name} should be string, got {type(field_value).__name__}",
                file_path=file_path,
                field=field_name,
            ))
            valid = False
        elif field_type == "boolean" and not isinstance(field_value, bool):
            issues.append(VerificationIssue(
                severity=VerificationSeverity.ERROR,
                category="schema",
                message=f"Field {field_name} should be boolean, got {type(field_value).__name__}",
                file_path=file_path,
                field=field_name,
            ))
            valid = False
        elif field_type == "integer" and not isinstance(field_value, int):
            issues.append(VerificationIssue(
                severity=VerificationSeverity.ERROR,
                category="schema",
                message=f"Field {field_name} should be integer, got {type(field_value).__name__}",
                file_path=file_path,
                field=field_name,
            ))
            valid = False
        elif field_type == "object" and isinstance(field_value, dict):
            # Recursively validate nested objects
            nested_valid = _validate_schema(field_value, field_schema, file_path, issues)
            valid = valid and nested_valid

        # Pattern checking for strings
        if field_type == "string" and isinstance(field_value, str):
            pattern = field_schema.get("pattern")
            if pattern and not re.match(pattern, field_value):
                issues.append(VerificationIssue(
                    severity=VerificationSeverity.ERROR,
                    category="schema",
                    message=f"Field {field_name} does not match pattern {pattern}",
                    file_path=file_path,
                    field=field_name,
                    actual=field_value,
                ))
                valid = False

            # Enum checking
            enum_values = field_schema.get("enum")
            if enum_values and field_value not in enum_values:
                issues.append(VerificationIssue(
                    severity=VerificationSeverity.ERROR,
                    category="schema",
                    message=f"Field {field_name} must be one of {enum_values}",
                    file_path=file_path,
                    field=field_name,
                    actual=field_value,
                ))
                valid = False

    return valid


def verify_bundle(
    run_dir: Path,
    *,
    strict: bool = False,
) -> VerificationResult:
    """
    Verify a run directory/bundle for conformance.

    Performs:
    1. Receipt JSON schema validation (receipt.json and signed variant)
    2. Hash recomputation and consistency checks (manifest_hash, proof_hash, bundle_hash, ledger_root)
    3. Absolute path detection in attested artifacts

    Args:
        run_dir: Path to the run directory
        strict: If True, treat warnings as errors

    Returns:
        VerificationResult with issues and computed hashes
    """
    run_dir = Path(run_dir)
    issues: list[VerificationIssue] = []
    computed_hashes: dict[str, str] = {}
    receipt_hashes: dict[str, str | None] = {}

    if not run_dir.exists():
        issues.append(VerificationIssue(
            severity=VerificationSeverity.ERROR,
            category="structure",
            message=f"Run directory does not exist: {run_dir}",
        ))
        return VerificationResult(
            valid=False,
            run_dir=str(run_dir),
            issues=issues,
        )

    # Load and validate receipt.json
    receipt_path = run_dir / "receipt.json"
    receipt_data: dict | None = None

    if receipt_path.exists():
        try:
            with open(receipt_path, encoding="utf-8") as f:
                receipt_data = json.load(f)

            schema = _get_schema("run_receipt.schema.json")
            _validate_schema(receipt_data, schema, str(receipt_path), issues)

            # Extract artifact hashes from receipt
            artifacts = receipt_data.get("artifacts", {})
            receipt_hashes["manifest_hash"] = artifacts.get("manifest_hash")
            receipt_hashes["proof_hash"] = artifacts.get("proof_hash")
            receipt_hashes["bundle_hash"] = artifacts.get("bundle_hash")
            receipt_hashes["ledger_root"] = artifacts.get("ledger_root")

        except json.JSONDecodeError as e:
            issues.append(VerificationIssue(
                severity=VerificationSeverity.ERROR,
                category="schema",
                message=f"Invalid JSON in receipt.json: {e}",
                file_path=str(receipt_path),
            ))
    else:
        issues.append(VerificationIssue(
            severity=VerificationSeverity.ERROR,
            category="structure",
            message="receipt.json not found",
            file_path=str(receipt_path),
        ))

    # Check for signed receipt variant
    signed_receipt_path = run_dir / "signed_receipt.json"
    if signed_receipt_path.exists():
        try:
            with open(signed_receipt_path, encoding="utf-8") as f:
                signed_data = json.load(f)

            schema = _get_schema("signed_run_receipt.schema.json")
            _validate_schema(signed_data, schema, str(signed_receipt_path), issues)

        except json.JSONDecodeError as e:
            issues.append(VerificationIssue(
                severity=VerificationSeverity.ERROR,
                category="schema",
                message=f"Invalid JSON in signed_receipt.json: {e}",
                file_path=str(signed_receipt_path),
            ))

    # Recompute and verify manifest_hash
    manifest_path = run_dir / "manifest.json"
    if manifest_path.exists():
        computed_hashes["manifest_hash"] = _hash_file(manifest_path)

        if receipt_hashes.get("manifest_hash"):
            if computed_hashes["manifest_hash"] != receipt_hashes["manifest_hash"]:
                issues.append(VerificationIssue(
                    severity=VerificationSeverity.ERROR,
                    category="hash_mismatch",
                    message="manifest_hash mismatch",
                    file_path=str(manifest_path),
                    field="manifest_hash",
                    expected=receipt_hashes["manifest_hash"],
                    actual=computed_hashes["manifest_hash"],
                ))
    elif receipt_hashes.get("manifest_hash"):
        issues.append(VerificationIssue(
            severity=VerificationSeverity.ERROR,
            category="structure",
            message="manifest.json referenced in receipt but not found",
            file_path=str(manifest_path),
        ))

    # Recompute and verify proof_hash
    proof_path = run_dir / "proof.json"
    if proof_path.exists():
        computed_hashes["proof_hash"] = _hash_file(proof_path)

        if receipt_hashes.get("proof_hash"):
            if computed_hashes["proof_hash"] != receipt_hashes["proof_hash"]:
                issues.append(VerificationIssue(
                    severity=VerificationSeverity.ERROR,
                    category="hash_mismatch",
                    message="proof_hash mismatch",
                    file_path=str(proof_path),
                    field="proof_hash",
                    expected=receipt_hashes["proof_hash"],
                    actual=computed_hashes["proof_hash"],
                ))
    elif receipt_hashes.get("proof_hash"):
        issues.append(VerificationIssue(
            severity=VerificationSeverity.WARNING,
            category="structure",
            message="proof.json referenced in receipt but not found",
            file_path=str(proof_path),
        ))

    # Recompute and verify bundle_hash (from bundle_manifest.json)
    bundle_manifest_path = run_dir / "bundle_manifest.json"
    if bundle_manifest_path.exists():
        try:
            with open(bundle_manifest_path, encoding="utf-8") as f:
                bundle_manifest_data = json.load(f)
            computed_hashes["bundle_hash"] = _hash_json_canonical(bundle_manifest_data)

            if receipt_hashes.get("bundle_hash"):
                if computed_hashes["bundle_hash"] != receipt_hashes["bundle_hash"]:
                    issues.append(VerificationIssue(
                        severity=VerificationSeverity.ERROR,
                        category="hash_mismatch",
                        message="bundle_hash mismatch",
                        file_path=str(bundle_manifest_path),
                        field="bundle_hash",
                        expected=receipt_hashes["bundle_hash"],
                        actual=computed_hashes["bundle_hash"],
                    ))
        except json.JSONDecodeError as e:
            issues.append(VerificationIssue(
                severity=VerificationSeverity.ERROR,
                category="structure",
                message=f"Invalid JSON in bundle_manifest.json: {e}",
                file_path=str(bundle_manifest_path),
            ))
    elif receipt_hashes.get("bundle_hash"):
        issues.append(VerificationIssue(
            severity=VerificationSeverity.WARNING,
            category="structure",
            message="bundle_hash in receipt but bundle_manifest.json not found",
        ))

    # Recompute and verify ledger_root (from ledger.jsonl via merkle tree)
    ledger_path = run_dir / "ledger.jsonl"
    ledger_root_path = run_dir / "ledger_root.json"
    if ledger_path.exists():
        try:
            from cyntra.trust.ledger.events import LedgerEvent
            from cyntra.trust.primitives.merkle import EventMerkleTree

            events: list[LedgerEvent] = []
            with open(ledger_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        events.append(LedgerEvent.from_dict(data))
                    except Exception:
                        continue

            if events:
                tree = EventMerkleTree(events)
                computed_hashes["ledger_root"] = tree.root

                if receipt_hashes.get("ledger_root"):
                    if computed_hashes["ledger_root"] != receipt_hashes["ledger_root"]:
                        issues.append(VerificationIssue(
                            severity=VerificationSeverity.ERROR,
                            category="hash_mismatch",
                            message="ledger_root mismatch",
                            file_path=str(ledger_path),
                            field="ledger_root",
                            expected=receipt_hashes["ledger_root"],
                            actual=computed_hashes["ledger_root"],
                        ))
        except ImportError:
            # Merkle tree not available, skip ledger verification
            pass
    elif ledger_root_path.exists():
        # ledger_root.json exists but not ledger.jsonl - read stored root
        try:
            with open(ledger_root_path, encoding="utf-8") as f:
                stored_root = json.load(f).get("ledger_root")
            if stored_root:
                computed_hashes["ledger_root"] = stored_root
        except (json.JSONDecodeError, KeyError):
            pass

    # Check for absolute paths in attested artifacts
    attested_files = [
        "manifest.json",
        "proof.json",
        "bundle_manifest.json",
        "bundle_pointer.json",
        "context.json",
        "receipt.json",
    ]

    for filename in attested_files:
        file_path = run_dir / filename
        if file_path.exists():
            try:
                content = file_path.read_text(encoding="utf-8")
                path_issues = _find_absolute_paths(content, str(file_path))
                issues.extend(path_issues)
            except Exception:
                pass

    # Determine overall validity
    error_count = sum(1 for i in issues if i.severity == VerificationSeverity.ERROR)
    warning_count = sum(1 for i in issues if i.severity == VerificationSeverity.WARNING)

    if strict:
        valid = error_count == 0 and warning_count == 0
    else:
        valid = error_count == 0

    return VerificationResult(
        valid=valid,
        run_dir=str(run_dir),
        issues=issues,
        computed_hashes=computed_hashes,
        receipt_hashes=receipt_hashes,
    )


@dataclass
class CorpusVerificationResult:
    """Result of verifying an entire corpus of bundles."""

    corpus_dir: str
    total_bundles: int
    passed_bundles: int
    failed_bundles: int
    bundle_results: list[VerificationResult] = field(default_factory=list)
    verification_times_ms: list[float] = field(default_factory=list)
    bundle_sizes_bytes: list[int] = field(default_factory=list)
    job_family_stats: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def pass_rate(self) -> float:
        """Overall pass rate as a fraction."""
        if self.total_bundles == 0:
            return 0.0
        return self.passed_bundles / self.total_bundles

    def to_dict(self) -> dict[str, Any]:
        return {
            "corpus_dir": self.corpus_dir,
            "total_bundles": self.total_bundles,
            "passed_bundles": self.passed_bundles,
            "failed_bundles": self.failed_bundles,
            "pass_rate": self.pass_rate,
            "bundle_results": [r.to_dict() for r in self.bundle_results],
            "verification_times_ms": self.verification_times_ms,
            "bundle_sizes_bytes": self.bundle_sizes_bytes,
            "job_family_stats": self.job_family_stats,
            "time_stats": self._compute_time_stats(),
            "size_stats": self._compute_size_stats(),
        }

    def _compute_time_stats(self) -> dict[str, float]:
        """Compute time-to-verify statistics."""
        if not self.verification_times_ms:
            return {}
        times = sorted(self.verification_times_ms)
        n = len(times)
        return {
            "min_ms": times[0],
            "max_ms": times[-1],
            "mean_ms": sum(times) / n,
            "median_ms": times[n // 2],
            "p95_ms": times[int(n * 0.95)] if n >= 20 else times[-1],
            "p99_ms": times[int(n * 0.99)] if n >= 100 else times[-1],
        }

    def _compute_size_stats(self) -> dict[str, int]:
        """Compute bundle size statistics."""
        if not self.bundle_sizes_bytes:
            return {}
        sizes = sorted(self.bundle_sizes_bytes)
        n = len(sizes)
        return {
            "min_bytes": sizes[0],
            "max_bytes": sizes[-1],
            "mean_bytes": sum(sizes) // n,
            "median_bytes": sizes[n // 2],
            "total_bytes": sum(sizes),
        }


def _get_bundle_size(bundle_dir: Path) -> int:
    """Compute total size of all files in a bundle directory."""
    total = 0
    for file_path in bundle_dir.rglob("*"):
        if file_path.is_file():
            total += file_path.stat().st_size
    return total


def _get_job_family(bundle_dir: Path) -> str:
    """Extract job family from bundle path."""
    # Look for job family in parent directories
    for parent in bundle_dir.parents:
        if parent.name in ("code-review", "fab-asset", "play-session", "edge-cases"):
            return parent.name
    # Try to extract from context.json
    context_path = bundle_dir / "context.json"
    if context_path.exists():
        try:
            with open(context_path, encoding="utf-8") as f:
                data = json.load(f)
                return data.get("job_family", "unknown")
        except (json.JSONDecodeError, KeyError):
            pass
    return "unknown"


def verify_corpus(
    corpus_dir: Path,
    *,
    strict: bool = False,
) -> CorpusVerificationResult:
    """
    Verify all bundles in a corpus directory.

    Scans for bundle directories (containing receipt.json) and verifies each.

    Args:
        corpus_dir: Path to the corpus directory containing bundle subdirectories
        strict: If True, treat warnings as errors

    Returns:
        CorpusVerificationResult with aggregate statistics
    """
    import time

    corpus_dir = Path(corpus_dir)
    bundle_results: list[VerificationResult] = []
    verification_times: list[float] = []
    bundle_sizes: list[int] = []
    job_family_stats: dict[str, dict[str, int]] = {}

    # Find all bundle directories (those containing receipt.json)
    bundle_dirs: list[Path] = []
    for receipt_path in corpus_dir.rglob("receipt.json"):
        bundle_dirs.append(receipt_path.parent)

    # Sort for deterministic ordering
    bundle_dirs.sort()

    for bundle_dir in bundle_dirs:
        # Measure verification time
        start_time = time.perf_counter()
        result = verify_bundle(bundle_dir, strict=strict)
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        bundle_results.append(result)
        verification_times.append(elapsed_ms)
        bundle_sizes.append(_get_bundle_size(bundle_dir))

        # Track job family stats
        job_family = _get_job_family(bundle_dir)
        if job_family not in job_family_stats:
            job_family_stats[job_family] = {"total": 0, "passed": 0, "failed": 0}
        job_family_stats[job_family]["total"] += 1
        if result.valid:
            job_family_stats[job_family]["passed"] += 1
        else:
            job_family_stats[job_family]["failed"] += 1

    passed = sum(1 for r in bundle_results if r.valid)
    failed = len(bundle_results) - passed

    return CorpusVerificationResult(
        corpus_dir=str(corpus_dir),
        total_bundles=len(bundle_results),
        passed_bundles=passed,
        failed_bundles=failed,
        bundle_results=bundle_results,
        verification_times_ms=verification_times,
        bundle_sizes_bytes=bundle_sizes,
        job_family_stats=job_family_stats,
    )


__all__ = [
    "VerificationSeverity",
    "VerificationIssue",
    "VerificationResult",
    "CorpusVerificationResult",
    "verify_bundle",
    "verify_corpus",
]
