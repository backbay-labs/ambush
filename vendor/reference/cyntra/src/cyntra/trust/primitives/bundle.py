"""Proof bundle manifest helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Iterable

from cyntra.trust.primitives.canonical_json import canonicalize


@dataclass
class ProofBundleEntry:
    """A single file entry in a proof bundle."""

    path: str
    sha256: str
    size_bytes: int


@dataclass
class ProofBundleManifest:
    """Manifest describing a proof bundle."""

    version: str
    run_id: str
    created_at: str
    entries: list[ProofBundleEntry] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "run_id": self.run_id,
            "created_at": self.created_at,
            "entries": [entry.__dict__ for entry in self.entries],
        }

    def to_canonical(self) -> str:
        """Return CCJ v1 (RFC 8785) canonical JSON representation."""
        return canonicalize(self.to_dict())

    def hash(self) -> str:
        payload = self.to_canonical().encode("utf-8")
        return "0x" + sha256(payload).hexdigest()

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2)


def build_bundle_manifest(
    run_dir: Path,
    *,
    include_paths: Iterable[str] | None = None,
    include_artifacts: bool = True,
    created_at: str | None = None,
) -> ProofBundleManifest:
    """Build a proof bundle manifest for a run directory.

    Args:
        run_dir: Path to the run directory
        include_paths: Specific paths to include in the manifest
        include_artifacts: Whether to include files from artifacts/ subdirectory
        created_at: Optional fixed timestamp for reproducibility. If not provided,
            will check for 'bundle_created_at' in context.json, otherwise uses now().
    """
    run_dir = Path(run_dir)
    run_id = run_dir.name

    # Use provided timestamp, or check context.json, or use current time
    if not created_at:
        context_path = run_dir / "context.json"
        if context_path.exists():
            try:
                import json as json_module
                with context_path.open() as f:
                    context = json_module.load(f)
                created_at = context.get("bundle_created_at")
            except (json.JSONDecodeError, OSError):
                pass

    if not created_at:
        created_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    if include_paths is None:
        include_paths = (
            "manifest.json",
            "proof.json",
            "patch.diff",
            "ledger.jsonl",
            "shield_alerts.jsonl",
            "run_metadata.json",
        )

    entries: list[ProofBundleEntry] = []
    seen: set[str] = set()

    for rel_path in include_paths:
        file_path = run_dir / rel_path
        if file_path.exists() and file_path.is_file():
            _append_entry(entries, file_path, run_dir, seen)

    if include_artifacts:
        artifacts_dir = run_dir / "artifacts"
        if artifacts_dir.exists():
            for file_path in sorted(artifacts_dir.rglob("*")):
                if file_path.is_file():
                    _append_entry(entries, file_path, run_dir, seen)

    entries.sort(key=lambda entry: entry.path)

    return ProofBundleManifest(
        version="1.0.0",
        run_id=run_id,
        created_at=created_at,
        entries=entries,
    )


def _append_entry(
    entries: list[ProofBundleEntry],
    file_path: Path,
    run_dir: Path,
    seen: set[str],
) -> None:
    rel_path = file_path.relative_to(run_dir).as_posix()
    if rel_path in seen:
        return
    seen.add(rel_path)

    size_bytes = file_path.stat().st_size
    file_hash = _hash_file(file_path)

    entries.append(
        ProofBundleEntry(path=rel_path, sha256=file_hash, size_bytes=size_bytes)
    )


def _hash_file(path: Path) -> str:
    hasher = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            hasher.update(chunk)
    return "0x" + hasher.hexdigest()
