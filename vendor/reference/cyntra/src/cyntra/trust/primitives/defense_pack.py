"""
DefensePack/DetectorPack helpers for range outputs.
"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _hash_file(path: Path) -> str | None:
    if not path.exists():
        return None
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            hasher.update(chunk)
    return "0x" + hasher.hexdigest()


@dataclass
class PackArtifact:
    kind: str
    path: str


@dataclass
class PackRef:
    receipt_hash: str | None = None
    scorecard_hash: str | None = None


@dataclass
class DefensePack:
    pack_id: str
    version: str = "1.0.0"
    pack_type: str = "detector"
    artifacts: list[PackArtifact] = field(default_factory=list)
    proof_refs: list[PackRef] = field(default_factory=list)
    license: str = "CC-BY-4.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "pack_id": self.pack_id,
            "version": self.version,
            "pack_type": self.pack_type,
            "artifacts": [a.__dict__ for a in self.artifacts],
            "proof_refs": [r.__dict__ for r in self.proof_refs],
            "license": self.license,
        }


def build_pack(
    *,
    pack_id: str,
    pack_type: str,
    artifacts: list[PackArtifact],
    run_dir: Path,
    license_id: str = "CC-BY-4.0",
) -> Path:
    """Build a DefensePack/DetectorPack JSON file."""
    receipt_hash = _hash_file(run_dir / "receipt.json")
    scorecard_hash = _hash_file(run_dir / "scorecard.json")

    pack = DefensePack(
        pack_id=pack_id,
        pack_type=pack_type,
        artifacts=artifacts,
        proof_refs=[PackRef(receipt_hash=receipt_hash, scorecard_hash=scorecard_hash)],
        license=license_id,
    )

    output_path = run_dir / f"{pack_type}_pack.json"
    output_path.write_text(json.dumps(pack.to_dict(), indent=2))
    return output_path
