"""
RunReceipt generation and canonicalization.

A RunReceipt is the attestable record of a completed run,
containing references to the universe, world, run artifacts,
and quality verdict.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cyntra.trust.primitives.canonical_json import canonicalize as canonicalize_json

@dataclass
class Universe:
    """Universe reference."""

    id: str
    name: str


@dataclass
class World:
    """World reference."""

    id: str
    name: str
    version: str | None = None


@dataclass
class Run:
    """Run metadata."""

    id: str
    timestamp: str
    git_sha: str
    toolchain: str  # codex, claude, opencode, crush, blender, fab


@dataclass
class Artifacts:
    """Artifact references."""

    manifest_hash: str  # 0x-prefixed SHA256
    proof_hash: str | None = None
    primary_asset_hash: str | None = None
    ledger_root: str | None = None
    bundle_hash: str | None = None
    bundle_uri: str | None = None
    bundle_size_bytes: int | None = None
    bundle_sig: str | None = None
    ipfs_cid: str | None = None


@dataclass
class Verdict:
    """Quality gate verdict."""

    passed: bool
    gate_id: str | None = None
    scores: dict = field(default_factory=dict)
    threshold: float | None = None
    risk_classification: str | None = None


@dataclass
class ViolationRef:
    """Reference to a policy violation."""

    guard: str
    severity: str
    message: str
    action: str | None = None


@dataclass
class Provenance:
    """Provenance metadata for the run."""

    kernel_version: str | None = None
    provider: str | None = None
    provider_attestation: str | None = None
    policy_hash: str | None = None
    lease_hash: str | None = None
    violations: list[ViolationRef] = field(default_factory=list)


@dataclass
class Signatures:
    """Signature references."""

    kernel: str | None = None
    verifier: str | None = None
    provider: str | None = None


@dataclass
class Attestation:
    """Attestation reference (filled after publishing)."""

    uid: str
    chain_id: int
    attester: str
    timestamp: str


@dataclass
class TransparencyLog:
    """Transparency log reference (Rekor, Trillian, etc.)."""

    log_id: str
    log_index: int
    inclusion_proof: str | None = None


@dataclass
class PlayStream:
    """Stream reference for play sessions."""

    provider: str
    room_id: str


@dataclass
class PlaySession:
    """Play session metadata."""

    title_id: str
    session_id: str
    mode: str
    title_version: str | None = None
    engine: str | None = None
    engine_version: str | None = None
    scenario_id: str | None = None
    park_name: str | None = None
    save_base_hash: str | None = None
    save_final_hash: str | None = None
    control_api_version: str | None = None
    control_api_hash: str | None = None
    capability_grants_hash: str | None = None
    asset_pack_hash: str | None = None
    stream: PlayStream | None = None


@dataclass
class RunReceipt:
    """
    Complete run receipt for attestation.

    This structure matches the TypeScript RunReceiptSchema
    in packages/membrane/src/types/receipt.ts
    """

    version: str
    receipt_id: str
    universe: Universe
    world: World
    run: Run
    artifacts: Artifacts
    verdict: Verdict
    play: PlaySession | None = None
    provenance: Provenance | None = None
    signatures: Signatures | None = None
    attestation: Attestation | None = None
    transparency_log: TransparencyLog | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary, excluding None values."""

        def clean(obj):
            if isinstance(obj, dict):
                return {k: clean(v) for k, v in obj.items() if v is not None}
            elif isinstance(obj, list):
                return [clean(v) for v in obj]
            else:
                return obj

        return clean(asdict(self))

    def to_canonical(self) -> str:
        """
        Return canonical JSON representation.

        CCJ v1 / RFC 8785 (JCS): sorted keys, no whitespace, UTF-8, and
        ECMAScript `JSON.stringify()` number+string semantics.
        """
        return canonicalize_json(self.to_dict())

    def hash(self) -> str:
        """
        Compute SHA256 hash of canonical representation.

        Returns 0x-prefixed hex string matching membrane's sha256().
        """
        canonical = self.to_canonical()
        hash_bytes = hashlib.sha256(canonical.encode("utf-8")).digest()
        return "0x" + hash_bytes.hex()

    def save(self, path: Path) -> None:
        """Save receipt to JSON file."""
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: Path) -> RunReceipt:
        """Load receipt from JSON file."""
        with open(path) as f:
            data = json.load(f)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> RunReceipt:
        """Create RunReceipt from dictionary."""
        attestation = None
        if data.get("attestation"):
            attestation = Attestation(**data["attestation"])
        provenance = None
        if data.get("provenance"):
            violations = [
                ViolationRef(**item) for item in data["provenance"].get("violations", [])
            ]
            provenance = Provenance(
                kernel_version=data["provenance"].get("kernel_version"),
                provider=data["provenance"].get("provider"),
                provider_attestation=data["provenance"].get("provider_attestation"),
                policy_hash=data["provenance"].get("policy_hash"),
                lease_hash=data["provenance"].get("lease_hash"),
                violations=violations,
            )
        signatures = None
        if data.get("signatures"):
            signatures = Signatures(**data["signatures"])
        transparency_log = None
        if data.get("transparency_log"):
            transparency_log = TransparencyLog(**data["transparency_log"])
        play = None
        if isinstance(data.get("play"), dict):
            stream = None
            stream_data = data["play"].get("stream")
            if isinstance(stream_data, dict):
                stream = PlayStream(**stream_data)
            play = PlaySession(
                title_id=data["play"].get("title_id", ""),
                session_id=data["play"].get("session_id", ""),
                mode=data["play"].get("mode", ""),
                title_version=data["play"].get("title_version"),
                engine=data["play"].get("engine"),
                engine_version=data["play"].get("engine_version"),
                scenario_id=data["play"].get("scenario_id"),
                park_name=data["play"].get("park_name"),
                save_base_hash=data["play"].get("save_base_hash"),
                save_final_hash=data["play"].get("save_final_hash"),
                control_api_version=data["play"].get("control_api_version"),
                control_api_hash=data["play"].get("control_api_hash"),
                capability_grants_hash=data["play"].get("capability_grants_hash"),
                asset_pack_hash=data["play"].get("asset_pack_hash"),
                stream=stream,
            )

        receipt_id = data.get("receipt_id") or data.get("run", {}).get("id") or ""

        return cls(
            version=data["version"],
            receipt_id=receipt_id,
            universe=Universe(**data["universe"]),
            world=World(**data["world"]),
            run=Run(**data["run"]),
            artifacts=Artifacts(**data["artifacts"]),
            verdict=Verdict(**data["verdict"]),
            play=play,
            provenance=provenance,
            signatures=signatures,
            attestation=attestation,
            transparency_log=transparency_log,
        )


def hash_file(path: Path) -> str:
    """
    Compute SHA256 hash of a file.

    Returns 0x-prefixed hex string.
    """
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return "0x" + hasher.hexdigest()


def generate_receipt(run_dir: Path) -> RunReceipt:
    """
    Generate a RunReceipt from a completed run directory.

    Expects the run directory to contain:
    - context.json: Run context with universe/world/toolchain info
    - manifest.json: Manifest of all run artifacts
    - proof.json: Quality gate proof with verdict

    Args:
        run_dir: Path to the run directory (e.g., .cyntra/runs/<run_id>/)

    Returns:
        RunReceipt ready for publishing
    """
    run_dir = Path(run_dir)

    # Load context
    context_path = run_dir / "context.json"
    if not context_path.exists():
        raise FileNotFoundError(f"context.json not found in {run_dir}")

    with open(context_path) as f:
        context = json.load(f)

    # Load manifest
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"manifest.json not found in {run_dir}")

    manifest_hash = hash_file(manifest_path)
    manifest_data = None
    try:
        with open(manifest_path) as f:
            manifest_data = json.load(f)
    except json.JSONDecodeError:
        manifest_data = None

    # Load proof
    proof_path = run_dir / "proof.json"
    proof_hash = None
    verdict_data = {"passed": False}

    if proof_path.exists():
        proof_hash = hash_file(proof_path)
        with open(proof_path) as f:
            proof = json.load(f)
        verdict_data = proof.get("verdict", verdict_data)

    ledger_root = None
    ledger_root_path = run_dir / "ledger_root.json"
    if ledger_root_path.exists():
        with open(ledger_root_path) as f:
            ledger_root = json.load(f).get("ledger_root")

    bundle_hash = None
    bundle_size_bytes = None
    bundle_uri = None
    bundle_sig = None
    bundle_manifest_path = run_dir / "bundle_manifest.json"
    if bundle_manifest_path.exists():
        with open(bundle_manifest_path) as f:
            bundle_manifest = json.load(f)
        canonical = canonicalize_json(bundle_manifest)
        bundle_hash = "0x" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        entries = bundle_manifest.get("entries") if isinstance(bundle_manifest, dict) else None
        if isinstance(entries, list):
            bundle_size_bytes = sum(
                int(entry.get("size_bytes", 0))
                for entry in entries
                if isinstance(entry, dict)
            )

    bundle_pointer_path = run_dir / "bundle_pointer.json"
    if bundle_pointer_path.exists():
        with open(bundle_pointer_path) as f:
            bundle_pointer = json.load(f)
        bundle_uri = bundle_pointer.get("bundle_uri") or bundle_pointer.get("uri")
        bundle_sig = bundle_pointer.get("bundle_sig") or bundle_pointer.get("signature")
        if bundle_size_bytes is None:
            try:
                bundle_size_bytes = int(bundle_pointer.get("bundle_size_bytes", 0)) or None
            except (TypeError, ValueError):
                bundle_size_bytes = None

    policy_hash = None
    policy_path = run_dir / "security_policy.json"
    if policy_path.exists():
        policy_hash = hash_file(policy_path)

    # Extract universe/world info from context
    universe_id = context.get("universe_id", "default")
    universe_name = context.get("universe_name", universe_id)
    world_id = context.get("world_id", "default")
    world_name = context.get("world_name", world_id)
    world_version = context.get("world_version")

    # Prefer toolchain from context, fallback to manifest
    toolchain_value = context.get("toolchain")
    if not toolchain_value and isinstance(manifest_data, dict):
        toolchain_value = manifest_data.get("toolchain")
    toolchain = str(toolchain_value or "unknown")

    primary_asset_hash = context.get("primary_asset_hash")
    if not primary_asset_hash and isinstance(manifest_data, dict):
        primary_asset_hash = manifest_data.get("primary_asset_hash")
        asset_info = manifest_data.get("asset") if isinstance(manifest_data.get("asset"), dict) else {}
        primary_asset_hash = primary_asset_hash or asset_info.get("hash")

    git_sha = context.get("git_sha")
    if not git_sha and isinstance(manifest_data, dict):
        git_sha = manifest_data.get("git_sha")
        if not git_sha:
            versions = manifest_data.get("versions") if isinstance(manifest_data.get("versions"), dict) else {}
            git_sha = versions.get("git_commit")
    git_sha = git_sha or ("0" * 40)

    receipt_id = context.get("receipt_id") or run_dir.name

    lease_hash = _extract_lease_hash(context, manifest_data)
    play = None
    play_data = context.get("play")
    if isinstance(play_data, dict):
        stream = None
        stream_data = play_data.get("stream")
        if isinstance(stream_data, dict):
            stream = PlayStream(**stream_data)
        play = PlaySession(
            title_id=play_data.get("title_id", ""),
            session_id=play_data.get("session_id", ""),
            mode=play_data.get("mode", ""),
            title_version=play_data.get("title_version"),
            engine=play_data.get("engine"),
            engine_version=play_data.get("engine_version"),
            scenario_id=play_data.get("scenario_id"),
            park_name=play_data.get("park_name"),
            save_base_hash=play_data.get("save_base_hash"),
            save_final_hash=play_data.get("save_final_hash"),
            control_api_version=play_data.get("control_api_version"),
            control_api_hash=play_data.get("control_api_hash"),
            capability_grants_hash=play_data.get("capability_grants_hash"),
            asset_pack_hash=play_data.get("asset_pack_hash"),
            stream=stream,
        )

    # Build receipt
    violations = [
        ViolationRef(**item)
        for item in context.get("policy_violations", [])
        if isinstance(item, dict)
    ]
    provenance = None
    if any(
        [
            context.get("kernel_version"),
            context.get("provider"),
            context.get("provider_attestation"),
            policy_hash,
            lease_hash,
            violations,
        ]
    ):
        provenance = Provenance(
            kernel_version=context.get("kernel_version"),
            provider=context.get("provider"),
            provider_attestation=context.get("provider_attestation"),
            policy_hash=policy_hash,
            lease_hash=lease_hash,
            violations=violations,
        )

    # Use context timestamp for reproducibility if provided, otherwise current time
    run_timestamp = context.get("run_timestamp")
    if not run_timestamp:
        run_timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    return RunReceipt(
        version="2.0.0",
        receipt_id=receipt_id,
        universe=Universe(
            id=universe_id,
            name=universe_name,
        ),
        world=World(
            id=world_id,
            name=world_name,
            version=world_version,
        ),
        run=Run(
            id=run_dir.name,
            timestamp=run_timestamp,
            git_sha=git_sha,
            toolchain=toolchain,
        ),
        artifacts=Artifacts(
            manifest_hash=manifest_hash,
            proof_hash=proof_hash,
            primary_asset_hash=primary_asset_hash,
            ledger_root=ledger_root,
            bundle_hash=bundle_hash,
            bundle_uri=bundle_uri,
            bundle_size_bytes=bundle_size_bytes,
            bundle_sig=bundle_sig,
        ),
        verdict=Verdict(
            passed=verdict_data.get("passed", False),
            gate_id=verdict_data.get("gate_id"),
            scores=verdict_data.get("scores", {}),
            threshold=verdict_data.get("threshold"),
            risk_classification=verdict_data.get("risk_classification"),
        ),
        play=play,
        provenance=provenance,
    )


def _extract_lease_hash(context: dict | None, manifest: dict | None) -> str | None:
    candidates = (context, manifest)
    for source in candidates:
        if not isinstance(source, dict):
            continue
        lease_hash = _extract_hash_from_map(source)
        if lease_hash:
            return lease_hash
        metadata = source.get("metadata")
        if isinstance(metadata, dict):
            lease_hash = _extract_hash_from_map(metadata)
            if lease_hash:
                return lease_hash
    return None


def _extract_hash_from_map(source: dict) -> str | None:
    for key in ("lease_hash", "leaseHash"):
        value = source.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None
