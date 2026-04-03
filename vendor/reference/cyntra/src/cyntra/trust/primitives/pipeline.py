"""Run finalization helpers for trust artifacts."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Iterable

from cyntra.trust.ledger.events import (
    EventType,
    LedgerEvent,
    LeaseAnchoredEvent,
    LeaseCreatedEvent,
)
from cyntra.trust.membrane.receipt import RunReceipt, generate_receipt
from cyntra.trust.primitives.availability import DataAvailabilityStore
from cyntra.trust.primitives.bundle import build_bundle_manifest
from cyntra.trust.primitives.merkle import EventMerkleTree


def finalize_run_artifacts(
    run_dir: Path,
    *,
    ledger_path: Path | None = None,
    bundle_store: DataAvailabilityStore | None = None,
) -> RunReceipt:
    """Build bundle manifest, ledger root, and receipt for a run directory."""
    run_dir = Path(run_dir)
    ledger_events = _load_events(run_dir, ledger_path=ledger_path)
    lease_hash = _load_lease_hash(run_dir)
    ledger_events, lease_updated = _ensure_lease_events(
        ledger_events,
        run_id=run_dir.name,
        lease_hash=lease_hash,
    )
    if lease_updated:
        _write_ledger_snapshot(run_dir / "ledger.jsonl", ledger_events)

    if ledger_events:
        tree = EventMerkleTree(ledger_events)
        _write_json(
            run_dir / "ledger_root.json",
            {"ledger_root": tree.root, "anchored_events": len(tree.leaves)},
        )

    manifest = build_bundle_manifest(run_dir)
    manifest_path = run_dir / "bundle_manifest.json"
    manifest.save(manifest_path)

    if bundle_store:
        pointer = bundle_store.register_bundle(run_dir, manifest)
        _write_json(
            run_dir / "bundle_pointer.json",
            {
                "bundle_hash": pointer.bundle_hash,
                "bundle_uri": pointer.uri,
                "bundle_size_bytes": pointer.size_bytes,
                "bundle_sig": pointer.signature,
                "availability_window_days": pointer.availability_window_days,
                "metadata": pointer.metadata or {},
            },
        )

    receipt = generate_receipt(run_dir)
    receipt.save(run_dir / "receipt.json")
    return receipt


def _load_events(
    run_dir: Path,
    *,
    ledger_path: Path | None = None,
) -> list[LedgerEvent]:
    if ledger_path and ledger_path.exists():
        return _read_ledger_jsonl(ledger_path)

    run_ledger = run_dir / "ledger.jsonl"
    if run_ledger.exists():
        return _read_ledger_jsonl(run_ledger)

    telemetry_path = run_dir / "telemetry.jsonl"
    if telemetry_path.exists():
        return _events_from_telemetry(telemetry_path)

    return []


def _read_ledger_jsonl(path: Path) -> list[LedgerEvent]:
    events: list[LedgerEvent] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            try:
                events.append(LedgerEvent.from_dict(data))
            except Exception:
                continue
    return events


def _events_from_telemetry(path: Path) -> list[LedgerEvent]:
    events: list[LedgerEvent] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            event_type = _map_telemetry_type(data.get("type"))
            if not event_type:
                continue
            timestamp = _parse_timestamp(data.get("timestamp"))
            events.append(
                LedgerEvent(
                    type=event_type,
                    run_id=str(data.get("run_id") or ""),
                    timestamp=timestamp or datetime.utcnow(),
                    data=data,
                )
            )
    return events


def _ensure_lease_events(
    events: list[LedgerEvent],
    *,
    run_id: str,
    lease_hash: str | None,
) -> tuple[list[LedgerEvent], bool]:
    if not lease_hash:
        return events, False

    has_created = any(event.type == EventType.LEASE_CREATED for event in events)
    has_anchored = any(event.type == EventType.LEASE_ANCHORED for event in events)
    updated = False

    if not has_created:
        events.append(LeaseCreatedEvent(run_id=run_id, lease_hash=lease_hash))
        updated = True
    if not has_anchored:
        events.append(LeaseAnchoredEvent(run_id=run_id, lease_hash=lease_hash))
        updated = True

    return events, updated


def _load_lease_hash(run_dir: Path) -> str | None:
    context = _read_json_if_exists(run_dir / "context.json")
    manifest = _read_json_if_exists(run_dir / "manifest.json")
    return _extract_lease_hash(context, manifest)


def _read_json_if_exists(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _extract_lease_hash(context: dict | None, manifest: dict | None) -> str | None:
    for source in (context, manifest):
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


def _map_telemetry_type(value: str | None) -> EventType | None:
    if value == "started":
        return EventType.RUN_STARTED
    if value == "completed":
        return EventType.RUN_COMPLETED
    if value == "error":
        return EventType.ERROR
    return None


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_ledger_snapshot(path: Path, events: Iterable[LedgerEvent]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(event.to_json() + "\n")
