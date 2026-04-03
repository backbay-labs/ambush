from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cyntra.cognition.memory.database import MemoryDB
from cyntra.cognition.memory.membox.membox_store import MemboxStore, MemboxStoreConfig


@dataclass(frozen=True)
class MemoryCoherenceGateConfig:
    """
    Lightweight "memory_coherence_v001" gate config.

    This gate is intentionally simple: it validates that (a) the workcell wrote some
    membox entries and (b) retrieval wasn't unexpectedly empty for a nontrivial run.
    """

    nontrivial_observation_min: int = 10
    recent_scan_limit: int = 500


def evaluate_memory_coherence_v001(
    *,
    workcell_id: str,
    manifest: dict[str, Any],
    db_path: Path,
    config: MemoryCoherenceGateConfig | None = None,
) -> dict[str, Any]:
    cfg = config or MemoryCoherenceGateConfig()

    failures: list[str] = []
    details: dict[str, Any] = {}

    # Load session stats (for nontrivial determination).
    memdb = MemoryDB(db_path)
    try:
        session = memdb.get_session_by_workcell_id(workcell_id)
        session_id = session.get("id") if isinstance(session, dict) else None
    finally:
        memdb.close()

    observation_count = int(session.get("observation_count", 0)) if isinstance(session, dict) else 0
    nontrivial = observation_count >= cfg.nontrivial_observation_min
    details["observation_count"] = observation_count
    details["nontrivial"] = nontrivial
    details["session_id"] = session_id

    memory_context = manifest.get("memory_context") if isinstance(manifest.get("memory_context"), dict) else {}
    membox_context = memory_context.get("membox") if isinstance(memory_context.get("membox"), dict) else {}
    selected = membox_context.get("selected") if isinstance(membox_context.get("selected"), list) else []
    details["retrieval_selected_count"] = len(selected)

    # Check: pre-run DB totals (captured at injection time).
    start_db_total = None
    stats = membox_context.get("stats") if isinstance(membox_context.get("stats"), dict) else {}
    db_totals = stats.get("db_totals") if isinstance(stats.get("db_totals"), dict) else None
    if isinstance(db_totals, dict):
        start_db_total = int(db_totals.get("memboxes", 0)) + int(db_totals.get("traces", 0))
    details["start_db_total"] = start_db_total

    # Fail (b): retrieval empty for a nontrivial run when there was prior memory available.
    if nontrivial and isinstance(start_db_total, int) and start_db_total > 0 and not selected:
        failures.append("MEMBOX_RETRIEVAL_EMPTY")

    # Fail (a): this workcell produced no membox entries (best-effort).
    store = MemboxStore(config=MemboxStoreConfig(db_path=db_path))
    try:
        memboxes = store.list_recent_memboxes(limit=cfg.recent_scan_limit)
    finally:
        store.close()

    produced = 0
    workcell_source = f"workcell:{workcell_id}"
    for box in memboxes:
        if any(m.source == workcell_source for m in box.messages):
            produced += 1

    details["memboxes_produced"] = produced
    if produced == 0:
        failures.append("MEMBOX_NO_ENTRIES")

    return {
        "gate_config_id": "memory_coherence_v001",
        "passed": len(failures) == 0,
        "fail_codes": failures,
        "details": details,
    }
