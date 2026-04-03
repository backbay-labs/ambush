"""
Workcell Cleanup - Remove old workcells.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import structlog

from cyntra.core.scheduler.routing import KernelConfig
from cyntra.core.workcell.manager import WorkcellManager

logger = structlog.get_logger()


def cleanup_workcells(
    config_path: Path,
    remove_all: bool = False,
    older_than_days: int | None = None,
    keep_logs: bool = True,
) -> int:
    """
    Clean up workcells.

    Returns the number of workcells removed.
    """
    config = KernelConfig.load(config_path)
    manager = WorkcellManager(config, config.repo_root)

    active = manager.list_active()
    removed = 0

    for wc_path in active:
        info = manager.get_workcell_info(wc_path)

        if not info:
            continue

        should_remove = False

        if remove_all:
            should_remove = True
        elif older_than_days is not None:
            created_str = info.get("created", "")
            if created_str:
                try:
                    created = datetime.strptime(created_str, "%Y%m%dT%H%M%SZ")
                    cutoff = datetime.utcnow() - timedelta(days=older_than_days)
                    should_remove = created < cutoff
                except ValueError:
                    pass

        if should_remove:
            manager.cleanup(wc_path, keep_logs=keep_logs)
            removed += 1
            logger.info("Removed workcell", workcell_id=info.get("id"))

    return removed
