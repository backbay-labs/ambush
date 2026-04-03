"""
AuditSession - Per-engagement metrics tracking.

Tracks cell-level execution metrics, phase aggregation, and
engagement-level summaries for cost accounting and reporting.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from hellcat.core.audit.writer import AuditWriter

logger = structlog.get_logger()


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _ms_since(iso_start: str) -> int:
    """Milliseconds elapsed since an ISO timestamp."""
    start = datetime.fromisoformat(iso_start)
    now = datetime.now(UTC)
    return int((now - start).total_seconds() * 1000)


@dataclass
class CellMetrics:
    """Metrics for a single StrikeCell execution."""

    cell_id: str
    operator: str
    model: str
    start_time: str
    end_time: str = ""
    duration_ms: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    success: bool = False
    error: str = ""
    phase: str = ""
    node_id: str = ""


@dataclass
class PhaseMetrics:
    """Aggregated metrics for a single engagement phase."""

    phase: str
    cell_count: int = 0
    total_duration_ms: int = 0
    total_cost_usd: float = 0.0
    success_count: int = 0
    failure_count: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0


@dataclass
class EngagementSummary:
    """Full engagement summary with per-phase breakdown."""

    engagement_id: str
    target_url: str
    start_time: str
    end_time: str = ""
    phases: list[PhaseMetrics] = field(default_factory=list)
    total_cost_usd: float = 0.0
    total_tokens: int = 0
    total_cells: int = 0
    total_succeeded: int = 0
    total_failed: int = 0
    vulns_found: int = 0
    vulns_exploited: int = 0
    duration_ms: int = 0


class AuditSession:
    """
    Tracks metrics for a full engagement lifecycle.

    Usage::

        session = AuditSession(audit_dir=Path(".hellcat/audit"))
        session.start_engagement("http://target", {"key": "val"})
        session.start_cell("cell-1", "injection_operator", "sonnet-4")
        session.end_cell("cell-1", success=True, cost=0.02, input_tokens=500, output_tokens=200)
        session.end_phase("vuln_analysis")
        summary = session.end_engagement()
    """

    def __init__(self, audit_dir: Path | None = None) -> None:
        self._engagement_id: str = ""
        self._target_url: str = ""
        self._start_time: str = ""
        self._config: dict[str, Any] = {}
        self._active_cells: dict[str, CellMetrics] = {}
        self._completed_cells: list[CellMetrics] = []
        self._phase_metrics: list[PhaseMetrics] = []
        self._current_phase: str = ""
        self._writer: AuditWriter | None = None
        self._audit_dir = audit_dir

    @property
    def engagement_id(self) -> str:
        return self._engagement_id

    def start_engagement(
        self, target_url: str, config: dict[str, Any] | None = None,
    ) -> str:
        self._engagement_id = str(uuid.uuid4())
        self._target_url = target_url
        self._start_time = _utc_now()
        self._config = config or {}

        if self._audit_dir:
            log_path = self._audit_dir / f"{self._engagement_id}.jsonl"
            self._writer = AuditWriter(log_path)
            self._write_record("engagement_start", {
                "target_url": target_url,
                "config": self._config,
            })

        logger.info(
            "audit.engagement_start",
            engagement_id=self._engagement_id,
            target=target_url,
        )
        return self._engagement_id

    def start_cell(
        self,
        cell_id: str,
        operator_name: str,
        model: str = "",
        phase: str = "",
        node_id: str = "",
    ) -> None:
        """Record the start of a cell execution."""
        self._current_phase = phase or self._current_phase
        metrics = CellMetrics(
            cell_id=cell_id,
            operator=operator_name,
            model=model,
            start_time=_utc_now(),
            phase=self._current_phase,
            node_id=node_id,
        )
        self._active_cells[cell_id] = metrics

        self._write_record("cell_start", {
            "cell_id": cell_id,
            "operator": operator_name,
            "model": model,
            "phase": self._current_phase,
        })

    def end_cell(
        self,
        cell_id: str,
        *,
        success: bool = False,
        cost: float = 0.0,
        input_tokens: int = 0,
        output_tokens: int = 0,
        error: str = "",
    ) -> CellMetrics:
        """Record cell completion with timing, cost, and token counts."""
        metrics = self._active_cells.pop(cell_id, None)
        if metrics is None:
            # Cell wasn't started via start_cell; create stub
            metrics = CellMetrics(
                cell_id=cell_id,
                operator="unknown",
                model="unknown",
                start_time=_utc_now(),
            )

        metrics.end_time = _utc_now()
        metrics.duration_ms = _ms_since(metrics.start_time)
        metrics.success = success
        metrics.cost_usd = cost
        metrics.input_tokens = input_tokens
        metrics.output_tokens = output_tokens
        metrics.error = error

        self._completed_cells.append(metrics)

        self._write_record("cell_end", asdict(metrics))

        logger.info(
            "audit.cell_end",
            cell_id=cell_id,
            operator=metrics.operator,
            success=success,
            duration_ms=metrics.duration_ms,
            cost=cost,
        )
        return metrics

    def end_phase(self, phase_name: str) -> PhaseMetrics:
        """Aggregate metrics for a completed phase."""
        cells = [c for c in self._completed_cells if c.phase == phase_name]

        phase = PhaseMetrics(
            phase=phase_name,
            cell_count=len(cells),
            total_duration_ms=sum(c.duration_ms for c in cells),
            total_cost_usd=sum(c.cost_usd for c in cells),
            success_count=sum(1 for c in cells if c.success),
            failure_count=sum(1 for c in cells if not c.success),
            total_input_tokens=sum(c.input_tokens for c in cells),
            total_output_tokens=sum(c.output_tokens for c in cells),
        )
        self._phase_metrics.append(phase)

        self._write_record("phase_end", asdict(phase))

        logger.info(
            "audit.phase_end",
            phase=phase_name,
            cells=phase.cell_count,
            cost=phase.total_cost_usd,
        )
        return phase

    def end_engagement(
        self, vulns_found: int = 0, vulns_exploited: int = 0,
    ) -> EngagementSummary:
        """Produce the final engagement summary."""
        end_time = _utc_now()

        summary = EngagementSummary(
            engagement_id=self._engagement_id,
            target_url=self._target_url,
            start_time=self._start_time,
            end_time=end_time,
            phases=list(self._phase_metrics),
            total_cost_usd=sum(c.cost_usd for c in self._completed_cells),
            total_tokens=sum(c.input_tokens + c.output_tokens for c in self._completed_cells),
            total_cells=len(self._completed_cells),
            total_succeeded=sum(1 for c in self._completed_cells if c.success),
            total_failed=sum(1 for c in self._completed_cells if not c.success),
            vulns_found=vulns_found,
            vulns_exploited=vulns_exploited,
            duration_ms=_ms_since(self._start_time),
        )

        self._write_record("engagement_end", asdict(summary))

        if self._writer:
            self._writer.close()
            self._writer = None

        logger.info(
            "audit.engagement_end",
            engagement_id=self._engagement_id,
            total_cost=summary.total_cost_usd,
            total_cells=summary.total_cells,
            duration_ms=summary.duration_ms,
        )
        return summary

    def get_summary(self) -> EngagementSummary:
        """Return a snapshot summary without ending the engagement."""
        return EngagementSummary(
            engagement_id=self._engagement_id,
            target_url=self._target_url,
            start_time=self._start_time,
            end_time="",
            phases=list(self._phase_metrics),
            total_cost_usd=sum(c.cost_usd for c in self._completed_cells),
            total_tokens=sum(c.input_tokens + c.output_tokens for c in self._completed_cells),
            total_cells=len(self._completed_cells),
            total_succeeded=sum(1 for c in self._completed_cells if c.success),
            total_failed=sum(1 for c in self._completed_cells if not c.success),
            duration_ms=_ms_since(self._start_time) if self._start_time else 0,
        )

    def get_completed_cells(self) -> list[CellMetrics]:
        """Return all completed cell metrics."""
        return list(self._completed_cells)

    def log_denied_action(
        self,
        action: str,
        reason: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Record a denied action for audit trail."""
        record = {
            "action": action,
            "reason": reason,
            "context": context or {},
        }
        self._write_record("action_denied", record)
        logger.warning(
            "audit.action_denied",
            action=action,
            reason=reason,
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _write_record(self, event: str, data: dict[str, Any]) -> None:
        """Write an audit record to the JSONL log if a writer is configured."""
        if self._writer is None:
            return
        self._writer.write({
            "event": event,
            "engagement_id": self._engagement_id,
            "timestamp": _utc_now(),
            **data,
        })
