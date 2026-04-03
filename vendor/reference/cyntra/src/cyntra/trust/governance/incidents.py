"""
Incident response for the verification market.

Defines incident classification, response runbooks, and tracking.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class IncidentSeverity(str, Enum):
    """Severity levels for incidents."""

    P0 = "p0"  # Critical - immediate response required
    P1 = "p1"  # High - response within 1 hour
    P2 = "p2"  # Medium - response within 4 hours
    P3 = "p3"  # Low - response within 24 hours
    P4 = "p4"  # Informational - no immediate response


class IncidentStatus(str, Enum):
    """Status of an incident."""

    DETECTED = "detected"  # Initial detection
    INVESTIGATING = "investigating"  # Under investigation
    MITIGATING = "mitigating"  # Mitigation in progress
    RESOLVED = "resolved"  # Resolved
    CLOSED = "closed"  # Closed after review
    FALSE_ALARM = "false_alarm"  # Determined to be false alarm


class ResponseAction(str, Enum):
    """Types of incident response actions."""

    PAUSE_GLOBAL = "pause_global"
    PAUSE_COVERAGE = "pause_coverage"
    PAUSE_CLAIMS = "pause_claims"
    ALERT_TEAM = "alert_team"
    FREEZE_ACCOUNT = "freeze_account"
    REVOKE_ACCESS = "revoke_access"
    ROLL_BACK = "roll_back"
    COMMUNICATE = "communicate"
    ESCALATE = "escalate"
    MONITOR = "monitor"


@dataclass
class ResponseRunbook:
    """
    Response runbook for a type of incident.

    Defines the steps to take when a specific type of incident occurs.
    """

    runbook_id: str
    name: str
    description: str
    severity: IncidentSeverity
    trigger_conditions: list[str] = field(default_factory=list)

    # Response steps in order
    immediate_actions: list[ResponseAction] = field(default_factory=list)
    investigation_steps: list[str] = field(default_factory=list)
    mitigation_steps: list[str] = field(default_factory=list)
    recovery_steps: list[str] = field(default_factory=list)
    post_incident_steps: list[str] = field(default_factory=list)

    # Escalation
    escalation_contacts: list[str] = field(default_factory=list)
    escalation_threshold_minutes: int = 30

    # SLA
    response_sla_minutes: int = 60
    resolution_sla_hours: int = 24

    # Status
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_used_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "runbook_id": self.runbook_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "trigger_conditions": self.trigger_conditions,
            "immediate_actions": [a.value for a in self.immediate_actions],
            "investigation_steps": self.investigation_steps,
            "mitigation_steps": self.mitigation_steps,
            "recovery_steps": self.recovery_steps,
            "post_incident_steps": self.post_incident_steps,
            "escalation_contacts": self.escalation_contacts,
            "escalation_threshold_minutes": self.escalation_threshold_minutes,
            "response_sla_minutes": self.response_sla_minutes,
            "resolution_sla_hours": self.resolution_sla_hours,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResponseRunbook:
        runbook = cls(
            runbook_id=data["runbook_id"],
            name=data["name"],
            description=data["description"],
            severity=IncidentSeverity(data["severity"]),
            trigger_conditions=data.get("trigger_conditions", []),
            investigation_steps=data.get("investigation_steps", []),
            mitigation_steps=data.get("mitigation_steps", []),
            recovery_steps=data.get("recovery_steps", []),
            post_incident_steps=data.get("post_incident_steps", []),
            escalation_contacts=data.get("escalation_contacts", []),
            escalation_threshold_minutes=data.get("escalation_threshold_minutes", 30),
            response_sla_minutes=data.get("response_sla_minutes", 60),
            resolution_sla_hours=data.get("resolution_sla_hours", 24),
            is_active=data.get("is_active", True),
            created_at=datetime.fromisoformat(data["created_at"]),
        )
        runbook.immediate_actions = [ResponseAction(a) for a in data.get("immediate_actions", [])]
        if data.get("last_used_at"):
            runbook.last_used_at = datetime.fromisoformat(data["last_used_at"])
        return runbook


@dataclass
class IncidentResponse:
    """
    A single response action taken during an incident.

    Records what action was taken, when, and by whom.
    """

    response_id: str
    incident_id: str
    action: ResponseAction
    performed_by: str
    performed_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Details
    description: str = ""
    target: str = ""  # What the action was applied to
    success: bool = True
    error_message: str = ""

    # Metadata
    automated: bool = False  # Was this automated or manual
    runbook_step: str = ""  # Which runbook step triggered this

    def to_dict(self) -> dict[str, Any]:
        return {
            "response_id": self.response_id,
            "incident_id": self.incident_id,
            "action": self.action.value,
            "performed_by": self.performed_by,
            "performed_at": self.performed_at.isoformat(),
            "description": self.description,
            "target": self.target,
            "success": self.success,
            "error_message": self.error_message,
            "automated": self.automated,
            "runbook_step": self.runbook_step,
        }


@dataclass
class IncidentRecord:
    """
    Record of a security or operational incident.

    Tracks the full lifecycle of an incident from detection to resolution.
    """

    incident_id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.DETECTED

    # Classification
    category: str = ""  # e.g., "security", "economic", "operational"
    subcategory: str = ""  # More specific classification
    affected_components: list[str] = field(default_factory=list)

    # Timing
    detected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    acknowledged_at: datetime | None = None
    mitigated_at: datetime | None = None
    resolved_at: datetime | None = None
    closed_at: datetime | None = None

    # People
    detected_by: str = ""  # Person or system that detected
    assigned_to: str = ""  # Person handling the incident
    acknowledged_by: str = ""

    # Runbook
    runbook_id: str = ""
    runbook_name: str = ""

    # Responses
    responses: list[IncidentResponse] = field(default_factory=list)

    # Impact
    impact_description: str = ""
    estimated_loss_wei: int = 0
    affected_users_count: int = 0
    affected_tasks_count: int = 0

    # Resolution
    resolution_summary: str = ""
    root_cause: str = ""
    lessons_learned: str = ""

    # Follow-up
    follow_up_issues: list[str] = field(default_factory=list)
    post_mortem_link: str = ""

    @property
    def time_to_acknowledge_minutes(self) -> float | None:
        if not self.acknowledged_at:
            return None
        return (self.acknowledged_at - self.detected_at).total_seconds() / 60

    @property
    def time_to_mitigate_minutes(self) -> float | None:
        if not self.mitigated_at:
            return None
        return (self.mitigated_at - self.detected_at).total_seconds() / 60

    @property
    def time_to_resolve_hours(self) -> float | None:
        if not self.resolved_at:
            return None
        return (self.resolved_at - self.detected_at).total_seconds() / 3600

    @property
    def duration_hours(self) -> float:
        end_time = self.resolved_at or datetime.now(UTC)
        return (end_time - self.detected_at).total_seconds() / 3600

    def acknowledge(self, by: str) -> None:
        """Acknowledge the incident."""
        self.acknowledged_at = datetime.now(UTC)
        self.acknowledged_by = by
        self.status = IncidentStatus.INVESTIGATING
        logger.info(f"Incident {self.incident_id} acknowledged by {by}")

    def assign(self, to: str) -> None:
        """Assign the incident."""
        self.assigned_to = to
        logger.info(f"Incident {self.incident_id} assigned to {to}")

    def start_mitigation(self) -> None:
        """Mark mitigation started."""
        self.status = IncidentStatus.MITIGATING

    def mark_mitigated(self) -> None:
        """Mark the incident as mitigated."""
        self.mitigated_at = datetime.now(UTC)
        self.status = IncidentStatus.MITIGATING
        logger.info(f"Incident {self.incident_id} mitigated")

    def resolve(self, summary: str) -> None:
        """Resolve the incident."""
        self.resolved_at = datetime.now(UTC)
        self.resolution_summary = summary
        self.status = IncidentStatus.RESOLVED
        logger.info(f"Incident {self.incident_id} resolved")

    def close(self, root_cause: str = "", lessons: str = "") -> None:
        """Close the incident after review."""
        self.closed_at = datetime.now(UTC)
        self.root_cause = root_cause
        self.lessons_learned = lessons
        self.status = IncidentStatus.CLOSED
        logger.info(f"Incident {self.incident_id} closed")

    def mark_false_alarm(self, reason: str) -> None:
        """Mark as false alarm."""
        self.resolution_summary = f"False alarm: {reason}"
        self.resolved_at = datetime.now(UTC)
        self.closed_at = datetime.now(UTC)
        self.status = IncidentStatus.FALSE_ALARM
        logger.info(f"Incident {self.incident_id} marked as false alarm")

    def add_response(self, response: IncidentResponse) -> None:
        """Add a response action."""
        self.responses.append(response)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "category": self.category,
            "subcategory": self.subcategory,
            "affected_components": self.affected_components,
            "detected_at": self.detected_at.isoformat(),
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "mitigated_at": self.mitigated_at.isoformat() if self.mitigated_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "detected_by": self.detected_by,
            "assigned_to": self.assigned_to,
            "acknowledged_by": self.acknowledged_by,
            "runbook_id": self.runbook_id,
            "runbook_name": self.runbook_name,
            "responses": [r.to_dict() for r in self.responses],
            "impact_description": self.impact_description,
            "estimated_loss_wei": self.estimated_loss_wei,
            "affected_users_count": self.affected_users_count,
            "affected_tasks_count": self.affected_tasks_count,
            "resolution_summary": self.resolution_summary,
            "root_cause": self.root_cause,
            "lessons_learned": self.lessons_learned,
            "follow_up_issues": self.follow_up_issues,
            "post_mortem_link": self.post_mortem_link,
            "time_to_acknowledge_minutes": self.time_to_acknowledge_minutes,
            "time_to_mitigate_minutes": self.time_to_mitigate_minutes,
            "time_to_resolve_hours": self.time_to_resolve_hours,
            "duration_hours": self.duration_hours,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IncidentRecord:
        record = cls(
            incident_id=data["incident_id"],
            title=data["title"],
            description=data["description"],
            severity=IncidentSeverity(data["severity"]),
            status=IncidentStatus(data["status"]),
            category=data.get("category", ""),
            subcategory=data.get("subcategory", ""),
            affected_components=data.get("affected_components", []),
            detected_at=datetime.fromisoformat(data["detected_at"]),
            detected_by=data.get("detected_by", ""),
            assigned_to=data.get("assigned_to", ""),
            acknowledged_by=data.get("acknowledged_by", ""),
            runbook_id=data.get("runbook_id", ""),
            runbook_name=data.get("runbook_name", ""),
            impact_description=data.get("impact_description", ""),
            estimated_loss_wei=data.get("estimated_loss_wei", 0),
            affected_users_count=data.get("affected_users_count", 0),
            affected_tasks_count=data.get("affected_tasks_count", 0),
            resolution_summary=data.get("resolution_summary", ""),
            root_cause=data.get("root_cause", ""),
            lessons_learned=data.get("lessons_learned", ""),
            follow_up_issues=data.get("follow_up_issues", []),
            post_mortem_link=data.get("post_mortem_link", ""),
        )

        if data.get("acknowledged_at"):
            record.acknowledged_at = datetime.fromisoformat(data["acknowledged_at"])
        if data.get("mitigated_at"):
            record.mitigated_at = datetime.fromisoformat(data["mitigated_at"])
        if data.get("resolved_at"):
            record.resolved_at = datetime.fromisoformat(data["resolved_at"])
        if data.get("closed_at"):
            record.closed_at = datetime.fromisoformat(data["closed_at"])

        return record


class IncidentRegistry:
    """
    Registry for incidents and runbooks.

    Manages incident lifecycle and runbook execution.
    """

    def __init__(self) -> None:
        self._incidents: dict[str, IncidentRecord] = {}
        self._runbooks: dict[str, ResponseRunbook] = {}
        self._by_status: dict[IncidentStatus, list[str]] = {s: [] for s in IncidentStatus}
        self._by_severity: dict[IncidentSeverity, list[str]] = {s: [] for s in IncidentSeverity}

        # Initialize default runbooks
        self._init_default_runbooks()

    def _init_default_runbooks(self) -> None:
        """Initialize default response runbooks."""
        # Security breach runbook
        self.register_runbook(ResponseRunbook(
            runbook_id="security_breach",
            name="Security Breach Response",
            description="Response to detected security breach or unauthorized access",
            severity=IncidentSeverity.P0,
            trigger_conditions=[
                "Unauthorized access detected",
                "Suspicious transaction pattern",
                "Key compromise suspected",
            ],
            immediate_actions=[
                ResponseAction.PAUSE_GLOBAL,
                ResponseAction.ALERT_TEAM,
                ResponseAction.ESCALATE,
            ],
            investigation_steps=[
                "Identify scope of compromise",
                "Review access logs",
                "Identify affected accounts",
                "Document timeline",
            ],
            mitigation_steps=[
                "Revoke compromised credentials",
                "Freeze affected accounts",
                "Deploy security patches",
            ],
            recovery_steps=[
                "Issue new credentials",
                "Restore from known-good state",
                "Verify system integrity",
            ],
            post_incident_steps=[
                "Conduct post-mortem",
                "Update security policies",
                "Implement additional monitoring",
            ],
            response_sla_minutes=15,
            resolution_sla_hours=4,
        ))

        # Economic attack runbook
        self.register_runbook(ResponseRunbook(
            runbook_id="economic_attack",
            name="Economic Attack Response",
            description="Response to economic manipulation or oracle attack",
            severity=IncidentSeverity.P0,
            trigger_conditions=[
                "Price oracle deviation > 10%",
                "Unusual claim pattern",
                "Flash loan detected",
            ],
            immediate_actions=[
                ResponseAction.PAUSE_CLAIMS,
                ResponseAction.PAUSE_COVERAGE,
                ResponseAction.ALERT_TEAM,
            ],
            investigation_steps=[
                "Analyze transaction patterns",
                "Verify oracle prices",
                "Identify attacker addresses",
            ],
            mitigation_steps=[
                "Blacklist attacker addresses",
                "Adjust oracle parameters",
                "Enable stricter validation",
            ],
            response_sla_minutes=30,
            resolution_sla_hours=8,
        ))

        # Circuit breaker runbook
        self.register_runbook(ResponseRunbook(
            runbook_id="circuit_breaker",
            name="Circuit Breaker Response",
            description="Response when circuit breaker is triggered",
            severity=IncidentSeverity.P1,
            trigger_conditions=[
                "Loss rate exceeds threshold",
                "Dispute rate exceeds threshold",
                "Consecutive losses exceed limit",
            ],
            immediate_actions=[
                ResponseAction.ALERT_TEAM,
                ResponseAction.MONITOR,
            ],
            investigation_steps=[
                "Analyze loss pattern",
                "Review disputed tasks",
                "Identify root cause",
            ],
            mitigation_steps=[
                "Adjust pricing parameters",
                "Update risk models",
                "Review verifier performance",
            ],
            response_sla_minutes=60,
            resolution_sla_hours=24,
        ))

    def register_runbook(self, runbook: ResponseRunbook) -> None:
        """Register a response runbook."""
        self._runbooks[runbook.runbook_id] = runbook
        logger.info(f"Registered runbook: {runbook.runbook_id} - {runbook.name}")

    def get_runbook(self, runbook_id: str) -> ResponseRunbook | None:
        """Get a runbook by ID."""
        return self._runbooks.get(runbook_id)

    def get_runbook_for_severity(self, severity: IncidentSeverity) -> list[ResponseRunbook]:
        """Get all runbooks for a severity level."""
        return [r for r in self._runbooks.values() if r.severity == severity]

    def create_incident(
        self,
        title: str,
        description: str,
        severity: IncidentSeverity,
        detected_by: str,
        category: str = "",
        runbook_id: str = "",
    ) -> IncidentRecord:
        """
        Create a new incident record.

        Args:
            title: Incident title
            description: Incident description
            severity: Severity level
            detected_by: Who/what detected the incident
            category: Incident category
            runbook_id: Optional runbook to associate

        Returns:
            The created incident record
        """
        incident_id = f"inc_{datetime.now(UTC).strftime('%Y%m%d%H%M%S%f')}_{severity.value}"
        incident = IncidentRecord(
            incident_id=incident_id,
            title=title,
            description=description,
            severity=severity,
            detected_by=detected_by,
            category=category,
        )

        if runbook_id:
            runbook = self._runbooks.get(runbook_id)
            if runbook:
                incident.runbook_id = runbook_id
                incident.runbook_name = runbook.name
                runbook.last_used_at = datetime.now(UTC)

        self._incidents[incident_id] = incident
        self._by_status[IncidentStatus.DETECTED].append(incident_id)
        self._by_severity[severity].append(incident_id)

        logger.warning(f"Incident created: {incident_id} - {title} ({severity.value})")
        return incident

    def get_incident(self, incident_id: str) -> IncidentRecord | None:
        """Get an incident by ID."""
        return self._incidents.get(incident_id)

    def get_active_incidents(self) -> list[IncidentRecord]:
        """Get all non-closed incidents."""
        return [
            i for i in self._incidents.values()
            if i.status not in (IncidentStatus.CLOSED, IncidentStatus.FALSE_ALARM)
        ]

    def get_by_severity(self, severity: IncidentSeverity) -> list[IncidentRecord]:
        """Get all incidents of a severity level."""
        incident_ids = self._by_severity.get(severity, [])
        return [self._incidents[iid] for iid in incident_ids if iid in self._incidents]

    def update_status(self, incident_id: str, new_status: IncidentStatus) -> IncidentRecord | None:
        """Update incident status."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return None

        old_status = incident.status
        incident.status = new_status

        # Update indexes
        if incident_id in self._by_status[old_status]:
            self._by_status[old_status].remove(incident_id)
        self._by_status[new_status].append(incident_id)

        return incident

    def record_response(
        self,
        incident_id: str,
        action: ResponseAction,
        performed_by: str,
        description: str = "",
        target: str = "",
        automated: bool = False,
    ) -> IncidentResponse | None:
        """
        Record a response action for an incident.

        Args:
            incident_id: Incident ID
            action: Action taken
            performed_by: Who performed the action
            description: Description of what was done
            target: What the action was applied to
            automated: Whether this was automated

        Returns:
            The recorded response
        """
        incident = self._incidents.get(incident_id)
        if not incident:
            return None

        response_id = f"resp_{incident_id}_{len(incident.responses) + 1}"
        response = IncidentResponse(
            response_id=response_id,
            incident_id=incident_id,
            action=action,
            performed_by=performed_by,
            description=description,
            target=target,
            automated=automated,
        )

        incident.add_response(response)
        logger.info(f"Response recorded for {incident_id}: {action.value}")
        return response

    def get_metrics(self) -> dict[str, Any]:
        """Get incident metrics."""
        total = len(self._incidents)
        active = len(self.get_active_incidents())
        by_severity = {s.value: len(ids) for s, ids in self._by_severity.items()}
        by_status = {s.value: len(ids) for s, ids in self._by_status.items()}

        # Calculate average response times
        resolved = [i for i in self._incidents.values() if i.resolved_at]
        avg_resolve_hours = 0.0
        if resolved:
            avg_resolve_hours = sum(i.time_to_resolve_hours or 0 for i in resolved) / len(resolved)

        return {
            "total_incidents": total,
            "active_incidents": active,
            "by_severity": by_severity,
            "by_status": by_status,
            "avg_resolution_hours": round(avg_resolve_hours, 2),
            "runbook_count": len(self._runbooks),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "incidents": {k: v.to_dict() for k, v in self._incidents.items()},
            "runbooks": {k: v.to_dict() for k, v in self._runbooks.items()},
            "metrics": self.get_metrics(),
        }
