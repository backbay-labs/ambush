"""
DeliverableManager - Standardized finding flow between engagement phases.

Operators produce Deliverables (structured findings) which are validated
against schemas, written to the TargetGraph as nodes/edges, and made
available as context for downstream operators via PromptEngine.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

from hellcat.core.deliverables.schemas import DELIVERABLE_SCHEMAS, validate_against_schema
from hellcat.offensive.target_graph.graph import TargetGraph
from hellcat.offensive.target_graph.models import (
    CredentialType,
    DefenseType,
    Severity,
)

logger = structlog.get_logger()


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


class DeliverableType(str, enum.Enum):
    VULN_FINDING = "vuln_finding"
    EXPLOIT_RESULT = "exploit_result"
    CREDENTIAL = "credential"
    DEFENSE_OBSERVATION = "defense_observation"
    ENDPOINT = "endpoint"
    PHISHING_RESULT = "phishing_result"


@dataclass
class Deliverable:
    """A structured finding produced by an operator."""

    type: DeliverableType
    operator_name: str
    cell_id: str
    data: dict[str, Any]
    schema_version: str = "1.0"
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=_utc_now)
    phase: str = ""
    node_id: str | None = None  # set after ingestion into TargetGraph


class DeliverableManager:
    """
    Manages the lifecycle of operator deliverables:
    submit -> validate -> ingest into TargetGraph -> retrieve for context.
    """

    def __init__(self, graph: TargetGraph) -> None:
        self.graph = graph
        self._deliverables: list[Deliverable] = []

    def submit(self, deliverable: Deliverable) -> Deliverable:
        """Validate a deliverable against its schema and write to TargetGraph.

        Returns the deliverable with ``node_id`` set after ingestion.

        Raises:
            ValueError: If validation fails.
        """
        errors = self.validate(deliverable)
        if errors:
            raise ValueError(
                f"Deliverable validation failed for {deliverable.type.value}: "
                + "; ".join(errors)
            )

        node_id = self._ingest(deliverable)
        deliverable.node_id = node_id
        self._deliverables.append(deliverable)

        logger.info(
            "deliverable.submitted",
            type=deliverable.type.value,
            operator=deliverable.operator_name,
            cell_id=deliverable.cell_id,
            node_id=node_id,
        )

        return deliverable

    def validate(self, deliverable: Deliverable) -> list[str]:
        """Validate a deliverable against its type schema."""
        schema = DELIVERABLE_SCHEMAS.get(deliverable.type.value)
        if schema is None:
            return [f"Unknown deliverable type: {deliverable.type.value}"]
        return validate_against_schema(deliverable.data, schema)

    def get_for_phase(self, phase: str) -> list[Deliverable]:
        """Retrieve deliverables from a specific phase."""
        return [d for d in self._deliverables if d.phase == phase]

    def get_all(self) -> list[Deliverable]:
        """Retrieve all submitted deliverables."""
        return list(self._deliverables)

    def get_by_type(self, dtype: DeliverableType) -> list[Deliverable]:
        """Retrieve deliverables of a specific type."""
        return [d for d in self._deliverables if d.type == dtype]

    def to_prompt_context(self, deliverables: list[Deliverable]) -> str:
        """Format deliverables as structured text for PromptEngine's {{PRIOR_FINDINGS}}.

        Groups by type and renders each as a concise block for LLM consumption.
        """
        if not deliverables:
            return ""

        sections: list[str] = []
        sections.append("<prior_findings>")
        sections.append(f"## Intelligence from Prior Phases ({len(deliverables)} findings)")

        # Group by type for clarity
        by_type: dict[str, list[Deliverable]] = {}
        for d in deliverables:
            by_type.setdefault(d.type.value, []).append(d)

        for dtype, items in by_type.items():
            sections.append(f"\n### {dtype.replace('_', ' ').title()} ({len(items)})")
            for i, d in enumerate(items, 1):
                sections.append(f"\n#### Finding {i} (from {d.operator_name})")
                for key, val in d.data.items():
                    if val and key != "data_extracted":
                        sections.append(f"- {key}: {val}")

        sections.append("</prior_findings>")
        return "\n".join(sections)

    def _ingest(self, deliverable: Deliverable) -> str:
        """Write a deliverable into the TargetGraph as the appropriate node type."""
        data = deliverable.data
        meta = {
            "deliverable_id": deliverable.id,
            "operator": deliverable.operator_name,
            "cell_id": deliverable.cell_id,
            "schema_version": deliverable.schema_version,
        }

        if deliverable.type == DeliverableType.VULN_FINDING:
            return self._ingest_vuln_finding(data, meta)

        if deliverable.type == DeliverableType.EXPLOIT_RESULT:
            return self._ingest_exploit_result(data, meta)

        if deliverable.type == DeliverableType.CREDENTIAL:
            return self._ingest_credential(data, meta)

        if deliverable.type == DeliverableType.DEFENSE_OBSERVATION:
            return self._ingest_defense_observation(data, meta)

        if deliverable.type == DeliverableType.ENDPOINT:
            return self._ingest_endpoint(data, meta)

        if deliverable.type == DeliverableType.PHISHING_RESULT:
            return deliverable.id

        raise ValueError(f"Unknown deliverable type: {deliverable.type}")

    def _ingest_vuln_finding(
        self, data: dict[str, Any], meta: dict[str, Any],
    ) -> str:
        severity_map = {
            "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
            "high": Severity.HIGH, "critical": Severity.CRITICAL,
        }
        if data.get("attack_tid"):
            meta["attack_tid"] = data["attack_tid"]
        if data.get("attack_tactic"):
            meta["attack_tactic"] = data["attack_tactic"]
        node = self.graph.add_vulnerability(
            vuln_type=data["vuln_type"],
            severity=severity_map.get(data.get("severity", "medium"), Severity.MEDIUM),
            confidence=float(data.get("confidence", 0.5)),
            cvss=data.get("cvss"),
            description=data.get("description", ""),
            source_location=data.get("endpoint", ""),
            metadata=meta,
        )
        return node.id

    def _ingest_exploit_result(
        self, data: dict[str, Any], meta: dict[str, Any],
    ) -> str:
        node = self.graph.add_vulnerability(
            vuln_type=data["vuln_type"],
            severity=Severity.HIGH,
            confidence=0.9,
            description=data.get("impact_description", ""),
            source_location="",
            witness_payload=data.get("payload", ""),
            metadata={**meta, "proof_level": data.get("proof_level", "L1")},
        )
        return node.id

    def _ingest_credential(
        self, data: dict[str, Any], meta: dict[str, Any],
    ) -> str:
        cred_type_str = data.get("credential_type", "password")
        try:
            cred_type = CredentialType(cred_type_str)
        except ValueError:
            cred_type = CredentialType.PASSWORD

        node = self.graph.add_credential(
            username=data["username"],
            credential_type=cred_type,
            source=data.get("source", ""),
            access_level=data.get("access_level", ""),
            metadata=meta,
        )
        return node.id

    def _ingest_defense_observation(
        self, data: dict[str, Any], meta: dict[str, Any],
    ) -> str:
        try:
            defense_type = DefenseType(data["defense_type"])
        except ValueError:
            defense_type = DefenseType.WAF

        node = self.graph.add_defense(
            defense_type=defense_type,
            strength=data.get("strength", "unknown"),
            observed_behavior=data.get("observed_behavior", ""),
            metadata=meta,
        )
        return node.id

    def _ingest_endpoint(
        self, data: dict[str, Any], meta: dict[str, Any],
    ) -> str:
        node = self.graph.add_target(
            url=data["url"],
            method=data.get("method", "GET"),
            tech_stack=data.get("tech_stack", ""),
            description=data.get("description", ""),
            metadata=meta,
        )
        return node.id
