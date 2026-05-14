from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define

from ..models.swarm_finding_envelope_severity import SwarmFindingEnvelopeSeverity

if TYPE_CHECKING:
    from ..models.swarm_finding_envelope_evidence import SwarmFindingEnvelopeEvidence


T = TypeVar("T", bound="SwarmFindingEnvelope")


@_attrs_define
class SwarmFindingEnvelope:
    """
    Attributes:
        confidence (float):
        event_id (str):
        evidence (SwarmFindingEnvelopeEvidence): Strategy-specific evidence payload.
        finding_id (str):
        schema (str):
        severity (SwarmFindingEnvelopeSeverity):
        strategy_id (str):
        threat_class (str):
    """

    confidence: float
    event_id: str
    evidence: SwarmFindingEnvelopeEvidence
    finding_id: str
    schema: str
    severity: SwarmFindingEnvelopeSeverity
    strategy_id: str
    threat_class: str

    def to_dict(self) -> dict[str, Any]:
        confidence = self.confidence

        event_id = self.event_id

        evidence = self.evidence.to_dict()

        finding_id = self.finding_id

        schema = self.schema

        severity = self.severity.value

        strategy_id = self.strategy_id

        threat_class = self.threat_class

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "confidence": confidence,
                "event_id": event_id,
                "evidence": evidence,
                "finding_id": finding_id,
                "schema": schema,
                "severity": severity,
                "strategy_id": strategy_id,
                "threat_class": threat_class,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.swarm_finding_envelope_evidence import SwarmFindingEnvelopeEvidence

        d = dict(src_dict)
        confidence = d.pop("confidence")

        event_id = d.pop("event_id")

        evidence = SwarmFindingEnvelopeEvidence.from_dict(d.pop("evidence"))

        finding_id = d.pop("finding_id")

        schema = d.pop("schema")

        severity = SwarmFindingEnvelopeSeverity(d.pop("severity"))

        strategy_id = d.pop("strategy_id")

        threat_class = d.pop("threat_class")

        swarm_finding_envelope = cls(
            confidence=confidence,
            event_id=event_id,
            evidence=evidence,
            finding_id=finding_id,
            schema=schema,
            severity=severity,
            strategy_id=strategy_id,
            threat_class=threat_class,
        )

        return swarm_finding_envelope
