from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define

from ..models.platform_asset_posture_escalation_level import PlatformAssetPostureEscalationLevel

if TYPE_CHECKING:
    from ..models.platform_finding_summary import PlatformFindingSummary
    from ..models.platform_investigation_summary import PlatformInvestigationSummary
    from ..models.platform_threat_concentration_summary import PlatformThreatConcentrationSummary


T = TypeVar("T", bound="PlatformAssetPosture")


@_attrs_define
class PlatformAssetPosture:
    """
    Attributes:
        active_investigations (list[PlatformInvestigationSummary]):
        captured_at_ms (int):
        escalation_level (PlatformAssetPostureEscalationLevel):
        host_id (str):
        recent_findings (list[PlatformFindingSummary]):
        threat_concentrations (list[PlatformThreatConcentrationSummary]):
    """

    active_investigations: list[PlatformInvestigationSummary]
    captured_at_ms: int
    escalation_level: PlatformAssetPostureEscalationLevel
    host_id: str
    recent_findings: list[PlatformFindingSummary]
    threat_concentrations: list[PlatformThreatConcentrationSummary]

    def to_dict(self) -> dict[str, Any]:
        active_investigations = []
        for active_investigations_item_data in self.active_investigations:
            active_investigations_item = active_investigations_item_data.to_dict()
            active_investigations.append(active_investigations_item)

        captured_at_ms = self.captured_at_ms

        escalation_level = self.escalation_level.value

        host_id = self.host_id

        recent_findings = []
        for recent_findings_item_data in self.recent_findings:
            recent_findings_item = recent_findings_item_data.to_dict()
            recent_findings.append(recent_findings_item)

        threat_concentrations = []
        for threat_concentrations_item_data in self.threat_concentrations:
            threat_concentrations_item = threat_concentrations_item_data.to_dict()
            threat_concentrations.append(threat_concentrations_item)

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "active_investigations": active_investigations,
                "captured_at_ms": captured_at_ms,
                "escalation_level": escalation_level,
                "host_id": host_id,
                "recent_findings": recent_findings,
                "threat_concentrations": threat_concentrations,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.platform_finding_summary import PlatformFindingSummary
        from ..models.platform_investigation_summary import PlatformInvestigationSummary
        from ..models.platform_threat_concentration_summary import PlatformThreatConcentrationSummary

        d = dict(src_dict)
        active_investigations = []
        _active_investigations = d.pop("active_investigations")
        for active_investigations_item_data in _active_investigations:
            active_investigations_item = PlatformInvestigationSummary.from_dict(active_investigations_item_data)

            active_investigations.append(active_investigations_item)

        captured_at_ms = d.pop("captured_at_ms")

        escalation_level = PlatformAssetPostureEscalationLevel(d.pop("escalation_level"))

        host_id = d.pop("host_id")

        recent_findings = []
        _recent_findings = d.pop("recent_findings")
        for recent_findings_item_data in _recent_findings:
            recent_findings_item = PlatformFindingSummary.from_dict(recent_findings_item_data)

            recent_findings.append(recent_findings_item)

        threat_concentrations = []
        _threat_concentrations = d.pop("threat_concentrations")
        for threat_concentrations_item_data in _threat_concentrations:
            threat_concentrations_item = PlatformThreatConcentrationSummary.from_dict(threat_concentrations_item_data)

            threat_concentrations.append(threat_concentrations_item)

        platform_asset_posture = cls(
            active_investigations=active_investigations,
            captured_at_ms=captured_at_ms,
            escalation_level=escalation_level,
            host_id=host_id,
            recent_findings=recent_findings,
            threat_concentrations=threat_concentrations,
        )

        return platform_asset_posture
