from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.platform_finding_summary_latest_rehearsal import PlatformFindingSummaryLatestRehearsal
    from ..models.platform_finding_summary_related_incident_providence_reconciliation import (
        PlatformFindingSummaryRelatedIncidentProvidenceReconciliation,
    )
    from ..models.swarm_finding_envelope import SwarmFindingEnvelope


T = TypeVar("T", bound="PlatformFindingSummary")


@_attrs_define
class PlatformFindingSummary:
    """
    Attributes:
        bundle_id (str):
        created_at_ms (int):
        finding (SwarmFindingEnvelope):
        hunt_id (str):
        related_receipt_ids (list[str]):
        response_kind (str):
        trail_id (str):
        host_id (str | Unset):
        latest_rehearsal (PlatformFindingSummaryLatestRehearsal | Unset): Latest rehearsal preview for the hunt.
        latest_rehearsal_bundle_id (str | Unset):
        related_incident_id (str | Unset):
        related_incident_providence_reconciliation (PlatformFindingSummaryRelatedIncidentProvidenceReconciliation |
            Unset): Latest Providence reconciliation state for the related incident.
        related_incident_summary (str | Unset):
        response_receipt_id (str | Unset):
    """

    bundle_id: str
    created_at_ms: int
    finding: SwarmFindingEnvelope
    hunt_id: str
    related_receipt_ids: list[str]
    response_kind: str
    trail_id: str
    host_id: str | Unset = UNSET
    latest_rehearsal: PlatformFindingSummaryLatestRehearsal | Unset = UNSET
    latest_rehearsal_bundle_id: str | Unset = UNSET
    related_incident_id: str | Unset = UNSET
    related_incident_providence_reconciliation: (
        PlatformFindingSummaryRelatedIncidentProvidenceReconciliation | Unset
    ) = UNSET
    related_incident_summary: str | Unset = UNSET
    response_receipt_id: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        bundle_id = self.bundle_id

        created_at_ms = self.created_at_ms

        finding = self.finding.to_dict()

        hunt_id = self.hunt_id

        related_receipt_ids = self.related_receipt_ids

        response_kind = self.response_kind

        trail_id = self.trail_id

        host_id = self.host_id

        latest_rehearsal: dict[str, Any] | Unset = UNSET
        if not isinstance(self.latest_rehearsal, Unset):
            latest_rehearsal = self.latest_rehearsal.to_dict()

        latest_rehearsal_bundle_id = self.latest_rehearsal_bundle_id

        related_incident_id = self.related_incident_id

        related_incident_providence_reconciliation: dict[str, Any] | Unset = UNSET
        if not isinstance(self.related_incident_providence_reconciliation, Unset):
            related_incident_providence_reconciliation = self.related_incident_providence_reconciliation.to_dict()

        related_incident_summary = self.related_incident_summary

        response_receipt_id = self.response_receipt_id

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "bundle_id": bundle_id,
                "created_at_ms": created_at_ms,
                "finding": finding,
                "hunt_id": hunt_id,
                "related_receipt_ids": related_receipt_ids,
                "response_kind": response_kind,
                "trail_id": trail_id,
            }
        )
        if host_id is not UNSET:
            field_dict["host_id"] = host_id
        if latest_rehearsal is not UNSET:
            field_dict["latest_rehearsal"] = latest_rehearsal
        if latest_rehearsal_bundle_id is not UNSET:
            field_dict["latest_rehearsal_bundle_id"] = latest_rehearsal_bundle_id
        if related_incident_id is not UNSET:
            field_dict["related_incident_id"] = related_incident_id
        if related_incident_providence_reconciliation is not UNSET:
            field_dict["related_incident_providence_reconciliation"] = related_incident_providence_reconciliation
        if related_incident_summary is not UNSET:
            field_dict["related_incident_summary"] = related_incident_summary
        if response_receipt_id is not UNSET:
            field_dict["response_receipt_id"] = response_receipt_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.platform_finding_summary_latest_rehearsal import PlatformFindingSummaryLatestRehearsal
        from ..models.platform_finding_summary_related_incident_providence_reconciliation import (
            PlatformFindingSummaryRelatedIncidentProvidenceReconciliation,
        )
        from ..models.swarm_finding_envelope import SwarmFindingEnvelope

        d = dict(src_dict)
        bundle_id = d.pop("bundle_id")

        created_at_ms = d.pop("created_at_ms")

        finding = SwarmFindingEnvelope.from_dict(d.pop("finding"))

        hunt_id = d.pop("hunt_id")

        related_receipt_ids = cast(list[str], d.pop("related_receipt_ids"))

        response_kind = d.pop("response_kind")

        trail_id = d.pop("trail_id")

        host_id = d.pop("host_id", UNSET)

        _latest_rehearsal = d.pop("latest_rehearsal", UNSET)
        latest_rehearsal: PlatformFindingSummaryLatestRehearsal | Unset
        if isinstance(_latest_rehearsal, Unset):
            latest_rehearsal = UNSET
        else:
            latest_rehearsal = PlatformFindingSummaryLatestRehearsal.from_dict(_latest_rehearsal)

        latest_rehearsal_bundle_id = d.pop("latest_rehearsal_bundle_id", UNSET)

        related_incident_id = d.pop("related_incident_id", UNSET)

        _related_incident_providence_reconciliation = d.pop("related_incident_providence_reconciliation", UNSET)
        related_incident_providence_reconciliation: (
            PlatformFindingSummaryRelatedIncidentProvidenceReconciliation | Unset
        )
        if isinstance(_related_incident_providence_reconciliation, Unset):
            related_incident_providence_reconciliation = UNSET
        else:
            related_incident_providence_reconciliation = (
                PlatformFindingSummaryRelatedIncidentProvidenceReconciliation.from_dict(
                    _related_incident_providence_reconciliation
                )
            )

        related_incident_summary = d.pop("related_incident_summary", UNSET)

        response_receipt_id = d.pop("response_receipt_id", UNSET)

        platform_finding_summary = cls(
            bundle_id=bundle_id,
            created_at_ms=created_at_ms,
            finding=finding,
            hunt_id=hunt_id,
            related_receipt_ids=related_receipt_ids,
            response_kind=response_kind,
            trail_id=trail_id,
            host_id=host_id,
            latest_rehearsal=latest_rehearsal,
            latest_rehearsal_bundle_id=latest_rehearsal_bundle_id,
            related_incident_id=related_incident_id,
            related_incident_providence_reconciliation=related_incident_providence_reconciliation,
            related_incident_summary=related_incident_summary,
            response_receipt_id=response_receipt_id,
        )

        return platform_finding_summary
