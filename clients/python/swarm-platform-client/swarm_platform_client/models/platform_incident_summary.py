from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.platform_incident_summary_latest_rehearsal import PlatformIncidentSummaryLatestRehearsal
    from ..models.platform_incident_summary_providence_reconciliation import (
        PlatformIncidentSummaryProvidenceReconciliation,
    )


T = TypeVar("T", bound="PlatformIncidentSummary")


@_attrs_define
class PlatformIncidentSummary:
    """
    Attributes:
        correlation_keys (list[str]):
        created_at_ms (int):
        incident_id (str):
        included_hunt_ids (list[str]):
        included_investigation_ids (list[str]):
        related_receipt_ids (list[str]):
        summary (str):
        latest_rehearsal (PlatformIncidentSummaryLatestRehearsal | Unset): Latest rehearsal preview linked to the
            incident.
        latest_rehearsal_bundle_id (str | Unset):
        latest_rehearsal_hunt_id (str | Unset):
        providence_reconciliation (PlatformIncidentSummaryProvidenceReconciliation | Unset): Providence reconciliation
            state for the incident.
    """

    correlation_keys: list[str]
    created_at_ms: int
    incident_id: str
    included_hunt_ids: list[str]
    included_investigation_ids: list[str]
    related_receipt_ids: list[str]
    summary: str
    latest_rehearsal: PlatformIncidentSummaryLatestRehearsal | Unset = UNSET
    latest_rehearsal_bundle_id: str | Unset = UNSET
    latest_rehearsal_hunt_id: str | Unset = UNSET
    providence_reconciliation: PlatformIncidentSummaryProvidenceReconciliation | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        correlation_keys = self.correlation_keys

        created_at_ms = self.created_at_ms

        incident_id = self.incident_id

        included_hunt_ids = self.included_hunt_ids

        included_investigation_ids = self.included_investigation_ids

        related_receipt_ids = self.related_receipt_ids

        summary = self.summary

        latest_rehearsal: dict[str, Any] | Unset = UNSET
        if not isinstance(self.latest_rehearsal, Unset):
            latest_rehearsal = self.latest_rehearsal.to_dict()

        latest_rehearsal_bundle_id = self.latest_rehearsal_bundle_id

        latest_rehearsal_hunt_id = self.latest_rehearsal_hunt_id

        providence_reconciliation: dict[str, Any] | Unset = UNSET
        if not isinstance(self.providence_reconciliation, Unset):
            providence_reconciliation = self.providence_reconciliation.to_dict()

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "correlation_keys": correlation_keys,
                "created_at_ms": created_at_ms,
                "incident_id": incident_id,
                "included_hunt_ids": included_hunt_ids,
                "included_investigation_ids": included_investigation_ids,
                "related_receipt_ids": related_receipt_ids,
                "summary": summary,
            }
        )
        if latest_rehearsal is not UNSET:
            field_dict["latest_rehearsal"] = latest_rehearsal
        if latest_rehearsal_bundle_id is not UNSET:
            field_dict["latest_rehearsal_bundle_id"] = latest_rehearsal_bundle_id
        if latest_rehearsal_hunt_id is not UNSET:
            field_dict["latest_rehearsal_hunt_id"] = latest_rehearsal_hunt_id
        if providence_reconciliation is not UNSET:
            field_dict["providence_reconciliation"] = providence_reconciliation

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.platform_incident_summary_latest_rehearsal import PlatformIncidentSummaryLatestRehearsal
        from ..models.platform_incident_summary_providence_reconciliation import (
            PlatformIncidentSummaryProvidenceReconciliation,
        )

        d = dict(src_dict)
        correlation_keys = cast(list[str], d.pop("correlation_keys"))

        created_at_ms = d.pop("created_at_ms")

        incident_id = d.pop("incident_id")

        included_hunt_ids = cast(list[str], d.pop("included_hunt_ids"))

        included_investigation_ids = cast(list[str], d.pop("included_investigation_ids"))

        related_receipt_ids = cast(list[str], d.pop("related_receipt_ids"))

        summary = d.pop("summary")

        _latest_rehearsal = d.pop("latest_rehearsal", UNSET)
        latest_rehearsal: PlatformIncidentSummaryLatestRehearsal | Unset
        if isinstance(_latest_rehearsal, Unset):
            latest_rehearsal = UNSET
        else:
            latest_rehearsal = PlatformIncidentSummaryLatestRehearsal.from_dict(_latest_rehearsal)

        latest_rehearsal_bundle_id = d.pop("latest_rehearsal_bundle_id", UNSET)

        latest_rehearsal_hunt_id = d.pop("latest_rehearsal_hunt_id", UNSET)

        _providence_reconciliation = d.pop("providence_reconciliation", UNSET)
        providence_reconciliation: PlatformIncidentSummaryProvidenceReconciliation | Unset
        if isinstance(_providence_reconciliation, Unset):
            providence_reconciliation = UNSET
        else:
            providence_reconciliation = PlatformIncidentSummaryProvidenceReconciliation.from_dict(
                _providence_reconciliation
            )

        platform_incident_summary = cls(
            correlation_keys=correlation_keys,
            created_at_ms=created_at_ms,
            incident_id=incident_id,
            included_hunt_ids=included_hunt_ids,
            included_investigation_ids=included_investigation_ids,
            related_receipt_ids=related_receipt_ids,
            summary=summary,
            latest_rehearsal=latest_rehearsal,
            latest_rehearsal_bundle_id=latest_rehearsal_bundle_id,
            latest_rehearsal_hunt_id=latest_rehearsal_hunt_id,
            providence_reconciliation=providence_reconciliation,
        )

        return platform_incident_summary
