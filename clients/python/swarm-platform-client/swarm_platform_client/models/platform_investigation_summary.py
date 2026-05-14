from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="PlatformInvestigationSummary")


@_attrs_define
class PlatformInvestigationSummary:
    """
    Attributes:
        correlation_keys (list[str]):
        finding_id (str):
        hunt_id (str):
        investigation_id (str):
        last_updated_ms (int):
        queued_at_ms (int):
        response_kind (str):
        status (str):
        summary_preview (str | Unset):
    """

    correlation_keys: list[str]
    finding_id: str
    hunt_id: str
    investigation_id: str
    last_updated_ms: int
    queued_at_ms: int
    response_kind: str
    status: str
    summary_preview: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        correlation_keys = self.correlation_keys

        finding_id = self.finding_id

        hunt_id = self.hunt_id

        investigation_id = self.investigation_id

        last_updated_ms = self.last_updated_ms

        queued_at_ms = self.queued_at_ms

        response_kind = self.response_kind

        status = self.status

        summary_preview = self.summary_preview

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "correlation_keys": correlation_keys,
                "finding_id": finding_id,
                "hunt_id": hunt_id,
                "investigation_id": investigation_id,
                "last_updated_ms": last_updated_ms,
                "queued_at_ms": queued_at_ms,
                "response_kind": response_kind,
                "status": status,
            }
        )
        if summary_preview is not UNSET:
            field_dict["summary_preview"] = summary_preview

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        correlation_keys = cast(list[str], d.pop("correlation_keys"))

        finding_id = d.pop("finding_id")

        hunt_id = d.pop("hunt_id")

        investigation_id = d.pop("investigation_id")

        last_updated_ms = d.pop("last_updated_ms")

        queued_at_ms = d.pop("queued_at_ms")

        response_kind = d.pop("response_kind")

        status = d.pop("status")

        summary_preview = d.pop("summary_preview", UNSET)

        platform_investigation_summary = cls(
            correlation_keys=correlation_keys,
            finding_id=finding_id,
            hunt_id=hunt_id,
            investigation_id=investigation_id,
            last_updated_ms=last_updated_ms,
            queued_at_ms=queued_at_ms,
            response_kind=response_kind,
            status=status,
            summary_preview=summary_preview,
        )

        return platform_investigation_summary
