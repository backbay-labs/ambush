from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

T = TypeVar("T", bound="BridgeStatusSnapshot")


@_attrs_define
class BridgeStatusSnapshot:
    """
    Attributes:
        error_count (int):
        events_processed (int):
        name (str):
        ready (bool):
        source_id (str):
        lag_seconds (float | Unset):
        last_error (str | Unset):
    """

    error_count: int
    events_processed: int
    name: str
    ready: bool
    source_id: str
    lag_seconds: float | Unset = UNSET
    last_error: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        error_count = self.error_count

        events_processed = self.events_processed

        name = self.name

        ready = self.ready

        source_id = self.source_id

        lag_seconds = self.lag_seconds

        last_error = self.last_error

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "error_count": error_count,
                "events_processed": events_processed,
                "name": name,
                "ready": ready,
                "source_id": source_id,
            }
        )
        if lag_seconds is not UNSET:
            field_dict["lag_seconds"] = lag_seconds
        if last_error is not UNSET:
            field_dict["last_error"] = last_error

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        error_count = d.pop("error_count")

        events_processed = d.pop("events_processed")

        name = d.pop("name")

        ready = d.pop("ready")

        source_id = d.pop("source_id")

        lag_seconds = d.pop("lag_seconds", UNSET)

        last_error = d.pop("last_error", UNSET)

        bridge_status_snapshot = cls(
            error_count=error_count,
            events_processed=events_processed,
            name=name,
            ready=ready,
            source_id=source_id,
            lag_seconds=lag_seconds,
            last_error=last_error,
        )

        return bridge_status_snapshot
