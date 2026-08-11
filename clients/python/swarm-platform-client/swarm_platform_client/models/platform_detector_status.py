from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

T = TypeVar("T", bound="PlatformDetectorStatus")


@_attrs_define
class PlatformDetectorStatus:
    """
    Attributes:
        details (str):
        ready (bool):
        strategy (str):
    """

    details: str
    ready: bool
    strategy: str

    def to_dict(self) -> dict[str, Any]:
        details = self.details

        ready = self.ready

        strategy = self.strategy

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "details": details,
                "ready": ready,
                "strategy": strategy,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        details = d.pop("details")

        ready = d.pop("ready")

        strategy = d.pop("strategy")

        platform_detector_status = cls(
            details=details,
            ready=ready,
            strategy=strategy,
        )

        return platform_detector_status
