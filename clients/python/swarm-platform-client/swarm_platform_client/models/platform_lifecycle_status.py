from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

T = TypeVar("T", bound="PlatformLifecycleStatus")


@_attrs_define
class PlatformLifecycleStatus:
    """
    Attributes:
        active_requests (int):
        draining (bool):
    """

    active_requests: int
    draining: bool

    def to_dict(self) -> dict[str, Any]:
        active_requests = self.active_requests

        draining = self.draining

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "active_requests": active_requests,
                "draining": draining,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        active_requests = d.pop("active_requests")

        draining = d.pop("draining")

        platform_lifecycle_status = cls(
            active_requests=active_requests,
            draining=draining,
        )

        return platform_lifecycle_status
