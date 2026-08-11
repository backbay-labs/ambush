from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define

if TYPE_CHECKING:
    from ..models.bridge_status_snapshot import BridgeStatusSnapshot


T = TypeVar("T", bound="BridgeStatusReport")


@_attrs_define
class BridgeStatusReport:
    """
    Attributes:
        configured (int):
        degraded (int):
        entries (list[BridgeStatusSnapshot]):
        idle (int):
        ok (int):
    """

    configured: int
    degraded: int
    entries: list[BridgeStatusSnapshot]
    idle: int
    ok: int

    def to_dict(self) -> dict[str, Any]:
        configured = self.configured

        degraded = self.degraded

        entries = []
        for entries_item_data in self.entries:
            entries_item = entries_item_data.to_dict()
            entries.append(entries_item)

        idle = self.idle

        ok = self.ok

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "configured": configured,
                "degraded": degraded,
                "entries": entries,
                "idle": idle,
                "ok": ok,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.bridge_status_snapshot import BridgeStatusSnapshot

        d = dict(src_dict)
        configured = d.pop("configured")

        degraded = d.pop("degraded")

        entries = []
        _entries = d.pop("entries")
        for entries_item_data in _entries:
            entries_item = BridgeStatusSnapshot.from_dict(entries_item_data)

            entries.append(entries_item)

        idle = d.pop("idle")

        ok = d.pop("ok")

        bridge_status_report = cls(
            configured=configured,
            degraded=degraded,
            entries=entries,
            idle=idle,
            ok=ok,
        )

        return bridge_status_report
