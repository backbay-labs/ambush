from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.platform_asset_posture import PlatformAssetPosture


T = TypeVar("T", bound="PlatformAssetPosturePage")


@_attrs_define
class PlatformAssetPosturePage:
    """
    Attributes:
        data (list[PlatformAssetPosture]):
        schema_version (int):  Default: 1.
        cursor (str | Unset):
    """

    data: list[PlatformAssetPosture]
    schema_version: int = 1
    cursor: str | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        data = []
        for data_item_data in self.data:
            data_item = data_item_data.to_dict()
            data.append(data_item)

        schema_version = self.schema_version

        cursor = self.cursor

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "data": data,
                "schema_version": schema_version,
            }
        )
        if cursor is not UNSET:
            field_dict["cursor"] = cursor

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.platform_asset_posture import PlatformAssetPosture

        d = dict(src_dict)
        data = []
        _data = d.pop("data")
        for data_item_data in _data:
            data_item = PlatformAssetPosture.from_dict(data_item_data)

            data.append(data_item)

        schema_version = d.pop("schema_version")

        cursor = d.pop("cursor", UNSET)

        platform_asset_posture_page = cls(
            data=data,
            schema_version=schema_version,
            cursor=cursor,
        )

        return platform_asset_posture_page
