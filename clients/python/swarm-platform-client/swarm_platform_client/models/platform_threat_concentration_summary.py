from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define

T = TypeVar("T", bound="PlatformThreatConcentrationSummary")


@_attrs_define
class PlatformThreatConcentrationSummary:
    """
    Attributes:
        distinct_sources (int):
        peak_confidence (float):
        threat_class (str):
        total_strength (float):
    """

    distinct_sources: int
    peak_confidence: float
    threat_class: str
    total_strength: float

    def to_dict(self) -> dict[str, Any]:
        distinct_sources = self.distinct_sources

        peak_confidence = self.peak_confidence

        threat_class = self.threat_class

        total_strength = self.total_strength

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "distinct_sources": distinct_sources,
                "peak_confidence": peak_confidence,
                "threat_class": threat_class,
                "total_strength": total_strength,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        distinct_sources = d.pop("distinct_sources")

        peak_confidence = d.pop("peak_confidence")

        threat_class = d.pop("threat_class")

        total_strength = d.pop("total_strength")

        platform_threat_concentration_summary = cls(
            distinct_sources=distinct_sources,
            peak_confidence=peak_confidence,
            threat_class=threat_class,
            total_strength=total_strength,
        )

        return platform_threat_concentration_summary
