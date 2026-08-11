from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define

if TYPE_CHECKING:
    from ..models.detector_evasion_coverage_report import DetectorEvasionCoverageReport


T = TypeVar("T", bound="EvasionCoverageSnapshot")


@_attrs_define
class EvasionCoverageSnapshot:
    """
    Attributes:
        corpus_version (str):
        detectors (list[DetectorEvasionCoverageReport]):
        generated_at_ms (int):
        suite_name (str):
        suite_path (str):
    """

    corpus_version: str
    detectors: list[DetectorEvasionCoverageReport]
    generated_at_ms: int
    suite_name: str
    suite_path: str

    def to_dict(self) -> dict[str, Any]:
        corpus_version = self.corpus_version

        detectors = []
        for detectors_item_data in self.detectors:
            detectors_item = detectors_item_data.to_dict()
            detectors.append(detectors_item)

        generated_at_ms = self.generated_at_ms

        suite_name = self.suite_name

        suite_path = self.suite_path

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "corpus_version": corpus_version,
                "detectors": detectors,
                "generated_at_ms": generated_at_ms,
                "suite_name": suite_name,
                "suite_path": suite_path,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.detector_evasion_coverage_report import DetectorEvasionCoverageReport

        d = dict(src_dict)
        corpus_version = d.pop("corpus_version")

        detectors = []
        _detectors = d.pop("detectors")
        for detectors_item_data in _detectors:
            detectors_item = DetectorEvasionCoverageReport.from_dict(detectors_item_data)

            detectors.append(detectors_item)

        generated_at_ms = d.pop("generated_at_ms")

        suite_name = d.pop("suite_name")

        suite_path = d.pop("suite_path")

        evasion_coverage_snapshot = cls(
            corpus_version=corpus_version,
            detectors=detectors,
            generated_at_ms=generated_at_ms,
            suite_name=suite_name,
            suite_path=suite_path,
        )

        return evasion_coverage_snapshot
