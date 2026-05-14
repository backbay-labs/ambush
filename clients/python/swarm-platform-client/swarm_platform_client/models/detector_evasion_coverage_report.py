from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define

if TYPE_CHECKING:
    from ..models.detector_evasion_coverage_report_intentionally_uncovered_item import (
        DetectorEvasionCoverageReportIntentionallyUncoveredItem,
    )
    from ..models.evasion_threat_class_coverage import EvasionThreatClassCoverage


T = TypeVar("T", bound="DetectorEvasionCoverageReport")


@_attrs_define
class DetectorEvasionCoverageReport:
    """
    Attributes:
        catch_rate (float):
        detected_payloads (int):
        detector (str):
        intentionally_uncovered (list[DetectorEvasionCoverageReportIntentionallyUncoveredItem]):
        threat_classes (list[EvasionThreatClassCoverage]):
        total_payloads (int):
    """

    catch_rate: float
    detected_payloads: int
    detector: str
    intentionally_uncovered: list[DetectorEvasionCoverageReportIntentionallyUncoveredItem]
    threat_classes: list[EvasionThreatClassCoverage]
    total_payloads: int

    def to_dict(self) -> dict[str, Any]:
        catch_rate = self.catch_rate

        detected_payloads = self.detected_payloads

        detector = self.detector

        intentionally_uncovered = []
        for intentionally_uncovered_item_data in self.intentionally_uncovered:
            intentionally_uncovered_item = intentionally_uncovered_item_data.to_dict()
            intentionally_uncovered.append(intentionally_uncovered_item)

        threat_classes = []
        for threat_classes_item_data in self.threat_classes:
            threat_classes_item = threat_classes_item_data.to_dict()
            threat_classes.append(threat_classes_item)

        total_payloads = self.total_payloads

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "catch_rate": catch_rate,
                "detected_payloads": detected_payloads,
                "detector": detector,
                "intentionally_uncovered": intentionally_uncovered,
                "threat_classes": threat_classes,
                "total_payloads": total_payloads,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.detector_evasion_coverage_report_intentionally_uncovered_item import (
            DetectorEvasionCoverageReportIntentionallyUncoveredItem,
        )
        from ..models.evasion_threat_class_coverage import EvasionThreatClassCoverage

        d = dict(src_dict)
        catch_rate = d.pop("catch_rate")

        detected_payloads = d.pop("detected_payloads")

        detector = d.pop("detector")

        intentionally_uncovered = []
        _intentionally_uncovered = d.pop("intentionally_uncovered")
        for intentionally_uncovered_item_data in _intentionally_uncovered:
            intentionally_uncovered_item = DetectorEvasionCoverageReportIntentionallyUncoveredItem.from_dict(
                intentionally_uncovered_item_data
            )

            intentionally_uncovered.append(intentionally_uncovered_item)

        threat_classes = []
        _threat_classes = d.pop("threat_classes")
        for threat_classes_item_data in _threat_classes:
            threat_classes_item = EvasionThreatClassCoverage.from_dict(threat_classes_item_data)

            threat_classes.append(threat_classes_item)

        total_payloads = d.pop("total_payloads")

        detector_evasion_coverage_report = cls(
            catch_rate=catch_rate,
            detected_payloads=detected_payloads,
            detector=detector,
            intentionally_uncovered=intentionally_uncovered,
            threat_classes=threat_classes,
            total_payloads=total_payloads,
        )

        return detector_evasion_coverage_report
