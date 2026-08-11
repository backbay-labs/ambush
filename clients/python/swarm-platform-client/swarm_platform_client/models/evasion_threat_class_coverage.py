from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define

T = TypeVar("T", bound="EvasionThreatClassCoverage")


@_attrs_define
class EvasionThreatClassCoverage:
    """
    Attributes:
        catch_rate (float):
        detected_payloads (int):
        scenario_count (int):
        techniques (list[str]):
        threat_class (str):
        total_payloads (int):
    """

    catch_rate: float
    detected_payloads: int
    scenario_count: int
    techniques: list[str]
    threat_class: str
    total_payloads: int

    def to_dict(self) -> dict[str, Any]:
        catch_rate = self.catch_rate

        detected_payloads = self.detected_payloads

        scenario_count = self.scenario_count

        techniques = self.techniques

        threat_class = self.threat_class

        total_payloads = self.total_payloads

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "catch_rate": catch_rate,
                "detected_payloads": detected_payloads,
                "scenario_count": scenario_count,
                "techniques": techniques,
                "threat_class": threat_class,
                "total_payloads": total_payloads,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        catch_rate = d.pop("catch_rate")

        detected_payloads = d.pop("detected_payloads")

        scenario_count = d.pop("scenario_count")

        techniques = cast(list[str], d.pop("techniques"))

        threat_class = d.pop("threat_class")

        total_payloads = d.pop("total_payloads")

        evasion_threat_class_coverage = cls(
            catch_rate=catch_rate,
            detected_payloads=detected_payloads,
            scenario_count=scenario_count,
            techniques=techniques,
            threat_class=threat_class,
            total_payloads=total_payloads,
        )

        return evasion_threat_class_coverage
