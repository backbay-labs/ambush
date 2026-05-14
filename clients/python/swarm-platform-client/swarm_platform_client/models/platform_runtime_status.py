from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.bridge_status_report import BridgeStatusReport
    from ..models.platform_detector_status import PlatformDetectorStatus
    from ..models.platform_lifecycle_status import PlatformLifecycleStatus
    from ..models.platform_runtime_status_agent_health_item import PlatformRuntimeStatusAgentHealthItem
    from ..models.platform_runtime_status_alert_tuning import PlatformRuntimeStatusAlertTuning
    from ..models.platform_runtime_status_anti_tamper import PlatformRuntimeStatusAntiTamper
    from ..models.platform_runtime_status_async_lane import PlatformRuntimeStatusAsyncLane
    from ..models.platform_runtime_status_bearer_tokens_item import PlatformRuntimeStatusBearerTokensItem
    from ..models.platform_runtime_status_degradation import PlatformRuntimeStatusDegradation
    from ..models.platform_runtime_status_false_positive_tracking import PlatformRuntimeStatusFalsePositiveTracking
    from ..models.platform_runtime_status_mode_state import PlatformRuntimeStatusModeState
    from ..models.platform_runtime_status_rate_limit import PlatformRuntimeStatusRateLimit


T = TypeVar("T", bound="PlatformRuntimeStatus")


@_attrs_define
class PlatformRuntimeStatus:
    """
    Attributes:
        agent_health (list[PlatformRuntimeStatusAgentHealthItem]):
        alert_tuning (PlatformRuntimeStatusAlertTuning): Aggregate alert-tuning recommendation report.
        anti_tamper (PlatformRuntimeStatusAntiTamper): Current anti-tamper status report.
        async_lane (PlatformRuntimeStatusAsyncLane): Async investigation and correlation lane status.
        bearer_tokens (list[PlatformRuntimeStatusBearerTokensItem]):
        captured_at_ms (int):
        degradation (PlatformRuntimeStatusDegradation): Current runtime degradation state and capabilities.
        detector (PlatformDetectorStatus):
        false_positive_tracking (PlatformRuntimeStatusFalsePositiveTracking): Aggregate analyst false-positive tracking
            report.
        lifecycle (PlatformLifecycleStatus):
        mode_state (PlatformRuntimeStatusModeState): Current swarm mode and last transition metadata.
        rate_limit (PlatformRuntimeStatusRateLimit): Per-source platform API rate-limit status.
        bridge_health (BridgeStatusReport | Unset):
    """

    agent_health: list[PlatformRuntimeStatusAgentHealthItem]
    alert_tuning: PlatformRuntimeStatusAlertTuning
    anti_tamper: PlatformRuntimeStatusAntiTamper
    async_lane: PlatformRuntimeStatusAsyncLane
    bearer_tokens: list[PlatformRuntimeStatusBearerTokensItem]
    captured_at_ms: int
    degradation: PlatformRuntimeStatusDegradation
    detector: PlatformDetectorStatus
    false_positive_tracking: PlatformRuntimeStatusFalsePositiveTracking
    lifecycle: PlatformLifecycleStatus
    mode_state: PlatformRuntimeStatusModeState
    rate_limit: PlatformRuntimeStatusRateLimit
    bridge_health: BridgeStatusReport | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        agent_health = []
        for agent_health_item_data in self.agent_health:
            agent_health_item = agent_health_item_data.to_dict()
            agent_health.append(agent_health_item)

        alert_tuning = self.alert_tuning.to_dict()

        anti_tamper = self.anti_tamper.to_dict()

        async_lane = self.async_lane.to_dict()

        bearer_tokens = []
        for bearer_tokens_item_data in self.bearer_tokens:
            bearer_tokens_item = bearer_tokens_item_data.to_dict()
            bearer_tokens.append(bearer_tokens_item)

        captured_at_ms = self.captured_at_ms

        degradation = self.degradation.to_dict()

        detector = self.detector.to_dict()

        false_positive_tracking = self.false_positive_tracking.to_dict()

        lifecycle = self.lifecycle.to_dict()

        mode_state = self.mode_state.to_dict()

        rate_limit = self.rate_limit.to_dict()

        bridge_health: dict[str, Any] | Unset = UNSET
        if not isinstance(self.bridge_health, Unset):
            bridge_health = self.bridge_health.to_dict()

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "agent_health": agent_health,
                "alert_tuning": alert_tuning,
                "anti_tamper": anti_tamper,
                "async_lane": async_lane,
                "bearer_tokens": bearer_tokens,
                "captured_at_ms": captured_at_ms,
                "degradation": degradation,
                "detector": detector,
                "false_positive_tracking": false_positive_tracking,
                "lifecycle": lifecycle,
                "mode_state": mode_state,
                "rate_limit": rate_limit,
            }
        )
        if bridge_health is not UNSET:
            field_dict["bridge_health"] = bridge_health

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.bridge_status_report import BridgeStatusReport
        from ..models.platform_detector_status import PlatformDetectorStatus
        from ..models.platform_lifecycle_status import PlatformLifecycleStatus
        from ..models.platform_runtime_status_agent_health_item import PlatformRuntimeStatusAgentHealthItem
        from ..models.platform_runtime_status_alert_tuning import PlatformRuntimeStatusAlertTuning
        from ..models.platform_runtime_status_anti_tamper import PlatformRuntimeStatusAntiTamper
        from ..models.platform_runtime_status_async_lane import PlatformRuntimeStatusAsyncLane
        from ..models.platform_runtime_status_bearer_tokens_item import PlatformRuntimeStatusBearerTokensItem
        from ..models.platform_runtime_status_degradation import PlatformRuntimeStatusDegradation
        from ..models.platform_runtime_status_false_positive_tracking import PlatformRuntimeStatusFalsePositiveTracking
        from ..models.platform_runtime_status_mode_state import PlatformRuntimeStatusModeState
        from ..models.platform_runtime_status_rate_limit import PlatformRuntimeStatusRateLimit

        d = dict(src_dict)
        agent_health = []
        _agent_health = d.pop("agent_health")
        for agent_health_item_data in _agent_health:
            agent_health_item = PlatformRuntimeStatusAgentHealthItem.from_dict(agent_health_item_data)

            agent_health.append(agent_health_item)

        alert_tuning = PlatformRuntimeStatusAlertTuning.from_dict(d.pop("alert_tuning"))

        anti_tamper = PlatformRuntimeStatusAntiTamper.from_dict(d.pop("anti_tamper"))

        async_lane = PlatformRuntimeStatusAsyncLane.from_dict(d.pop("async_lane"))

        bearer_tokens = []
        _bearer_tokens = d.pop("bearer_tokens")
        for bearer_tokens_item_data in _bearer_tokens:
            bearer_tokens_item = PlatformRuntimeStatusBearerTokensItem.from_dict(bearer_tokens_item_data)

            bearer_tokens.append(bearer_tokens_item)

        captured_at_ms = d.pop("captured_at_ms")

        degradation = PlatformRuntimeStatusDegradation.from_dict(d.pop("degradation"))

        detector = PlatformDetectorStatus.from_dict(d.pop("detector"))

        false_positive_tracking = PlatformRuntimeStatusFalsePositiveTracking.from_dict(d.pop("false_positive_tracking"))

        lifecycle = PlatformLifecycleStatus.from_dict(d.pop("lifecycle"))

        mode_state = PlatformRuntimeStatusModeState.from_dict(d.pop("mode_state"))

        rate_limit = PlatformRuntimeStatusRateLimit.from_dict(d.pop("rate_limit"))

        _bridge_health = d.pop("bridge_health", UNSET)
        bridge_health: BridgeStatusReport | Unset
        if isinstance(_bridge_health, Unset):
            bridge_health = UNSET
        else:
            bridge_health = BridgeStatusReport.from_dict(_bridge_health)

        platform_runtime_status = cls(
            agent_health=agent_health,
            alert_tuning=alert_tuning,
            anti_tamper=anti_tamper,
            async_lane=async_lane,
            bearer_tokens=bearer_tokens,
            captured_at_ms=captured_at_ms,
            degradation=degradation,
            detector=detector,
            false_positive_tracking=false_positive_tracking,
            lifecycle=lifecycle,
            mode_state=mode_state,
            rate_limit=rate_limit,
            bridge_health=bridge_health,
        )

        return platform_runtime_status
