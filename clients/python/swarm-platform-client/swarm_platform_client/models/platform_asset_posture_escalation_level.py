from enum import Enum


class PlatformAssetPostureEscalationLevel(str, Enum):
    ALERT = "alert"
    INCIDENT = "incident"
    NORMAL = "normal"

    def __str__(self) -> str:
        return str(self.value)
