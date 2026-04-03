"""
Continuous Engagement Mode - Watch and re-test on changes.

Monitors targets for changes and automatically re-tests affected
attack surfaces with targeted re-engagements.
"""

from hellcat.offensive.continuous.differ import SurfaceDiff, SurfaceDiffer
from hellcat.offensive.continuous.history import EngagementHistory
from hellcat.offensive.continuous.scheduler import ContinuousScheduler
from hellcat.offensive.continuous.triggers import (
    GitTrigger,
    PollingTrigger,
    ScheduleTrigger,
    Trigger,
    WebhookTrigger,
)
from hellcat.offensive.continuous.watcher import EngagementWatcher

__all__ = [
    "EngagementWatcher",
    "SurfaceDiff",
    "SurfaceDiffer",
    "ContinuousScheduler",
    "EngagementHistory",
    "Trigger",
    "WebhookTrigger",
    "PollingTrigger",
    "GitTrigger",
    "ScheduleTrigger",
]
