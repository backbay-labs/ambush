"""
Ralph-style Rate Limiter for Hellcat Kernel.

Implements intelligent API quota management:
- Per-hour call limits with automatic reset
- Per-toolchain quotas
- 5-hour API limit detection (Claude-specific)
- Countdown timers and wait estimation
- Configurable burst limits

Inspired by: https://github.com/frankbria/ralph-claude-code
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from pathlib import Path

logger = structlog.get_logger()


@dataclass
class RateLimiterConfig:
    """Configuration for rate limiting behavior."""

    # Global limits
    max_calls_per_hour: int = 100
    max_tokens_per_hour: int = 500_000

    # Per-toolchain limits (optional overrides)
    toolchain_limits: dict[str, int] = field(default_factory=dict)

    # Burst control
    max_burst: int = 10  # Max concurrent calls
    burst_window_seconds: int = 60

    # 5-hour limit handling (Claude-specific)
    five_hour_limit_detection: bool = True
    five_hour_wait_minutes: int = 60


@dataclass
class UsageWindow:
    """Tracks usage within a time window."""

    start_time: float = field(default_factory=time.time)
    call_count: int = 0
    token_count: int = 0
    timestamps: list[float] = field(default_factory=list)

    def reset(self) -> None:
        """Reset the window."""
        self.start_time = time.time()
        self.call_count = 0
        self.token_count = 0
        self.timestamps.clear()

    def age_seconds(self) -> float:
        """Time since window started."""
        return time.time() - self.start_time


@dataclass
class WaitResult:
    """Result of checking if we should wait."""

    should_wait: bool = False
    wait_seconds: float = 0.0
    reason: str = ""
    current_usage: int = 0
    limit: int = 0


class RateLimiter:
    """
    Rate limiter for kernel API calls.

    Tracks and enforces:
    - Hourly call limits (global and per-toolchain)
    - Token usage limits
    - Burst control (prevent stampede)
    - 5-hour API limit detection

    Usage:
        limiter = RateLimiter(config)

        if limiter.should_wait():
            wait_result = limiter.get_wait_info()
            time.sleep(wait_result.wait_seconds)

        limiter.record_call("claude", tokens=50000)
    """

    def __init__(
        self,
        config: RateLimiterConfig | None = None,
        persist_path: Path | None = None,
    ) -> None:
        self.config = config or RateLimiterConfig()
        self.persist_path = persist_path

        # Global hourly window
        self._hourly_window = UsageWindow()

        # Per-toolchain windows
        self._toolchain_windows: dict[str, UsageWindow] = {}

        # Burst tracking (last N timestamps)
        self._burst_timestamps: list[float] = []

        # 5-hour limit state
        self._five_hour_limit_hit = False
        self._five_hour_limit_at: float | None = None

        # Load persisted state
        if persist_path:
            self._load_state()

    def should_wait(self, toolchain: str | None = None) -> bool:
        """Check if we should wait before making a call."""
        self._maybe_reset_windows()
        return self.get_wait_info(toolchain).should_wait

    def get_wait_info(self, toolchain: str | None = None) -> WaitResult:
        self._maybe_reset_windows()

        # Check 5-hour limit first
        if self._five_hour_limit_hit:
            wait_remaining = self._five_hour_wait_remaining()
            if wait_remaining > 0:
                return WaitResult(
                    should_wait=True,
                    wait_seconds=wait_remaining,
                    reason="5_hour_api_limit",
                    current_usage=0,
                    limit=0,
                )
            else:
                self._clear_five_hour_limit()

        # Check burst limit
        burst_result = self._check_burst()
        if burst_result.should_wait:
            return burst_result

        # Check hourly global limit
        if self._hourly_window.call_count >= self.config.max_calls_per_hour:
            wait_seconds = 3600 - self._hourly_window.age_seconds()
            return WaitResult(
                should_wait=True,
                wait_seconds=max(0, wait_seconds),
                reason="hourly_call_limit",
                current_usage=self._hourly_window.call_count,
                limit=self.config.max_calls_per_hour,
            )

        # Check hourly token limit
        if self._hourly_window.token_count >= self.config.max_tokens_per_hour:
            wait_seconds = 3600 - self._hourly_window.age_seconds()
            return WaitResult(
                should_wait=True,
                wait_seconds=max(0, wait_seconds),
                reason="hourly_token_limit",
                current_usage=self._hourly_window.token_count,
                limit=self.config.max_tokens_per_hour,
            )

        # Check per-toolchain limit
        if toolchain and toolchain in self.config.toolchain_limits:
            tc_window = self._get_toolchain_window(toolchain)
            tc_limit = self.config.toolchain_limits[toolchain]
            if tc_window.call_count >= tc_limit:
                wait_seconds = 3600 - tc_window.age_seconds()
                return WaitResult(
                    should_wait=True,
                    wait_seconds=max(0, wait_seconds),
                    reason=f"toolchain_{toolchain}_limit",
                    current_usage=tc_window.call_count,
                    limit=tc_limit,
                )

        return WaitResult(should_wait=False)

    def record_call(
        self,
        toolchain: str,
        tokens: int = 0,
        success: bool = True,
    ) -> None:
        """Record an API call."""
        now = time.time()
        tokens = tokens or 0  # Ensure tokens is never None

        # Update global window
        self._hourly_window.call_count += 1
        self._hourly_window.token_count += tokens
        self._hourly_window.timestamps.append(now)

        # Update toolchain window
        tc_window = self._get_toolchain_window(toolchain)
        tc_window.call_count += 1
        tc_window.token_count += tokens
        tc_window.timestamps.append(now)

        # Update burst tracking
        self._burst_timestamps.append(now)
        self._prune_burst_timestamps()

        logger.debug(
            "rate_limiter.recorded",
            toolchain=toolchain,
            tokens=tokens,
            hourly_calls=self._hourly_window.call_count,
            hourly_tokens=self._hourly_window.token_count,
        )

        self._persist_state()

    def record_five_hour_limit(self) -> None:
        """Record that the 5-hour API limit was hit."""
        self._five_hour_limit_hit = True
        self._five_hour_limit_at = time.time()
        logger.warning("rate_limiter.five_hour_limit_hit")
        self._persist_state()

    def detect_five_hour_limit(self, error_message: str) -> bool:
        """Check if an error message indicates the 5-hour limit."""
        if not self.config.five_hour_limit_detection:
            return False

        indicators = [
            "rate limit",
            "rate_limit",
            "too many requests",
            "429",
            "quota exceeded",
            "usage limit",
            "api limit",
        ]

        error_lower = error_message.lower()
        return any(ind in error_lower for ind in indicators)

    def get_status(self) -> dict:
        self._maybe_reset_windows()

        hourly_remaining = self.config.max_calls_per_hour - self._hourly_window.call_count
        token_remaining = self.config.max_tokens_per_hour - self._hourly_window.token_count
        reset_in = max(0, 3600 - self._hourly_window.age_seconds())

        toolchain_status = {}
        for tc, limit in self.config.toolchain_limits.items():
            window = self._get_toolchain_window(tc)
            toolchain_status[tc] = {
                "calls": window.call_count,
                "limit": limit,
                "remaining": limit - window.call_count,
            }

        return {
            "hourly": {
                "calls": self._hourly_window.call_count,
                "calls_limit": self.config.max_calls_per_hour,
                "calls_remaining": hourly_remaining,
                "tokens": self._hourly_window.token_count,
                "tokens_limit": self.config.max_tokens_per_hour,
                "tokens_remaining": token_remaining,
                "reset_in_seconds": reset_in,
            },
            "toolchains": toolchain_status,
            "burst": {
                "current": len(self._burst_timestamps),
                "limit": self.config.max_burst,
            },
            "five_hour_limit": {
                "hit": self._five_hour_limit_hit,
                "hit_at": self._five_hour_limit_at,
                "wait_remaining": self._five_hour_wait_remaining() if self._five_hour_limit_hit else 0,
            },
        }

    def reset(self) -> None:
        """Reset all rate limiting state."""
        self._hourly_window.reset()
        self._toolchain_windows.clear()
        self._burst_timestamps.clear()
        self._five_hour_limit_hit = False
        self._five_hour_limit_at = None
        self._persist_state()

    def _get_toolchain_window(self, toolchain: str) -> UsageWindow:
        if toolchain not in self._toolchain_windows:
            self._toolchain_windows[toolchain] = UsageWindow()
        return self._toolchain_windows[toolchain]

    def _maybe_reset_windows(self) -> None:
        """Reset windows if they've expired (hourly)."""
        time.time()

        # Reset hourly window
        if self._hourly_window.age_seconds() >= 3600:
            self._hourly_window.reset()
            logger.info("rate_limiter.hourly_reset")

        # Reset toolchain windows
        for _tc, window in list(self._toolchain_windows.items()):
            if window.age_seconds() >= 3600:
                window.reset()

    def _check_burst(self) -> WaitResult:
        """Check burst rate limit."""
        self._prune_burst_timestamps()

        if len(self._burst_timestamps) >= self.config.max_burst:
            # Calculate when the oldest timestamp will age out
            oldest = min(self._burst_timestamps)
            wait_seconds = self.config.burst_window_seconds - (time.time() - oldest)
            return WaitResult(
                should_wait=True,
                wait_seconds=max(0, wait_seconds),
                reason="burst_limit",
                current_usage=len(self._burst_timestamps),
                limit=self.config.max_burst,
            )

        return WaitResult(should_wait=False)

    def _prune_burst_timestamps(self) -> None:
        """Remove timestamps outside the burst window."""
        cutoff = time.time() - self.config.burst_window_seconds
        self._burst_timestamps = [t for t in self._burst_timestamps if t > cutoff]

    def _five_hour_wait_remaining(self) -> float:
        """Calculate remaining wait time for 5-hour limit."""
        if not self._five_hour_limit_at:
            return 0

        wait_duration = self.config.five_hour_wait_minutes * 60
        elapsed = time.time() - self._five_hour_limit_at
        return max(0, wait_duration - elapsed)

    def _clear_five_hour_limit(self) -> None:
        """Clear the 5-hour limit flag."""
        self._five_hour_limit_hit = False
        self._five_hour_limit_at = None
        logger.info("rate_limiter.five_hour_limit_cleared")
        self._persist_state()

    def _persist_state(self) -> None:
        """Persist state to disk."""
        if not self.persist_path:
            return

        import json

        try:
            self.persist_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.persist_path, "w") as f:
                json.dump(
                    {
                        "hourly": {
                            "start_time": self._hourly_window.start_time,
                            "call_count": self._hourly_window.call_count,
                            "token_count": self._hourly_window.token_count,
                        },
                        "toolchains": {
                            tc: {
                                "start_time": w.start_time,
                                "call_count": w.call_count,
                                "token_count": w.token_count,
                            }
                            for tc, w in self._toolchain_windows.items()
                        },
                        "five_hour_limit_hit": self._five_hour_limit_hit,
                        "five_hour_limit_at": self._five_hour_limit_at,
                    },
                    f,
                )
        except Exception:
            logger.exception("Failed to persist rate limiter state")

    def _load_state(self) -> None:
        """Load persisted state from disk."""
        if not self.persist_path or not self.persist_path.exists():
            return

        import json

        try:
            with open(self.persist_path) as f:
                data = json.load(f)

            hourly = data.get("hourly", {})
            self._hourly_window.start_time = hourly.get("start_time", time.time())
            self._hourly_window.call_count = hourly.get("call_count", 0)
            self._hourly_window.token_count = hourly.get("token_count", 0)

            for tc, tc_data in data.get("toolchains", {}).items():
                window = UsageWindow()
                window.start_time = tc_data.get("start_time", time.time())
                window.call_count = tc_data.get("call_count", 0)
                window.token_count = tc_data.get("token_count", 0)
                self._toolchain_windows[tc] = window

            self._five_hour_limit_hit = data.get("five_hour_limit_hit", False)
            self._five_hour_limit_at = data.get("five_hour_limit_at")

            # Reset if windows are stale
            self._maybe_reset_windows()

            logger.info(
                "rate_limiter.loaded",
                hourly_calls=self._hourly_window.call_count,
            )
        except Exception:
            logger.exception("Failed to load rate limiter state")


def format_wait_time(seconds: float) -> str:
    """Format wait time in human-readable form."""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        mins = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{mins}m {secs}s"
    else:
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        return f"{hours}h {mins}m"
