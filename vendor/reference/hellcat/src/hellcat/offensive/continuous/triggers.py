"""
Trigger implementations for continuous engagement mode.

Each trigger monitors for changes and invokes a callback when a change
is detected. Triggers implement the Trigger ABC with start(), stop(),
and on_change(callback).
"""

from __future__ import annotations

import hashlib
import subprocess
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()

# Type for trigger callbacks: receives trigger_type and trigger_data dict
ChangeCallback = Callable[[str, dict[str, Any]], None]


@dataclass
class TriggerEvent:
    """Metadata about a trigger firing."""

    trigger_type: str
    timestamp: float
    data: dict[str, Any] = field(default_factory=dict)


class Trigger(ABC):
    """Abstract base class for change detection triggers.

    Subclasses must implement:
    - start(): Begin monitoring for changes.
    - stop(): Stop monitoring and clean up resources.

    Use on_change() to register a callback before calling start().
    """

    def __init__(self) -> None:
        self._callbacks: list[ChangeCallback] = []
        self._running = False

    def on_change(self, callback: ChangeCallback) -> None:
        """Register a callback to be invoked when a change is detected.

        Args:
            callback: Function(trigger_type, trigger_data) called on change.
        """
        self._callbacks.append(callback)

    def _fire(self, trigger_type: str, data: dict[str, Any]) -> None:
        """Invoke all registered callbacks."""
        for cb in self._callbacks:
            try:
                cb(trigger_type, data)
            except Exception as exc:
                logger.error(
                    "trigger.callback_error",
                    trigger_type=trigger_type,
                    error=str(exc),
                )

    @property
    def running(self) -> bool:
        return self._running

    @abstractmethod
    def start(self) -> None:
        """Begin monitoring for changes."""
        ...

    @abstractmethod
    def stop(self) -> None:
        """Stop monitoring and clean up resources."""
        ...


class WebhookTrigger(Trigger):
    """HTTP webhook receiver trigger.

    Starts a lightweight HTTP server that receives POST notifications.
    Any POST to the server fires the change callback with the request
    body as trigger data.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8080) -> None:
        super().__init__()
        self.host = host
        self.port = port
        self._server: Any = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the HTTP webhook server in a background thread."""
        import json
        from http.server import BaseHTTPRequestHandler, HTTPServer

        trigger = self

        class _Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length).decode("utf-8", errors="replace")
                try:
                    data = json.loads(body) if body else {}
                except json.JSONDecodeError:
                    data = {"raw_body": body}

                logger.info("trigger.webhook_received", path=self.path, size=content_length)
                trigger._fire("webhook", {"path": self.path, "body": data})

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"accepted"}')

            def log_message(self, format: str, *args: Any) -> None:
                pass  # Suppress default logging

        self._server = HTTPServer((self.host, self.port), _Handler)
        self._running = True
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="hellcat-webhook",
        )
        self._thread.start()
        logger.info("trigger.webhook_started", host=self.host, port=self.port)

    def stop(self) -> None:
        """Shut down the webhook server."""
        self._running = False
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("trigger.webhook_stopped")


class PollingTrigger(Trigger):
    """Periodic URL polling trigger.

    Periodically fetches the target URL and fires when the response
    content hash changes, indicating the application was modified.
    """

    def __init__(
        self,
        url: str,
        interval_seconds: float = 300.0,
        timeout: float = 30.0,
    ) -> None:
        super().__init__()
        self.url = url
        self.interval_seconds = interval_seconds
        self.timeout = timeout
        self._last_hash: str = ""
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the polling loop in a background thread."""
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._poll_loop,
            daemon=True,
            name="hellcat-poller",
        )
        self._thread.start()
        logger.info(
            "trigger.polling_started",
            url=self.url,
            interval=self.interval_seconds,
        )

    def stop(self) -> None:
        """Stop the polling loop."""
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=self.interval_seconds + 5)
            self._thread = None
        logger.info("trigger.polling_stopped")

    def _poll_loop(self) -> None:
        """Background polling loop."""
        import urllib.error
        import urllib.request

        while not self._stop_event.is_set():
            try:
                req = urllib.request.Request(self.url, method="GET")
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    body = resp.read()
                    current_hash = hashlib.sha256(body).hexdigest()

                if self._last_hash and current_hash != self._last_hash:
                    logger.info(
                        "trigger.polling_change_detected",
                        url=self.url,
                        old_hash=self._last_hash[:12],
                        new_hash=current_hash[:12],
                    )
                    self._fire("polling", {
                        "url": self.url,
                        "old_hash": self._last_hash,
                        "new_hash": current_hash,
                    })

                self._last_hash = current_hash

            except Exception as exc:
                logger.warning(
                    "trigger.polling_error",
                    url=self.url,
                    error=str(exc),
                )

            self._stop_event.wait(self.interval_seconds)


class GitTrigger(Trigger):
    """Git repository change trigger.

    Polls a git remote for new commits using ``git ls-remote``.
    Fires when the HEAD ref changes.
    """

    def __init__(
        self,
        repo_url: str,
        branch: str = "main",
        interval_seconds: float = 60.0,
    ) -> None:
        super().__init__()
        self.repo_url = repo_url
        self.branch = branch
        self.interval_seconds = interval_seconds
        self._last_ref: str = ""
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the git polling loop in a background thread."""
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._poll_loop,
            daemon=True,
            name="hellcat-git-trigger",
        )
        self._thread.start()
        logger.info(
            "trigger.git_started",
            repo=self.repo_url,
            branch=self.branch,
            interval=self.interval_seconds,
        )

    def stop(self) -> None:
        """Stop the git polling loop."""
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=self.interval_seconds + 5)
            self._thread = None
        logger.info("trigger.git_stopped")

    def _poll_loop(self) -> None:
        """Background git polling loop."""
        while not self._stop_event.is_set():
            try:
                ref = self._get_remote_ref()
                if ref and self._last_ref and ref != self._last_ref:
                    logger.info(
                        "trigger.git_change_detected",
                        repo=self.repo_url,
                        branch=self.branch,
                        old_ref=self._last_ref[:12],
                        new_ref=ref[:12],
                    )
                    self._fire("git", {
                        "repo_url": self.repo_url,
                        "branch": self.branch,
                        "old_ref": self._last_ref,
                        "new_ref": ref,
                    })

                if ref:
                    self._last_ref = ref

            except Exception as exc:
                logger.warning(
                    "trigger.git_error",
                    repo=self.repo_url,
                    error=str(exc),
                )

            self._stop_event.wait(self.interval_seconds)

    def _get_remote_ref(self) -> str:
        """Get the current HEAD ref for the branch via git ls-remote."""
        try:
            result = subprocess.run(
                ["git", "ls-remote", self.repo_url, f"refs/heads/{self.branch}"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                # Output: "<hash>\trefs/heads/<branch>"
                return result.stdout.strip().split()[0]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return ""


class ScheduleTrigger(Trigger):
    """Simple interval-based schedule trigger.

    Fires at a fixed interval (e.g., every hour). Does not depend on
    external state changes.
    """

    def __init__(self, interval_seconds: float = 3600.0) -> None:
        super().__init__()
        self.interval_seconds = interval_seconds
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the schedule loop in a background thread."""
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._schedule_loop,
            daemon=True,
            name="hellcat-scheduler",
        )
        self._thread.start()
        logger.info(
            "trigger.schedule_started",
            interval=self.interval_seconds,
        )

    def stop(self) -> None:
        """Stop the schedule loop."""
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=self.interval_seconds + 5)
            self._thread = None
        logger.info("trigger.schedule_stopped")

    def _schedule_loop(self) -> None:
        """Background schedule loop: wait, then fire."""
        # Wait for the first interval before firing
        self._stop_event.wait(self.interval_seconds)
        while not self._stop_event.is_set():
            logger.info("trigger.schedule_fired", interval=self.interval_seconds)
            self._fire("schedule", {
                "interval_seconds": self.interval_seconds,
                "fired_at": time.time(),
            })
            self._stop_event.wait(self.interval_seconds)
