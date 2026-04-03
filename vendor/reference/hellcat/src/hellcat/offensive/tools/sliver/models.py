"""Data models for Sliver C2 integration."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SliverSession:
    """An active Sliver session (interactive)."""

    session_id: str
    name: str = ""
    transport: str = ""  # "mtls", "wg", "dns", "http", "https"
    remote_address: str = ""
    hostname: str = ""
    username: str = ""
    os: str = ""
    arch: str = ""
    pid: int = 0
    filename: str = ""
    active_c2: str = ""


@dataclass
class SliverBeacon:
    """A Sliver beacon (asynchronous check-in)."""

    beacon_id: str
    name: str = ""
    transport: str = ""
    remote_address: str = ""
    hostname: str = ""
    username: str = ""
    os: str = ""
    arch: str = ""
    interval: int = 60
    jitter: int = 30
    next_checkin: str = ""


@dataclass
class SliverImplant:
    """A Sliver implant configuration."""

    implant_id: str
    name: str = ""
    os: str = ""
    arch: str = ""
    format: str = ""  # "exe", "shared", "service", "shellcode"
    c2_urls: list[str] = field(default_factory=list)
    is_beacon: bool = False
