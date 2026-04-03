"""Parser for Sliver C2 JSON output."""

from __future__ import annotations

import json

from hellcat.offensive.tools.sliver.models import SliverBeacon, SliverImplant, SliverSession


class SliverParser:
    """Parse Sliver CLI JSON output into typed models."""

    @staticmethod
    def parse_sessions(output: str) -> list[SliverSession]:
        """Parse sessions JSON array output."""
        try:
            data = json.loads(output)
        except (json.JSONDecodeError, ValueError):
            return []

        if not isinstance(data, list):
            data = [data] if isinstance(data, dict) else []

        sessions: list[SliverSession] = []
        for item in data:
            sessions.append(SliverSession(
                session_id=str(item.get("ID", item.get("id", ""))),
                name=item.get("Name", item.get("name", "")),
                transport=item.get("Transport", item.get("transport", "")),
                remote_address=item.get("RemoteAddress", item.get("remote_address", "")),
                hostname=item.get("Hostname", item.get("hostname", "")),
                username=item.get("Username", item.get("username", "")),
                os=item.get("OS", item.get("os", "")),
                arch=item.get("Arch", item.get("arch", "")),
                pid=item.get("PID", item.get("pid", 0)),
                filename=item.get("Filename", item.get("filename", "")),
                active_c2=item.get("ActiveC2", item.get("active_c2", "")),
            ))
        return sessions

    @staticmethod
    def parse_beacons(output: str) -> list[SliverBeacon]:
        """Parse beacons JSON array output."""
        try:
            data = json.loads(output)
        except (json.JSONDecodeError, ValueError):
            return []

        if not isinstance(data, list):
            data = [data] if isinstance(data, dict) else []

        beacons: list[SliverBeacon] = []
        for item in data:
            beacons.append(SliverBeacon(
                beacon_id=str(item.get("ID", item.get("id", ""))),
                name=item.get("Name", item.get("name", "")),
                transport=item.get("Transport", item.get("transport", "")),
                remote_address=item.get("RemoteAddress", item.get("remote_address", "")),
                hostname=item.get("Hostname", item.get("hostname", "")),
                username=item.get("Username", item.get("username", "")),
                os=item.get("OS", item.get("os", "")),
                arch=item.get("Arch", item.get("arch", "")),
                interval=item.get("Interval", item.get("interval", 60)),
                jitter=item.get("Jitter", item.get("jitter", 30)),
                next_checkin=item.get("NextCheckin", item.get("next_checkin", "")),
            ))
        return beacons

    @staticmethod
    def parse_implants(output: str) -> list[SliverImplant]:
        """Parse implants JSON array output."""
        try:
            data = json.loads(output)
        except (json.JSONDecodeError, ValueError):
            return []

        if not isinstance(data, list):
            data = [data] if isinstance(data, dict) else []

        implants: list[SliverImplant] = []
        for item in data:
            c2_urls: list[str] = []
            for c2 in item.get("C2", item.get("c2", [])):
                if isinstance(c2, dict):
                    c2_urls.append(c2.get("URL", c2.get("url", "")))
                elif isinstance(c2, str):
                    c2_urls.append(c2)

            implants.append(SliverImplant(
                implant_id=str(item.get("ID", item.get("id", ""))),
                name=item.get("Name", item.get("name", "")),
                os=item.get("OS", item.get("os", "")),
                arch=item.get("Arch", item.get("arch", "")),
                format=item.get("Format", item.get("format", "")),
                c2_urls=c2_urls,
                is_beacon=item.get("IsBeacon", item.get("is_beacon", False)),
            ))
        return implants
