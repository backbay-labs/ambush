#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATED_CLIENT_ROOT = REPO_ROOT / "clients/python/swarm-platform-client"
sys.path.insert(0, str(GENERATED_CLIENT_ROOT))

from swarm_platform_client import AuthenticatedClient  # noqa: E402
from swarm_platform_client.api.platform import (  # noqa: E402
    get_asset_posture,
    get_runtime_status,
    list_findings,
    list_incidents,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Smoke-test the generated platform API Python client against a live Swarm runtime."
    )
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--bearer-token", required=True)
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--schema-version", type=int, default=1)
    parser.add_argument("--expected-hunt-id", required=True)
    parser.add_argument("--expected-finding-id", required=True)
    parser.add_argument("--expected-incident-id", required=True)
    parser.add_argument("--expected-host-id", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client = AuthenticatedClient(
        base_url=args.base_url,
        token=args.bearer_token,
        headers={"x-api-key": args.api_key},
        raise_on_unexpected_status=True,
    )

    runtime_status = get_runtime_status.sync(
        client=client,
        x_swarm_schema_version=args.schema_version,
    )
    if runtime_status is None or len(runtime_status.data) != 1:
        raise AssertionError("expected one runtime status document")

    findings = list_findings.sync(
        client=client,
        hunt_id=args.expected_hunt_id,
        x_swarm_schema_version=args.schema_version,
    )
    if findings is None or len(findings.data) != 1:
        raise AssertionError("expected one finding for the seeded hunt")
    finding = findings.data[0]
    if finding.finding.finding_id != args.expected_finding_id:
        raise AssertionError(
            f"unexpected finding id: {finding.finding.finding_id} != {args.expected_finding_id}"
        )

    incidents = list_incidents.sync(
        client=client,
        incident_id=args.expected_incident_id,
        x_swarm_schema_version=args.schema_version,
    )
    if incidents is None or len(incidents.data) != 1:
        raise AssertionError("expected one incident for the seeded incident id")
    incident = incidents.data[0]
    if incident.incident_id != args.expected_incident_id:
        raise AssertionError(
            f"unexpected incident id: {incident.incident_id} != {args.expected_incident_id}"
        )

    posture = get_asset_posture.sync(
        args.expected_host_id,
        client=client,
        x_swarm_schema_version=args.schema_version,
    )
    if posture is None or len(posture.data) != 1:
        raise AssertionError("expected one asset posture record")
    host_posture = posture.data[0]
    if host_posture.host_id != args.expected_host_id:
        raise AssertionError(
            f"unexpected host id: {host_posture.host_id} != {args.expected_host_id}"
        )

    print(
        json.dumps(
            {
                "runtime_mode": runtime_status.data[0].mode_state.to_dict(),
                "finding_id": finding.finding.finding_id,
                "incident_id": incident.incident_id,
                "host_id": host_posture.host_id,
                "asset_posture_findings": len(host_posture.recent_findings),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
