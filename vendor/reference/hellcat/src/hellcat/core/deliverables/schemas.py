"""JSON schemas for each deliverable type.

Each schema defines required fields and constraints for validation
before a deliverable is written to the TargetGraph.
"""

from __future__ import annotations

from typing import Any

# Schema format: {field_name: {"type": str, "required": bool}}
# type values: "str", "float", "int", "bool", "list", "dict"

_VULN_FINDING_SCHEMA: dict[str, dict[str, Any]] = {
    "vuln_type": {"type": "str", "required": True},
    "severity": {"type": "str", "required": True, "values": ["info", "low", "medium", "high", "critical"]},
    "confidence": {"type": "float", "required": True, "min": 0.0, "max": 1.0},
    "description": {"type": "str", "required": True},
    "endpoint": {"type": "str", "required": False},
    "cvss": {"type": "float", "required": False, "min": 0.0, "max": 10.0},
    "evidence_summary": {"type": "str", "required": False},
    "attack_tid": {"type": "str", "required": False},
    "attack_tactic": {"type": "str", "required": False},
}

_EXPLOIT_RESULT_SCHEMA: dict[str, dict[str, Any]] = {
    "vuln_type": {"type": "str", "required": True},
    "payload": {"type": "str", "required": True},
    "proof_level": {"type": "str", "required": True, "values": ["L1", "L2", "L3", "L4"]},
    "impact_description": {"type": "str", "required": True},
    "response_summary": {"type": "str", "required": False},
    "data_extracted": {"type": "dict", "required": False},
    "reproduction_steps": {"type": "str", "required": False},
    "attack_tid": {"type": "str", "required": False},
}

_CREDENTIAL_SCHEMA: dict[str, dict[str, Any]] = {
    "username": {"type": "str", "required": True},
    "credential_type": {"type": "str", "required": True, "values": ["password", "hash", "token", "cookie", "api_key", "ssh_key", "certificate"]},
    "access_level": {"type": "str", "required": False},
    "source": {"type": "str", "required": False},
}

_DEFENSE_OBSERVATION_SCHEMA: dict[str, dict[str, Any]] = {
    "defense_type": {"type": "str", "required": True, "values": ["waf", "rate_limiter", "input_validation", "csrf_token", "auth_mechanism", "captcha", "ip_allowlist"]},
    "strength": {"type": "str", "required": False},
    "observed_behavior": {"type": "str", "required": True},
    "bypass_possible": {"type": "bool", "required": False},
}

_ENDPOINT_SCHEMA: dict[str, dict[str, Any]] = {
    "url": {"type": "str", "required": True},
    "method": {"type": "str", "required": False},
    "tech_stack": {"type": "str", "required": False},
    "description": {"type": "str", "required": False},
    "has_auth": {"type": "bool", "required": False},
}


_PHISHING_RESULT_SCHEMA: dict[str, dict[str, Any]] = {
    "campaign_name": {"type": "str", "required": True},
    "targets_sent": {"type": "int", "required": True},
    "emails_opened": {"type": "int", "required": True},
    "links_clicked": {"type": "int", "required": True},
    "credentials_captured": {"type": "int", "required": True},
    "reported_count": {"type": "int", "required": False},
}


DELIVERABLE_SCHEMAS: dict[str, dict[str, dict[str, Any]]] = {
    "vuln_finding": _VULN_FINDING_SCHEMA,
    "exploit_result": _EXPLOIT_RESULT_SCHEMA,
    "credential": _CREDENTIAL_SCHEMA,
    "defense_observation": _DEFENSE_OBSERVATION_SCHEMA,
    "endpoint": _ENDPOINT_SCHEMA,
    "phishing_result": _PHISHING_RESULT_SCHEMA,
}


def validate_against_schema(
    data: dict[str, Any],
    schema: dict[str, dict[str, Any]],
) -> list[str]:
    """Validate data dict against a schema. Returns list of error messages."""
    errors: list[str] = []

    for field_name, rules in schema.items():
        value = data.get(field_name)

        # Check required
        if rules.get("required") and (value is None or value == ""):
            errors.append(f"Missing required field: {field_name}")
            continue

        if value is None:
            continue

        # Check type
        expected_type = rules.get("type")
        type_map = {
            "str": str, "float": (int, float), "int": int,
            "bool": bool, "list": list, "dict": dict,
        }
        if expected_type and expected_type in type_map:
            expected = type_map[expected_type]
            if not isinstance(value, expected):
                errors.append(f"Field {field_name}: expected {expected_type}, got {type(value).__name__}")
                continue

        # Check allowed values
        allowed = rules.get("values")
        if allowed and value not in allowed:
            errors.append(f"Field {field_name}: '{value}' not in {allowed}")

        # Check numeric range
        if isinstance(value, (int, float)):
            min_val = rules.get("min")
            max_val = rules.get("max")
            if min_val is not None and value < min_val:
                errors.append(f"Field {field_name}: {value} < min {min_val}")
            if max_val is not None and value > max_val:
                errors.append(f"Field {field_name}: {value} > max {max_val}")

    return errors
