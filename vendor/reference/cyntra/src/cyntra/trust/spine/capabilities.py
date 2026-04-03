"""Capability tokens (Spine v1).

Normative reference:
- `docs/specs/cyntra-aegis-spine.md` §5.3 (capability tokens)

This module implements minimal token verification for use by transports and gateways.
It is intentionally policy-light: callers decide which scopes are required.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cyntra.trust.spine.crypto import Ed25519Keypair, sign_by_issuer, verify_signature_by_issuer


def _parse_time(value: str) -> datetime | None:
    try:
        # Accept RFC3339-ish `...Z` used in specs.
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value).astimezone(UTC)
    except Exception:
        return None


def _now_utc() -> datetime:
    return datetime.now(UTC)


def token_is_expired(token: dict[str, Any], *, now: datetime | None = None) -> bool:
    now = now or _now_utc()
    expires_at = token.get("expires_at")
    if not isinstance(expires_at, str) or not expires_at:
        return False
    t = _parse_time(expires_at)
    if t is None:
        return True
    return now >= t


def token_is_not_yet_valid(token: dict[str, Any], *, now: datetime | None = None) -> bool:
    now = now or _now_utc()
    not_before = token.get("not_before")
    if not isinstance(not_before, str) or not not_before:
        return False
    t = _parse_time(not_before)
    if t is None:
        return True
    return now < t


def scope_allows(scope: str, required: str) -> bool:
    """Return True if a granted scope string covers `required`.

    Supported patterns:
    - exact match: `facts:publish:revocation`
    - wildcard suffix: `facts:publish:*` matches any `facts:publish:<kind>`
    - prefix wildcard: `facts:*` matches any `facts:<...>`
    """

    scope = str(scope)
    required = str(required)

    if scope == required:
        return True
    if scope.endswith("*"):
        prefix = scope[:-1]
        return required.startswith(prefix)
    return False


def scopes_allow(scopes: Iterable[str], required_scopes: Iterable[str]) -> bool:
    scopes_list = list(scopes)
    required = list(required_scopes)
    # All required scopes must be satisfied by at least one granted scope.
    return all(any(scope_allows(granted, req) for granted in scopes_list) for req in required)


def fact_kind_from_schema(fact_schema: str) -> str | None:
    prefix = "aegis.spine.fact."
    if not fact_schema.startswith(prefix):
        return None
    rest = fact_schema[len(prefix) :]
    # `incident.v1` -> `incident`
    if ".v" in rest:
        return rest.split(".v", 1)[0]
    return rest


def required_scopes_for_fact_schema(fact_schema: str) -> list[str]:
    kind = fact_kind_from_schema(fact_schema)
    if not kind:
        return []

    # Privileged facts use dedicated publish scopes.
    if kind == "policy_delta":
        return ["policy:publish"]
    if kind == "revocation":
        return ["revocation:publish"]
    if kind == "log_checkpoint":
        return ["log:publish_checkpoint"]
    return [f"facts:publish:{kind}"]


@dataclass(frozen=True)
class CapabilityPolicy:
    """Local policy knobs for token enforcement."""

    require_token_for_fact_schemas: set[str]
    trusted_token_issuers: set[str]
    allow_self_issued_tokens: bool = True


def sign_capability_token(token: dict[str, Any], keypair: Ed25519Keypair) -> dict[str, Any]:
    """Sign a token in-place (returns a new dict)."""
    signed = dict(token)
    signed["signature"] = sign_by_issuer(signed, keypair)
    return signed


def verify_capability_token(
    token: dict[str, Any],
    *,
    envelope_issuer: str,
    required_scopes: list[str],
    policy: CapabilityPolicy,
    revoked_token_ids: set[str] | None = None,
    revoked_issuers: set[str] | None = None,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Verify token signature, validity window, and scope.

    Returns `(ok, reason)` where `reason` is stable-ish for audit logs.
    """

    revoked_token_ids = revoked_token_ids or set()
    revoked_issuers = revoked_issuers or set()
    now = now or _now_utc()

    token_id = token.get("token_id")
    if not isinstance(token_id, str) or not token_id:
        return False, "invalid_token_id"
    if token_id in revoked_token_ids:
        return False, "revoked_token_id"

    issuer = token.get("issuer")
    if not isinstance(issuer, str) or not issuer:
        return False, "invalid_token_issuer"
    if issuer in revoked_issuers:
        return False, "revoked_token_issuer"

    subject = token.get("subject")
    if not isinstance(subject, str) or not subject:
        return False, "invalid_token_subject"
    if subject != envelope_issuer:
        return False, "token_subject_mismatch"

    if token_is_not_yet_valid(token, now=now):
        return False, "token_not_yet_valid"
    if token_is_expired(token, now=now):
        return False, "token_expired"

    if not verify_signature_by_issuer(token):
        return False, "invalid_token_signature"

    if issuer == envelope_issuer:
        if not policy.allow_self_issued_tokens:
            return False, "self_issued_tokens_disallowed"
    else:
        if policy.trusted_token_issuers and issuer not in policy.trusted_token_issuers:
            return False, "untrusted_token_issuer"

    scopes = token.get("scopes")
    if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
        return False, "invalid_token_scopes"

    if required_scopes and not scopes_allow(scopes, required_scopes):
        return False, "missing_required_scope"

    return True, "ok"
