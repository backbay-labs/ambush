"""
ExploitReproducer - HTTP-based reproduction gate for L3+ security proofs.

Attempts to replay the witness payload against the target endpoint and
verify that the response matches the claimed evidence.  Uses only
urllib.request (stdlib) to avoid extra dependencies.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass

import structlog

from hellcat.offensive.proof.evidence import ReproductionResult, SecurityProof

logger = structlog.get_logger()

_MAX_RESPONSE_SNIPPET = 500
_DEFAULT_TIMEOUT_S = 15
_MAX_ATTEMPTS = 3


@dataclass
class ReproducerConfig:
    """Tuning knobs for the reproduction gate."""

    timeout_s: int = _DEFAULT_TIMEOUT_S
    max_attempts: int = _MAX_ATTEMPTS
    user_agent: str = "Hellcat-Reproducer/1.0"


class ExploitReproducer:
    """Re-execute an exploit to confirm L3+ findings.

    For L3 proofs the reproducer sends the witness_payload to the
    source_location and checks whether response_evidence appears in the
    actual response body.

    For L4 proofs the same HTTP replay is performed; full multi-step
    chain reproduction is reserved for a future iteration.
    """

    def __init__(self, config: ReproducerConfig | None = None) -> None:
        self.config = config or ReproducerConfig()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reproduce(self, proof: SecurityProof, target_url: str | None = None) -> ReproductionResult:
        """Attempt to reproduce a claimed exploit.

        Args:
            proof: The security proof containing payload and expected evidence.
            target_url: Override URL. Falls back to ``proof.source_location``.

        Returns:
            ReproductionResult summarising the outcome.
        """
        url = target_url or proof.source_location
        if not url:
            return ReproductionResult(
                reproduced=False,
                attempts=0,
                matching_response=False,
                response_snippet="",
                duration_ms=0,
                error="no target URL or source_location provided",
            )

        logger.info(
            "proof.reproduce.start",
            operator=proof.operator_name,
            url=url,
            claimed_level=proof.claimed_level.value,
        )

        last_error: str | None = None
        for attempt in range(1, self.config.max_attempts + 1):
            result = self._single_attempt(proof, url, attempt)
            if result.reproduced:
                return result
            last_error = result.error

        # All attempts failed
        return ReproductionResult(
            reproduced=False,
            attempts=self.config.max_attempts,
            matching_response=False,
            response_snippet="",
            duration_ms=0,
            error=last_error,
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _single_attempt(
        self,
        proof: SecurityProof,
        url: str,
        attempt: int,
    ) -> ReproductionResult:
        """Run one reproduction attempt via urllib.request."""
        start = time.monotonic()
        try:
            req = self._build_request(proof, url)
            with urllib.request.urlopen(req, timeout=self.config.timeout_s) as resp:  # noqa: S310
                body = resp.read().decode("utf-8", errors="replace")

            duration_ms = int((time.monotonic() - start) * 1000)
            snippet = body[:_MAX_RESPONSE_SNIPPET]
            matching = self._check_match(proof.response_evidence, body)

            logger.debug(
                "proof.reproduce.attempt",
                attempt=attempt,
                matching=matching,
                duration_ms=duration_ms,
            )

            return ReproductionResult(
                reproduced=matching,
                attempts=attempt,
                matching_response=matching,
                response_snippet=snippet,
                duration_ms=duration_ms,
            )

        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            error_msg = f"{type(exc).__name__}: {exc}"

            # An HTTP error response may still contain matching evidence
            if isinstance(exc, urllib.error.HTTPError) and exc.fp is not None:
                body = exc.fp.read().decode("utf-8", errors="replace")
                snippet = body[:_MAX_RESPONSE_SNIPPET]
                matching = self._check_match(proof.response_evidence, body)
                if matching:
                    return ReproductionResult(
                        reproduced=True,
                        attempts=attempt,
                        matching_response=True,
                        response_snippet=snippet,
                        duration_ms=duration_ms,
                    )

            logger.warning(
                "proof.reproduce.error",
                attempt=attempt,
                error=error_msg,
            )

            return ReproductionResult(
                reproduced=False,
                attempts=attempt,
                matching_response=False,
                response_snippet="",
                duration_ms=duration_ms,
                error=error_msg,
            )

    def _build_request(self, proof: SecurityProof, url: str) -> urllib.request.Request:
        """Build an HTTP request from the proof's witness payload."""
        headers = {"User-Agent": self.config.user_agent}

        if proof.witness_payload:
            # POST with the witness payload as the body
            data = proof.witness_payload.encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            return urllib.request.Request(url, data=data, headers=headers, method="POST")

        # No payload: simple GET
        return urllib.request.Request(url, headers=headers, method="GET")

    @staticmethod
    def _check_match(expected_evidence: str, response_body: str) -> bool:
        """Check whether the expected evidence appears in the response."""
        if not expected_evidence:
            return False
        return expected_evidence in response_body
