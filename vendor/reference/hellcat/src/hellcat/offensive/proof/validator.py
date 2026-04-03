"""
ProofValidator - L1-L4 evidence gate pipeline for security findings.

Runs schema validation, evidence-level checks, confidence gates,
and optional reproduction before recording validated findings to the
TargetGraph.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import structlog

from hellcat.offensive.proof.evidence import (
    EVIDENCE_REQUIREMENTS,
    EvidenceLevel,
    SecurityProof,
)
from hellcat.offensive.proof.reproducer import ExploitReproducer

logger = structlog.get_logger()

# Ordered from lowest to highest so we can downgrade by stepping backwards.
_LEVEL_ORDER: list[EvidenceLevel] = [
    EvidenceLevel.L1_INFORMATIONAL,
    EvidenceLevel.L2_LIKELY,
    EvidenceLevel.L3_CONFIRMED,
    EvidenceLevel.L4_EXPLOITED,
]


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class GateResult:
    """Outcome of a single validation gate."""

    name: str
    passed: bool
    message: str
    duration_ms: int = 0


@dataclass
class ValidationResult:
    """Full validation outcome for a SecurityProof."""

    proof: SecurityProof
    valid: bool
    validated_level: EvidenceLevel
    original_level: EvidenceLevel
    downgraded: bool
    gate_results: dict[str, GateResult] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


class ProofValidator:
    """Validate SecurityProofs through the L1-L4 evidence gate pipeline.

    The validator works standalone but can optionally record validated
    findings to a TargetGraph instance.

    Pipeline steps:
        1. Schema validation   - required fields present and non-empty
        2. Evidence level check - does evidence actually meet the claimed level?
        3. Confidence check     - is confidence >= min for the level?
        4. Reproduction gate    - L3+ only, calls ExploitReproducer
        5. Record to TargetGraph (if available)
    """

    def __init__(
        self,
        target_graph: object | None = None,
        reproducer: ExploitReproducer | None = None,
    ) -> None:
        self.target_graph = target_graph
        self.reproducer = reproducer or ExploitReproducer()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(self, proof: SecurityProof) -> ValidationResult:
        """Run the full validation pipeline on a single proof."""
        original_level = proof.claimed_level
        current_level = original_level
        gates: dict[str, GateResult] = {}
        errors: list[str] = []
        warnings: list[str] = []

        log = logger.bind(
            vuln_node_id=proof.vuln_node_id,
            operator=proof.operator_name,
            claimed_level=original_level.value,
        )

        # -- Step 1: Schema validation --
        gate = self._gate_schema(proof, current_level)
        gates["schema"] = gate
        if not gate.passed:
            current_level = self._downgrade_to_met(proof)
            warnings.append(
                f"schema gate failed for {original_level.value}, "
                f"downgraded to {current_level.value}"
            )

        # -- Step 2: Evidence level check --
        gate = self._gate_evidence(proof, current_level)
        gates["evidence"] = gate
        if not gate.passed:
            current_level = self._downgrade_to_met(proof)
            warnings.append(
                f"evidence gate: downgraded to {current_level.value}"
            )

        # -- Step 3: Confidence check --
        gate = self._gate_confidence(proof, current_level)
        gates["confidence"] = gate
        if not gate.passed:
            # Try one level lower
            prev = self._level_below(current_level)
            if prev is not None:
                current_level = prev
                warnings.append(
                    f"confidence too low for {gate.message}; "
                    f"downgraded to {current_level.value}"
                )
            else:
                errors.append("confidence below L1 minimum")

        # -- Step 4: Reproduction gate (L3+ only) --
        req = EVIDENCE_REQUIREMENTS[current_level]
        if req.requires_reproduction:
            gate = self._gate_reproduction(proof)
            gates["reproduction"] = gate
            if not gate.passed:
                # Downgrade to L2 since reproduction failed
                current_level = EvidenceLevel.L2_LIKELY
                warnings.append(
                    "reproduction failed; downgraded to L2"
                )
        else:
            gates["reproduction"] = GateResult(
                name="reproduction",
                passed=True,
                message="not required for this level",
            )

        downgraded = current_level != original_level
        valid = len(errors) == 0

        # -- Step 5: Record to TargetGraph --
        if valid and self.target_graph is not None:
            self._record_to_graph(proof, current_level)

        log.info(
            "proof.validated",
            valid=valid,
            validated_level=current_level.value,
            downgraded=downgraded,
            errors=errors,
        )

        return ValidationResult(
            proof=proof,
            valid=valid,
            validated_level=current_level,
            original_level=original_level,
            downgraded=downgraded,
            gate_results=gates,
            errors=errors,
            warnings=warnings,
        )

    def validate_batch(self, proofs: list[SecurityProof]) -> list[ValidationResult]:
        """Validate a list of proofs sequentially."""
        return [self.validate(p) for p in proofs]

    def speculate_and_vote(
        self,
        proofs: list[SecurityProof],
        threshold: float = 0.7,
    ) -> SecurityProof | None:
        """Multiple operators vote on whether a finding is valid.

        Accept if >= *threshold* fraction of proofs agree the vulnerability
        exists (validated_level >= L1 and valid). Returns the highest-evidence
        proof from the agreeing voters, or None if the vote fails.
        """
        if not proofs:
            return None

        results = self.validate_batch(proofs)
        valid_results = [r for r in results if r.valid]

        if not valid_results:
            return None

        agree_ratio = len(valid_results) / len(results)
        if agree_ratio < threshold:
            logger.info(
                "proof.vote.rejected",
                agree_ratio=agree_ratio,
                threshold=threshold,
                total=len(results),
            )
            return None

        # Return the proof with the highest validated level
        best = max(
            valid_results,
            key=lambda r: _LEVEL_ORDER.index(r.validated_level),
        )

        logger.info(
            "proof.vote.accepted",
            agree_ratio=agree_ratio,
            best_level=best.validated_level.value,
        )

        return best.proof

    # ------------------------------------------------------------------
    # Gate implementations
    # ------------------------------------------------------------------

    def _gate_schema(self, proof: SecurityProof, level: EvidenceLevel) -> GateResult:
        """Check all required fields for the claimed level are present and non-empty."""
        start = time.monotonic()
        req = EVIDENCE_REQUIREMENTS[level]
        missing: list[str] = []

        for fld in req.required_fields:
            value = getattr(proof, fld, "")
            if not value:
                missing.append(fld)

        passed = len(missing) == 0
        duration_ms = int((time.monotonic() - start) * 1000)
        msg = "all fields present" if passed else f"missing: {', '.join(missing)}"

        return GateResult(name="schema", passed=passed, message=msg, duration_ms=duration_ms)

    def _gate_evidence(self, proof: SecurityProof, level: EvidenceLevel) -> GateResult:
        """Verify the proof evidence actually meets the claimed level."""
        start = time.monotonic()
        req = EVIDENCE_REQUIREMENTS[level]

        issues: list[str] = []
        if req.requires_payload and not proof.witness_payload:
            issues.append("requires witness_payload")
        if req.requires_impact and not (
            proof.impact_description
            or proof.data_accessed
            or proof.privilege_gained
        ):
            issues.append("requires impact demonstration")

        passed = len(issues) == 0
        duration_ms = int((time.monotonic() - start) * 1000)
        msg = "evidence sufficient" if passed else "; ".join(issues)

        return GateResult(name="evidence", passed=passed, message=msg, duration_ms=duration_ms)

    def _gate_confidence(self, proof: SecurityProof, level: EvidenceLevel) -> GateResult:
        """Check confidence meets the minimum threshold for the level."""
        start = time.monotonic()
        req = EVIDENCE_REQUIREMENTS[level]
        passed = proof.confidence >= req.min_confidence
        duration_ms = int((time.monotonic() - start) * 1000)
        msg = (
            f"confidence {proof.confidence:.2f} >= {req.min_confidence:.2f}"
            if passed
            else f"confidence {proof.confidence:.2f} < {req.min_confidence:.2f} for {level.value}"
        )

        return GateResult(name="confidence", passed=passed, message=msg, duration_ms=duration_ms)

    def _gate_reproduction(self, proof: SecurityProof) -> GateResult:
        """Attempt to reproduce the exploit via the ExploitReproducer."""
        start = time.monotonic()

        result = self.reproducer.reproduce(proof)
        proof.reproduction_result = result

        duration_ms = int((time.monotonic() - start) * 1000)
        if result.reproduced:
            msg = f"reproduced in {result.attempts} attempt(s)"
        else:
            msg = f"reproduction failed: {result.error or 'response mismatch'}"

        return GateResult(
            name="reproduction",
            passed=result.reproduced,
            message=msg,
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _downgrade_to_met(self, proof: SecurityProof) -> EvidenceLevel:
        """Find the highest evidence level the proof actually satisfies."""
        # Walk from highest to lowest, return first level whose schema passes.
        for level in reversed(_LEVEL_ORDER):
            req = EVIDENCE_REQUIREMENTS[level]
            all_present = all(
                getattr(proof, fld, "") for fld in req.required_fields
            )
            if all_present and proof.confidence >= req.min_confidence:
                return level

        # Fallback: everything at least meets L1 schema if description exists.
        return EvidenceLevel.L1_INFORMATIONAL

    @staticmethod
    def _level_below(level: EvidenceLevel) -> EvidenceLevel | None:
        idx = _LEVEL_ORDER.index(level)
        if idx == 0:
            return None
        return _LEVEL_ORDER[idx - 1]

    def _record_to_graph(self, proof: SecurityProof, level: EvidenceLevel) -> None:
        """Update the TargetGraph with the validated finding.

        Uses duck-typed access so the validator does not hard-depend
        on TargetGraph being imported.
        """
        graph = self.target_graph
        if graph is None:
            return

        try:
            node = graph.get_node(proof.vuln_node_id)  # type: ignore[union-attr]
            if node is None:
                logger.warning(
                    "proof.record.node_not_found",
                    vuln_node_id=proof.vuln_node_id,
                )
                return

            import json

            existing_meta = json.loads(node.get("metadata_json", "{}"))
            existing_meta["validated_level"] = level.value
            existing_meta["confidence"] = proof.confidence
            if proof.cvss is not None:
                existing_meta["cvss"] = proof.cvss

            graph.conn.execute(  # type: ignore[union-attr]
                "UPDATE vulnerabilities SET metadata_json = ? WHERE id = ?",
                (json.dumps(existing_meta, sort_keys=True, separators=(",", ":")), proof.vuln_node_id),
            )
            graph.conn.commit()  # type: ignore[union-attr]

            logger.debug(
                "proof.record.updated",
                vuln_node_id=proof.vuln_node_id,
                validated_level=level.value,
            )
        except Exception:
            logger.exception("proof.record.failed", vuln_node_id=proof.vuln_node_id)
