"""
Manifest Validator - Validate manifests for correctness.
"""

from __future__ import annotations

from dataclasses import dataclass

from hellcat.core.manifests.schema import (
    GateSpec,
    RuntimeConfig,
    SecurityPolicy,
    ShieldSpec,
    TaskSpec,
    ToolchainManifest,
)


class ManifestValidationError(Exception):
    """Raised when manifest validation fails."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(f"Manifest validation failed: {'; '.join(errors)}")


@dataclass
class ValidationResult:
    """Result of manifest validation."""

    valid: bool
    errors: list[str]
    warnings: list[str]

    def raise_if_invalid(self) -> None:
        """Raise ManifestValidationError if not valid."""
        if not self.valid:
            raise ManifestValidationError(self.errors)


def validate_manifest(manifest: ToolchainManifest) -> ValidationResult:
    """
    Validate a manifest for correctness.

    Checks:
    - Required fields are present
    - Field values are valid
    - Cross-field consistency
    - Provider compatibility

    Args:
        manifest: Manifest to validate

    Returns:
        ValidationResult with errors and warnings
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Validate schema version
    if not manifest.schema_version:
        errors.append("schema_version is required")
    elif not manifest.schema_version.startswith("2."):
        warnings.append(f"Schema version {manifest.schema_version} may not be fully supported")

    # Validate toolchain
    if not manifest.toolchain:
        errors.append("toolchain is required")

    # Validate task
    task_errors, task_warnings = _validate_task(manifest.task)
    errors.extend(task_errors)
    warnings.extend(task_warnings)

    # Validate runtime
    runtime_errors, runtime_warnings = _validate_runtime(manifest.runtime)
    errors.extend(runtime_errors)
    warnings.extend(runtime_warnings)

    # Validate gates
    for i, gate in enumerate(manifest.gates):
        gate_errors, gate_warnings = _validate_gate(gate, i)
        errors.extend(gate_errors)
        warnings.extend(gate_warnings)

    # Validate security policy
    security_errors, security_warnings = _validate_security(manifest.security)
    errors.extend(security_errors)
    warnings.extend(security_warnings)

    # Validate shields
    for i, shield in enumerate(manifest.shields):
        shield_errors, shield_warnings = _validate_shield(shield, i)
        errors.extend(shield_errors)
        warnings.extend(shield_warnings)

    # Validate requirements consistency
    req_errors, req_warnings = _validate_requirements(manifest)
    errors.extend(req_errors)
    warnings.extend(req_warnings)

    # Validate speculate configuration
    if manifest.speculate:
        if manifest.speculate_parallelism < 2:
            errors.append("speculate_parallelism must be >= 2 when speculate=True")
        if manifest.speculate_parallelism > 5:
            warnings.append(f"High speculate_parallelism ({manifest.speculate_parallelism}) may be costly")

    return ValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings
    )


def _validate_task(task: TaskSpec) -> tuple[list[str], list[str]]:
    """Validate task specification."""
    errors = []
    warnings = []

    if not task.issue_id:
        errors.append("task.issue_id is required")

    if not task.title:
        errors.append("task.title is required")

    if not task.description and task.job_type == "code":
        warnings.append("task.description is recommended for code tasks")

    if task.job_type == "custom" and not task.entrypoint:
        errors.append("task.entrypoint is required for custom job_type")

    # Check for potentially dangerous forbidden paths
    dangerous_forbidden = ["/", "/home", "/root", "/etc"]
    for path in task.forbidden_paths:
        if path in dangerous_forbidden:
            warnings.append(f"Broad forbidden path '{path}' may cause issues")

    return errors, warnings


def _validate_runtime(runtime: RuntimeConfig) -> tuple[list[str], list[str]]:
    """Validate runtime configuration."""
    errors = []
    warnings = []

    # Timeout validation
    if runtime.timeout.total_seconds() < 10:
        errors.append("runtime.timeout must be at least 10 seconds")
    elif runtime.timeout.total_seconds() < 60:
        warnings.append("Short timeout may cause premature failures")
    elif runtime.timeout.total_seconds() > 86400:  # 24 hours
        warnings.append("Very long timeout (>24h) may not be supported by all providers")

    # Retry validation
    if runtime.max_retries < 0:
        errors.append("runtime.max_retries must be >= 0")
    elif runtime.max_retries > 10:
        warnings.append("High max_retries may cause long execution times")

    # Sampling validation
    if "temperature" in runtime.sampling:
        temp = runtime.sampling["temperature"]
        if not 0 <= temp <= 2:
            errors.append("sampling.temperature must be between 0 and 2")

    if "top_p" in runtime.sampling:
        top_p = runtime.sampling["top_p"]
        if not 0 <= top_p <= 1:
            errors.append("sampling.top_p must be between 0 and 1")

    # Secrets validation
    for secret in runtime.secrets:
        if not secret.replace("_", "").replace("-", "").isalnum():
            warnings.append(f"Secret name '{secret}' may have compatibility issues")

    return errors, warnings


def _validate_gate(gate: GateSpec, index: int) -> tuple[list[str], list[str]]:
    """Validate a gate specification."""
    errors = []
    warnings = []

    prefix = f"gates[{index}]"

    if not gate.name:
        errors.append(f"{prefix}.name is required")

    if not gate.command:
        errors.append(f"{prefix}.command is required")

    if gate.timeout.total_seconds() < 1:
        errors.append(f"{prefix}.timeout must be at least 1 second")
    elif gate.timeout.total_seconds() > 3600:
        warnings.append(f"{prefix}.timeout is very long (>1h)")

    # Check for potentially dangerous commands
    dangerous_patterns = ["rm -rf", "sudo", "> /dev/", "mkfs", "dd if="]
    for pattern in dangerous_patterns:
        if pattern in gate.command:
            warnings.append(f"{prefix}.command contains potentially dangerous pattern: {pattern}")

    return errors, warnings


def _validate_security(policy: SecurityPolicy) -> tuple[list[str], list[str]]:
    """Validate security policy configuration."""
    errors: list[str] = []
    warnings: list[str] = []

    allowed_egress_modes = {"deny_all", "allowlist", "open"}
    if policy.egress_mode not in allowed_egress_modes:
        errors.append(f"security.egress_mode must be one of {sorted(allowed_egress_modes)}")

    if policy.egress_mode == "allowlist" and not (
        policy.allowed_domains or policy.allowed_ip_cidrs
    ):
        warnings.append("security.egress_mode=allowlist with empty allowlist")

    if not policy.allowed_write_roots:
        errors.append("security.allowed_write_roots must not be empty")

    if any(root == "/" for root in policy.allowed_write_roots):
        warnings.append("security.allowed_write_roots includes '/' (broad write access)")

    allowed_actions = {"cancel", "isolate", "revoke", "escalate", "speculate_vote"}
    if policy.on_violation not in allowed_actions:
        errors.append(f"security.on_violation must be one of {sorted(allowed_actions)}")

    overlap = set(policy.allowed_domains) & set(policy.deny_domains)
    if overlap:
        warnings.append(f"security.allowed_domains overlaps deny_domains: {sorted(overlap)}")

    return errors, warnings


def _validate_shield(spec: ShieldSpec, index: int) -> tuple[list[str], list[str]]:
    """Validate shield configuration."""
    errors: list[str] = []
    warnings: list[str] = []

    prefix = f"shields[{index}]"

    if not spec.name:
        errors.append(f"{prefix}.name is required")

    if spec.mode not in {None, "inline", "export", "ingest"}:
        errors.append(f"{prefix}.mode must be inline, export, ingest, or null")

    return errors, warnings


def _validate_requirements(manifest: ToolchainManifest) -> tuple[list[str], list[str]]:
    """Validate requirements consistency with task."""
    errors = []
    warnings = []

    req = manifest.requirements
    task = manifest.task
    runtime = manifest.runtime

    # GPU requirements
    if runtime.prefer_gpu and not req.gpu:
        warnings.append("runtime.prefer_gpu=True but requirements.gpu=False")

    # Job type consistency
    if task.job_type == "fab-world" and not req.gpu:
        warnings.append("fab-world job type typically requires GPU")

    # Provider hint validation
    if manifest.provider_hint:
        known_providers = [
            "local",
            "e2b",
            "modal",
            "mcp",
            "gpu-pool",
            "ray",
            "dagster",
            "airflow",
            "n8n",
            "devin",
            "youtu-agent",
        ]
        if manifest.provider_hint not in known_providers:
            warnings.append(f"Unknown provider hint: {manifest.provider_hint}")

    return errors, warnings


def validate_manifest_dict(data: dict) -> ValidationResult:
    """
    Validate manifest data before deserializing.

    Useful for validating user input before creating a manifest object.

    Args:
        data: Raw manifest data

    Returns:
        ValidationResult
    """
    errors = []
    warnings = []

    # Required top-level fields
    required_fields = ["toolchain", "task"]
    for field in required_fields:
        if field not in data:
            errors.append(f"Missing required field: {field}")

    # Task validation
    if "task" in data and isinstance(data["task"], dict):
        task = data["task"]
        if "issue_id" not in task:
            errors.append("task.issue_id is required")
        if "title" not in task:
            errors.append("task.title is required")

    # Try to deserialize and validate
    if not errors:
        try:
            manifest = ToolchainManifest.from_dict(data)
            result = validate_manifest(manifest)
            errors.extend(result.errors)
            warnings.extend(result.warnings)
        except Exception as e:
            errors.append(f"Failed to parse manifest: {e}")

    return ValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings
    )
