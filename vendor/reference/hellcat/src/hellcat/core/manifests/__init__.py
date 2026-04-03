"""
Hellcat Manifests - Portable toolchain specifications.

A manifest is the complete specification for running a toolchain,
including task definition, requirements, runtime config, and gates.
Manifests are portable: the same manifest can run on any provider
that satisfies its requirements.
"""

from hellcat.core.manifests.loader import load_manifest, save_manifest
from hellcat.core.manifests.schema import (
    ContextSpec,
    GateSpec,
    RuntimeConfig,
    SecurityPolicy,
    ShieldSpec,
    TaskSpec,
    ToolchainManifest,
)
from hellcat.core.manifests.validator import ManifestValidationError, validate_manifest

__all__ = [
    "ToolchainManifest",
    "TaskSpec",
    "RuntimeConfig",
    "GateSpec",
    "ContextSpec",
    "SecurityPolicy",
    "ShieldSpec",
    "load_manifest",
    "save_manifest",
    "validate_manifest",
    "ManifestValidationError",
]
