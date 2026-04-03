"""
Operator Registry - Maps operator names to classes for factory dispatch.

The kernel uses this registry to look up and instantiate operators
by name when scheduling strike cells against the TargetGraph.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hellcat.offensive.operator_base import SecurityOperator

# Registry mapping operator name -> (module_path, class_name)
# Uses lazy imports to avoid pulling in all operators at import time.
_OPERATOR_REGISTRY: dict[str, tuple[str, str]] = {
    # Recon
    "recon": (
        "hellcat.offensive.operators.recon_operator",
        "ReconOperator",
    ),
    # Vuln analysis
    "injection-vuln": (
        "hellcat.offensive.operators.injection_operator",
        "InjectionVulnOperator",
    ),
    "xss-vuln": (
        "hellcat.offensive.operators.xss_operator",
        "XSSVulnOperator",
    ),
    "auth-vuln": (
        "hellcat.offensive.operators.auth_operator",
        "AuthVulnOperator",
    ),
    "authz-vuln": (
        "hellcat.offensive.operators.authz_operator",
        "AuthzVulnOperator",
    ),
    "ssrf-vuln": (
        "hellcat.offensive.operators.ssrf_operator",
        "SSRFVulnOperator",
    ),
    # Exploitation
    "injection-exploit": (
        "hellcat.offensive.operators.injection_operator",
        "InjectionExploitOperator",
    ),
    "xss-exploit": (
        "hellcat.offensive.operators.xss_operator",
        "XSSExploitOperator",
    ),
    "auth-exploit": (
        "hellcat.offensive.operators.auth_operator",
        "AuthExploitOperator",
    ),
    "authz-exploit": (
        "hellcat.offensive.operators.authz_operator",
        "AuthzExploitOperator",
    ),
    "ssrf-exploit": (
        "hellcat.offensive.operators.ssrf_operator",
        "SSRFExploitOperator",
    ),
    # Network operators
    "network-recon": (
        "hellcat.offensive.operators.network_recon_operator",
        "NetworkReconOperator",
    ),
    "service-exploit": (
        "hellcat.offensive.operators.service_exploit_operator",
        "ServiceExploitOperator",
    ),
    "cloud-config": (
        "hellcat.offensive.operators.cloud_config_operator",
        "CloudConfigOperator",
    ),
    # Identity / cloud offensive
    "identity-attack-paths": (
        "hellcat.offensive.operators.identity_operator",
        "IdentityAttackPathOperator",
    ),
    "cloud-offensive": (
        "hellcat.offensive.operators.cloudfox_operator",
        "CloudFoxOperator",
    ),
    # Binary analysis
    "binary-analysis": (
        "hellcat.offensive.operators.binary_analysis_operator",
        "BinaryAnalysisOperator",
    ),
    # Metasploit
    "metasploit": (
        "hellcat.offensive.operators.metasploit_operator",
        "MetasploitOperator",
    ),
    # Sliver C2
    "sliver-c2": (
        "hellcat.offensive.operators.sliver_operator",
        "SliverOperator",
    ),
    # Reporting
    "report": (
        "hellcat.offensive.operators.report_operator",
        "ReportOperator",
    ),
}


def get_operator(name: str) -> SecurityOperator:
    """Instantiate an operator by name.

    Args:
        name: Operator name (e.g., "recon", "injection-vuln", "xss-exploit").

    Returns:
        A new SecurityOperator instance.

    Raises:
        KeyError: If no operator is registered under *name*.
        ImportError: If the operator module cannot be imported.
    """
    import importlib

    key = name.lower()
    if key not in _OPERATOR_REGISTRY:
        raise KeyError(
            f"Unknown operator {name!r}. "
            f"Available: {', '.join(sorted(_OPERATOR_REGISTRY))}"
        )

    module_path, class_name = _OPERATOR_REGISTRY[key]
    module = importlib.import_module(module_path)
    cls = getattr(module, class_name)
    return cls()


def list_operators() -> list[str]:
    """Return all registered operator names."""
    return sorted(_OPERATOR_REGISTRY.keys())


def get_operators_by_type(
    operator_type: str,
) -> list[SecurityOperator]:
    """Instantiate all operators of a given type.

    Args:
        operator_type: One of "recon", "vuln_analysis", "exploitation",
                       "reporting".

    Returns:
        List of SecurityOperator instances matching the type.
    """
    results = []
    for name in _OPERATOR_REGISTRY:
        op = get_operator(name)
        if op.operator_type == operator_type:
            results.append(op)
    return results


def get_operators_by_category(
    category: str,
) -> list[SecurityOperator]:
    """Instantiate all operators covering a vulnerability category.

    Args:
        category: One of "injection", "xss", "auth", "authz", "ssrf",
                  "general".

    Returns:
        List of SecurityOperator instances matching the category.
    """
    results = []
    for name in _OPERATOR_REGISTRY:
        op = get_operator(name)
        if op.vulnerability_category == category:
            results.append(op)
    return results
