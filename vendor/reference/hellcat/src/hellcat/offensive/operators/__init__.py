"""
Security Operators - Hellcat pentesting operators.

Each operator wraps one or more prompt templates and exposes
them as Hellcat toolchain adapters that the kernel can schedule and
dispatch against targets in the TargetGraph.

Operator lifecycle:
    ReconOperator -> [vuln operators in parallel] -> [exploit operators] -> ReportOperator

Vuln analysis operators (run in parallel after recon):
    InjectionVulnOperator, XSSVulnOperator, AuthVulnOperator,
    AuthzVulnOperator, SSRFVulnOperator

Exploitation operators (run after their corresponding vuln operator):
    InjectionExploitOperator, XSSExploitOperator, AuthExploitOperator,
    AuthzExploitOperator, SSRFExploitOperator

Network/cloud operators (extend beyond web apps):
    NetworkReconOperator, ServiceExploitOperator, CloudConfigOperator

Identity and cloud offensive operators:
    IdentityAttackPathOperator (BloodHound CE / AD / Entra ID attack paths)
    CloudFoxOperator (CloudFox + PMapper cloud privilege escalation)

C2 frameworks:
    SliverOperator (Sliver implant generation + lateral movement)

Social engineering operators:
    PhishingOperator (GoPhish campaign management)

Binary analysis operators:
    BinaryAnalysisOperator
"""

from hellcat.offensive.operators.auth_operator import (
    AuthExploitOperator,
    AuthVulnOperator,
)
from hellcat.offensive.operators.authz_operator import (
    AuthzExploitOperator,
    AuthzVulnOperator,
)
from hellcat.offensive.operators.binary_analysis_operator import BinaryAnalysisOperator
from hellcat.offensive.operators.cloud_config_operator import CloudConfigOperator
from hellcat.offensive.operators.cloudfox_operator import CloudFoxOperator
from hellcat.offensive.operators.identity_operator import IdentityAttackPathOperator
from hellcat.offensive.operators.injection_operator import (
    InjectionExploitOperator,
    InjectionVulnOperator,
)
from hellcat.offensive.operators.metasploit_operator import MetasploitOperator
from hellcat.offensive.operators.network_recon_operator import NetworkReconOperator
from hellcat.offensive.operators.phishing_operator import PhishingOperator
from hellcat.offensive.operators.recon_operator import ReconOperator
from hellcat.offensive.operators.report_operator import ReportOperator
from hellcat.offensive.operators.service_exploit_operator import ServiceExploitOperator
from hellcat.offensive.operators.sliver_operator import SliverOperator
from hellcat.offensive.operators.ssrf_operator import (
    SSRFExploitOperator,
    SSRFVulnOperator,
)
from hellcat.offensive.operators.xss_operator import (
    XSSExploitOperator,
    XSSVulnOperator,
)

__all__ = [
    # Recon
    "ReconOperator",
    # Vuln analysis
    "InjectionVulnOperator",
    "XSSVulnOperator",
    "AuthVulnOperator",
    "AuthzVulnOperator",
    "SSRFVulnOperator",
    # Exploitation
    "InjectionExploitOperator",
    "XSSExploitOperator",
    "AuthExploitOperator",
    "AuthzExploitOperator",
    "SSRFExploitOperator",
    "MetasploitOperator",
    # Network / cloud
    "NetworkReconOperator",
    "ServiceExploitOperator",
    "CloudConfigOperator",
    "CloudFoxOperator",
    "IdentityAttackPathOperator",
    # C2 frameworks
    "SliverOperator",
    # Social engineering
    "PhishingOperator",
    # Binary analysis
    "BinaryAnalysisOperator",
    # Reporting
    "ReportOperator",
]
