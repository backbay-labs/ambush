"""
Data models for the TargetGraph.

All node types are plain dataclasses for minimal overhead.
Enums define valid values for statuses, edge types, and categorizations.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


class NodeType(str, enum.Enum):
    TARGET = "target"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    ACCESS_LEVEL = "access_level"
    DEFENSE = "defense"
    SUBDOMAIN = "subdomain"
    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    ENDPOINT = "endpoint"
    TECHNOLOGY = "technology"
    CERTIFICATE = "certificate"
    SESSION = "session"
    IAM_PRINCIPAL = "iam_principal"
    CLOUD_RESOURCE = "cloud_resource"


class AttackStatus(str, enum.Enum):
    DISCOVERED = "discovered"
    RECOND = "recond"
    ANALYZED = "analyzed"
    ATTEMPTED = "attempted"
    EXPLOITED = "exploited"
    CHAINED = "chained"
    BLOCKED = "blocked"
    EVASION_QUEUED = "evasion_queued"
    RETRIED = "retried"
    HARDENED = "hardened"


# Valid state transitions for the attack status machine.
# Maps current_status -> set of allowed next statuses.
VALID_TRANSITIONS: dict[AttackStatus, set[AttackStatus]] = {
    AttackStatus.DISCOVERED: {AttackStatus.RECOND},
    AttackStatus.RECOND: {AttackStatus.ANALYZED},
    AttackStatus.ANALYZED: {AttackStatus.ATTEMPTED},
    AttackStatus.ATTEMPTED: {AttackStatus.EXPLOITED, AttackStatus.BLOCKED},
    AttackStatus.EXPLOITED: {AttackStatus.CHAINED},
    AttackStatus.CHAINED: set(),  # terminal
    AttackStatus.BLOCKED: {AttackStatus.EVASION_QUEUED, AttackStatus.HARDENED},
    AttackStatus.EVASION_QUEUED: {AttackStatus.RETRIED},
    AttackStatus.RETRIED: {AttackStatus.EXPLOITED, AttackStatus.BLOCKED},
    AttackStatus.HARDENED: set(),  # terminal
}


class EdgeType(str, enum.Enum):
    EXPOSES = "exposes"
    ENABLES = "enables"
    CHAINS_TO = "chains_to"
    BLOCKS = "blocks"
    BYPASSED_BY = "bypassed_by"
    REQUIRES = "requires"
    HAS_SUBDOMAIN = "has_subdomain"
    RESOLVES_TO = "resolves_to"
    HAS_PORT = "has_port"
    RUNS_SERVICE = "runs_service"
    HAS_ENDPOINT = "has_endpoint"
    USES_TECH = "uses_tech"
    HAS_CERT = "has_cert"
    EXPLOITED_VIA = "exploited_via"
    TRUSTS = "trusts"
    DELEGATES_TO = "delegates_to"
    CAN_ESCALATE_TO = "can_escalate_to"
    HAS_PERMISSION = "has_permission"
    ASSUMES_ROLE = "assumes_role"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CredentialType(str, enum.Enum):
    PASSWORD = "password"
    HASH = "hash"
    TOKEN = "token"
    COOKIE = "cookie"
    API_KEY = "api_key"
    SSH_KEY = "ssh_key"
    CERTIFICATE = "certificate"


class AccessLevel(str, enum.Enum):
    ANONYMOUS = "anonymous"
    USER = "user"
    ADMIN = "admin"
    ROOT = "root"


class DefenseType(str, enum.Enum):
    WAF = "waf"
    RATE_LIMITER = "rate_limiter"
    INPUT_VALIDATION = "input_validation"
    CSRF_TOKEN = "csrf_token"
    AUTH_MECHANISM = "auth_mechanism"
    CAPTCHA = "captcha"
    IP_ALLOWLIST = "ip_allowlist"


@dataclass
class TargetNode:
    """An endpoint, service, host, or subdomain under test."""

    url: str
    method: str = "GET"
    tech_stack: str = ""
    description: str = ""
    status: AttackStatus = AttackStatus.DISCOVERED
    id: str = field(default_factory=_new_id)
    discovered_at: str = field(default_factory=_utc_now)
    metadata_json: str = "{}"

    @property
    def node_type(self) -> NodeType:
        return NodeType.TARGET


@dataclass
class VulnerabilityNode:
    """A discovered vulnerability linked to a target."""

    vuln_type: str
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.5
    cvss: float | None = None
    description: str = ""
    source_location: str = ""
    witness_payload: str = ""
    status: AttackStatus = AttackStatus.DISCOVERED
    id: str = field(default_factory=_new_id)
    discovered_at: str = field(default_factory=_utc_now)
    metadata_json: str = "{}"

    @property
    def node_type(self) -> NodeType:
        return NodeType.VULNERABILITY


@dataclass
class CredentialNode:
    """A credential obtained during the engagement."""

    username: str
    credential_type: CredentialType
    source: str = ""
    access_level: str = ""
    status: AttackStatus = AttackStatus.DISCOVERED
    id: str = field(default_factory=_new_id)
    discovered_at: str = field(default_factory=_utc_now)
    metadata_json: str = "{}"

    @property
    def node_type(self) -> NodeType:
        return NodeType.CREDENTIAL


@dataclass
class AccessLevelNode:
    """Represents an access level obtained during the engagement."""

    level: AccessLevel
    scope: str = ""
    obtained_via: str = ""
    status: AttackStatus = AttackStatus.DISCOVERED
    id: str = field(default_factory=_new_id)
    discovered_at: str = field(default_factory=_utc_now)
    metadata_json: str = "{}"

    @property
    def node_type(self) -> NodeType:
        return NodeType.ACCESS_LEVEL


@dataclass
class DefenseNode:
    """A defensive control observed on the target."""

    defense_type: DefenseType
    strength: str = "unknown"
    observed_behavior: str = ""
    status: AttackStatus = AttackStatus.DISCOVERED
    id: str = field(default_factory=_new_id)
    discovered_at: str = field(default_factory=_utc_now)
    metadata_json: str = "{}"

    @property
    def node_type(self) -> NodeType:
        return NodeType.DEFENSE


@dataclass
class SubdomainNode:
    """A discovered subdomain."""

    hostname: str
    resolved_ips: str = ""
    source: str = ""
    status: AttackStatus = AttackStatus.DISCOVERED
    id: str = field(default_factory=_new_id)
    discovered_at: str = field(default_factory=_utc_now)
    metadata_json: str = "{}"

    @property
    def node_type(self) -> NodeType:
        return NodeType.SUBDOMAIN


@dataclass
class HostNode:
    """A host (IP or resolved hostname) on the network."""

    ip: str
    hostname: str = ""
    os_guess: str = ""
    is_cdn: bool = False
    status: AttackStatus = AttackStatus.DISCOVERED
    id: str = field(default_factory=_new_id)
    discovered_at: str = field(default_factory=_utc_now)
    metadata_json: str = "{}"

    @property
    def node_type(self) -> NodeType:
        return NodeType.HOST


@dataclass
class PortNode:
    """An open port on a host."""

    port_number: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: str = ""
    service_version: str = ""
    status: AttackStatus = AttackStatus.DISCOVERED
    id: str = field(default_factory=_new_id)
    discovered_at: str = field(default_factory=_utc_now)
    metadata_json: str = "{}"

    @property
    def node_type(self) -> NodeType:
        return NodeType.PORT


@dataclass
class ServiceNode:
    """A service running on a port."""

    name: str
    version: str = ""
    product: str = ""
    banner: str = ""
    cpe: str = ""
    status: AttackStatus = AttackStatus.DISCOVERED
    id: str = field(default_factory=_new_id)
    discovered_at: str = field(default_factory=_utc_now)
    metadata_json: str = "{}"

    @property
    def node_type(self) -> NodeType:
        return NodeType.SERVICE


@dataclass
class EndpointNode:
    """A discovered URL endpoint."""

    url: str
    method: str = "GET"
    auth_required: bool = False
    parameters: str = ""
    content_type: str = ""
    status: AttackStatus = AttackStatus.DISCOVERED
    id: str = field(default_factory=_new_id)
    discovered_at: str = field(default_factory=_utc_now)
    metadata_json: str = "{}"

    @property
    def node_type(self) -> NodeType:
        return NodeType.ENDPOINT


@dataclass
class TechnologyNode:
    """A technology detected on a target or service."""

    name: str
    version: str = ""
    category: str = ""
    status: AttackStatus = AttackStatus.DISCOVERED
    id: str = field(default_factory=_new_id)
    discovered_at: str = field(default_factory=_utc_now)
    metadata_json: str = "{}"

    @property
    def node_type(self) -> NodeType:
        return NodeType.TECHNOLOGY


@dataclass
class CertificateNode:
    """A TLS certificate observed on a subdomain or host."""

    subject: str
    issuer: str = ""
    valid_from: str = ""
    valid_to: str = ""
    san_list: str = ""
    status: AttackStatus = AttackStatus.DISCOVERED
    id: str = field(default_factory=_new_id)
    discovered_at: str = field(default_factory=_utc_now)
    metadata_json: str = "{}"

    @property
    def node_type(self) -> NodeType:
        return NodeType.CERTIFICATE


@dataclass
class SessionNode:
    """A Metasploit or exploitation session."""

    session_type: str
    session_id: str = ""
    target_host: str = ""
    via_exploit: str = ""
    status: AttackStatus = AttackStatus.DISCOVERED
    id: str = field(default_factory=_new_id)
    discovered_at: str = field(default_factory=_utc_now)
    metadata_json: str = "{}"

    @property
    def node_type(self) -> NodeType:
        return NodeType.SESSION


@dataclass
class IamPrincipalNode:
    """An IAM principal (AD user/group, cloud IAM role)."""

    name: str
    principal_type: str = ""  # "user", "group", "role", "service_principal"
    domain: str = ""
    enabled: bool = True
    status: AttackStatus = AttackStatus.DISCOVERED
    id: str = field(default_factory=_new_id)
    discovered_at: str = field(default_factory=_utc_now)
    metadata_json: str = "{}"

    @property
    def node_type(self) -> NodeType:
        return NodeType.IAM_PRINCIPAL


@dataclass
class CloudResourceNode:
    """A cloud resource (S3 bucket, EC2 instance, Lambda, etc.)."""

    resource_id: str
    resource_type: str = ""  # "s3_bucket", "ec2_instance", "lambda", etc.
    provider: str = ""  # "aws", "gcp", "azure"
    region: str = ""
    status: AttackStatus = AttackStatus.DISCOVERED
    id: str = field(default_factory=_new_id)
    discovered_at: str = field(default_factory=_utc_now)
    metadata_json: str = "{}"

    @property
    def node_type(self) -> NodeType:
        return NodeType.CLOUD_RESOURCE


@dataclass
class GraphEdge:
    """A directed edge between two nodes in the TargetGraph."""

    source_id: str
    target_id: str
    edge_type: EdgeType
    metadata_json: str = "{}"
    id: str = field(default_factory=_new_id)
    created_at: str = field(default_factory=_utc_now)
