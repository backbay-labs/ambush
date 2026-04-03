"""SQLite schema for the TargetGraph."""

SCHEMA_SQL = """
-- =====================================================================
-- Target nodes (endpoints, services, hosts, subdomains)
-- =====================================================================
CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    tech_stack TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'discovered',
    discovered_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status);
CREATE INDEX IF NOT EXISTS idx_targets_url ON targets(url);

-- =====================================================================
-- Vulnerability nodes
-- =====================================================================
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    vuln_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    confidence REAL NOT NULL DEFAULT 0.5,
    cvss REAL,
    description TEXT NOT NULL DEFAULT '',
    source_location TEXT NOT NULL DEFAULT '',
    witness_payload TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'discovered',
    discovered_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_type ON vulnerabilities(vuln_type);

-- =====================================================================
-- Credential nodes
-- =====================================================================
CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    credential_type TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    access_level TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'discovered',
    discovered_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_creds_status ON credentials(status);
CREATE INDEX IF NOT EXISTS idx_creds_type ON credentials(credential_type);

-- =====================================================================
-- Access level nodes
-- =====================================================================
CREATE TABLE IF NOT EXISTS access_levels (
    id TEXT PRIMARY KEY,
    level TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '',
    obtained_via TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'discovered',
    discovered_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_access_status ON access_levels(status);
CREATE INDEX IF NOT EXISTS idx_access_level ON access_levels(level);

-- =====================================================================
-- Defense nodes
-- =====================================================================
CREATE TABLE IF NOT EXISTS defenses (
    id TEXT PRIMARY KEY,
    defense_type TEXT NOT NULL,
    strength TEXT NOT NULL DEFAULT 'unknown',
    observed_behavior TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'discovered',
    discovered_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_defenses_status ON defenses(status);
CREATE INDEX IF NOT EXISTS idx_defenses_type ON defenses(defense_type);

-- =====================================================================
-- Subdomain nodes
-- =====================================================================
CREATE TABLE IF NOT EXISTS subdomains (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    resolved_ips TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'discovered',
    discovered_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_subdomains_status ON subdomains(status);
CREATE INDEX IF NOT EXISTS idx_subdomains_hostname ON subdomains(hostname);

-- =====================================================================
-- Host nodes
-- =====================================================================
CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    hostname TEXT NOT NULL DEFAULT '',
    os_guess TEXT NOT NULL DEFAULT '',
    is_cdn INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'discovered',
    discovered_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status);
CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);

-- =====================================================================
-- Port nodes
-- =====================================================================
CREATE TABLE IF NOT EXISTS ports (
    id TEXT PRIMARY KEY,
    port_number INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    state TEXT NOT NULL DEFAULT 'open',
    service_name TEXT NOT NULL DEFAULT '',
    service_version TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'discovered',
    discovered_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_ports_status ON ports(status);
CREATE INDEX IF NOT EXISTS idx_ports_number ON ports(port_number);

-- =====================================================================
-- Service nodes
-- =====================================================================
CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    product TEXT NOT NULL DEFAULT '',
    banner TEXT NOT NULL DEFAULT '',
    cpe TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'discovered',
    discovered_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_services_status ON services(status);
CREATE INDEX IF NOT EXISTS idx_services_name ON services(name);

-- =====================================================================
-- Endpoint nodes
-- =====================================================================
CREATE TABLE IF NOT EXISTS endpoints (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    auth_required INTEGER NOT NULL DEFAULT 0,
    parameters TEXT NOT NULL DEFAULT '',
    content_type TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'discovered',
    discovered_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_endpoints_status ON endpoints(status);
CREATE INDEX IF NOT EXISTS idx_endpoints_url ON endpoints(url);

-- =====================================================================
-- Technology nodes
-- =====================================================================
CREATE TABLE IF NOT EXISTS technologies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'discovered',
    discovered_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_technologies_status ON technologies(status);
CREATE INDEX IF NOT EXISTS idx_technologies_name ON technologies(name);

-- =====================================================================
-- Certificate nodes
-- =====================================================================
CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL DEFAULT '',
    valid_from TEXT NOT NULL DEFAULT '',
    valid_to TEXT NOT NULL DEFAULT '',
    san_list TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'discovered',
    discovered_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_certificates_subject ON certificates(subject);

-- =====================================================================
-- Session nodes (Metasploit / exploitation sessions)
-- =====================================================================
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    session_type TEXT NOT NULL,
    session_id TEXT NOT NULL DEFAULT '',
    target_host TEXT NOT NULL DEFAULT '',
    via_exploit TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'discovered',
    discovered_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_sessions_type ON sessions(session_type);

-- =====================================================================
-- IAM Principal nodes (AD users/groups, cloud IAM roles)
-- =====================================================================
CREATE TABLE IF NOT EXISTS iam_principals (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    principal_type TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'discovered',
    discovered_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_iam_principals_status ON iam_principals(status);
CREATE INDEX IF NOT EXISTS idx_iam_principals_name ON iam_principals(name);
CREATE INDEX IF NOT EXISTS idx_iam_principals_type ON iam_principals(principal_type);

-- =====================================================================
-- Cloud Resource nodes (S3 buckets, EC2 instances, Lambda, etc.)
-- =====================================================================
CREATE TABLE IF NOT EXISTS cloud_resources (
    id TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL,
    resource_type TEXT NOT NULL DEFAULT '',
    provider TEXT NOT NULL DEFAULT '',
    region TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'discovered',
    discovered_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_cloud_resources_status ON cloud_resources(status);
CREATE INDEX IF NOT EXISTS idx_cloud_resources_type ON cloud_resources(resource_type);
CREATE INDEX IF NOT EXISTS idx_cloud_resources_provider ON cloud_resources(provider);

-- =====================================================================
-- Edges (directed graph connections between any node types)
-- =====================================================================
CREATE TABLE IF NOT EXISTS edges (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    edge_type TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source_id);
CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target_id);
CREATE INDEX IF NOT EXISTS idx_edges_type ON edges(edge_type);

-- =====================================================================
-- Status history (audit trail for state machine transitions)
-- =====================================================================
CREATE TABLE IF NOT EXISTS status_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL,
    node_type TEXT NOT NULL,
    from_status TEXT NOT NULL,
    to_status TEXT NOT NULL,
    changed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_status_history_node ON status_history(node_id);
CREATE INDEX IF NOT EXISTS idx_status_history_type ON status_history(node_type);
"""
