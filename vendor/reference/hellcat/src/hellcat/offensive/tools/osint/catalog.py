"""
Curated catalog of hacker search engines for penetration testing reconnaissance.

Based on the awesome-hacker-search-engines list, filtered down to the ~40 most
impactful engines for authorized pentest engagements. Each entry records API
availability, auth requirements, and rate-limit notes so operators can make
informed decisions about which engines to query.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

import structlog

logger = structlog.get_logger()


class SearchEngineCategory(StrEnum):
    """Categories of hacker search engines by data type."""

    SERVERS = "servers"
    VULNERABILITIES = "vulnerabilities"
    EXPLOITS = "exploits"
    ATTACK_SURFACE = "attack_surface"
    CODE = "code"
    DOMAINS = "domains"
    DNS = "dns"
    CERTIFICATES = "certificates"
    CREDENTIALS = "credentials"
    URLS = "urls"
    THREAT_INTEL = "threat_intel"


@dataclass
class SearchEngine:
    """A hacker search engine or OSINT data source."""

    name: str
    url: str
    category: SearchEngineCategory
    description: str = ""
    requires_auth: bool = False
    api_available: bool = False
    free_tier: bool = True
    rate_limit_notes: str = ""


SEARCH_ENGINE_CATALOG: list[SearchEngine] = [
    # --- SERVERS ---
    SearchEngine(
        name="Shodan",
        url="https://shodan.io",
        category=SearchEngineCategory.SERVERS,
        description="Internet-wide device and service search engine",
        requires_auth=True,
        api_available=True,
        free_tier=True,
        rate_limit_notes="Free: 1 req/sec, 100 results. Paid: higher limits.",
    ),
    SearchEngine(
        name="Censys",
        url="https://search.censys.io",
        category=SearchEngineCategory.SERVERS,
        description="Internet host and certificate search with TLS analysis",
        requires_auth=True,
        api_available=True,
        free_tier=True,
        rate_limit_notes="Free: 250 queries/month. Paid plans available.",
    ),
    SearchEngine(
        name="ZoomEye",
        url="https://zoomeye.org",
        category=SearchEngineCategory.SERVERS,
        description="Cyberspace search engine for devices and web services",
        requires_auth=True,
        api_available=True,
        free_tier=True,
        rate_limit_notes="Free tier with limited monthly queries.",
    ),
    SearchEngine(
        name="FOFA",
        url="https://fofa.info",
        category=SearchEngineCategory.SERVERS,
        description="Cyberspace mapping with fingerprint-based search",
        requires_auth=True,
        api_available=True,
        free_tier=True,
        rate_limit_notes="Free tier with limited daily queries.",
    ),
    SearchEngine(
        name="GreyNoise",
        url="https://viz.greynoise.io",
        category=SearchEngineCategory.SERVERS,
        description="Internet-wide scanner and noise classification",
        requires_auth=True,
        api_available=True,
        free_tier=True,
        rate_limit_notes="Community API: 50 req/day. Enterprise: unlimited.",
    ),
    SearchEngine(
        name="Netlas",
        url="https://netlas.io",
        category=SearchEngineCategory.SERVERS,
        description="Internet intelligence with DNS, WHOIS, and response data",
        requires_auth=True,
        api_available=True,
        free_tier=True,
        rate_limit_notes="Free: 50 req/day.",
    ),
    SearchEngine(
        name="ONYPHE",
        url="https://onyphe.io",
        category=SearchEngineCategory.SERVERS,
        description="Cyber defense search engine with passive and active data",
        requires_auth=True,
        api_available=True,
        free_tier=True,
        rate_limit_notes="Free: limited daily queries.",
    ),
    # --- VULNERABILITIES ---
    SearchEngine(
        name="NIST NVD",
        url="https://nvd.nist.gov",
        category=SearchEngineCategory.VULNERABILITIES,
        description="National Vulnerability Database with CVE details and CVSS",
        requires_auth=False,
        api_available=True,
        free_tier=True,
        rate_limit_notes="No key: 5 req/30s. With key: 50 req/30s.",
    ),
    SearchEngine(
        name="OSV",
        url="https://osv.dev",
        category=SearchEngineCategory.VULNERABILITIES,
        description="Open-source vulnerability database across ecosystems",
        requires_auth=False,
        api_available=True,
        free_tier=True,
        rate_limit_notes="No strict limits documented.",
    ),
    SearchEngine(
        name="Vulners",
        url="https://vulners.com",
        category=SearchEngineCategory.VULNERABILITIES,
        description="Vulnerability intelligence search across multiple feeds",
        requires_auth=True,
        api_available=True,
        free_tier=True,
        rate_limit_notes="Free: 200 req/day.",
    ),
    SearchEngine(
        name="CVEDetails",
        url="https://cvedetails.com",
        category=SearchEngineCategory.VULNERABILITIES,
        description="CVE browser with vendor and product statistics",
        requires_auth=False,
        api_available=False,
        free_tier=True,
    ),
    SearchEngine(
        name="OpenCVE",
        url="https://opencve.io",
        category=SearchEngineCategory.VULNERABILITIES,
        description="CVE monitoring with vendor/product tracking and alerts",
        requires_auth=True,
        api_available=True,
        free_tier=True,
    ),
    SearchEngine(
        name="InTheWild",
        url="https://inthewild.io",
        category=SearchEngineCategory.VULNERABILITIES,
        description="Tracks CVEs exploited in the wild with evidence",
        requires_auth=False,
        api_available=True,
        free_tier=True,
    ),
    # --- EXPLOITS ---
    SearchEngine(
        name="Exploit-DB",
        url="https://exploit-db.com",
        category=SearchEngineCategory.EXPLOITS,
        description="Archive of public exploits and vulnerable software",
        requires_auth=False,
        api_available=False,
        free_tier=True,
    ),
    SearchEngine(
        name="Sploitus",
        url="https://sploitus.com",
        category=SearchEngineCategory.EXPLOITS,
        description="Exploit and tool search engine aggregating multiple sources",
        requires_auth=False,
        api_available=False,
        free_tier=True,
    ),
    SearchEngine(
        name="PacketStorm",
        url="https://packetstormsecurity.com",
        category=SearchEngineCategory.EXPLOITS,
        description="Security news, exploits, and advisories archive",
        requires_auth=False,
        api_available=False,
        free_tier=True,
    ),
    SearchEngine(
        name="GTFOBins",
        url="https://gtfobins.github.io",
        category=SearchEngineCategory.EXPLOITS,
        description="Unix binaries exploitable for privilege escalation",
        requires_auth=False,
        api_available=False,
        free_tier=True,
    ),
    SearchEngine(
        name="LOLBAS",
        url="https://lolbas-project.github.io",
        category=SearchEngineCategory.EXPLOITS,
        description="Living Off The Land Binaries, Scripts, and Libraries",
        requires_auth=False,
        api_available=False,
        free_tier=True,
    ),
    SearchEngine(
        name="PayloadsAllTheThings",
        url="https://github.com/swisskyrepo/PayloadsAllTheThings",
        category=SearchEngineCategory.EXPLOITS,
        description="Payload lists and bypass techniques for web security",
        requires_auth=False,
        api_available=False,
        free_tier=True,
    ),
    # --- ATTACK_SURFACE ---
    SearchEngine(
        name="SecurityTrails",
        url="https://securitytrails.com",
        category=SearchEngineCategory.ATTACK_SURFACE,
        description="Historical DNS, WHOIS, and subdomain intelligence",
        requires_auth=True,
        api_available=True,
        free_tier=True,
        rate_limit_notes="Free: 50 queries/month.",
    ),
    SearchEngine(
        name="FullHunt",
        url="https://fullhunt.io",
        category=SearchEngineCategory.ATTACK_SURFACE,
        description="Attack surface discovery and exposed asset search",
        requires_auth=True,
        api_available=True,
        free_tier=True,
        rate_limit_notes="Free: limited queries/month.",
    ),
    SearchEngine(
        name="BinaryEdge",
        url="https://binaryedge.io",
        category=SearchEngineCategory.ATTACK_SURFACE,
        description="Internet-wide scanning for exposed services and vulns",
        requires_auth=True,
        api_available=True,
        free_tier=True,
        rate_limit_notes="Free: 250 queries/month.",
    ),
    SearchEngine(
        name="IPInfo",
        url="https://ipinfo.io",
        category=SearchEngineCategory.ATTACK_SURFACE,
        description="IP geolocation, ASN, and company data",
        requires_auth=True,
        api_available=True,
        free_tier=True,
        rate_limit_notes="Free: 50k lookups/month.",
    ),
    # --- CODE ---
    SearchEngine(
        name="GitHub Code Search",
        url="https://github.com/search",
        category=SearchEngineCategory.CODE,
        description="Search code across all public GitHub repositories",
        requires_auth=False,
        api_available=True,
        free_tier=True,
        rate_limit_notes="Authenticated: 30 req/min. Unauthenticated: 10 req/min.",
    ),
    SearchEngine(
        name="grep.app",
        url="https://grep.app",
        category=SearchEngineCategory.CODE,
        description="Regex search across half a million public git repos",
        requires_auth=False,
        api_available=False,
        free_tier=True,
    ),
    SearchEngine(
        name="PublicWWW",
        url="https://publicwww.com",
        category=SearchEngineCategory.CODE,
        description="Source code search engine for web page contents",
        requires_auth=False,
        api_available=True,
        free_tier=True,
        rate_limit_notes="Free: limited results. Paid for full access.",
    ),
    SearchEngine(
        name="SearchCode",
        url="https://searchcode.com",
        category=SearchEngineCategory.CODE,
        description="Free source code search across 75+ billion lines",
        requires_auth=False,
        api_available=True,
        free_tier=True,
    ),
    SearchEngine(
        name="Postman Public Collections",
        url="https://postman.com/explore",
        category=SearchEngineCategory.CODE,
        description="Public API collections often containing keys and endpoints",
        requires_auth=False,
        api_available=False,
        free_tier=True,
    ),
    # --- DOMAINS ---
    SearchEngine(
        name="BuiltWith",
        url="https://builtwith.com",
        category=SearchEngineCategory.DOMAINS,
        description="Technology profiling for websites",
        requires_auth=False,
        api_available=True,
        free_tier=True,
        rate_limit_notes="Free lookup available. API requires paid plan.",
    ),
    SearchEngine(
        name="Netcraft",
        url="https://sitereport.netcraft.com",
        category=SearchEngineCategory.DOMAINS,
        description="Site infrastructure, technology, and hosting analysis",
        requires_auth=False,
        api_available=False,
        free_tier=True,
    ),
    SearchEngine(
        name="URLScan",
        url="https://urlscan.io",
        category=SearchEngineCategory.DOMAINS,
        description="URL and website analysis with screenshot and DOM capture",
        requires_auth=False,
        api_available=True,
        free_tier=True,
        rate_limit_notes="Public scans free. Private scans require auth.",
    ),
    SearchEngine(
        name="WhoisXML",
        url="https://whois.whoisxmlapi.com",
        category=SearchEngineCategory.DOMAINS,
        description="WHOIS, DNS, and domain intelligence API",
        requires_auth=True,
        api_available=True,
        free_tier=True,
        rate_limit_notes="Free: 500 credits on signup.",
    ),
    # --- DNS ---
    SearchEngine(
        name="DNSDumpster",
        url="https://dnsdumpster.com",
        category=SearchEngineCategory.DNS,
        description="DNS reconnaissance with subdomain and record discovery",
        requires_auth=False,
        api_available=False,
        free_tier=True,
    ),
    SearchEngine(
        name="RapidDNS",
        url="https://rapiddns.io",
        category=SearchEngineCategory.DNS,
        description="Fast DNS query tool for subdomains and records",
        requires_auth=False,
        api_available=False,
        free_tier=True,
    ),
    SearchEngine(
        name="PassiveDNS",
        url="https://passivedns.mnemonic.no",
        category=SearchEngineCategory.DNS,
        description="Passive DNS database by mnemonic",
        requires_auth=False,
        api_available=True,
        free_tier=True,
    ),
    SearchEngine(
        name="DNSTwister",
        url="https://dnstwister.report",
        category=SearchEngineCategory.DNS,
        description="Domain typosquatting and phishing detection",
        requires_auth=False,
        api_available=True,
        free_tier=True,
    ),
    # --- CERTIFICATES ---
    SearchEngine(
        name="crt.sh",
        url="https://crt.sh",
        category=SearchEngineCategory.CERTIFICATES,
        description="Certificate Transparency log search",
        requires_auth=False,
        api_available=True,
        free_tier=True,
        rate_limit_notes="No strict limits but may throttle under load.",
    ),
    SearchEngine(
        name="CertSpotter",
        url="https://sslmate.com/certspotter",
        category=SearchEngineCategory.CERTIFICATES,
        description="Certificate Transparency monitoring by SSLMate",
        requires_auth=False,
        api_available=True,
        free_tier=True,
        rate_limit_notes="Free: 100 queries/hour.",
    ),
    # --- CREDENTIALS ---
    SearchEngine(
        name="Have I Been Pwned",
        url="https://haveibeenpwned.com",
        category=SearchEngineCategory.CREDENTIALS,
        description="Breach database search (informational/defensive use)",
        requires_auth=True,
        api_available=True,
        free_tier=False,
        rate_limit_notes="API requires paid key. Password API is free.",
    ),
    # --- URLS ---
    SearchEngine(
        name="URLScan Search",
        url="https://urlscan.io",
        category=SearchEngineCategory.URLS,
        description="Historical URL scan results with DOM and network data",
        requires_auth=False,
        api_available=True,
        free_tier=True,
    ),
    SearchEngine(
        name="CommonCrawl",
        url="https://index.commoncrawl.org",
        category=SearchEngineCategory.URLS,
        description="Petabyte-scale web crawl archive with URL index",
        requires_auth=False,
        api_available=True,
        free_tier=True,
    ),
    SearchEngine(
        name="Wayback Machine",
        url="https://web.archive.org",
        category=SearchEngineCategory.URLS,
        description="Internet Archive with historical page snapshots",
        requires_auth=False,
        api_available=True,
        free_tier=True,
        rate_limit_notes="CDX API: no strict limit but be respectful.",
    ),
    # --- THREAT_INTEL ---
    SearchEngine(
        name="VirusTotal",
        url="https://virustotal.com",
        category=SearchEngineCategory.THREAT_INTEL,
        description="File, URL, IP, and domain malware analysis",
        requires_auth=True,
        api_available=True,
        free_tier=True,
        rate_limit_notes="Free: 4 req/min, 500 req/day.",
    ),
    SearchEngine(
        name="AlienVault OTX",
        url="https://otx.alienvault.com",
        category=SearchEngineCategory.THREAT_INTEL,
        description="Open threat exchange with IOC and pulse data",
        requires_auth=True,
        api_available=True,
        free_tier=True,
    ),
    SearchEngine(
        name="Pulsedive",
        url="https://pulsedive.com",
        category=SearchEngineCategory.THREAT_INTEL,
        description="Threat intelligence with IOC enrichment and risk scoring",
        requires_auth=True,
        api_available=True,
        free_tier=True,
        rate_limit_notes="Free: 30 req/min.",
    ),
    SearchEngine(
        name="AbuseIPDB",
        url="https://abuseipdb.com",
        category=SearchEngineCategory.THREAT_INTEL,
        description="IP abuse reporting and reputation database",
        requires_auth=True,
        api_available=True,
        free_tier=True,
        rate_limit_notes="Free: 1000 checks/day.",
    ),
]


def get_engines_for_category(
    category: SearchEngineCategory,
) -> list[SearchEngine]:
    """Return all catalog engines matching a given category."""
    return [e for e in SEARCH_ENGINE_CATALOG if e.category == category]


def get_engines_with_api() -> list[SearchEngine]:
    """Return all catalog engines that offer an API."""
    return [e for e in SEARCH_ENGINE_CATALOG if e.api_available]


def get_free_engines() -> list[SearchEngine]:
    """Return all catalog engines with a free tier."""
    return [e for e in SEARCH_ENGINE_CATALOG if e.free_tier]


def format_osint_suggestions(
    target: str,
    categories: list[SearchEngineCategory] | None = None,
) -> str:
    """Generate markdown block suggesting relevant OSINT engines for manual lookup.

    Used by operators when no API integration is available for a category.
    Returns a <osint_suggestions> block with engine names and URLs.

    Args:
        target: The target domain or IP being assessed.
        categories: Optional list of categories to include. If None, all
            categories with engines are included.

    Returns:
        Formatted suggestions string, or empty string if no engines match.
    """
    cats = categories or list(SearchEngineCategory)
    lines: list[str] = [
        "<osint_suggestions>",
        f"Manual OSINT lookup suggestions for: {target}",
        "",
    ]

    found_any = False
    for cat in cats:
        engines = get_engines_for_category(cat)
        if not engines:
            continue
        found_any = True
        lines.append(f"### {cat.value.replace('_', ' ').title()}")
        for engine in engines:
            auth_tag = " [auth required]" if engine.requires_auth else ""
            api_tag = " [API]" if engine.api_available else ""
            lines.append(
                f"- **{engine.name}**{api_tag}{auth_tag}: {engine.url}"
            )
            if engine.description:
                lines.append(f"  {engine.description}")
        lines.append("")

    if not found_any:
        return ""

    lines.append("</osint_suggestions>")
    return "\n".join(lines)
