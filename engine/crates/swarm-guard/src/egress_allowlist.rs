//! Guard that controls outbound network destinations.
//!
//! On top of the string-pattern allowlist, this guard performs SSRF hardening:
//! it parses the destination host as an IP literal and denies dangerous address
//! classes (loopback, link-local incl. the `169.254.169.254` cloud-metadata IP,
//! IPv4 private / special-use ranges, and IPv6 unique-local `fc00::/7`) so that
//! an attacker cannot reach internal services by handing the engine a raw IP
//! that side-steps a name-based allowlist. Dangerous classes can only be
//! reached when an operator lists the exact IP literal in `allow`, or disables
//! the matching `deny_*` flag *and* allowlists the destination. Defaults fail
//! closed: every `deny_*` flag is on.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// Default behavior when no domain pattern matches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultAction {
    Allow,
    #[default]
    Block,
}

/// Configuration for [`EgressAllowlistGuard`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressAllowlistConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_allow")]
    pub allow: Vec<String>,
    #[serde(default)]
    pub block: Vec<String>,
    #[serde(default)]
    pub default_action: DefaultAction,
    /// Deny loopback destinations (`127.0.0.0/8`, `::1`, `localhost`) unless the
    /// exact host is explicitly allowlisted.
    #[serde(default = "default_true")]
    pub deny_loopback: bool,
    /// Deny link-local destinations (`169.254.0.0/16` incl. the
    /// `169.254.169.254` cloud-metadata IP, `fe80::/10`) unless the exact host
    /// is explicitly allowlisted.
    #[serde(default = "default_true")]
    pub deny_link_local: bool,
    /// Deny IPv6 unique-local destinations (`fc00::/7`) unless the exact host is
    /// explicitly allowlisted.
    #[serde(default = "default_true")]
    pub deny_ipv6_ula: bool,
    /// Deny IPv4 private and special-use destinations (RFC 1918, broadcast,
    /// multicast, shared/CGNAT, documentation and reserved ranges) unless the
    /// exact host is explicitly allowlisted.
    #[serde(default = "default_true")]
    pub deny_private: bool,
}

impl Default for EgressAllowlistConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow: default_allow(),
            block: Vec::new(),
            default_action: DefaultAction::Block,
            deny_loopback: true,
            deny_link_local: true,
            deny_ipv6_ula: true,
            deny_private: true,
        }
    }
}

fn default_enabled() -> bool {
    true
}

fn default_true() -> bool {
    true
}

fn default_allow() -> Vec<String> {
    vec![
        "*.openai.com".to_string(),
        "*.anthropic.com".to_string(),
        "api.github.com".to_string(),
        "registry.npmjs.org".to_string(),
        "pypi.org".to_string(),
        "crates.io".to_string(),
        "static.crates.io".to_string(),
    ]
}

/// Outcome of an egress destination decision.
#[derive(Clone, Debug, PartialEq, Eq)]
enum EgressDecision {
    Allow,
    Deny(String),
}

/// Address-class of a parsed IP literal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IpClass {
    Global,
    Loopback,
    LinkLocal,
    Ipv6Ula,
    Private,
}

/// Guard that enforces a domain allowlist with SSRF address-class hardening.
pub struct EgressAllowlistGuard {
    name: String,
    config: EgressAllowlistConfig,
}

impl EgressAllowlistGuard {
    pub fn new() -> Self {
        Self::with_config(EgressAllowlistConfig::default())
    }

    pub fn with_config(config: EgressAllowlistConfig) -> Self {
        Self {
            name: "egress_allowlist".to_string(),
            config,
        }
    }

    /// Match `domain` against a single allow/block pattern.
    ///
    /// Hosts and patterns are normalized (trimmed, lowercased, IPv6 brackets and
    /// trailing dots removed). A leading `*.` is a subdomain wildcard.
    pub fn matches_domain(pattern: &str, domain: &str) -> bool {
        let pattern = normalize_host(pattern);
        let domain = normalize_host(domain);
        if pattern.is_empty() || domain.is_empty() {
            return false;
        }

        if let Some(suffix) = pattern.strip_prefix("*.") {
            return domain.ends_with(&format!(".{suffix}"));
        }

        pattern == domain
    }

    /// Return true when `host` exactly matches a non-wildcard allow entry.
    ///
    /// Only an exact literal entry (for example `127.0.0.1` or `localhost`)
    /// overrides an SSRF address-class denial; wildcard patterns never do.
    fn host_is_explicitly_allowlisted(&self, host: &str) -> bool {
        self.config.allow.iter().any(|pattern| {
            let pattern = normalize_host(pattern);
            !pattern.is_empty() && !pattern.starts_with("*.") && pattern == host
        })
    }

    fn decide(&self, host: &str) -> EgressDecision {
        let normalized = normalize_host(host);
        if normalized.is_empty() {
            return EgressDecision::Deny("empty network destination".to_string());
        }

        if self
            .config
            .block
            .iter()
            .any(|pattern| Self::matches_domain(pattern, &normalized))
        {
            return EgressDecision::Deny(format!(
                "network destination on blocklist: {normalized}"
            ));
        }

        let allowed_by_pattern = self
            .config
            .allow
            .iter()
            .any(|pattern| Self::matches_domain(pattern, &normalized));
        let explicitly_allowed = self.host_is_explicitly_allowlisted(&normalized);

        // Resolve the host as an IP literal, including non-dotted inet_aton forms (decimal
        // 2130706433, hex 0x7f000001, octal 0177.0.0.1, short 127.1) that Rust's strict parser
        // rejects but libc/curl resolvers honour — closing an SSRF classifier bypass.
        let parsed_ip = normalized
            .parse::<IpAddr>()
            .ok()
            .or_else(|| parse_inet_aton(&normalized).map(IpAddr::V4));
        match parsed_ip {
            Some(ip) => {
                let (denied, label) = match classify_ip(ip) {
                    IpClass::Global => (false, ""),
                    IpClass::Loopback => (self.config.deny_loopback, "loopback"),
                    IpClass::LinkLocal => (self.config.deny_link_local, "link-local"),
                    IpClass::Ipv6Ula => (self.config.deny_ipv6_ula, "IPv6 unique-local"),
                    IpClass::Private => (self.config.deny_private, "private/special-use"),
                };

                if denied && !explicitly_allowed {
                    return EgressDecision::Deny(format!(
                        "SSRF-blocked {label} IP literal: {normalized}"
                    ));
                }

                self.finalize(&normalized, allowed_by_pattern, explicitly_allowed)
            }
            None => {
                // Numeric-looking host that did not resolve to a valid IP: fail closed rather than
                // let an ambiguous/overflowing literal fall through to the permissive name path.
                if looks_numeric_ip(&normalized) && !explicitly_allowed {
                    return EgressDecision::Deny(format!(
                        "SSRF-blocked ambiguous numeric host: {normalized}"
                    ));
                }
                if self.config.deny_loopback
                    && is_loopback_hostname(&normalized)
                    && !explicitly_allowed
                {
                    return EgressDecision::Deny(format!(
                        "SSRF-blocked loopback hostname: {normalized}"
                    ));
                }

                self.finalize(&normalized, allowed_by_pattern, explicitly_allowed)
            }
        }
    }

    /// Apply the ordinary allowlist / default-action decision once a destination
    /// has cleared the SSRF address-class checks.
    fn finalize(
        &self,
        normalized: &str,
        allowed_by_pattern: bool,
        explicitly_allowed: bool,
    ) -> EgressDecision {
        if explicitly_allowed
            || allowed_by_pattern
            || matches!(self.config.default_action, DefaultAction::Allow)
        {
            EgressDecision::Allow
        } else {
            EgressDecision::Deny(format!(
                "network destination not on allowlist: {normalized}"
            ))
        }
    }

    pub fn is_allowed(&self, host: &str) -> bool {
        matches!(self.decide(host), EgressDecision::Allow)
    }
}

impl Default for EgressAllowlistGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for EgressAllowlistGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        self.config.enabled && matches!(action, GuardAction::NetworkEgress(_, _))
    }

    fn check(&self, action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        if !self.config.enabled {
            return GuardResult::allow(&self.name);
        }

        let GuardAction::NetworkEgress(host, port) = action else {
            return GuardResult::allow(&self.name);
        };

        match self.decide(host) {
            EgressDecision::Allow => GuardResult::allow(&self.name),
            EgressDecision::Deny(reason) => {
                GuardResult::block(&self.name, Severity::Error, reason).with_details(
                    serde_json::json!({
                        "host": host,
                        "port": port,
                    }),
                )
            }
        }
    }
}

/// Normalize a host or pattern: trim, drop surrounding IPv6 brackets and any
/// trailing dots, and lowercase.
fn normalize_host(host: &str) -> String {
    let host = host.trim();
    let host = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Known loopback hostnames, including the reserved `.localhost` TLD.
fn is_loopback_hostname(host: &str) -> bool {
    host == "localhost" || host == "localhost.localdomain" || host.ends_with(".localhost")
}

/// True when a host is an IP-literal-looking numeric string (so a non-IP form should fail closed
/// rather than be treated as a resolvable name). Numeric = a digit present and every char is a hex
/// digit, `.`, or the `x`/`X` radix marker; real hostnames contain other letters or `-`.
fn looks_numeric_ip(host: &str) -> bool {
    !host.is_empty()
        && host.bytes().any(|b| b.is_ascii_digit())
        && host
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b'.' || b == b'x' || b == b'X')
}

/// inet_aton-style IPv4 parser for the non-dotted-quad forms libc accepts: 1–4 parts, each decimal,
/// octal (`0`-prefixed) or hex (`0x`-prefixed). Returns None on overflow/garbage.
fn parse_inet_aton(host: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut nums = Vec::with_capacity(parts.len());
    for p in &parts {
        nums.push(parse_radix_u32(p)?);
    }
    let value: u32 = match nums.as_slice() {
        [a] => *a,
        [a, b] if *a <= 0xff && *b <= 0x00ff_ffff => (a << 24) | b,
        [a, b, c] if *a <= 0xff && *b <= 0xff && *c <= 0xffff => (a << 24) | (b << 16) | c,
        [a, b, c, d] if *a <= 0xff && *b <= 0xff && *c <= 0xff && *d <= 0xff => {
            (a << 24) | (b << 16) | (c << 8) | d
        }
        _ => return None,
    };
    Some(Ipv4Addr::from(value))
}

fn parse_radix_u32(s: &str) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else if s.len() > 1 && s.starts_with('0') {
        u32::from_str_radix(&s[1..], 8).ok()
    } else {
        s.parse::<u32>().ok()
    }
}

fn classify_ip(ip: IpAddr) -> IpClass {
    match ip {
        IpAddr::V4(address) => classify_ipv4(&address),
        IpAddr::V6(address) => classify_ipv6(&address),
    }
}

fn classify_ipv4(address: &Ipv4Addr) -> IpClass {
    if address.is_loopback() {
        return IpClass::Loopback;
    }
    if address.is_link_local() {
        return IpClass::LinkLocal;
    }
    if is_ipv4_private_or_special_use(address) {
        return IpClass::Private;
    }
    IpClass::Global
}

fn classify_ipv6(address: &Ipv6Addr) -> IpClass {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return classify_ipv4(&mapped);
    }
    if address.is_loopback() {
        return IpClass::Loopback;
    }
    if is_ipv6_unicast_link_local(address) {
        return IpClass::LinkLocal;
    }
    if is_ipv6_unique_local(address) {
        return IpClass::Ipv6Ula;
    }
    if is_ipv6_private_or_special_use(address) {
        return IpClass::Private;
    }
    IpClass::Global
}

fn is_ipv6_unicast_link_local(address: &Ipv6Addr) -> bool {
    address.segments()[0] & 0xffc0 == 0xfe80
}

fn is_ipv6_unique_local(address: &Ipv6Addr) -> bool {
    address.segments()[0] & 0xfe00 == 0xfc00
}

fn is_ipv4_private_or_special_use(address: &Ipv4Addr) -> bool {
    let octets = address.octets();
    address.is_private()
        || address.is_broadcast()
        || address.is_multicast()
        || octets[0] == 0
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && (18..=19).contains(&octets[1]))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || octets[0] >= 240
}

fn is_ipv6_private_or_special_use(address: &Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_ipv4_private_or_special_use(&mapped);
    }
    let segments = address.segments();
    address.is_unspecified()
        || address.is_multicast()
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
}

#[cfg(test)]
mod tests {
    use super::{DefaultAction, EgressAllowlistConfig, EgressAllowlistGuard};
    use crate::{Guard, GuardAction, GuardContext};

    #[test]
    fn default_config_allows_expected_domains() {
        let guard = EgressAllowlistGuard::new();

        assert!(guard.is_allowed("api.openai.com"));
        assert!(guard.is_allowed("console.anthropic.com"));
        assert!(guard.is_allowed("api.github.com"));
        assert!(guard.is_allowed("registry.npmjs.org"));
        assert!(guard.is_allowed("crates.io"));
    }

    #[test]
    fn default_config_blocks_unknown_domains() {
        let guard = EgressAllowlistGuard::new();

        assert!(!guard.is_allowed("evil.com"));
        assert!(!guard.is_allowed("random-site.org"));
    }

    #[test]
    fn custom_allowlist_and_blocklist_work() {
        let guard = EgressAllowlistGuard::with_config(EgressAllowlistConfig {
            enabled: true,
            allow: vec!["*.example.com".to_string()],
            block: vec!["blocked.example.com".to_string()],
            default_action: DefaultAction::Block,
            deny_loopback: true,
            deny_link_local: true,
            deny_ipv6_ula: true,
            deny_private: true,
        });

        assert!(guard.is_allowed("sub.example.com"));
        assert!(!guard.is_allowed("example.com"));
        assert!(!guard.is_allowed("blocked.example.com"));
    }

    #[test]
    fn handles_only_network_egress() {
        let guard = EgressAllowlistGuard::new();
        assert!(guard.handles(&GuardAction::NetworkEgress("api.openai.com", 443)));
        assert!(!guard.handles(&GuardAction::FileAccess("/tmp/file")));
    }

    #[test]
    fn blocks_loopback_ipv4_literal() {
        let guard = EgressAllowlistGuard::new();
        assert!(!guard.is_allowed("127.0.0.1"));
        assert!(!guard.is_allowed("127.255.255.254"));
    }

    #[test]
    fn blocks_loopback_ipv6_literal() {
        let guard = EgressAllowlistGuard::new();
        assert!(!guard.is_allowed("::1"));
        assert!(!guard.is_allowed("[::1]"));
    }

    #[test]
    fn blocks_loopback_hostnames() {
        let guard = EgressAllowlistGuard::new();
        assert!(!guard.is_allowed("localhost"));
        assert!(!guard.is_allowed("localhost.localdomain"));
        assert!(!guard.is_allowed("anything.localhost"));
    }

    #[test]
    fn blocks_link_local_including_cloud_metadata_ip() {
        let guard = EgressAllowlistGuard::new();
        // AWS/GCP/Azure instance metadata endpoint.
        assert!(!guard.is_allowed("169.254.169.254"));
        assert!(!guard.is_allowed("169.254.0.1"));
        assert!(!guard.is_allowed("fe80::1"));
    }

    #[test]
    fn blocks_private_ipv4_ranges() {
        let guard = EgressAllowlistGuard::new();
        assert!(!guard.is_allowed("10.0.0.5"));
        assert!(!guard.is_allowed("172.16.0.1"));
        assert!(!guard.is_allowed("192.168.1.1"));
        assert!(!guard.is_allowed("0.0.0.0"));
        assert!(!guard.is_allowed("255.255.255.255"));
        // CGNAT / shared address space.
        assert!(!guard.is_allowed("100.64.0.1"));
    }

    #[test]
    fn blocks_ipv6_unique_local() {
        let guard = EgressAllowlistGuard::new();
        assert!(!guard.is_allowed("fc00::1"));
        assert!(!guard.is_allowed("fd12:3456::1"));
    }

    #[test]
    fn blocks_ipv4_mapped_private_literal() {
        let guard = EgressAllowlistGuard::new();
        // An IPv4-mapped IPv6 literal must not smuggle a private address through.
        assert!(!guard.is_allowed("::ffff:10.0.0.5"));
        assert!(!guard.is_allowed("[::ffff:169.254.169.254]"));
    }

    #[test]
    fn blocks_non_dotted_numeric_ip_encodings() {
        let guard = EgressAllowlistGuard::new();
        // inet_aton forms of 127.0.0.1 and 169.254.169.254 must not slip past the classifier.
        assert!(!guard.is_allowed("2130706433")); // 127.0.0.1 decimal
        assert!(!guard.is_allowed("0x7f000001")); // 127.0.0.1 hex
        assert!(!guard.is_allowed("0177.0.0.1")); // octal first octet
        assert!(!guard.is_allowed("127.1")); // short form -> 127.0.0.1
        assert!(!guard.is_allowed("2852039166")); // 169.254.169.254 decimal
        // even under default_action=Allow.
        let permissive = EgressAllowlistGuard::with_config(EgressAllowlistConfig {
            enabled: true,
            allow: Vec::new(),
            default_action: DefaultAction::Allow,
            ..EgressAllowlistConfig::default()
        });
        assert!(!permissive.is_allowed("2130706433"));
        assert!(!permissive.is_allowed("0x7f000001"));
    }

    #[test]
    fn ip_literal_cannot_bypass_name_allowlist() {
        let guard = EgressAllowlistGuard::with_config(EgressAllowlistConfig {
            enabled: true,
            allow: vec!["*.example.com".to_string()],
            ..EgressAllowlistConfig::default()
        });
        // A public IP literal that is not explicitly allowlisted is still denied
        // by the default Block action; a name wildcard never grants it.
        assert!(!guard.is_allowed("93.184.216.34"));
    }

    #[test]
    fn dangerous_ip_is_blocked_even_when_default_action_allow() {
        let guard = EgressAllowlistGuard::with_config(EgressAllowlistConfig {
            enabled: true,
            allow: Vec::new(),
            default_action: DefaultAction::Allow,
            ..EgressAllowlistConfig::default()
        });
        // default_action=Allow must not open up SSRF-class destinations.
        assert!(!guard.is_allowed("169.254.169.254"));
        assert!(!guard.is_allowed("127.0.0.1"));
        assert!(!guard.is_allowed("10.0.0.5"));
        // A genuine public host is allowed under default Allow.
        assert!(guard.is_allowed("example.com"));
    }

    #[test]
    fn explicit_allowlist_entry_overrides_class_denial() {
        let guard = EgressAllowlistGuard::with_config(EgressAllowlistConfig {
            enabled: true,
            allow: vec!["127.0.0.1".to_string(), "localhost".to_string()],
            ..EgressAllowlistConfig::default()
        });
        // Exact literal entries are an intentional, operator-declared escape.
        assert!(guard.is_allowed("127.0.0.1"));
        assert!(guard.is_allowed("localhost"));
        // A different loopback address that was NOT listed stays blocked.
        assert!(!guard.is_allowed("127.0.0.2"));
    }

    #[test]
    fn allows_public_destination() {
        let guard = EgressAllowlistGuard::with_config(EgressAllowlistConfig {
            enabled: true,
            allow: vec!["api.example.com".to_string()],
            ..EgressAllowlistConfig::default()
        });
        assert!(guard.is_allowed("api.example.com"));
    }

    #[test]
    fn check_blocks_metadata_ip_with_ssrf_reason() {
        let guard = EgressAllowlistGuard::new();
        let result = guard.check(
            &GuardAction::NetworkEgress("169.254.169.254", 80),
            &GuardContext::new(),
        );
        assert!(!result.allowed);
        assert!(result.message.contains("SSRF-blocked"));
        assert!(result.message.contains("link-local"));
    }
}
