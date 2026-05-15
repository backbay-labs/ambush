use chrono::DateTime;
use reqwest::Client;
use serde_json::Value;
use swarm_core::config::TaxiiThreatIntelFeedConfig;
use swarm_core::{ThreatIntelEntry, ThreatIntelIndicatorType};

#[derive(Debug, Clone)]
pub struct TaxiiPoller {
    config: TaxiiThreatIntelFeedConfig,
    client: Client,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaxiiPollOutcome {
    pub polled_at_ms: i64,
    pub entries: Vec<ThreatIntelEntry>,
}

#[derive(Debug, thiserror::Error)]
pub enum TaxiiPollError {
    #[error("failed to fetch TAXII collection `{url}`: {source}")]
    Fetch {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("TAXII collection `{url}` returned HTTP {status}")]
    HttpStatus {
        url: String,
        status: reqwest::StatusCode,
    },

    #[error("failed to decode TAXII collection `{url}` as JSON: {source}")]
    Decode {
        url: String,
        #[source]
        source: reqwest::Error,
    },
}

impl TaxiiPoller {
    pub fn new(config: TaxiiThreatIntelFeedConfig) -> Self {
        // Bound every request so a half-open or stalled TAXII endpoint cannot
        // pin a worker indefinitely and block runtime shutdown.
        let timeout = std::time::Duration::from_millis(config.poll_interval_ms.max(1_000));
        let client = Client::builder()
            .timeout(timeout)
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self { config, client }
    }

    pub fn from_config(config: &TaxiiThreatIntelFeedConfig) -> Self {
        Self::new(config.clone())
    }

    pub fn config(&self) -> &TaxiiThreatIntelFeedConfig {
        &self.config
    }

    pub async fn poll_once(&self) -> Result<TaxiiPollOutcome, TaxiiPollError> {
        let polled_at_ms = now_ms();
        let response = self
            .client
            .get(&self.config.collection_url)
            .header("accept", "application/taxii+json, application/json")
            .send()
            .await
            .map_err(|source| TaxiiPollError::Fetch {
                url: self.config.collection_url.clone(),
                source,
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(TaxiiPollError::HttpStatus {
                url: self.config.collection_url.clone(),
                status,
            });
        }
        let body = response
            .json::<Value>()
            .await
            .map_err(|source| TaxiiPollError::Decode {
                url: self.config.collection_url.clone(),
                source,
            })?;
        Ok(TaxiiPollOutcome {
            polled_at_ms,
            entries: parse_taxii_bundle(
                &body,
                &self.config.name,
                self.config.default_ttl_secs,
                polled_at_ms,
            ),
        })
    }
}

pub fn parse_taxii_bundle(
    bundle: &Value,
    source: &str,
    default_ttl_secs: i64,
    now_ms: i64,
) -> Vec<ThreatIntelEntry> {
    bundle
        .get("objects")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|object| parse_indicator_object(object, source, default_ttl_secs, now_ms))
        .collect()
}

fn parse_indicator_object(
    object: &Value,
    source: &str,
    default_ttl_secs: i64,
    now_ms: i64,
) -> Vec<ThreatIntelEntry> {
    if object.get("type").and_then(Value::as_str) != Some("indicator") {
        return Vec::new();
    }
    let Some(pattern) = object.get("pattern").and_then(Value::as_str) else {
        return Vec::new();
    };
    let revoked = object.get("revoked").and_then(Value::as_bool) == Some(true);
    let indicator_id = object.get("id").and_then(Value::as_str).map(str::to_string);
    let confidence = if revoked {
        0.0
    } else {
        object
            .get("confidence")
            .and_then(Value::as_f64)
            .map(|value| (value / 100.0).clamp(0.0, 1.0))
            .unwrap_or(0.20)
    };
    // Revoked indicators are written as immediately-expired tombstones so the
    // substrate's keyed insert overwrites the previously-stored live entry and
    // the regular `expires_at > now` query filter (and TTL GC) drop them.
    let expires_at = if revoked {
        now_ms.saturating_sub(1)
    } else {
        object
            .get("valid_until")
            .and_then(Value::as_str)
            .and_then(parse_timestamp_ms)
            .unwrap_or_else(|| now_ms.saturating_add(default_ttl_secs.saturating_mul(1_000)))
    };

    split_pattern_clauses(pattern)
        .into_iter()
        .filter_map(parse_pattern_clause)
        .map(|(indicator_type, value)| ThreatIntelEntry {
            indicator_type,
            value,
            source: source.to_string(),
            indicator_id: indicator_id.clone(),
            confidence,
            expires_at,
        })
        .collect()
}

fn split_pattern_clauses(pattern: &str) -> Vec<&str> {
    let trimmed = pattern
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut clauses = Vec::new();
    let mut start = 0usize;
    let bytes = trimmed.as_bytes();
    let mut index = 0usize;
    let mut quoted = false;
    while index + 4 <= bytes.len() {
        let current = bytes[index];
        if current == b'\'' || current == b'"' {
            quoted = !quoted;
            index += 1;
            continue;
        }
        if !quoted
            && (trimmed[index..].starts_with(" AND ") || trimmed[index..].starts_with(" OR "))
        {
            clauses.push(trimmed[start..index].trim());
            let separator_len = if trimmed[index..].starts_with(" AND ") {
                5
            } else {
                4
            };
            index += separator_len;
            start = index;
            continue;
        }
        index += 1;
    }
    clauses.push(trimmed[start..].trim());
    clauses
        .into_iter()
        .filter(|clause| !clause.is_empty())
        .collect()
}

fn parse_pattern_clause(clause: &str) -> Option<(ThreatIntelIndicatorType, String)> {
    let (lhs, rhs) = clause.split_once('=')?;
    let lhs = lhs.trim().to_ascii_lowercase();
    let rhs = unquote(rhs.trim())?;
    let indicator_type = if lhs == "ipv4-addr:value" {
        ThreatIntelIndicatorType::IpAddress
    } else if lhs == "domain-name:value" {
        ThreatIntelIndicatorType::Domain
    } else if lhs == "url:value" {
        ThreatIntelIndicatorType::Url
    } else if lhs == "file:hashes.'sha-256'" || lhs == "file:hashes.\"sha-256\"" {
        ThreatIntelIndicatorType::FileHash
    } else {
        return None;
    };
    Some((indicator_type, rhs))
}

fn unquote(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.len() >= 2 {
        let bytes = trimmed.as_bytes();
        let first = bytes.first().copied()?;
        let last = bytes.last().copied()?;
        if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
            return Some(trimmed[1..trimmed.len() - 1].to_string());
        }
    }
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn parse_timestamp_ms(raw: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|value| value.timestamp_millis())
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{TaxiiPoller, parse_taxii_bundle};
    use axum::{Json, Router, routing::get};
    use serde_json::json;
    use swarm_core::ThreatIntelIndicatorType;
    use swarm_core::config::TaxiiThreatIntelFeedConfig;

    #[test]
    fn parses_supported_indicator_types_from_taxii_bundle() {
        let bundle = json!({
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--ipv4",
                    "pattern": "[ipv4-addr:value = '198.51.100.7']",
                    "confidence": 80,
                    "valid_until": "2026-04-15T12:00:00Z"
                },
                {
                    "type": "indicator",
                    "id": "indicator--domain",
                    "pattern": "[domain-name:value = 'EVIL.EXAMPLE.']"
                },
                {
                    "type": "indicator",
                    "id": "indicator--url",
                    "pattern": "[url:value = 'https://evil.example/payload']"
                },
                {
                    "type": "indicator",
                    "id": "indicator--hash",
                    "pattern": "[file:hashes.'SHA-256' = 'ABCDEF1234']"
                }
            ]
        });

        let entries = parse_taxii_bundle(&bundle, "taxii-primary", 3600, 1_760_000_000_000);
        assert_eq!(entries.len(), 4);
        assert_eq!(
            entries[0].indicator_type,
            ThreatIntelIndicatorType::IpAddress
        );
        assert_eq!(entries[0].source, "taxii-primary");
        assert_eq!(entries[0].indicator_id.as_deref(), Some("indicator--ipv4"));
        assert_eq!(entries[1].indicator_type, ThreatIntelIndicatorType::Domain);
        assert_eq!(entries[1].value, "EVIL.EXAMPLE.");
        assert_eq!(entries[2].indicator_type, ThreatIntelIndicatorType::Url);
        assert_eq!(
            entries[3].indicator_type,
            ThreatIntelIndicatorType::FileHash
        );
    }

    #[tokio::test]
    async fn poll_once_fetches_taxii_collection() {
        let app = Router::new().route(
            "/collection",
            get(|| async {
                Json(json!({
                    "objects": [{
                        "type": "indicator",
                        "id": "indicator--one",
                        "pattern": "[domain-name:value = 'evil.example']",
                        "confidence": 60
                    }]
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let poller = TaxiiPoller::new(TaxiiThreatIntelFeedConfig {
            name: "taxii-primary".to_string(),
            collection_url: format!("http://{addr}/collection"),
            poll_interval_ms: 1_000,
            default_ttl_secs: 3_600,
        });
        let outcome = poller.poll_once().await.expect("poll should succeed");
        assert_eq!(outcome.entries.len(), 1);
        assert_eq!(outcome.entries[0].source, "taxii-primary");
        assert_eq!(
            outcome.entries[0].indicator_type,
            ThreatIntelIndicatorType::Domain
        );
        assert_eq!(
            outcome.entries[0].indicator_id.as_deref(),
            Some("indicator--one")
        );

        server.abort();
    }

    #[test]
    fn revoked_indicator_objects_become_immediately_expired_tombstones() {
        let bundle = json!({
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--live",
                    "pattern": "[domain-name:value = 'live.example']"
                },
                {
                    "type": "indicator",
                    "id": "indicator--gone",
                    "pattern": "[domain-name:value = 'withdrawn.example']",
                    "revoked": true
                }
            ]
        });

        let now_ms = 1_760_000_000_000;
        let entries = parse_taxii_bundle(&bundle, "taxii-primary", 3600, now_ms);
        assert_eq!(entries.len(), 2);
        let live = entries
            .iter()
            .find(|entry| entry.value == "live.example")
            .expect("live entry must be present");
        assert!(live.expires_at > now_ms);

        let revoked = entries
            .iter()
            .find(|entry| entry.value == "withdrawn.example")
            .expect("revoked entry must be emitted as tombstone");
        assert!(revoked.expires_at < now_ms);
        assert_eq!(revoked.confidence, 0.0);
    }
}
