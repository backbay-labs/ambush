//! Per-source HTTP rate limiting, shared by every HTTP surface in the tree.
//!
//! # Why this lives in `swarm-core` (SPLIT-05, phase 282)
//!
//! The limiter used to be `swarm_runtime::http::rate_limit`. SPLIT-01 moved the
//! rest of `http/` up into `swarm-runtime-http` and deliberately left this
//! module behind, because `ingest/` -- which was still in the composition root
//! -- holds an `HttpRateLimiter` for the platform API surface and maps its
//! `HttpRateLimitRejection` onto a 429.
//!
//! SPLIT-05 takes `ingest/` out into `swarm-ingest-runtime`, and the settled
//! layering is:
//!
//! ```text
//! swarm-runtime-http -> swarm-ingest-runtime -> swarm-runtime -> swarm-core
//! ```
//!
//! Two surfaces need the limiter and they sit at different heights: the
//! operator surface in `swarm-runtime-http` (top) and the platform API surface
//! in `swarm-ingest-runtime` (middle). So the limiter cannot live in either of
//! them without the other acquiring a dependency that points back down the
//! stack:
//!
//! - in `swarm-runtime-http`, `swarm-ingest-runtime` would have to depend on a
//!   crate that already depends on it, which Cargo rejects outright;
//! - in `swarm-ingest-runtime`, it would still be above `swarm-runtime`, whose
//!   `service` module embeds [`HttpRateLimitStatus`] in its operator status
//!   report.
//!
//! `swarm-core` is the only position that both surfaces can reach downward, and
//! it is where the limiter's own configuration type,
//! [`crate::config::HttpRateLimitConfig`], already lived. Same precedent as
//! SPLIT-02's `OperatorSurfacePaths` and SPLIT-05's own `BridgeStatusReport`:
//! shared data and the primitive that produces it go down into `swarm-core`,
//! the transport that mounts them stays up.
//!
//! # `http` rather than `axum`
//!
//! `check_request` takes an [`http::HeaderMap`]. It used to be spelled
//! `axum::http::HeaderMap`, which is a re-export of exactly this type from
//! exactly this crate, so every call site is unchanged and no coercion was
//! introduced. Naming `http` directly keeps the web framework out of
//! `swarm-core`; `axum` still depends on `http`, so nothing new is compiled.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use arc_swap::ArcSwap;
use http::HeaderMap;
use serde::{Deserialize, Serialize};

use crate::config::HttpRateLimitConfig;

const MAX_TRACKED_SOURCES: usize = 4_096;
const MAX_RECENT_VIOLATIONS: usize = 64;

/// Which of the two configured windows a request tripped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpRateLimitThreshold {
    Burst,
    Sustained,
}

/// One recorded rejection, retained for the operator status surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRateLimitViolationRecord {
    pub source: String,
    pub path: String,
    pub threshold: HttpRateLimitThreshold,
    pub observed_at_ms: i64,
    pub retry_after_ms: u64,
}

/// A limiter's configuration and recent violations, as reported to operators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRateLimitStatus {
    pub surface: String,
    pub config: HttpRateLimitConfig,
    #[serde(default)]
    pub recent_violations: Vec<HttpRateLimitViolationRecord>,
}

#[derive(Debug, Clone)]
pub struct HttpRateLimiter {
    surface: &'static str,
    config: Arc<ArcSwap<HttpRateLimitConfig>>,
    state: Arc<Mutex<HttpRateLimiterState>>,
}

#[derive(Debug, Clone)]
pub struct HttpRateLimitRejection {
    pub source: String,
    pub path: String,
    pub threshold: HttpRateLimitThreshold,
    pub retry_after_ms: u64,
}

#[derive(Debug, Default)]
struct HttpRateLimiterState {
    sources: HashMap<String, SourceRateLimitState>,
    recent_violations: VecDeque<HttpRateLimitViolationRecord>,
}

#[derive(Debug, Default)]
struct SourceRateLimitState {
    burst: VecDeque<i64>,
    sustained: VecDeque<i64>,
    last_seen_ms: i64,
}

impl HttpRateLimiter {
    pub fn new(surface: &'static str, config: HttpRateLimitConfig) -> Self {
        Self {
            surface,
            config: Arc::new(ArcSwap::from_pointee(config)),
            state: Arc::new(Mutex::new(HttpRateLimiterState::default())),
        }
    }

    pub fn update_config(&self, config: HttpRateLimitConfig) {
        self.config.store(Arc::new(config));
    }

    pub fn check_request(
        &self,
        headers: &HeaderMap,
        peer_addr: Option<SocketAddr>,
        path: &str,
        now_ms: i64,
    ) -> Result<(), HttpRateLimitRejection> {
        let config = self.config.load_full();
        let source = request_source(headers, peer_addr, config.trust_forwarded_headers);
        self.check_source(source, path.to_string(), now_ms, &config)
    }

    pub fn status(&self) -> HttpRateLimitStatus {
        let state = self.lock_state();
        HttpRateLimitStatus {
            surface: self.surface.to_string(),
            config: self.config.load_full().as_ref().clone(),
            recent_violations: state.recent_violations.iter().cloned().collect(),
        }
    }

    fn check_source(
        &self,
        source: String,
        path: String,
        now_ms: i64,
        config: &HttpRateLimitConfig,
    ) -> Result<(), HttpRateLimitRejection> {
        let mut state = self.lock_state();
        let rejection = {
            let source_state = state.sources.entry(source.clone()).or_default();
            prune_window(&mut source_state.burst, now_ms, config.burst_window_ms);
            prune_window(
                &mut source_state.sustained,
                now_ms,
                config.sustained_window_ms,
            );

            if source_state.burst.len() >= config.burst_max_requests {
                Some(HttpRateLimitRejection {
                    source,
                    path,
                    threshold: HttpRateLimitThreshold::Burst,
                    retry_after_ms: retry_after_ms(
                        &source_state.burst,
                        now_ms,
                        config.burst_window_ms,
                    ),
                })
            } else if source_state.sustained.len() >= config.sustained_max_requests {
                Some(HttpRateLimitRejection {
                    source,
                    path,
                    threshold: HttpRateLimitThreshold::Sustained,
                    retry_after_ms: retry_after_ms(
                        &source_state.sustained,
                        now_ms,
                        config.sustained_window_ms,
                    ),
                })
            } else {
                source_state.burst.push_back(now_ms);
                source_state.sustained.push_back(now_ms);
                source_state.last_seen_ms = now_ms;
                None
            }
        };

        if let Some(rejection) = rejection {
            push_violation(&mut state.recent_violations, &rejection, now_ms);
            compact_sources(&mut state.sources, now_ms, config);
            tracing::warn!(
                surface = self.surface,
                source = %rejection.source,
                path = %rejection.path,
                threshold = ?rejection.threshold,
                retry_after_ms = rejection.retry_after_ms,
                "HTTP rate limit exceeded"
            );
            return Err(rejection);
        }

        compact_sources(&mut state.sources, now_ms, config);
        Ok(())
    }

    fn lock_state(&self) -> MutexGuard<'_, HttpRateLimiterState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn request_source(
    headers: &HeaderMap,
    peer_addr: Option<SocketAddr>,
    trust_forwarded_headers: bool,
) -> String {
    if trust_forwarded_headers {
        if let Some(source) = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(first_forwarded_source)
        {
            return source;
        }

        if let Some(source) = headers
            .get("x-real-ip")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
        {
            return source;
        }

        if let Some(source) = headers
            .get("forwarded")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_forwarded_header_source)
        {
            return source;
        }
    }

    if let Some(addr) = peer_addr {
        return addr.ip().to_string();
    }

    "unknown".to_string()
}

fn first_forwarded_source(value: &str) -> Option<String> {
    value
        .split(',')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn parse_forwarded_header_source(value: &str) -> Option<String> {
    for entry in value.split(',') {
        for segment in entry.split(';') {
            let segment = segment.trim();
            let Some(rest) = segment.strip_prefix("for=") else {
                continue;
            };
            let rest = rest.trim_matches('"').trim();
            let rest = rest.trim_start_matches('[').trim_end_matches(']');
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
    }
    None
}

fn prune_window(window: &mut VecDeque<i64>, now_ms: i64, window_ms: u64) {
    while let Some(oldest) = window.front().copied() {
        if now_ms.saturating_sub(oldest) < window_ms as i64 {
            break;
        }
        window.pop_front();
    }
}

fn retry_after_ms(window: &VecDeque<i64>, now_ms: i64, window_ms: u64) -> u64 {
    window
        .front()
        .map(|oldest| {
            let resume_at_ms = oldest.saturating_add(window_ms as i64);
            resume_at_ms.saturating_sub(now_ms).max(1) as u64
        })
        .unwrap_or(window_ms.max(1))
}

fn push_violation(
    recent_violations: &mut VecDeque<HttpRateLimitViolationRecord>,
    rejection: &HttpRateLimitRejection,
    now_ms: i64,
) {
    recent_violations.push_front(HttpRateLimitViolationRecord {
        source: rejection.source.clone(),
        path: rejection.path.clone(),
        threshold: rejection.threshold,
        observed_at_ms: now_ms,
        retry_after_ms: rejection.retry_after_ms,
    });
    while recent_violations.len() > MAX_RECENT_VIOLATIONS {
        recent_violations.pop_back();
    }
}

fn compact_sources(
    sources: &mut HashMap<String, SourceRateLimitState>,
    now_ms: i64,
    config: &HttpRateLimitConfig,
) {
    sources.retain(|_, state| {
        prune_window(&mut state.burst, now_ms, config.burst_window_ms);
        prune_window(&mut state.sustained, now_ms, config.sustained_window_ms);
        !(state.burst.is_empty()
            && state.sustained.is_empty()
            && now_ms.saturating_sub(state.last_seen_ms) >= config.sustained_window_ms as i64)
    });

    while sources.len() > MAX_TRACKED_SOURCES {
        let Some(oldest_key) = sources
            .iter()
            .min_by_key(|(_, state)| state.last_seen_ms)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        sources.remove(&oldest_key);
    }
}
