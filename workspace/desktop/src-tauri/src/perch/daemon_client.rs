//! The console's ONLY path to the daemon. One dispatch function consults the
//! INV-01 table; every command names a route constant; nothing here accepts a
//! path from the renderer.
//!
//! "Perch never authorizes" is a claim about a SET — the set of non-GET
//! requests this process can issue to a daemon host. The claim is only true if
//! the set is enumerable, so there is no generic passthrough: one Tauri command
//! per route, each naming a `&'static str` template compiled into this binary,
//! and [`PERCH_DAEMON_WRITES`] is the whole of it.

use crate::app_state::AppState;

/// INV-01: the console's entire daemon-bound non-GET surface.
///
/// First card implements the two operator routes it needs
/// (`/v1/operator/findings/{finding_id}/feedback` and
/// `/v1/operator/incidents`); the other three are listed because the set has to
/// be reviewable as a set, and `tools/check-perch-write-allowlist.sh` asserts
/// this table against the same five, both directions.
pub const PERCH_DAEMON_WRITES: [(&str, &str); 5] = [
    ("POST", "/v1/response/holds/{hold_id}/decide"),
    ("POST", "/v1/operator/findings/{finding_id}/feedback"),
    ("POST", "/v1/operator/incidents"),
    ("POST", "/v1/operator/containment/leases/{lease_id}/release"),
    ("POST", "/v1/operator/review/sessions"),
];

/// Keyring key holding the daemon base URL. Never crosses IPC.
pub const PERCH_DAEMON_URL_KEY: &str = "perch.daemon_url";
/// Keyring key holding the daemon bearer token. Never crosses IPC.
pub const PERCH_DAEMON_BEARER_KEY: &str = "perch.daemon_bearer";
/// Keyring key holding this operator's daemon principal id. Never crosses IPC.
pub const PERCH_OPERATOR_ID_KEY: &str = "perch.operator_id";

const SCHEMA_VERSION_HEADER: (&str, &str) = ("x-swarm-schema-version", "1");

/// A route the console is allowed to name: the compiled-in template it was
/// built from, and the concrete path with its parameters substituted.
///
/// The template is what the allowlist is checked against, so a parameter value
/// can never smuggle a route past the table.
#[derive(Debug, Clone)]
pub struct DaemonRoute {
    /// The compiled-in `&'static str` this path was built from.
    pub template: &'static str,
    /// The concrete path, percent-encoded.
    pub path: String,
}

/// A daemon answer: the HTTP status, and the JSON body (`Null` when the body
/// was empty or not JSON). Commands decide what a non-200 means.
#[derive(Debug, Clone)]
pub struct DaemonResponse {
    /// The HTTP status code.
    pub status: u16,
    /// The parsed JSON body, or `Null`.
    pub body: serde_json::Value,
    /// `Retry-After`, in seconds, when the daemon sent one. The decide route
    /// returns it on a 409 whose conflict resolves itself.
    pub retry_after_seconds: Option<u64>,
}

/// Percent-encode `value` over the RFC 3986 unreserved set. Everything else is
/// escaped, so no parameter value can introduce a path segment, a query or a
/// fragment.
fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Build a concrete [`DaemonRoute`] from a compiled-in template.
///
/// Refuses an empty parameter, a parameter containing a slash, and any template
/// left with an unsubstituted `{placeholder}`.
pub fn route(template: &'static str, params: &[(&str, &str)]) -> Result<DaemonRoute, String> {
    let mut path = template.to_string();
    for (name, value) in params {
        if value.is_empty() || value.contains('/') {
            return Err(format!(
                "route parameter `{name}` is empty or contains a slash"
            ));
        }
        let encoded = url_encode(value);
        path = path.replace(&format!("{{{name}}}"), &encoded);
    }
    if path.contains('{') {
        return Err(format!("route `{template}` has an unsubstituted parameter"));
    }
    Ok(DaemonRoute { template, path })
}

/// The daemon's page-size floor and ceiling, mirrored from
/// `crates/swarm-runtime-http/src/http/perch/holds.rs` (`1..=1000`).
///
/// Clamped HERE and not left to the daemon: a console that sends a value the
/// daemon has to reinterpret is a console whose displayed page size is a guess.
const HOLD_LIMIT_RANGE: std::ops::RangeInclusive<usize> = 1..=1_000;

/// The query string for `GET /v1/response/holds`, built from typed values.
///
/// The route template stays exactly `/v1/response/holds` so the INV-01 table
/// is compared against an unchanging string; the query is appended to the
/// concrete path, never to the base URL, and every value here is a `bool`, a
/// clamped `usize` or an `i64`, so nothing the renderer supplies can shape a
/// path, a second query parameter or a fragment.
pub fn hold_list_query(
    include_terminal: bool,
    limit: Option<usize>,
    now_ms: Option<i64>,
) -> String {
    let mut query = format!("?include_terminal={include_terminal}");
    if let Some(limit) = limit {
        let limit = limit.clamp(*HOLD_LIMIT_RANGE.start(), *HOLD_LIMIT_RANGE.end());
        query.push_str(&format!("&limit={limit}"));
    }
    if let Some(now_ms) = now_ms {
        query.push_str(&format!("&now_ms={now_ms}"));
    }
    query
}

/// The marker every redaction leaves behind.
const REDACTED: &str = "[redacted]";

/// Prefixes after which the next run of non-delimiter characters is a secret.
///
/// Matched case-insensitively. `presented` is the daemon's own field for the
/// credential it was HANDED, which on a misconfigured console is a token this
/// process never held — shape, not ownership, is what makes a string unsafe.
const SECRET_PREFIXES: [&str; 6] = [
    "bearer ",
    "basic ",
    "token=",
    "access_token=",
    "presented=",
    "\"presented\":",
];

/// Shortest token worth substring-replacing. A one- or two-character "secret"
/// would redact half of every message and hide the error instead of the token.
const MIN_REPLACEABLE_TOKEN: usize = 8;

/// Strip anything bearer-shaped from a string before it crosses IPC (INV-22).
///
/// Two passes: the exact `token` this process holds, and then any value that
/// FOLLOWS a credential-shaped prefix, whoever it belongs to. Redaction is
/// idempotent and never panics on multi-byte text.
pub fn redact_for_ipc(message: &str, token: &str) -> String {
    let mut out = if token.len() >= MIN_REPLACEABLE_TOKEN {
        message.replace(token, REDACTED)
    } else {
        message.to_string()
    };
    for prefix in SECRET_PREFIXES {
        out = redact_after_prefix(&out, prefix);
    }
    out
}

/// Characters that end a secret. A value that reaches one of these has ended,
/// whether it was quoted, parenthesised or the tail of a JSON object.
fn is_secret_terminator(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\'' | ')' | '}' | ',' | ';' | '&')
}

/// Replace the run of characters following each (case-insensitive) `prefix`
/// with [`REDACTED`], stopping at the first [`is_secret_terminator`].
///
/// One optional opening quote directly after the prefix is stepped over, so
/// `presented="abc"` and `presented=abc` both redact `abc` and neither leaves
/// the quote inside the marker.
fn redact_after_prefix(haystack: &str, prefix: &str) -> String {
    // `to_ascii_lowercase` preserves byte length and char boundaries, so an
    // index found in the lowered copy is valid in the original.
    let lowered = haystack.to_ascii_lowercase();
    let needle = prefix.to_ascii_lowercase();
    let mut out = String::with_capacity(haystack.len());
    let mut cursor = 0usize;
    while let Some(found) = lowered[cursor..].find(&needle) {
        let mut value_start = cursor + found + prefix.len();
        if haystack[value_start..].starts_with(['"', '\'']) {
            value_start += 1;
        }
        out.push_str(&haystack[cursor..value_start]);
        let value_end = haystack[value_start..]
            .find(is_secret_terminator)
            .map_or(haystack.len(), |offset| value_start + offset);
        if value_end > value_start {
            out.push_str(REDACTED);
        }
        cursor = value_end;
    }
    out.push_str(&haystack[cursor..]);
    out
}

/// A non-2xx daemon answer as one redacted line for the webview.
///
/// Keeps the daemon's `error` slug verbatim — it is the taxonomy the console
/// branches on (W3-17: a `409` is resolved by RE-READING the hold, and the
/// slug says which 409 it was) — and redacts only the free-text `message`.
pub fn daemon_status_error(status: u16, body: &serde_json::Value, token: &str) -> String {
    let error = body["error"].as_str().unwrap_or("unknown");
    let message = redact_for_ipc(body["message"].as_str().unwrap_or(""), token);
    format!("daemon answered {status} {error}: {message}")
}

/// Whether `(method, template)` is one of the five INV-01 writes.
pub fn is_allowlisted_write(method: &str, template: &str) -> bool {
    PERCH_DAEMON_WRITES
        .iter()
        .any(|(m, t)| *m == method && *t == template)
}

/// The daemon base URL from the keyring, or an error naming the missing
/// configuration. The value never crosses IPC into the webview.
pub fn daemon_url(_state: &AppState) -> Result<String, String> {
    keyring_value(PERCH_DAEMON_URL_KEY)
}

/// The daemon bearer token from the keyring. The value never crosses IPC into
/// the webview; only this module ever reads it, and only into a header.
pub fn daemon_bearer() -> Result<String, String> {
    keyring_value(PERCH_DAEMON_BEARER_KEY)
}

/// This operator's daemon principal id from the keyring. Public by
/// construction: the daemon derives the voter id from the operator's verifying
/// key and refuses a signature whose key_id does not bind to the principal.
pub fn operator_id() -> Result<String, String> {
    keyring_value(PERCH_OPERATOR_ID_KEY)
}

fn keyring_value(key: &str) -> Result<String, String> {
    let store = crate::secret_store::SecretStore::shared(crate::app_state::keyring_service());
    match store.load(key) {
        Ok(Some(value)) if !value.is_empty() => Ok(value),
        Ok(_) => Err(format!("daemon not configured: {key} is unset")),
        Err(e) => Err(format!("daemon not configured: {key} unreadable: {e}")),
    }
}

async fn perch_daemon_request(
    state: &AppState,
    method: reqwest::Method,
    route: &DaemonRoute,
    body: Option<serde_json::Value>,
) -> Result<DaemonResponse, String> {
    if method != reqwest::Method::GET && !is_allowlisted_write(method.as_str(), route.template) {
        return Err(format!(
            "{} {} is not on the INV-01 allowlist",
            method, route.template
        ));
    }
    let url = format!("{}{}", daemon_url(state)?.trim_end_matches('/'), route.path);
    let token = daemon_bearer()?;
    let mut request = state
        .http_client
        .request(method, &url)
        .bearer_auth(&token)
        .header(SCHEMA_VERSION_HEADER.0, SCHEMA_VERSION_HEADER.1);
    if let Some(body) = body {
        request = request.json(&body);
    }
    // A transport error carries the request URL and, through a proxy, whatever
    // the proxy chose to say. Both the URL and the bearer are redacted before
    // this can become a `Result::Err` a command hands to the webview (INV-22).
    let response = request
        .send()
        .await
        .map_err(|e| transport_error_message(&e.to_string(), &url, &token))?;
    let status = response.status().as_u16();
    // Read before the body is consumed. W3-17: a 409 whose conflict resolves
    // itself carries this, and the console waits rather than re-reading at once.
    let retry_after_seconds = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok());
    let body = response
        .json::<serde_json::Value>()
        .await
        .unwrap_or(serde_json::Value::Null);
    Ok(DaemonResponse {
        status,
        body,
        retry_after_seconds,
    })
}

/// Read a daemon route. GETs are not on the write table and are not checked
/// against it; nothing here mutates daemon state.
#[rustfmt::skip]
pub async fn perch_daemon_get(state: &AppState, route: &DaemonRoute) -> Result<DaemonResponse, String> { perch_daemon_request(state, reqwest::Method::GET, route, None).await }

/// Write to a daemon route. The `(method, template)` pair must be one of the
/// five in [`PERCH_DAEMON_WRITES`], checked before the keyring is read and
/// before any socket is opened.
#[rustfmt::skip]
pub async fn perch_daemon_post(state: &AppState, route: &DaemonRoute, body: serde_json::Value) -> Result<DaemonResponse, String> { perch_daemon_request(state, reqwest::Method::POST, route, Some(body)).await }

/// A non-2xx [`DaemonResponse`] as one redacted line for the webview.
///
/// Reads this process's own bearer for the substring pass so that no command
/// module ever names the keyring: a command that could read the token is a
/// command one careless `format!` away from returning it.
pub fn daemon_response_error(response: &DaemonResponse) -> String {
    let token = daemon_bearer().unwrap_or_default();
    daemon_status_error(response.status, &response.body, &token)
}

/// The admitted-issuer set, as the daemon publishes it.
///
/// D-FC-2: the daemon serves this unauthenticated at
/// `/metrics/perch/identities` and it carries public keys and lane channel ids
/// only, so it is fetched without a bearer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct PerchAdmittedIssuers {
    /// The bridge identities whose cards this console renders, lowercased hex.
    pub issuers: Vec<String>,
    /// Lane name → lane channel UUID.
    pub lanes: std::collections::BTreeMap<String, String>,
    /// The colony this daemon speaks for.
    pub colony_id: String,
}

/// Route of the unauthenticated identities endpoint (D-FC-2).
pub const ROUTE_IDENTITIES: &str = "/metrics/perch/identities";

/// Fetch the admitted-issuer set from the daemon.
///
/// Sent without a bearer: the endpoint is public by decision D-FC-2, and
/// attaching the operator's token to an unauthenticated endpoint would widen
/// where that token travels for nothing.
pub async fn fetch_admitted_issuers(state: &AppState) -> Result<PerchAdmittedIssuers, String> {
    let url = format!(
        "{}{}",
        daemon_url(state)?.trim_end_matches('/'),
        ROUTE_IDENTITIES
    );
    let body: serde_json::Value = state
        .http_client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("daemon unreachable: {e}"))?
        .json()
        .await
        .map_err(|e| format!("the identities endpoint did not answer JSON: {e}"))?;
    Ok(PerchAdmittedIssuers {
        colony_id: body["colony_id"].as_str().unwrap_or_default().to_string(),
        issuers: body["identities"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|i| i["pubkey"].as_str().map(|s| s.to_ascii_lowercase()))
                    .collect()
            })
            .unwrap_or_default(),
        lanes: serde_json::from_value(body["lanes"].clone()).unwrap_or_default(),
    })
}

/// Seed the daemon settings into the keyring from the environment, in debug
/// builds only (D-FC-4).
///
/// A release build never reads these variables; a Settings surface arrives with
/// Operator-complete. An already-present keyring value always wins, so a
/// developer who configured the console by hand is not overwritten on the next
/// launch.
pub fn seed_daemon_settings_from_env_in_debug() {
    if !cfg!(debug_assertions) {
        return;
    }
    let store = crate::secret_store::SecretStore::shared(crate::app_state::keyring_service());
    for (key, var, default) in [
        (
            PERCH_DAEMON_URL_KEY,
            "AMBUSH_PERCH_DAEMON_URL",
            Some("http://127.0.0.1:9090"),
        ),
        (PERCH_DAEMON_BEARER_KEY, "AMBUSH_PERCH_DAEMON_BEARER", None),
        (
            PERCH_OPERATOR_ID_KEY,
            "AMBUSH_PERCH_OPERATOR_ID",
            Some("local-operator"),
        ),
    ] {
        if matches!(store.load(key), Ok(Some(_))) {
            continue;
        }
        if let Some(value) = std::env::var(var)
            .ok()
            .filter(|v| !v.is_empty())
            .or_else(|| default.map(str::to_string))
        {
            if let Err(e) = store.store(key, &value) {
                tracing::warn!(key, "perch: could not seed keyring: {e}");
            }
        }
    }
}

#[cfg(test)]
#[path = "daemon_client_tests.rs"]
mod tests;

// ── Carried from the hold-daemon branch: Tasks 20/21 call this ────────────

/// Build the message for a transport failure with the daemon URL and the
/// bearer removed.
///
/// A `reqwest::Error`'s `Display` names the URL it was dialling, and both the
/// URL and the token are keyring values this process is supposed to keep. The
/// redaction happens HERE, at the one place a transport error becomes a
/// string, rather than at each call site, because a call site can forget.
pub fn transport_error_message(error: &str, url: &str, bearer: &str) -> String {
    // Both the URL and the bearer are keyring values, and this module's
    // redactor takes one secret at a time, so pass each through in turn. The
    // origin goes too: host and port alone disclose where the daemon lives.
    let once = redact_for_ipc(error, bearer);
    format!("daemon unreachable: {}", redact_for_ipc(&once, url))
}
