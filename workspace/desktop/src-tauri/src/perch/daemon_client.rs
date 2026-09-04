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
    let mut request = state
        .http_client
        .request(method, &url)
        .bearer_auth(daemon_bearer()?)
        .header(SCHEMA_VERSION_HEADER.0, SCHEMA_VERSION_HEADER.1);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .await
        .map_err(|e| format!("daemon unreachable: {e}"))?;
    let status = response.status().as_u16();
    let body = response
        .json::<serde_json::Value>()
        .await
        .unwrap_or(serde_json::Value::Null);
    Ok(DaemonResponse { status, body })
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
