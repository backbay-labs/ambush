//! Guards on the packaged-app Content-Security-Policy in `tauri.conf.json`.
//!
//! The CSP is only enforced on assets Tauri itself serves, so neither
//! `just dev` (loads the Vite `devUrl`) nor the Playwright suite (runs under
//! `vite preview`) can catch a policy that breaks the app. These tests pin the
//! non-obvious sources the frontend actually needs, so a future tightening
//! fails here instead of in a signed build.
//!
//! The whole policy string is additionally pinned as a literal by
//! `src/csp_pin_tests.rs` (INV-30 as narrowed by 00-DECISIONS W3-23): the
//! shape checks here say what each directive must keep; the pin says nothing
//! may be added without a reviewed edit.
//!
//! Kept as an integration test so the policy can be checked without the app
//! crate having to declare a test-only module.

use std::collections::HashMap;

const TAURI_CONF: &str = include_str!("../tauri.conf.json");

fn csp_directives() -> HashMap<String, Vec<String>> {
    let conf: serde_json::Value =
        serde_json::from_str(TAURI_CONF).expect("tauri.conf.json is valid JSON");
    let csp = conf["app"]["security"]["csp"]
        .as_str()
        .expect("app.security.csp is set as a policy string");

    csp.split(';')
        .filter_map(|directive| {
            let mut parts = directive.split_whitespace();
            let name = parts.next()?;
            Some((name.to_owned(), parts.map(str::to_owned).collect()))
        })
        .collect()
}

fn sources(directive: &str) -> Vec<String> {
    csp_directives()
        .remove(directive)
        .unwrap_or_else(|| panic!("csp is missing the {directive} directive"))
}

#[test]
fn script_src_allows_wasm_instantiation() {
    // Shiki's default engine (Oniguruma) instantiates inlined WebAssembly for
    // every code block. Without this token highlighting silently drops to
    // plain text.
    assert!(sources("script-src").contains(&"'wasm-unsafe-eval'".to_owned()));
}

#[test]
fn script_src_names_no_remote_host() {
    // Every script the app runs ships inside the bundle. The animated-avatar
    // capture feature was the only remote loader (a jsDelivr path prefix for
    // the MediaPipe wasm); it was removed under W3-23, and no replacement may
    // reintroduce a remote script source without a reviewed edit of the pin
    // in `src/csp_pin_tests.rs`.
    for source in sources("script-src") {
        assert!(
            source.starts_with('\''),
            "script-src must stay keyword-only, found remote source `{source}`"
        );
    }
}

/// How many path segments a source narrows to past its origin.
fn path_depth(source: &str) -> usize {
    let Some((_scheme, authority)) = source.split_once("://") else {
        return 0;
    };
    match authority.split_once('/') {
        Some((_host, path)) => path.split('/').filter(|part| !part.is_empty()).count(),
        None => 0,
    }
}

/// Whether a `script-src` source is narrow enough to be worth allowing. CSP
/// keywords (`'self'`, `'wasm-unsafe-eval'`) pass. A remote source must name a
/// non-wildcard host *and* a path reaching at least a publisher scope — a bare
/// origin, a scheme, or a registry root would put arbitrary third-party code
/// one injected `<script>` away.
fn is_pinned_script_source(source: &str) -> bool {
    if source.starts_with('\'') {
        return true;
    }
    !source.contains('*') && path_depth(source) >= 2
}

#[test]
fn script_src_trusts_no_bare_origins() {
    for source in sources("script-src") {
        assert!(
            is_pinned_script_source(&source),
            "script-src must stay scoped, found broad source `{source}`"
        );
    }
}

#[test]
fn pinned_script_source_rejects_broad_sources() {
    // Guards the guard: the check above is only worth having if it fails on the
    // shapes that reopen the allowlist.
    for allowed in [
        "'self'",
        "'wasm-unsafe-eval'",
        "https://cdn.jsdelivr.net/npm/@scope/",
        "https://cdn.jsdelivr.net/npm/@scope/package@1.0.0/dist/index.js",
    ] {
        assert!(is_pinned_script_source(allowed), "{allowed} should pass");
    }
    for rejected in [
        "https://cdn.jsdelivr.net",
        "https://cdn.jsdelivr.net/",
        "https://cdn.jsdelivr.net/npm/",
        "https://cdn.jsdelivr.net/gh/",
        "https://*.jsdelivr.net/npm/@scope/",
        "https:",
        "*",
    ] {
        assert!(
            !is_pinned_script_source(rejected),
            "{rejected} should be rejected"
        );
    }
}

#[test]
fn media_directives_allow_the_ambush_media_scheme() {
    // `rewriteRelayUrl` emits `ambush-media://localhost/...` until the loopback
    // proxy port resolves, so cold-start media renders through the custom
    // scheme (mapped to `http://ambush-media.localhost` on Windows).
    for directive in ["img-src", "media-src", "connect-src"] {
        let allowed = sources(directive);
        assert!(
            allowed.contains(&"ambush-media:".to_owned()),
            "{directive} must allow ambush-media:"
        );
        assert!(
            allowed.contains(&"http://ambush-media.localhost".to_owned()),
            "{directive} must allow http://ambush-media.localhost"
        );
    }
}

#[test]
fn connect_src_allows_ipc_and_cleartext_relays() {
    // `ipc:` / `http://ipc.localhost` carry every Tauri command. Cleartext
    // `http:`/`ws:` stay allowed because a relay URL is user-supplied and the
    // app accepts plain `ws://` on any host (`communityStorage::normalizeRelayUrl`,
    // the community edit form): `relayProbe` opens a browser WebSocket to it,
    // so narrowing this to loopback would report reachable relays as dead —
    // while the real connection, which runs through tauri-plugin-websocket in
    // Rust, is not governed by CSP at all. Blanket `https:` is already allowed,
    // so restricting the cleartext schemes would close no exfiltration path.
    let allowed = sources("connect-src");
    for source in [
        "ipc:",
        "http://ipc.localhost",
        "https:",
        "http:",
        "wss:",
        "ws:",
    ] {
        assert!(
            allowed.contains(&source.to_owned()),
            "connect-src must allow {source}"
        );
    }
}

#[test]
fn script_src_stays_free_of_unsafe_inline_and_eval() {
    let allowed = sources("script-src");
    // The inline boot script in index.html is covered by Tauri's build-time
    // SHA-256 hashing (scripts only — Tauri nonces inline <style> elements via
    // a different path), so neither escape hatch is ever needed here. The boot
    // background style was moved to public/boot.css to avoid the nonce path for
    // style-src; see boot.css for the full rationale.
    assert!(!allowed.contains(&"'unsafe-inline'".to_owned()));
    assert!(!allowed.contains(&"'unsafe-eval'".to_owned()));
}
