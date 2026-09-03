//! INV-30 (as narrowed by 00-DECISIONS W3-23): the CSP is a pinned literal.
//!
//! `tests/csp.rs` checks the *shape* of individual directives (no bare
//! origins, the media scheme, no `unsafe-inline`); this module pins the whole
//! policy string so any widening — a new remote script host in particular —
//! is a reviewed edit of this file rather than a config drift.

const PINNED_CSP: &str = "default-src 'self'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self' ipc: http://ipc.localhost ambush-media: http://ambush-media.localhost https: http: wss: ws:; img-src 'self' ambush-media: http://ambush-media.localhost data: blob: https: http:; media-src 'self' ambush-media: http://ambush-media.localhost data: blob: https: http:; worker-src 'self' blob:";

#[test]
fn csp_is_the_pinned_literal() {
    let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json"))
        .unwrap_or_else(|e| panic!("tauri.conf.json must parse: {e}"));
    let csp = conf["app"]["security"]["csp"].as_str().unwrap_or_default();
    assert_eq!(
        csp, PINNED_CSP,
        "security.csp changed; widening it is a reviewed edit of this test"
    );
}

#[test]
fn csp_has_no_remote_script_source() {
    let script_src = PINNED_CSP
        .split(';')
        .find(|d| d.trim().starts_with("script-src"))
        .unwrap_or_default();
    assert!(
        !script_src.contains("http"),
        "script-src must not name a remote host: {script_src}"
    );
}
