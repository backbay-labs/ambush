//! ADR 0014 C1 / INV-29: no renderer-supplied content may be signed as a swarm
//! governance marker, on any command. `perch_record_verdict` is the only
//! producer of `swarm:verdict:v1`, and it never passes its content here.
//!
//! Every `#[tauri::command]` that signs renderer-supplied `content` calls
//! [`perch_sign_gate`] with the kind it is about to sign, before any signing
//! identity is resolved; `perch_sign_gate_inventory_tests.rs` asserts that set
//! from the source rather than remembering it.

/// The kind the swarm bridge alone may publish (a held destructive action).
pub const KIND_WORKFLOW_APPROVAL_REQUESTED: u16 = 46010;

/// The chat message kind whose line 0 the console parses for a swarm card.
pub const KIND_STREAM_MESSAGE: u16 = 9;

// The local `u16` constants must never drift from the relay's kind registry.
const _: () = assert!(
    KIND_WORKFLOW_APPROVAL_REQUESTED as u32
        == ambush_core_pkg::kind::KIND_WORKFLOW_APPROVAL_REQUESTED
);
const _: () = assert!(KIND_STREAM_MESSAGE as u32 == ambush_core_pkg::kind::KIND_STREAM_MESSAGE);

/// Refuses kind 46010 outright and any kind 9 whose line 0 is exactly a
/// `<!-- swarm:<slug>:v<N> -->` marker (line 0 is `trim_end`ed, never
/// `trim_start`ed, matching the renderer's whole-line rule).
///
/// Call it with the exact string that will be signed: a site that trims its
/// content before building the event must gate the trimmed string, or a
/// leading space would slip a marker past the check.
pub fn perch_sign_gate(kind: u16, content: &str) -> Result<(), String> {
    if kind == KIND_WORKFLOW_APPROVAL_REQUESTED {
        return Err("restricted: kind 46010 is published by the swarm bridge only".to_string());
    }
    if kind == KIND_STREAM_MESSAGE {
        let line0 = content.split('\n').next().unwrap_or("").trim_end();
        if is_swarm_marker_line(line0) {
            return Err(
                "restricted: swarm markers are produced by perch_record_verdict only".to_string(),
            );
        }
    }
    Ok(())
}

/// `^<!-- swarm:[a-z]+:v\d+ -->$` without a regex dependency.
pub fn is_swarm_marker_line(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("<!-- swarm:") else {
        return false;
    };
    let Some(rest) = rest.strip_suffix(" -->") else {
        return false;
    };
    let mut parts = rest.split(':');
    let (Some(slug), Some(version), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let slug_ok = !slug.is_empty() && slug.bytes().all(|b| b.is_ascii_lowercase());
    let version_ok = version
        .strip_prefix('v')
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()));
    slug_ok && version_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_kind_46010_outright() {
        assert!(perch_sign_gate(46010, "anything").is_err());
    }

    #[test]
    fn refuses_a_kind_9_governance_marker() {
        assert!(perch_sign_gate(9, "<!-- swarm:verdict:v1 -->\n{}\nhuman").is_err());
        assert!(perch_sign_gate(9, "<!-- swarm:finding:v1 -->").is_err());
        assert!(
            perch_sign_gate(9, "<!-- swarm:hold:v12 -->   ").is_err(),
            "trailing whitespace is trimmed"
        );
    }

    #[test]
    fn allows_the_chat_apps_own_markers_and_prose() {
        assert!(perch_sign_gate(9, "<!-- ambush:wave:v1 -->\nhello").is_ok());
        assert!(
            perch_sign_gate(9, "hello <!-- swarm:verdict:v1 -->").is_ok(),
            "not the whole line"
        );
        assert!(
            perch_sign_gate(9, " <!-- swarm:verdict:v1 -->").is_ok(),
            "leading space: the renderer will not parse it either"
        );
        assert!(
            perch_sign_gate(40002, "<!-- swarm:verdict:v1 -->").is_ok(),
            "only kind 9 carries cards"
        );
    }

    #[test]
    fn marker_grammar_is_exact() {
        assert!(is_swarm_marker_line("<!-- swarm:finding:v1 -->"));
        assert!(!is_swarm_marker_line("<!-- swarm:Finding:v1 -->"));
        assert!(!is_swarm_marker_line("<!-- swarm:finding:1 -->"));
        assert!(!is_swarm_marker_line("<!-- swarm:finding:v -->"));
        assert!(!is_swarm_marker_line("<!-- swarm::v1 -->"));
    }
}
