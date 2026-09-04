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

/// Every kind whose body reaches `MessageBody` — and therefore the perch card
/// seam — in the renderer.
///
/// This is `isTimelineContentEvent`'s eleven kinds
/// (`src/features/messages/lib/formatTimelineMessages.ts`) minus the two that
/// `MessageRow.renderBody` gives a dedicated case (40008 diff, 48100 huddle
/// start). Gating only kind 9 was not enough: a marker signed under any other
/// kind in this set still renders as a card, so `sign_event(40002, marker)`
/// produced a real, publishable, card-bearing event that the gate waved
/// through. `card_bearing_kinds_match_the_renderer` derives this set from those
/// two TypeScript sources and fails when they drift.
pub const CARD_BEARING_KINDS: [u16; 9] =
    [9, 40002, 40099, 43001, 43002, 43003, 43004, 43005, 43006];

// The local `u16` constants must never drift from the relay's kind registry.
const _: () = assert!(
    KIND_WORKFLOW_APPROVAL_REQUESTED as u32
        == ambush_core_pkg::kind::KIND_WORKFLOW_APPROVAL_REQUESTED
);
const _: () = assert!(KIND_STREAM_MESSAGE as u32 == ambush_core_pkg::kind::KIND_STREAM_MESSAGE);

/// Refuses kind 46010 outright and any [`CARD_BEARING_KINDS`] event whose line 0
/// is exactly a `<!-- swarm:<slug>:v<N> -->` marker (line 0 is `trim_end`ed,
/// never `trim_start`ed, matching the renderer's whole-line rule).
///
/// The kind set is the renderer's, not a single kind: correctness must not
/// depend on every command naming the one kind that carries cards.
///
/// Call it with the exact string that will be signed: a site that trims its
/// content before building the event must gate the trimmed string, or a
/// leading space would slip a marker past the check.
pub fn perch_sign_gate(kind: u16, content: &str) -> Result<(), String> {
    if kind == KIND_WORKFLOW_APPROVAL_REQUESTED {
        return Err("restricted: kind 46010 is published by the swarm bridge only".to_string());
    }
    if CARD_BEARING_KINDS.contains(&kind) {
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
            perch_sign_gate(48100, "<!-- swarm:verdict:v1 -->").is_ok(),
            "kind 48100 has its own MessageRow case and never reaches the card seam"
        );
    }

    #[test]
    fn every_card_bearing_kind_is_gated_not_only_kind_9() {
        for kind in CARD_BEARING_KINDS {
            assert!(
                perch_sign_gate(kind, "<!-- swarm:verdict:v1 -->\nhold h_a07aeacf granted")
                    .is_err(),
                "kind {kind} reaches the card seam and must refuse a swarm marker"
            );
        }
        // The two kinds MessageRow renders itself never reach `MessageBody`.
        for kind in [40008u16, 48100] {
            assert!(
                perch_sign_gate(kind, "<!-- swarm:verdict:v1 -->").is_ok(),
                "kind {kind} has a dedicated MessageRow case"
            );
        }
    }

    /// INV-29 is only as wide as the renderer. Derive the seam's kind set from
    /// the two TypeScript sources that define it and require the Rust constant
    /// to equal it, so adding a kind to `isTimelineContentEvent` (or removing a
    /// `MessageRow` case) fails here instead of silently opening the gate.
    #[test]
    fn card_bearing_kinds_match_the_renderer() {
        use std::{collections::BTreeSet, fs, path::Path};

        let desktop = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap_or_else(|| panic!("src-tauri must have a parent"));
        let read = |relative: &str| -> String {
            let path = desktop.join(relative);
            fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
        };

        let kinds_ts = read("src/shared/constants/kinds.ts");
        let numbers: std::collections::BTreeMap<String, u16> = kinds_ts
            .lines()
            .filter_map(|line| {
                let rest = line.trim().strip_prefix("export const ")?;
                let (name, value) = rest.split_once(" = ")?;
                let number = value.trim_end_matches(';').trim().parse::<u16>().ok()?;
                Some((name.to_string(), number))
            })
            .collect();
        assert!(
            numbers.len() > 20,
            "kinds.ts parse looks broken: {} constants",
            numbers.len()
        );

        let timeline_src = read("src/features/messages/lib/formatTimelineMessages.ts");
        let body = timeline_src
            .split_once("export function isTimelineContentEvent")
            .and_then(|(_, rest)| rest.split_once("\n}"))
            .map(|(body, _)| body.to_string())
            .unwrap_or_else(|| panic!("isTimelineContentEvent not found"));
        let timeline: BTreeSet<String> = body
            .split("event.kind === ")
            .skip(1)
            .filter_map(|chunk| {
                let name: String = chunk
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                (!name.is_empty()).then_some(name)
            })
            .collect();
        assert_eq!(
            timeline.len(),
            11,
            "isTimelineContentEvent shape changed: {timeline:?}"
        );

        let row_src = read("src/features/messages/ui/MessageRow.tsx");
        // `renderBody`'s switch runs from its declaration to the `default:` arm
        // that falls through to `MessageBody`; every `case` before it is a kind
        // the row renders itself.
        let render_body = row_src
            .split_once("const renderBody")
            .and_then(|(_, rest)| rest.split_once("default:"))
            .map(|(body, _)| body.to_string())
            .unwrap_or_else(|| panic!("renderBody switch not found in MessageRow.tsx"));
        let handled: BTreeSet<String> = render_body
            .split("case ")
            .skip(1)
            .filter_map(|chunk| {
                let name: String = chunk
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                (!name.is_empty()).then_some(name)
            })
            .collect();
        assert!(
            !handled.is_empty(),
            "renderBody parse found no dedicated cases"
        );

        let expected: BTreeSet<u16> = timeline
            .difference(&handled)
            .map(|name| {
                *numbers
                    .get(name)
                    .unwrap_or_else(|| panic!("{name} has no number in kinds.ts"))
            })
            .collect();
        let declared: BTreeSet<u16> = CARD_BEARING_KINDS.into_iter().collect();
        assert_eq!(
            declared, expected,
            "CARD_BEARING_KINDS must equal the kinds that reach MessageBody"
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
