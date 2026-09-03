#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The seven human fallback lines, pinned against the golden vectors.
//!
//! The grammars are `13-WIRE-SCHEMAS.md` §7.1. The line is THE DEGRADATION
//! CONTRACT: it is what the Flutter app renders, what an FTS snippet shows, and
//! what `ambush --format compact messages thread` returns, so it must carry the
//! identifiers a human needs to go find the real thing with no tags and no kind.

use serde_json::Value;
use swarm_perch_wire::cards::Card;

fn fact(stem: &str) -> Value {
    let raw = std::fs::read_to_string(format!("{}/golden/{stem}.json", env!("CARGO_MANIFEST_DIR")))
        .unwrap();
    serde_json::from_str::<Value>(&raw).unwrap()["fact"].clone()
}

fn line(stem: &str) -> String {
    let card: Card = serde_json::from_value(fact(stem)).unwrap();
    card.human_line()
}

#[test]
fn the_finding_human_line_follows_the_section_7_1_grammar() {
    let card: Card = serde_json::from_value(fact("card-swarm-finding-v1")).unwrap();
    assert_eq!(
        card.human_line(),
        "whisker-7a3f · data_exfiltration · HIGH · confidence 0.82 · host web-04 · finding f2c9a1b4"
    );
}

#[test]
fn every_card_has_a_one_line_human_fallback() {
    for stem in [
        "card-swarm-finding-v1",
        "card-swarm-escalation-v1",
        "card-swarm-hold-v1",
        "card-swarm-verdict-v1",
        "card-swarm-receipt-v1",
        "card-swarm-lease-v1",
        "card-swarm-rollback-v1",
    ] {
        let card: Card = serde_json::from_value(fact(stem)).unwrap();
        let line = card.human_line();
        assert!(!line.is_empty() && !line.contains('\n'), "{stem}: {line:?}");
        assert!(
            line.contains(" · "),
            "{stem}: fields are separated by U+00B7: {line:?}"
        );
    }
}

#[test]
fn the_escalation_line_names_the_unresolved_agent_half() {
    // §7.2.1: the `M agents` half has no Phase-1 data source, and the line says
    // so rather than fabricating a number. The level is SCREAMING_SNAKE; the
    // strength carries two decimals and the word.
    assert_eq!(
        line("card-swarm-escalation-v1"),
        "execution · ALERT · strength 2.70 · 2 sources / agents not yet resolved · mode alert"
    );
}

#[test]
fn the_hold_line_says_when_the_scope_is_unresolved() {
    // The golden hold has `rehearsal: null`, so the blast-radius slot cannot be
    // filled and the line says so. `expires` is RFC 3339 at second precision.
    assert_eq!(
        line("card-swarm-hold-v1"),
        "hold h_a07aeacf · isolate_host · CRITICAL · scope unresolved · expires 2026-03-17T10:14:42Z"
    );
}

#[test]
fn the_verdict_line_leads_with_the_operators_verb() {
    assert_eq!(
        line("card-swarm-verdict-v1"),
        "grant · hold h_a07aeacf · by perch-operator-1 · 2026-03-17T09:16:19Z"
    );
    assert_eq!(
        line("card-swarm-verdict-v1-superseded"),
        "grant · hold h_a07aeacf · by perch-operator-2 · 2026-03-17T09:16:19Z"
    );
}

#[test]
fn the_receipt_line_reads_the_success_arm_beside_its_tag() {
    assert_eq!(
        line("card-swarm-receipt-v1"),
        "receipt resp-contain:tel-8831:lease:web-04 · isolate_host · executed · enforced · trail trail-4411"
    );
}

#[test]
fn the_lease_line_carries_both_instants_and_the_origin_receipt() {
    assert_eq!(
        line("card-swarm-lease-v1"),
        "containment lease cl_51aa · isolate_host · issued 2026-08-26T14:37:11Z · expires 2026-08-26T14:52:11Z · origin receipt resp-contain:tel-8831:lease:web-04"
    );
}

#[test]
fn the_rollback_line_counts_reversed_steps_over_all_steps() {
    // Voice law L5: `{k} of {n} steps reversed`, never a bare `{k} reversed`.
    assert_eq!(
        line("card-swarm-rollback-v1"),
        "rollback rb_9c02 · containment lease cl_51aa · expiry · executed · 1 of 1 steps reversed"
    );
}

#[test]
fn a_receipt_with_no_response_receipt_says_none_rather_than_inventing_one() {
    let mut fact = fact("card-swarm-receipt-v1");
    fact["locator"]["receipt_id"] = Value::Null;
    fact["audit_trail"]["response"] = serde_json::json!({ "kind": "skipped", "reason": "dry run" });
    let card: Card = serde_json::from_value(fact).unwrap();
    assert_eq!(
        card.human_line(),
        "receipt none · none · skipped · none · trail trail-4411"
    );
}

#[test]
fn a_finding_with_no_host_says_unknown() {
    let mut fact = fact("card-swarm-finding-v1");
    fact["locator"]["host_id"] = Value::Null;
    let card: Card = serde_json::from_value(fact).unwrap();
    assert!(card.human_line().contains(" · host unknown · "));
}
