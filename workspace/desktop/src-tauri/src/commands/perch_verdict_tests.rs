use super::*;

/// The console half of the relay-publish invariant. The operator's own key
/// publishes exactly one kind and exactly one marker; widening either needs an
/// argument, not an edit.
#[test]
fn the_operator_key_publishes_exactly_one_kind_and_one_marker() {
    assert_eq!(PERCH_RELAY_PUBLISHED_KINDS, [9]);
    assert_eq!(PERCH_RELAY_PUBLISHED_MARKERS, ["swarm:verdict:v1"]);
}

/// The generic signer must refuse the exact line 0 this command publishes, or
/// the two are not describing one rule. A marker the gate lets through is a
/// marker the renderer could have signed itself.
#[test]
fn the_generic_signer_refuses_what_this_command_publishes() {
    assert!(crate::perch_sign_gate::perch_sign_gate(9, "<!-- swarm:verdict:v1 -->\nx").is_err());
    // And the marker this file names is the one the card actually carries, so
    // the assertion above cannot drift away from the published body.
    assert_eq!(
        swarm_perch_wire::marker::CardKind::Verdict.marker(),
        format!("<!-- {} -->", PERCH_RELAY_PUBLISHED_MARKERS[0])
    );
}

/// The command reads the relay and the identities endpoint; it POSTs nothing
/// to the daemon. Asserted rather than assumed, because the two tables are in
/// two files.
#[test]
fn this_files_daemon_reads_are_not_writes() {
    assert!(!crate::perch::daemon_client::PERCH_DAEMON_WRITES
        .iter()
        .any(|(_, p)| p.contains("verdict")));
}

/// Four members, key-sorted, with the rationale bound by its digest and never
/// by its text. The empty-string digest stands in for an absent rationale, so
/// a verifier can rebuild the preimage from the card body alone.
#[test]
fn the_preimage_is_rfc_8785_canonical_with_four_members() {
    let empty_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(
        String::from_utf8(verdict_preimage(1_773_738_979_000, "dismiss", "f2c9a1b4", None))
            .expect("utf-8"),
        format!(
            "{{\"decided_at_ms\":1773738979000,\"decision\":\"dismiss\",\"finding_id\":\"f2c9a1b4\",\"rationale_sha256\":\"{empty_sha}\"}}"
        )
    );
    let with =
        String::from_utf8(verdict_preimage(1, "confirm", "f", Some("backup job"))).expect("utf-8");
    assert!(with.contains("\"rationale_sha256\":\"") && !with.contains("backup job"));
}

/// The three verbs are the finding vocabulary, not the hold vocabulary. A
/// `grant` here would be a decision on a held action written where a decision
/// on a detection belongs, and the two go to different daemon routes.
#[test]
fn the_finding_verbs_are_the_three_b3_words() {
    for (word, spelling) in [
        (FindingVerdictWord::Confirm, "confirm"),
        (FindingVerdictWord::Dismiss, "dismiss"),
        (FindingVerdictWord::Investigate, "investigate"),
    ] {
        assert_eq!(word.as_str(), spelling);
        assert_eq!(
            serde_json::to_value(word).expect("serializes"),
            serde_json::Value::String(spelling.to_string())
        );
        assert_eq!(
            serde_json::from_str::<FindingVerdictWord>(&format!("\"{spelling}\""))
                .expect("round trip"),
            word
        );
    }
    assert!(serde_json::from_str::<FindingVerdictWord>("\"grant\"").is_err());
}

/// The tags this command publishes: `h`, `t`, `l` and `k`, and never `p` or
/// `e`. An `e` would point at the finding card in another channel and let the
/// relay's thread resolver mutate a lane card's reply count from a case
/// (D-FC-3); a `p` is refused outright for a card.
#[test]
fn the_verdict_card_tags_carry_no_e_and_no_p() {
    let tags = swarm_perch_wire::tags::TagSet::card(
        swarm_perch_wire::marker::CardKind::Verdict,
        "27799e23-ab25-4659-b381-3de47ea7ca4d",
        None,
        None,
    );
    tags.assert_publishable(swarm_perch_wire::KIND_CARD)
        .expect("a card with h and k is publishable");
    let names: Vec<String> = tags.to_tags().into_iter().map(|t| t[0].clone()).collect();
    assert!(names.contains(&"h".to_string()));
    assert!(names.contains(&"k".to_string()));
    assert!(!names.contains(&"e".to_string()));
    assert!(!names.contains(&"p".to_string()));
}
