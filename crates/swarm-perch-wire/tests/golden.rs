//! Golden-vector tests. THIS IS THE SYNC MECHANISM.
//!
//! There is no codegen step in either repository and this crate does not add
//! one. Instead, one directory of golden vectors is the contract, and BOTH
//! language bindings are asserted against it:
//!
//! - Rust, here, with `include_str!` — no filesystem access at test time, so the
//!   vectors are compiled in and a missing file is a build error.
//! - TypeScript, in `workspace/desktop/src/features/perch/wire/golden.test.mjs`,
//!   run by `pnpm test` (`node --import ./test-loader.mjs
//!   --experimental-strip-types --test "src/**/*.test.mjs"`), which is
//!   `just desktop-test` and one of lefthook's pre-push groups.
//!
//! Neither suite can pass while the other's parse of the same bytes differs.
//! `tools/sync-perch-golden.sh` mirrors the directory into the desktop tree and
//! re-pins both suites from one computation, so drift makes both suites go red
//! in the same commit rather than one of them silently.
//!
//! What this catches that a schema alone does not: serde's shape. Three of the
//! types on this wire are internally tagged in ways a hand-written TypeScript
//! type gets wrong on the first try —
//! `ResponseAction` is `#[serde(tag = "type")]` so
//! `{"type":"isolate_host","host_id":"web-04"}` and not
//! `{"isolate_host":{...}}`; `AuditResponseRecord` is `#[serde(tag = "kind")]`
//! over two NEWTYPE variants, so a success arm is
//! `{"kind":"success","receipt_id":...}` with `ResponseReceipt`'s seven fields
//! flattened beside the tag; and `ThreatClass` is EXTERNALLY tagged with a
//! `Custom(String)` variant, so it is `"lateral_movement"` for the twelve and
//! `{"custom":"..."}` for the thirteenth.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::Value;
use swarm_perch_wire::cards::Card;
use swarm_perch_wire::envelope::CardEnvelope;
use swarm_perch_wire::frames::{Frame, FrameKind};

macro_rules! vector {
    ($name:literal) => {
        ($name, include_str!(concat!("../golden/", $name, ".json")))
    };
}

/// Every golden vector, by file stem.
const VECTORS: &[(&str, &str)] = &[
    vector!("card-swarm-finding-v1"),
    vector!("card-swarm-escalation-v1"),
    vector!("card-swarm-hold-v1"),
    vector!("card-swarm-verdict-v1"),
    vector!("card-swarm-verdict-v1-superseded"),
    vector!("card-swarm-verdict-v1-finding"),
    vector!("card-swarm-receipt-v1"),
    vector!("card-swarm-lease-v1"),
    vector!("card-swarm-rollback-v1"),
    vector!("event-46010-hold-notice"),
    vector!("frame-26000-ingest-rate"),
    vector!("frame-26001-concentration"),
    vector!("frame-26002-agent-health"),
    vector!("frame-26003-mode-transition"),
    vector!("frame-26004-governance-status"),
    vector!("frame-26005-tamper-alert"),
    vector!("frame-26006-hold-alarm"),
];

#[test]
fn every_vector_parses() {
    for (name, raw) in VECTORS {
        serde_json::from_str::<Value>(raw)
            .unwrap_or_else(|e| panic!("{name} is not valid JSON: {e}"));
    }
}

#[test]
fn the_registry_is_seven_cards_one_stored_kind_and_seven_frames() {
    // Nine card VECTORS, seven card TYPES: `swarm:verdict:v1` has three -- the
    // hold grant, the losing console's `superseded` update card, and the
    // finding-subject verdict D-FC-3 added. Counting distinct `fact.schema`
    // values is what keeps this honest.
    let mut schemas: Vec<String> = VECTORS
        .iter()
        .filter(|(n, _)| n.starts_with("card-"))
        .map(|(_, raw)| {
            serde_json::from_str::<Value>(raw).unwrap()["fact"]["schema"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    schemas.sort();
    schemas.dedup();
    let frames = VECTORS
        .iter()
        .filter(|(n, _)| n.starts_with("frame-"))
        .count();
    let stored = VECTORS
        .iter()
        .filter(|(n, _)| n.starts_with("event-"))
        .count();
    assert_eq!((schemas.len(), stored, frames), (7, 1, 7));
}

/// The pin. Both suites assert it; drift makes both go red in the same commit.
///
/// This constant was CLAIMED by `13-WIRE-SCHEMAS.md` §0 before it existed in any
/// committed file — the hash had been computed by hand and quoted as a test
/// result. It is a test now. Re-pin with `tools/sync-perch-golden.sh`, never by
/// hand: the vectors are extracted from the schemas' own `examples`, so editing a
/// vector to match a hash inverts the whole mechanism.
const GOLDEN_SHA256: &str = "5a189116479f2c0a73b27ee5a9effc73554375c22d83cc76594f5bd06aeaec82";

#[test]
fn the_golden_corpus_matches_its_pinned_hash() {
    use sha2::{Digest, Sha256};
    // Sorted by FILE NAME in byte order, exactly as `tools/sync-perch-golden.sh`
    // (`LC_ALL=C sort` over `*.json`) and `golden.test.mjs` (`readdirSync().sort()`)
    // do. Sorting the bare stems would put `card-swarm-verdict-v1` before
    // `card-swarm-verdict-v1-superseded`, while the file names sort the other way
    // round (`-` is 0x2D, `.` is 0x2E) -- and the three pins would never agree.
    let mut names: Vec<&str> = VECTORS.iter().map(|(n, _)| *n).collect();
    names.sort_unstable_by_key(|name| format!("{name}.json"));
    let mut hasher = Sha256::new();
    for name in &names {
        let raw = VECTORS.iter().find(|(n, _)| n == name).unwrap().1;
        hasher.update(raw.as_bytes());
    }
    assert_eq!(
        format!("{:x}", hasher.finalize()),
        GOLDEN_SHA256,
        "golden corpus drifted; re-run tools/sync-perch-golden.sh"
    );
}

#[test]
fn the_pin_file_agrees_with_the_constant() {
    // `GOLDEN.sha256` is what the sync script writes and what the desktop suite
    // reads; the constant is what this suite asserts. They are one computation.
    let pin = include_str!("../golden/GOLDEN.sha256");
    let first = pin.split_whitespace().next().expect("a hash");
    assert_eq!(
        first, GOLDEN_SHA256,
        "GOLDEN.sha256 and golden.rs pin different corpora"
    );
}

#[test]
fn no_card_stamps_an_agent_role_on_a_human() {
    // AgentRole::Tom is "Governance -- enforces policy, manages lifecycle"
    // (AMB crates/swarm-core/src/agent.rs:26-27): the VETO actor.
    // APPENDIX-NORMATIVE section 7 rules that governance's veto and the
    // operator's refuse are never conflated, and adr/0016 spends a document
    // keeping the two identity chains apart. A verdict vector previously carried
    // `role: "tom"` on an operator's own decision and the hash pinned it there.
    for (name, raw) in VECTORS {
        let v: Value = serde_json::from_str(raw).unwrap();
        let Some(fact) = v.get("fact") else { continue };
        if fact["schema"] == "swarm.perch.verdict.v1" {
            assert!(
                fact["issuer"]["role"].is_null(),
                "{name}: a human decision may not carry an AgentRole"
            );
        }
        // Nothing anywhere may claim tom produced a fact: the only tom-shaped
        // object in the registry is a governance RECEIPT, which is a nested
        // object with its own badge, never a fact issuer.
        assert_ne!(
            fact["issuer"]["role"], "tom",
            "{name}: `tom` is the governance/veto actor and never a fact issuer"
        );
    }
}

#[test]
fn the_escalation_vector_names_the_true_counting_unit() {
    // resolve_deposits writes agent_id: strategy_scoped_agent_id(...) onto every
    // deposit (AMB crates/swarm-runtime/src/detection/pipeline.rs:573) and
    // concentration_for counts those strings
    // (AMB crates/swarm-pheromone/src/substrate.rs:1295), over a base that is
    // already instance-scoped (whisker_agent.rs:148-149). The wrong const
    // `agent_instance_id` would have REJECTED a truthful bridge at admission.
    let raw = VECTORS
        .iter()
        .find(|(n, _)| *n == "card-swarm-escalation-v1")
        .unwrap()
        .1;
    let v: Value = serde_json::from_str(raw).unwrap();
    let esc = &v["fact"]["escalation"];
    assert_eq!(esc["distinct_sources_counts"], "strategy_scoped_agent_id");
    // And the absent half of render law 2 is a NAMED state, not a bare null.
    assert!(esc["source_ids"].is_null());
    assert_eq!(
        esc["source_ids_absent_reason"],
        "not_carried_by_runtime_event"
    );
}

#[test]
fn a_superseded_verdict_names_the_card_that_won() {
    let raw = VECTORS
        .iter()
        .find(|(n, _)| *n == "card-swarm-verdict-v1-superseded")
        .unwrap()
        .1;
    let v: Value = serde_json::from_str(raw).unwrap();
    let leg2 = &v["fact"]["leg2"];
    assert_eq!(leg2["state"], "superseded");
    assert_eq!(
        leg2["superseded_by"].as_str().map(str::len),
        Some(64),
        "a superseded card with no winner is a dead end for the reconciler"
    );
    assert!(leg2["superseded_at_ms"].is_i64());
}

#[test]
fn every_hold_id_is_an_opaque_token() {
    // Six formats were in circulation across the wave-2 artifact set; two used
    // the `hold:` colon prefix, which is the forbidden hunt-id-derived shape.
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                for (k, sub) in m {
                    if k == "hold_id"
                        && let Some(s) = sub.as_str()
                    {
                        out.push(s.to_string());
                    }
                    walk(sub, out);
                }
            }
            Value::Array(a) => a.iter().for_each(|sub| walk(sub, out)),
            _ => {}
        }
    }
    let mut seen = 0usize;
    for (name, raw) in VECTORS {
        let mut ids = Vec::new();
        walk(&serde_json::from_str::<Value>(raw).unwrap(), &mut ids);
        for id in ids {
            seen += 1;
            assert!(
                swarm_perch_wire::tags::is_opaque_hold_id(&id),
                "{name}: hold id `{id}` is not an opaque URL-safe token"
            );
        }
    }
    assert!(
        seen >= 4,
        "expected the hold path's vectors to carry hold ids"
    );
}

#[test]
fn every_card_vector_is_a_spine_envelope_with_no_signature() {
    // The envelope ships from day one; the signature does not. A vector that
    // grows a `signature` key is B6 landing, and it must land with a tier change
    // in the same commit.
    for (name, raw) in VECTORS.iter().filter(|(n, _)| n.starts_with("card-")) {
        let v: Value = serde_json::from_str(raw).expect("valid JSON");
        assert_eq!(
            v["schema"], "swarm.spine.envelope.v1",
            "{name} must be a spine envelope"
        );
        assert!(
            v["issuer"]
                .as_str()
                .expect("issuer is a string")
                .starts_with("swarm:ed25519:"),
            "{name}: verify_chain_link runs parse_issuer_pubkey_hex on this"
        );
        assert!(v["seq"].as_u64().expect("seq is a number") >= 1, "{name}");
        assert!(
            v.get("envelope_hash").is_some(),
            "{name}: keyless, so present"
        );
        assert!(
            v.get("signature").is_none(),
            "{name}: absent until B6, and its absence pins tier 0"
        );
        assert_eq!(v["capability_token"], Value::Null, "{name}");
    }
}

#[test]
fn every_card_facts_schema_matches_its_marker() {
    use swarm_perch_wire::CardKind;
    for kind in CardKind::ALL {
        let stem = format!("card-swarm-{}-v1", kind.slug());
        let (_, raw) = VECTORS
            .iter()
            .find(|(n, _)| *n == stem)
            .unwrap_or_else(|| panic!("no golden vector for {stem}"));
        let v: Value = serde_json::from_str(raw).expect("valid JSON");
        assert_eq!(v["fact"]["schema"], kind.fact_schema());
    }
}

#[test]
fn the_content_grammar_round_trips_for_every_card() {
    use swarm_perch_wire::CardKind;
    use swarm_perch_wire::marker::{build_content, parse_content};
    for kind in CardKind::ALL {
        let stem = format!("card-swarm-{}-v1", kind.slug());
        let (_, raw) = VECTORS.iter().find(|(n, _)| *n == stem).expect("vector");
        let compact: String =
            serde_json::to_string(&serde_json::from_str::<Value>(raw).expect("valid JSON"))
                .expect("re-serializes");

        let human = format!("{} · fixture", kind.slug());
        let body = build_content(kind, &human, &compact).expect("builds");

        // The marker is the WHOLE first line (INV-15).
        assert_eq!(body.lines().next(), Some(kind.marker()));
        // The human fallback is second, not last, because the desktop's search
        // preview slices the first 96 characters
        // (BUZZ desktop/src/features/search/lib/searchMatch.ts:169-200).
        assert_eq!(body.lines().nth(1), Some(human.as_str()));

        let parts = parse_content(&body).expect("parses");
        assert_eq!(parts.kind, kind);
        assert_eq!(parts.human_line, human);
        assert_eq!(
            serde_json::from_str::<Value>(parts.json).expect("json"),
            serde_json::from_str::<Value>(&compact).expect("json")
        );
    }
}

#[test]
fn the_hold_notice_carries_no_e_t_l_or_k_tag() {
    // RF-D1, and the four-tag contract in event-46010-hold-notice.schema.json.
    let (_, raw) = VECTORS
        .iter()
        .find(|(n, _)| *n == "event-46010-hold-notice")
        .expect("vector");
    let v: Value = serde_json::from_str(raw).expect("valid JSON");
    let names: Vec<&str> = v["tags"]
        .as_array()
        .expect("tags is an array")
        .iter()
        .map(|t| t[0].as_str().expect("tag name"))
        .collect();
    assert_eq!(names, vec!["h", "p", "hold", "card"]);
    for banned in ["e", "t", "l", "k"] {
        assert!(!names.contains(&banned), "46010 may not carry `{banned}`");
    }
}

#[test]
fn every_p_tag_is_64_lowercase_hex() {
    // insert_mentions drops anything else with a debug! and the publish still
    // returns OK (BUZZ crates/buzz-db/src/runtime/mod.rs:65-81, :943-948).
    use swarm_perch_wire::tags::is_relay_pubkey;
    let (_, raw) = VECTORS
        .iter()
        .find(|(n, _)| *n == "event-46010-hold-notice")
        .expect("vector");
    let v: Value = serde_json::from_str(raw).expect("valid JSON");
    for tag in v["tags"].as_array().expect("tags") {
        if tag[0] == "p" {
            assert!(is_relay_pubkey(tag[1].as_str().expect("value")));
        }
    }
}

#[test]
fn no_global_frame_carries_a_host_id_or_a_path() {
    // The aggregates-only rule, as a mechanical check over the frame vectors.
    // filter_fanout_by_access does not compartment a channel-less ephemeral
    // (BUZZ crates/buzz-relay/src/handlers/event.rs:177-179), so anything here
    // reaches every member of the community.
    const BANNED_KEYS: &[&str] = &[
        "host_id",
        "unexpected_library_loads",
        "details",
        "evidence",
        "finding_id",
        "event_id",
        "hunt_id",
        "correlation_id",
        "indicator",
    ];
    fn walk(v: &Value, path: &str, out: &mut Vec<String>) {
        match v {
            Value::Object(map) => {
                for (k, sub) in map {
                    if BANNED_KEYS.contains(&k.as_str()) {
                        out.push(format!("{path}.{k}"));
                    }
                    walk(sub, &format!("{path}.{k}"), out);
                }
            }
            Value::Array(items) => {
                for (i, sub) in items.iter().enumerate() {
                    walk(sub, &format!("{path}[{i}]"), out);
                }
            }
            _ => {}
        }
    }
    for (name, raw) in VECTORS.iter().filter(|(n, _)| n.starts_with("frame-")) {
        // 26006 carries case_channel and hold_id, both opaque, both allowed.
        let v: Value = serde_json::from_str(raw).expect("valid JSON");
        let mut hits = Vec::new();
        walk(&v, name, &mut hits);
        assert!(hits.is_empty(), "aggregates-only violated: {hits:?}");
    }
}

#[test]
fn every_card_vector_decodes_into_the_envelope_and_the_typed_card() {
    // The golden vectors are the contract; a wire DTO that cannot decode one of
    // them is wrong, whatever the schema says. `Card` is internally tagged on
    // `fact.schema`, so the fact decodes straight into the right variant.
    for (name, raw) in VECTORS.iter().filter(|(n, _)| n.starts_with("card-")) {
        let envelope: CardEnvelope =
            serde_json::from_str(raw).unwrap_or_else(|e| panic!("{name}: envelope: {e}"));
        assert!(envelope.is_tier_zero(), "{name}");
        let card: Card = serde_json::from_value(envelope.fact.clone())
            .unwrap_or_else(|e| panic!("{name}: fact: {e}"));
        assert_eq!(card.kind().fact_schema(), envelope.fact["schema"], "{name}");
        assert_eq!(
            card.emitted_at_ms(),
            envelope.fact["emitted_at_ms"]
                .as_i64()
                .expect("emitted_at_ms"),
            "{name}"
        );
        // Re-serializing and decoding again lands on the same value: nothing is
        // dropped on the way through the typed form.
        let again: Card = serde_json::from_value(serde_json::to_value(&card).expect("serializes"))
            .unwrap_or_else(|e| panic!("{name}: round trip: {e}"));
        assert_eq!(again, card, "{name}");
    }
}

#[test]
fn every_frame_vector_decodes_into_the_typed_frame() {
    for (name, raw) in VECTORS.iter().filter(|(n, _)| n.starts_with("frame-")) {
        let frame: Frame = serde_json::from_str(raw).unwrap_or_else(|e| panic!("{name}: {e}"));
        let v: Value = serde_json::from_str(raw).expect("valid JSON");
        let kind = frame.frame_kind();
        assert_eq!(
            u64::from(frame.header().kind),
            v["kind"].as_u64().expect("kind"),
            "{name}"
        );
        assert_eq!(
            u64::from(kind.kind()),
            v["kind"].as_u64().expect("kind"),
            "{name}"
        );
        assert_eq!(kind.schema(), v["schema"], "{name}");
        assert_eq!(
            FrameKind::from_kind(frame.header().kind),
            Some(kind),
            "{name}"
        );
        // The typed form serializes back to the vector minus its explicit nulls:
        // the DTO omits an absent optional (`tracer_pid`, `last_transition_at_ms`)
        // where the schema example spells it `null`, and both decode the same.
        let back = serde_json::to_value(&frame).expect("serializes");
        let mut expected = v.clone();
        if let Value::Object(map) = &mut expected {
            map.retain(|_, value| !value.is_null());
        }
        assert_eq!(back, expected, "{name}");
        let again: Frame = serde_json::from_value(back).expect("round trip");
        assert_eq!(again, frame, "{name}");
    }
}

#[test]
fn the_verdict_vectors_carry_an_operator_issuer_with_a_null_role() {
    // The typed decode refuses `role: "tom"` on a verdict with the same force
    // the schema does: `OperatorFactIssuer.role` is a unit type.
    let (_, raw) = VECTORS
        .iter()
        .find(|(n, _)| *n == "card-swarm-verdict-v1")
        .expect("vector");
    let mut v: Value = serde_json::from_str(raw).expect("valid JSON");
    assert!(serde_json::from_value::<Card>(v["fact"].clone()).is_ok());
    v["fact"]["issuer"]["role"] = Value::String("tom".into());
    assert!(serde_json::from_value::<Card>(v["fact"].clone()).is_err());
}

#[test]
fn the_verdict_subject_discriminator_is_on_the_wire() {
    // D-FC-3. One marker carries verdicts on two subjects because the registry
    // is closed at seven. The tag is a wire field, not an inference from which
    // keys happen to be present, so a reader never has to guess which join
    // keys a card carries -- and a hold-shaped body can never be read as a
    // finding verdict by accident.
    use swarm_perch_wire::cards::{VerdictDecision, VerdictLocator};
    for (name, expected) in [
        ("card-swarm-verdict-v1", "hold"),
        ("card-swarm-verdict-v1-superseded", "hold"),
        ("card-swarm-verdict-v1-finding", "finding"),
    ] {
        let raw = VECTORS.iter().find(|(n, _)| *n == name).unwrap().1;
        let v: Value = serde_json::from_str(raw).unwrap();
        assert_eq!(v["fact"]["locator"]["subject"], expected, "{name}");
        assert_eq!(v["fact"]["decision"]["subject"], expected, "{name}");
        let card: swarm_perch_wire::cards::VerdictCard =
            serde_json::from_value(v["fact"].clone()).unwrap();
        match (&card.locator, &card.decision) {
            (VerdictLocator::Hold { .. }, VerdictDecision::Hold { .. }) => {
                assert_eq!(expected, "hold")
            }
            (VerdictLocator::Finding { .. }, VerdictDecision::Finding { .. }) => {
                assert_eq!(expected, "finding");
            }
            _ => panic!("{name}: the locator and the decision disagree on their subject"),
        }
    }
}

#[test]
fn a_finding_verdict_carries_no_hold_id_and_joins_by_the_card_id() {
    // The `e` tag is deliberately absent (D-FC-3): the finding card lives in a
    // lane channel and the verdict in a case channel, so an `e` across
    // channels would let the relay's thread resolver mutate a lane card's
    // reply_count from a case. `locator.finding_card_id` in the SIGNED body is
    // the join instead, so nothing outside the signature carries it.
    let raw = VECTORS
        .iter()
        .find(|(n, _)| *n == "card-swarm-verdict-v1-finding")
        .unwrap()
        .1;
    let v: Value = serde_json::from_str(raw).unwrap();
    assert!(v["fact"]["locator"]["hold_id"].is_null());
    assert!(v["fact"]["decision"]["hold_id"].is_null());
    assert_eq!(
        v["fact"]["locator"]["finding_card_id"]
            .as_str()
            .map(str::len),
        Some(64)
    );
    assert_eq!(v["fact"]["decision"]["decision"], "dismiss");
}
