#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The W3-27 differential control.
//!
//! `swarm-perch-wire` depends on no `swarm-*` crate, so its RFC 8785 canonical bytes and its
//! keyless `envelope_hash` are a second implementation of the engine's spine envelope
//! (`swarm_spine::envelope`). The bridge signs with the engine's implementation while the desktop
//! verifies the wire crate's bytes independently, so the two must agree byte for byte on every
//! golden envelope and on the JCS edge vectors the engine's own canonicalizer is pinned to.

use serde_json::Value;

const GOLDEN_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../swarm-perch-wire/golden");

fn golden_card_envelopes() -> Vec<(String, Value)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(GOLDEN_DIR).expect("golden dir") {
        let path = entry.expect("entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        if !name.starts_with("card-") || !name.ends_with(".json") {
            continue;
        }
        let value: Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("json");
        out.push((name, value));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn without_hash_and_signature(envelope: &Value) -> Value {
    let Value::Object(map) = envelope else {
        panic!("a card golden is a JSON object");
    };
    let mut unsigned = map.clone();
    unsigned.remove("envelope_hash");
    unsigned.remove("signature");
    Value::Object(unsigned)
}

#[test]
fn every_golden_envelope_canonicalizes_identically_in_both_implementations() {
    let goldens = golden_card_envelopes();
    assert_eq!(
        goldens.len(),
        9,
        "nine card vectors: the seven card kinds, plus the superseded verdict and the \
         finding-subject verdict that D-FC-3 added as distinct vectors of the same kind"
    );
    for (name, envelope) in goldens {
        let unsigned = without_hash_and_signature(&envelope);
        let wire = swarm_perch_wire::envelope::canonical_bytes(&unsigned).expect("wire canonical");
        let spine =
            swarm_spine::envelope::envelope_signing_bytes(&unsigned).expect("spine canonical");
        assert_eq!(wire, spine, "{name}: canonical bytes differ");

        let wire_hash =
            swarm_perch_wire::envelope::compute_envelope_hash_hex(&envelope).expect("wire hash");
        let spine_hash =
            swarm_spine::envelope::compute_envelope_hash_hex(&unsigned).expect("spine hash");
        assert_eq!(wire_hash, spine_hash, "{name}: envelope hashes differ");
        assert!(
            wire_hash.starts_with("0x") && wire_hash.len() == 66,
            "{name}: {wire_hash}"
        );

        // The typed decoder agrees with the raw computation on the same bytes.
        let typed: swarm_perch_wire::CardEnvelope =
            serde_json::from_value(envelope.clone()).expect("typed");
        let recomputed = serde_json::to_value(&typed).expect("value");
        assert_eq!(
            swarm_perch_wire::envelope::compute_envelope_hash_hex(&recomputed).expect("typed hash"),
            spine_hash,
            "{name}: the typed envelope re-serializes to different canonical bytes"
        );
        // The vectors pin a placeholder hash; a vector that carries a real hash must verify.
        if typed.envelope_hash
            != "0xabababababababababababababababababababababababababababababababab"
        {
            assert!(
                typed.hash_matches().expect("hashes"),
                "{name}: pinned hash does not verify"
            );
        }
    }
}

#[test]
fn the_jcs_edge_vectors_agree_between_the_wire_crate_and_the_spine() {
    // RFC 8785 appendix vectors, as vendored by `swarm-crypto/src/canonical.rs`'s tests:
    // number formatting, unicode and control escapes, escape shortcuts, and numeric string keys.
    let vectors: Vec<(&str, Value, &str)> = vec![
        (
            "numbers",
            serde_json::json!({"a": 1.0, "b": 0.0, "c": -0.0, "d": 1e21, "e": 1e20, "f": 1e-6, "g": 1e-7}),
            r#"{"a":1,"b":0,"c":0,"d":1e+21,"e":100000000000000000000,"f":0.000001,"g":1e-7}"#,
        ),
        (
            "unicode and controls",
            serde_json::json!({"s": "e", "u2028": "\u{2028}", "u2029": "\u{2029}", "emoji": "X", "nl": "\n", "tab": "\t"}),
            "{\"emoji\":\"X\",\"nl\":\"\\n\",\"s\":\"e\",\"tab\":\"\\t\",\"u2028\":\"\u{2028}\",\"u2029\":\"\u{2029}\"}",
        ),
        (
            "escape shortcuts",
            serde_json::json!({"b": "\u{0008}", "f": "\u{000c}", "ctl": "\u{000f}", "quote": "\"", "backslash": "\\"}),
            r#"{"b":"\b","backslash":"\\","ctl":"\u000f","f":"\f","quote":"\""}"#,
        ),
        (
            "numeric string keys",
            serde_json::json!({"2": "b", "10": "a", "a": 0}),
            r#"{"10":"a","2":"b","a":0}"#,
        ),
        (
            "utf-16 code unit key order",
            serde_json::json!({"\u{1F41D}": 1, "\u{FF5E}": 2, "a": 3}),
            "{\"a\":3,\"\u{1F41D}\":1,\"\u{FF5E}\":2}",
        ),
    ];
    for (name, value, expected) in vectors {
        let wire = swarm_perch_wire::envelope::canonical_bytes(&value).expect("wire");
        let spine = swarm_spine::envelope::envelope_signing_bytes(&value).expect("spine");
        assert_eq!(wire, spine, "{name}: implementations disagree");
        assert_eq!(String::from_utf8(wire).expect("utf8"), expected, "{name}");
    }
}
