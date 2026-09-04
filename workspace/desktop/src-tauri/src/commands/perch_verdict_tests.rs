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
///
/// Written over EVERY kind the gate acts on rather than over kind 9 alone, so
/// it stays correct — and gets stronger on its own — when the gate widens from
/// the one chat kind to every card-bearing kind that reaches the renderer's
/// seam. Nothing here names a kind, so that widening needs no edit in this file.
///
/// A DIFFERENT swarm marker is the detector. Asking "does this kind refuse the
/// marker this command publishes" and then asserting exactly that would be a
/// test of its own premise; asking "does this kind refuse some OTHER swarm
/// marker" is independent, and it is what catches a gate with a hole for
/// precisely this command's line 0.
#[test]
fn the_generic_signer_refuses_what_this_command_publishes_on_every_kind_it_gates() {
    use crate::perch_sign_gate::perch_sign_gate;
    let published = format!("{}\nx", CardKind::Verdict.marker());
    let detector = format!("{}\nx", CardKind::Hold.marker());
    let mut gated: Vec<u16> = Vec::new();
    for kind in u16::MIN..=u16::MAX {
        if perch_sign_gate(kind, &detector).is_ok() {
            continue;
        }
        gated.push(kind);
        assert!(
            perch_sign_gate(kind, &published).is_err(),
            "kind {kind} refuses a swarm marker but admits the line 0 perch_record_verdict publishes"
        );
    }
    // Two today: the chat kind, whose refusal is content-gated, and the hold
    // notice, refused outright. A vacuous loop would pass silently, so the
    // floor is asserted rather than assumed.
    assert!(
        gated.len() >= 2,
        "the gate acted on {} kind(s); the probe is broken",
        gated.len()
    );
    // And the marker this file names is the one the card actually carries, so
    // the assertions above cannot drift away from the published body.
    assert_eq!(
        CardKind::Verdict.marker(),
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

// ===========================================================================
// The case-channel gate
// ===========================================================================

fn proof(kind: u16, tags: &[[&str; 2]]) -> ChannelProof {
    ChannelProof {
        kind,
        tags: tags
            .iter()
            .map(|t| t.iter().map(|s| (*s).to_string()).collect())
            .collect(),
    }
}

const CASE: &str = "27799e23-ab25-4659-b381-3de47ea7ca4d";
const ME: &str = "e5ebc6cdb579be112e336cc319b5989b4bb6af11786ea90dbe52b5f08d741b34";
const SOMEBODY_ELSE: &str = "953d3363262e86b770419834c53d2446409db6d918a57f8f339d495d54ab001f";

/// Both filters name their kinds explicitly. An omitted `kinds` trips the
/// relay's p-gate with a 403, so a probe without one never answers at all and
/// this command would time out on every case.
#[test]
fn the_case_channel_probe_names_both_kinds_and_scopes_the_membership_to_me() {
    let filters = case_channel_filters(CASE, ME);
    assert_eq!(filters.len(), 2);
    assert_eq!(filters[0]["kinds"], serde_json::json!([39000]));
    assert_eq!(filters[0]["#d"], serde_json::json!([CASE]));
    assert!(filters[0].get("#p").is_none());
    assert_eq!(filters[1]["kinds"], serde_json::json!([39002]));
    assert_eq!(filters[1]["#d"], serde_json::json!([CASE]));
    assert_eq!(filters[1]["#p"], serde_json::json!([ME]));
}

/// The rule is re-checked over the returned events, not inferred from having
/// asked. A relay that ignored `#p` — or answered a different channel's
/// membership — would otherwise let this command publish a decision into a
/// case the operator is not in.
#[test]
fn visibility_needs_the_metadata_and_this_operators_own_membership() {
    let metadata = proof(39000, &[["d", CASE]]);
    let mine = proof(39002, &[["d", CASE], ["p", ME]]);
    let theirs = proof(39002, &[["d", CASE], ["p", SOMEBODY_ELSE]]);
    let other_case = proof(39002, &[["d", "not-this-case"], ["p", ME]]);

    assert!(case_channel_is_visible(
        &[
            proof(39000, &[["d", CASE]]),
            proof(39002, &[["d", CASE], ["p", SOMEBODY_ELSE], ["p", ME]]),
        ],
        CASE,
        ME
    ));
    assert!(
        !case_channel_is_visible(&[], CASE, ME),
        "nothing is not proof"
    );
    assert!(
        !case_channel_is_visible(&[proof(39000, &[["d", CASE]])], CASE, ME),
        "a channel this operator is not in is not a channel to publish into"
    );
    assert!(
        !case_channel_is_visible(&[mine], CASE, ME),
        "membership without metadata is a half-created channel"
    );
    assert!(
        !case_channel_is_visible(&[proof(39000, &[["d", CASE]]), theirs], CASE, ME),
        "somebody else's membership is not this operator's"
    );
    assert!(
        !case_channel_is_visible(&[metadata, other_case], CASE, ME),
        "a membership in another channel proves nothing about this one"
    );
    assert!(
        !case_channel_is_visible(
            &[
                proof(9, &[["d", CASE]]),
                proof(9, &[["d", CASE], ["p", ME]])
            ],
            CASE,
            ME
        ),
        "the kinds are load-bearing; a kind:9 saying so is not the relay saying so"
    );
}

/// The wait ends the moment both halves are visible, and not a tick later.
#[tokio::test(start_paused = true)]
async fn the_wait_returns_as_soon_as_the_channel_appears() {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = calls.clone();
    let started = tokio::time::Instant::now();
    let result = await_case_channel(move || {
        let seen = seen.clone();
        async move {
            let n = seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(n >= 2)
        }
    })
    .await;
    assert!(result.is_ok());
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert_eq!(started.elapsed(), std::time::Duration::from_millis(200));
}

/// Exhaustion refuses with a prefix the console can key on, and the wait is
/// bounded at five seconds of 100 ms probes.
#[tokio::test(start_paused = true)]
async fn an_exhausted_wait_refuses_with_the_stable_prefix() {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = calls.clone();
    let started = tokio::time::Instant::now();
    let error = await_case_channel(move || {
        let seen = seen.clone();
        async move {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(false)
        }
    })
    .await
    .expect_err("a channel that never appears must refuse");
    assert!(
        error.starts_with(CASE_CHANNEL_PENDING_PREFIX),
        "the console keys retry on this prefix: {error}"
    );
    assert_eq!(started.elapsed(), CASE_CHANNEL_WAIT);
    // t = 0, 100, ..., 5000: fifty sleeps, fifty-one probes.
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 51);
}

/// Nothing is spawned, so dropping the future stops the polling. A command
/// the webview abandoned must not keep asking the relay for five seconds.
#[tokio::test(start_paused = true)]
async fn dropping_the_wait_stops_the_polling() {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = calls.clone();
    let cancelled = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        await_case_channel(move || {
            let seen = seen.clone();
            async move {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(false)
            }
        }),
    )
    .await;
    assert!(cancelled.is_err(), "the outer timeout drops the wait");
    let at_drop = calls.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(at_drop, 3, "probes at t = 0, 100 and 200 ms");
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        at_drop,
        "a dropped wait polls nothing"
    );
}

/// A relay this command cannot read is a fault to surface now, not a reason
/// to keep asking for five seconds and then report a different problem.
#[tokio::test(start_paused = true)]
async fn a_probe_error_ends_the_wait_at_once() {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = calls.clone();
    let error = await_case_channel(move || {
        let seen = seen.clone();
        async move {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err::<bool, String>("relay query failed: 503".to_string())
        }
    })
    .await
    .expect_err("the probe's error is the command's error");
    assert_eq!(error, "relay query failed: 503");
    assert!(!error.starts_with(CASE_CHANNEL_PENDING_PREFIX));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// The verdict signature must actually verify, not merely be present.
///
/// `swarm_crypto::verify_detached_signature` refuses any `key_id` that is not
/// `sha256(public_key_hex)`. This command set `key_id` to the operator's id, so
/// every verdict card it produced carried a signature that verified nowhere.
/// Nothing caught it because the finding-feedback route records
/// `operator-bearer:{operator_id}` and never checks the signature — only the
/// hold decide route and tier-2 verification do, and neither existed yet.
///
/// The desktop crate cannot depend on `swarm-crypto` (W3-27 keeps the Tauri
/// process off every engine crate but the wire one), so this reproduces the
/// verifier's two rules with the crates the console already has: the key_id
/// hash, then the Ed25519 signature over the same preimage.
#[test]
fn the_verdict_signature_verifies_under_the_daemon_s_own_rule() {
    use ed25519_dalek::{Signature, Verifier as _};

    let key = SigningKey::from_bytes(&[7u8; 32]);
    let preimage = verdict_preimage(1_700_000_000_000, "dismiss", "f-1", Some("noise"));
    assert!(!preimage.is_empty());

    // THE PRODUCTION CONSTRUCTION, not a copy of it. Rebuilding the struct here
    // would assert the rule while passing over a command that breaks it — which
    // is exactly what the first version of this test did.
    let signature = sign_verdict(&key, &preimage);

    // Rule 1, the one that was wrong: the id names the key, not the operator.
    assert_eq!(
        signature.key_id,
        sha256_hex(signature.public_key_hex.as_bytes()),
        "key_id must be sha256(public_key_hex); an operator id verifies nowhere"
    );

    // Rule 2: the signature is over the preimage under that key.
    let bytes: [u8; 64] = hex::decode(&signature.signature_hex)
        .unwrap_or_else(|error| panic!("signature hex: {error}"))
        .try_into()
        .unwrap_or_else(|_| panic!("an ed25519 signature is 64 bytes"));
    key.verifying_key()
        .verify(&preimage, &Signature::from_bytes(&bytes))
        .unwrap_or_else(|error| panic!("the signature must verify: {error}"));

    // And the operator id specifically is NOT a valid key_id, which is what the
    // regression was.
    assert_ne!(
        signature.key_id, "local-operator",
        "the operator id must never be used as a key_id"
    );
}
