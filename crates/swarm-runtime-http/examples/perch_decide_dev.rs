//! Print a SIGNED hold-decision body, the way the console's leg 2 builds one.
//!
//! Development helper for the walking skeleton in `docs/PERCH-DEV.md`. It uses
//! the SHARED preimage function rather than a local copy, so what it signs is
//! what the daemon rebuilds and verifies. It prints the body and posts nothing:
//! piping it to `curl` keeps this example free of an HTTP dependency.
//!
//! ```sh
//! cargo run -p swarm-runtime-http --example perch_decide_dev -- <hold_id> refuse \
//!   | curl -sS -X POST "$DAEMON/v1/response/holds/<hold_id>/decide" \
//!       -H "Authorization: Bearer $SWARM_OPERATOR_TOKEN" \
//!       -H 'x-swarm-schema-version: 1' -H 'content-type: application/json' --data @-
//! ```
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let Some(hold_id) = args.get(1) else {
        return Err("usage: perch_decide_dev <hold_id> <grant|refuse> [rationale]".into());
    };
    let decision = args.get(2).map(String::as_str).unwrap_or("refuse");
    let rationale = args.get(3).cloned();

    let signer = swarm_crypto::Ed25519Signer::from_secret_material("ambush-perch-dev-operator-v1");
    let decided_at_ms = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?;

    let digest = swarm_perch_wire::verdict::rationale_sha256_hex(rationale.as_deref());
    let preimage = swarm_perch_wire::verdict::decision_preimage_bytes(
        decided_at_ms,
        decision,
        hold_id,
        digest.as_deref(),
    );
    // A 64-hex pointer standing in for the leg-1 card id. Leg 1 is the relay
    // write the console makes first; this helper exercises leg 2 alone, which
    // is why the id is derived rather than read off a published card.
    let intent = swarm_crypto::sha256_hex(format!("{hold_id}:{decided_at_ms}").as_bytes());

    let body = serde_json::json!({
        "decision": decision,
        "decided_at_ms": decided_at_ms,
        "nostr_intent_event_id": intent,
        "signature": signer.sign(&preimage),
        "rationale": rationale,
    });
    println!("{}", serde_json::to_string(&body)?);
    Ok(())
}
