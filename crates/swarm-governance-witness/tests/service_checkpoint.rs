use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use swarm_governance::persistence_protocol::{WitnessReadResponseV1, canonical_wire_bytes};
use swarm_governance::witness_engine::store::{
    WitnessStoreProxyOperationV1, WitnessStoreProxyRequestV1, WitnessStoreProxyResponseBodyV1,
    WitnessStoreProxyResponseV1, WitnessStoreReadResultV1,
};
use swarm_governance::witness_service::{
    WitnessServiceOperationV1, WitnessServiceRequestBodyV1, WitnessServiceRequestV1,
    WitnessServiceResponseV1,
};
use swarm_governance_witness::RuntimeWitnessClientConfigV1;

fn must<T, E: std::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
    result.unwrap_or_else(|error| panic!("{context}: {error:?}"))
}

fn required<T>(value: Option<T>, context: &str) -> T {
    value.unwrap_or_else(|| panic!("{context}"))
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn exact_artifact(variable: &str, maximum: u64) -> (PathBuf, Vec<u8>) {
    let path = PathBuf::from(must(std::env::var(variable), "artifact path absent"));
    assert!(path.is_absolute(), "artifact path is relative");
    let metadata = must(std::fs::symlink_metadata(&path), "artifact metadata");
    assert!(
        metadata.file_type().is_file(),
        "artifact is not a regular file"
    );
    assert!(!metadata.file_type().is_symlink(), "artifact is a symlink");
    assert!(metadata.len() <= maximum, "artifact exceeds bound");
    let framed = must(std::fs::read(&path), "artifact read");
    assert_eq!(framed.last(), Some(&b'\n'), "artifact newline absent");
    assert_eq!(framed.iter().filter(|byte| **byte == b'\n').count(), 1);
    (path, framed[..framed.len() - 1].to_vec())
}

fn field<'a>(value: &'a Value, name: &str, relation: &str) -> &'a Value {
    value
        .get(name)
        .unwrap_or_else(|| panic!("{relation}: {name} absent"))
}

fn string<'a>(value: &'a Value, name: &str, relation: &str) -> &'a str {
    field(value, name, relation)
        .as_str()
        .unwrap_or_else(|| panic!("{relation}: {name} is not a string"))
}

fn number(value: &Value, name: &str, relation: &str) -> u64 {
    field(value, name, relation)
        .as_u64()
        .unwrap_or_else(|| panic!("{relation}: {name} is not an integer"))
}

fn decoded_hex(value: &Value, name: &str, relation: &str) -> Vec<u8> {
    must(hex::decode(string(value, name, relation)), relation)
}

fn canonical_value(value: &Value, relation: &str) -> Vec<u8> {
    must(canonical_wire_bytes(value), relation)
}

fn assert_digest(value: &Value, bytes_field: &str, digest_field: &str, relation: &str) -> Vec<u8> {
    let bytes = decoded_hex(value, bytes_field, relation);
    assert_eq!(
        digest(&bytes),
        string(value, digest_field, relation),
        "{relation}"
    );
    bytes
}

fn independently_validate_artifacts(ledger_bytes: &[u8], receipt_bytes: &[u8]) {
    let receipt: Value = must(serde_json::from_slice(receipt_bytes), "receipt canonical");
    assert_eq!(
        canonical_value(&receipt, "receipt canonical"),
        receipt_bytes
    );
    assert_eq!(number(&receipt, "schema_version", "receipt schema"), 1);
    assert_eq!(
        digest(ledger_bytes),
        string(&receipt, "observation_ledger_sha256", "ledger digest"),
        "ledger digest"
    );
    assert_eq!(
        decoded_hex(
            &receipt,
            "observation_ledger_canonical_hex",
            "ledger canonical"
        ),
        ledger_bytes,
        "ledger canonical"
    );

    let ledger: Value = must(serde_json::from_slice(ledger_bytes), "ledger canonical");
    assert_eq!(canonical_value(&ledger, "ledger canonical"), ledger_bytes);
    assert_eq!(number(&ledger, "schema_version", "ledger identity"), 1);
    assert_eq!(
        string(&ledger, "tree", "ledger identity"),
        must(
            std::env::var("PHASE285_SERVICE_CHECKPOINT_TREE"),
            "complete receipt tree absent"
        ),
        "ledger identity"
    );
    assert_eq!(
        string(&ledger, "invocation_token", "ledger identity"),
        must(
            std::env::var("PHASE285_COMPLETE_RECEIPT_INVOCATION_TOKEN"),
            "complete receipt invocation token absent"
        ),
        "ledger identity"
    );
    assert_eq!(
        string(&ledger, "case", "ledger identity"),
        "service_checkpoint_complete_receipt",
        "ledger identity"
    );
    assert_eq!(string(&ledger, "status", "ledger identity"), "passed");
    assert_eq!(string(&ledger, "operation", "public request"), "ReadHead");
    assert_eq!(
        string(&ledger, "public_subject", "public request"),
        "swarm.governance.witness.v1.read_head"
    );

    let request_bytes = decoded_hex(&ledger, "request_canonical_hex", "public request");
    let request = must(
        WitnessServiceRequestV1::decode(&request_bytes),
        "public request",
    );
    assert_eq!(
        must(request.canonical_bytes(), "public request"),
        request_bytes
    );
    assert_eq!(request.operation, WitnessServiceOperationV1::ReadHead);
    assert_eq!(
        request.request_nonce,
        string(&ledger, "request_nonce", "public request")
    );
    assert_eq!(
        request.request_digest,
        string(&ledger, "request_digest", "public request")
    );
    let response_bytes = decoded_hex(&ledger, "response_canonical_hex", "public response");
    let response = must(
        WitnessServiceResponseV1::decode_for_client_request(&response_bytes, &request),
        "public response",
    );

    let expected_events = json!([
        {"event":"dequeued","worker":"public"},
        {"event":"post_preflight","worker":"public"},
        {"cas_attempted":false,"event":"proxy_store_begin","operation":"read_entry","worker":"public"},
        {"event":"dequeued","worker":"private"},
        {"event":"post_preflight","worker":"private"},
        {"cas_attempted":false,"event":"proxy_store_begin","operation":"read_entry","worker":"private"},
        {"cas_applied":false,"event":"proxy_store_end","operation":"read_entry","succeeded":true,"worker":"private"},
        {"accepted":true,"event":"response_enqueue_attempt","worker":"private"},
        {"event":"publish_attempt","published":true,"worker":"private"},
        {"cas_applied":false,"event":"proxy_store_end","operation":"read_entry","succeeded":true,"worker":"public"},
        {"accepted":true,"event":"response_enqueue_attempt","worker":"public"},
        {"event":"publish_attempt","published":true,"worker":"public"}
    ]);
    let worker_events = field(&ledger, "worker_events", "worker operation");
    let worker_event_rows = required(worker_events.as_array(), "worker operation");
    assert_eq!(worker_event_rows.len(), 12, "worker operation");
    for index in [2_usize, 5] {
        assert_eq!(
            field(&worker_event_rows[index], "cas_attempted", "worker CAS").as_bool(),
            Some(false),
            "worker CAS"
        );
    }
    for index in [6_usize, 9] {
        assert_eq!(
            field(&worker_event_rows[index], "cas_applied", "worker CAS").as_bool(),
            Some(false),
            "worker CAS"
        );
    }
    assert_eq!(worker_events, &expected_events, "worker operation");

    let private = required(
        field(&ledger, "private_exchanges", "private exchange").as_array(),
        "private exchange array",
    );
    assert_eq!(private.len(), 3, "private exchange");
    let expected_private = [
        WitnessStoreProxyOperationV1::InspectReady,
        WitnessStoreProxyOperationV1::ReadEntry,
        WitnessStoreProxyOperationV1::ReadEntry,
    ];
    let mut previous_response_at = 0;
    let mut final_private_response = None;
    for (exchange, expected_operation) in private.iter().zip(expected_private) {
        let private_request_bytes = assert_digest(
            exchange,
            "request_canonical_hex",
            "request_sha256",
            "private request digest",
        );
        let private_response_bytes = assert_digest(
            exchange,
            "response_canonical_hex",
            "response_sha256",
            "private response digest",
        );
        let private_request = must(
            WitnessStoreProxyRequestV1::decode(&private_request_bytes),
            "private request digest",
        );
        must(
            private_request.validate_semantics(),
            "private request digest",
        );
        must(
            private_request.validate_signature(),
            "private request digest",
        );
        let private_response = must(
            WitnessStoreProxyResponseV1::decode(&private_response_bytes),
            "private response digest",
        );
        assert_eq!(
            private_request.operation, expected_operation,
            "private exchange"
        );
        assert_eq!(
            private_response.operation, expected_operation,
            "private exchange"
        );
        assert_eq!(
            private_response.request_digest, private_request.request_digest,
            "private exchange"
        );
        let request_at = number(exchange, "request_at_nanos", "causal timestamps");
        let response_at = number(exchange, "response_at_nanos", "causal timestamps");
        assert!(
            request_at >= previous_response_at && response_at >= request_at,
            "causal timestamps"
        );
        previous_response_at = response_at;
        final_private_response = Some(private_response);
    }

    let proxy = required(
        field(&ledger, "proxy_exchanges", "proxy cross-copy").as_array(),
        "proxy cross-copy",
    );
    assert_eq!(proxy.len(), 1, "proxy cross-copy");
    assert_eq!(
        canonical_value(&proxy[0], "proxy cross-copy"),
        canonical_value(&private[2], "proxy cross-copy"),
        "proxy cross-copy"
    );

    let publisher_attempts = required(
        field(&ledger, "publisher_attempts", "publisher fabrication").as_array(),
        "publisher fabrication",
    );
    let expected_publishers = [(8_u64, "private"), (11_u64, "public")];
    assert_eq!(
        publisher_attempts.len(),
        expected_publishers.len(),
        "publisher fabrication"
    );
    for (attempt, (ordinal, worker)) in publisher_attempts.iter().zip(expected_publishers) {
        let ordinal_index =
            usize::try_from(ordinal).unwrap_or_else(|_| panic!("publisher fabrication"));
        let event = worker_event_rows
            .get(ordinal_index)
            .unwrap_or_else(|| panic!("publisher fabrication"));
        assert_eq!(
            number(attempt, "ordinal", "publisher fabrication"),
            ordinal,
            "publisher fabrication"
        );
        assert_eq!(
            string(attempt, "worker", "publisher fabrication"),
            worker,
            "publisher fabrication"
        );
        assert_eq!(
            field(attempt, "published", "publisher fabrication").as_bool(),
            Some(true),
            "publisher fabrication"
        );
        assert_eq!(
            string(event, "event", "publisher fabrication"),
            "publish_attempt",
            "publisher fabrication"
        );
        assert_eq!(
            string(event, "worker", "publisher fabrication"),
            worker,
            "publisher fabrication"
        );
        assert_eq!(
            field(event, "published", "publisher fabrication").as_bool(),
            Some(true),
            "publisher fabrication"
        );
    }
    let store = required(
        field(&ledger, "store_operations", "store result digest").as_array(),
        "store operation array",
    );
    assert_eq!(store.len(), 1, "store result digest");
    assert_eq!(
        string(&store[0], "operation", "store result digest"),
        "read_entry"
    );
    assert_eq!(
        field(&store[0], "cas_attempted", "worker CAS").as_bool(),
        Some(false),
        "worker CAS"
    );
    assert_eq!(
        field(&store[0], "cas_applied", "worker CAS").as_bool(),
        Some(false),
        "worker CAS"
    );
    let store_input = assert_digest(
        &store[0],
        "input_canonical_hex",
        "input_sha256",
        "store input digest",
    );
    let stream: String = must(serde_json::from_slice(&store_input), "store input digest");
    assert_eq!(
        must(canonical_wire_bytes(&stream), "store input digest"),
        store_input,
        "store input digest"
    );
    assert_eq!(stream, "tom-primary", "store input digest");
    let store_result_bytes = assert_digest(
        &store[0],
        "result_canonical_hex",
        "result_sha256",
        "store result digest",
    );
    let store_result: WitnessStoreReadResultV1 = must(
        serde_json::from_slice(&store_result_bytes),
        "store result digest",
    );
    assert_eq!(
        must(canonical_wire_bytes(&store_result), "store result digest"),
        store_result_bytes,
        "store result digest"
    );
    let (store_stream, store_revision, store_envelope) = store_result.parts();
    assert_eq!(store_stream, stream, "store result digest");
    assert_eq!(
        number(&store[0], "revision", "store result digest"),
        store_revision,
        "store result digest"
    );
    assert_eq!(
        number(&store[0], "store_generation", "store result digest"),
        store_envelope.store_generation,
        "store result digest"
    );
    assert_eq!(
        string(&store[0], "store_state_digest", "store result digest"),
        must(store_envelope.store_state_digest(), "store result digest"),
        "store result digest"
    );

    let final_private_response = required(final_private_response, "private store entry");
    match final_private_response.body {
        WitnessStoreProxyResponseBodyV1::Entry {
            stream_id,
            revision,
            envelope,
        } if stream_id == store_stream
            && revision == store_revision
            && envelope.as_ref() == store_envelope => {}
        _ => panic!("private store entry"),
    }
    assert_eq!(
        number(&ledger, "selected_store_revision", "store result digest"),
        store_revision,
        "store result digest"
    );
    assert_eq!(
        number(&ledger, "selected_store_generation", "store result digest"),
        store_envelope.store_generation,
        "store result digest"
    );
    assert_eq!(
        string(
            &ledger,
            "selected_store_state_digest",
            "store result digest"
        ),
        must(store_envelope.store_state_digest(), "store result digest"),
        "store result digest"
    );
    assert_eq!(
        string(&ledger, "selected_envelope_digest", "store result digest"),
        must(
            store_envelope.signed_envelope_digest(),
            "store result digest"
        ),
        "store result digest"
    );

    let selected_head = &required(store_envelope.current.as_ref(), "public/store Head").head;
    let WitnessServiceResponseV1::Read(read) = response else {
        panic!("public/store Head")
    };
    let WitnessReadResponseV1::Head(head) = &read.response else {
        panic!("public/store Head")
    };
    assert_eq!(
        head.as_ref().as_ref(),
        Some(selected_head),
        "public/store Head"
    );
    assert_eq!(read.target_txid, selected_head.txid, "public/store Head");
    assert_eq!(
        string(&ledger, "selected_head_txid", "public/store Head"),
        selected_head.txid,
        "public/store Head"
    );
    let WitnessServiceRequestBodyV1::ReadHead { target_txid, .. } = &request.body else {
        panic!("public/store Head")
    };
    assert_eq!(target_txid, &selected_head.txid, "public/store Head");

    let admission = field(&ledger, "public_admission", "publisher reply subject");
    let publisher = field(&ledger, "publisher", "publisher reply subject");
    let reply = string(publisher, "reply_subject", "publisher reply subject");
    assert_eq!(
        string(admission, "reply_subject", "publisher reply subject"),
        reply,
        "publisher reply subject"
    );
    assert!(
        reply.len() <= 512
            && (reply.starts_with("_INBOX.") || reply.starts_with("_R_."))
            && !reply.contains(['*', '>']),
        "publisher reply subject"
    );
    assert_eq!(
        string(admission, "subject", "publisher reply subject"),
        string(&ledger, "public_subject", "publisher reply subject"),
        "publisher reply subject"
    );
    assert_eq!(
        string(admission, "payload_sha256", "publisher reply subject"),
        digest(&request_bytes),
        "publisher reply subject"
    );
    assert_eq!(
        number(admission, "deadline_millis", "publisher reply subject"),
        10_000,
        "publisher reply subject"
    );
    let published_response = assert_digest(
        publisher,
        "response_canonical_hex",
        "response_sha256",
        "publisher response",
    );
    assert_eq!(published_response, response_bytes, "publisher response");
    let request_received = number(publisher, "request_received_at_nanos", "causal timestamps");
    let response_received = number(publisher, "response_received_at_nanos", "causal timestamps");
    assert_eq!(
        number(admission, "received_at_nanos", "causal timestamps"),
        request_received,
        "causal timestamps"
    );
    assert!(
        number(
            required(private.last(), "private exchange"),
            "request_at_nanos",
            "causal timestamps"
        ) >= request_received,
        "causal timestamps"
    );
    assert!(
        number(
            required(private.last(), "private exchange"),
            "response_at_nanos",
            "causal timestamps"
        ) <= response_received,
        "causal timestamps"
    );

    let connections = required(
        field(&ledger, "connections", "connection identity").as_array(),
        "connection identity",
    );
    let client_ids = required(
        field(&ledger, "connection_client_ids", "connection identity").as_array(),
        "connection identity",
    );
    let expected = [
        ("runtime-client", "PHASE285_RUNTIME", "phase285_foreign"),
        ("public-witness", "PHASE285_WITNESS", "phase285_witness"),
        (
            "private-store",
            "PHASE285_WITNESS_STORE",
            "phase285_witness_store",
        ),
    ];
    assert_eq!(connections.len(), 3, "connection identity");
    assert_eq!(client_ids.len(), 3, "connection identity");
    let mut distinct = std::collections::BTreeSet::new();
    for ((connection, client_id), (role, account, user)) in
        connections.iter().zip(client_ids).zip(expected)
    {
        let id = required(client_id.as_u64(), "connection identity");
        assert!(id > 0 && distinct.insert(id), "connection identity");
        assert_eq!(
            number(connection, "server_client_id", "connection identity"),
            id,
            "connection identity"
        );
        assert_eq!(
            string(connection, "runner_role", "connection identity"),
            role,
            "connection identity"
        );
        assert_eq!(
            string(connection, "account", "connection identity"),
            account,
            "connection identity"
        );
        assert_eq!(
            string(connection, "authenticated_user", "connection identity"),
            user,
            "connection identity"
        );
        let evidence = assert_digest(
            connection,
            "server_evidence_canonical_hex",
            "server_evidence_sha256",
            "connection identity",
        );
        let authority: Value = must(serde_json::from_slice(&evidence), "connection identity");
        assert_eq!(
            canonical_value(&authority, "connection identity"),
            evidence,
            "connection identity"
        );
        assert_eq!(
            string(&authority, "account", "connection identity"),
            account,
            "connection identity"
        );
        assert_eq!(
            string(&authority, "authenticated_user", "connection identity"),
            user,
            "connection identity"
        );
        assert_eq!(
            number(&authority, "server_client_id", "connection identity"),
            id,
            "connection identity"
        );
    }

    let counts = field(&ledger, "counts", "ledger counts");
    for (name, expected) in [
        ("worker_events", 12),
        ("proxy_exchanges", 1),
        ("private_exchanges", 3),
        ("store_operations", 1),
        ("publisher_attempts", 2),
        ("connections", 3),
        ("cas_attempted", 0),
        ("cas_applied", 0),
    ] {
        assert_eq!(
            number(counts, name, "ledger counts"),
            expected,
            "ledger counts"
        );
    }
    let digests = field(&ledger, "digests", "ledger digests");
    for (name, value) in [
        (
            "worker_events_sha256",
            field(&ledger, "worker_events", "ledger digests"),
        ),
        (
            "proxy_exchanges_sha256",
            field(&ledger, "proxy_exchanges", "ledger digests"),
        ),
        (
            "private_exchanges_sha256",
            field(&ledger, "private_exchanges", "ledger digests"),
        ),
        (
            "store_operations_sha256",
            field(&ledger, "store_operations", "ledger digests"),
        ),
        (
            "publisher_attempts_sha256",
            field(&ledger, "publisher_attempts", "ledger digests"),
        ),
        ("public_admission_sha256", admission),
        ("publisher_sha256", publisher),
        (
            "connections_sha256",
            field(&ledger, "connections", "ledger digests"),
        ),
        (
            "connection_client_ids_sha256",
            field(&ledger, "connection_client_ids", "ledger digests"),
        ),
    ] {
        assert_eq!(
            string(digests, name, "ledger digests"),
            digest(&canonical_value(value, "ledger digests")),
            "ledger digests"
        );
    }
    assert_eq!(
        string(digests, "request_sha256", "ledger digests"),
        digest(&request_bytes),
        "ledger digests"
    );
    assert_eq!(
        string(digests, "response_sha256", "ledger digests"),
        digest(&response_bytes),
        "ledger digests"
    );
}

#[test]
fn service_checkpoint_runtime_client_transport_is_closed() {
    let config = RuntimeWitnessClientConfigV1 {
        nats_url: "tls://localhost:4222".to_string(),
        nats_credentials_path: "/run/phase285/runtime.credentials.json".to_string(),
        credential_invocation_token: "a".repeat(64),
        tls_ca_path: "/run/phase285/ca.pem".to_string(),
        tls_server_name: "localhost".to_string(),
        max_request_bytes: 1_048_576,
        max_response_bytes: 1_048_576,
        subscription_capacity: 8,
        client_capacity: 8,
        read_buffer_capacity: 4_096,
        request_deadline_millis: 12_000,
    };
    assert!(config.validate().is_ok());
    let mut wrong_authority = config.clone();
    wrong_authority.tls_server_name = "wrong.invalid".to_string();
    assert!(wrong_authority.validate().is_err());
    let mut wrong_deadline = config;
    wrong_deadline.request_deadline_millis = 11_999;
    assert!(wrong_deadline.validate().is_err());
}

#[test]
fn complete_receipt_validation_precedes_suppression_and_failures_forward() {
    let (ledger_path, ledger) = exact_artifact("PHASE285_COMPLETE_RECEIPT_LEDGER_PATH", 1_048_576);
    let (receipt_path, receipt) = exact_artifact("PHASE285_COMPLETE_RECEIPT_PATH", 2_097_152);
    assert_ne!(ledger_path, receipt_path, "artifact paths alias");
    independently_validate_artifacts(&ledger, &receipt);
    println!("complete_receipt_external ledger=1 receipt=1 private=3 worker=12 passed=1");
}
