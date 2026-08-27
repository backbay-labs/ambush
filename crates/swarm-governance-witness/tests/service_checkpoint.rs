use swarm_governance_witness::RuntimeWitnessClientConfigV1;

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
