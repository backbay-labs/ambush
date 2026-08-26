use serde::{Deserialize, Serialize};
use swarm_governance::persistence_protocol::{
    MAX_PROTOCOL_RECORD_BYTES, MAX_PROTOCOL_STRING_BYTES, ProtocolError, ProtocolResult,
};
use swarm_governance::witness_engine::store::WitnessAdmissionSetV1;
use swarm_governance::witness_service::WitnessServiceOperationV1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicWitnessServiceConfigV1 {
    pub nats_url: String,
    pub nats_credentials_path: String,
    pub tls_ca_path: String,
    pub tls_server_name: String,
    pub witness_key_path: String,
    pub witness_identity: String,
    pub witness_key_id: String,
    pub bucket_name: String,
    pub bucket_configuration_digest: String,
    pub bucket_epoch_digest: String,
    pub bucket_anchor_digest: String,
    pub admission_set_digest: String,
    pub ready_manifest_digest: String,
    pub admission_set: WitnessAdmissionSetV1,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub ingress_queue_capacity: usize,
    pub max_in_flight: usize,
    pub request_deadline_millis: u64,
}

impl PublicWitnessServiceConfigV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        for (field, value) in [
            ("nats_url", self.nats_url.as_str()),
            ("nats_credentials_path", self.nats_credentials_path.as_str()),
            ("tls_ca_path", self.tls_ca_path.as_str()),
            ("tls_server_name", self.tls_server_name.as_str()),
            ("witness_key_path", self.witness_key_path.as_str()),
            ("witness_identity", self.witness_identity.as_str()),
            ("witness_key_id", self.witness_key_id.as_str()),
            ("bucket_name", self.bucket_name.as_str()),
            (
                "bucket_configuration_digest",
                self.bucket_configuration_digest.as_str(),
            ),
            ("bucket_epoch_digest", self.bucket_epoch_digest.as_str()),
            ("bucket_anchor_digest", self.bucket_anchor_digest.as_str()),
            ("admission_set_digest", self.admission_set_digest.as_str()),
            ("ready_manifest_digest", self.ready_manifest_digest.as_str()),
        ] {
            if value.is_empty() || value.len() > MAX_PROTOCOL_STRING_BYTES {
                return Err(invalid(field, "must be nonempty and bounded"));
            }
        }
        if !self.nats_url.starts_with("tls://") {
            return Err(invalid("nats_url", "must use tls://"));
        }
        for (field, digest) in [
            ("witness_key_id", self.witness_key_id.as_str()),
            (
                "bucket_configuration_digest",
                self.bucket_configuration_digest.as_str(),
            ),
            ("bucket_epoch_digest", self.bucket_epoch_digest.as_str()),
            ("bucket_anchor_digest", self.bucket_anchor_digest.as_str()),
            ("admission_set_digest", self.admission_set_digest.as_str()),
            ("ready_manifest_digest", self.ready_manifest_digest.as_str()),
        ] {
            if digest.len() != 64
                || digest
                    .bytes()
                    .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
            {
                return Err(invalid(field, "must be a lowercase SHA-256 digest"));
            }
        }
        self.admission_set.validate()?;
        if self.admission_set.admission_set_digest != self.admission_set_digest {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        for admission in &self.admission_set.entries {
            if admission.witness_identity != self.witness_identity
                || admission.witness_key_id != self.witness_key_id
            {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
        }
        for (field, value) in [
            ("max_request_bytes", self.max_request_bytes),
            ("max_response_bytes", self.max_response_bytes),
            ("ingress_queue_capacity", self.ingress_queue_capacity),
            ("max_in_flight", self.max_in_flight),
        ] {
            if value == 0 || value > MAX_PROTOCOL_RECORD_BYTES {
                return Err(ProtocolError::Bounds {
                    field: field.to_string(),
                    observed: value,
                    maximum: MAX_PROTOCOL_RECORD_BYTES,
                });
            }
        }
        if self.max_in_flight > self.ingress_queue_capacity || self.request_deadline_millis == 0 {
            return Err(invalid(
                "service_limits",
                "max-in-flight must fit the queue and deadline must be nonzero",
            ));
        }
        Ok(())
    }

    pub const fn subject_for(operation: WitnessServiceOperationV1) -> &'static str {
        match operation {
            WitnessServiceOperationV1::Fence => "swarm.governance.witness.v1.fence",
            WitnessServiceOperationV1::Establish => "swarm.governance.witness.v1.establish",
            WitnessServiceOperationV1::Discover => "swarm.governance.witness.v1.discover",
            WitnessServiceOperationV1::Prepare => "swarm.governance.witness.v1.prepare",
            WitnessServiceOperationV1::Commit => "swarm.governance.witness.v1.commit",
            WitnessServiceOperationV1::Abort => "swarm.governance.witness.v1.abort",
            WitnessServiceOperationV1::ReadPrepared => "swarm.governance.witness.v1.read_prepared",
            WitnessServiceOperationV1::ReadHead => "swarm.governance.witness.v1.read_head",
            WitnessServiceOperationV1::FetchPayload => "swarm.governance.witness.v1.fetch_payload",
        }
    }
}

fn invalid(field: &'static str, reason: &'static str) -> ProtocolError {
    ProtocolError::InvalidField {
        field: field.to_string(),
        reason: reason.to_string(),
    }
}
