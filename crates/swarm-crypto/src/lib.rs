//! Minimal repo-owned cryptographic primitives for evidence export and verification.
//!
//! This is intentionally smaller than the long-term upstream hush-core target.
//! The v1.18 milestone only needs deterministic JSON bytes, SHA-256 digests,
//! and detached Ed25519 signatures that can be verified locally.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Errors raised while canonicalizing, signing, or verifying payloads.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("failed to serialize canonical JSON: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("failed to decode hex for `{field}`: {reason}")]
    InvalidHex { field: &'static str, reason: String },

    #[error("invalid byte length for `{field}`: expected {expected} bytes, received {actual}")]
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("signature verification failed")]
    SignatureInvalid,
}

/// Detached signature metadata stored alongside one exported evidence payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetachedSignature {
    pub algorithm: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

/// Repo-owned Ed25519 signer derived from secret material.
#[derive(Debug, Clone)]
pub struct Ed25519Signer {
    signing_key: SigningKey,
    key_id: String,
    public_key_hex: String,
}

impl Ed25519Signer {
    /// Derive a deterministic Ed25519 signing key from local secret material.
    pub fn from_secret_material(secret_material: &str) -> Self {
        let seed = sha256_bytes(secret_material.as_bytes());
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let public_key_hex = encode_hex(&verifying_key.to_bytes());
        let key_id = sha256_hex(&verifying_key.to_bytes());
        Self {
            signing_key,
            key_id,
            public_key_hex,
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    /// Sign arbitrary bytes with the derived key.
    pub fn sign(&self, payload: &[u8]) -> DetachedSignature {
        let signature = self.signing_key.sign(payload);
        DetachedSignature {
            algorithm: "ed25519".to_string(),
            key_id: self.key_id.clone(),
            public_key_hex: self.public_key_hex.clone(),
            signature_hex: encode_hex(&signature.to_bytes()),
        }
    }
}

/// Serialize a value into deterministic JSON bytes.
pub fn canonical_json_bytes<T>(value: &T) -> Result<Vec<u8>, CryptoError>
where
    T: Serialize,
{
    let normalized = serde_json::to_value(value)?;
    Ok(serde_json::to_vec(&normalized)?)
}

/// Serialize a value into deterministic UTF-8 JSON text.
pub fn canonical_json_string<T>(value: &T) -> Result<String, CryptoError>
where
    T: Serialize,
{
    Ok(String::from_utf8(canonical_json_bytes(value)?).expect("JSON is valid UTF-8"))
}

/// Parse JSON text and normalize it into deterministic UTF-8 JSON text.
pub fn normalize_canonical_json(raw: &str) -> Result<String, CryptoError> {
    let parsed: serde_json::Value = serde_json::from_str(raw)?;
    canonical_json_string(&parsed)
}

/// Compute a lowercase hex SHA-256 digest.
pub fn sha256_hex(bytes: &[u8]) -> String {
    encode_hex(&sha256_bytes(bytes))
}

/// Verify a detached signature over the provided payload bytes.
pub fn verify_detached_signature(
    payload: &[u8],
    signature: &DetachedSignature,
) -> Result<(), CryptoError> {
    if signature.algorithm != "ed25519" {
        return Err(CryptoError::InvalidHex {
            field: "algorithm",
            reason: format!("unsupported signature algorithm `{}`", signature.algorithm),
        });
    }

    let verifying_key_bytes = decode_hex("public_key_hex", &signature.public_key_hex)?;
    let verifying_key_bytes: [u8; 32] =
        verifying_key_bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| CryptoError::InvalidLength {
                field: "public_key_hex",
                expected: 32,
                actual: bytes.len(),
            })?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .map_err(|_| CryptoError::SignatureInvalid)?;

    if sha256_hex(&verifying_key_bytes) != signature.key_id {
        return Err(CryptoError::SignatureInvalid);
    }

    let signature_bytes = decode_hex("signature_hex", &signature.signature_hex)?;
    let signature_bytes: [u8; 64] =
        signature_bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| CryptoError::InvalidLength {
                field: "signature_hex",
                expected: 64,
                actual: bytes.len(),
            })?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(payload, &signature)
        .map_err(|_| CryptoError::SignatureInvalid)
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn encode_hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(ALPHABET[(byte >> 4) as usize] as char);
        output.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex(field: &'static str, value: &str) -> Result<Vec<u8>, CryptoError> {
    if !value.len().is_multiple_of(2) {
        return Err(CryptoError::InvalidHex {
            field,
            reason: "hex strings must have an even number of characters".to_string(),
        });
    }

    let mut output = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let high = decode_hex_nibble(field, chunk[0] as char)?;
        let low = decode_hex_nibble(field, chunk[1] as char)?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn decode_hex_nibble(field: &'static str, value: char) -> Result<u8, CryptoError> {
    match value {
        '0'..='9' => Ok(value as u8 - b'0'),
        'a'..='f' => Ok(value as u8 - b'a' + 10),
        'A'..='F' => Ok(value as u8 - b'A' + 10),
        other => Err(CryptoError::InvalidHex {
            field,
            reason: format!("invalid hex character `{other}`"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Ed25519Signer, canonical_json_string, normalize_canonical_json, sha256_hex,
        verify_detached_signature,
    };
    use serde::Serialize;

    #[derive(Debug, Serialize)]
    struct CanonicalFixture {
        name: &'static str,
        priority: u8,
    }

    #[test]
    fn canonical_json_is_compact_and_deterministic() {
        let canonical = canonical_json_string(&CanonicalFixture {
            name: "bundle",
            priority: 7,
        })
        .unwrap();
        assert_eq!(canonical, r#"{"name":"bundle","priority":7}"#);

        let normalized =
            normalize_canonical_json("{\n  \"priority\": 7,\n  \"name\": \"bundle\"\n}").unwrap();
        assert_eq!(normalized, r#"{"name":"bundle","priority":7}"#);
    }

    #[test]
    fn detached_signature_round_trips() {
        let signer = Ed25519Signer::from_secret_material("local evidence test key");
        let payload = br#"{"payload":"signed"}"#;
        let signature = signer.sign(payload);

        verify_detached_signature(payload, &signature).unwrap();
        assert_eq!(signature.key_id, signer.key_id());
        assert_eq!(signature.public_key_hex, signer.public_key_hex());
        assert_eq!(sha256_hex(payload).len(), 64);
    }

    #[test]
    fn detached_signature_fails_on_tamper() {
        let signer = Ed25519Signer::from_secret_material("local evidence test key");
        let payload = br#"{"payload":"signed"}"#;
        let signature = signer.sign(payload);
        let tampered = br#"{"payload":"tampered"}"#;

        assert!(verify_detached_signature(tampered, &signature).is_err());
    }
}
